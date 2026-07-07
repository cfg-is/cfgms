// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// provisionModuleWithTransport builds a hypervModule wired with the given
// transport and an in-memory provision store for create-from-source tests. A
// real in-memory SecretStore is injected so the windows create path can resolve
// the .ppkg host-path secret ({{ secret "ppkg-path-key" }}) when rendering the
// autounattend answer file (#2047) — no mock framework is used.
func provisionModuleWithTransport(t *testing.T, transport winrmTransport) *hypervModule {
	t.Helper()
	m := &hypervModule{
		executor:       &stubHypervExecutor{},
		transport:      transport,
		tenantID:       "ops",
		vms:            make(map[string]VMConfig),
		detector:       &fakeDetector{result: true},
		provisionStore: NewMemProvisionStore(),
		// Controller-supplied enrollment wiring (ADR-010): both the Windows
		// autounattend and the Linux preseed bake these in via ProfileVars.
		enrollToken:         "reg-token-stub-value",
		enrollCAFingerprint: "abc123fingerprint",
	}
	// Inject a single in-memory SecretStore carrying the keys the Linux preseed
	// (#2046) still resolves at render time so the create-from-source tests
	// exercise the real render path (no mocks): registration token + crypted
	// user password. The Windows autounattend (ADR-010) no longer reads secrets
	// (token + CA fingerprint are controller-supplied ProfileVars), so it needs
	// no store entries.
	require.NoError(t, m.SetSecretStore(newInlineStore(
		"hyperv/enroll/regtoken", "reg-token-stub-value",
		"hyperv/enroll/user-password-crypted", "$6$rounds=4096$stub$cryptedstub",
	)))
	return m
}

// sourceVMConfigMap returns the executor-shaped config map for an absent VM
// that carries a source block, for the requested generation and os_family.
func sourceVMConfigMap(generation int, osFamily string) map[string]interface{} {
	return map[string]interface{}{
		"name":        "stw-01",
		"memory_mb":   4096,
		"cpu_count":   2,
		"vhd_path":    `C:\ClusterStorage\CSV01\stw-01.vhdx`,
		"generation":  generation,
		"state":       "running",
		"switch_name": "HVSwitch_1G",
		"source": map[string]interface{}{
			"iso":       `C:\ClusterStorage\CSV01\iso\server.iso`,
			"os_family": osFamily,
			"completion": map[string]interface{}{
				"mode":    "steward-registration",
				"timeout": "60m",
			},
			"on_existing": "never",
		},
	}
}

// ── REQUIRED TEST: secureBootTemplate ──────────────────────────────────────

// TestProvisionVM_SecureBootTemplate asserts the os_family → secure-boot
// template mapping required by ADR-009 §5.
func TestProvisionVM_SecureBootTemplate(t *testing.T) {
	assert.Equal(t, "MicrosoftWindows", secureBootTemplate("windows"))
	assert.Equal(t, "MicrosoftUEFICertificateAuthority", secureBootTemplate("linux"))
}

// ── REQUIRED TEST: Gen1 skips firmware ──────────────────────────────────────

// TestProvisionVM_Gen1SkipsFirmware drives an absent Gen1 VM with a source
// block and asserts no Set-VMFirmware PS call is issued (Gen1 has no secure
// boot), while the seed VHDX + ISO attach + create still run.
func TestProvisionVM_Gen1SkipsFirmware(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`}, // getVM → absent
	}
	m := provisionModuleWithTransport(t, transport)

	cfg := rawConfigState{m: sourceVMConfigMap(1, "linux")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, callsContaining(calls, "Set-VMFirmware"),
		"Gen1 VMs must not issue Set-VMFirmware — Gen1 has no UEFI/secure boot")

	// Create + seed build + attach still happen on the Gen1 path.
	require.Len(t, callsContaining(calls, "New-VM"), 1, "Gen1 VM must still be created")
	assert.NotEmpty(t, callsContaining(calls, "New-VHD"), "seed VHDX must still be built")
	assert.NotEmpty(t, callsContaining(calls, "Add-VMDvdDrive"), "install ISO must still be attached")
}

// ── REQUIRED TEST: seed path validation ─────────────────────────────────────

// TestProvisionVM_SeedPathValidation asserts that a non-absolute seed path and
// a UNC path are rejected before reaching the PS transport.
func TestProvisionVM_SeedPathValidation(t *testing.T) {
	cases := []struct {
		name string
		path string
		ok   bool
	}{
		{"absolute local", `C:\VMs\cfgms-seed-x.vhdx`, true},
		{"non-absolute relative", `VMs\cfgms-seed-x.vhdx`, false},
		{"non-absolute bare", `cfgms-seed-x.vhdx`, false},
		{"UNC share", `\\server\share\cfgms-seed-x.vhdx`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSeedPath(tc.path)
			if tc.ok {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, ErrInvalidSeedPath)
			}
		})
	}
}

// ── Gen1 create emits -Generation 1 ─────────────────────────────────────────

// TestProvisionVM_Gen1CreatePassesGeneration drives an absent Gen1 VM (no
// source) and asserts the New-VM call carries Generation 1 in args.
func TestProvisionVM_Gen1CreatePassesGeneration(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := rawConfigState{m: map[string]interface{}{
		"name":        "gen1-vm",
		"memory_mb":   2048,
		"cpu_count":   2,
		"vhd_path":    `C:\VMs\gen1-vm.vhdx`,
		"generation":  1,
		"state":       "stopped",
		"switch_name": "sw-a",
	}}
	require.NoError(t, m.Set(context.Background(), "vm:gen1-vm", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	newVM := callsContaining(calls, "New-VM")
	require.Len(t, newVM, 1)
	assert.True(t, argsContain(newVM[0], "1"), "New-VM must pass Generation 1 via args")
	// Generation must never be interpolated into the script text.
	assert.Contains(t, newVM[0].scriptBlock, "$Generation",
		"generation must travel as the $Generation param reference")
}

// TestProvisionVM_Gen2CreateDefaultsGeneration drives an absent VM with
// generation unset (0) and asserts New-VM defaults to Generation 2.
func TestProvisionVM_Gen2CreateDefaultsGeneration(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := rawConfigState{m: map[string]interface{}{
		"name":        "def-vm",
		"memory_mb":   2048,
		"cpu_count":   2,
		"vhd_path":    `C:\VMs\def-vm.vhdx`,
		"state":       "stopped",
		"switch_name": "sw-a",
		// generation omitted → 0 → defaults to 2
	}}
	require.NoError(t, m.Set(context.Background(), "vm:def-vm", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	newVM := callsContaining(calls, "New-VM")
	require.Len(t, newVM, 1)
	assert.True(t, argsContain(newVM[0], "2"), "unset generation must default to Generation 2 in args")
}

// ── Gen2 create-from-source: firmware template per os_family ─────────────────

// TestProvisionVM_Gen2WindowsFirmwareTemplate drives an absent Gen2 windows VM
// with a source block and asserts Set-VMFirmware travels with the
// MicrosoftWindows template via args (never interpolated).
func TestProvisionVM_Gen2WindowsFirmwareTemplate(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	m := provisionModuleWithTransport(t, transport)

	cfg := rawConfigState{m: sourceVMConfigMap(2, "windows")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	fw := callsContaining(calls, "SecureBootTemplate")
	require.Len(t, fw, 1, "Gen2 VM must set the secure-boot template exactly once")
	assert.True(t, argsContain(fw[0], "MicrosoftWindows"),
		"windows os_family must select the MicrosoftWindows template")
	assert.NotContains(t, fw[0].scriptBlock, "MicrosoftWindows",
		"firmware template must travel via args, not the script text")
	// Gen2 must also make the install DVD the first boot device.
	require.Len(t, callsContaining(calls, "FirstBootDevice"), 1,
		"Gen2 VM must set the install DVD as the first boot device")
}

// TestProvisionVM_Gen2LinuxFirmwareTemplate asserts the linux os_family selects
// the MicrosoftUEFICertificateAuthority template on the Gen2 source path.
func TestProvisionVM_Gen2LinuxFirmwareTemplate(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	m := provisionModuleWithTransport(t, transport)

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	fw := callsContaining(calls, "SecureBootTemplate")
	require.Len(t, fw, 1)
	assert.True(t, argsContain(fw[0], "MicrosoftUEFICertificateAuthority"),
		"linux os_family must select the MicrosoftUEFICertificateAuthority template")
}

// ── Seed VHDX build + attach sequence ────────────────────────────────────────

// TestProvisionVM_SeedVHDBuildAndAttachSequence drives an absent Gen2 LINUX
// VM with a source block and asserts the full seed build + media attach
// sequence is emitted in order: New-VHD → Format-Volume (Mount) → Set-Content
// (copy) → Add-VMHardDiskDrive (seed attach) → Add-VMDvdDrive (ISO). The seed
// VHDX path is Linux-only; Windows delivers its answer file on an ISO (see
// TestProvisionVM_WindowsBuildsAnswerISO).
func TestProvisionVM_SeedVHDBuildAndAttachSequence(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	m := provisionModuleWithTransport(t, transport)

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// Each provisioning verb runs exactly once.
	require.Len(t, callsContaining(calls, "New-VHD"), 1, "one New-VHD (seed create)")
	require.Len(t, callsContaining(calls, "Format-Volume"), 1, "one Format-Volume (seed mount/format)")
	require.Len(t, callsContaining(calls, "Set-Content"), 1, "one Set-Content (answer file copy)")
	require.Len(t, callsContaining(calls, "Add-VMHardDiskDrive"), 1, "one Add-VMHardDiskDrive (seed attach)")
	require.Len(t, callsContaining(calls, "Add-VMDvdDrive"), 1, "one Add-VMDvdDrive (install ISO)")

	// Assert ordering by scanning the recorded call sequence.
	order := map[string]int{}
	for i, c := range calls {
		for _, verb := range []string{"New-VHD", "Format-Volume", "Set-Content", "Add-VMHardDiskDrive", "Add-VMDvdDrive", "Start-VM"} {
			if _, seen := order[verb]; !seen && strings.Contains(c.scriptBlock, verb) {
				order[verb] = i
			}
		}
	}
	assert.Less(t, order["New-VHD"], order["Format-Volume"], "New-VHD before Format-Volume")
	assert.Less(t, order["Format-Volume"], order["Set-Content"], "Format before copy")
	assert.Less(t, order["Set-Content"], order["Add-VMHardDiskDrive"], "copy before seed attach")
	assert.Less(t, order["Add-VMHardDiskDrive"], order["Add-VMDvdDrive"], "seed attach before ISO attach")
	assert.Less(t, order["Add-VMDvdDrive"], order["Start-VM"], "media attached before power on")

	// The seed path and answer file name travel via args, never the script.
	seedNew := callsContaining(calls, "New-VHD")[0]
	assert.True(t, argsContain(seedNew, `C:\ClusterStorage\CSV01\cfgms-seed-stw-01.vhdx`),
		"seed path must derive from the VM VHD directory and travel via args")
	assert.NotContains(t, seedNew.scriptBlock, "cfgms-seed-stw-01",
		"seed path must not be interpolated into the script text")

	copy := callsContaining(calls, "Set-Content")[0]
	assert.True(t, argsContain(copy, "preseed.cfg"),
		"linux os_family must seed preseed.cfg")
}

// TestProvisionVM_WindowsBuildsAnswerISO asserts the Windows path delivers the
// answer file via an ISO (the new Server 2025 Setup does not scan data disks):
// it builds an answer ISO, attaches TWO DVDs (answer ISO + install ISO), sets
// the install DVD first boot, and drives the boot keypress — and never builds a
// seed VHDX.
func TestProvisionVM_WindowsBuildsAnswerISO(t *testing.T) {
	transport := &testWinRMTransport{perCallOutputs: []string{`{"found":false}`}}
	m := provisionModuleWithTransport(t, transport)

	cfg := rawConfigState{m: sourceVMConfigMap(2, "windows")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, callsContaining(calls, "Cfgms-BuildAnswerIso"), 1, "one answer-ISO build")
	require.Len(t, callsContaining(calls, "Add-VMDvdDrive"), 2, "two DVDs: answer ISO + install ISO")
	require.Len(t, callsContaining(calls, "Cfgms-BootKeypress"), 1, "one boot keypress")
	assert.Empty(t, callsContaining(calls, "New-VHD"), "windows must NOT build a seed VHDX")
	assert.Empty(t, callsContaining(calls, "Add-VMHardDiskDrive"), "windows attaches no seed disk")

	build := callsContaining(calls, "Cfgms-BuildAnswerIso")[0]
	assert.True(t, argsContain(build, "autounattend.xml"), "windows answer file is autounattend.xml")
	assert.True(t, argsContain(build, `C:\ClusterStorage\CSV01\cfgms-answer-stw-01.iso`),
		"answer ISO path derives from the VM VHD dir and travels via args")
}

// TestProvisionVM_AttachesInstallISOFromHostPath asserts the install ISO is
// attached from the host path via args, never repacked or interpolated.
func TestProvisionVM_AttachesInstallISOFromHostPath(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	m := provisionModuleWithTransport(t, transport)

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	dvd := callsContaining(calls, "Add-VMDvdDrive")
	require.Len(t, dvd, 1)
	assert.True(t, argsContain(dvd[0], `C:\ClusterStorage\CSV01\iso\server.iso`),
		"install ISO host path must travel via args")
	assert.NotContains(t, dvd[0].scriptBlock, "server.iso",
		"ISO path must not be interpolated into the script text")
}

// ── cloud-init (Linux VM-from-cloud-image) path ──────────────────────────────

// cloudInitVMConfigMap returns the executor-shaped config map for an absent
// linux VM that boots a cloud image (source.image) via cloud-init.
func cloudInitVMConfigMap(generation int) map[string]interface{} {
	return map[string]interface{}{
		"name":        "stw-01",
		"memory_mb":   2048,
		"cpu_count":   2,
		"vhd_path":    `C:\VMs\stw-01.vhdx`,
		"generation":  generation,
		"state":       "running",
		"switch_name": "HVSwitch_1G",
		"source": map[string]interface{}{
			"image":     `C:\images\debian-13-generic-amd64.raw`,
			"os_family": "linux",
			"resize_gb": 20,
			"completion": map[string]interface{}{
				"mode":    "steward-registration",
				"timeout": "60m",
			},
			"on_existing": "never",
		},
	}
}

// TestProvisionVM_CloudInitPath drives an absent Gen2 linux VM that declares a
// cloud image and asserts the codified cloud-init path: the boot disk is prepared
// from the image (Cfgms-PrepCloudBootDisk) and the VM is created attaching that
// existing disk (Cfgms-CreateVMFromDisk); a CIDATA NoCloud seed (user-data +
// meta-data + cfgms-steward) is built and attached; the OS disk is made the first
// boot device; and there is NO install ISO, NO answer ISO, and NO boot keypress.
func TestProvisionVM_CloudInitPath(t *testing.T) {
	transport := &testWinRMTransport{perCallOutputs: []string{`{"found":false}`}}
	m := provisionModuleWithTransport(t, transport)
	// The linux steward + launcher binaries + CA host paths the seed stages (ADR-010).
	// The launcher is required for a launcher-managed (push-upgradeable) install.
	m.enrollStewardPath = `C:\seed-assets\cfgms-steward-linux`
	m.enrollLauncherPath = `C:\seed-assets\cfgms-steward-launcher-linux`
	m.enrollCAPath = `C:\seed-assets\controller-ca.crt`

	cfg := rawConfigState{m: cloudInitVMConfigMap(2)}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// Boot disk prepared from the cloud image, then VM created attaching it.
	prep := callsContaining(calls, "Cfgms-PrepCloudBootDisk")
	require.Len(t, prep, 1, "one Cfgms-PrepCloudBootDisk (cloud image → boot VHDX)")
	assert.True(t, argsContain(prep[0], `C:\images\debian-13-generic-amd64.raw`),
		"cloud image path travels via args")
	assert.True(t, argsContain(prep[0], `C:\VMs\stw-01.vhdx`), "boot VHDX path travels via args")
	require.Len(t, callsContaining(calls, "Cfgms-CreateVMFromDisk"), 1,
		"cloud-init VM is created attaching the existing prepared disk")

	// NoCloud CIDATA seed: New-VHD → Format → Set-Content (user-data + meta-data)
	// → Add-VMHardDiskDrive. The seed carries the steward binary too.
	require.Len(t, callsContaining(calls, "New-VHD"), 1, "one New-VHD (CIDATA seed)")
	require.Len(t, callsContaining(calls, "Set-Content"), 1, "one Set-Content (seed write)")
	require.Len(t, callsContaining(calls, "Add-VMHardDiskDrive"), 1, "one seed attach")
	copyCall := callsContaining(calls, "Set-Content")[0]
	assert.True(t, argsContain(copyCall, "CIDATA"), "seed volume is labelled CIDATA")
	assert.True(t, argsContain(copyCall, "user-data"), "seed carries user-data")
	assert.True(t, argsContain(copyCall, "meta-data"), "seed carries meta-data")
	assert.True(t, argsContain(copyCall, "cfgms-steward"), "seed stages the linux steward (dest cfgms-steward)")
	assert.True(t, argsContain(copyCall, "cfgms-steward-launcher"),
		"seed stages the launcher so the guest performs a launcher-managed (push-upgradeable) install")

	// OS disk made first boot; no installer media; no keypress.
	require.Len(t, callsContaining(calls, "Cfgms-SetHddFirstBoot"), 1,
		"cloud-init must make the OS disk the first boot device")
	assert.Empty(t, callsContaining(calls, "Add-VMDvdDrive"), "cloud-init attaches no install ISO")
	assert.Empty(t, callsContaining(calls, "Cfgms-BuildAnswerIso"), "cloud-init builds no answer ISO")
	assert.Empty(t, callsContaining(calls, "Cfgms-BootKeypress"), "cloud-init needs no boot keypress")
	require.Len(t, callsContaining(calls, "Start-VM"), 1, "VM is powered on")
}

// TestProvisionVM_CloudInitGen1SkipsHddFirstBoot drives an absent Gen1 linux
// cloud-image VM and asserts the cloud-init seed is still built and attached but
// Cfgms-SetHddFirstBoot is NOT issued (Gen1 uses BIOS startup order, not UEFI
// firmware boot device — same Gen1 contract as the install-media path).
func TestProvisionVM_CloudInitGen1SkipsHddFirstBoot(t *testing.T) {
	transport := &testWinRMTransport{perCallOutputs: []string{`{"found":false}`}}
	m := provisionModuleWithTransport(t, transport)

	cfg := rawConfigState{m: cloudInitVMConfigMap(1)}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, callsContaining(calls, "Cfgms-SetHddFirstBoot"),
		"Gen1 cloud-init VMs must not set a UEFI first boot device")
	assert.Empty(t, callsContaining(calls, "Set-VMFirmware"),
		"Gen1 has no secure boot / firmware step")
	// The cloud-init seed build + boot-disk prep still happen on Gen1.
	require.Len(t, callsContaining(calls, "Cfgms-PrepCloudBootDisk"), 1, "Gen1 still preps the cloud boot disk")
	require.Len(t, callsContaining(calls, "New-VHD"), 1, "Gen1 still builds the CIDATA seed")
	require.Len(t, callsContaining(calls, "Add-VMHardDiskDrive"), 1, "Gen1 still attaches the seed")
}

// TestProvision_CloudInitUserDataRenderedToSeed asserts the cloud-init path
// writes a REAL rendered cloud-config user-data (not the placeholder) carrying the
// controller-supplied token + CA fingerprint and the CorrelationID, with list-form
// runcmd and no banned patterns.
func TestProvision_CloudInitUserDataRenderedToSeed(t *testing.T) {
	transport := &testWinRMTransport{perCallOutputs: []string{`{"found":false}`}}
	m := provisionModuleWithTransport(t, transport)

	cfg := rawConfigState{m: cloudInitVMConfigMap(2)}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	copyCall := callsContaining(calls, "Set-Content")[0]
	var userData string
	for _, a := range copyCall.args {
		if s, ok := a.(string); ok && strings.Contains(s, "#cloud-config") && len(s) > len(userData) {
			userData = s
		}
	}
	require.NotEmpty(t, userData, "rendered cloud-config user-data must be present in the copy args")
	assert.Contains(t, userData, "runcmd", "user-data must carry runcmd")
	assert.Contains(t, userData, "cfgms-steward", "user-data must install the steward")
	assert.Contains(t, userData, "/opt/cfgms-steward-launcher", "user-data must stage the launcher for a launcher-managed install")
	assert.Contains(t, userData, "install", "user-data must run the steward install command")
	assert.Contains(t, userData, "reg-token-stub-value", "controller-supplied token must be rendered into user-data")
	assert.Contains(t, userData, "abc123fingerprint", "CA fingerprint must be rendered into user-data")
	assert.Contains(t, userData, "stw-01", "CorrelationID must appear in the user-data")
	// runcmd must be list/exec form (argv arrays), never shell-string composition.
	assert.Contains(t, userData, "  - [ ", "runcmd entries must be YAML list (exec) form, not shell strings")
	lower := strings.ToLower(userData)
	// CLAUDE.md banned patterns: no shell-string composition / runtime code eval.
	for _, banned := range []string{"eval", "bash -c", "sh -c", "iex", "invoke-expression", "-encodedcommand", "python -c"} {
		assert.NotContains(t, lower, banned, "rendered user-data must not contain banned pattern %q", banned)
	}
}

// ── REQUIRED TEST: installing → finalizing detaches the seed ─────────────────

// runningSourceVMJSON returns a getVM JSON response for a running VM whose
// CPU/memory/switch match sourceVMConfigMap so applyVMState issues no resize,
// start, or network reconcile — isolating the finalize behaviour under test.
func runningSourceVMJSON() string {
	return `{"found":true,"Name":"stw-01","MemoryStartupBytes":4294967296,` +
		`"ProcessorCount":2,"Generation":2,"Path":"C:\\ClusterStorage\\CSV01\\stw-01.vhdx",` +
		`"SwitchName":"HVSwitch_1G","SwitchNames":["HVSwitch_1G"],"State":"Running"}`
}

// TestProvision_InstallingToFinalizingDetachesSeed asserts that a convergence
// cycle on a VM whose record sits at installing — once the conservative settle
// window has elapsed and the VM is observed running — advances the record to
// finalizing and issues Cfgms-DetachSeedVHD (Dismount-VHD). The host-side
// module must NOT advance to ready (that is controller-side, #2050).
func TestProvision_InstallingToFinalizingDetachesSeed(t *testing.T) {
	// getVM is queried twice before detach: once by setVM (existence) and once
	// by vmIsRunning inside finalizeProvision. Both report Running.
	transport := &testWinRMTransport{
		output: runningSourceVMJSON(),
	}
	store := NewMemProvisionStore()
	// Seed an installing record whose StartedAt is well past the settle window
	// (completion.timeout is 60m → settle is 30m).
	require.NoError(t, store.SetProvision(context.Background(), &ProvisionRecord{
		VMName:        "stw-01",
		State:         ProvisionStateInstalling,
		CorrelationID: "stw-01",
		StartedAt:     time.Now().Add(-2 * time.Hour),
	}))
	m := provisionModuleWithTransport(t, transport)
	m.provisionStore = store

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	detach := callsContaining(calls, "Dismount-VHD")
	require.Len(t, detach, 1, "finalizing must issue exactly one Cfgms-DetachSeedVHD (Dismount-VHD)")
	assert.True(t, argsContain(detach[0], `C:\ClusterStorage\CSV01\cfgms-seed-stw-01.vhdx`),
		"seed path must travel via args, derived from the VM VHD directory")
	assert.NotContains(t, detach[0].scriptBlock, "cfgms-seed-stw-01",
		"seed path must not be interpolated into the script text")

	rec, err := store.GetProvision(context.Background(), "stw-01")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateFinalizing, rec.State,
		"host-side module must advance installing → finalizing")
	assert.NotEqual(t, ProvisionStateReady, rec.State,
		"host-side module must NOT advance to ready — that is controller-side (#2050)")
}

// TestProvision_InstallingNotSettledDoesNotDetach asserts that a VM whose
// installing record has not yet passed the settle window is left at installing
// with no seed detach — the conservative completion guard (ADR-009 §8).
func TestProvision_InstallingNotSettledDoesNotDetach(t *testing.T) {
	transport := &testWinRMTransport{
		output: runningSourceVMJSON(),
	}
	store := NewMemProvisionStore()
	require.NoError(t, store.SetProvision(context.Background(), &ProvisionRecord{
		VMName:        "stw-01",
		State:         ProvisionStateInstalling,
		CorrelationID: "stw-01",
		StartedAt:     time.Now(), // just started — well within the settle window
	}))
	m := provisionModuleWithTransport(t, transport)
	m.provisionStore = store

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, callsContaining(calls, "Dismount-VHD"),
		"install not yet settled must not detach the seed")

	rec, err := store.GetProvision(context.Background(), "stw-01")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateInstalling, rec.State,
		"record must remain at installing until the settle window elapses")
}

// TestProvision_RealPreseedRenderedToSeed asserts the Linux create path writes
// the REAL rendered preseed (not the placeholder) to the seed VHDX, with the
// resolved registration-token secret and the CorrelationID hostname hint
// present, and no banned patterns.
func TestProvision_RealPreseedRenderedToSeed(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`}, // getVM → absent
	}
	m := provisionModuleWithTransport(t, transport)
	require.NoError(t, m.SetSecretStore(preseedTestStore()))

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	copyCalls := callsContaining(calls, "Set-Content")
	require.Len(t, copyCalls, 1, "one Set-Content (answer file copy)")
	// The answer file name is preseed.cfg for linux.
	assert.True(t, argsContain(copyCalls[0], "preseed.cfg"), "linux must seed preseed.cfg")

	// Find the rendered content arg (the longest string arg is the preseed body).
	var content string
	for _, a := range copyCalls[0].args {
		if s, ok := a.(string); ok && len(s) > len(content) {
			content = s
		}
	}
	require.NotEmpty(t, content, "preseed content must be present in the copy args")
	assert.NotContains(t, content, "placeholder preseed", "linux path must render the REAL preseed, not the placeholder")
	assert.Contains(t, content, "d-i partman", "rendered preseed must carry partitioning directives")
	assert.Contains(t, content, "reg-token-stub-value", "registration token secret must be resolved into the preseed")
	assert.Contains(t, content, "stw-01", "CorrelationID must appear in the preseed")
	lower := strings.ToLower(content)
	for _, banned := range []string{"eval", "bash -c", "iex"} {
		assert.NotContains(t, lower, banned, "rendered preseed must not contain banned pattern %q", banned)
	}
}

// ── Provisioning record advancement ──────────────────────────────────────────

// TestProvisionVM_AdvancesRecordAbsentToInstalling asserts the create-from-source
// path advances the provisioning record absent → creating → installing with
// timestamps and the correlation identity baked in.
func TestProvisionVM_AdvancesRecordAbsentToInstalling(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	store := NewMemProvisionStore()
	m := provisionModuleWithTransport(t, transport)
	m.provisionStore = store

	cfg := rawConfigState{m: sourceVMConfigMap(2, "windows")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	rec, err := store.GetProvision(context.Background(), "stw-01")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateInstalling, rec.State,
		"host-side provisioning must end at installing (ready is controller-side, #2050)")
	assert.Equal(t, "stw-01", rec.CorrelationID, "correlation id baked from the VM name")
	assert.False(t, rec.StartedAt.IsZero(), "StartedAt must be stamped")
	assert.False(t, rec.UpdatedAt.IsZero(), "UpdatedAt must be stamped")
}

// TestProvisionVM_ResumeFromInstallingDoesNotRestart asserts that re-running the
// create-from-source path while a record already sits at installing does not
// rebuild the seed or re-attach media (no restart from absent — ADR-009 §2).
func TestProvisionVM_ResumeFromInstallingDoesNotRestart(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	store := NewMemProvisionStore()
	require.NoError(t, store.SetProvision(context.Background(), &ProvisionRecord{
		VMName:        "stw-01",
		State:         ProvisionStateInstalling,
		CorrelationID: "stw-01",
	}))
	m := provisionModuleWithTransport(t, transport)
	m.provisionStore = store

	cfg := rawConfigState{m: sourceVMConfigMap(2, "windows")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// The VM is still absent on the host (getVM → not found) so createVM runs,
	// but provisionVM must short-circuit on the installing record: no seed
	// rebuild, no media re-attach, no firmware re-apply.
	assert.Empty(t, callsContaining(calls, "New-VHD"),
		"resume from installing must not rebuild the seed VHDX")
	assert.Empty(t, callsContaining(calls, "Add-VMDvdDrive"),
		"resume from installing must not re-attach the install ISO")
	assert.Empty(t, callsContaining(calls, "Set-VMFirmware"),
		"resume from installing must not re-apply firmware")
}

// TestProvisionVM_NoSourceSkipsProvisioning asserts a plain absent VM (no
// source) takes the normal lifecycle path: no seed build, no media attach, and
// no provisioning record written.
func TestProvisionVM_NoSourceSkipsProvisioning(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	store := NewMemProvisionStore()
	m := provisionModuleWithTransport(t, transport)
	m.provisionStore = store

	cfg := rawConfigState{m: map[string]interface{}{
		"name":        "plain-vm",
		"memory_mb":   2048,
		"cpu_count":   2,
		"vhd_path":    `C:\VMs\plain-vm.vhdx`,
		"generation":  2,
		"state":       "running",
		"switch_name": "sw-a",
	}}
	require.NoError(t, m.Set(context.Background(), "vm:plain-vm", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, callsContaining(calls, "New-VHD"), "no source: no seed build")
	assert.Empty(t, callsContaining(calls, "Add-VMDvdDrive"), "no source: no ISO attach")
	assert.Empty(t, callsContaining(calls, "Set-VMFirmware"), "no source: no firmware step")

	_, err := store.GetProvision(context.Background(), "plain-vm")
	assert.ErrorIs(t, err, ErrProvisionNotFound, "no source: no provisioning record")
}

// ── REQUIRED TEST: seed VHDX + answer media deleted post-finalizing ──────────

// TestProvision_FinalizeDeletesSeedMediaPostDetach is the REQUIRED TEST
// (ADR-010 §5 / Issue #2081). It proves that when a VM's installing record
// passes the settle window and the VM is running, finalizeProvision:
//  1. Issues Dismount-VHD (detach) before Remove-Item (delete).
//  2. Issues Remove-Item for BOTH the seed VHDX path and the answer ISO path
//     — idempotent, so a non-existent file is not an error.
//  3. Advances the record to finalizing (not ready — that is controller-side).
//
// The delete is issued post-finalizing in the sense that it is part of the
// same convergence cycle that advances the record to finalizing, bounding the
// on-disk join-token window to that single cycle. A second convergence cycle
// on the same (now-finalizing) record issues no further Remove-Item calls,
// proving system-level idempotency.
func TestProvision_FinalizeDeletesSeedMediaPostDetach(t *testing.T) {
	transport := &testWinRMTransport{
		output: runningSourceVMJSON(),
	}
	store := NewMemProvisionStore()
	require.NoError(t, store.SetProvision(context.Background(), &ProvisionRecord{
		VMName:        "stw-01",
		State:         ProvisionStateInstalling,
		CorrelationID: "stw-01",
		StartedAt:     time.Now().Add(-2 * time.Hour),
	}))
	m := provisionModuleWithTransport(t, transport)
	m.provisionStore = store

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// Detach must precede delete — both path values travel via args, never the
	// script text (ADR-009 §5 — no user-controlled value in script).
	detach := callsContaining(calls, "Dismount-VHD")
	require.Len(t, detach, 1, "finalizing must issue exactly one Dismount-VHD")
	assert.True(t, argsContain(detach[0], `C:\ClusterStorage\CSV01\cfgms-seed-stw-01.vhdx`),
		"seed path must travel via args")
	assert.NotContains(t, detach[0].scriptBlock, "cfgms-seed-stw-01",
		"seed path must not be interpolated into the script text")

	// Remove-Item is issued for both the seed VHDX and the answer ISO — both
	// paths travel via args only. SilentlyContinue makes it idempotent.
	deletes := callsContaining(calls, "Remove-Item")
	require.GreaterOrEqual(t, len(deletes), 2, "finalizing must issue Remove-Item for both seed VHDX and answer ISO")
	seedPaths := make([]string, 0, len(deletes))
	for _, d := range deletes {
		for _, a := range d.args {
			if s, ok := a.(string); ok && strings.Contains(s, "cfgms-") {
				seedPaths = append(seedPaths, s)
			}
		}
	}
	assert.Contains(t, seedPaths, `C:\ClusterStorage\CSV01\cfgms-seed-stw-01.vhdx`,
		"seed VHDX must be deleted via args")
	for _, d := range deletes {
		assert.Contains(t, d.scriptBlock, "SilentlyContinue",
			"seed media delete must be idempotent (SilentlyContinue)")
		assert.NotContains(t, d.scriptBlock, "cfgms-seed-stw-01",
			"path must not be interpolated into the delete script text")
	}

	// Detach must precede the first Remove-Item in the recorded call sequence.
	detachIdx := -1
	firstDeleteIdx := -1
	for i, c := range calls {
		if strings.Contains(c.scriptBlock, "Dismount-VHD") && detachIdx < 0 {
			detachIdx = i
		}
		if strings.Contains(c.scriptBlock, "Remove-Item") && firstDeleteIdx < 0 {
			firstDeleteIdx = i
		}
	}
	require.Greater(t, detachIdx, -1, "Dismount-VHD must be recorded")
	require.Greater(t, firstDeleteIdx, -1, "Remove-Item must be recorded")
	assert.Less(t, detachIdx, firstDeleteIdx, "Dismount-VHD must precede Remove-Item")

	// Record must be at finalizing after the cycle.
	rec, err := store.GetProvision(context.Background(), "stw-01")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateFinalizing, rec.State,
		"record must advance to finalizing after detach+delete")

	// ── Idempotency: a second convergence cycle on the now-finalizing record
	// must NOT issue another Dismount-VHD or Remove-Item.
	transport.mu.Lock()
	transport.calls = nil
	transport.mu.Unlock()

	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls2 := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, callsContaining(calls2, "Dismount-VHD"),
		"second cycle on finalizing record must not re-detach the seed")
	assert.Empty(t, callsContaining(calls2, "Remove-Item"),
		"second cycle on finalizing record must not re-delete seed media")
}

// TestProvision_WindowsFinalizeDeletesAnswerISO asserts the Windows path
// (answer ISO, not seed VHDX) issues Remove-Item for the answer ISO path on
// finalization. The seed VHDX path is also attempted (idempotent no-op since
// it never existed for Windows VMs).
func TestProvision_WindowsFinalizeDeletesAnswerISO(t *testing.T) {
	vmJSON := `{"found":true,"Name":"stw-01","MemoryStartupBytes":4294967296,` +
		`"ProcessorCount":2,"Generation":2,"Path":"C:\\ClusterStorage\\CSV01\\stw-01.vhdx",` +
		`"SwitchName":"HVSwitch_1G","SwitchNames":["HVSwitch_1G"],"State":"Running"}`
	transport := &testWinRMTransport{output: vmJSON}
	store := NewMemProvisionStore()
	require.NoError(t, store.SetProvision(context.Background(), &ProvisionRecord{
		VMName:        "stw-01",
		State:         ProvisionStateInstalling,
		CorrelationID: "stw-01",
		StartedAt:     time.Now().Add(-2 * time.Hour),
	}))
	m := provisionModuleWithTransport(t, transport)
	m.provisionStore = store

	cfg := rawConfigState{m: sourceVMConfigMap(2, "windows")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	deletes := callsContaining(calls, "Remove-Item")
	require.GreaterOrEqual(t, len(deletes), 1, "windows finalization must issue Remove-Item for answer ISO")

	isoPaths := make([]string, 0)
	for _, d := range deletes {
		for _, a := range d.args {
			if s, ok := a.(string); ok && strings.Contains(s, "cfgms-answer") {
				isoPaths = append(isoPaths, s)
			}
		}
	}
	assert.Contains(t, isoPaths, `C:\ClusterStorage\CSV01\cfgms-answer-stw-01.iso`,
		"answer ISO path must be deleted for the windows path")
}

// TestProvision_FinalizeDeleteSeedMediaErrorDoesNotBlockAdvance asserts that a
// transient ExecutePS failure on psDeleteSeedMedia does NOT fail the provision
// or block the record from advancing to finalizing. The detach (psDetachSeedVHD)
// already removed the answer file from the guest's visible media; the delete is
// a best-effort on-disk cleanup, and the TTL sweep is the safety net for any
// failed deletes. A failed delete must log a warning and continue.
func TestProvision_FinalizeDeleteSeedMediaErrorDoesNotBlockAdvance(t *testing.T) {
	// Call sequence when an installing record is past the settle window and the VM
	// is running:
	//   0: getVM (existence check in setVM)        → Running
	//   1: getVM (vmIsRunning in finalizeProvision) → Running
	//   2: psDetachSeedVHD                          → success
	//   3: psDeleteSeedMedia (seed VHDX path)       → ERROR (simulated transient failure)
	//   4: psDeleteSeedMedia (answer ISO path)      → success (continue after error)
	deleteErr := fmt.Errorf("PS host: Remove-Item failed (access denied)")
	transport := &testWinRMTransport{
		output:        runningSourceVMJSON(),
		perCallErrors: []error{nil, nil, nil, deleteErr},
	}
	store := NewMemProvisionStore()
	require.NoError(t, store.SetProvision(context.Background(), &ProvisionRecord{
		VMName:        "stw-01",
		State:         ProvisionStateInstalling,
		CorrelationID: "stw-01",
		StartedAt:     time.Now().Add(-2 * time.Hour),
		UpdatedAt:     time.Now().Add(-2 * time.Hour),
	}))
	m := provisionModuleWithTransport(t, transport)
	m.provisionStore = store

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")}
	// Must succeed — a failed seed-media delete is non-fatal.
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg),
		"failed seed-media delete must not propagate as a provision failure")

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// Detach must still run.
	require.Len(t, callsContaining(calls, "Dismount-VHD"), 1)
	// Both Remove-Item calls must be issued (error on first does not skip second).
	require.Len(t, callsContaining(calls, "Remove-Item"), 2,
		"both seed VHDX and answer ISO Remove-Item calls must be attempted even after error on first")

	// Record must advance to finalizing despite the failed delete.
	rec, err := store.GetProvision(context.Background(), "stw-01")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateFinalizing, rec.State,
		"record must still advance to finalizing when seed-media delete fails")
}

// TestProvision_SweepNilGuardsAreNoop asserts that sweepStaleSeedMedia returns
// silently when the provision store or transport are nil, without panicking.
func TestProvision_SweepNilGuardsAreNoop(t *testing.T) {
	// nil provisionStore
	m1 := &hypervModule{
		transport:      &testWinRMTransport{},
		provisionStore: nil,
		vms:            make(map[string]VMConfig),
	}
	require.NotPanics(t, func() { m1.sweepStaleSeedMedia(context.Background()) },
		"nil provisionStore must not panic")

	// nil transport
	m2 := &hypervModule{
		transport:      nil,
		provisionStore: NewMemProvisionStore(),
		vms:            make(map[string]VMConfig),
	}
	require.NotPanics(t, func() { m2.sweepStaleSeedMedia(context.Background()) },
		"nil transport must not panic")
}

// TestProvision_SweepDeletesStaleSeedMedia asserts that sweepStaleSeedMedia
// issues Remove-Item for a stale provision record's seed paths when the record
// is older than seedMediaTTL, without affecting a fresh record.
func TestProvision_SweepDeletesStaleSeedMedia(t *testing.T) {
	transport := &testWinRMTransport{output: runningSourceVMJSON()}
	store := NewMemProvisionStore()

	// Stale record: updated 48h ago — well past seedMediaTTL.
	stalePast := time.Now().Add(-48 * time.Hour)
	require.NoError(t, store.SetProvision(context.Background(), &ProvisionRecord{
		VMName:        "stale-vm",
		State:         ProvisionStateFinalizing,
		CorrelationID: "stale-vm",
		StartedAt:     stalePast,
		UpdatedAt:     stalePast,
	}))

	// Fresh record: updated just now — within the TTL window, must not be swept.
	require.NoError(t, store.SetProvision(context.Background(), &ProvisionRecord{
		VMName:        "fresh-vm",
		State:         ProvisionStateInstalling,
		CorrelationID: "fresh-vm",
		StartedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}))

	// Wire a VHD path for stale-vm so the sweep can derive the media path.
	m := provisionModuleWithTransport(t, transport)
	m.provisionStore = store
	m.seedDir = `C:\cfgms-seeds`
	m.vmsMu.Lock()
	m.vms["stale-vm"] = VMConfig{VHDPath: `C:\VMs\stale-vm.vhdx`}
	m.vmsMu.Unlock()

	m.sweepStaleSeedMedia(context.Background())

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	deletes := callsContaining(calls, "Remove-Item")
	require.GreaterOrEqual(t, len(deletes), 1, "sweep must issue Remove-Item for the stale record")

	// The stale-vm seed paths must appear in the delete args.
	var deletedPaths []string
	for _, d := range deletes {
		for _, a := range d.args {
			if s, ok := a.(string); ok && strings.Contains(s, "stale-vm") {
				deletedPaths = append(deletedPaths, s)
			}
		}
	}
	assert.NotEmpty(t, deletedPaths, "stale-vm seed media paths must be deleted by the sweep")

	// The fresh-vm paths must NOT appear in the delete args.
	for _, d := range deletes {
		for _, a := range d.args {
			if s, ok := a.(string); ok {
				assert.NotContains(t, s, "fresh-vm",
					"fresh record must not be swept before TTL expires")
			}
		}
	}
}
