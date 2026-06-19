// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
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
func provisionModuleWithTransport(transport winrmTransport) *hypervModule {
	m := &hypervModule{
		executor:       &stubHypervExecutor{},
		transport:      transport,
		tenantID:       "ops",
		vms:            make(map[string]VMConfig),
		detector:       &fakeDetector{result: true},
		provisionStore: NewMemProvisionStore(),
	}
	// Inject a single in-memory SecretStore carrying every key both OS create
	// paths resolve at render time so the create-from-source provisioning tests
	// exercise the real render path (no mocks):
	//   - Linux preseed (#2046): registration token + crypted user password
	//   - Windows autounattend (#2047): .ppkg host path + registration token
	// defaultRegTokenSecretKey is "hyperv/enroll/regtoken", shared by both paths.
	_ = m.SetSecretStore(newInlineStore(
		"hyperv/enroll/regtoken", "reg-token-stub-value",
		"hyperv/enroll/user-password-crypted", "$6$rounds=4096$stub$cryptedstub",
		ppkgPathSecretKey, `C:\cfgms\packages\cfgms-enroll.ppkg`,
	))
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
	m := provisionModuleWithTransport(transport)

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
	m := provisionModuleWithTransport(transport)

	cfg := rawConfigState{m: sourceVMConfigMap(2, "windows")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	fw := callsContaining(calls, "Set-VMFirmware")
	require.Len(t, fw, 1, "Gen2 VM must call Set-VMFirmware exactly once")
	assert.True(t, argsContain(fw[0], "MicrosoftWindows"),
		"windows os_family must select the MicrosoftWindows template")
	assert.NotContains(t, fw[0].scriptBlock, "MicrosoftWindows",
		"firmware template must travel via args, not the script text")
}

// TestProvisionVM_Gen2LinuxFirmwareTemplate asserts the linux os_family selects
// the MicrosoftUEFICertificateAuthority template on the Gen2 source path.
func TestProvisionVM_Gen2LinuxFirmwareTemplate(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	m := provisionModuleWithTransport(transport)

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	fw := callsContaining(calls, "Set-VMFirmware")
	require.Len(t, fw, 1)
	assert.True(t, argsContain(fw[0], "MicrosoftUEFICertificateAuthority"),
		"linux os_family must select the MicrosoftUEFICertificateAuthority template")
}

// ── Seed VHDX build + attach sequence ────────────────────────────────────────

// TestProvisionVM_SeedVHDBuildAndAttachSequence drives an absent Gen2 windows
// VM with a source block and asserts the full seed build + media attach
// sequence is emitted in order: New-VHD → Format-Volume (Mount) → Set-Content
// (copy) → Add-VMHardDiskDrive (seed attach) → Add-VMDvdDrive (ISO).
func TestProvisionVM_SeedVHDBuildAndAttachSequence(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	m := provisionModuleWithTransport(transport)

	cfg := rawConfigState{m: sourceVMConfigMap(2, "windows")}
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
	assert.True(t, argsContain(copy, "autounattend.xml"),
		"windows os_family must seed autounattend.xml")
}

// TestProvisionVM_AttachesInstallISOFromHostPath asserts the install ISO is
// attached from the host path via args, never repacked or interpolated.
func TestProvisionVM_AttachesInstallISOFromHostPath(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	m := provisionModuleWithTransport(transport)

	cfg := rawConfigState{m: sourceVMConfigMap(2, "windows")}
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
	m := provisionModuleWithTransport(transport)
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
	m := provisionModuleWithTransport(transport)
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
	m := provisionModuleWithTransport(transport)
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
	m := provisionModuleWithTransport(transport)
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
	m := provisionModuleWithTransport(transport)
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
	m := provisionModuleWithTransport(transport)
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
