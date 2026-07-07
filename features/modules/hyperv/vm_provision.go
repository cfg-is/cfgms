// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// ── Provisioning PS verb constants (ADR-009 §5) ────────────────────────────
//
// These are platform-neutral const strings: they are the dispatch keys the
// Windows transport (pstransport_dispatch_windows.go) pattern-matches and the
// scriptBlock the test transport records. They are NOT executed directly on
// non-Windows — the production PS host transport only exists on Windows — but
// the create-from-source orchestration in provisionVM() runs on every platform
// (driven by the recording transport in tests), so the consts cannot be
// gated behind a build tag.
//
// All user-controlled values (seed path, VM name, ISO path, file name,
// answer-file content, firmware template) travel via PS function parameters
// over ArgumentList — never interpolated into the script text. The dispatcher
// maps each const to its Cfgms-* preamble function.

const (
	// psNewSeedVHD ensures the seed's parent directory exists (seed_dir may be a
	// fresh local path), then wraps New-VHD to create the empty dynamic seed disk.
	psNewSeedVHD = `New-Item -ItemType Directory -Force -Path (Split-Path -Path $Path -Parent) | Out-Null; New-VHD -Path $Path -SizeBytes $SizeBytes -Dynamic | Out-Null`

	// psMountSeedVHD wraps the Mount-VHD → Initialize-Disk → New-Partition →
	// Format-Volume pipeline: lay a FAT32 CFGMS_SEED volume on the seed disk, then
	// Dismount-VHD. The trailing dismount is REQUIRED: Mount-VHD attaches the VHD
	// host-wide (not process-scoped), so without it the disk stays mounted after
	// this PS process exits and the subsequent psCopyToSeedVHD Mount-VHD fails with
	// a sharing violation (0x80070020 "being used by another process"). The
	// formatted volume persists on the (now-detached) VHD for the copy step to
	// re-mount.
	//
	// This const is the script the WinRM transport runs directly (buildInvokeCommand
	// wraps it as Invoke-Command); the ps-host transport instead dispatches to the
	// preamble's Cfgms-MountSeedVHD. The two must agree on the PARAMETER CONTRACT —
	// $Label (optional) selects the FAT32 volume label: legacy preseed/windows
	// callers omit it (so it is $null on WinRM → defaults to CFGMS_SEED), the
	// cloud-init path passes CIDATA. (The ps-host preamble additionally hardens the
	// trailing dismount with a verify-loop, Cfgms-DismountAndVerify, which the bare
	// WinRM const text below does not replicate — WinRM is the secondary transport.)
	psMountSeedVHD = `Mount-VHD -Path $Path -Passthru | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem FAT32 -NewFileSystemLabel $(if ($Label) { $Label } else { 'CFGMS_SEED' }) -Confirm:$false | Out-Null; Dismount-VHD -Path $Path`

	// psCopyToSeedVHD mounts the seed (volume matched by $Label, default
	// CFGMS_SEED), writes $Content to <drive>:\$FileName and — when supplied — a
	// second file $Content2 to <drive>:\$FileName2 (the cloud-init path writes both
	// user-data and meta-data). It optionally stages the steward binary ($StewardSrc
	// → $StewardDest, default cfgms-steward.exe; the linux cloud-init path passes
	// cfgms-steward) and controller CA ($CASrc → <drive>:\controller-ca.crt) so the
	// guest can self-install + enroll offline (ADR-010), and dismounts. All values
	// travel via ArgumentList; empty optional params fall back to their defaults.
	// WinRM-transport variant of the preamble's Cfgms-CopyToSeedVHD — same parameter
	// contract; the preamble adds the verify-dismount hardening (see psMountSeedVHD).
	psCopyToSeedVHD = `$disk = Mount-VHD -Path $SeedPath -Passthru; $label = $(if ($Label) { $Label } else { 'CFGMS_SEED' }); $letter = ($disk | Get-Disk | Get-Partition | Get-Volume | Where-Object { $_.FileSystemLabel -eq $label } | Select-Object -First 1).DriveLetter; Set-Content -Path ($letter + ':\' + $FileName) -Value $Content -NoNewline; if ($FileName2) { Set-Content -Path ($letter + ':\' + $FileName2) -Value $Content2 -NoNewline }; if ($StewardSrc -and (Test-Path -LiteralPath $StewardSrc)) { Copy-Item -LiteralPath $StewardSrc -Destination ($letter + ':\' + $(if ($StewardDest) { $StewardDest } else { 'cfgms-steward.exe' })) -Force }; if ($LauncherSrc -and (Test-Path -LiteralPath $LauncherSrc)) { Copy-Item -LiteralPath $LauncherSrc -Destination ($letter + ':\' + $(if ($LauncherDest) { $LauncherDest } else { 'cfgms-steward-launcher' })) -Force }; if ($CASrc -and (Test-Path -LiteralPath $CASrc)) { Copy-Item -LiteralPath $CASrc -Destination ($letter + ':\controller-ca.crt') -Force }; Dismount-VHD -Path $SeedPath`

	// psDetachSeedVHD wraps Dismount-VHD (called at finalizing, not in the
	// create path this story implements).
	psDetachSeedVHD = `Dismount-VHD -Path $Path -ErrorAction SilentlyContinue`

	// psDeleteSeedMedia removes a staged seed file (seed VHDX or answer ISO)
	// after enrollment. Idempotent — SilentlyContinue means an already-absent
	// file is not an error. The path travels via ArgumentList only; it is never
	// interpolated into the script text.
	psDeleteSeedMedia = `Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue`

	// psAttachSeedDisk wraps Add-VMHardDiskDrive: attach the seed VHDX as the
	// VM's secondary disk.
	psAttachSeedDisk = `Add-VMHardDiskDrive -VMName $Name -Path $SeedPath`

	// psAttachDVD wraps Add-VMDvdDrive: attach the install ISO as the VM's DVD
	// drive. The ISO is never repacked or re-signed.
	psAttachDVD = `Add-VMDvdDrive -VMName $Name -Path $ISOPath`

	// psSetDVDFirstBoot makes the install DVD the Gen2 firmware's first boot
	// device. Without this a freshly-created Gen2 VM boots the empty OS VHD (no
	// bootloader) instead of the installer ISO, so the unattended install never
	// starts. Gen1 VMs use BIOS startup order (CD precedes IDE by default) and
	// never reach this.
	psSetDVDFirstBoot = `$dvd = Get-VMDvdDrive -VMName $Name | Select-Object -First 1; Set-VMFirmware -VMName $Name -FirstBootDevice $dvd`

	// psSetVMFirmware wraps Set-VMFirmware: select the Gen2 secure-boot
	// template. Gen1 VMs never reach this.
	psSetVMFirmware = `Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate $Template`

	// psBuildAnswerIso builds a small ISO carrying the rendered answer file
	// (+ steward binary + CA) for the Windows path: the new Server 2025 Setup
	// scans DVD roots for autounattend.xml but NOT data disks, so the answer file
	// is delivered on an ISO attached as a second DVD (built natively via IMAPI2).
	psBuildAnswerIso = `Cfgms-BuildAnswerIso`

	// psBootKeypress drives the VM keyboard after power-on to satisfy the Windows
	// install media's "Press any key to boot from CD or DVD" prompt.
	psBootKeypress = `Cfgms-BootKeypress`

	// ── cloud-init (Linux VM-from-cloud-image) path (ADR-009 §6) ─────────────
	//
	// psPrepCloudBootDisk prepares the VM's boot disk from a cloud image: a raw
	// image is wrapped with a fixed-VHD footer and converted to a dynamic VHDX (a
	// .vhdx image is copied as-is), optionally resized. Host-native — no qemu-img,
	// no xorriso, no WSL. The cloud image's signed bootloader is never modified.
	psPrepCloudBootDisk = `Cfgms-PrepCloudBootDisk`

	// psCreateVMFromDisk creates a VM that boots an EXISTING prepared disk
	// (New-VM -VHDPath), used by the cloud-init path where the boot disk is the
	// converted cloud image rather than a freshly-created empty VHD.
	psCreateVMFromDisk = `Cfgms-CreateVMFromDisk`

	// psSetHddFirstBoot makes the OS hard disk (matched by path) the Gen2
	// firmware's first boot device, so a cloud-init VM boots the cloud image
	// rather than the attached CIDATA seed disk.
	psSetHddFirstBoot = `Cfgms-SetHddFirstBoot`
)

// gibibyte is 1024^3, used to convert source.resize_gb into a byte count for the
// cloud boot-disk resize (0 means "leave at native size").
const gibibyte = int64(1) << 30

// seedMediaTTL is the maximum time staged seed media (seed VHDX, answer ISO)
// may remain on disk after the provision record's last update. The TTL sweep
// (sweepStaleSeedMedia) catches orphaned media from failed or aborted
// provisions — bounding the on-disk join-token window even when the per-VM
// finalizeProvision delete was never reached (e.g. the VM was deleted
// mid-install).
const seedMediaTTL = 24 * time.Hour

// secureBootTemplate returns the Gen2 secure-boot firmware template for the
// given os_family. Windows guests use the Microsoft Windows template; Linux
// guests (and any non-Windows UEFI guest) use the third-party UEFI CA template
// so shim/grub signed by the UEFI CA validate. Gen1 VMs have no secure boot
// and never call this (ADR-009 §5).
func secureBootTemplate(osFamily string) string {
	if osFamily == "windows" {
		return "MicrosoftWindows"
	}
	return "MicrosoftUEFICertificateAuthority"
}

// seedAnswerFileName returns the answer-file name for the os_family. Windows
// Setup auto-reads autounattend.xml from removable media; debian-installer
// reads preseed.cfg from the labelled seed volume (ADR-009 §6).
func seedAnswerFileName(osFamily string) string {
	if osFamily == "windows" {
		return "autounattend.xml"
	}
	return "preseed.cfg"
}

// seedAnswerFilePlaceholder returns the placeholder answer-file content for the
// os_family when no real profile can be resolved. The Windows path (#2047)
// renders a real autounattend.xml via renderSeedAnswerFile; this stub remains
// only for the Linux path (#2046) and as a defensive fallback. The content is a
// one-line comment stub so the seed VHDX is non-empty.
func seedAnswerFilePlaceholder(osFamily string) string {
	if osFamily == "windows" {
		return "<!-- placeholder autounattend -->"
	}
	return "# placeholder preseed"
}

// resolveProfile resolves the unattended-install profile for a VM source by
// os_family. When the source declares a profile:// reference it is loaded from
// the profileStore; otherwise the built-in default for the os_family is used:
// the Debian 12 profile for linux (#2046) and the Windows Server profile for
// windows (#2047). An unsupported os_family returns nil, nil so the caller
// falls back to the os_family placeholder.
func (m *hypervModule) resolveProfile(ctx context.Context, src *SourceConfig) (*UnattendProfile, error) {
	switch src.OSFamily {
	case "linux":
		return m.resolveLinuxProfile(ctx, src)
	case "windows":
		return m.resolveWindowsProfile(ctx, src.Unattend)
	default:
		return nil, nil
	}
}

// resolveWindowsProfile returns the UnattendProfile for a Windows VM source.
// When the source references a profile (profile://<name>) it is loaded from the
// profile store; when no reference is given the built-in Windows Server profile
// is used so a minimal Windows source ("iso" + "os_family: windows") provisions
// without operator-authored config (ADR-009 §6/§7).
func (m *hypervModule) resolveWindowsProfile(ctx context.Context, unattendRef string) (*UnattendProfile, error) {
	if unattendRef == "" {
		return defaultWindowsProfile(), nil
	}
	name, err := parseProfileName(unattendRef)
	if err != nil {
		return nil, err
	}
	if m.profileStore == nil {
		return nil, fmt.Errorf("hyperv: profile %q referenced but no profile store configured: %w", name, ErrProfileNotFound)
	}
	profile, err := m.profileStore.GetProfile(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("hyperv: load profile %q: %w", name, err)
	}
	return profile, nil
}

// renderSeedAnswerFile resolves the profile for the VM source and renders the
// answer-file content written to the seed VHDX, dispatching on os_family. For
// os_family: linux it renders the REAL preseed (#2046) from the referenced (or
// built-in Debian) profile; for os_family: windows it renders the real
// autounattend.xml (#2047) from the referenced (or built-in Windows) profile,
// substituting the product edition. Both bake the per-VM CorrelationID in so the
// controller-side reconciler (#2050) can match the registered steward
// (ADR-009 §8). Secret values referenced via {{ secret "key" }} (e.g. the .ppkg
// host path) are resolved from the injected SecretStore at render time and are
// never logged. When no profile resolves (an unsupported os_family), it falls
// back to the os_family placeholder.
func (m *hypervModule) renderSeedAnswerFile(ctx context.Context, vmName string, src *SourceConfig, correlationID string) (string, error) {
	profile, err := m.resolveProfile(ctx, src)
	if err != nil {
		return "", err
	}
	if profile == nil {
		return seedAnswerFilePlaceholder(src.OSFamily), nil
	}

	store, injected := m.GetSecretStore()
	if !injected || store == nil {
		return "", errSecretStoreRequired
	}

	vars := ProfileVars{
		VMName:        vmName,
		OSFamily:      src.OSFamily,
		CorrelationID: correlationID,
		BundleURL:     profile.Enroll.BundleURL,
		// Controller-supplied enrollment values (ADR-010 §2/§4): the join token
		// and CA fingerprint ride the config sync, not the local SecretStore.
		// The default Windows/Linux profiles reference {{ .EnrollToken }} /
		// {{ .CAFingerprint }} directly so render no longer depends on the
		// (operator-unwritable) SecretStore for the token (#2077 fix).
		EnrollToken:   m.enrollToken,
		CAFingerprint: m.enrollCAFingerprint,
		// Optional operator-provided debug SSH public key (diagnose failed enroll).
		DebugSSHKey: m.debugSSHAuthorizedKey,
	}
	// A per-VM random password is generated for both families: Windows uses it
	// for the one-shot AutoLogon that runs enrollment; Linux uses it for the
	// local cfgms user (the steward is the management path, so the value is
	// never surfaced — ADR-010 §4 "randomize it").
	pw, pwErr := randomAdminPassword()
	if pwErr != nil {
		return "", fmt.Errorf("hyperv: generate provisioning password for VM %q: %w", vmName, pwErr)
	}
	vars.AdminPassword = pw

	// ProductEdition only applies to the Windows autounattend image-install step;
	// it is ignored by the Linux preseed template.
	if src.OSFamily == "windows" {
		vars.ProductEdition = defaultWindowsEdition
		if src.Edition != "" {
			vars.ProductEdition = src.Edition
		}
	}

	rendered, err := NewProfileRenderer().Render(ctx, profile, vars, store)
	if err != nil {
		return "", err
	}
	return string(rendered), nil
}

// seedVHDPath derives the seed VHDX path. When seedDir is set (module config
// seed_dir) the seed lands there: <seedDir>\cfgms-seed-<vmName>.vhdx. Otherwise
// it lands next to the VM's primary disk: <vhdDir>\cfgms-seed-<vmName>.vhdx.
//
// IMPORTANT: the seed must NOT live on a Cluster Shared Volume
// (C:\ClusterStorage\...). Mount-VHD against a VHDX on a CSV hangs on a cluster
// node (CSV redirected-I/O / cluster coordination), stalling the whole seed
// build. The seed is ephemeral (built, attached for install, detached and
// deleted at finalize), so seed_dir should point at a local, non-CSV directory
// even when the VM's own VHD lives on CSV.
//
// The parent directory is computed with Windows path semantics (split on \ or /)
// rather than filepath.Dir, which is OS-dependent: filepath.Dir("C:\\dir\\x.vhdx")
// returns "." on Linux (it does not treat "\" as a separator), mangling the
// always-Windows Hyper-V path when the steward or CI runs on a non-Windows OS
// (Issue #2044).
func seedVHDPath(vmName, vhdPath, seedDir string) string {
	dir := seedDir
	if dir == "" {
		dir = vhdPath
		if i := strings.LastIndexAny(vhdPath, `\/`); i >= 0 {
			dir = vhdPath[:i]
		}
	}
	dir = strings.TrimRight(dir, `\/`)
	return dir + `\` + "cfgms-seed-" + vmName + ".vhdx"
}

// answerISOPath derives the Windows answer-ISO path, mirroring seedVHDPath's
// directory rules (seed_dir when set, else next to the VM's VHD). The answer ISO
// carries autounattend.xml (+ steward binary + CA) and is attached as a second
// DVD so the new Server 2025 Setup auto-discovers it (it does not scan data
// disks). Must be a local, non-CSV path for the same reason as the seed.
func answerISOPath(vmName, vhdPath, seedDir string) string {
	dir := seedDir
	if dir == "" {
		dir = vhdPath
		if i := strings.LastIndexAny(vhdPath, `\/`); i >= 0 {
			dir = vhdPath[:i]
		}
	}
	dir = strings.TrimRight(dir, `\/`)
	return dir + `\` + "cfgms-answer-" + vmName + ".iso"
}

// validateSeedPath rejects a seed path that is not a safe absolute Windows
// path before it can reach the PS transport. A non-absolute path (no drive
// letter) and a UNC path (\\server\share) are both rejected: the seed must
// live on a local/CSV drive next to the VM's VHD, never on an arbitrary
// network share. Defense-in-depth even though the value travels via
// ArgumentList.
func validateSeedPath(path string) error {
	if strings.HasPrefix(path, `\\`) {
		return ErrInvalidSeedPath
	}
	if !vhdPathPattern.MatchString(path) {
		return ErrInvalidSeedPath
	}
	return nil
}

// provisionVM performs the create-from-source flow for a VM that was just
// created by createVM and carries a source block (ADR-009 §3, §5). It:
//
//  1. resumes from / initialises the provisioning record (absent → creating);
//  2. selects the Gen2 secure-boot firmware template by os_family (Gen1 skips);
//  3. builds the seed VHDX (New-VHD → Mount/format → copy answer file);
//  4. attaches the seed VHDX as the secondary disk;
//  5. attaches the install ISO as the DVD (never repacked/re-signed);
//  6. powers the VM on and advances the record to installing.
//
// The ready transition is controller-side (#2050) and is NOT performed here —
// the host-side module stops at installing.
func (m *hypervModule) provisionVM(ctx context.Context, vmName, hostName string, cfg *VMConfig) error {
	if cfg.Source == nil {
		return nil
	}

	// Resolve the provisioning record. Resuming from an in-progress record must
	// NOT restart from absent (ADR-009 §2 safety invariant): if a record exists
	// at installing/finalizing, the steps below have already run and we leave it.
	record, err := m.loadOrInitProvision(ctx, vmName)
	if err != nil {
		return err
	}
	if record.State == ProvisionStateInstalling ||
		record.State == ProvisionStateFinalizing ||
		record.State == ProvisionStateReady {
		// Already past the host-side create steps — nothing to redo here. For an
		// installing record the seed-detach + installing → finalizing transition
		// is driven by the converge path via finalizeProvision (which applies the
		// conservative settle-time + running guard); the ready transition is
		// controller-side (#2050).
		return nil
	}

	// absent → creating once the VM and disks exist.
	if err := m.advanceProvision(ctx, vmName, record, ProvisionStateCreating); err != nil {
		return err
	}

	generation := cfg.Generation
	if generation == 0 {
		generation = 2
	}

	cfgResourceID := "vm:" + vmName

	// Gen2 secure-boot template by os_family; Gen1 has no UEFI/secure boot.
	if generation == 2 {
		template := secureBootTemplate(cfg.Source.OSFamily)
		if _, psErr := m.transport.ExecutePS(ctx, psSetVMFirmware, map[string]string{
			"Name":     hostName,
			"Template": template,
		}); psErr != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-VMFirmware", cfgResourceID, nil, nil, psErr)
			return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: set firmware for VM %q: %w", vmName, psErr))
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-VMFirmware", cfgResourceID, nil, nil, nil)
	}

	// cloud-init (Linux VM-from-cloud-image): the boot disk (already prepared
	// from the cloud image by createVM) carries its own OS + cloud-init. There is
	// NO installer and NO install ISO — enrollment rides a NoCloud CIDATA seed
	// VHDX (user-data + meta-data + steward + CA) that cloud-init auto-detects on
	// first boot. Build + attach that seed, make the OS disk the first boot
	// device, and we're done (no DVD, no keypress).
	if cfg.Source.isCloudInit() {
		if err := m.provisionCloudInit(ctx, vmName, hostName, cfg, record, generation); err != nil {
			return err
		}
		if err := m.execStartVM(ctx, cfgResourceID, hostName,
			map[string]interface{}{"state": "stopped"},
			map[string]interface{}{"state": "running"}); err != nil {
			return m.failProvision(ctx, vmName, record, err)
		}
		return m.advanceProvision(ctx, vmName, record, ProvisionStateInstalling)
	}

	// Render the unattended answer file (os_family dispatch): linux → preseed
	// (#2046), windows → autounattend.xml (#2047). The per-VM CorrelationID is
	// baked in so the controller-side reconciler (#2050) can match the registered
	// steward (ADR-009 §8). Per-VM vars + secrets substituted at render time.
	answerContent, renderErr := m.renderSeedAnswerFile(ctx, vmName, cfg.Source, record.CorrelationID)
	if renderErr != nil {
		return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: render answer file for VM %q: %w", vmName, renderErr))
	}

	// Answer-file delivery is os_family-specific. Windows: the new Server 2025
	// Setup scans DVD roots for autounattend.xml but NOT data disks, so the
	// answer file (+ steward binary + CA) ships on a small ISO attached as a
	// second DVD (built natively via IMAPI2). Linux: debian-installer reads the
	// preseed from the labelled FAT32 CFGMS_SEED volume on a seed VHDX.
	if cfg.Source.OSFamily == "windows" {
		isoPath := answerISOPath(vmName, cfg.VHDPath, m.seedDir)
		if err := validateSeedPath(isoPath); err != nil {
			return m.failProvision(ctx, vmName, record, err)
		}
		if _, psErr := m.transport.ExecutePS(ctx, psBuildAnswerIso, map[string]string{
			"IsoPath":    isoPath,
			"FileName":   seedAnswerFileName("windows"),
			"Content":    answerContent,
			"StewardSrc": m.enrollStewardPath,
			"CASrc":      m.enrollCAPath,
		}); psErr != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Cfgms-BuildAnswerIso", cfgResourceID, nil, nil, psErr)
			return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: build answer ISO for VM %q: %w", vmName, psErr))
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Cfgms-BuildAnswerIso", cfgResourceID, nil, nil, nil)
		if _, psErr := m.transport.ExecutePS(ctx, psAttachDVD, map[string]string{
			"Name":    hostName,
			"ISOPath": isoPath,
		}); psErr != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Add-VMDvdDrive", cfgResourceID, nil, nil, psErr)
			return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: attach answer ISO to VM %q: %w", vmName, psErr))
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Add-VMDvdDrive", cfgResourceID, nil, nil, nil)
	} else {
		seedPath := seedVHDPath(vmName, cfg.VHDPath, m.seedDir)
		if err := validateSeedPath(seedPath); err != nil {
			return m.failProvision(ctx, vmName, record, err)
		}
		if _, psErr := m.transport.ExecutePS(ctx, psNewSeedVHD, map[string]string{
			"Path":      seedPath,
			"SizeBytes": "268435456",
		}); psErr != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "New-VHD", cfgResourceID, nil, nil, psErr)
			return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: create seed VHDX for VM %q: %w", vmName, psErr))
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "New-VHD", cfgResourceID, nil, nil, nil)
		if _, psErr := m.transport.ExecutePS(ctx, psMountSeedVHD, map[string]string{"Path": seedPath}); psErr != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Format-Volume", cfgResourceID, nil, nil, psErr)
			return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: format seed VHDX for VM %q: %w", vmName, psErr))
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Format-Volume", cfgResourceID, nil, nil, nil)
		if _, psErr := m.transport.ExecutePS(ctx, psCopyToSeedVHD, map[string]string{
			"SeedPath":   seedPath,
			"FileName":   seedAnswerFileName("linux"),
			"Content":    answerContent,
			"StewardSrc": "",
			"CASrc":      "",
		}); psErr != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-Content", cfgResourceID, nil, nil, psErr)
			return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: write answer file to seed for VM %q: %w", vmName, psErr))
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-Content", cfgResourceID, nil, nil, nil)
		if _, psErr := m.transport.ExecutePS(ctx, psAttachSeedDisk, map[string]string{
			"Name":     hostName,
			"SeedPath": seedPath,
		}); psErr != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Add-VMHardDiskDrive", cfgResourceID, nil, nil, psErr)
			return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: attach seed disk to VM %q: %w", vmName, psErr))
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Add-VMHardDiskDrive", cfgResourceID, nil, nil, nil)
	}

	// Attach the install ISO as a DVD drive (host path, never repacked).
	if _, psErr := m.transport.ExecutePS(ctx, psAttachDVD, map[string]string{
		"Name":    hostName,
		"ISOPath": cfg.Source.ISO,
	}); psErr != nil {
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Add-VMDvdDrive", cfgResourceID, nil, nil, psErr)
		return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: attach install ISO to VM %q: %w", vmName, psErr))
	}
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Add-VMDvdDrive", cfgResourceID, nil, nil, nil)

	// Make the install DVD the first boot device so a Gen2 VM boots the installer
	// rather than the empty OS VHD or the (bootloader-less) answer ISO. The
	// install ISO is selected by path. Gen1 uses BIOS startup order and is skipped.
	if generation == 2 {
		if _, psErr := m.transport.ExecutePS(ctx, psSetDVDFirstBoot, map[string]string{
			"Name":    hostName,
			"ISOPath": cfg.Source.ISO,
		}); psErr != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-VMFirmware", cfgResourceID, nil, nil, psErr)
			return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: set DVD first boot for VM %q: %w", vmName, psErr))
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-VMFirmware", cfgResourceID, nil, nil, nil)
	}

	// Power on and advance creating → installing. The unattended install runs
	// inside the guest; the host-side module observes no further until the
	// controller-side reconciler (#2050) flips ready.
	if err := m.execStartVM(ctx, cfgResourceID, hostName,
		map[string]interface{}{"state": "stopped"},
		map[string]interface{}{"state": "running"}); err != nil {
		return m.failProvision(ctx, vmName, record, err)
	}

	// Windows: drive the keyboard past the install media's "Press any key to
	// boot from CD or DVD" prompt, which otherwise times out headlessly. The
	// post-install reboots boot the OS (Windows Setup re-prioritises its own boot
	// manager). Best-effort — a keypress failure does not fail the provision.
	if cfg.Source.OSFamily == "windows" {
		if _, psErr := m.transport.ExecutePS(ctx, psBootKeypress, map[string]string{"Name": hostName}); psErr != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Cfgms-BootKeypress", cfgResourceID, nil, nil, psErr)
			if logger, ok := m.GetLogger(); ok {
				logger.Warn("hyperv: boot keypress failed (install may still proceed)",
					"vm_name", logging.SanitizeLogValue(vmName))
			}
		} else {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Cfgms-BootKeypress", cfgResourceID, nil, nil, nil)
		}
	}

	return m.advanceProvision(ctx, vmName, record, ProvisionStateInstalling)
}

// cloudInitMetaData returns the minimal NoCloud meta-data document for a VM.
// instance-id is unique per VM (cloud-init only re-runs when it changes);
// local-hostname is set to the CorrelationID so the booted guest's hostname
// matches the provisioning record the controller-side reconciler keys on.
func cloudInitMetaData(vmName, correlationID string) string {
	host := correlationID
	if host == "" {
		host = vmName
	}
	return "instance-id: " + vmName + "\nlocal-hostname: " + host + "\n"
}

// provisionCloudInit performs the cloud-init media setup for a Linux
// VM-from-cloud-image: render user-data, build the NoCloud CIDATA seed VHDX
// (user-data + meta-data + steward binary + controller CA), attach it as a data
// disk, and make the OS disk the Gen2 first boot device. The boot disk itself was
// already prepared from the cloud image by createVM. No install ISO, no keypress
// — cloud-init auto-detects the CIDATA seed on first boot. The caller powers the
// VM on and advances the record to installing.
func (m *hypervModule) provisionCloudInit(ctx context.Context, vmName, hostName string, cfg *VMConfig, record *ProvisionRecord, generation int) error {
	cfgResourceID := "vm:" + vmName

	// Render the cloud-init user-data (resolves the built-in or operator
	// cloud-init profile). CorrelationID is baked in for controller-side matching.
	userData, renderErr := m.renderSeedAnswerFile(ctx, vmName, cfg.Source, record.CorrelationID)
	if renderErr != nil {
		return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: render cloud-init user-data for VM %q: %w", vmName, renderErr))
	}
	metaData := cloudInitMetaData(vmName, record.CorrelationID)

	// Build the NoCloud seed: a FAT32 volume labelled CIDATA carrying user-data,
	// meta-data, the linux steward binary (dest name cfgms-steward) and the
	// controller CA. Reuses the seed-VHDX machinery (#2044) via the Label /
	// FileName2 / StewardDest parameters. The seed MUST be on a local (non-CSV)
	// path — Mount-VHD against a CSV-resident VHDX hangs (seed_dir handles this).
	seedPath := seedVHDPath(vmName, cfg.VHDPath, m.seedDir)
	if err := validateSeedPath(seedPath); err != nil {
		return m.failProvision(ctx, vmName, record, err)
	}
	if _, psErr := m.transport.ExecutePS(ctx, psNewSeedVHD, map[string]string{
		"Path":      seedPath,
		"SizeBytes": "268435456",
	}); psErr != nil {
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "New-VHD", cfgResourceID, nil, nil, psErr)
		return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: create CIDATA seed VHDX for VM %q: %w", vmName, psErr))
	}
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "New-VHD", cfgResourceID, nil, nil, nil)
	if _, psErr := m.transport.ExecutePS(ctx, psMountSeedVHD, map[string]string{
		"Path":  seedPath,
		"Label": cidataVolumeLabel,
	}); psErr != nil {
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Format-Volume", cfgResourceID, nil, nil, psErr)
		return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: format CIDATA seed VHDX for VM %q: %w", vmName, psErr))
	}
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Format-Volume", cfgResourceID, nil, nil, nil)
	if _, psErr := m.transport.ExecutePS(ctx, psCopyToSeedVHD, map[string]string{
		"SeedPath":     seedPath,
		"Label":        cidataVolumeLabel,
		"FileName":     "user-data",
		"Content":      userData,
		"FileName2":    "meta-data",
		"Content2":     metaData,
		"StewardSrc":   m.enrollStewardPath,
		"StewardDest":  "cfgms-steward",
		"LauncherSrc":  m.enrollLauncherPath,
		"LauncherDest": "cfgms-steward-launcher",
		"CASrc":        m.enrollCAPath,
	}); psErr != nil {
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-Content", cfgResourceID, nil, nil, psErr)
		return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: write cloud-init seed for VM %q: %w", vmName, psErr))
	}
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-Content", cfgResourceID, nil, nil, nil)
	if _, psErr := m.transport.ExecutePS(ctx, psAttachSeedDisk, map[string]string{
		"Name":     hostName,
		"SeedPath": seedPath,
	}); psErr != nil {
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Add-VMHardDiskDrive", cfgResourceID, nil, nil, psErr)
		return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: attach CIDATA seed to VM %q: %w", vmName, psErr))
	}
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Add-VMHardDiskDrive", cfgResourceID, nil, nil, nil)

	// Make the OS disk (the converted cloud image) the first boot device so the
	// VM boots the cloud image rather than the attached CIDATA seed. Gen1 uses
	// BIOS startup order and is skipped.
	if generation == 2 {
		if _, psErr := m.transport.ExecutePS(ctx, psSetHddFirstBoot, map[string]string{
			"Name":    hostName,
			"VHDPath": cfg.VHDPath,
		}); psErr != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-VMFirmware", cfgResourceID, nil, nil, psErr)
			return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: set OS-disk first boot for VM %q: %w", vmName, psErr))
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-VMFirmware", cfgResourceID, nil, nil, nil)
	}
	return nil
}

// cidataVolumeLabel is the NoCloud seed volume label cloud-init auto-detects.
const cidataVolumeLabel = "CIDATA"

// resolveLinuxProfile returns the UnattendProfile for a Linux VM source. When
// the source references a profile (profile://<name>) it is loaded from the
// profile store; when no reference is given the built-in profile is used so a
// minimal Linux source provisions without operator-authored config: cloud-init
// for a cloud image (source.image), preseed for a netinst ISO (ADR-009 §6/§7).
func (m *hypervModule) resolveLinuxProfile(ctx context.Context, src *SourceConfig) (*UnattendProfile, error) {
	if src.Unattend == "" {
		// No operator profile: choose the built-in by media kind. A cloud image
		// (source.image) → cloud-init user-data; a netinst ISO → preseed (legacy).
		if src.isCloudInit() {
			return defaultLinuxCloudInitProfile(), nil
		}
		return defaultLinuxProfile(), nil
	}
	name, err := parseProfileName(src.Unattend)
	if err != nil {
		return nil, err
	}
	if m.profileStore == nil {
		return nil, fmt.Errorf("hyperv: profile %q referenced but no profile store configured: %w", name, ErrProfileNotFound)
	}
	profile, err := m.profileStore.GetProfile(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("hyperv: load profile %q: %w", name, err)
	}
	return profile, nil
}

// finalizeProvision advances a VM whose provisioning record is at installing to
// finalizing once the unattended install is judged complete, detaching the seed
// VHDX so the installed OS does not re-read the answer file on subsequent boots
// (ADR-009 §6/§8). It is invoked on a convergence cycle for a VM that already
// exists on the host and carries a source block.
//
// Completion detection is deliberately conservative (ADR-009 §8 implementation
// note): the install is judged complete only after at least completion.timeout/2
// has elapsed since StartedAt AND the VM is observed Running. The host-side
// module NEVER advances to ready — that transition is owned by the
// controller-side completion reconciler (#2050) keyed on CorrelationID. When the
// record is not at installing, or the settle conditions are not met, this is a
// no-op and the record is left unchanged.
func (m *hypervModule) finalizeProvision(ctx context.Context, vmName, hostName string, cfg *VMConfig) error {
	if cfg.Source == nil {
		return nil
	}
	record, err := m.loadOrInitProvision(ctx, vmName)
	if err != nil {
		return err
	}
	if record.State != ProvisionStateInstalling {
		// Only an installing record is eligible to advance to finalizing.
		return nil
	}

	settle := installSettleDuration(cfg.Source.Completion.Timeout)
	if time.Since(record.StartedAt) < settle {
		// Too early — err on the side of waiting (conservative completion).
		return nil
	}

	// Confirm the VM is running (booted into the installed OS / past installer).
	running, err := m.vmIsRunning(ctx, vmName)
	if err != nil {
		return err
	}
	if !running {
		return nil
	}

	// Detach the seed VHDX so the answer file is gone on the next boot.
	seedPath := seedVHDPath(vmName, cfg.VHDPath, m.seedDir)
	if vErr := validateSeedPath(seedPath); vErr != nil {
		return m.failProvision(ctx, vmName, record, vErr)
	}
	if _, psErr := m.transport.ExecutePS(ctx, psDetachSeedVHD, map[string]string{
		"Path": seedPath,
	}); psErr != nil {
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Dismount-VHD", "vm:"+vmName, nil, nil, psErr)
		return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: detach seed VHDX for VM %q: %w", vmName, psErr))
	}
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Dismount-VHD", "vm:"+vmName, nil, nil, nil)

	// Delete the seed VHDX and the answer ISO (ADR-010 §5). Both calls are
	// idempotent — psDeleteSeedMedia uses SilentlyContinue so an absent file
	// is not an error. For linux/cloud-init VMs the seed VHDX exists; the ISO
	// path is a no-op. For windows VMs the seed VHDX never existed; the ISO
	// path deletes the answer ISO built by psBuildAnswerIso.
	isoPath := answerISOPath(vmName, cfg.VHDPath, m.seedDir)
	for _, mediaPath := range []string{seedPath, isoPath} {
		if _, psErr := m.transport.ExecutePS(ctx, psDeleteSeedMedia, map[string]string{
			"Path": mediaPath,
		}); psErr != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Remove-Item", "vm:"+vmName, nil, nil, psErr)
			if logger, ok := m.GetLogger(); ok {
				logger.Warn("hyperv: seed media delete failed; TTL sweep will retry",
					"vm_name", logging.SanitizeLogValue(vmName),
					"path", logging.SanitizeLogValue(mediaPath))
			}
			continue
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Remove-Item", "vm:"+vmName, nil, nil, nil)
	}

	// Cluster-role registration for a source-provisioned VM (#2372): ha_role is
	// convergent on every path, so a VM born via source: is registered here —
	// no later than the installing → finalizing transition (ready is
	// controller-side, #2050, never observed by this steward-side code). A
	// registration failure returns BEFORE the record advances, keeping it at
	// installing so the next converge cycle retries the finalize (transient CNO
	// failover must not strand a should-be-HA VM as standalone).
	if cfg.HARole != nil {
		roleCfg := *cfg
		roleCfg.Name = vmName
		if err := m.registerClusteredRole(ctx, &roleCfg); err != nil {
			return fmt.Errorf("hyperv: register clustered role for provisioned VM %q: %w", vmName, err)
		}
	}

	// Advance installing → finalizing. ready is controller-side (#2050).
	return m.advanceProvision(ctx, vmName, record, ProvisionStateFinalizing)
}

// installSettleDuration returns half of the parsed completion.timeout, the
// minimum elapsed time before the host judges an install complete. An empty or
// unparseable timeout falls back to half of the default completion timeout. The
// timeout string is validated upstream by SourceConfig.Validate, so a parse
// failure here is defensive only.
func installSettleDuration(timeout string) time.Duration {
	const defaultCompletionTimeout = 30 * time.Minute
	if timeout == "" {
		return defaultCompletionTimeout / 2
	}
	d, err := time.ParseDuration(timeout)
	if err != nil || d <= 0 {
		return defaultCompletionTimeout / 2
	}
	return d / 2
}

// vmIsRunning queries live host state via getVM and reports whether the VM is in
// the running power state. A VM that is absent or stopped reports false.
func (m *hypervModule) vmIsRunning(ctx context.Context, vmName string) (bool, error) {
	current, err := m.getVM(ctx, vmName)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(current.State, "running"), nil
}

// sweepStaleSeedMedia deletes staged seed media (seed VHDX + answer ISO) for
// any provision record whose UpdatedAt is older than seedMediaTTL. This is a
// safety net that bounds the on-disk join-token window for orphaned media left
// by failed or aborted provisions — e.g. a VM deleted mid-install, or a
// finalizeProvision delete that failed transiently. All Remove-Item calls use
// psDeleteSeedMedia (SilentlyContinue), so absent files are not errors. Paths
// are derived from seedVHDPath / answerISOPath; if neither seedDir is set nor
// the VM's VHD path is known from the module cache, the path fails validation
// and that file is silently skipped.
func (m *hypervModule) sweepStaleSeedMedia(ctx context.Context) {
	if m.provisionStore == nil || m.transport == nil {
		return
	}
	records, err := m.provisionStore.ListProvisions(ctx)
	if err != nil {
		return
	}
	for _, rec := range records {
		if rec.State == ProvisionStateAbsent {
			continue
		}
		if time.Since(rec.UpdatedAt) < seedMediaTTL {
			continue
		}
		// Derive the VHD path from the module's VM cache. Unknown VMs (deleted
		// mid-provision) get an empty vhdPath, which is fine when seedDir is set.
		m.vmsMu.RLock()
		cachedCfg, ok := m.vms[rec.VMName]
		m.vmsMu.RUnlock()
		vhdPath := ""
		if ok {
			vhdPath = cachedCfg.VHDPath
		}
		for _, mediaPath := range []string{
			seedVHDPath(rec.VMName, vhdPath, m.seedDir),
			answerISOPath(rec.VMName, vhdPath, m.seedDir),
		} {
			if validateSeedPath(mediaPath) != nil {
				// Path not derivable (seedDir unset and VM absent from cache); skip.
				continue
			}
			if _, psErr := m.transport.ExecutePS(ctx, psDeleteSeedMedia, map[string]string{
				"Path": mediaPath,
			}); psErr != nil {
				if logger, ok := m.GetLogger(); ok {
					logger.Warn("hyperv: TTL sweep seed media delete failed",
						"vm_name", logging.SanitizeLogValue(rec.VMName),
						"path", logging.SanitizeLogValue(mediaPath))
				}
			}
		}
	}
}
