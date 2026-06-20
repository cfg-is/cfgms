// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"fmt"
	"strings"
	"time"
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
	// psNewSeedVHD wraps New-VHD: create the empty dynamic seed disk.
	psNewSeedVHD = `New-VHD -Path $Path -SizeBytes $SizeBytes -Dynamic | Out-Null`

	// psMountSeedVHD wraps the Mount-VHD → Initialize-Disk → New-Partition →
	// Format-Volume pipeline: lay a FAT32 CFGMS_SEED volume on the seed disk.
	psMountSeedVHD = `Mount-VHD -Path $Path -Passthru | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem FAT32 -NewFileSystemLabel 'CFGMS_SEED' -Confirm:$false | Out-Null`

	// psCopyToSeedVHD mounts the seed, writes $Content to <drive>:\$FileName,
	// optionally stages the steward binary ($StewardSrc → <drive>:\cfgms-steward.exe)
	// and controller CA ($CASrc → <drive>:\controller-ca.crt) so a Windows guest
	// can self-install + enroll offline (ADR-010), and dismounts. $Content,
	// $FileName, $StewardSrc and $CASrc travel via ArgumentList; empty
	// $StewardSrc / $CASrc skip staging (the Linux/preseed path stages neither).
	psCopyToSeedVHD = `$disk = Mount-VHD -Path $SeedPath -Passthru; $letter = ($disk | Get-Disk | Get-Partition | Get-Volume | Where-Object { $_.FileSystemLabel -eq 'CFGMS_SEED' } | Select-Object -First 1).DriveLetter; Set-Content -Path ($letter + ':\' + $FileName) -Value $Content -NoNewline; if ($StewardSrc -and (Test-Path -LiteralPath $StewardSrc)) { Copy-Item -LiteralPath $StewardSrc -Destination ($letter + ':\cfgms-steward.exe') -Force }; if ($CASrc -and (Test-Path -LiteralPath $CASrc)) { Copy-Item -LiteralPath $CASrc -Destination ($letter + ':\controller-ca.crt') -Force }; Dismount-VHD -Path $SeedPath`

	// psDetachSeedVHD wraps Dismount-VHD (called at finalizing, not in the
	// create path this story implements).
	psDetachSeedVHD = `Dismount-VHD -Path $Path -ErrorAction SilentlyContinue`

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
)

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
		return m.resolveLinuxProfile(ctx, src.Unattend)
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

// seedVHDPath derives the seed VHDX path from the VM's VHD path so the seed
// lands in the same directory as the VM's primary disk:
// <vhdDir>\cfgms-seed-<vmName>.vhdx. The parent directory is computed with
// Windows path semantics (split on \ or /) rather than filepath.Dir, which is
// OS-dependent: filepath.Dir("C:\\dir\\x.vhdx") returns "." on Linux (it does
// not treat "\" as a separator), mangling the always-Windows Hyper-V path when
// the steward or CI runs on a non-Windows OS (Issue #2044).
func seedVHDPath(vmName, vhdPath string) string {
	dir := vhdPath
	if i := strings.LastIndexAny(vhdPath, `\/`); i >= 0 {
		dir = vhdPath[:i]
	}
	dir = strings.TrimRight(dir, `\/`)
	return dir + `\` + "cfgms-seed-" + vmName + ".vhdx"
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

	// Gen2 secure-boot template by os_family; Gen1 has no UEFI/secure boot.
	if generation == 2 {
		template := secureBootTemplate(cfg.Source.OSFamily)
		if _, psErr := m.transport.ExecutePS(ctx, psSetVMFirmware, map[string]string{
			"Name":     hostName,
			"Template": template,
		}); psErr != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-VMFirmware", hostName, psErr)
			return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: set firmware for VM %q: %w", vmName, psErr))
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-VMFirmware", hostName, nil)
	}

	// Build the seed VHDX next to the VM's primary VHD.
	seedPath := seedVHDPath(vmName, cfg.VHDPath)
	if err := validateSeedPath(seedPath); err != nil {
		return m.failProvision(ctx, vmName, record, err)
	}

	if _, psErr := m.transport.ExecutePS(ctx, psNewSeedVHD, map[string]string{
		"Path": seedPath,
		// 256 MiB (dynamic, so near-zero on-disk until written). The Windows path
		// stages the steward binary (~tens of MB) + CA onto the seed; 64 MiB was
		// too small for the binary, so the seed is sized to hold it (ADR-010).
		"SizeBytes": "268435456",
	}); psErr != nil {
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "New-VHD", hostName, psErr)
		return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: create seed VHDX for VM %q: %w", vmName, psErr))
	}
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "New-VHD", hostName, nil)

	if _, psErr := m.transport.ExecutePS(ctx, psMountSeedVHD, map[string]string{
		"Path": seedPath,
	}); psErr != nil {
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Format-Volume", hostName, psErr)
		return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: format seed VHDX for VM %q: %w", vmName, psErr))
	}
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Format-Volume", hostName, nil)

	// Render the unattended answer file for the os_family. renderSeedAnswerFile
	// dispatches on os_family: linux renders the REAL preseed from the referenced
	// (or built-in Debian) profile (#2046); windows renders the real
	// autounattend.xml from the referenced (or built-in Windows) profile (#2047).
	// Both bake the per-VM CorrelationID in so the controller-side reconciler
	// (#2050) can match the registered steward (ADR-009 §8). Per-VM vars +
	// secrets are substituted at render time.
	answerContent, renderErr := m.renderSeedAnswerFile(ctx, vmName, cfg.Source, record.CorrelationID)
	if renderErr != nil {
		return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: render answer file for VM %q: %w", vmName, renderErr))
	}

	// Stage the steward binary + controller CA onto the seed for the Windows
	// self-install path (ADR-010); the Linux/preseed path stages neither (it
	// fetches the .deb in late_command). Empty values skip staging.
	var stewardSrc, caSrc string
	if cfg.Source.OSFamily == "windows" {
		stewardSrc = m.enrollStewardPath
		caSrc = m.enrollCAPath
	}
	if _, psErr := m.transport.ExecutePS(ctx, psCopyToSeedVHD, map[string]string{
		"SeedPath":   seedPath,
		"FileName":   seedAnswerFileName(cfg.Source.OSFamily),
		"Content":    answerContent,
		"StewardSrc": stewardSrc,
		"CASrc":      caSrc,
	}); psErr != nil {
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-Content", hostName, psErr)
		return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: write answer file to seed for VM %q: %w", vmName, psErr))
	}
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-Content", hostName, nil)

	// Attach the seed VHDX as the secondary disk.
	if _, psErr := m.transport.ExecutePS(ctx, psAttachSeedDisk, map[string]string{
		"Name":     hostName,
		"SeedPath": seedPath,
	}); psErr != nil {
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Add-VMHardDiskDrive", hostName, psErr)
		return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: attach seed disk to VM %q: %w", vmName, psErr))
	}
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Add-VMHardDiskDrive", hostName, nil)

	// Attach the install ISO as the DVD drive (host path, never repacked).
	if _, psErr := m.transport.ExecutePS(ctx, psAttachDVD, map[string]string{
		"Name":    hostName,
		"ISOPath": cfg.Source.ISO,
	}); psErr != nil {
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Add-VMDvdDrive", hostName, psErr)
		return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: attach install ISO to VM %q: %w", vmName, psErr))
	}
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Add-VMDvdDrive", hostName, nil)

	// Make the install DVD the first boot device so a Gen2 VM boots the installer
	// rather than the empty OS VHD. Gen1 uses BIOS startup order (CD precedes the
	// IDE disk by default) and is skipped.
	if generation == 2 {
		if _, psErr := m.transport.ExecutePS(ctx, psSetDVDFirstBoot, map[string]string{
			"Name": hostName,
		}); psErr != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-VMFirmware", hostName, psErr)
			return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: set DVD first boot for VM %q: %w", vmName, psErr))
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Set-VMFirmware", hostName, nil)
	}

	// Power on and advance creating → installing. The unattended install runs
	// inside the guest; the host-side module observes no further until the
	// controller-side reconciler (#2050) flips ready.
	if err := m.execStartVM(ctx, vmName, hostName); err != nil {
		return m.failProvision(ctx, vmName, record, err)
	}

	return m.advanceProvision(ctx, vmName, record, ProvisionStateInstalling)
}

// resolveLinuxProfile returns the UnattendProfile for a Linux VM source. When
// the source references a profile (profile://<name>) it is loaded from the
// profile store; when no reference is given the built-in Debian 12 profile is
// used so a minimal Linux source ("iso" + "os_family: linux") provisions
// without operator-authored config (ADR-009 §6/§7).
func (m *hypervModule) resolveLinuxProfile(ctx context.Context, unattendRef string) (*UnattendProfile, error) {
	if unattendRef == "" {
		return defaultLinuxProfile(), nil
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
	seedPath := seedVHDPath(vmName, cfg.VHDPath)
	if vErr := validateSeedPath(seedPath); vErr != nil {
		return m.failProvision(ctx, vmName, record, vErr)
	}
	if _, psErr := m.transport.ExecutePS(ctx, psDetachSeedVHD, map[string]string{
		"Path": seedPath,
	}); psErr != nil {
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Dismount-VHD", hostName, psErr)
		return m.failProvision(ctx, vmName, record, fmt.Errorf("hyperv: detach seed VHDX for VM %q: %w", vmName, psErr))
	}
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Dismount-VHD", hostName, nil)

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
