// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"fmt"
	"strings"
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
	// and dismounts. $Content and $FileName travel via ArgumentList.
	psCopyToSeedVHD = `$disk = Mount-VHD -Path $SeedPath -Passthru; $letter = ($disk | Get-Disk | Get-Partition | Get-Volume | Where-Object { $_.FileSystemLabel -eq 'CFGMS_SEED' } | Select-Object -First 1).DriveLetter; Set-Content -Path ($letter + ':\' + $FileName) -Value $Content -NoNewline; Dismount-VHD -Path $SeedPath`

	// psDetachSeedVHD wraps Dismount-VHD (called at finalizing, not in the
	// create path this story implements).
	psDetachSeedVHD = `Dismount-VHD -Path $Path -ErrorAction SilentlyContinue`

	// psAttachSeedDisk wraps Add-VMHardDiskDrive: attach the seed VHDX as the
	// VM's secondary disk.
	psAttachSeedDisk = `Add-VMHardDiskDrive -VMName $Name -Path $SeedPath`

	// psAttachDVD wraps Add-VMDvdDrive: attach the install ISO as the VM's DVD
	// drive. The ISO is never repacked or re-signed.
	psAttachDVD = `Add-VMDvdDrive -VMName $Name -Path $ISOPath`

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
// os_family. Real templates are injected by #2046/#2047; this story only needs
// the seed VHDX to be non-empty. The content is a one-line comment stub.
func seedAnswerFilePlaceholder(osFamily string) string {
	if osFamily == "windows" {
		return "<!-- placeholder autounattend -->"
	}
	return "# placeholder preseed"
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
		// Already past the host-side create steps — nothing to redo.
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
		"Path":      seedPath,
		"SizeBytes": "67108864", // 64 MiB
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

	if _, psErr := m.transport.ExecutePS(ctx, psCopyToSeedVHD, map[string]string{
		"SeedPath": seedPath,
		"FileName": seedAnswerFileName(cfg.Source.OSFamily),
		"Content":  seedAnswerFilePlaceholder(cfg.Source.OSFamily),
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

	// Power on and advance creating → installing. The unattended install runs
	// inside the guest; the host-side module observes no further until the
	// controller-side reconciler (#2050) flips ready.
	if err := m.execStartVM(ctx, vmName, hostName); err != nil {
		return m.failProvision(ctx, vmName, record, err)
	}

	return m.advanceProvision(ctx, vmName, record, ProvisionStateInstalling)
}
