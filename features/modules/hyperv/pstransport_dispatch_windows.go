// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"context"
	"fmt"
	"strings"
)

// ExecutePS satisfies the winrmTransport interface. Pattern-matches the
// incoming psCommand against the known psXxx const set from vm.go and
// vswitch.go and dispatches the equivalent Cfgms-* verb over the
// persistent PS host.
//
// Unknown psCommand strings return an error rather than silently no-op'ing.
// We don't fall back to WinRM here — the wholesale-WinRM-fallback model
// from earlier #1887 drafts assumed WinRM worked; in this codebase it's
// reliably broken on the same-host deployment shape (see #1852 F16–F21).
// If a future verb gets added in vm.go/vswitch.go without a matching
// Cfgms-* function, that's a build-time omission, not a runtime graceful
// degradation candidate.
func (t *psHostTransport) ExecutePS(ctx context.Context, psCommand string, psArgs map[string]string) (string, error) {
	// External vSwitch creation is the one psCommand that's built by a
	// function (psCreateVSwitchExternal) rather than declared as a const,
	// because the AllowManagementOS bool is embedded in the script text.
	// We check it BEFORE the const-based switch because its text starts
	// with "New-VMSwitch ... -SwitchType External ..." and otherwise
	// wouldn't match anything.
	if strings.Contains(psCommand, "-SwitchType External -NetAdapterName") {
		return t.dispatchCreateVSwitchExternal(ctx, psCommand, psArgs)
	}

	switch psCommand {
	// ── VM ──────────────────────────────────────────────────────────
	case psGetVM:
		return t.run(ctx, "Cfgms-GetVM -Name "+quoteArg(psArgs, "Name"))
	case psCreateVM:
		return t.run(ctx,
			"Cfgms-CreateVM -Name "+quoteArg(psArgs, "Name")+
				" -MemoryMB "+intArg(psArgs, "MemoryMB")+
				" -CPU "+intArg(psArgs, "CPU")+
				" -VHDPath "+quoteArg(psArgs, "VHDPath")+
				" -SwitchName "+quoteArg(psArgs, "SwitchName")+
				" -Generation "+intArg(psArgs, "Generation"))
	case psRemoveVM:
		return t.run(ctx, "Cfgms-RemoveVM -Name "+quoteArg(psArgs, "Name"))
	case psStartVM:
		return t.run(ctx, "Cfgms-StartVM -Name "+quoteArg(psArgs, "Name"))
	case psStopVM:
		return t.run(ctx, "Cfgms-StopVM -Name "+quoteArg(psArgs, "Name"))
	case psSetVMProcessor:
		return t.run(ctx,
			"Cfgms-SetVMProcessor -Name "+quoteArg(psArgs, "Name")+
				" -CPU "+intArg(psArgs, "CPU"))
	case psSetVMMemory:
		return t.run(ctx,
			"Cfgms-SetVMMemory -Name "+quoteArg(psArgs, "Name")+
				" -MemoryMB "+intArg(psArgs, "MemoryMB"))

	// ── VM provisioning: seed VHDX disk ops (#2044) ──────────────────
	// These four use runFresh (a fresh `powershell -File` process), NOT the
	// persistent `-Command -` host: Mount-VHD/Dismount-VHD deadlock there
	// (async Virtual Disk Service). Media-attach + firmware below stay on the
	// persistent host (Add-VM*/Set-VMFirmware are synchronous and work there).
	case psNewSeedVHD:
		return t.runFresh(ctx,
			"Cfgms-NewSeedVHD -Path "+quoteArg(psArgs, "Path")+
				" -SizeBytes "+intArg(psArgs, "SizeBytes"))
	case psMountSeedVHD:
		// -Label is optional: omitted for the legacy CFGMS_SEED path (PS default),
		// passed as CIDATA for the cloud-init NoCloud seed.
		return t.runFresh(ctx, "Cfgms-MountSeedVHD -Path "+quoteArg(psArgs, "Path")+
			optArg(psArgs, "Label", "Label"))
	case psCopyToSeedVHD:
		// -Label / -FileName2 / -Content2 / -StewardDest are optional: absent for
		// the legacy single-file CFGMS_SEED path (PS defaults), present for the
		// cloud-init CIDATA seed (user-data + meta-data + cfgms-steward).
		return t.runFresh(ctx,
			"Cfgms-CopyToSeedVHD -SeedPath "+quoteArg(psArgs, "SeedPath")+
				" -FileName "+quoteArg(psArgs, "FileName")+
				" -Content "+quoteArg(psArgs, "Content")+
				optArg(psArgs, "Label", "Label")+
				optArg(psArgs, "FileName2", "FileName2")+
				optArg(psArgs, "Content2", "Content2")+
				optArg(psArgs, "StewardDest", "StewardDest")+
				" -StewardSrc "+quoteArg(psArgs, "StewardSrc")+
				" -CASrc "+quoteArg(psArgs, "CASrc"))
	case psDetachSeedVHD:
		return t.runFresh(ctx, "Cfgms-DetachSeedVHD -Path "+quoteArg(psArgs, "Path"))
	case psAttachSeedDisk:
		// runFresh: Add-VMHardDiskDrive opens the seed VHD, which hits the same
		// async-VHD deadlock as Mount-VHD in the persistent -Command - host.
		return t.runFresh(ctx,
			"Cfgms-AttachSeedDisk -Name "+quoteArg(psArgs, "Name")+
				" -SeedPath "+quoteArg(psArgs, "SeedPath"))
	case psAttachDVD:
		// runFresh: Add-VMDvdDrive opens the install ISO (same reason).
		return t.runFresh(ctx,
			"Cfgms-AttachDVD -Name "+quoteArg(psArgs, "Name")+
				" -ISOPath "+quoteArg(psArgs, "ISOPath"))
	case psSetVMFirmware:
		return t.run(ctx,
			"Cfgms-SetVMFirmware -Name "+quoteArg(psArgs, "Name")+
				" -Template "+quoteArg(psArgs, "Template"))
	case psSetDVDFirstBoot:
		// runFresh: Set-VMFirmware -FirstBootDevice references the DVD/ISO and
		// deadlocks in the persistent host (the secure-boot case above does not).
		return t.runFresh(ctx,
			"Cfgms-SetDVDFirstBoot -Name "+quoteArg(psArgs, "Name")+
				" -ISOPath "+quoteArg(psArgs, "ISOPath"))
	case psBuildAnswerIso:
		// runFresh: IMAPI2 COM + file I/O; heavy, must not run in the persistent host.
		return t.runFresh(ctx,
			"Cfgms-BuildAnswerIso -IsoPath "+quoteArg(psArgs, "IsoPath")+
				" -FileName "+quoteArg(psArgs, "FileName")+
				" -Content "+quoteArg(psArgs, "Content")+
				" -StewardSrc "+quoteArg(psArgs, "StewardSrc")+
				" -CASrc "+quoteArg(psArgs, "CASrc"))
	case psBootKeypress:
		// runFresh: blocks ~40s driving the VM keyboard.
		return t.runFresh(ctx, "Cfgms-BootKeypress -Name "+quoteArg(psArgs, "Name"))

	// ── cloud-init (Linux VM-from-cloud-image) ───────────────────────
	case psPrepCloudBootDisk:
		// runFresh: Convert-VHD is heavy file I/O.
		return t.runFresh(ctx,
			"Cfgms-PrepCloudBootDisk -ImagePath "+quoteArg(psArgs, "ImagePath")+
				" -VhdPath "+quoteArg(psArgs, "VhdPath")+
				" -ResizeBytes "+intArg(psArgs, "ResizeBytes"))
	case psCreateVMFromDisk:
		// Persistent host (like Cfgms-CreateVM): New-VM does not mount the disk.
		return t.run(ctx,
			"Cfgms-CreateVMFromDisk -Name "+quoteArg(psArgs, "Name")+
				" -MemoryMB "+intArg(psArgs, "MemoryMB")+
				" -CPU "+intArg(psArgs, "CPU")+
				" -VHDPath "+quoteArg(psArgs, "VHDPath")+
				" -SwitchName "+quoteArg(psArgs, "SwitchName")+
				" -Generation "+intArg(psArgs, "Generation"))
	case psSetHddFirstBoot:
		// runFresh: Set-VMFirmware -FirstBootDevice referencing a disk deadlocks
		// in the persistent host (same as Cfgms-SetDVDFirstBoot).
		return t.runFresh(ctx,
			"Cfgms-SetHddFirstBoot -Name "+quoteArg(psArgs, "Name")+
				" -VHDPath "+quoteArg(psArgs, "VHDPath"))

	// ── VM network reconcile (declarative multi-NIC, #2021) ──────────
	case psConnectVMNic:
		return t.run(ctx,
			"Cfgms-ConnectVMNic -Name "+quoteArg(psArgs, "Name")+
				" -SwitchName "+quoteArg(psArgs, "SwitchName"))
	case psDisconnectVMNic:
		return t.run(ctx,
			"Cfgms-DisconnectVMNic -Name "+quoteArg(psArgs, "Name")+
				" -SwitchName "+quoteArg(psArgs, "SwitchName"))

	// ── VSwitch ─────────────────────────────────────────────────────
	case psGetVSwitch:
		return t.run(ctx, "Cfgms-GetVSwitch -Name "+quoteArg(psArgs, "Name"))
	case psRemoveVSwitch:
		return t.run(ctx, "Cfgms-RemoveVSwitch -Name "+quoteArg(psArgs, "Name"))
	case psCreateVSwitchInternal:
		return t.run(ctx, "Cfgms-CreateVSwitchInternal -Name "+quoteArg(psArgs, "Name"))
	case psCreateVSwitchPrivate:
		return t.run(ctx, "Cfgms-CreateVSwitchPrivate -Name "+quoteArg(psArgs, "Name"))

	// ── Failover cluster (read-only, #2199 S1) ──────────────────────
	case psGetCluster:
		return t.run(ctx, "Cfgms-GetCluster -ClusterName "+quoteArg(psArgs, "ClusterName"))
	case psGetClusterOwnerNode:
		return t.run(ctx, "Cfgms-GetClusterOwnerNode -ClusterName "+quoteArg(psArgs, "ClusterName"))
	case psGetClusterResourceOwner:
		return t.run(ctx, "Cfgms-GetClusterResourceOwner -ClusterName "+quoteArg(psArgs, "ClusterName"))
	case psGetClusterAccessSelf:
		return t.run(ctx, "Cfgms-GetClusterAccessSelf -ClusterName "+quoteArg(psArgs, "ClusterName"))

	// ── Failover cluster (write, #2202 S2) ──────────────────────────
	case psAddClusterVMRole:
		return t.run(ctx,
			"Cfgms-AddClusterVMRole -ClusterName "+quoteArg(psArgs, "ClusterName")+
				" -VMName "+quoteArg(psArgs, "VMName"))
	case psRemoveClusterResource:
		return t.run(ctx, "Cfgms-RemoveClusterResource -Name "+quoteArg(psArgs, "Name"))

	// ── Failover cluster-role properties (write, #2306 PROPERTIES-B) ─
	case psSetClusterRolePreferredOwners:
		return t.run(ctx, "Cfgms-SetClusterRolePreferredOwners -ClusterName "+quoteArg(psArgs, "ClusterName")+
			" -GroupName "+quoteArg(psArgs, "GroupName")+" -Owners "+quoteArg(psArgs, "Owners"))
	case psSetClusterRolePossibleOwners:
		return t.run(ctx, "Cfgms-SetClusterRolePossibleOwners -ClusterName "+quoteArg(psArgs, "ClusterName")+
			" -ResourceName "+quoteArg(psArgs, "ResourceName")+" -Owners "+quoteArg(psArgs, "Owners"))
	case psSetClusterGroupPriority:
		return t.run(ctx, "Cfgms-SetClusterGroupPriority -ClusterName "+quoteArg(psArgs, "ClusterName")+
			" -GroupName "+quoteArg(psArgs, "GroupName")+" -Priority "+quoteArg(psArgs, "Priority"))
	case psSetClusterGroupAutoStart:
		return t.run(ctx, "Cfgms-SetClusterGroupAutoStart -ClusterName "+quoteArg(psArgs, "ClusterName")+
			" -GroupName "+quoteArg(psArgs, "GroupName")+" -AutoStart "+quoteArg(psArgs, "AutoStart"))
	case psSetClusterGroupAntiAffinity:
		return t.run(ctx, "Cfgms-SetClusterGroupAntiAffinity -ClusterName "+quoteArg(psArgs, "ClusterName")+
			" -GroupName "+quoteArg(psArgs, "GroupName")+" -ClassName "+quoteArg(psArgs, "ClassName"))
	}

	return "", fmt.Errorf("hyperv-ps-host: unknown psCommand (not in dispatch table); add a Cfgms-* function and a case here")
}

// dispatchCreateVSwitchExternal handles the one dynamic psCommand —
// psCreateVSwitchExternal builds its string body with an embedded $true /
// $false literal because AllowManagementOS is a Go bool. We recover the
// bool by inspecting the suffix.
func (t *psHostTransport) dispatchCreateVSwitchExternal(ctx context.Context, psCommand string, psArgs map[string]string) (string, error) {
	allow := "$false"
	if strings.HasSuffix(strings.TrimSpace(psCommand), "$true | Out-Null") {
		allow = "$true"
	}
	return t.run(ctx,
		"Cfgms-CreateVSwitchExternal -Name "+quoteArg(psArgs, "Name")+
			" -NetAdapter "+quoteArg(psArgs, "NetAdapter")+
			" -AllowManagementOS "+allow)
}

// quoteArg returns the named psArgs value PS-quoted (single quotes,
// doubled-up internal single quotes). Missing keys return an empty quoted
// string so the generated invocation still parses; the upstream
// vm.go/vswitch.go callers always populate every key required
// by the verb they're invoking, so an empty here would itself indicate a
// caller bug — but we don't try to detect it here because the existing
// const-based call sites already validate the inputs.
func quoteArg(psArgs map[string]string, key string) string {
	return quoteForPS(psArgs[key])
}

// optArg renders an OPTIONAL named parameter: when psArgs[key] is non-empty it
// returns " -<paramName> '<quoted value>'", otherwise the empty string so the PS
// function's own default applies. This lets the cloud-init path pass extra args
// (Label, FileName2, Content2, StewardDest) to the shared seed functions while
// the legacy CFGMS_SEED single-file call sites stay byte-for-byte unchanged.
func optArg(psArgs map[string]string, paramName, key string) string {
	if psArgs[key] == "" {
		return ""
	}
	return " -" + paramName + " " + quoteForPS(psArgs[key])
}

// intArg returns the named psArgs value rendered as an unquoted bare
// integer literal. PowerShell's [int] / [long] type coercion handles the
// parameter casting; we just need a valid numeric literal. Non-numeric
// values would fail at the PS function's parameter binding stage with a
// clear error message that propagates back via the stderr drain.
func intArg(psArgs map[string]string, key string) string {
	v := strings.TrimSpace(psArgs[key])
	if v == "" {
		return "0"
	}
	return v
}
