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
// incoming psCommand against the known psXxx const set from vm.go,
// vswitch.go, and snapshot.go and dispatches the equivalent Cfgms-* verb
// over the persistent PS host.
//
// Unknown psCommand strings return an error rather than silently no-op'ing.
// We don't fall back to WinRM here — the wholesale-WinRM-fallback model
// from earlier #1887 drafts assumed WinRM worked; in this codebase it's
// reliably broken on the same-host deployment shape (see #1852 F16–F21).
// If a future verb gets added in vm.go/vswitch.go/snapshot.go without a
// matching Cfgms-* function, that's a build-time omission, not a runtime
// graceful degradation candidate.
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
				" -SwitchName "+quoteArg(psArgs, "SwitchName"))
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

	// ── Snapshot ────────────────────────────────────────────────────
	case psGetSnapshot:
		return t.run(ctx,
			"Cfgms-GetSnapshot -VMName "+quoteArg(psArgs, "VMName")+
				" -Name "+quoteArg(psArgs, "Name"))
	case psCreateSnapshot:
		return t.run(ctx,
			"Cfgms-CreateSnapshot -VMName "+quoteArg(psArgs, "VMName")+
				" -Name "+quoteArg(psArgs, "Name"))
	case psRemoveSnapshot:
		return t.run(ctx,
			"Cfgms-RemoveSnapshot -VMName "+quoteArg(psArgs, "VMName")+
				" -Name "+quoteArg(psArgs, "Name"))
	case psRestoreSnapshot:
		return t.run(ctx,
			"Cfgms-RestoreSnapshot -VMName "+quoteArg(psArgs, "VMName")+
				" -Name "+quoteArg(psArgs, "Name"))
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
// vm.go/vswitch.go/snapshot.go callers always populate every key required
// by the verb they're invoking, so an empty here would itself indicate a
// caller bug — but we don't try to detect it here because the existing
// const-based call sites already validate the inputs.
func quoteArg(psArgs map[string]string, key string) string {
	return quoteForPS(psArgs[key])
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
