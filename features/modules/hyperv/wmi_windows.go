// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

// Package hyperv WMI transport.
//
// wmiTransport replaces WinRM as the primary transport for Hyper-V operations
// when the steward runs ON the Hyper-V host itself (the only deployment shape
// after #1894 lands). It connects directly to the local WMI provider in the
// `root\virtualization\v2` namespace — no listener, no NTLM, no LSA loopback,
// no service-account, no trust-store dance.
//
// # Transport contract
//
// wmiTransport satisfies the existing winrmTransport interface so the module's
// vm.go / vswitch.go / snapshot.go call sites are unchanged. Each call into
// ExecutePS pattern-matches the psCommand string constant against the known
// set and dispatches to a WMI-equivalent operation. Unknown commands return
// ErrUseWinRMFallback so hypervModule can retry via winrmClient.
//
// # WMI library choice
//
// Read paths (Get-VM, Get-VMSwitch, Get-VMSnapshot, Get-VMNetworkAdapter) use
// github.com/yusufpapurcu/wmi's high-level QueryNamespace — WQL is sufficient.
//
// Method invocations on the singleton management services
// (Msvm_VirtualSystemManagementService.DefineSystem,
// Msvm_ComputerSystem.RequestStateChange,
// Msvm_VirtualSystemSnapshotService.CreateSnapshot, etc.) require instance
// method calls against a specific WMI object. The high-level package only
// exposes static class method invocation; we drop down to its underlying
// go-ole COM dispatch for these. The package is a thin wrapper over go-ole
// (it imports it itself) so using both is consistent.
package hyperv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/yusufpapurcu/wmi"
)

// hypervNamespace is the WMI namespace for the Hyper-V V2 provider. Present on
// every Windows host with the Hyper-V role installed; absent (returns
// WBEM_E_INVALID_NAMESPACE) on hosts without it — that's how detection in
// detection_windows.go differentiates Hyper-V vs non-Hyper-V hosts.
const hypervNamespace = `root\virtualization\v2`

// ErrUseWinRMFallback signals to hypervModule that the requested operation
// has no clean WMI equivalent and the module should retry the same psCommand
// via the WinRM client. Returned by ExecutePS for psCommands that wmiTransport
// has not (yet) implemented.
var ErrUseWinRMFallback = errors.New("hyperv: wmi transport has no equivalent — fall back to winrm")

// wmiTransport executes the module's PowerShell-shaped operations against the
// local Hyper-V WMI provider. Zero value is a working transport; no init or
// connection setup is needed (each ExecutePS opens its own short-lived
// WMI client).
type wmiTransport struct {
	// tenantID is used to build the cfgms-<tenant>__ host-side prefix when
	// matching incoming psArgs against persisted WMI ElementName values.
	// Optional — the module already prefixes names before calling ExecutePS,
	// so tenantID here is informational and may be used by future verbs that
	// need to enumerate the steward's VMs without a specific name.
	tenantID string

	// client allows tests to inject a recording client. Production callers
	// leave this nil and the package-level Query/CallMethod helpers are used,
	// which means the OS WMI provider is hit directly.
	client *wmi.Client
}

// newWMITransport creates a wmiTransport. tenantID is informational only — the
// hypervModule prefixes ElementNames before dispatch, so the transport itself
// is tenant-agnostic for the verbs we have today.
func newWMITransport(tenantID string) *wmiTransport {
	return &wmiTransport{tenantID: tenantID}
}

// ExecutePS pattern-matches psCommand against the known PowerShell command
// templates from vm.go / vswitch.go / snapshot.go and dispatches to a WMI
// equivalent. Returns ErrUseWinRMFallback for unknown commands so the module
// can retry via winrmClient.
func (t *wmiTransport) ExecutePS(ctx context.Context, psCommand string, psArgs map[string]string) (string, error) {
	switch psCommand {
	case psGetVM:
		return t.getVM(ctx, psArgs)
	default:
		return "", ErrUseWinRMFallback
	}
}

// msvmComputerSystem is the WMI projection of Hyper-V's `Msvm_ComputerSystem`
// instance for a guest VM. We project only the fields the module's psGetVM
// output JSON contains; the package's struct-based mapping fills the rest of
// the response shape (Caption, Description, etc.) lazily.
//
// Field types match the WMI provider's reported types (uint64 for memory,
// uint16 for state, etc.). The high-level package handles the COM → Go
// conversion.
type msvmComputerSystem struct {
	ElementName string
	Name        string // VM GUID; not the user-visible name (that's ElementName)
	EnabledState uint16
}

// getVM translates psGetVM (Get-VM with -Name $Name) into a WMI query and
// returns the JSON shape the existing parsing code in vm.go expects:
//
//	{"found":true,"Name":"<hostName>","MemoryStartupBytes":<n>,"ProcessorCount":<n>,
//	 "Generation":<n>,"Path":"<p>","SwitchName":"<sw>","State":"<state>"}
//
// or {"found":false} when no VM matches the requested name.
//
// The WMI query is a WQL SELECT on Msvm_ComputerSystem filtered by
// ElementName (the user-visible / cfgms-prefixed name). Additional details
// (memory, CPU, generation, path, switch) are sourced from associated
// instances via secondary queries — this matches the layered shape of the
// Hyper-V WMI provider where each "VM aspect" is its own associated class.
//
// For the very first end-to-end validation we only populate the fields that
// drive drift detection: found + ElementName + EnabledState mapping. The
// remaining fields (Memory/CPU/Generation/Path/SwitchName) are filled in
// progressively as we wire each verb. Empty values are returned in their
// type's zero form so the parser in vm.go:getVM keeps working.
func (t *wmiTransport) getVM(ctx context.Context, psArgs map[string]string) (string, error) {
	name := psArgs["Name"]
	if name == "" {
		return "", fmt.Errorf("hyperv-wmi: getVM: Name argument is required")
	}

	// Filter by ElementName (the user-visible/host-prefixed name); exclude the
	// host's own Msvm_ComputerSystem (whose Caption is "Hosting Computer
	// System") via the standard "Caption = 'Virtual Machine'" guard.
	query := fmt.Sprintf(
		"SELECT ElementName, Name, EnabledState FROM Msvm_ComputerSystem "+
			"WHERE Caption = 'Virtual Machine' AND ElementName = %s",
		quoteWQL(name))

	var rows []msvmComputerSystem
	if err := t.queryNamespace(query, &rows); err != nil {
		return "", fmt.Errorf("hyperv-wmi: getVM query: %w", err)
	}

	if len(rows) == 0 {
		return `{"found":false}`, nil
	}

	vm := rows[0]
	state := mapEnabledStateToHyperVState(vm.EnabledState)

	// Mirror psGetVM's JSON shape so vm.go:getVM's parser is unmodified.
	// Memory/CPU/Generation/Path/SwitchName are filled in via secondary
	// associated-class queries as their verbs are wired up; for now we emit
	// zero values that vm.go handles cleanly (it tolerates missing optional
	// fields).
	resp := map[string]interface{}{
		"found":              true,
		"Name":               vm.ElementName,
		"MemoryStartupBytes": int64(0),
		"ProcessorCount":     0,
		"Generation":         0,
		"Path":               "",
		"SwitchName":         "",
		"State":              state,
	}
	buf, err := json.Marshal(resp)
	if err != nil {
		return "", fmt.Errorf("hyperv-wmi: getVM marshal: %w", err)
	}
	return string(buf), nil
}

// queryNamespace runs a WQL query against the Hyper-V namespace using the
// configured client (or the package default when client is nil). Centralised
// so tests can swap in a recording client and so future error wrapping is
// in one place.
func (t *wmiTransport) queryNamespace(query string, dst interface{}) error {
	if t.client != nil {
		return t.client.Query(query, dst, nil, hypervNamespace)
	}
	return wmi.QueryNamespace(query, dst, hypervNamespace)
}

// mapEnabledStateToHyperVState converts the WMI Msvm_ComputerSystem
// EnabledState integer value (CIM-defined) to the string form the existing
// psGetVM output uses ("Running", "Off", "Paused", etc.). vm.go:getVM then
// lowercases these into the module's "running" / "stopped" vocabulary.
//
// Reference values come from CIM_EnabledLogicalElement and the Hyper-V
// extension overlay (Msvm_ComputerSystem). Defined inline rather than via
// a typed constant set because we only consume a handful and round-tripping
// to enum types here would add noise without value.
func mapEnabledStateToHyperVState(state uint16) string {
	switch state {
	case 2:
		return "Running"
	case 3:
		return "Off"
	case 32768:
		return "Paused"
	case 32769:
		return "Suspended"
	case 32770:
		return "Starting"
	case 32773:
		return "Saving"
	case 32774:
		return "Stopping"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

// quoteWQL wraps a string in single quotes and escapes any embedded single
// quotes per WQL syntax (doubled, not backslash-escaped). The module already
// validates names against a strict allowlist before they reach the
// transport, but defense-in-depth: if a non-validated value ever sneaks
// through, the worst it can do is be quoted incorrectly inside the WHERE
// clause — never injected as a separate clause.
func quoteWQL(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
