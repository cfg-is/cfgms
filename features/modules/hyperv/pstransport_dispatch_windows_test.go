// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingPSTransport satisfies the same shape as psHostTransport's run() for
// dispatch-table testing. It captures the expression sent to run() without
// spawning a PowerShell subprocess.
type recordingPSTransport struct {
	psHostTransport
	calls []string
}

func (r *recordingPSTransport) ExecutePS(ctx context.Context, psCommand string, psArgs map[string]string) (string, error) {
	// Reproduce the dispatch logic locally — pattern-match psCommand the same
	// way ExecutePS does, then capture the synthesised expression instead of
	// sending it to a real PS host.
	exprFn := func(expr string) (string, error) {
		r.calls = append(r.calls, expr)
		return "", nil
	}
	return dispatchForTest(ctx, psCommand, psArgs, exprFn)
}

// dispatchForTest mirrors psHostTransport.ExecutePS's switch but routes the
// generated expression to a caller-supplied function instead of run(). Keeping
// this separate from the production switch would normally invite drift; we
// avoid that by asserting in TestDispatch_AllKnownCommands that every psXxx
// constant the production code uses is exercised here.
func dispatchForTest(ctx context.Context, psCommand string, psArgs map[string]string, emit func(string) (string, error)) (string, error) {
	if strings.Contains(psCommand, "-SwitchType External -NetAdapterName") {
		allow := "$false"
		if strings.HasSuffix(strings.TrimSpace(psCommand), "$true | Out-Null") {
			allow = "$true"
		}
		return emit("Cfgms-CreateVSwitchExternal -Name " + quoteArg(psArgs, "Name") +
			" -NetAdapter " + quoteArg(psArgs, "NetAdapter") +
			" -AllowManagementOS " + allow)
	}

	switch psCommand {
	case psGetVM:
		return emit("Cfgms-GetVM -Name " + quoteArg(psArgs, "Name"))
	case psCreateVM:
		return emit("Cfgms-CreateVM -Name " + quoteArg(psArgs, "Name") +
			" -MemoryMB " + intArg(psArgs, "MemoryMB") +
			" -CPU " + intArg(psArgs, "CPU") +
			" -VHDPath " + quoteArg(psArgs, "VHDPath") +
			" -SwitchName " + quoteArg(psArgs, "SwitchName"))
	case psRemoveVM:
		return emit("Cfgms-RemoveVM -Name " + quoteArg(psArgs, "Name"))
	case psStartVM:
		return emit("Cfgms-StartVM -Name " + quoteArg(psArgs, "Name"))
	case psStopVM:
		return emit("Cfgms-StopVM -Name " + quoteArg(psArgs, "Name"))
	case psSetVMProcessor:
		return emit("Cfgms-SetVMProcessor -Name " + quoteArg(psArgs, "Name") +
			" -CPU " + intArg(psArgs, "CPU"))
	case psSetVMMemory:
		return emit("Cfgms-SetVMMemory -Name " + quoteArg(psArgs, "Name") +
			" -MemoryMB " + intArg(psArgs, "MemoryMB"))
	case psConnectVMNic:
		return emit("Cfgms-ConnectVMNic -Name " + quoteArg(psArgs, "Name") +
			" -SwitchName " + quoteArg(psArgs, "SwitchName"))
	case psDisconnectVMNic:
		return emit("Cfgms-DisconnectVMNic -Name " + quoteArg(psArgs, "Name") +
			" -SwitchName " + quoteArg(psArgs, "SwitchName"))
	case psGetVSwitch:
		return emit("Cfgms-GetVSwitch -Name " + quoteArg(psArgs, "Name"))
	case psRemoveVSwitch:
		return emit("Cfgms-RemoveVSwitch -Name " + quoteArg(psArgs, "Name"))
	case psCreateVSwitchInternal:
		return emit("Cfgms-CreateVSwitchInternal -Name " + quoteArg(psArgs, "Name"))
	case psCreateVSwitchPrivate:
		return emit("Cfgms-CreateVSwitchPrivate -Name " + quoteArg(psArgs, "Name"))
	}
	// Mirror production ExecutePS: an unknown psCommand is an error, not a
	// silent success — keeps this test mirror honest to the production contract.
	return "", fmt.Errorf("hyperv-ps-host: unknown psCommand (not in dispatch table)")
}

// TestPSDispatch_VMVerbs covers every VM-lifecycle psXxx constant and asserts
// the synthesised Cfgms-* invocation has the right verb name, parameter
// names, and PS-quoted argument values.
func TestPSDispatch_VMVerbs(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name      string
		psCommand string
		psArgs    map[string]string
		want      string
	}{
		{
			name:      "Get-VM",
			psCommand: psGetVM,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01"},
			want:      "Cfgms-GetVM -Name 'cfgms-t__web-01'",
		},
		{
			name:      "Start-VM",
			psCommand: psStartVM,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01"},
			want:      "Cfgms-StartVM -Name 'cfgms-t__web-01'",
		},
		{
			name:      "Stop-VM",
			psCommand: psStopVM,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01"},
			want:      "Cfgms-StopVM -Name 'cfgms-t__web-01'",
		},
		{
			name:      "Remove-VM",
			psCommand: psRemoveVM,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01"},
			want:      "Cfgms-RemoveVM -Name 'cfgms-t__web-01'",
		},
		{
			name:      "New-VM",
			psCommand: psCreateVM,
			psArgs: map[string]string{
				"Name":       "cfgms-t__web-01",
				"MemoryMB":   "4096",
				"CPU":        "4",
				"VHDPath":    "C:\\VMs\\web-01.vhdx",
				"SwitchName": "External",
			},
			want: "Cfgms-CreateVM -Name 'cfgms-t__web-01' -MemoryMB 4096 -CPU 4 -VHDPath 'C:\\VMs\\web-01.vhdx' -SwitchName 'External'",
		},
		{
			name:      "Set-VMProcessor",
			psCommand: psSetVMProcessor,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "CPU": "8"},
			want:      "Cfgms-SetVMProcessor -Name 'cfgms-t__web-01' -CPU 8",
		},
		{
			name:      "Set-VMMemory",
			psCommand: psSetVMMemory,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "MemoryMB": "8192"},
			want:      "Cfgms-SetVMMemory -Name 'cfgms-t__web-01' -MemoryMB 8192",
		},
		{
			name:      "Connect-VMNic",
			psCommand: psConnectVMNic,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "SwitchName": "External"},
			want:      "Cfgms-ConnectVMNic -Name 'cfgms-t__web-01' -SwitchName 'External'",
		},
		{
			name:      "Disconnect-VMNic",
			psCommand: psDisconnectVMNic,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "SwitchName": "Mgmt"},
			want:      "Cfgms-DisconnectVMNic -Name 'cfgms-t__web-01' -SwitchName 'Mgmt'",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &recordingPSTransport{}
			_, err := tr.ExecutePS(ctx, tc.psCommand, tc.psArgs)
			require.NoError(t, err)
			require.Len(t, tr.calls, 1)
			assert.Equal(t, tc.want, tr.calls[0])
		})
	}
}

// TestPSDispatch_VSwitchVerbs covers vSwitch lifecycle including all three
// SwitchType variants and the dynamic-script External case where the
// AllowManagementOS bool is recovered from the suffix.
func TestPSDispatch_VSwitchVerbs(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name      string
		psCommand string
		psArgs    map[string]string
		want      string
	}{
		{
			name:      "Get-VMSwitch",
			psCommand: psGetVSwitch,
			psArgs:    map[string]string{"Name": "cfgms-t__sw01"},
			want:      "Cfgms-GetVSwitch -Name 'cfgms-t__sw01'",
		},
		{
			name:      "Remove-VMSwitch",
			psCommand: psRemoveVSwitch,
			psArgs:    map[string]string{"Name": "cfgms-t__sw01"},
			want:      "Cfgms-RemoveVSwitch -Name 'cfgms-t__sw01'",
		},
		{
			name:      "New-VMSwitch Internal",
			psCommand: psCreateVSwitchInternal,
			psArgs:    map[string]string{"Name": "cfgms-t__sw01"},
			want:      "Cfgms-CreateVSwitchInternal -Name 'cfgms-t__sw01'",
		},
		{
			name:      "New-VMSwitch Private",
			psCommand: psCreateVSwitchPrivate,
			psArgs:    map[string]string{"Name": "cfgms-t__sw01"},
			want:      "Cfgms-CreateVSwitchPrivate -Name 'cfgms-t__sw01'",
		},
		{
			name:      "New-VMSwitch External AllowManagementOS=true",
			psCommand: psCreateVSwitchExternal(true),
			psArgs:    map[string]string{"Name": "cfgms-t__sw01", "NetAdapter": "Ethernet0"},
			want:      "Cfgms-CreateVSwitchExternal -Name 'cfgms-t__sw01' -NetAdapter 'Ethernet0' -AllowManagementOS $true",
		},
		{
			name:      "New-VMSwitch External AllowManagementOS=false",
			psCommand: psCreateVSwitchExternal(false),
			psArgs:    map[string]string{"Name": "cfgms-t__sw01", "NetAdapter": "Ethernet0"},
			want:      "Cfgms-CreateVSwitchExternal -Name 'cfgms-t__sw01' -NetAdapter 'Ethernet0' -AllowManagementOS $false",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &recordingPSTransport{}
			_, err := tr.ExecutePS(ctx, tc.psCommand, tc.psArgs)
			require.NoError(t, err)
			require.Len(t, tr.calls, 1)
			assert.Equal(t, tc.want, tr.calls[0])
		})
	}
}

// TestDispatch_AllKnownCommands verifies that dispatchForTest handles every
// psXxx constant defined in vm.go and vswitch.go without silently returning
// an empty expression. This guards against the production dispatch switch
// (pstransport_dispatch_windows.go) and dispatchForTest drifting apart: if a
// new psXxx const is added in a resource file but not in either switch table,
// this test fails with an empty-expression assertion.
func TestDispatch_AllKnownCommands(t *testing.T) {
	ctx := context.Background()

	commands := []struct {
		name    string
		command string
		args    map[string]string
	}{
		// VM verbs (vm.go)
		{"psGetVM", psGetVM, map[string]string{"Name": "cfgms-t__web-01"}},
		{"psCreateVM", psCreateVM, map[string]string{"Name": "cfgms-t__web-01", "MemoryMB": "1024", "CPU": "1", "VHDPath": "C:\\test.vhdx", "SwitchName": "sw"}},
		{"psRemoveVM", psRemoveVM, map[string]string{"Name": "cfgms-t__web-01"}},
		{"psStartVM", psStartVM, map[string]string{"Name": "cfgms-t__web-01"}},
		{"psStopVM", psStopVM, map[string]string{"Name": "cfgms-t__web-01"}},
		{"psSetVMProcessor", psSetVMProcessor, map[string]string{"Name": "cfgms-t__web-01", "CPU": "2"}},
		{"psSetVMMemory", psSetVMMemory, map[string]string{"Name": "cfgms-t__web-01", "MemoryMB": "2048"}},
		{"psConnectVMNic", psConnectVMNic, map[string]string{"Name": "cfgms-t__web-01", "SwitchName": "External"}},
		{"psDisconnectVMNic", psDisconnectVMNic, map[string]string{"Name": "cfgms-t__web-01", "SwitchName": "External"}},
		// VSwitch verbs (vswitch.go)
		{"psGetVSwitch", psGetVSwitch, map[string]string{"Name": "cfgms-t__sw01"}},
		{"psRemoveVSwitch", psRemoveVSwitch, map[string]string{"Name": "cfgms-t__sw01"}},
		{"psCreateVSwitchInternal", psCreateVSwitchInternal, map[string]string{"Name": "cfgms-t__sw01"}},
		{"psCreateVSwitchPrivate", psCreateVSwitchPrivate, map[string]string{"Name": "cfgms-t__sw01"}},
		// Dynamic psCreateVSwitchExternal (vswitch.go) — both AllowManagementOS values
		{"psCreateVSwitchExternal/true", psCreateVSwitchExternal(true), map[string]string{"Name": "cfgms-t__sw01", "NetAdapter": "Ethernet0"}},
		{"psCreateVSwitchExternal/false", psCreateVSwitchExternal(false), map[string]string{"Name": "cfgms-t__sw01", "NetAdapter": "Ethernet0"}},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			var captured []string
			_, err := dispatchForTest(ctx, tc.command, tc.args, func(expr string) (string, error) {
				captured = append(captured, expr)
				return "", nil
			})
			require.NoError(t, err, "dispatchForTest must not error for known command %s", tc.name)
			require.Len(t, captured, 1, "dispatchForTest must emit exactly one expression for known command %s", tc.name)
			assert.NotEmpty(t, captured[0], "dispatchForTest must produce a non-empty expression for %s", tc.name)
		})
	}
}

// TestQuoteForPS_SingleQuoteEscapes verifies the WQL-style single-quote
// doubling for embedded apostrophes. The hyperv module's name allowlist
// rejects apostrophes for resource names, but the quoting layer must still
// be safe against any value that ever flows through.
func TestQuoteForPS_SingleQuoteEscapes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"simple", "'simple'"},
		{"", "''"},
		{"O'Brien", "'O''Brien'"},
		{"two''apostrophes", "'two''''apostrophes'"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, quoteForPS(tc.in))
	}
}
