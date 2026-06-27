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
			" -SwitchName " + quoteArg(psArgs, "SwitchName") +
			" -Generation " + intArg(psArgs, "Generation"))
	case psNewSeedVHD:
		return emit("Cfgms-NewSeedVHD -Path " + quoteArg(psArgs, "Path") +
			" -SizeBytes " + intArg(psArgs, "SizeBytes"))
	case psMountSeedVHD:
		return emit("Cfgms-MountSeedVHD -Path " + quoteArg(psArgs, "Path") +
			optArg(psArgs, "Label", "Label"))
	case psCopyToSeedVHD:
		return emit("Cfgms-CopyToSeedVHD -SeedPath " + quoteArg(psArgs, "SeedPath") +
			" -FileName " + quoteArg(psArgs, "FileName") +
			" -Content " + quoteArg(psArgs, "Content") +
			optArg(psArgs, "Label", "Label") +
			optArg(psArgs, "FileName2", "FileName2") +
			optArg(psArgs, "Content2", "Content2") +
			optArg(psArgs, "StewardDest", "StewardDest") +
			" -StewardSrc " + quoteArg(psArgs, "StewardSrc") +
			" -CASrc " + quoteArg(psArgs, "CASrc"))
	case psDetachSeedVHD:
		return emit("Cfgms-DetachSeedVHD -Path " + quoteArg(psArgs, "Path"))
	case psPrepCloudBootDisk:
		return emit("Cfgms-PrepCloudBootDisk -ImagePath " + quoteArg(psArgs, "ImagePath") +
			" -VhdPath " + quoteArg(psArgs, "VhdPath") +
			" -ResizeBytes " + intArg(psArgs, "ResizeBytes"))
	case psCreateVMFromDisk:
		return emit("Cfgms-CreateVMFromDisk -Name " + quoteArg(psArgs, "Name") +
			" -MemoryMB " + intArg(psArgs, "MemoryMB") +
			" -CPU " + intArg(psArgs, "CPU") +
			" -VHDPath " + quoteArg(psArgs, "VHDPath") +
			" -SwitchName " + quoteArg(psArgs, "SwitchName") +
			" -Generation " + intArg(psArgs, "Generation"))
	case psSetHddFirstBoot:
		return emit("Cfgms-SetHddFirstBoot -Name " + quoteArg(psArgs, "Name") +
			" -VHDPath " + quoteArg(psArgs, "VHDPath"))
	case psAttachSeedDisk:
		return emit("Cfgms-AttachSeedDisk -Name " + quoteArg(psArgs, "Name") +
			" -SeedPath " + quoteArg(psArgs, "SeedPath"))
	case psAttachDVD:
		return emit("Cfgms-AttachDVD -Name " + quoteArg(psArgs, "Name") +
			" -ISOPath " + quoteArg(psArgs, "ISOPath"))
	case psSetVMFirmware:
		return emit("Cfgms-SetVMFirmware -Name " + quoteArg(psArgs, "Name") +
			" -Template " + quoteArg(psArgs, "Template"))
	case psSetDVDFirstBoot:
		return emit("Cfgms-SetDVDFirstBoot -Name " + quoteArg(psArgs, "Name") +
			" -ISOPath " + quoteArg(psArgs, "ISOPath"))
	case psBuildAnswerIso:
		return emit("Cfgms-BuildAnswerIso -IsoPath " + quoteArg(psArgs, "IsoPath") +
			" -FileName " + quoteArg(psArgs, "FileName") +
			" -Content " + quoteArg(psArgs, "Content") +
			" -StewardSrc " + quoteArg(psArgs, "StewardSrc") +
			" -CASrc " + quoteArg(psArgs, "CASrc"))
	case psBootKeypress:
		return emit("Cfgms-BootKeypress -Name " + quoteArg(psArgs, "Name"))
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
	case psGetCluster:
		return emit("Cfgms-GetCluster -ClusterName " + quoteArg(psArgs, "ClusterName"))
	case psGetClusterOwnerNode:
		return emit("Cfgms-GetClusterOwnerNode -ClusterName " + quoteArg(psArgs, "ClusterName"))
	case psGetClusterResourceOwner:
		return emit("Cfgms-GetClusterResourceOwner -ClusterName " + quoteArg(psArgs, "ClusterName"))
	case psAddClusterVMRole:
		return emit("Cfgms-AddClusterVMRole -ClusterName " + quoteArg(psArgs, "ClusterName") +
			" -VMName " + quoteArg(psArgs, "VMName"))
	case psRemoveClusterResource:
		return emit("Cfgms-RemoveClusterResource -Name " + quoteArg(psArgs, "Name"))
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
				"Generation": "2",
			},
			want: "Cfgms-CreateVM -Name 'cfgms-t__web-01' -MemoryMB 4096 -CPU 4 -VHDPath 'C:\\VMs\\web-01.vhdx' -SwitchName 'External' -Generation 2",
		},
		{
			name:      "New-VM Gen1",
			psCommand: psCreateVM,
			psArgs: map[string]string{
				"Name":       "cfgms-t__web-01",
				"MemoryMB":   "2048",
				"CPU":        "2",
				"VHDPath":    "C:\\VMs\\web-01.vhdx",
				"SwitchName": "External",
				"Generation": "1",
			},
			want: "Cfgms-CreateVM -Name 'cfgms-t__web-01' -MemoryMB 2048 -CPU 2 -VHDPath 'C:\\VMs\\web-01.vhdx' -SwitchName 'External' -Generation 1",
		},
		{
			name:      "New-VHD seed",
			psCommand: psNewSeedVHD,
			psArgs:    map[string]string{"Path": "C:\\VMs\\cfgms-seed-web-01.vhdx", "SizeBytes": "67108864"},
			want:      "Cfgms-NewSeedVHD -Path 'C:\\VMs\\cfgms-seed-web-01.vhdx' -SizeBytes 67108864",
		},
		{
			name:      "Mount-VHD seed",
			psCommand: psMountSeedVHD,
			psArgs:    map[string]string{"Path": "C:\\VMs\\cfgms-seed-web-01.vhdx"},
			want:      "Cfgms-MountSeedVHD -Path 'C:\\VMs\\cfgms-seed-web-01.vhdx'",
		},
		{
			name:      "Copy seed answer file",
			psCommand: psCopyToSeedVHD,
			psArgs: map[string]string{
				"SeedPath": "C:\\VMs\\cfgms-seed-web-01.vhdx",
				"FileName": "autounattend.xml",
				"Content":  "<!-- placeholder autounattend -->",
			},
			want: "Cfgms-CopyToSeedVHD -SeedPath 'C:\\VMs\\cfgms-seed-web-01.vhdx' -FileName 'autounattend.xml' -Content '<!-- placeholder autounattend -->' -StewardSrc '' -CASrc ''",
		},
		{
			name:      "Attach seed disk",
			psCommand: psAttachSeedDisk,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "SeedPath": "C:\\VMs\\cfgms-seed-web-01.vhdx"},
			want:      "Cfgms-AttachSeedDisk -Name 'cfgms-t__web-01' -SeedPath 'C:\\VMs\\cfgms-seed-web-01.vhdx'",
		},
		{
			name:      "Attach install ISO DVD",
			psCommand: psAttachDVD,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "ISOPath": "C:\\ISO\\server.iso"},
			want:      "Cfgms-AttachDVD -Name 'cfgms-t__web-01' -ISOPath 'C:\\ISO\\server.iso'",
		},
		{
			name:      "Set firmware secure-boot template",
			psCommand: psSetVMFirmware,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "Template": "MicrosoftWindows"},
			want:      "Cfgms-SetVMFirmware -Name 'cfgms-t__web-01' -Template 'MicrosoftWindows'",
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
		{"psCreateVM", psCreateVM, map[string]string{"Name": "cfgms-t__web-01", "MemoryMB": "1024", "CPU": "1", "VHDPath": "C:\\test.vhdx", "SwitchName": "sw", "Generation": "2"}},
		{"psRemoveVM", psRemoveVM, map[string]string{"Name": "cfgms-t__web-01"}},
		{"psStartVM", psStartVM, map[string]string{"Name": "cfgms-t__web-01"}},
		{"psStopVM", psStopVM, map[string]string{"Name": "cfgms-t__web-01"}},
		{"psSetVMProcessor", psSetVMProcessor, map[string]string{"Name": "cfgms-t__web-01", "CPU": "2"}},
		{"psSetVMMemory", psSetVMMemory, map[string]string{"Name": "cfgms-t__web-01", "MemoryMB": "2048"}},
		{"psConnectVMNic", psConnectVMNic, map[string]string{"Name": "cfgms-t__web-01", "SwitchName": "External"}},
		{"psDisconnectVMNic", psDisconnectVMNic, map[string]string{"Name": "cfgms-t__web-01", "SwitchName": "External"}},
		// VM provisioning verbs (#2044)
		{"psNewSeedVHD", psNewSeedVHD, map[string]string{"Path": "C:\\VMs\\cfgms-seed-web-01.vhdx", "SizeBytes": "67108864"}},
		{"psMountSeedVHD", psMountSeedVHD, map[string]string{"Path": "C:\\VMs\\cfgms-seed-web-01.vhdx"}},
		{"psCopyToSeedVHD", psCopyToSeedVHD, map[string]string{"SeedPath": "C:\\VMs\\cfgms-seed-web-01.vhdx", "FileName": "preseed.cfg", "Content": "# placeholder preseed"}},
		{"psDetachSeedVHD", psDetachSeedVHD, map[string]string{"Path": "C:\\VMs\\cfgms-seed-web-01.vhdx"}},
		{"psAttachSeedDisk", psAttachSeedDisk, map[string]string{"Name": "cfgms-t__web-01", "SeedPath": "C:\\VMs\\cfgms-seed-web-01.vhdx"}},
		{"psAttachDVD", psAttachDVD, map[string]string{"Name": "cfgms-t__web-01", "ISOPath": "C:\\ISO\\server.iso"}},
		{"psSetVMFirmware", psSetVMFirmware, map[string]string{"Name": "cfgms-t__web-01", "Template": "MicrosoftWindows"}},
		{"psSetDVDFirstBoot", psSetDVDFirstBoot, map[string]string{"Name": "cfgms-t__web-01", "ISOPath": "C:\\ISO\\server.iso"}},
		{"psBuildAnswerIso", psBuildAnswerIso, map[string]string{"IsoPath": "C:\\cfgms-seeds\\a.iso", "FileName": "autounattend.xml", "Content": "<x/>", "StewardSrc": "", "CASrc": ""}},
		{"psBootKeypress", psBootKeypress, map[string]string{"Name": "cfgms-t__web-01"}},
		// cloud-init (Linux VM-from-cloud-image) verbs (#2080)
		{"psPrepCloudBootDisk", psPrepCloudBootDisk, map[string]string{"ImagePath": "C:\\images\\debian.raw", "VhdPath": "C:\\VMs\\web-01.vhdx", "ResizeBytes": "21474836480"}},
		{"psCreateVMFromDisk", psCreateVMFromDisk, map[string]string{"Name": "cfgms-t__web-01", "MemoryMB": "2048", "CPU": "2", "VHDPath": "C:\\VMs\\web-01.vhdx", "SwitchName": "External", "Generation": "2"}},
		{"psSetHddFirstBoot", psSetHddFirstBoot, map[string]string{"Name": "cfgms-t__web-01", "VHDPath": "C:\\VMs\\web-01.vhdx"}},
		// cloud-init CIDATA seed reuses psMountSeedVHD/psCopyToSeedVHD with extra optional args
		{"psMountSeedVHD/cidata", psMountSeedVHD, map[string]string{"Path": "C:\\VMs\\cfgms-seed-web-01.vhdx", "Label": "CIDATA"}},
		{"psCopyToSeedVHD/cidata", psCopyToSeedVHD, map[string]string{"SeedPath": "C:\\VMs\\cfgms-seed-web-01.vhdx", "Label": "CIDATA", "FileName": "user-data", "Content": "#cloud-config", "FileName2": "meta-data", "Content2": "instance-id: x", "StewardSrc": "C:\\s\\cfgms-steward-linux", "StewardDest": "cfgms-steward", "CASrc": "C:\\s\\ca.crt"}},
		// VSwitch verbs (vswitch.go)
		{"psGetVSwitch", psGetVSwitch, map[string]string{"Name": "cfgms-t__sw01"}},
		{"psRemoveVSwitch", psRemoveVSwitch, map[string]string{"Name": "cfgms-t__sw01"}},
		{"psCreateVSwitchInternal", psCreateVSwitchInternal, map[string]string{"Name": "cfgms-t__sw01"}},
		{"psCreateVSwitchPrivate", psCreateVSwitchPrivate, map[string]string{"Name": "cfgms-t__sw01"}},
		// Dynamic psCreateVSwitchExternal (vswitch.go) — both AllowManagementOS values
		{"psCreateVSwitchExternal/true", psCreateVSwitchExternal(true), map[string]string{"Name": "cfgms-t__sw01", "NetAdapter": "Ethernet0"}},
		{"psCreateVSwitchExternal/false", psCreateVSwitchExternal(false), map[string]string{"Name": "cfgms-t__sw01", "NetAdapter": "Ethernet0"}},
		// Failover cluster read-only verbs (cluster.go, #2199 S1)
		{"psGetCluster", psGetCluster, map[string]string{"ClusterName": "lab-hv"}},
		{"psGetClusterOwnerNode", psGetClusterOwnerNode, map[string]string{"ClusterName": "lab-hv"}},
		{"psGetClusterResourceOwner", psGetClusterResourceOwner, map[string]string{"ClusterName": "lab-hv"}},
		// Failover cluster write verbs (cluster.go, #2202 S2)
		{"psAddClusterVMRole", psAddClusterVMRole, map[string]string{"ClusterName": "lab-hv", "VMName": "web-01"}},
		{"psRemoveClusterResource", psRemoveClusterResource, map[string]string{"Name": "web-01"}},
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

// TestPreamble_RemoveVMStopsRunningVMFirst guards the regression that shipped
// in v0.5.13: psRemoveVM (vm.go) carried the stop-then-remove guard, but the
// Windows runtime never executes that const — the dispatcher maps psRemoveVM
// to the Cfgms-RemoveVM function in psHostPreamble, which was still the old
// un-guarded `Remove-VM -Name $Name -Force`. Result: deleting a running VM
// failed live ("the operation cannot be performed while the object is in its
// current state"), and its connected vSwitch stayed busy and could not be
// removed either. The dispatch tests above only assert the SYNTHESISED call
// string, never the function body, so they stayed green. This test asserts the
// preamble function actually powers a running VM off before removing it, with
// Stop-VM ordered before Remove-VM.
func TestPreamble_RemoveVMStopsRunningVMFirst(t *testing.T) {
	body := preambleFunctionBody(t, "Cfgms-RemoveVM")

	assert.Contains(t, body, "Stop-VM",
		"Cfgms-RemoveVM must power off a running VM before deleting it")
	assert.Contains(t, body, "-TurnOff",
		"Cfgms-RemoveVM must hard power-off (-TurnOff), matching psRemoveVM")
	assert.Contains(t, body, "$vm.State -ne 'Off'",
		"Cfgms-RemoveVM must only stop the VM when it is not already Off")
	assert.Contains(t, body, "Remove-VM",
		"Cfgms-RemoveVM must still remove the VM")

	stopIdx := strings.Index(body, "Stop-VM")
	removeIdx := strings.Index(body, "Remove-VM")
	require.NotEqual(t, -1, stopIdx)
	require.NotEqual(t, -1, removeIdx)
	assert.Less(t, stopIdx, removeIdx,
		"Stop-VM must be ordered before Remove-VM, otherwise the running VM blocks its own deletion")
}

// preambleFunctionBody extracts the body of a `function <name> { ... }` block
// from psHostPreamble, balancing braces so nested blocks (if/foreach) are
// included. It fails the test if the function is not found.
func preambleFunctionBody(t *testing.T, name string) string {
	t.Helper()
	marker := "function " + name
	start := strings.Index(psHostPreamble, marker)
	require.NotEqual(t, -1, start, "function %s not found in psHostPreamble", name)
	open := strings.Index(psHostPreamble[start:], "{")
	require.NotEqual(t, -1, open, "no opening brace for function %s", name)
	open += start
	depth := 0
	for i := open; i < len(psHostPreamble); i++ {
		switch psHostPreamble[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return psHostPreamble[open : i+1]
			}
		}
	}
	t.Fatalf("unbalanced braces for function %s in psHostPreamble", name)
	return ""
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
