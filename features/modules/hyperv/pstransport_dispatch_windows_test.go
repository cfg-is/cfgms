// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPSDispatch_VMVerbs covers every VM-lifecycle psXxx constant and asserts
// the production planPSCall picks the right verb and produces the right
// parameter names, order and JSON types.
func TestPSDispatch_VMVerbs(t *testing.T) {
	cases := []struct {
		name      string
		psCommand string
		psArgs    map[string]string
		wantVerb  string
		wantJSON  string
	}{
		{
			name:      "Get-VM",
			psCommand: psGetVM,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01"},
			wantVerb:  "GetVM",
			wantJSON:  `{"Name":"cfgms-t__web-01"}`,
		},
		{
			name:      "Start-VM",
			psCommand: psStartVM,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01"},
			wantVerb:  "StartVM",
			wantJSON:  `{"Name":"cfgms-t__web-01"}`,
		},
		{
			name:      "Stop-VM",
			psCommand: psStopVM,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01"},
			wantVerb:  "StopVM",
			wantJSON:  `{"Name":"cfgms-t__web-01"}`,
		},
		{
			name:      "Remove-VM",
			psCommand: psRemoveVM,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01"},
			wantVerb:  "RemoveVM",
			wantJSON:  `{"Name":"cfgms-t__web-01"}`,
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
			wantVerb: "CreateVM",
			wantJSON: `{"Name":"cfgms-t__web-01","MemoryMB":4096,"CPU":4,"VHDPath":"C:\\VMs\\web-01.vhdx","SwitchName":"External","Generation":2}`,
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
			wantVerb: "CreateVM",
			wantJSON: `{"Name":"cfgms-t__web-01","MemoryMB":2048,"CPU":2,"VHDPath":"C:\\VMs\\web-01.vhdx","SwitchName":"External","Generation":1}`,
		},
		{
			name:      "New-VHD seed",
			psCommand: psNewSeedVHD,
			psArgs:    map[string]string{"Path": "C:\\VMs\\cfgms-seed-web-01.vhdx", "SizeBytes": "67108864"},
			wantVerb:  "NewSeedVHD",
			wantJSON:  `{"Path":"C:\\VMs\\cfgms-seed-web-01.vhdx","SizeBytes":67108864}`,
		},
		{
			name:      "Mount-VHD seed",
			psCommand: psMountSeedVHD,
			psArgs:    map[string]string{"Path": "C:\\VMs\\cfgms-seed-web-01.vhdx"},
			wantVerb:  "MountSeedVHD",
			wantJSON:  `{"Path":"C:\\VMs\\cfgms-seed-web-01.vhdx"}`,
		},
		{
			name:      "Copy seed answer file",
			psCommand: psCopyToSeedVHD,
			psArgs: map[string]string{
				"SeedPath": "C:\\VMs\\cfgms-seed-web-01.vhdx",
				"FileName": "autounattend.xml",
				"Content":  "<!-- placeholder autounattend -->",
			},
			wantVerb: "CopyToSeedVHD",
			wantJSON: `{"SeedPath":"C:\\VMs\\cfgms-seed-web-01.vhdx","FileName":"autounattend.xml","Content":"\u003c!-- placeholder autounattend --\u003e","StewardSrc":"","CASrc":""}`,
		},
		{
			name:      "Attach seed disk",
			psCommand: psAttachSeedDisk,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "SeedPath": "C:\\VMs\\cfgms-seed-web-01.vhdx"},
			wantVerb:  "AttachSeedDisk",
			wantJSON:  `{"Name":"cfgms-t__web-01","SeedPath":"C:\\VMs\\cfgms-seed-web-01.vhdx"}`,
		},
		{
			name:      "Attach install ISO DVD",
			psCommand: psAttachDVD,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "ISOPath": "C:\\ISO\\server.iso"},
			wantVerb:  "AttachDVD",
			wantJSON:  `{"Name":"cfgms-t__web-01","ISOPath":"C:\\ISO\\server.iso"}`,
		},
		{
			name:      "Set firmware secure-boot template",
			psCommand: psSetVMFirmware,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "Template": "MicrosoftWindows"},
			wantVerb:  "SetVMFirmware",
			wantJSON:  `{"Name":"cfgms-t__web-01","Template":"MicrosoftWindows"}`,
		},
		{
			name:      "Set-VMProcessor",
			psCommand: psSetVMProcessor,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "CPU": "8"},
			wantVerb:  "SetVMProcessor",
			wantJSON:  `{"Name":"cfgms-t__web-01","CPU":8}`,
		},
		{
			name:      "Set-VMMemory",
			psCommand: psSetVMMemory,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "MemoryMB": "8192"},
			wantVerb:  "SetVMMemory",
			wantJSON:  `{"Name":"cfgms-t__web-01","MemoryMB":8192}`,
		},
		{
			// #2411: -Path (the VM home, dir(vhd_path)) rides New-VM as an
			// optional arg so config files start co-located with the disk.
			name:      "New-VM with home Path",
			psCommand: psCreateVM,
			psArgs: map[string]string{
				"Name":       "cfgms-t__web-01",
				"MemoryMB":   "4096",
				"CPU":        "4",
				"VHDPath":    "C:\\VMs\\web-01\\web-01.vhdx",
				"SwitchName": "External",
				"Generation": "2",
				"Path":       "C:\\VMs\\web-01",
			},
			wantVerb: "CreateVM",
			wantJSON: `{"Name":"cfgms-t__web-01","MemoryMB":4096,"CPU":4,"VHDPath":"C:\\VMs\\web-01\\web-01.vhdx","SwitchName":"External","Generation":2,"Path":"C:\\VMs\\web-01"}`,
		},
		{
			// #2411: the create-time config-only home move. NOTE the parameter is
			// -VMHome (the Go psArgs key is "Home"): $Home is a read-only PowerShell
			// automatic variable and cannot be a function parameter name.
			name:      "SetVMHome",
			psCommand: psSetVMHome,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "Home": "C:\\VMs\\web-01"},
			wantVerb:  "SetVMHome",
			wantJSON:  `{"Name":"cfgms-t__web-01","VMHome":"C:\\VMs\\web-01"}`,
		},
		{
			name:      "VMStorageMovePreflight",
			psCommand: psVMStorageMovePreflight,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "DestDir": "C:\\ClusterStorage\\CSV01\\web-01"},
			wantVerb:  "VMStorageMovePreflight",
			wantJSON:  `{"Name":"cfgms-t__web-01","DestDir":"C:\\ClusterStorage\\CSV01\\web-01"}`,
		},
		{
			name:      "MoveVMStorage",
			psCommand: psMoveVMStorage,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "Home": "C:\\ClusterStorage\\CSV01\\web-01"},
			wantVerb:  "MoveVMStorage",
			wantJSON:  `{"Name":"cfgms-t__web-01","VMHome":"C:\\ClusterStorage\\CSV01\\web-01"}`,
		},
		{
			name:      "GetVMMoveError",
			psCommand: psGetVMMoveError,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01"},
			wantVerb:  "GetVMMoveError",
			wantJSON:  `{"Name":"cfgms-t__web-01"}`,
		},
		{
			name:      "ClearVMMoveError",
			psCommand: psClearVMMoveError,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01"},
			wantVerb:  "ClearVMMoveError",
			wantJSON:  `{"Name":"cfgms-t__web-01"}`,
		},
		{
			name:      "Connect-VMNic",
			psCommand: psConnectVMNic,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "SwitchName": "External"},
			wantVerb:  "ConnectVMNic",
			wantJSON:  `{"Name":"cfgms-t__web-01","SwitchName":"External"}`,
		},
		{
			name:      "Disconnect-VMNic",
			psCommand: psDisconnectVMNic,
			psArgs:    map[string]string{"Name": "cfgms-t__web-01", "SwitchName": "Mgmt"},
			wantVerb:  "DisconnectVMNic",
			wantJSON:  `{"Name":"cfgms-t__web-01","SwitchName":"Mgmt"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertPlanned(t, tc.psCommand, tc.psArgs, tc.wantVerb, tc.wantJSON)
		})
	}
}

// TestPSDispatch_VSwitchVerbs covers vSwitch lifecycle including all three
// SwitchType variants and the dynamic-script External case where the
// AllowManagementOS bool is recovered from the suffix.
func TestPSDispatch_VSwitchVerbs(t *testing.T) {
	cases := []struct {
		name      string
		psCommand string
		psArgs    map[string]string
		wantVerb  string
		wantJSON  string
	}{
		{
			name:      "Get-VMSwitch",
			psCommand: psGetVSwitch,
			psArgs:    map[string]string{"Name": "cfgms-t__sw01"},
			wantVerb:  "GetVSwitch",
			wantJSON:  `{"Name":"cfgms-t__sw01"}`,
		},
		{
			name:      "Remove-VMSwitch",
			psCommand: psRemoveVSwitch,
			psArgs:    map[string]string{"Name": "cfgms-t__sw01"},
			wantVerb:  "RemoveVSwitch",
			wantJSON:  `{"Name":"cfgms-t__sw01"}`,
		},
		{
			name:      "New-VMSwitch Internal",
			psCommand: psCreateVSwitchInternal,
			psArgs:    map[string]string{"Name": "cfgms-t__sw01"},
			wantVerb:  "CreateVSwitchInternal",
			wantJSON:  `{"Name":"cfgms-t__sw01"}`,
		},
		{
			name:      "New-VMSwitch Private",
			psCommand: psCreateVSwitchPrivate,
			psArgs:    map[string]string{"Name": "cfgms-t__sw01"},
			wantVerb:  "CreateVSwitchPrivate",
			wantJSON:  `{"Name":"cfgms-t__sw01"}`,
		},
		{
			name:      "New-VMSwitch External AllowManagementOS=true",
			psCommand: psCreateVSwitchExternal(true),
			psArgs:    map[string]string{"Name": "cfgms-t__sw01", "NetAdapter": "Ethernet0"},
			wantVerb:  "CreateVSwitchExternal",
			wantJSON:  `{"Name":"cfgms-t__sw01","NetAdapter":"Ethernet0","AllowManagementOS":true}`,
		},
		{
			name:      "New-VMSwitch External AllowManagementOS=false",
			psCommand: psCreateVSwitchExternal(false),
			psArgs:    map[string]string{"Name": "cfgms-t__sw01", "NetAdapter": "Ethernet0"},
			wantVerb:  "CreateVSwitchExternal",
			wantJSON:  `{"Name":"cfgms-t__sw01","NetAdapter":"Ethernet0","AllowManagementOS":false}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertPlanned(t, tc.psCommand, tc.psArgs, tc.wantVerb, tc.wantJSON)
		})
	}
}

// TestPSDispatch_ClusterVerbs covers all FIVE failover-cluster psXxx constants
// (three read-only + two write) and asserts the EXACT synthesised Cfgms-*
// invocation string for each, mirroring TestPSDispatch_VMVerbs /
// TestPSDispatch_VSwitchVerbs. The wrapper parameter names asserted here
// (-ClusterName / -VMName / -Name) must match the param(...) declarations of the
// corresponding Cfgms-* functions in pstransport_preamble_windows.go: notably
// Cfgms-AddClusterVMRole takes -ClusterName/-VMName and internally maps to
// Add-ClusterVirtualMachineRole -Cluster $ClusterName -VirtualMachine $VMName,
// so the wrapper param is -ClusterName (NOT the real cmdlet's -Cluster).
func TestPSDispatch_ClusterVerbs(t *testing.T) {
	cases := []struct {
		name      string
		psCommand string
		psArgs    map[string]string
		wantVerb  string
		wantJSON  string
	}{
		{
			name:      "Get-Cluster",
			psCommand: psGetCluster,
			psArgs:    map[string]string{"ClusterName": "lab-hv"},
			wantVerb:  "GetCluster",
			wantJSON:  `{"ClusterName":"lab-hv"}`,
		},
		{
			name:      "Get-ClusterOwnerNode",
			psCommand: psGetClusterOwnerNode,
			psArgs:    map[string]string{"ClusterName": "lab-hv"},
			wantVerb:  "GetClusterOwnerNode",
			wantJSON:  `{"ClusterName":"lab-hv"}`,
		},
		{
			name:      "Get-ClusterResourceOwner",
			psCommand: psGetClusterResourceOwner,
			psArgs:    map[string]string{"ClusterName": "lab-hv"},
			wantVerb:  "GetClusterResourceOwner",
			wantJSON:  `{"ClusterName":"lab-hv"}`,
		},
		{
			name:      "Add-ClusterVMRole",
			psCommand: psAddClusterVMRole,
			psArgs:    map[string]string{"ClusterName": "lab-hv", "VMName": "web-01"},
			wantVerb:  "AddClusterVMRole",
			wantJSON:  `{"ClusterName":"lab-hv","VMName":"web-01"}`,
		},
		{
			name:      "Remove-ClusterResource",
			psCommand: psRemoveClusterResource,
			psArgs:    map[string]string{"Name": "web-01"},
			wantVerb:  "RemoveClusterResource",
			wantJSON:  `{"Name":"web-01"}`,
		},
		{
			name:      "SetClusterRolePreferredOwners",
			psCommand: psSetClusterRolePreferredOwners,
			psArgs:    map[string]string{"ClusterName": "lab-hv", "GroupName": "web-01", "Owners": "NODE1,NODE2"},
			wantVerb:  "SetClusterRolePreferredOwners",
			wantJSON:  `{"ClusterName":"lab-hv","GroupName":"web-01","Owners":"NODE1,NODE2"}`,
		},
		{
			name:      "SetClusterRolePossibleOwners",
			psCommand: psSetClusterRolePossibleOwners,
			psArgs:    map[string]string{"ClusterName": "lab-hv", "ResourceName": "web-01", "Owners": "NODE1"},
			wantVerb:  "SetClusterRolePossibleOwners",
			wantJSON:  `{"ClusterName":"lab-hv","ResourceName":"web-01","Owners":"NODE1"}`,
		},
		{
			name:      "SetClusterGroupPriority",
			psCommand: psSetClusterGroupPriority,
			psArgs:    map[string]string{"ClusterName": "lab-hv", "GroupName": "web-01", "Priority": "2000"},
			wantVerb:  "SetClusterGroupPriority",
			wantJSON:  `{"ClusterName":"lab-hv","GroupName":"web-01","Priority":"2000"}`,
		},
		{
			name:      "SetClusterGroupAutoStart",
			psCommand: psSetClusterGroupAutoStart,
			psArgs:    map[string]string{"ClusterName": "lab-hv", "GroupName": "web-01", "AutoStart": "1"},
			wantVerb:  "SetClusterGroupAutoStart",
			wantJSON:  `{"ClusterName":"lab-hv","GroupName":"web-01","AutoStart":"1"}`,
		},
		{
			name:      "SetClusterGroupAntiAffinity",
			psCommand: psSetClusterGroupAntiAffinity,
			psArgs:    map[string]string{"ClusterName": "lab-hv", "GroupName": "web-01", "ClassName": "db-tier"},
			wantVerb:  "SetClusterGroupAntiAffinity",
			wantJSON:  `{"ClusterName":"lab-hv","GroupName":"web-01","ClassName":"db-tier"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertPlanned(t, tc.psCommand, tc.psArgs, tc.wantVerb, tc.wantJSON)
		})
	}
}

// assertPlanned plans psCommand with the production planPSCall and checks the
// verb and the exact args JSON (keys in table order, typed values).
func assertPlanned(t *testing.T, psCommand string, psArgs map[string]string, wantVerb, wantJSON string) {
	t.Helper()
	call, err := planPSCall(psCommand, psArgs)
	require.NoError(t, err)
	assert.Equal(t, wantVerb, call.Verb)
	got, err := call.argsJSON()
	require.NoError(t, err)
	assert.Equal(t, wantJSON, string(got))
}

// knownPSCommands names every psXxx value the package passes to ExecutePS.
// TestDispatch_EveryExecutePSCommandHasARow checks this list against the
// source, so a new caller cannot be added without a table row.
var knownPSCommands = map[string]string{
	"psEnumerateVMs":                  psEnumerateVMs,
	"psEnumerateVSwitches":            psEnumerateVSwitches,
	"psGetClusterSelf":                psGetClusterSelf,
	"psGetVM":                         psGetVM,
	"psCreateVM":                      psCreateVM,
	"psRemoveVM":                      psRemoveVM,
	"psRenameVM":                      psRenameVM,
	"psStartVM":                       psStartVM,
	"psStopVM":                        psStopVM,
	"psSetVMProcessor":                psSetVMProcessor,
	"psSetVMMemory":                   psSetVMMemory,
	"psGetVMSnapshots":                psGetVMSnapshots,
	"psRemoveVMSnapshot":              psRemoveVMSnapshot,
	"psNewSeedVHD":                    psNewSeedVHD,
	"psMountSeedVHD":                  psMountSeedVHD,
	"psCopyToSeedVHD":                 psCopyToSeedVHD,
	"psDetachSeedVHD":                 psDetachSeedVHD,
	"psDeleteSeedMedia":               psDeleteSeedMedia,
	"psAttachSeedDisk":                psAttachSeedDisk,
	"psAttachDVD":                     psAttachDVD,
	"psSetVMFirmware":                 psSetVMFirmware,
	"psDisableVMFirmwareSecureBoot":   psDisableVMFirmwareSecureBoot,
	"psSetDVDFirstBoot":               psSetDVDFirstBoot,
	"psBuildAnswerIso":                psBuildAnswerIso,
	"psBootKeypress":                  psBootKeypress,
	"psPrepCloudBootDisk":             psPrepCloudBootDisk,
	"psCreateVMFromDisk":              psCreateVMFromDisk,
	"psSetHddFirstBoot":               psSetHddFirstBoot,
	"psSetVMHome":                     psSetVMHome,
	"psVMStorageMovePreflight":        psVMStorageMovePreflight,
	"psMoveVMStorage":                 psMoveVMStorage,
	"psGetVMMoveError":                psGetVMMoveError,
	"psClearVMMoveError":              psClearVMMoveError,
	"psConnectVMNic":                  psConnectVMNic,
	"psDisconnectVMNic":               psDisconnectVMNic,
	"psGetVSwitch":                    psGetVSwitch,
	"psRemoveVSwitch":                 psRemoveVSwitch,
	"psCreateVSwitchInternal":         psCreateVSwitchInternal,
	"psCreateVSwitchPrivate":          psCreateVSwitchPrivate,
	"psCreateVSwitchExternal(true)":   psCreateVSwitchExternal(true),
	"psCreateVSwitchExternal(false)":  psCreateVSwitchExternal(false),
	"psGetCluster":                    psGetCluster,
	"psGetClusterOwnerNode":           psGetClusterOwnerNode,
	"psGetClusterResourceOwner":       psGetClusterResourceOwner,
	"psGetClusterAccessSelf":          psGetClusterAccessSelf,
	"psAddClusterVMRole":              psAddClusterVMRole,
	"psRemoveClusterResource":         psRemoveClusterResource,
	"psSetClusterRolePreferredOwners": psSetClusterRolePreferredOwners,
	"psSetClusterRolePossibleOwners":  psSetClusterRolePossibleOwners,
	"psSetClusterGroupPriority":       psSetClusterGroupPriority,
	"psSetClusterGroupAutoStart":      psSetClusterGroupAutoStart,
	"psSetClusterGroupAntiAffinity":   psSetClusterGroupAntiAffinity,
	"psListClusterAccessNodes":        psListClusterAccessNodes,
	"psGrantClusterAccess":            psGrantClusterAccess,
	"psRevokeClusterAccess":           psRevokeClusterAccess,
}

// TestDispatch_EveryExecutePSCommandHasARow is the [REQUIRED TEST] coverage
// check. It scans the package source for every psXxx passed to ExecutePS
// (directly, or through vswitch.go's psCmd variable) and requires each one
// to be in knownPSCommands, and every knownPSCommands value to plan through
// the production planPSCall without error.
func TestDispatch_EveryExecutePSCommandHasARow(t *testing.T) {
	direct := regexp.MustCompile(`ExecutePS\(\s*ctx,\s*(ps[A-Z]\w*)`)
	viaVar := regexp.MustCompile(`psCmd = (ps[A-Z]\w*)`)
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		for _, re := range []*regexp.Regexp{direct, viaVar} {
			for _, m := range re.FindAllStringSubmatch(string(src), -1) {
				seen[m[1]] = true
			}
		}
	}
	require.NotEmpty(t, seen, "the source scan found no ExecutePS call sites")
	for name := range seen {
		switch name {
		case "psCmd", "psCommand":
			// Variables, not constants: vswitch.go's psCmd is resolved by
			// viaVar; psCommand is the transports' own parameter.
			continue
		}
		if name == "psCreateVSwitchExternal" {
			assert.Contains(t, knownPSCommands, "psCreateVSwitchExternal(true)")
			continue
		}
		assert.Contains(t, knownPSCommands, name, "%s is passed to ExecutePS but has no entry in knownPSCommands", name)
	}
	for name, cmd := range knownPSCommands {
		_, err := planPSCall(cmd, map[string]string{})
		assert.NoError(t, err, "%s has no dispatch table row", name)
	}
}

// TestDispatch_RunModes pins which verbs leave the persistent host. The
// fresh-process verbs deadlock in the `-Command -` host (async Virtual Disk
// Service, storage cmdlets); the storage move must not wait.
func TestDispatch_RunModes(t *testing.T) {
	fresh := map[string]bool{
		"NewSeedVHD": true, "MountSeedVHD": true, "CopyToSeedVHD": true, "DetachSeedVHD": true,
		"AttachSeedDisk": true, "AttachDVD": true, "SetDVDFirstBoot": true, "BuildAnswerIso": true,
		"BootKeypress": true, "PrepCloudBootDisk": true, "SetHddFirstBoot": true, "SetVMHome": true,
		"VMStorageMovePreflight": true,
	}
	for cmd, spec := range psDispatchTable {
		want := psModeHost
		switch {
		case spec.Verb == "MoveVMStorage":
			want = psModeDetached
		case fresh[spec.Verb]:
			want = psModeFresh
		}
		assert.Equal(t, want, spec.Mode, "run mode of Cfgms-%s (%.40q)", spec.Verb, cmd)
	}
	assert.Equal(t, psModeHost, psCreateVSwitchExternalSpec.Mode)
}

// hostileValue is a value that would break out of, or execute inside, any
// PowerShell string literal or expression it was composed into.
func hostileValue(i int) string {
	return fmt.Sprintf("v%d' \u2018\u2019\u201a\u201b; $(New-Item x) `n \"\r\nWrite-Output pwned #", i)
}

// TestDispatch_NoValueReachesScriptText is the [REQUIRED TEST] that no config
// value appears in dispatched script text. For every table row it fills every
// string parameter with a hostile value, plans the call, writes the real args
// file, and builds the real expression and fresh-process script body. The
// expression must be exactly the fixed form, neither text may hold any value,
// and the args JSON must carry every value unchanged and typed.
func TestDispatch_NoValueReachesScriptText(t *testing.T) {
	useTestStagingBase(t) // writeArgsFile stages in the secured base (#5635)
	type row struct {
		cmd  string
		spec psVerbSpec
	}
	rows := []row{{psCreateVSwitchExternal(true), psCreateVSwitchExternalSpec}}
	for cmd, spec := range psDispatchTable {
		rows = append(rows, row{cmd, spec})
	}
	for _, r := range rows {
		t.Run(r.spec.Verb, func(t *testing.T) {
			psArgs := map[string]string{}
			var values []string
			for i, p := range r.spec.Params {
				switch p.Kind {
				case psInt:
					psArgs[p.Key] = "4096"
				case psBool:
					// AllowManagementOS comes from the psCommand suffix.
				default:
					v := hostileValue(i)
					psArgs[p.Key] = v
					values = append(values, v)
				}
			}

			call, err := planPSCall(r.cmd, psArgs)
			require.NoError(t, err)
			argsPath, remove, err := writeArgsFile(call)
			require.NoError(t, err)
			t.Cleanup(remove)

			expr, err := invokeExpression(call.Verb, argsPath)
			require.NoError(t, err)
			assert.Equal(t, "Cfgms-Invoke -Verb '"+r.spec.Verb+"' -ArgsFile '"+argsPath+"'", expr)
			body := freshScriptBody(expr)
			for _, v := range values {
				assert.NotContains(t, expr, v)
				assert.NotContains(t, body, v)
			}

			raw, err := os.ReadFile(argsPath)
			require.NoError(t, err)
			assert.False(t, bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}), "args file must have no BOM")
			var decoded map[string]any
			require.NoError(t, json.Unmarshal(raw, &decoded))
			for _, p := range r.spec.Params {
				switch p.Kind {
				case psInt:
					assert.Equal(t, float64(4096), decoded[p.Param], "%s must be a JSON number", p.Param)
				case psBool:
					assert.Equal(t, true, decoded[p.Param], "%s must be a JSON boolean", p.Param)
				default:
					assert.Equal(t, psArgs[p.Key], decoded[p.Param], "%s must arrive unchanged", p.Param)
				}
			}
		})
	}
}

// TestPlanPSCall_TypedValues covers the int, optional and bool rules.
func TestPlanPSCall_TypedValues(t *testing.T) {
	// 64-bit ints: ResizeBytes exceeds int32.
	assertPlanned(t, psPrepCloudBootDisk,
		map[string]string{"ImagePath": `C:\i.raw`, "VhdPath": `C:\v.vhdx`, "ResizeBytes": " 21474836480 "},
		"PrepCloudBootDisk", `{"ImagePath":"C:\\i.raw","VhdPath":"C:\\v.vhdx","ResizeBytes":21474836480}`)
	// An empty int keeps today's 0; an empty optional string is omitted; an
	// empty required string is sent empty.
	assertPlanned(t, psCreateVM, map[string]string{"Name": "web-01"},
		"CreateVM", `{"Name":"web-01","MemoryMB":0,"CPU":0,"VHDPath":"","SwitchName":"","Generation":0}`)
	// Priority and AutoStart stay strings.
	assertPlanned(t, psSetClusterGroupPriority,
		map[string]string{"ClusterName": "c", "GroupName": "g", "Priority": "2000"},
		"SetClusterGroupPriority", `{"ClusterName":"c","GroupName":"g","Priority":"2000"}`)
	// The caller's map is not modified by the external-switch bool recovery.
	in := map[string]string{"Name": "sw", "NetAdapter": "Ethernet0"}
	assertPlanned(t, psCreateVSwitchExternal(false), in,
		"CreateVSwitchExternal", `{"Name":"sw","NetAdapter":"Ethernet0","AllowManagementOS":false}`)
	assert.Len(t, in, 2)
}

// TestDispatch_FailsClosed is the fail-closed criterion: a non-numeric int,
// an unknown psCommand, and an args path holding a quote or control
// character each return an error and run no PowerShell. The transport here
// is a zero value with no PowerShell process, so reaching run() would panic
// on its nil stdin.
func TestDispatch_FailsClosed(t *testing.T) {
	ctx := context.Background()
	tr := &psHostTransport{}

	t.Run("non-numeric int", func(t *testing.T) {
		bad := "$(New-Item -ItemType File -Path marker)"
		_, err := tr.ExecutePS(ctx, psSetVMMemory, map[string]string{"Name": "web-01", "MemoryMB": bad})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not an integer")
		assert.NotContains(t, err.Error(), bad, "the error must not echo the value")
	})

	t.Run("unknown psCommand", func(t *testing.T) {
		_, err := tr.ExecutePS(ctx, "Get-Process | Stop-Process", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown psCommand")
	})

	for name, dir := range map[string]string{
		"ascii quote in args path":   "o'q",
		"unicode quote in args path": "o\u2019q",
	} {
		t.Run(name, func(t *testing.T) {
			// The args file is staged in the secured base (#5635), so the
			// quote goes in the base's own name.
			tmp := stagingBaseAt(t, filepath.Join(t.TempDir(), dir), "O:BA")
			for _, cmd := range []string{psGetVM, psMountSeedVHD, psMoveVMStorage} {
				_, err := tr.ExecutePS(ctx, cmd, map[string]string{"Name": "web-01", "Path": `C:\s.vhdx`})
				require.Error(t, err)
				assert.Contains(t, err.Error(), "refusing args path")
			}
			left, err := os.ReadDir(tmp)
			require.NoError(t, err)
			assert.Empty(t, left, "a refused call must remove its args file")
		})
	}

	t.Run("control character or bad verb", func(t *testing.T) {
		_, err := invokeExpression("GetVM", "C:\\t\\a\nb.json")
		require.Error(t, err)
		for _, verb := range []string{"", "Get VM", "GetVM'", "Get-VM", "GetVM;x"} {
			_, err := invokeExpression(verb, `C:\t\a.json`)
			assert.Error(t, err, "verb %q must be refused", verb)
		}
	})
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

// TestPreamble_DeleteSeedMediaUsesLiteralPathAndSilentContinue guards the
// security and idempotency properties of the Cfgms-DeleteSeedMedia preamble
// function (ADR-010 §5 / Issue #2081). Dispatch tests assert routing only;
// this test asserts the function body itself:
//   - -LiteralPath prevents wildcard/glob expansion — a crafted path like
//     "C:\seeds\*" or "C:\seeds\[vol]*.vhdx" must not expand.
//   - -ErrorAction SilentlyContinue makes the delete idempotent — removing an
//     already-absent file is not an error.
func TestPreamble_DeleteSeedMediaUsesLiteralPathAndSilentContinue(t *testing.T) {
	body := preambleFunctionBody(t, "Cfgms-DeleteSeedMedia")

	assert.Contains(t, body, "-LiteralPath",
		"Cfgms-DeleteSeedMedia must use -LiteralPath to prevent wildcard glob expansion on the seed path")
	assert.Contains(t, body, "SilentlyContinue",
		"Cfgms-DeleteSeedMedia must use -ErrorAction SilentlyContinue for idempotency (absent file is not an error)")
	assert.Contains(t, body, "Remove-Item",
		"Cfgms-DeleteSeedMedia must call Remove-Item")
}

// TestNewSeedVHD_DeletesExistingFileBeforeCreate guards the seed-VHDX idempotency
// fix (Issue #2466). A failed/retried seed build previously wedged on a leftover
// file: New-VHD refuses to overwrite an existing path with
// "The file exists. (0x80070050)". The dispatch tests assert only the synthesised
// Cfgms-NewSeedVHD call string, never the function body, so a missing guard stayed
// green. This asserts the preamble function deletes an existing file at $Path
// (mirroring Cfgms-PrepCloudBootDisk) and that the delete is ordered BEFORE
// New-VHD, otherwise the stale file still blocks creation.
func TestNewSeedVHD_DeletesExistingFileBeforeCreate(t *testing.T) {
	body := preambleFunctionBody(t, "Cfgms-NewSeedVHD")

	assert.Contains(t, body, "Test-Path -LiteralPath $Path",
		"Cfgms-NewSeedVHD must test for an existing file via -LiteralPath (no glob expansion) before creating the VHD")
	assert.Contains(t, body, "Remove-Item -LiteralPath $Path -Force",
		"Cfgms-NewSeedVHD must delete an existing file at $Path before New-VHD, mirroring Cfgms-PrepCloudBootDisk")
	assert.Contains(t, body, "New-VHD",
		"Cfgms-NewSeedVHD must still create the seed VHD")

	testPathIdx := strings.Index(body, "Test-Path -LiteralPath $Path")
	removeIdx := strings.Index(body, "Remove-Item")
	newVHDIdx := strings.Index(body, "New-VHD")
	require.NotEqual(t, -1, testPathIdx)
	require.NotEqual(t, -1, removeIdx)
	require.NotEqual(t, -1, newVHDIdx)
	assert.Less(t, testPathIdx, removeIdx,
		"the Test-Path existence guard must precede Remove-Item (delete only when the file is present)")
	assert.Less(t, removeIdx, newVHDIdx,
		"Remove-Item must be ordered before New-VHD, otherwise the leftover file blocks creation with 0x80070050")
}

// TestPreamble_PossibleOwnersFilterUsesStringCoercion guards the regression the
// idiomatic Layer-2 cascade surfaced live on cfg-lab (Windows Server 2025, Issue
// #2577): Cfgms-SetClusterRolePossibleOwners resolved the role's Virtual Machine
// resource with `$_.OwnerGroup.Name -eq $ResourceName -and $_.ResourceType.Name
// -eq 'Virtual Machine'`. On that FailoverClusters PowerShell build,
// Get-ClusterResource returns .OwnerGroup and .ResourceType as plain STRINGS, on
// which .Name is $null — so the filter matched nothing, $res.Count was 0, and
// possible_owners was silently never applied (no error, so reconcileRoleProperties
// proceeded to the remaining properties). The dispatch tests assert only the
// synthesised call string and the reconcile unit tests drive a fake transport, so
// none exercise this filter against the real object shape and all stayed green.
// The fix compares via [string] coercion, which yields the group/type name whether
// the property is a string (itself) or an object (ToString), so it is robust
// across builds. This asserts the robust form is used and the brittle .Name form
// is gone.
func TestPreamble_PossibleOwnersFilterUsesStringCoercion(t *testing.T) {
	body := preambleFunctionBody(t, "Cfgms-SetClusterRolePossibleOwners")

	assert.Contains(t, body, "[string]$_.OwnerGroup -eq $ResourceName",
		"possible_owners resource lookup must match the owner group via [string] coercion (Get-ClusterResource returns .OwnerGroup as a string on some FailoverClusters builds, where .OwnerGroup.Name is $null)")
	assert.Contains(t, body, "[string]$_.ResourceType -eq 'Virtual Machine'",
		"possible_owners resource lookup must match the resource type via [string] coercion (.ResourceType is a string on some builds, where .ResourceType.Name is $null)")
	assert.NotContains(t, body, "$_.OwnerGroup.Name",
		"the brittle .OwnerGroup.Name filter silently matches nothing when Get-ClusterResource returns a string — it must not return")
	assert.NotContains(t, body, "$_.ResourceType.Name",
		"the brittle .ResourceType.Name filter silently matches nothing when Get-ClusterResource returns a string — it must not return")
	assert.Contains(t, body, "Set-ClusterOwnerNode -Cluster $ClusterName -Resource",
		"the function must still restrict possible owners on the resolved VM resource")
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

// ── #3168 seed-mount leak guards ───────────────────────────────────────────
//
// These assert the PREAMBLE FUNCTION BODIES, for the same reason
// TestPreamble_RemoveVMStopsRunningVMFirst does: the dispatch tests only check
// the synthesised call string and stay green while the function body regresses.
// The live bug was exactly that class — a mount/dismount pair that looked
// correct at the call site and leaked on every error path.

// TestPreamble_SeedMountsDismountInFinally is the [REQUIRED TEST] for the mount
// leak. Both functions that Mount-VHD must dismount in a `finally`, or any error
// between mount and dismount leaks a host-attached VHD PERMANENTLY — which then
// fails the NEXT VM's Add-VMHardDiskDrive with a 0x80070020 sharing violation.
// One transient error silently breaks seed provisioning for every later VM on
// the host. Observed live: a seed left Attached=True for two days after its VM
// had been deleted.
func TestPreamble_SeedMountsDismountInFinally(t *testing.T) {
	for _, fn := range []string{"Cfgms-MountSeedVHD", "Cfgms-CopyToSeedVHD"} {
		t.Run(fn, func(t *testing.T) {
			body := preambleFunctionBody(t, fn)

			require.Contains(t, body, "Mount-VHD",
				"%s is expected to mount the seed VHD", fn)
			// Match the TOKEN, not the bare word: "finally" also appears in the
			// explanatory comments above the code.
			require.Contains(t, body, "} finally {",
				"%s must dismount in a finally block — without it any error between "+
					"Mount-VHD and the dismount leaks a host-attached VHD permanently", fn)

			mountIdx := strings.Index(body, "Mount-VHD -Path")
			finallyIdx := strings.Index(body, "} finally {")
			tryIdx := strings.Index(body, "try {")
			assert.Less(t, tryIdx, mountIdx,
				"%s must open its try BEFORE Mount-VHD, or a mount failure escapes the cleanup", fn)
			assert.Less(t, mountIdx, finallyIdx,
				"%s must mount inside the try, before the finally", fn)
			assert.Contains(t, body[finallyIdx:], "Cfgms-DismountAndVerify",
				"%s must call Cfgms-DismountAndVerify from its finally", fn)
		})
	}
}

// TestPreamble_SeedMountCleanupDoesNotMaskOriginalError guards the subtler half.
// A finally that throws REPLACES the in-flight exception, so a naive
// `finally { Cfgms-DismountAndVerify }` would discard the real cause of a seed
// failure and report a dismount error instead — the same diagnostic blindness
// that made this bug expensive to find. But cleanup must NOT be silently
// swallowed either: on the success path a failed dismount IS the leak.
//
// The contract: guard on a success flag, let the dismount throw when the body
// succeeded, and catch-and-warn only when an exception is already in flight.
func TestPreamble_SeedMountCleanupDoesNotMaskOriginalError(t *testing.T) {
	for _, fn := range []string{"Cfgms-MountSeedVHD", "Cfgms-CopyToSeedVHD"} {
		t.Run(fn, func(t *testing.T) {
			body := preambleFunctionBody(t, fn)
			finallyIdx := strings.Index(body, "} finally {")
			require.NotEqual(t, -1, finallyIdx, "%s must have a finally block", fn)
			cleanup := body[finallyIdx:]

			assert.Contains(t, body, "$ok = $false",
				"%s must initialise a success flag before the try", fn)
			assert.Contains(t, body, "$ok = $true",
				"%s must set the success flag as the LAST statement inside the try", fn)
			assert.Contains(t, cleanup, "if ($ok)",
				"%s cleanup must branch on the success flag", fn)
			assert.Contains(t, cleanup, "catch",
				"%s must catch a dismount failure on the FAILURE path so it cannot "+
					"replace the in-flight exception and hide the real cause", fn)

			// On the success path the dismount must be un-caught, so a leak throws.
			okBranch := cleanup[strings.Index(cleanup, "if ($ok)"):]
			elseIdx := strings.Index(okBranch, "} else {")
			require.NotEqual(t, -1, elseIdx, "%s cleanup must have an else branch", fn)
			assert.NotContains(t, okBranch[:elseIdx], "catch",
				"%s must NOT swallow a dismount failure on the success path — that "+
					"failure is the leak this function exists to prevent", fn)
		})
	}
}

// TestPreamble_CopyToSeedVHDFailsLoudlyOnMissingVolume: without an explicit
// check, a missing labelled volume yields a null $letter and the writes fail
// obscurely on a path like ":\user-data" — a confusing error for what is really
// "the format step did not produce the volume we expected".
func TestPreamble_CopyToSeedVHDFailsLoudlyOnMissingVolume(t *testing.T) {
	body := preambleFunctionBody(t, "Cfgms-CopyToSeedVHD")
	assert.Contains(t, body, "if (-not $letter)",
		"Cfgms-CopyToSeedVHD must check the drive letter was resolved")
	assert.Contains(t, body, "throw",
		"a missing labelled seed volume must throw a named error, not fail obscurely on a null path")
}
