// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// psRunMode is how a Cfgms-* verb runs on the local host.
type psRunMode int

const (
	// psModeHost runs the verb in the persistent `-Command -` host (run).
	psModeHost psRunMode = iota
	// psModeFresh runs the verb in a fresh `powershell -File` process
	// (runFresh). Required for the async Virtual Disk Service and storage
	// cmdlets, which deadlock in the persistent host.
	psModeFresh
	// psModeDetached starts the verb in a fresh process and returns without
	// waiting (runDetached). Used for the live storage migration.
	psModeDetached
)

// psParamKind is the JSON type a parameter value is sent as.
type psParamKind int

const (
	// psString is a required string: always sent, empty when the key is absent.
	psString psParamKind = iota
	// psOptString is an optional string: omitted when empty, so the PS
	// function's own default applies.
	psOptString
	// psInt is a 64-bit integer parsed from the trimmed value; empty is 0.
	psInt
	// psBool is a boolean parsed with strconv.ParseBool.
	psBool
)

// psParamSpec maps one psArgs key to one named parameter of a Cfgms-* verb.
// Param and Key differ where the PS parameter name is not the psArgs key
// (-VMHome reads psArgs["Home"]).
type psParamSpec struct {
	Param string
	Key   string
	Kind  psParamKind
}

// psVerbSpec is one row of the dispatch table.
type psVerbSpec struct {
	Verb   string // Cfgms-<Verb>
	Mode   psRunMode
	Params []psParamSpec
}

// psArg is one typed parameter value, in the order the table declares it.
type psArg struct {
	Param string
	Value any // string, int64 or bool
}

// psCall is a planned invocation: the verb, how to run it, and its typed
// parameter values. Values travel to PowerShell only as JSON in the args
// file; the script text names the verb and the file and nothing else.
type psCall struct {
	Verb string
	Mode psRunMode
	Args []psArg
	// psArgs is the caller's map, kept for the seed-cleanup path selection.
	psArgs map[string]string
}

func psStr(param string) psParamSpec          { return psParamSpec{param, param, psString} }
func psOptStr(param string) psParamSpec       { return psParamSpec{param, param, psOptString} }
func psIntParam(param string) psParamSpec     { return psParamSpec{param, param, psInt} }
func psRenamed(param, key string) psParamSpec { return psParamSpec{param, key, psString} }

// psDispatchTable maps every psXxx constant passed to ExecutePS to its
// Cfgms-* verb. A psCommand missing from the table is an error, never a
// fallback: a new verb needs a preamble function and a row here.
var psDispatchTable = map[string]psVerbSpec{
	// ── Domain observe (no parameters) ──────────────────────────────
	psEnumerateVMs:       {"EnumerateVMs", psModeHost, nil},
	psEnumerateVSwitches: {"EnumerateVSwitches", psModeHost, nil},
	psGetClusterSelf:     {"GetClusterSelf", psModeHost, nil},

	// ── VM ──────────────────────────────────────────────────────────
	psGetVM: {"GetVM", psModeHost, []psParamSpec{psStr("Name")}},
	// -Path is optional (#2411): the VM home (dir(vhd_path)); omitted when no
	// vhd_path directory is derivable so New-VM keeps the host default.
	psCreateVM: {"CreateVM", psModeHost, []psParamSpec{
		psStr("Name"), psIntParam("MemoryMB"), psIntParam("CPU"), psStr("VHDPath"),
		psStr("SwitchName"), psIntParam("Generation"), psOptStr("Path"),
	}},
	psRemoveVM:       {"RemoveVM", psModeHost, []psParamSpec{psStr("Name")}},
	psRenameVM:       {"RenameVM", psModeHost, []psParamSpec{psStr("OldName"), psStr("NewName")}},
	psStartVM:        {"StartVM", psModeHost, []psParamSpec{psStr("Name")}},
	psStopVM:         {"StopVM", psModeHost, []psParamSpec{psStr("Name")}},
	psSetVMProcessor: {"SetVMProcessor", psModeHost, []psParamSpec{psStr("Name"), psIntParam("CPU")}},
	psSetVMMemory:    {"SetVMMemory", psModeHost, []psParamSpec{psStr("Name"), psIntParam("MemoryMB")}},

	// ── Declarative checkpoint policy (#2627) ────────────────────────
	psGetVMSnapshots:   {"GetVMSnapshots", psModeHost, []psParamSpec{psStr("Name")}},
	psRemoveVMSnapshot: {"RemoveVMSnapshot", psModeHost, []psParamSpec{psStr("Name"), psStr("SnapshotName")}},

	// ── VM provisioning: seed VHDX disk ops (#2044) ──────────────────
	// The fresh-process rows use runFresh, NOT the persistent `-Command -`
	// host: Mount-VHD/Dismount-VHD deadlock there (async Virtual Disk
	// Service). Add-VMHardDiskDrive, Add-VMDvdDrive and Set-VMFirmware
	// -FirstBootDevice open the disk or ISO and deadlock the same way.
	psNewSeedVHD: {"NewSeedVHD", psModeFresh, []psParamSpec{psStr("Path"), psIntParam("SizeBytes")}},
	// -Label is optional: omitted for the legacy CFGMS_SEED path (PS default),
	// passed as CIDATA for the cloud-init NoCloud seed.
	psMountSeedVHD: {"MountSeedVHD", psModeFresh, []psParamSpec{psStr("Path"), psOptStr("Label")}},
	// The optional parameters are absent for the legacy single-file CFGMS_SEED
	// path (PS defaults), present for the cloud-init CIDATA seed.
	psCopyToSeedVHD: {"CopyToSeedVHD", psModeFresh, []psParamSpec{
		psStr("SeedPath"), psStr("FileName"), psStr("Content"),
		psOptStr("Label"), psOptStr("FileName2"), psOptStr("Content2"), psOptStr("StewardDest"),
		psOptStr("LauncherSrc"), psOptStr("LauncherDest"),
		psStr("StewardSrc"), psStr("CASrc"),
	}},
	psDetachSeedVHD:               {"DetachSeedVHD", psModeFresh, []psParamSpec{psStr("Path")}},
	psDeleteSeedMedia:             {"DeleteSeedMedia", psModeHost, []psParamSpec{psStr("Path")}},
	psAttachSeedDisk:              {"AttachSeedDisk", psModeFresh, []psParamSpec{psStr("Name"), psStr("SeedPath")}},
	psAttachDVD:                   {"AttachDVD", psModeFresh, []psParamSpec{psStr("Name"), psStr("ISOPath")}},
	psSetVMFirmware:               {"SetVMFirmware", psModeHost, []psParamSpec{psStr("Name"), psStr("Template")}},
	psDisableVMFirmwareSecureBoot: {"DisableVMFirmwareSecureBoot", psModeHost, []psParamSpec{psStr("Name")}},
	psSetDVDFirstBoot:             {"SetDVDFirstBoot", psModeFresh, []psParamSpec{psStr("Name"), psStr("ISOPath")}},
	// Fresh process: IMAPI2 COM + file I/O; heavy, must not run in the persistent host.
	psBuildAnswerIso: {"BuildAnswerIso", psModeFresh, []psParamSpec{
		psStr("IsoPath"), psStr("FileName"), psStr("Content"), psStr("StewardSrc"), psStr("CASrc"),
	}},
	// Fresh process: blocks ~40s driving the VM keyboard.
	psBootKeypress: {"BootKeypress", psModeFresh, []psParamSpec{psStr("Name")}},

	// ── cloud-init (Linux VM-from-cloud-image) ───────────────────────
	// Fresh process: Convert-VHD is heavy file I/O.
	psPrepCloudBootDisk: {"PrepCloudBootDisk", psModeFresh, []psParamSpec{
		psStr("ImagePath"), psStr("VhdPath"), psIntParam("ResizeBytes"),
	}},
	// Persistent host (like Cfgms-CreateVM): New-VM does not mount the disk.
	psCreateVMFromDisk: {"CreateVMFromDisk", psModeHost, []psParamSpec{
		psStr("Name"), psIntParam("MemoryMB"), psIntParam("CPU"), psStr("VHDPath"),
		psStr("SwitchName"), psIntParam("Generation"), psOptStr("Path"),
	}},
	psSetHddFirstBoot: {"SetHddFirstBoot", psModeFresh, []psParamSpec{psStr("Name"), psStr("VHDPath")}},

	// ── VM storage location (#2411) ──────────────────────────────────
	// Fresh process: Move-VMStorage and Get-Volume deadlock in the persistent host.
	psSetVMHome:              {"SetVMHome", psModeFresh, []psParamSpec{psStr("Name"), psRenamed("VMHome", "Home")}},
	psVMStorageMovePreflight: {"VMStorageMovePreflight", psModeFresh, []psParamSpec{psStr("Name"), psStr("DestDir")}},
	// Detached: the live migration can run for minutes to hours; the module
	// call must return as soon as the migration process starts (executor
	// per-call deadline, ADR-012 §7). The MoveRecord is the source of truth
	// for "started"; failure surfaces via the marker Cfgms-GetVMMoveError probes.
	psMoveVMStorage:    {"MoveVMStorage", psModeDetached, []psParamSpec{psStr("Name"), psRenamed("VMHome", "Home")}},
	psGetVMMoveError:   {"GetVMMoveError", psModeHost, []psParamSpec{psStr("Name")}},
	psClearVMMoveError: {"ClearVMMoveError", psModeHost, []psParamSpec{psStr("Name")}},

	// ── VM network reconcile (declarative multi-NIC, #2021) ──────────
	psConnectVMNic:    {"ConnectVMNic", psModeHost, []psParamSpec{psStr("Name"), psStr("SwitchName")}},
	psDisconnectVMNic: {"DisconnectVMNic", psModeHost, []psParamSpec{psStr("Name"), psStr("SwitchName")}},

	// ── VSwitch ─────────────────────────────────────────────────────
	psGetVSwitch:            {"GetVSwitch", psModeHost, []psParamSpec{psStr("Name")}},
	psRemoveVSwitch:         {"RemoveVSwitch", psModeHost, []psParamSpec{psStr("Name")}},
	psCreateVSwitchInternal: {"CreateVSwitchInternal", psModeHost, []psParamSpec{psStr("Name")}},
	psCreateVSwitchPrivate:  {"CreateVSwitchPrivate", psModeHost, []psParamSpec{psStr("Name")}},

	// ── Failover cluster (read-only, #2199 S1) ──────────────────────
	psGetCluster:              {"GetCluster", psModeHost, []psParamSpec{psStr("ClusterName")}},
	psGetClusterOwnerNode:     {"GetClusterOwnerNode", psModeHost, []psParamSpec{psStr("ClusterName")}},
	psGetClusterResourceOwner: {"GetClusterResourceOwner", psModeHost, []psParamSpec{psStr("ClusterName")}},
	psGetClusterAccessSelf:    {"GetClusterAccessSelf", psModeHost, []psParamSpec{psStr("ClusterName")}},

	// ── Failover cluster (write, #2202 S2) ──────────────────────────
	psAddClusterVMRole:      {"AddClusterVMRole", psModeHost, []psParamSpec{psStr("ClusterName"), psStr("VMName")}},
	psRemoveClusterResource: {"RemoveClusterResource", psModeHost, []psParamSpec{psStr("Name")}},

	// ── Failover cluster-role properties (write, #2306 PROPERTIES-B) ─
	// Priority and AutoStart are sent as strings, as before; the PS function
	// binds them to [int].
	psSetClusterRolePreferredOwners: {"SetClusterRolePreferredOwners", psModeHost, []psParamSpec{
		psStr("ClusterName"), psStr("GroupName"), psStr("Owners"),
	}},
	psSetClusterRolePossibleOwners: {"SetClusterRolePossibleOwners", psModeHost, []psParamSpec{
		psStr("ClusterName"), psStr("ResourceName"), psStr("Owners"),
	}},
	psSetClusterGroupPriority: {"SetClusterGroupPriority", psModeHost, []psParamSpec{
		psStr("ClusterName"), psStr("GroupName"), psStr("Priority"),
	}},
	psSetClusterGroupAutoStart: {"SetClusterGroupAutoStart", psModeHost, []psParamSpec{
		psStr("ClusterName"), psStr("GroupName"), psStr("AutoStart"),
	}},
	psSetClusterGroupAntiAffinity: {"SetClusterGroupAntiAffinity", psModeHost, []psParamSpec{
		psStr("ClusterName"), psStr("GroupName"), psStr("ClassName"),
	}},

	// ── Cluster-access lifecycle (write, #2306 option 3, privileged) ─
	psListClusterAccessNodes: {"ListClusterAccessNodes", psModeHost, []psParamSpec{psStr("ClusterName")}},
	psGrantClusterAccess:     {"GrantClusterAccess", psModeHost, []psParamSpec{psStr("ClusterName"), psStr("NodeName")}},
	psRevokeClusterAccess:    {"RevokeClusterAccess", psModeHost, []psParamSpec{psStr("ClusterName"), psStr("NodeName")}},
}

// psCreateVSwitchExternalSpec is the row for the one psCommand built by a
// function rather than declared as a const: psCreateVSwitchExternal embeds the
// AllowManagementOS bool in its text, so planPSCall matches it by content and
// recovers the bool from the suffix.
var psCreateVSwitchExternalSpec = psVerbSpec{"CreateVSwitchExternal", psModeHost, []psParamSpec{
	psStr("Name"), psStr("NetAdapter"), {"AllowManagementOS", "AllowManagementOS", psBool},
}}

// psCreateVSwitchExternalAllowKey carries the recovered bool into the row's
// psBool parameter. It is set on a copy of psArgs, never on the caller's map.
const psCreateVSwitchExternalAllowKey = "AllowManagementOS"

// planPSCall resolves psCommand to its table row and converts psArgs to typed
// values. It is pure: it runs nothing and touches no file. An unknown
// psCommand or a value that does not parse as its declared type is an error,
// and the error never echoes the value.
func planPSCall(psCommand string, psArgs map[string]string) (psCall, error) {
	spec, ok := psDispatchTable[psCommand]
	if !ok && strings.Contains(psCommand, "-SwitchType External -NetAdapterName") {
		spec, ok = psCreateVSwitchExternalSpec, true
		withAllow := make(map[string]string, len(psArgs)+1)
		for k, v := range psArgs {
			withAllow[k] = v
		}
		withAllow[psCreateVSwitchExternalAllowKey] = strconv.FormatBool(
			strings.HasSuffix(strings.TrimSpace(psCommand), "$true | Out-Null"))
		psArgs = withAllow
	}
	if !ok {
		return psCall{}, fmt.Errorf("hyperv-ps-host: unknown psCommand (not in dispatch table); add a Cfgms-* function and a table row")
	}

	call := psCall{Verb: spec.Verb, Mode: spec.Mode, psArgs: psArgs}
	for _, p := range spec.Params {
		raw := psArgs[p.Key]
		switch p.Kind {
		case psString:
			call.Args = append(call.Args, psArg{p.Param, raw})
		case psOptString:
			if raw != "" {
				call.Args = append(call.Args, psArg{p.Param, raw})
			}
		case psInt:
			v := strings.TrimSpace(raw)
			if v == "" {
				call.Args = append(call.Args, psArg{p.Param, int64(0)})
				continue
			}
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return psCall{}, fmt.Errorf("hyperv-ps-host: parameter %s of Cfgms-%s is not an integer", p.Param, spec.Verb)
			}
			call.Args = append(call.Args, psArg{p.Param, n})
		case psBool:
			b, err := strconv.ParseBool(strings.TrimSpace(raw))
			if err != nil {
				return psCall{}, fmt.Errorf("hyperv-ps-host: parameter %s of Cfgms-%s is not a boolean", p.Param, spec.Verb)
			}
			call.Args = append(call.Args, psArg{p.Param, b})
		}
	}
	return call, nil
}

// argsJSON renders the call's values as one JSON object, keys in table order.
func (c psCall) argsJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, a := range c.Args {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, err := json.Marshal(a.Param)
		if err != nil {
			return nil, err
		}
		v, err := json.Marshal(a.Value)
		if err != nil {
			return nil, err
		}
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// writeArgsFile writes the call's values to a new JSON file (UTF-8, no BOM) in
// the secured staging base (stageFile) and returns its path and a remove
// function. The caller must run remove on every exit path; a remove of an
// already-removed file is a no-op.
func writeArgsFile(call psCall) (path string, remove func(), err error) {
	body, err := call.argsJSON()
	if err != nil {
		return "", func() {}, fmt.Errorf("hyperv-ps-host: encode args: %w", err)
	}
	path, remove, err = stageFile("cfgms-args-*.json", body)
	if err != nil {
		return "", func() {}, fmt.Errorf("stage args file: %w", err)
	}
	return path, remove, nil
}

// invokeExpression returns the only script text a dispatched call sends to
// PowerShell: `Cfgms-Invoke -Verb '<verb>' -ArgsFile '<path>'`. The verb is a
// table constant and the path comes from stageFile, never from config.
// Both are still checked: a verb must be letters only, and a path holding an
// ASCII or Unicode single quote (U+0027, U+2018 to U+201B) or a control
// character is refused, so neither can end the single-quoted literal.
func invokeExpression(verb, argsPath string) (string, error) {
	if verb == "" {
		return "", fmt.Errorf("hyperv-ps-host: empty verb")
	}
	for _, r := range verb {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			return "", fmt.Errorf("hyperv-ps-host: verb is not letters only")
		}
	}
	for _, r := range argsPath {
		if r == '\'' || (r >= '‘' && r <= '‛') || unicode.IsControl(r) {
			return "", fmt.Errorf("hyperv-ps-host: refusing args path with a quote or control character")
		}
	}
	return "Cfgms-Invoke -Verb '" + verb + "' -ArgsFile '" + argsPath + "'", nil
}
