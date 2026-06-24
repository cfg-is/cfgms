// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
)

// vmModuleWithTransport creates a hypervModule wired with the given transport
// and tenantID for VM operation tests. vms cache is initialised empty.
func vmModuleWithTransport(transport winrmTransport, tenantID string) *hypervModule {
	return &hypervModule{
		executor:  &stubHypervExecutor{},
		transport: transport,
		tenantID:  tenantID,
		vms:       make(map[string]VMConfig),
		detector:  &fakeDetector{result: true},
	}
}

// hostVMJSON builds the getVM-shaped JSON the transport returns for call 0 of a
// setVM, expressing the LIVE host state the reconcile decision is made against
// (Part 2: host truth, never the cache). state is the desired-config vocabulary
// ("running"/"stopped"); it is mapped to the Hyper-V State string the host emits.
func hostVMJSON(name, state string, cpu int, memMB int64) string {
	hvState := "Off"
	if state == "running" {
		hvState = "Running"
	}
	return fmt.Sprintf(
		`{"found":true,"Name":%q,"MemoryStartupBytes":%d,"ProcessorCount":%d,"Generation":2,"Path":"C:\\VMs\\%s.vhdx","SwitchName":"","SwitchNames":[],"State":%q}`,
		name, memMB*1024*1024, cpu, name, hvState)
}

// ─── Exact host-name tests ─────────────────────────────────────────────────────

// TestVMHostName_IsExactConfigName verifies that the host-side VM name is the
// exact name the admin specifies — CFGMS adds no prefix or suffix. This is the
// founder directive: the actual VM name on the host must equal what is in the cfg.
func TestVMHostName_IsExactConfigName(t *testing.T) {
	const tenantID = "root/msp-a"
	const vmName = "web-01"

	transport := &testWinRMTransport{}
	m := vmModuleWithTransport(transport, tenantID)

	// state:absent → getVM (call 0) then Remove-VM (call 1).
	// Both pass only Name in args — the exact config name, no prefix.
	require.NoError(t, m.Set(context.Background(), "vm:"+vmName,
		mapConfigState{"name": vmName, "state": "absent"}))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 2, "getVM + Remove-VM expected for absent path")
	// calls[1] is Remove-VM — verify the exact name is passed as an arg.
	require.NotEmpty(t, calls[1].args)
	assert.Equal(t, vmName, calls[1].args[0],
		"host-side VM name must be the exact config name — no cfgms- prefix or tenant namespacing")
}

// ─── VMConfig.Validate tests ───────────────────────────────────────────────────

// TestVMConfig_Validate_AcceptsDoubleUnderscore verifies that VM names containing
// __ are now accepted — the underscore is in the allowlist charset and there is
// no longer a reserved separator (host names are exact, never namespaced).
func TestVMConfig_Validate_AcceptsDoubleUnderscore(t *testing.T) {
	cfg := &VMConfig{Name: "my__vm", VHDPath: `C:\VMs\test.vhdx`}
	require.NoError(t, cfg.Validate(),
		"VM name containing __ must be accepted now that names are not namespaced")
}

// TestVMConfig_Validate_AcceptsGen1 verifies that Generation 1 VMs are accepted
// (ADR-009 §5 lifted the Gen-2-only restriction).
func TestVMConfig_Validate_AcceptsGen1(t *testing.T) {
	cfg := &VMConfig{Name: "test-vm", Generation: 1, VHDPath: `C:\VMs\test.vhdx`}
	require.NoError(t, cfg.Validate(), "Generation 1 must be accepted per ADR-009 §5")
}

// TestVMConfig_Validate_AcceptsGen2 verifies that Generation 2 and unset (0) are accepted.
func TestVMConfig_Validate_AcceptsGen2(t *testing.T) {
	cfg2 := &VMConfig{Name: "test-vm", Generation: 2, VHDPath: `C:\VMs\test.vhdx`}
	require.NoError(t, cfg2.Validate(), "Generation 2 must be accepted")

	cfgDefault := &VMConfig{Name: "test-vm", Generation: 0, VHDPath: `C:\VMs\test.vhdx`}
	require.NoError(t, cfgDefault.Validate(), "Generation 0 (default) must be accepted")
}

// TestVMConfig_Validate_RejectsInjectionChars verifies that VM names containing
// PowerShell injection characters are rejected by the allowlist regex.
func TestVMConfig_Validate_RejectsInjectionChars(t *testing.T) {
	payloads := []string{
		"'; Remove-VM -Force; '", // single-quote injection
		"$(Remove-VM)",           // subexpression
		"`Remove-VM",             // backtick escape
		"vm\x00name",             // null byte
		"vm‐name",                // U+2010 Unicode hyphen lookalike
	}
	for _, payload := range payloads {
		cfg := &VMConfig{Name: payload, VHDPath: `C:\VMs\test.vhdx`}
		err := cfg.Validate()
		require.Error(t, err, "payload %q must be rejected", payload)
		assert.ErrorIs(t, err, ErrInvalidVMName, "payload %q should return ErrInvalidVMName", payload)
	}
}

// ─── Injection defense tests ───────────────────────────────────────────────────

// TestVMInjectionDefense verifies that the (exact) VM name is transmitted as a
// WinRM ArgumentList parameter, never interpolated into the PowerShell script text.
// Uses Get("vm:foo") since Get passes only the Name argument, making args[0] the
// exact VM name.
func TestVMInjectionDefense(t *testing.T) {
	const tenantID = "acme"
	const vmName = "webserver"

	transport := &testWinRMTransport{
		output: `{"found":true,"Name":"` + vmName + `","MemoryStartupBytes":4294967296,"ProcessorCount":2,"Generation":2,"Path":"C:\\VMs\\webserver.vhdx","SwitchName":"External","State":"Running"}`,
	}
	m := vmModuleWithTransport(transport, tenantID)

	_, err := m.Get(context.Background(), "vm:"+vmName)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 1, "exactly one ExecutePS call expected")
	call := calls[0]

	// args[0] must be the exact host-side name
	require.Len(t, call.args, 1, "only Name should be in psArgs for GetVM")
	assert.Equal(t, vmName, call.args[0], "VM name must appear in args, not scriptBlock")

	// script block must NOT contain the name literal
	assert.NotContains(t, call.scriptBlock, vmName,
		"VM name must NOT appear in scriptBlock text — use $Name param reference")
}

// ─── Set absent tests ──────────────────────────────────────────────────────────

// TestSet_VMAbsent_CallsRemoveVM verifies that Set with state "absent" calls Remove-VM
// and passes the exact VM name as a WinRM argument (not interpolated into the script).
func TestSet_VMAbsent_CallsRemoveVM(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vmModuleWithTransport(transport, "ops")

	cfg := mapConfigState{
		"name":  "myvm",
		"state": "absent",
	}

	err := m.Set(context.Background(), "vm:myvm", cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// absent path: call 0 = getVM (before-snapshot), call 1 = Remove-VM.
	require.Len(t, calls, 2, "getVM + Remove-VM expected for absent path")
	call := calls[1]

	// script must contain Remove-VM
	assert.Contains(t, call.scriptBlock, "Remove-VM",
		"Set with state absent must invoke Remove-VM")

	// exact name must appear in args, not script
	require.NotEmpty(t, call.args)
	assert.Equal(t, "myvm", call.args[0],
		"exact VM name must appear in args[0] for Remove")
	assert.NotContains(t, call.scriptBlock, "myvm",
		"name must not be interpolated in scriptBlock")
}

// ─── Get not found tests ───────────────────────────────────────────────────────

// TestGet_VM_ReturnsAbsentWhenMissing verifies that Get returns a state:"absent"
// ConfigState (no error) when the remote host reports the VM does not exist.
// This matches the contract honored by the directory and file modules and lets
// the unified executor detect drift against a desired state:"present"/"running"
// configuration.
func TestGet_VM_ReturnsAbsentWhenMissing(t *testing.T) {
	// Transport returns not-found JSON (VM absent on host)
	transport := &testWinRMTransport{output: `{"found":false}`}
	m := vmModuleWithTransport(transport, "t")

	state, err := m.Get(context.Background(), "vm:nonexistent")
	require.NoError(t, err, "missing VM must NOT be reported as an error")
	require.NotNil(t, state)
	assert.Equal(t, "absent", state.AsMap()["state"],
		"missing VM must surface as state:absent so the executor can drive Set")
}

// TestGet_VM_WrapsTransportError verifies that transport-layer failures (e.g.
// WinRM connection refused) are returned as wrapped errors, NOT as
// ErrVMNotFound. Conflating "absent" with "transport broken" was the root
// cause of F14: every failed Get aborted the Set even when the host was
// simply offline.
func TestGet_VM_WrapsTransportError(t *testing.T) {
	transport := &testWinRMTransport{execErr: errors.New("winrm: connection refused")}
	m := vmModuleWithTransport(transport, "t")

	_, err := m.Get(context.Background(), "vm:unreachable")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrVMNotFound,
		"transport errors must NOT be reported as ErrVMNotFound")
	assert.Contains(t, err.Error(), "winrm: connection refused",
		"underlying transport error message must be preserved in the chain")
}

// ─── Tenant isolation tests ────────────────────────────────────────────────────

// TestExactName_RegardlessOfTenant verifies that the host-side VM name is the
// exact config name regardless of tenant_id — CFGMS never namespaces. Two modules
// for different tenants both target the exact name "foo" on the host. (Operators
// sharing a host across tenants are responsible for choosing non-colliding names.)
func TestExactName_RegardlessOfTenant(t *testing.T) {
	transportA := &testWinRMTransport{}
	transportB := &testWinRMTransport{}

	moduleA := vmModuleWithTransport(transportA, "a")
	moduleB := vmModuleWithTransport(transportB, "b")

	// Both tenants remove a VM named "foo" (state: absent — only Name in args)
	cfg := mapConfigState{"name": "foo", "state": "absent"}

	require.NoError(t, moduleA.Set(context.Background(), "vm:foo", cfg))
	require.NoError(t, moduleB.Set(context.Background(), "vm:foo", cfg))

	transportA.mu.Lock()
	callsA := transportA.calls
	transportA.mu.Unlock()

	transportB.mu.Lock()
	callsB := transportB.calls
	transportB.mu.Unlock()

	// absent path: call 0 = getVM, call 1 = Remove-VM.
	require.Len(t, callsA, 2, "getVM + Remove-VM expected for absent path (tenant A)")
	require.Len(t, callsB, 2, "getVM + Remove-VM expected for absent path (tenant B)")

	// Both tenants must target the exact name "foo" in the Remove-VM call — no prefix.
	require.NotEmpty(t, callsA[1].args)
	assert.Equal(t, "foo", callsA[1].args[0], "tenant A must use the exact name")
	require.NotEmpty(t, callsB[1].args)
	assert.Equal(t, "foo", callsB[1].args[0], "tenant B must use the exact name")

	// Injection safety: the name still travels via args, never interpolated.
	assert.NotContains(t, callsA[1].scriptBlock, "foo")
	assert.NotContains(t, callsB[1].scriptBlock, "foo")
}

// ─── VMConfig ConfigState interface tests ─────────────────────────────────────

// TestVMConfig_AsMap verifies that AsMap includes all configuration fields.
func TestVMConfig_AsMap(t *testing.T) {
	cfg := &VMConfig{
		Name:       "my-vm",
		MemoryMB:   4096,
		CPUCount:   2,
		VHDPath:    `C:\VMs\my-vm.vhdx`,
		SwitchName: "External",
		Generation: 2,
		State:      "running",
	}
	m := cfg.AsMap()
	assert.Equal(t, "my-vm", m["name"])
	assert.Equal(t, int64(4096), m["memory_mb"])
	assert.Equal(t, 2, m["cpu_count"])
	assert.Equal(t, `C:\VMs\my-vm.vhdx`, m["vhd_path"])
	assert.Equal(t, "External", m["switch_name"])
	assert.Equal(t, 2, m["generation"])
	assert.Equal(t, "running", m["state"])
}

// TestVMConfig_YAML verifies round-trip YAML serialization.
func TestVMConfig_YAML(t *testing.T) {
	original := &VMConfig{
		Name:       "roundtrip-vm",
		MemoryMB:   2048,
		CPUCount:   4,
		VHDPath:    `C:\VMs\rt.vhdx`,
		SwitchName: "Default Switch",
		Generation: 2,
		State:      "stopped",
	}
	data, err := original.ToYAML()
	require.NoError(t, err)

	decoded := &VMConfig{}
	require.NoError(t, decoded.FromYAML(data))
	assert.Equal(t, original, decoded)
}

// TestVMConfig_Validate_RejectsInvalidVHDPath verifies that non-Windows paths are rejected.
func TestVMConfig_Validate_RejectsInvalidVHDPath(t *testing.T) {
	cfg := &VMConfig{Name: "vm", VHDPath: "/unix/path/disk.vhd"}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidVHDPath)
}

// TestVMConfig_Validate_AcceptsValidConfig verifies a well-formed VMConfig passes Validate.
func TestVMConfig_Validate_AcceptsValidConfig(t *testing.T) {
	cfg := &VMConfig{
		Name:       "prod-vm",
		MemoryMB:   8192,
		CPUCount:   4,
		VHDPath:    `C:\VMs\prod-vm.vhdx`,
		SwitchName: "External",
		Generation: 2,
	}
	require.NoError(t, cfg.Validate())
}

// ─── Declarative multi-NIC (switch_name list) parse tests (#2021) ─────────────

// TestVMConfig_SwitchName_AcceptsSingleString verifies the back-compat path:
// a single switch_name string materialises a one-element desired set and keeps
// SwitchName populated for the New-VM primary-adapter path.
func TestVMConfig_SwitchName_AcceptsSingleString(t *testing.T) {
	cfg := &VMConfig{}
	require.NoError(t, cfg.FromYAML([]byte("name: web-01\nswitch_name: External\n")))
	assert.Equal(t, "External", cfg.SwitchName, "single string must populate primary SwitchName")
	assert.Equal(t, []string{"External"}, cfg.desiredSwitches(),
		"single switch_name string must yield a one-element desired set")
}

// TestVMConfig_SwitchName_AcceptsList verifies that switch_name as a YAML list
// materialises the full ordered desired set with the first element as primary.
func TestVMConfig_SwitchName_AcceptsList(t *testing.T) {
	cfg := &VMConfig{}
	require.NoError(t, cfg.FromYAML([]byte("name: web-01\nswitch_name:\n  - External\n  - Mgmt\n")))
	assert.Equal(t, "External", cfg.SwitchName, "first list element must become primary SwitchName")
	assert.Equal(t, []string{"External", "Mgmt"}, cfg.desiredSwitches(),
		"switch_name list must yield the full ordered desired set")
}

// TestVMConfig_DesiredSwitches_DedupesAndDropsEmpty verifies that the desired
// set is de-duplicated and empty entries are dropped, preserving first-seen order.
func TestVMConfig_DesiredSwitches_DedupesAndDropsEmpty(t *testing.T) {
	cfg := &VMConfig{SwitchName: "External", SwitchNames: stringOrStringList{"External", "", "Mgmt", "Mgmt"}}
	assert.Equal(t, []string{"External", "Mgmt"}, cfg.desiredSwitches())
}

// TestVMConfig_SwitchName_YAMLRoundTripSingle verifies a single switch_name
// round-trips as a bare scalar (not a one-element list).
func TestVMConfig_SwitchName_YAMLRoundTripSingle(t *testing.T) {
	cfg := &VMConfig{Name: "web-01", SwitchName: "External"}
	data, err := cfg.ToYAML()
	require.NoError(t, err)
	assert.Contains(t, string(data), "switch_name: External",
		"single switch must serialise as a bare scalar for back-compat")
}

// TestVMConfig_SwitchName_YAMLRoundTripList verifies a multi-switch config
// round-trips through YAML preserving the full set.
func TestVMConfig_SwitchName_YAMLRoundTripList(t *testing.T) {
	cfg := &VMConfig{Name: "web-01", SwitchNames: stringOrStringList{"External", "Mgmt"}}
	data, err := cfg.ToYAML()
	require.NoError(t, err)

	decoded := &VMConfig{}
	require.NoError(t, decoded.FromYAML(data))
	assert.Equal(t, []string{"External", "Mgmt"}, decoded.desiredSwitches())
}

// TestVMConfig_Validate_RejectsBadSwitchInList verifies that a malformed switch
// name anywhere in the desired set is rejected before any PS call.
func TestVMConfig_Validate_RejectsBadSwitchInList(t *testing.T) {
	cfg := &VMConfig{
		Name:        "web-01",
		VHDPath:     `C:\VMs\web-01.vhdx`,
		SwitchNames: stringOrStringList{"External", "'; Remove-VMSwitch; '"},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSwitchName)
}

// ─── Convergence diff logic tests (#2021) ─────────────────────────────────────

// TestSwitchSetDiff verifies the pure desired-vs-current reconcile planner:
// correct connect/disconnect actions and idempotence when the sets are equal.
func TestSwitchSetDiff(t *testing.T) {
	cases := []struct {
		name           string
		desired        []string
		current        []string
		wantConnect    []string
		wantDisconnect []string
	}{
		{
			name:    "equal sets are idempotent (no actions)",
			desired: []string{"External", "Mgmt"},
			current: []string{"External", "Mgmt"},
		},
		{
			name:        "add one switch connects one adapter",
			desired:     []string{"External", "Mgmt"},
			current:     []string{"External"},
			wantConnect: []string{"Mgmt"},
		},
		{
			name:           "remove one switch disconnects one adapter",
			desired:        []string{"External"},
			current:        []string{"External", "Mgmt"},
			wantDisconnect: []string{"Mgmt"},
		},
		{
			name:           "swap switch connects new and disconnects old",
			desired:        []string{"External", "Storage"},
			current:        []string{"External", "Mgmt"},
			wantConnect:    []string{"Storage"},
			wantDisconnect: []string{"Mgmt"},
		},
		{
			name:        "empty current connects all desired in order",
			desired:     []string{"External", "Mgmt"},
			current:     nil,
			wantConnect: []string{"External", "Mgmt"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			connect, disconnect := switchSetDiff(tc.desired, tc.current)
			assert.Equal(t, tc.wantConnect, connect, "toConnect mismatch")
			assert.Equal(t, tc.wantDisconnect, disconnect, "toDisconnect mismatch")
		})
	}
}

// ─── getVM multi-adapter read tests (#2021) ───────────────────────────────────

// TestGet_VM_ReadsMultipleAdapters verifies getVM surfaces every connected
// switch (not just the first adapter) in the observed desired set.
func TestGet_VM_ReadsMultipleAdapters(t *testing.T) {
	const tenantID = "prod"
	const vmName = "app-server"

	transport := &testWinRMTransport{
		output: `{"found":true,"Name":"` + vmName + `","MemoryStartupBytes":4294967296,"ProcessorCount":4,"Generation":2,"Path":"C:\\VMs\\app-server.vhdx","SwitchName":"External","SwitchNames":["External","Mgmt"],"State":"Running"}`,
	}
	m := vmModuleWithTransport(transport, tenantID)

	state, err := m.Get(context.Background(), "vm:"+vmName)
	require.NoError(t, err)

	cfg, ok := state.(*VMConfig)
	require.True(t, ok)
	assert.Equal(t, "External", cfg.SwitchName, "primary switch is the first adapter")
	assert.Equal(t, []string{"External", "Mgmt"}, cfg.desiredSwitches(),
		"getVM must read all adapters' switches into the observed set")
}

// TestGet_VM_SingleAdapterScalarSwitchNames verifies tolerance for the PS
// ConvertTo-Json single-element collapse (SwitchNames as a bare string).
func TestGet_VM_SingleAdapterScalarSwitchNames(t *testing.T) {
	const tenantID = "prod"
	const vmName = "app-server"

	transport := &testWinRMTransport{
		output: `{"found":true,"Name":"` + vmName + `","MemoryStartupBytes":4294967296,"ProcessorCount":4,"Generation":2,"Path":"C:\\VMs\\app-server.vhdx","SwitchName":"External","SwitchNames":"External","State":"Running"}`,
	}
	m := vmModuleWithTransport(transport, tenantID)

	state, err := m.Get(context.Background(), "vm:"+vmName)
	require.NoError(t, err)
	cfg := state.(*VMConfig)
	assert.Equal(t, []string{"External"}, cfg.desiredSwitches())
}

// ─── setVM network reconcile tests (#2021) ────────────────────────────────────

// TestSetVM_MultiSwitchCreate verifies that creating a VM with two desired
// switches issues New-VM (first switch) plus one Add-VMNetworkAdapter for the
// second switch.
func TestSetVM_MultiSwitchCreate(t *testing.T) {
	transport := &testWinRMTransport{perCallOutputs: []string{`{"found":false}`}}
	m := vmModuleWithTransport(transport, "dev")

	cfg := &VMConfig{
		Name:        "multinic",
		MemoryMB:    4096,
		CPUCount:    2,
		VHDPath:     `C:\VMs\multinic.vhdx`,
		SwitchNames: stringOrStringList{"External", "Mgmt"},
		Generation:  2,
		State:       "stopped",
	}

	require.NoError(t, m.Set(context.Background(), "vm:multinic", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// getVM (not-found) + New-VM + one Add-VMNetworkAdapter for the 2nd switch.
	require.Len(t, calls, 3)
	assert.Contains(t, calls[1].scriptBlock, "New-VM", "second call must be New-VM")
	assert.Contains(t, calls[2].scriptBlock, "Add-VMNetworkAdapter",
		"third call must connect the additional adapter")
	// The additional switch name travels as an argument, never in the script.
	require.NotEmpty(t, calls[2].args)
	// The switch name is the EXACT name (no namespacing) and travels via args,
	// never interpolated into the script body.
	assert.Contains(t, calls[2].args, "Mgmt", "additional switch must travel via args, exact name")
	assert.NotContains(t, calls[2].scriptBlock, "Mgmt",
		"switch name must not be interpolated into the script body")
}

// TestSetVM_MultiSwitch_AddsAndRemovesAdapters verifies the UPDATE reconcile:
// from current {External, Mgmt} to desired {External, Storage} connects Storage
// and disconnects Mgmt, with no New-VM.
func TestSetVM_MultiSwitch_AddsAndRemovesAdapters(t *testing.T) {
	// getVM (call 0) reports the live host: VM exists, stopped, on [External, Mgmt].
	// Part 2: the reconcile decision is made off this host truth, not the cache.
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":true,"Name":"foo","MemoryStartupBytes":4294967296,"ProcessorCount":2,"Generation":2,"Path":"C:\\VMs\\foo.vhdx","SwitchName":"External","SwitchNames":["External","Mgmt"],"State":"Off"}`},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := &VMConfig{
		Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 4096,
		SwitchNames: stringOrStringList{"External", "Storage"},
	}
	require.NoError(t, m.Set(context.Background(), "vm:foo", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	var connect, disconnect bool
	for _, c := range calls {
		assert.NotContains(t, c.scriptBlock, "New-VM", "reconcile on existing VM must not create")
		if strings.Contains(c.scriptBlock, "Add-VMNetworkAdapter") {
			connect = true
			assert.Contains(t, c.args, "Storage", "newly desired switch uses its exact name")
		}
		if strings.Contains(c.scriptBlock, "Remove-VMNetworkAdapter") {
			disconnect = true
			assert.Contains(t, c.args, "Mgmt", "removed switch uses its exact name")
		}
	}
	assert.True(t, connect, "must connect the newly desired switch")
	assert.True(t, disconnect, "must disconnect the no-longer-desired switch")
}

// TestSetVM_MultiSwitch_IdempotentWhenEqual verifies that when the desired set
// equals the current set, NO network mutation runs (no Add/Remove-VMNetworkAdapter).
func TestSetVM_MultiSwitch_IdempotentWhenEqual(t *testing.T) {
	// getVM (call 0) reports the host already on [External, Mgmt], stopped, with
	// the desired CPU/memory — fully converged.
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":true,"Name":"foo","MemoryStartupBytes":4294967296,"ProcessorCount":2,"Generation":2,"Path":"C:\\VMs\\foo.vhdx","SwitchName":"External","SwitchNames":["External","Mgmt"],"State":"Off"}`},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := &VMConfig{
		Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 4096,
		SwitchNames: stringOrStringList{"External", "Mgmt"},
	}
	require.NoError(t, m.Set(context.Background(), "vm:foo", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// Fully converged desired==current state must issue ZERO host MUTATIONS. The
	// only call is the getVM host-truth read (call 0); no Add/Remove/Stop/Start.
	require.Len(t, calls, 1, "only the getVM host-truth read should run when desired == current")
	for _, c := range calls {
		assert.NotContains(t, c.scriptBlock, "Add-VMNetworkAdapter",
			"equal switch sets must not connect adapters")
		assert.NotContains(t, c.scriptBlock, "Remove-VMNetworkAdapter",
			"equal switch sets must not remove adapters")
		assert.NotContains(t, c.scriptBlock, "Stop-VM")
		assert.NotContains(t, c.scriptBlock, "Start-VM")
	}
}

// rawConfigState is a minimal ConfigState backed by a plain map — exactly the
// shape the steward executor hands the module (config.AsMap), as opposed to a
// *VMConfig. Used to exercise setVM's config-map parsing path.
type rawConfigState struct{ m map[string]interface{} }

func (r rawConfigState) AsMap() map[string]interface{} { return r.m }
func (r rawConfigState) ToYAML() ([]byte, error)       { return nil, nil }
func (r rawConfigState) FromYAML([]byte) error         { return nil }
func (r rawConfigState) Validate() error               { return nil }
func (r rawConfigState) GetManagedFields() []string    { return nil }

// TestSetVM_ConfigMap_SwitchNameList_Connects is the regression for the
// live-found bug: when the desired config arrives as a generic map (the real
// executor path) with switch_name as a LIST, setVM must parse it and reconcile
// the adapters. The *VMConfig-based multi-NIC tests bypassed this map parsing,
// so the list was silently dropped (desired set empty -> reconcile no-op).
func TestSetVM_ConfigMap_SwitchNameList_Connects(t *testing.T) {
	// getVM (call 0) reports the host on [hv-int]; desired adds hv-priv.
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":true,"Name":"foo","MemoryStartupBytes":4294967296,"ProcessorCount":2,"Generation":2,"Path":"C:\\VMs\\foo.vhdx","SwitchName":"hv-int","SwitchNames":["hv-int"],"State":"Off"}`},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := rawConfigState{m: map[string]interface{}{
		"memory_mb":   4096,
		"cpu_count":   2,
		"state":       "stopped",
		"switch_name": []interface{}{"hv-int", "hv-priv"}, // LIST via the map path
	}}
	require.NoError(t, m.Set(context.Background(), "vm:foo", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	var connectedPriv bool
	for _, c := range calls {
		if strings.Contains(c.scriptBlock, "Add-VMNetworkAdapter") && contains(c.args, "hv-priv") {
			connectedPriv = true
		}
	}
	assert.True(t, connectedPriv,
		"switch_name LIST from the config map must be parsed and connect hv-priv (exact name)")
}

func contains(args []interface{}, want string) bool {
	for _, a := range args {
		if s, ok := a.(string); ok && s == want {
			return true
		}
	}
	return false
}

// ─── SourceConfig validation tests ────────────────────────────────────────────

// TestSourceConfig_Validate exercises every invalid-source error path via real
// VMConfig.Validate() calls (no mocks).
func TestSourceConfig_Validate(t *testing.T) {
	validBase := func() *VMConfig {
		return &VMConfig{
			Name:    "src-vm",
			VHDPath: `C:\VMs\src-vm.vhdx`,
			Source: &SourceConfig{
				ISO:      `C:\ISO\server.iso`,
				OSFamily: "windows",
				Completion: CompletionConfig{
					Mode: "steward-registration",
				},
			},
		}
	}

	t.Run("valid source passes validation", func(t *testing.T) {
		require.NoError(t, validBase().Validate())
	})

	t.Run("non-absolute iso path", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.ISO = "relative/path/server.iso"
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSourceISO)
	})

	t.Run("empty iso path", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.ISO = ""
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSourceISO)
	})

	t.Run("unknown os_family", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.OSFamily = "bsd"
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSourceOSFamily)
	})

	t.Run("empty os_family", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.OSFamily = ""
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSourceOSFamily)
	})

	t.Run("os_family linux is valid", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.OSFamily = "linux"
		require.NoError(t, cfg.Validate())
	})

	// ── cloud-init (source.image) validation ──────────────────────────────
	// validCloudInit returns a linux cloud-init source (image, no iso).
	validCloudInit := func() *VMConfig {
		return &VMConfig{
			Name:    "ci-vm",
			VHDPath: `C:\VMs\ci-vm.vhdx`,
			Source: &SourceConfig{
				Image:    `C:\images\debian-13-generic-amd64.raw`,
				OSFamily: "linux",
				ResizeGB: 20,
				Completion: CompletionConfig{
					Mode: "steward-registration",
				},
			},
		}
	}

	t.Run("linux cloud-init image is valid", func(t *testing.T) {
		require.NoError(t, validCloudInit().Validate())
	})

	t.Run("linux cloud-init image is detected", func(t *testing.T) {
		assert.True(t, validCloudInit().Source.isCloudInit())
		// A linux source with iso (not image) is NOT cloud-init.
		legacy := validBase()
		legacy.Source.OSFamily = "linux"
		assert.False(t, legacy.Source.isCloudInit())
	})

	t.Run("linux with neither image nor iso", func(t *testing.T) {
		cfg := validCloudInit()
		cfg.Source.Image = ""
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSourceMedia)
	})

	t.Run("non-absolute image path", func(t *testing.T) {
		cfg := validCloudInit()
		cfg.Source.Image = "images/debian.raw"
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSourceImage)
	})

	t.Run("UNC image path is rejected", func(t *testing.T) {
		cfg := validCloudInit()
		cfg.Source.Image = `\\fileserver\share\debian.raw`
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSourceImage)
	})

	t.Run("negative resize_gb is rejected", func(t *testing.T) {
		cfg := validCloudInit()
		cfg.Source.ResizeGB = -1
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSourceResize)
	})

	t.Run("oversized resize_gb is rejected", func(t *testing.T) {
		cfg := validCloudInit()
		cfg.Source.ResizeGB = 100000
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSourceResize)
	})

	t.Run("zero resize_gb is valid (native size)", func(t *testing.T) {
		cfg := validCloudInit()
		cfg.Source.ResizeGB = 0
		require.NoError(t, cfg.Validate())
	})

	t.Run("unattend without profile:// prefix", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.Unattend = "s3://bucket/unattend.xml"
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSourceUnattend)
	})

	t.Run("unattend with profile:// prefix is valid", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.Unattend = "profile://windows/server2022"
		require.NoError(t, cfg.Validate())
	})

	t.Run("unattend empty is valid (optional)", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.Unattend = ""
		require.NoError(t, cfg.Validate())
	})

	t.Run("unknown completion mode", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.Completion.Mode = "ssh-probe"
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSourceCompletionMode)
	})

	t.Run("empty completion mode is valid (optional)", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.Completion.Mode = ""
		require.NoError(t, cfg.Validate())
	})

	t.Run("unparseable completion timeout", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.Completion.Timeout = "not-a-duration"
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSourceCompletionTimeout)
	})

	t.Run("valid completion timeout", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.Completion.Timeout = "60m"
		require.NoError(t, cfg.Validate())
	})

	t.Run("empty completion timeout is valid (optional)", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.Completion.Timeout = ""
		require.NoError(t, cfg.Validate())
	})

	t.Run("unknown on_existing", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.OnExisting = "replace"
		err := cfg.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSourceOnExisting)
	})

	t.Run("on_existing never is valid", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.OnExisting = "never"
		require.NoError(t, cfg.Validate())
	})

	t.Run("on_existing recreate is valid", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.OnExisting = "recreate"
		require.NoError(t, cfg.Validate())
	})

	t.Run("on_existing empty defaults to never (valid)", func(t *testing.T) {
		cfg := validBase()
		cfg.Source.OnExisting = ""
		require.NoError(t, cfg.Validate())
	})

	t.Run("nil source leaves existing configs unchanged", func(t *testing.T) {
		cfg := &VMConfig{Name: "no-src-vm", VHDPath: `C:\VMs\no-src.vhdx`}
		require.NoError(t, cfg.Validate(), "absent source: block must not affect validation")
	})
}

// TestVMConfig_AsMap_SwitchNameReflectsFullSet is the drift-detection
// regression: AsMap must surface the FULL switch set on the "switch_name"
// managed field, so the executor's CompareStates detects a removed NIC (a
// reduced desired set differs from the current full set). Emitting only the
// primary switch hid un-set from the comparator (live-found on CFG-70-02).
func TestVMConfig_AsMap_SwitchNameReflectsFullSet(t *testing.T) {
	// Multi-NIC: switch_name must be the full list, not just the first switch.
	multi := (&VMConfig{Name: "vm", SwitchNames: stringOrStringList{"a", "b"}}).AsMap()
	assert.Equal(t, []interface{}{"a", "b"}, multi["switch_name"],
		"multi-NIC switch_name must reflect the full set so un-set is detectable")

	// Single NIC: a bare string (matches the common config, stays idempotent).
	single := (&VMConfig{Name: "vm", SwitchName: "a"}).AsMap()
	assert.Equal(t, "a", single["switch_name"])

	// No network: empty string, not a bare prefix or nil.
	none := (&VMConfig{Name: "vm"}).AsMap()
	assert.Equal(t, "", none["switch_name"])
}

// ─── Module routing tests ──────────────────────────────────────────────────────

// TestModule_Get_UnknownResourceIDReturnsNotImplemented verifies that resource IDs
// without a known prefix still return ErrNotImplemented (backward compat).
func TestModule_Get_UnknownResourceIDReturnsNotImplemented(t *testing.T) {
	m := New(&fakeDetector{result: true})
	_, err := m.Get(context.Background(), "unknown-resource")
	assert.ErrorIs(t, err, modules.ErrNotImplemented)
}

// TestModule_Set_UnknownResourceIDReturnsNotImplemented verifies backward compat.
func TestModule_Set_UnknownResourceIDReturnsNotImplemented(t *testing.T) {
	m := New(&fakeDetector{result: true})
	err := m.Set(context.Background(), "unknown-resource", nil)
	assert.ErrorIs(t, err, modules.ErrNotImplemented)
}

// TestModule_Get_VMPrefix_NoTransport verifies that vm: prefix without transport
// returns ErrVMNotFound (module not yet configured).
func TestModule_Get_VMPrefix_NoTransport(t *testing.T) {
	m := &hypervModule{
		executor: &stubHypervExecutor{},
		vms:      make(map[string]VMConfig),
		detector: &fakeDetector{result: true},
	}
	_, err := m.Get(context.Background(), "vm:somevm")
	assert.ErrorIs(t, err, ErrVMNotFound)
}

// TestGet_VM_ReturnsConfig verifies that Get returns a properly mapped VMConfig
// when the transport returns valid VM JSON.
func TestGet_VM_ReturnsConfig(t *testing.T) {
	const tenantID = "prod"
	const vmName = "app-server"

	transport := &testWinRMTransport{
		output: `{"found":true,"Name":"` + vmName + `","MemoryStartupBytes":4294967296,"ProcessorCount":4,"Generation":2,"Path":"C:\\VMs\\app-server.vhdx","SwitchName":"External","State":"Running"}`,
	}
	m := vmModuleWithTransport(transport, tenantID)

	state, err := m.Get(context.Background(), "vm:"+vmName)
	require.NoError(t, err)
	require.NotNil(t, state)

	cfg, ok := state.(*VMConfig)
	require.True(t, ok, "Get must return *VMConfig")
	assert.Equal(t, vmName, cfg.Name, "Name must be the exact config name")
	assert.Equal(t, int64(4096), cfg.MemoryMB, "MemoryMB = MemoryStartupBytes / 1024^2")
	assert.Equal(t, 4, cfg.CPUCount)
	assert.Equal(t, 2, cfg.Generation)
	assert.Equal(t, "External", cfg.SwitchName)
	assert.Equal(t, "running", cfg.State, "State 'Running' must map to 'running'")
}

// TestSet_VMCreate verifies that Set creates a VM and passes all fields via ArgumentList.
// setVM calls getVM first to check existence: the mock returns `{"found":false}`
// for call[0] so getVM reports state:"absent" (per the F14 contract), then Set
// falls through to New-VM as call[1]. Two transport calls expected total:
// getVM (call[0]) + New-VM (call[1]).
func TestSet_VMCreate(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	m := vmModuleWithTransport(transport, "dev")

	cfg := &VMConfig{
		Name:       "test-vm",
		MemoryMB:   4096,
		CPUCount:   2,
		VHDPath:    `C:\VMs\test-vm.vhdx`,
		SwitchName: "Default Switch",
		Generation: 2,
	}

	err := m.Set(context.Background(), "vm:test-vm", cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// Two calls: getVM existence check (returns not-found) + New-VM creation
	require.Len(t, calls, 2)
	call := calls[1] // New-VM is the second call

	// Script must reference $Name parameter, not the literal name
	assert.Contains(t, call.scriptBlock, "$Name",
		"script block must use $Name parameter reference")
	assert.NotContains(t, call.scriptBlock, "test-vm",
		"VM name must not appear in scriptBlock")

	// Exact name must appear somewhere in args
	var found bool
	for _, arg := range call.args {
		if arg == "test-vm" {
			found = true
			break
		}
	}
	assert.True(t, found, "exact VM name must appear in args")
}

// ─── VM power state tests ──────────────────────────────────────────────────────

// TestSetVM_RunningState_CallsStartVM asserts that Set with state "running" on an
// existing VM issues Start-VM and does not issue New-VM.
func TestSetVM_RunningState_CallsStartVM(t *testing.T) {
	// getVM (call 0) reports the live host: VM exists, stopped, matching CPU/mem.
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSON("foo", "stopped", 2, 4096)},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := &VMConfig{
		Name:     "foo",
		State:    "running",
		CPUCount: 2,
		MemoryMB: 4096,
	}

	err := m.Set(context.Background(), "vm:foo", cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 2, "getVM host-truth read + Start-VM")
	assert.Contains(t, calls[1].scriptBlock, "Start-VM",
		"Set with state running must invoke Start-VM")
	assert.NotContains(t, calls[1].scriptBlock, "New-VM",
		"Set with state running on existing VM must not invoke New-VM")
}

// TestSetVM_StoppedState_CallsStopVM asserts that Set with state "stopped" on an
// existing VM issues Stop-VM and does not issue New-VM.
func TestSetVM_StoppedState_CallsStopVM(t *testing.T) {
	// getVM (call 0) reports the live host: VM exists, running, matching CPU/mem.
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSON("foo", "running", 2, 4096)},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := &VMConfig{
		Name:     "foo",
		State:    "stopped",
		CPUCount: 2,
		MemoryMB: 4096,
	}

	err := m.Set(context.Background(), "vm:foo", cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 2, "getVM host-truth read + Stop-VM")
	assert.Contains(t, calls[1].scriptBlock, "Stop-VM",
		"Set with state stopped must invoke Stop-VM")
	assert.NotContains(t, calls[1].scriptBlock, "New-VM",
		"Set with state stopped on existing VM must not invoke New-VM")
}

// TestSetVM_ExistingVM_ResizesViaCmdlets asserts that Set on an already-stopped VM
// with changed cpu_count and memory_mb issues Set-VMProcessor and Set-VM (for
// memory) without issuing New-VM. Because the VM is already stopped, NO Stop-VM
// is issued (power-state gating): the only calls are the two resize cmdlets.
func TestSetVM_ExistingVM_ResizesViaCmdlets(t *testing.T) {
	// getVM (call 0) reports the live host: VM stopped, 2 CPUs / 4096 MB.
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSON("foo", "stopped", 2, 4096)},
	}
	m := vmModuleWithTransport(transport, "ops")

	// Desired: 4 CPUs, 8192 MB — both differ from current.
	cfg := &VMConfig{
		Name:     "foo",
		State:    "stopped",
		CPUCount: 4,
		MemoryMB: 8192,
	}

	err := m.Set(context.Background(), "vm:foo", cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// Already-stopped VM: no Stop-VM. getVM read + Set-VMProcessor + Set-VMMemory.
	require.Len(t, calls, 3, "resize on already-stopped VM: getVM + Set-VMProcessor + Set-VMMemory")

	var scripts []string
	for _, c := range calls {
		scripts = append(scripts, c.scriptBlock)
	}

	for _, s := range scripts {
		assert.NotContains(t, s, "New-VM", "resize on existing VM must not invoke New-VM")
		assert.NotContains(t, s, "Stop-VM", "resize on already-stopped VM must not invoke Stop-VM")
	}

	hasSetVMProcessor := false
	hasSetVMMemory := false
	for _, s := range scripts {
		if strings.Contains(s, "Set-VMProcessor") {
			hasSetVMProcessor = true
		}
		if strings.Contains(s, "Set-VM") && strings.Contains(s, "MemoryStartupBytes") {
			hasSetVMMemory = true
		}
	}
	assert.True(t, hasSetVMProcessor, "resize must call Set-VMProcessor for CPU change")
	assert.True(t, hasSetVMMemory, "resize must call Set-VM with MemoryStartupBytes for memory change")
}

// TestSetVM_RunningState_WithResize verifies that Set with state "running" and
// changed CPU/memory issues Stop-VM → Set-VMProcessor → Set-VMMemory → Start-VM
// (the resize-while-running path) without issuing New-VM.
func TestSetVM_RunningState_WithResize(t *testing.T) {
	// getVM (call 0) reports the live host: VM running, 2 CPUs / 4096 MB.
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSON("foo", "running", 2, 4096)},
	}
	m := vmModuleWithTransport(transport, "ops")

	// Desired: still running, but 4 CPUs and 8192 MB.
	cfg := &VMConfig{
		Name:     "foo",
		State:    "running",
		CPUCount: 4,
		MemoryMB: 8192,
	}

	err := m.Set(context.Background(), "vm:foo", cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// Expected sequence: getVM, Stop-VM, Set-VMProcessor, Set-VMMemory, Start-VM
	require.Len(t, calls, 5, "running+resize: getVM + Stop-VM + Set-VMProcessor + Set-VMMemory + Start-VM")

	assert.Contains(t, calls[1].scriptBlock, "Stop-VM", "must Stop-VM before resize")
	assert.Contains(t, calls[2].scriptBlock, "Set-VMProcessor", "must Set-VMProcessor")
	assert.Contains(t, calls[3].scriptBlock, "Set-VM", "must Set-VM (memory)")
	assert.Contains(t, calls[4].scriptBlock, "Start-VM", "must Start-VM after resize")
	for _, c := range calls {
		assert.NotContains(t, c.scriptBlock, "New-VM", "resize on existing VM must not invoke New-VM")
	}
}

// ─── VM power-state idempotency tests (Fix B) ─────────────────────────────────

// TestSetVM_RunningState_AlreadyRunning_NoStartVM verifies that re-applying a
// desired-running config to a VM that is ALREADY running, with no other drift,
// issues NO Start-VM (and no Stop-VM). Without the current.State gate this
// re-issued Start-VM on every converge, which Hyper-V rejects with "already in
// the running state".
func TestSetVM_RunningState_AlreadyRunning_NoStartVM(t *testing.T) {
	// getVM (call 0) reports the host already running with the desired CPU/memory.
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSON("foo", "running", 2, 4096)},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := &VMConfig{Name: "foo", State: "running", CPUCount: 2, MemoryMB: 4096}
	require.NoError(t, m.Set(context.Background(), "vm:foo", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// Only the getVM host-truth read runs — no power transition.
	require.Len(t, calls, 1,
		"desired running + already running + no other drift must issue no power transitions")
	for _, c := range calls {
		assert.NotContains(t, c.scriptBlock, "Start-VM")
		assert.NotContains(t, c.scriptBlock, "Stop-VM")
	}
}

// TestSetVM_StoppedState_AlreadyStopped_NoStopVM verifies that re-applying a
// desired-stopped config to a VM that is ALREADY stopped issues NO Stop-VM.
func TestSetVM_StoppedState_AlreadyStopped_NoStopVM(t *testing.T) {
	// getVM (call 0) reports the host already stopped with the desired CPU/memory.
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSON("foo", "stopped", 2, 4096)},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := &VMConfig{Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 4096}
	require.NoError(t, m.Set(context.Background(), "vm:foo", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// Only the getVM host-truth read runs — no power transition.
	require.Len(t, calls, 1,
		"desired stopped + already stopped + no other drift must issue no power transitions")
	for _, c := range calls {
		assert.NotContains(t, c.scriptBlock, "Stop-VM")
	}
}

// TestSetVM_RunningResize_StopResizeStart verifies that a CPU/memory resize on a
// RUNNING VM still performs the full stop → resize → start sequence: the gate
// only suppresses redundant transitions, it must not suppress the stop a resize
// genuinely needs.
func TestSetVM_RunningResize_StopResizeStart(t *testing.T) {
	// getVM (call 0) reports the host running, 2 CPUs / 4096 MB.
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSON("foo", "running", 2, 4096)},
	}
	m := vmModuleWithTransport(transport, "ops")

	// Desired: still running but 4 CPUs / 8192 MB.
	cfg := &VMConfig{Name: "foo", State: "running", CPUCount: 4, MemoryMB: 8192}
	require.NoError(t, m.Set(context.Background(), "vm:foo", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 5,
		"running VM resize: getVM + Stop-VM + Set-VMProcessor + Set-VMMemory + Start-VM")
	assert.Contains(t, calls[1].scriptBlock, "Stop-VM", "must Stop-VM before resize")
	assert.Contains(t, calls[2].scriptBlock, "Set-VMProcessor", "must Set-VMProcessor")
	assert.Contains(t, calls[3].scriptBlock, "Set-VM", "must Set-VM (memory)")
	assert.Contains(t, calls[4].scriptBlock, "Start-VM", "must Start-VM after resize")
}

// ─── VM power state failure-mode tests ────────────────────────────────────────

// TestSetVM_StartVM_TransportError verifies that a transport failure on Start-VM
// surfaces an error containing "Start-VM".
func TestSetVM_StartVM_TransportError(t *testing.T) {
	// getVM (call 0) succeeds; Start-VM (call 1) fails.
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSON("foo", "stopped", 2, 4096)},
		perCallErrors:  []error{nil, errors.New("winrm: timeout")},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := &VMConfig{Name: "foo", State: "running", CPUCount: 2, MemoryMB: 4096}
	err := m.Set(context.Background(), "vm:foo", cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, "Start-VM")
}

// TestSetVM_StopVM_TransportError verifies that a transport failure on Stop-VM
// surfaces an error containing "Stop-VM".
func TestSetVM_StopVM_TransportError(t *testing.T) {
	// getVM (call 0) succeeds; Stop-VM (call 1) fails.
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSON("foo", "running", 2, 4096)},
		perCallErrors:  []error{nil, errors.New("winrm: timeout")},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := &VMConfig{Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 4096}
	err := m.Set(context.Background(), "vm:foo", cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, "Stop-VM")
}

// TestSetVM_SetVMProcessor_TransportError verifies that a transport failure on
// Set-VMProcessor surfaces an error containing "Set-VMProcessor". The VM is
// already stopped, so power-state gating skips Stop-VM and Set-VMProcessor is
// the first (and failing) call.
func TestSetVM_SetVMProcessor_TransportError(t *testing.T) {
	// getVM (call 0) succeeds; Set-VMProcessor (call 1) fails. VM already stopped,
	// so power-state gating skips Stop-VM and Set-VMProcessor is the first mutation.
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSON("foo", "stopped", 2, 4096)},
		perCallErrors:  []error{nil, errors.New("winrm: timeout")},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := &VMConfig{Name: "foo", State: "stopped", CPUCount: 4, MemoryMB: 4096}
	err := m.Set(context.Background(), "vm:foo", cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, "Set-VMProcessor")
}

// TestSetVM_SetVMMemory_TransportError verifies that a transport failure on
// Set-VMMemory surfaces an error containing "Set-VMMemory". The VM is already
// stopped (no Stop-VM) and only memory changes, so Set-VMMemory is the first
// (and failing) call.
func TestSetVM_SetVMMemory_TransportError(t *testing.T) {
	// getVM (call 0) succeeds; Set-VMMemory (call 1) fails. VM already stopped and
	// only memory changes, so Set-VMMemory is the first (and failing) mutation.
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSON("foo", "stopped", 2, 4096)},
		perCallErrors:  []error{nil, errors.New("winrm: timeout")},
	}
	m := vmModuleWithTransport(transport, "ops")

	// Only memory changes — no CPU resize, so the single resize call is Set-VMMemory.
	cfg := &VMConfig{Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 8192}
	err := m.Set(context.Background(), "vm:foo", cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, "Set-VMMemory")
}
