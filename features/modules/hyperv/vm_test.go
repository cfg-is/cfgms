// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
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

// ─── vmHostName collision tests ────────────────────────────────────────────────

// TestVMHostName_NoPrefixCollision verifies that distinct (tenantID, vmName) pairs
// always produce distinct host-side names, defeating tenant prefix forgery.
func TestVMHostName_NoPrefixCollision(t *testing.T) {
	type pair struct {
		tenantID string
		vmName   string
	}
	cases := []pair{
		// underscore in tenant vs underscore in vm name
		{"tenant_a", "foo"},
		{"tenant", "a_foo"},
		// hyphen in tenant vs hyphen in vm name
		{"tenant-a", "b"},
		{"tenant", "a-b"},
		// slash in tenant path
		{"root/msp-a", "foo"},
	}

	seen := make(map[string]pair)
	for _, c := range cases {
		host := vmHostName(c.tenantID, c.vmName)
		if prev, ok := seen[host]; ok {
			t.Errorf("collision: (%q, %q) and (%q, %q) both produce %q",
				prev.tenantID, prev.vmName, c.tenantID, c.vmName, host)
		}
		seen[host] = c
	}
}

// ─── VMConfig.Validate tests ───────────────────────────────────────────────────

// TestVMConfig_Validate_RejectsDoubleUnderscore verifies that VM names containing
// __ are rejected — this character sequence is reserved for the tenant separator.
func TestVMConfig_Validate_RejectsDoubleUnderscore(t *testing.T) {
	cfg := &VMConfig{Name: "my__vm", VHDPath: `C:\VMs\test.vhdx`}
	err := cfg.Validate()
	require.Error(t, err, "VM name containing __ must be rejected")
	assert.ErrorIs(t, err, ErrInvalidVMName)
}

// TestVMConfig_Validate_RejectsGen1 verifies that Generation 1 VMs are rejected.
func TestVMConfig_Validate_RejectsGen1(t *testing.T) {
	cfg := &VMConfig{Name: "test-vm", Generation: 1, VHDPath: `C:\VMs\test.vhdx`}
	err := cfg.Validate()
	require.Error(t, err, "Generation 1 must be rejected")
	assert.ErrorIs(t, err, ErrInvalidGeneration)
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

// TestVMInjectionDefense verifies that the prefixed VM name is transmitted as a
// WinRM ArgumentList parameter, never interpolated into the PowerShell script text.
// Uses Get("vm:foo") since Get passes only the Name argument, making args[0] the
// prefixed VM name.
func TestVMInjectionDefense(t *testing.T) {
	const tenantID = "acme"
	const vmName = "webserver"
	expectedHost := vmHostName(tenantID, vmName)

	transport := &testWinRMTransport{
		output: `{"found":true,"Name":"` + expectedHost + `","MemoryStartupBytes":4294967296,"ProcessorCount":2,"Generation":2,"Path":"C:\\VMs\\webserver.vhdx","SwitchName":"External","State":"Running"}`,
	}
	m := vmModuleWithTransport(transport, tenantID)

	_, err := m.Get(context.Background(), "vm:"+vmName)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 1, "exactly one ExecutePS call expected")
	call := calls[0]

	// args[0] must be the prefixed host-side name
	require.Len(t, call.args, 1, "only Name should be in psArgs for GetVM")
	assert.Equal(t, expectedHost, call.args[0], "prefixed VM name must appear in args, not scriptBlock")

	// script block must NOT contain the prefixed name literal
	assert.NotContains(t, call.scriptBlock, expectedHost,
		"prefixed VM name must NOT appear in scriptBlock text — use $Name param reference")
}

// ─── Set absent tests ──────────────────────────────────────────────────────────

// TestSet_VMAbsent_CallsRemoveVM verifies that Set with state "absent" calls Remove-VM
// and passes the prefixed VM name as a WinRM argument (not interpolated into the script).
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

	require.Len(t, calls, 1, "exactly one ExecutePS call expected for Remove")
	call := calls[0]

	// script must contain Remove-VM
	assert.Contains(t, call.scriptBlock, "Remove-VM",
		"Set with state absent must invoke Remove-VM")

	// prefixed name must appear in args, not script
	require.NotEmpty(t, call.args)
	assert.Equal(t, "cfgms-ops__myvm", call.args[0],
		"prefixed VM name must appear in args[0] for Remove")
	assert.NotContains(t, call.scriptBlock, "cfgms-ops__myvm",
		"prefixed name must not be interpolated in scriptBlock")
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

// TestCrossTenantIsolation_SharedHost verifies that two modules configured for
// different tenants produce distinct host-side VM names, preventing one tenant
// from interfering with another tenant's VMs on a shared Hyper-V host.
func TestCrossTenantIsolation_SharedHost(t *testing.T) {
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

	require.Len(t, callsA, 1)
	require.Len(t, callsB, 1)

	// Tenant A: host-side name must be cfgms-a__foo
	require.NotEmpty(t, callsA[0].args)
	assert.Equal(t, "cfgms-a__foo", callsA[0].args[0], "tenant A must use cfgms-a__ prefix")
	assert.NotContains(t, callsA[0].scriptBlock, "cfgms-a__foo",
		"tenant A prefixed name must not appear in scriptBlock")

	// Tenant B: host-side name must be cfgms-b__foo
	require.NotEmpty(t, callsB[0].args)
	assert.Equal(t, "cfgms-b__foo", callsB[0].args[0], "tenant B must use cfgms-b__ prefix")
	assert.NotContains(t, callsB[0].scriptBlock, "cfgms-b__foo",
		"tenant B prefixed name must not appear in scriptBlock")

	// Tenant B's name must not appear in tenant A's scriptBlock (and vice versa)
	assert.NotContains(t, callsA[0].scriptBlock, "cfgms-b__foo")
	assert.NotContains(t, callsB[0].scriptBlock, "cfgms-a__foo")

	// The two host-side names must be distinct
	assert.NotEqual(t, callsA[0].args[0], callsB[0].args[0],
		"cross-tenant isolation: host-side names must differ")
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
	hostName := vmHostName(tenantID, vmName)

	transport := &testWinRMTransport{
		output: `{"found":true,"Name":"` + hostName + `","MemoryStartupBytes":4294967296,"ProcessorCount":4,"Generation":2,"Path":"C:\\VMs\\app-server.vhdx","SwitchName":"External","SwitchNames":["External","Mgmt"],"State":"Running"}`,
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
	hostName := vmHostName(tenantID, vmName)

	transport := &testWinRMTransport{
		output: `{"found":true,"Name":"` + hostName + `","MemoryStartupBytes":4294967296,"ProcessorCount":4,"Generation":2,"Path":"C:\\VMs\\app-server.vhdx","SwitchName":"External","SwitchNames":"External","State":"Running"}`,
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
	// The switch name is translated to its host-side cfgms-<tenant>__name and
	// travels via args, never interpolated into the script body.
	assert.Contains(t, calls[2].args, "cfgms-dev__Mgmt", "additional switch must travel via args, host-namespaced")
	assert.NotContains(t, calls[2].scriptBlock, "Mgmt",
		"switch name must not be interpolated into the script body")
}

// TestSetVM_MultiSwitch_AddsAndRemovesAdapters verifies the UPDATE reconcile:
// from current {External, Mgmt} to desired {External, Storage} connects Storage
// and disconnects Mgmt, with no New-VM.
func TestSetVM_MultiSwitch_AddsAndRemovesAdapters(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vmModuleWithTransport(transport, "ops")

	m.vmsMu.Lock()
	m.vms["foo"] = VMConfig{
		Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 4096,
		SwitchName: "External", SwitchNames: stringOrStringList{"External", "Mgmt"},
	}
	m.vmsMu.Unlock()

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
			assert.Contains(t, c.args, "cfgms-ops__Storage")
		}
		if strings.Contains(c.scriptBlock, "Remove-VMNetworkAdapter") {
			disconnect = true
			assert.Contains(t, c.args, "cfgms-ops__Mgmt")
		}
	}
	assert.True(t, connect, "must connect the newly desired switch")
	assert.True(t, disconnect, "must disconnect the no-longer-desired switch")
}

// TestSetVM_MultiSwitch_IdempotentWhenEqual verifies that when the desired set
// equals the current set, NO network mutation runs (no Add/Remove-VMNetworkAdapter).
func TestSetVM_MultiSwitch_IdempotentWhenEqual(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vmModuleWithTransport(transport, "ops")

	m.vmsMu.Lock()
	m.vms["foo"] = VMConfig{
		Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 4096,
		SwitchName: "External", SwitchNames: stringOrStringList{"External", "Mgmt"},
	}
	m.vmsMu.Unlock()

	cfg := &VMConfig{
		Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 4096,
		SwitchNames: stringOrStringList{"External", "Mgmt"},
	}
	require.NoError(t, m.Set(context.Background(), "vm:foo", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// Fully converged desired==current state must issue ZERO host mutations —
	// asserting Empty makes the idempotency proof real rather than vacuous (the
	// per-call NotContains loop below is a no-op when calls is empty).
	assert.Empty(t, calls, "idempotent: zero transport calls expected when desired == current")
	for _, c := range calls {
		assert.NotContains(t, c.scriptBlock, "Add-VMNetworkAdapter",
			"equal switch sets must not connect adapters")
		assert.NotContains(t, c.scriptBlock, "Remove-VMNetworkAdapter",
			"equal switch sets must not remove adapters")
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
	transport := &testWinRMTransport{}
	m := vmModuleWithTransport(transport, "ops")

	m.vmsMu.Lock()
	m.vms["foo"] = VMConfig{
		Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 4096,
		SwitchName: "hv-int", SwitchNames: stringOrStringList{"hv-int"},
	}
	m.vmsMu.Unlock()

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
		if strings.Contains(c.scriptBlock, "Add-VMNetworkAdapter") && contains(c.args, "cfgms-ops__hv-priv") {
			connectedPriv = true
		}
	}
	assert.True(t, connectedPriv,
		"switch_name LIST from the config map must be parsed and connect hv-priv (host-namespaced)")
}

func contains(args []interface{}, want string) bool {
	for _, a := range args {
		if s, ok := a.(string); ok && s == want {
			return true
		}
	}
	return false
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
	hostName := vmHostName(tenantID, vmName)

	transport := &testWinRMTransport{
		output: `{"found":true,"Name":"` + hostName + `","MemoryStartupBytes":4294967296,"ProcessorCount":4,"Generation":2,"Path":"C:\\VMs\\app-server.vhdx","SwitchName":"External","State":"Running"}`,
	}
	m := vmModuleWithTransport(transport, tenantID)

	state, err := m.Get(context.Background(), "vm:"+vmName)
	require.NoError(t, err)
	require.NotNil(t, state)

	cfg, ok := state.(*VMConfig)
	require.True(t, ok, "Get must return *VMConfig")
	assert.Equal(t, vmName, cfg.Name, "Name must be user-visible (without prefix)")
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

	// Script must reference $Name parameter, not literal prefixed name
	assert.Contains(t, call.scriptBlock, "$Name",
		"script block must use $Name parameter reference")
	assert.NotContains(t, call.scriptBlock, "cfgms-dev__test-vm",
		"prefixed VM name must not appear in scriptBlock")

	// Prefixed name must appear somewhere in args
	var found bool
	for _, arg := range call.args {
		if arg == "cfgms-dev__test-vm" {
			found = true
			break
		}
	}
	assert.True(t, found, "prefixed VM name must appear in args")
}

// ─── VM power state tests ──────────────────────────────────────────────────────

// TestSetVM_RunningState_CallsStartVM asserts that Set with state "running" on an
// existing VM issues Start-VM and does not issue New-VM.
func TestSetVM_RunningState_CallsStartVM(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vmModuleWithTransport(transport, "ops")

	// Pre-seed VM cache to simulate existing stopped VM, bypassing getVM transport call.
	m.vmsMu.Lock()
	m.vms["foo"] = VMConfig{Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 4096}
	m.vmsMu.Unlock()

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

	require.Len(t, calls, 1, "cache-seeded VM must produce exactly one transport call (Start-VM)")
	assert.Contains(t, calls[0].scriptBlock, "Start-VM",
		"Set with state running must invoke Start-VM")
	assert.NotContains(t, calls[0].scriptBlock, "New-VM",
		"Set with state running on existing VM must not invoke New-VM")
}

// TestSetVM_StoppedState_CallsStopVM asserts that Set with state "stopped" on an
// existing VM issues Stop-VM and does not issue New-VM.
func TestSetVM_StoppedState_CallsStopVM(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vmModuleWithTransport(transport, "ops")

	// Pre-seed VM cache to simulate existing running VM.
	m.vmsMu.Lock()
	m.vms["foo"] = VMConfig{Name: "foo", State: "running", CPUCount: 2, MemoryMB: 4096}
	m.vmsMu.Unlock()

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

	require.Len(t, calls, 1, "cache-seeded VM must produce exactly one transport call (Stop-VM)")
	assert.Contains(t, calls[0].scriptBlock, "Stop-VM",
		"Set with state stopped must invoke Stop-VM")
	assert.NotContains(t, calls[0].scriptBlock, "New-VM",
		"Set with state stopped on existing VM must not invoke New-VM")
}

// TestSetVM_ExistingVM_ResizesViaCmdlets asserts that Set on an already-stopped VM
// with changed cpu_count and memory_mb issues Set-VMProcessor and Set-VM (for
// memory) without issuing New-VM. Because the VM is already stopped, NO Stop-VM
// is issued (power-state gating): the only calls are the two resize cmdlets.
func TestSetVM_ExistingVM_ResizesViaCmdlets(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vmModuleWithTransport(transport, "ops")

	// Existing VM: 2 CPUs, 4096 MB — already stopped.
	m.vmsMu.Lock()
	m.vms["foo"] = VMConfig{Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 4096}
	m.vmsMu.Unlock()

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

	// Already-stopped VM: no Stop-VM. Exactly Set-VMProcessor + Set-VMMemory.
	require.Len(t, calls, 2, "resize on already-stopped VM must produce only Set-VMProcessor + Set-VMMemory")

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
	transport := &testWinRMTransport{}
	m := vmModuleWithTransport(transport, "ops")

	// Existing running VM with 2 CPUs, 4096 MB.
	m.vmsMu.Lock()
	m.vms["foo"] = VMConfig{Name: "foo", State: "running", CPUCount: 2, MemoryMB: 4096}
	m.vmsMu.Unlock()

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

	// Expected sequence: Stop-VM, Set-VMProcessor, Set-VMMemory, Start-VM
	require.Len(t, calls, 4, "running+resize must produce Stop-VM + Set-VMProcessor + Set-VMMemory + Start-VM")

	assert.Contains(t, calls[0].scriptBlock, "Stop-VM", "first call must be Stop-VM")
	assert.Contains(t, calls[1].scriptBlock, "Set-VMProcessor", "second call must be Set-VMProcessor")
	assert.Contains(t, calls[2].scriptBlock, "Set-VM", "third call must be Set-VM (memory)")
	assert.Contains(t, calls[3].scriptBlock, "Start-VM", "fourth call must be Start-VM")
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
	transport := &testWinRMTransport{}
	m := vmModuleWithTransport(transport, "ops")

	// Existing VM already running with the exact desired CPU/memory.
	m.vmsMu.Lock()
	m.vms["foo"] = VMConfig{Name: "foo", State: "running", CPUCount: 2, MemoryMB: 4096}
	m.vmsMu.Unlock()

	cfg := &VMConfig{Name: "foo", State: "running", CPUCount: 2, MemoryMB: 4096}
	require.NoError(t, m.Set(context.Background(), "vm:foo", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, calls,
		"desired running + already running + no other drift must issue no power transitions")
	for _, c := range calls {
		assert.NotContains(t, c.scriptBlock, "Start-VM")
		assert.NotContains(t, c.scriptBlock, "Stop-VM")
	}
}

// TestSetVM_StoppedState_AlreadyStopped_NoStopVM verifies that re-applying a
// desired-stopped config to a VM that is ALREADY stopped issues NO Stop-VM.
func TestSetVM_StoppedState_AlreadyStopped_NoStopVM(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vmModuleWithTransport(transport, "ops")

	m.vmsMu.Lock()
	m.vms["foo"] = VMConfig{Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 4096}
	m.vmsMu.Unlock()

	cfg := &VMConfig{Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 4096}
	require.NoError(t, m.Set(context.Background(), "vm:foo", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, calls,
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
	transport := &testWinRMTransport{}
	m := vmModuleWithTransport(transport, "ops")

	// Running VM with 2 CPUs / 4096 MB.
	m.vmsMu.Lock()
	m.vms["foo"] = VMConfig{Name: "foo", State: "running", CPUCount: 2, MemoryMB: 4096}
	m.vmsMu.Unlock()

	// Desired: still running but 4 CPUs / 8192 MB.
	cfg := &VMConfig{Name: "foo", State: "running", CPUCount: 4, MemoryMB: 8192}
	require.NoError(t, m.Set(context.Background(), "vm:foo", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 4,
		"running VM resize must produce Stop-VM + Set-VMProcessor + Set-VMMemory + Start-VM")
	assert.Contains(t, calls[0].scriptBlock, "Stop-VM", "first call must be Stop-VM")
	assert.Contains(t, calls[1].scriptBlock, "Set-VMProcessor", "second call must be Set-VMProcessor")
	assert.Contains(t, calls[2].scriptBlock, "Set-VM", "third call must be Set-VM (memory)")
	assert.Contains(t, calls[3].scriptBlock, "Start-VM", "fourth call must be Start-VM")
}

// ─── VM power state failure-mode tests ────────────────────────────────────────

// TestSetVM_StartVM_TransportError verifies that a transport failure on Start-VM
// surfaces an error containing "Start-VM".
func TestSetVM_StartVM_TransportError(t *testing.T) {
	transport := &testWinRMTransport{execErr: errors.New("winrm: timeout")}
	m := vmModuleWithTransport(transport, "ops")

	m.vmsMu.Lock()
	m.vms["foo"] = VMConfig{Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 4096}
	m.vmsMu.Unlock()

	cfg := &VMConfig{Name: "foo", State: "running", CPUCount: 2, MemoryMB: 4096}
	err := m.Set(context.Background(), "vm:foo", cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, "Start-VM")
}

// TestSetVM_StopVM_TransportError verifies that a transport failure on Stop-VM
// surfaces an error containing "Stop-VM".
func TestSetVM_StopVM_TransportError(t *testing.T) {
	transport := &testWinRMTransport{execErr: errors.New("winrm: timeout")}
	m := vmModuleWithTransport(transport, "ops")

	m.vmsMu.Lock()
	m.vms["foo"] = VMConfig{Name: "foo", State: "running", CPUCount: 2, MemoryMB: 4096}
	m.vmsMu.Unlock()

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
	transport := &testWinRMTransport{execErr: errors.New("winrm: timeout")}
	m := vmModuleWithTransport(transport, "ops")

	m.vmsMu.Lock()
	m.vms["foo"] = VMConfig{Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 4096}
	m.vmsMu.Unlock()

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
	transport := &testWinRMTransport{execErr: errors.New("winrm: timeout")}
	m := vmModuleWithTransport(transport, "ops")

	m.vmsMu.Lock()
	m.vms["foo"] = VMConfig{Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 4096}
	m.vmsMu.Unlock()

	// Only memory changes — no CPU resize, so the single resize call is Set-VMMemory.
	cfg := &VMConfig{Name: "foo", State: "stopped", CPUCount: 2, MemoryMB: 8192}
	err := m.Set(context.Background(), "vm:foo", cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, "Set-VMMemory")
}
