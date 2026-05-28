// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
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

// TestGet_VM_ReturnsErrVMNotFound_WhenMissing verifies that Get returns ErrVMNotFound
// when the remote host reports the VM does not exist.
func TestGet_VM_ReturnsErrVMNotFound_WhenMissing(t *testing.T) {
	// Transport returns not-found JSON (VM absent on host)
	transport := &testWinRMTransport{output: `{"found":false}`}
	m := vmModuleWithTransport(transport, "t")

	_, err := m.Get(context.Background(), "vm:nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrVMNotFound)
}

// TestGet_VM_ReturnsErrVMNotFound_OnTransportError verifies that transport errors
// (e.g., WinRM connection failure) are surfaced as ErrVMNotFound.
func TestGet_VM_ReturnsErrVMNotFound_OnTransportError(t *testing.T) {
	transport := &testWinRMTransport{execErr: errors.New("winrm: connection refused")}
	m := vmModuleWithTransport(transport, "t")

	_, err := m.Get(context.Background(), "vm:unreachable")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrVMNotFound)
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

// ─── Module routing tests ──────────────────────────────────────────────────────

// TestModule_Get_UnknownResourceIDReturnsNotImplemented verifies that resource IDs
// without a known prefix still return ErrNotImplemented (backward compat).
func TestModule_Get_UnknownResourceIDReturnsNotImplemented(t *testing.T) {
	m := New(nil)
	_, err := m.Get(context.Background(), "unknown-resource")
	assert.ErrorIs(t, err, modules.ErrNotImplemented)
}

// TestModule_Set_UnknownResourceIDReturnsNotImplemented verifies backward compat.
func TestModule_Set_UnknownResourceIDReturnsNotImplemented(t *testing.T) {
	m := New(nil)
	err := m.Set(context.Background(), "unknown-resource", nil)
	assert.ErrorIs(t, err, modules.ErrNotImplemented)
}

// TestModule_Get_VMPrefix_NoTransport verifies that vm: prefix without transport
// returns ErrVMNotFound (module not yet configured).
func TestModule_Get_VMPrefix_NoTransport(t *testing.T) {
	m := &hypervModule{
		executor: &stubHypervExecutor{},
		vms:      make(map[string]VMConfig),
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
func TestSet_VMCreate(t *testing.T) {
	transport := &testWinRMTransport{}
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

	require.Len(t, calls, 1)
	call := calls[0]

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
