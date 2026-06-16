// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests drive the REAL executor path: module.Set(ctx, "vm:<name>", cfg)
// with a MAP-backed ConfigState (the shape the steward executor hands the module
// via config.AsMap) AND a transport whose getVM output controls the simulated
// HOST state. They are the regression coverage for the live-found bugs that the
// *VMConfig-based unit tests missed:
//
//   - Part 1: host object names are the EXACT config names (no cfgms- prefix).
//   - Part 2: setVM reconciles against HOST TRUTH (getVM), never the stale cache,
//     so SET (multi-NIC connect) and delete cannot be computed as no-ops.
//
// Each case sets the host state via the transport's getVM JSON (call 0) and then
// asserts the intended host mutation calls.

// scriptIndex returns the indices of recorded calls whose scriptBlock contains
// the given substring, in call order.
func callsContaining(calls []winRMCall, substr string) []winRMCall {
	var out []winRMCall
	for _, c := range calls {
		if strings.Contains(c.scriptBlock, substr) {
			out = append(out, c)
		}
	}
	return out
}

func argsContain(call winRMCall, want string) bool {
	for _, a := range call.args {
		if s, ok := a.(string); ok && s == want {
			return true
		}
	}
	return false
}

// TestReconcile_CreateWhenHostMissing_ConnectsEachSwitchByExactName drives a
// create through the map path: getVM reports not-found, so Set issues New-VM with
// the exact name and connects each additional desired switch by its exact name.
func TestReconcile_CreateWhenHostMissing_ConnectsEachSwitchByExactName(t *testing.T) {
	// Call 0: getVM → not found. Subsequent calls succeed.
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := rawConfigState{m: map[string]interface{}{
		"name":        "web-01",
		"memory_mb":   4096,
		"cpu_count":   2,
		"vhd_path":    `C:\VMs\web-01.vhdx`,
		"generation":  2,
		"state":       "stopped",
		"switch_name": []interface{}{"sw-a", "sw-b"}, // LIST via the map
	}}

	require.NoError(t, m.Set(context.Background(), "vm:web-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	newVM := callsContaining(calls, "New-VM")
	require.Len(t, newVM, 1, "exactly one New-VM expected")
	// New-VM connects the FIRST switch (sw-a) by exact name and uses the exact VM name.
	assert.True(t, argsContain(newVM[0], "web-01"), "New-VM must use the exact VM name")
	assert.True(t, argsContain(newVM[0], "sw-a"), "New-VM must connect the first switch by exact name")

	adds := callsContaining(calls, "Add-VMNetworkAdapter")
	require.Len(t, adds, 1, "one Add-VMNetworkAdapter expected for the second switch")
	assert.True(t, argsContain(adds[0], "sw-b"), "second switch must connect by exact name")
	assert.NotContains(t, adds[0].scriptBlock, "sw-b", "switch name must travel via args, not the script")
}

// TestReconcile_MultiNICSet_AddsAdapterFromHostTruth drives the multi-NIC SET via
// the map path: host VM is on [sw-a], desired is ["sw-a","sw-b"] → one
// Add-VMNetworkAdapter for sw-b, no New-VM. Proves the reconcile reads the host
// adapters (Part 2), not a cache that might say otherwise.
func TestReconcile_MultiNICSet_AddsAdapterFromHostTruth(t *testing.T) {
	// Call 0: getVM reports the host on [sw-a].
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":true,"Name":"web-01","MemoryStartupBytes":4294967296,"ProcessorCount":2,"Generation":2,"Path":"C:\\VMs\\web-01.vhdx","SwitchName":"sw-a","SwitchNames":["sw-a"],"State":"Off"}`},
	}
	m := vmModuleWithTransport(transport, "ops")

	// Seed the cache with a DIVERGENT (stale) view that already shows both
	// adapters — if reconcile used the cache it would (wrongly) skip the add.
	m.vmsMu.Lock()
	m.vms["web-01"] = VMConfig{
		Name: "web-01", State: "stopped", CPUCount: 2, MemoryMB: 4096,
		SwitchName: "sw-a", SwitchNames: stringOrStringList{"sw-a", "sw-b"},
	}
	m.vmsMu.Unlock()

	cfg := rawConfigState{m: map[string]interface{}{
		"name":        "web-01",
		"memory_mb":   4096,
		"cpu_count":   2,
		"state":       "stopped",
		"switch_name": []interface{}{"sw-a", "sw-b"},
	}}

	require.NoError(t, m.Set(context.Background(), "vm:web-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, callsContaining(calls, "New-VM"), "must not create an existing VM")
	adds := callsContaining(calls, "Add-VMNetworkAdapter")
	require.Len(t, adds, 1, "host truth ([sw-a]) vs desired ([sw-a,sw-b]) must add sw-b despite the stale cache")
	assert.True(t, argsContain(adds[0], "sw-b"), "must connect sw-b by exact name")
}

// TestReconcile_MultiNICUnSet_RemovesAdapterFromHostTruth drives the multi-NIC
// UN-SET via the map path: host VM is on [sw-a,sw-b], desired is "sw-a" (a scalar)
// → one Remove-VMNetworkAdapter for sw-b.
func TestReconcile_MultiNICUnSet_RemovesAdapterFromHostTruth(t *testing.T) {
	// Call 0: getVM reports the host on [sw-a, sw-b].
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":true,"Name":"web-01","MemoryStartupBytes":4294967296,"ProcessorCount":2,"Generation":2,"Path":"C:\\VMs\\web-01.vhdx","SwitchName":"sw-a","SwitchNames":["sw-a","sw-b"],"State":"Off"}`},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := rawConfigState{m: map[string]interface{}{
		"name":        "web-01",
		"memory_mb":   4096,
		"cpu_count":   2,
		"state":       "stopped",
		"switch_name": "sw-a", // scalar — desired set is just {sw-a}
	}}

	require.NoError(t, m.Set(context.Background(), "vm:web-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, callsContaining(calls, "New-VM"), "must not create an existing VM")
	removes := callsContaining(calls, "Remove-VMNetworkAdapter")
	require.Len(t, removes, 1, "host truth ([sw-a,sw-b]) vs desired ([sw-a]) must remove sw-b")
	assert.True(t, argsContain(removes[0], "sw-b"), "must disconnect sw-b by exact name")
}

// TestReconcile_Idempotent_NoHostMutationWhenConverged drives a fully-converged
// apply: host == desired → only the getVM read runs, zero mutations.
func TestReconcile_Idempotent_NoHostMutationWhenConverged(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":true,"Name":"web-01","MemoryStartupBytes":4294967296,"ProcessorCount":2,"Generation":2,"Path":"C:\\VMs\\web-01.vhdx","SwitchName":"sw-a","SwitchNames":["sw-a","sw-b"],"State":"Off"}`},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := rawConfigState{m: map[string]interface{}{
		"name":        "web-01",
		"memory_mb":   4096,
		"cpu_count":   2,
		"state":       "stopped",
		"switch_name": []interface{}{"sw-a", "sw-b"},
	}}

	require.NoError(t, m.Set(context.Background(), "vm:web-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 1, "converged apply must issue only the getVM host-truth read")
	for _, c := range calls {
		assert.NotContains(t, c.scriptBlock, "Add-VMNetworkAdapter")
		assert.NotContains(t, c.scriptBlock, "Remove-VMNetworkAdapter")
		assert.NotContains(t, c.scriptBlock, "Stop-VM")
		assert.NotContains(t, c.scriptBlock, "Start-VM")
		assert.NotContains(t, c.scriptBlock, "New-VM")
	}
}

// TestReconcile_Delete_RemovesVMByExactName drives state:absent via the map path
// on an existing VM → Remove-VM with the exact name. This is the delete path that
// the cache short-circuit previously let skip when the cache disagreed with host.
func TestReconcile_Delete_RemovesVMByExactName(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vmModuleWithTransport(transport, "ops")

	cfg := rawConfigState{m: map[string]interface{}{
		"name":  "web-01",
		"state": "absent",
	}}

	require.NoError(t, m.Set(context.Background(), "vm:web-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	removes := callsContaining(calls, "Remove-VM")
	require.Len(t, removes, 1, "state:absent must issue Remove-VM")
	assert.True(t, argsContain(removes[0], "web-01"), "Remove-VM must target the exact VM name")
	assert.NotContains(t, removes[0].scriptBlock, "web-01", "name must travel via args, not the script")
}

// TestReconcile_PowerIdempotent_NoStartWhenAlreadyRunning drives desired:running
// against a host already running (via getVM) → no Start-VM. Proves the power
// decision is made off host truth (Part 2).
func TestReconcile_PowerIdempotent_NoStartWhenAlreadyRunning(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":true,"Name":"web-01","MemoryStartupBytes":4294967296,"ProcessorCount":2,"Generation":2,"Path":"C:\\VMs\\web-01.vhdx","SwitchName":"sw-a","SwitchNames":["sw-a"],"State":"Running"}`},
	}
	m := vmModuleWithTransport(transport, "ops")

	cfg := rawConfigState{m: map[string]interface{}{
		"name":        "web-01",
		"memory_mb":   4096,
		"cpu_count":   2,
		"state":       "running",
		"switch_name": "sw-a",
	}}

	require.NoError(t, m.Set(context.Background(), "vm:web-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, callsContaining(calls, "Start-VM"),
		"already-running host must not be issued a redundant Start-VM")
	assert.Empty(t, callsContaining(calls, "Stop-VM"))
	require.Len(t, calls, 1, "fully converged running VM: only the getVM read runs")
}
