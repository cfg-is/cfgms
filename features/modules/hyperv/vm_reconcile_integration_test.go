// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"strings"
	"testing"
	"time"

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
	// Hyper-V refuses to remove a non-Off VM (and the connected switch stays "in
	// use"), so the delete script hard-powers-off a running VM before removing it.
	assert.Contains(t, removes[0].scriptBlock, "Stop-VM", "delete must stop a running VM before Remove-VM")
	assert.Contains(t, removes[0].scriptBlock, "-TurnOff", "delete uses a hard power-off")
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

// ── Existence-gating safety invariant (ADR-009 §2, Story #2048) ─────────────
//
// These tests prove the non-negotiable safety invariant: source provisioning is
// existence-gated, never health-gated. An existing VM is NEVER auto-destroyed or
// recreated by default; a broken existing VM is surfaced as degraded, not torn
// down; only an explicit on_existing: recreate permits destruction; an own
// in-progress attempt surfaces-and-waits rather than auto-retrying.

// existingSourceVMJSON builds a getVM-shaped JSON for a VM that already exists on
// the host, in the given raw Hyper-V State string (e.g. "Running", "Off",
// "Critical"). Used to drive the existence-gating decision tree against a VM the
// host reports as present.
func existingSourceVMJSON(name, hvState string) string {
	return `{"found":true,"Name":"` + name + `","MemoryStartupBytes":4294967296,` +
		`"ProcessorCount":2,"Generation":2,"Path":"C:\\ClusterStorage\\CSV01\\` + name + `.vhdx",` +
		`"SwitchName":"HVSwitch_1G","SwitchNames":["HVSwitch_1G"],"State":"` + hvState + `"}`
}

// TestExistenceGating_ExistingVMNotRecreatedByDefault is the headline [REQUIRED
// TEST]: when a VM already exists on the host and the desired config carries a
// source block with on_existing: never (the default), the module must issue
// ZERO New-VM and ZERO Remove-VM calls — the existing VM is never auto-destroyed
// or recreated. This is the core ADR-009 §2 safety invariant.
func TestExistenceGating_ExistingVMNotRecreatedByDefault(t *testing.T) {
	// getVM (call 0) reports the VM already present and running.
	transport := &testWinRMTransport{
		output: existingSourceVMJSON("stw-01", "Running"),
	}
	m := provisionModuleWithTransport(t, transport)

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")} // on_existing: never

	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, callsContaining(calls, "New-VM"),
		"existing VM must NEVER be (re)created when on_existing is never")
	assert.Empty(t, callsContaining(calls, "Remove-VM"),
		"existing VM must NEVER be destroyed when on_existing is never")
	// Source orchestration must not have run any of its create-path verbs either.
	assert.Empty(t, callsContaining(calls, "New-VHD"),
		"no seed VHDX may be built for an existing VM under the default")
	assert.Empty(t, callsContaining(calls, "Add-VMDvdDrive"),
		"no install ISO may be attached to an existing VM under the default")
}

// TestExistenceGating_ExistingStoppedVMNotRecreatedByDefault proves the invariant
// holds for an existing STOPPED VM too — existence, not power state, gates source.
// A stopped VM with desired state running is started, but never recreated.
func TestExistenceGating_ExistingStoppedVMNotRecreatedByDefault(t *testing.T) {
	transport := &testWinRMTransport{
		output: existingSourceVMJSON("stw-01", "Off"),
	}
	m := provisionModuleWithTransport(t, transport)

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")} // desired running, on_existing: never

	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, callsContaining(calls, "New-VM"), "existing stopped VM must not be recreated")
	assert.Empty(t, callsContaining(calls, "Remove-VM"), "existing stopped VM must not be destroyed")
	// Plain lifecycle still converges power state: desired running → Start-VM.
	require.Len(t, callsContaining(calls, "Start-VM"), 1,
		"an existing healthy VM still converges to its declared power state")
}

// TestExistenceGating_BrokenVMSurfacesAsDegraded is the second [REQUIRED TEST]:
// a VM that exists in an unexpected/broken Hyper-V state ("Critical") under the
// default on_existing must be surfaced as a degraded provisioning record with
// LastError describing the observed state — and NEVER torn down.
func TestExistenceGating_BrokenVMSurfacesAsDegraded(t *testing.T) {
	transport := &testWinRMTransport{
		output: existingSourceVMJSON("stw-01", "Critical"),
	}
	m := provisionModuleWithTransport(t, transport)

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")} // on_existing: never

	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, callsContaining(calls, "Remove-VM"),
		"a broken existing VM must NEVER be torn down — degraded is observed, not remediated")
	assert.Empty(t, callsContaining(calls, "New-VM"),
		"a broken existing VM must NEVER be recreated")

	rec, err := m.provisionStore.GetProvision(context.Background(), "stw-01")
	require.NoError(t, err, "a degraded provisioning record must be written")
	assert.Equal(t, ProvisionStateDegraded, rec.State,
		"a broken existing VM surfaces as a degraded provisioning record")
	assert.Contains(t, strings.ToLower(rec.LastError), "critical",
		"LastError must describe the observed broken VM state")
}

// TestExistenceGating_RecreateOnlyWhenExplicit proves the ONLY destructive path:
// when on_existing is recreate and the VM exists, the module issues Remove-VM
// THEN New-VM (in that order) — the explicit opt-in reprovision.
func TestExistenceGating_RecreateOnlyWhenExplicit(t *testing.T) {
	transport := &testWinRMTransport{
		output: existingSourceVMJSON("stw-01", "Running"),
	}
	m := provisionModuleWithTransport(t, transport)

	configMap := sourceVMConfigMap(2, "linux")
	src := configMap["source"].(map[string]interface{})
	src["on_existing"] = "recreate"

	cfg := rawConfigState{m: configMap}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	removes := callsContaining(calls, "Remove-VM")
	news := callsContaining(calls, "New-VM")
	require.Len(t, removes, 1, "on_existing: recreate must destroy the existing VM exactly once")
	require.Len(t, news, 1, "on_existing: recreate must recreate the VM exactly once")

	// Remove must precede New (tear down, then rebuild) — assert by call ordering.
	var removeIdx, newIdx int
	for i, c := range calls {
		if strings.Contains(c.scriptBlock, "Remove-VM") && !strings.Contains(c.scriptBlock, "Remove-VMNetworkAdapter") {
			removeIdx = i
		}
		if strings.Contains(c.scriptBlock, "New-VM") {
			newIdx = i
		}
	}
	assert.Less(t, removeIdx, newIdx, "Remove-VM must precede New-VM on the recreate path")
}

// TestApplySourceGated_RecreateCleansUpSeedMedia proves the seed-media idempotency
// fix (Issue #2466) on the on_existing: recreate path. The recreate branch calls
// DeleteProvision immediately after removeVM, so the torn-down VM leaves
// sweepStaleSeedMedia's TTL safety net — a leftover seed VHDX / answer ISO from a
// prior attempt would then never be collected, and a stale seed VHDX wedges the
// rebuild at New-VHD with "The file exists. (0x80070050)". This asserts the recreate
// cycle issues Cfgms-DeleteSeedMedia for BOTH the seed VHDX and the answer ISO,
// ordered after the teardown (Remove-VM) and before the seed is rebuilt (New-VHD).
func TestApplySourceGated_RecreateCleansUpSeedMedia(t *testing.T) {
	transport := &testWinRMTransport{
		output: existingSourceVMJSON("stw-01", "Running"),
	}
	m := provisionModuleWithTransport(t, transport)

	configMap := sourceVMConfigMap(2, "linux")
	src := configMap["source"].(map[string]interface{})
	src["on_existing"] = "recreate"

	cfg := rawConfigState{m: configMap}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// seed_dir is unset on the test module, so the seed media derives next to the
	// VM's own VHD (seedVHDPath / answerISOPath, Issue #2044).
	const vhdPath = `C:\ClusterStorage\CSV01\stw-01.vhdx`
	seedDeleteIdx := deleteSeedMediaCallIndex(calls, seedVHDPath("stw-01", vhdPath, ""))
	isoDeleteIdx := deleteSeedMediaCallIndex(calls, answerISOPath("stw-01", vhdPath, ""))
	require.NotEqual(t, -1, seedDeleteIdx, "recreate must delete the leftover seed VHDX before rebuilding it")
	require.NotEqual(t, -1, isoDeleteIdx, "recreate must delete the leftover answer ISO")

	// Ordering: cleanup runs after the VM teardown (Remove-VM) and before the seed
	// VHDX is rebuilt (New-VHD), so New-VHD never hits a pre-existing file.
	removeVMIdx, newVHDIdx := -1, -1
	for i, c := range calls {
		if strings.Contains(c.scriptBlock, "Remove-VM") && !strings.Contains(c.scriptBlock, "Remove-VMNetworkAdapter") {
			removeVMIdx = i
		}
		if strings.Contains(c.scriptBlock, "New-VHD") && newVHDIdx == -1 {
			newVHDIdx = i
		}
	}
	require.NotEqual(t, -1, removeVMIdx, "recreate must tear down the existing VM (Remove-VM)")
	require.NotEqual(t, -1, newVHDIdx, "recreate must rebuild the seed VHDX (New-VHD)")
	assert.Less(t, removeVMIdx, seedDeleteIdx, "seed-media cleanup must run after the VM teardown")
	assert.Less(t, seedDeleteIdx, newVHDIdx,
		"seed VHDX must be deleted before New-VHD, otherwise the stale file blocks creation (0x80070050)")
}

// TestApplySourceGated_RecreateCleansUpSeedMedia_VHDPathChanged proves that when
// vhd_path changes alongside on_existing: recreate, the seed-media cleanup uses the
// OBSERVED (pre-recreate) VHD path, not the new desired path. Without this fix, old
// seed media sitting beside the old disk would be permanently orphaned once
// DeleteProvision removes the record (TTL sweep can no longer see the VM after that).
func TestApplySourceGated_RecreateCleansUpSeedMedia_VHDPathChanged(t *testing.T) {
	const oldVHDPath = `C:\OldStorage\stw-01.vhdx`
	const newVHDPath = `C:\NewStorage\stw-01.vhdx`

	// call 0 (getVM) returns the VM with the OLD VHD path; subsequent calls
	// return empty string (output discarded by Remove-VM / provision verbs).
	oldVMJSON := `{"found":true,"Name":"stw-01","MemoryStartupBytes":4294967296,` +
		`"ProcessorCount":2,"Generation":2,"Path":"C:\\OldStorage\\stw-01.vhdx",` +
		`"SwitchName":"HVSwitch_1G","SwitchNames":["HVSwitch_1G"],"State":"Running"}`
	transport := &testWinRMTransport{
		perCallOutputs: []string{oldVMJSON},
	}
	m := provisionModuleWithTransport(t, transport)

	configMap := sourceVMConfigMap(2, "linux")
	configMap["vhd_path"] = newVHDPath // desired path differs from the observed old path
	src := configMap["source"].(map[string]interface{})
	src["on_existing"] = "recreate"

	require.NoError(t, m.Set(context.Background(), "vm:stw-01", rawConfigState{m: configMap}))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// Cleanup must use the OLD observed VHD path so the seed VHDX next to the
	// original disk is found and removed.
	seedDeleteIdx := deleteSeedMediaCallIndex(calls, seedVHDPath("stw-01", oldVHDPath, ""))
	isoDeleteIdx := deleteSeedMediaCallIndex(calls, answerISOPath("stw-01", oldVHDPath, ""))
	require.NotEqual(t, -1, seedDeleteIdx,
		"recreate must delete seed VHDX at the OBSERVED (pre-recreate) vhd_path, not the new desired path")
	require.NotEqual(t, -1, isoDeleteIdx,
		"recreate must delete answer ISO at the OBSERVED (pre-recreate) vhd_path, not the new desired path")

	// The new-path seed media must not be attempted (it doesn't exist yet at cleanup time).
	newSeedDeleteIdx := deleteSeedMediaCallIndex(calls, seedVHDPath("stw-01", newVHDPath, ""))
	assert.Equal(t, -1, newSeedDeleteIdx,
		"must not attempt to delete seed media at the new desired vhd_path (it hasn't been created yet)")
}

// TestSet_VMAbsent_CleansUpSeedMedia proves the VM-deletion (state: absent) half
// of the seed-media idempotency fix (Issue #2466). Deleting a VM that has staged
// seed media must reclaim it synchronously: DeleteProvision removes the record, so
// sweepStaleSeedMedia's TTL sweep can no longer see the VM, making this delete the
// only collector. The delete uses the observed VHD path from the pre-delete getVM
// (cur.VHDPath), so a VM being torn down with no desired source config still gets
// its media cleaned. This is the call site TestApplySourceGated_RecreateCleansUpSeedMedia
// does NOT cover.
func TestSet_VMAbsent_CleansUpSeedMedia(t *testing.T) {
	// getVM (call 0) reports the VM present with a VHD at C:\ClusterStorage\CSV01\stw-01.vhdx.
	transport := &testWinRMTransport{
		output: existingSourceVMJSON("stw-01", "Running"),
	}
	m := provisionModuleWithTransport(t, transport)

	require.NoError(t, m.Set(context.Background(), "vm:stw-01",
		mapConfigState{"name": "stw-01", "state": "absent"}))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	// seed_dir is unset, so the media derives next to the observed VHD (Issue #2044).
	const vhdPath = `C:\ClusterStorage\CSV01\stw-01.vhdx`
	seedDeleteIdx := deleteSeedMediaCallIndex(calls, seedVHDPath("stw-01", vhdPath, ""))
	isoDeleteIdx := deleteSeedMediaCallIndex(calls, answerISOPath("stw-01", vhdPath, ""))
	require.NotEqual(t, -1, seedDeleteIdx, "deleting a VM must reclaim its seed VHDX")
	require.NotEqual(t, -1, isoDeleteIdx, "deleting a VM must reclaim its answer ISO")

	// Cleanup must run after the VM teardown (Remove-VM).
	removeVMIdx := -1
	for i, c := range calls {
		if strings.Contains(c.scriptBlock, "Remove-VM") && !strings.Contains(c.scriptBlock, "Remove-VMNetworkAdapter") {
			removeVMIdx = i
		}
	}
	require.NotEqual(t, -1, removeVMIdx, "absent path must tear down the VM (Remove-VM)")
	assert.Less(t, removeVMIdx, seedDeleteIdx, "seed-media cleanup must run after the VM teardown")
}

// deleteSeedMediaCallIndex returns the index of the first psDeleteSeedMedia call
// whose Path argument equals wantPath, or -1 if none. The path travels via psArgs
// (recorded in winRMCall.args), never the scriptBlock text (S3).
func deleteSeedMediaCallIndex(calls []winRMCall, wantPath string) int {
	for i, c := range calls {
		if c.scriptBlock != psDeleteSeedMedia {
			continue
		}
		for _, a := range c.args {
			if s, ok := a.(string); ok && s == wantPath {
				return i
			}
		}
	}
	return -1
}

// TestExistenceGating_OwnIncompleteAttemptDoesNotAutoRetry proves surface-and-
// wait: when an own provisioning record exists at installing but the VM is
// absent from the host (mid-install / transiently not yet visible), the module
// must NOT re-issue New-VM — auto-retry is off by default (ADR-009 §2).
func TestExistenceGating_OwnIncompleteAttemptDoesNotAutoRetry(t *testing.T) {
	transport := &testWinRMTransport{
		output: `{"found":false}`, // host reports the VM absent
	}
	m := provisionModuleWithTransport(t, transport)
	require.NoError(t, m.provisionStore.SetProvision(context.Background(), &ProvisionRecord{
		VMName:        "stw-01",
		State:         ProvisionStateInstalling,
		CorrelationID: "stw-01",
		StartedAt:     time.Now(),
	}))

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, callsContaining(calls, "New-VM"),
		"an own in-progress provisioning attempt must surface-and-wait, not auto-retry New-VM")
	assert.Empty(t, callsContaining(calls, "New-VHD"),
		"no seed rebuild for an in-progress own attempt")

	// The record must remain at installing — surface-and-wait leaves it untouched.
	rec, err := m.provisionStore.GetProvision(context.Background(), "stw-01")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateInstalling, rec.State,
		"surface-and-wait must leave the in-progress record at installing")
}

// TestApplySourceGated_FailedSeedPhaseDoesNotStartVM is the [REQUIRED TEST] for
// the #2467/#3802 seed-phase gate's terminal state: an existing, powered-OFF VM
// whose own provisioning record failed during the host-side seed/create phase
// (Failed, FailedFrom=creating) AND has exhausted its bounded auto-retry budget
// (RetryCount == defaultSeedPhaseRetryMax) must be surfaced-and-waited-on: the
// module leaves the VM OFF, issues no Start-VM and no seed rebuild, rather than
// powering on a guest that has no working seed or retrying past its budget.
// applySourceGated (via Set) must return nil (surface-and-wait), not an error.
// This is the exact terminal state (RetryCount == 3 on a Failed/seed-phase
// record) the visibility sibling story's fixture checks.
func TestApplySourceGated_FailedSeedPhaseDoesNotStartVM(t *testing.T) {
	// getVM (call 0) reports the VM present but OFF; desired state is running
	// (sourceVMConfigMap sets state: running), so absent the gate the VM would be
	// started. Off is a healthy state (isHealthyVMState), so only the new gate —
	// not the degraded branch — can keep it off.
	transport := &testWinRMTransport{
		output: existingSourceVMJSON("stw-01", "Off"),
	}
	m := provisionModuleWithTransport(t, transport)

	// Seed the VM's own record as a seed-phase failure that has already used up
	// its bounded auto-retry budget: Failed, having failed from creating, at
	// RetryCount == defaultSeedPhaseRetryMax (3) — the original attempt plus 2
	// automatic repair retries, all failed.
	require.NoError(t, m.provisionStore.SetProvision(context.Background(), &ProvisionRecord{
		VMName:        "stw-01",
		State:         ProvisionStateFailed,
		FailedFrom:    ProvisionStateCreating,
		CorrelationID: "stw-01",
		StartedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		LastError:     `hyperv: create seed VHDX for VM "stw-01": exit status 1`,
		RetryCount:    defaultSeedPhaseRetryMax,
	}))

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")} // state: running, on_existing: never
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg),
		"a retry-exhausted seed-phase-failed VM must surface-and-wait (return nil), not error")

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, callsContaining(calls, "Start-VM"),
		"a VM whose seed phase failed must NOT be powered on (surface-and-wait)")
	assert.Empty(t, callsContaining(calls, "New-VM"),
		"surface-and-wait must not create or recreate the VM")
	assert.Empty(t, callsContaining(calls, "Remove-VM"),
		"surface-and-wait must never destroy the existing VM")
	assert.Empty(t, callsContaining(calls, "New-VHD"),
		"a retry-exhausted record must NOT trigger another seed-build attempt")

	// Surface-and-wait does not mutate the record — it is left at failed for an
	// operator (per the visibility sibling story) to retry from a clean seed.
	rec, err := m.provisionStore.GetProvision(context.Background(), "stw-01")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateFailed, rec.State)
	assert.Equal(t, ProvisionStateCreating, rec.FailedFrom)
	assert.Equal(t, defaultSeedPhaseRetryMax, rec.RetryCount,
		"retry-exhausted must not be incremented further")
}

// TestApplySourceGated_FailedSeedPhaseRetriesWithinBudget is the [REQUIRED
// TEST] for the #3802 bounded auto-retry itself: an existing, powered-OFF VM
// whose own provisioning record failed during the create/seed phase, with
// RetryCount below the budget, must have provisionVM RE-INVOKED on the next
// applySourceGated call — not just logged and left alone. This asserts the
// real seed-build PS calls happen again (New-VHD, Mount/Format, seed attach,
// install-ISO attach, Start-VM) and that RetryCount increments, proving a
// genuine re-invocation rather than a no-op return.
func TestApplySourceGated_FailedSeedPhaseRetriesWithinBudget(t *testing.T) {
	transport := &testWinRMTransport{
		output: existingSourceVMJSON("stw-01", "Off"),
	}
	m := provisionModuleWithTransport(t, transport)

	require.NoError(t, m.provisionStore.SetProvision(context.Background(), &ProvisionRecord{
		VMName:        "stw-01",
		State:         ProvisionStateFailed,
		FailedFrom:    ProvisionStateCreating,
		CorrelationID: "stw-01",
		StartedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		LastError:     `hyperv: create seed VHDX for VM "stw-01": exit status 1`,
		RetryCount:    1, // one prior failed attempt; still well within the default budget of 3
	}))

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")} // state: running, on_existing: never
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.NotEmpty(t, callsContaining(calls, "New-VHD"),
		"a retry within budget must rebuild the seed VHDX — a real re-invocation of provisionVM, not a no-op")
	assert.NotEmpty(t, callsContaining(calls, "Add-VMHardDiskDrive"),
		"a retry within budget must re-attach the rebuilt seed disk")
	assert.NotEmpty(t, callsContaining(calls, "Start-VM"),
		"a successful repair completes the create/seed phase and powers the VM on, same as a fresh attempt")
	assert.Empty(t, callsContaining(calls, "New-VM"),
		"the VM already exists on the host — retry must never call createVM")
	assert.Empty(t, callsContaining(calls, "Remove-VM"),
		"retry must never destroy the existing VM")

	rec, err := m.provisionStore.GetProvision(context.Background(), "stw-01")
	require.NoError(t, err)
	assert.Equal(t, 2, rec.RetryCount, "RetryCount must increment on the retry re-entry into creating")
	assert.Equal(t, ProvisionStateInstalling, rec.State,
		"a successful repair advances the record to installing, exactly like a fresh create-from-source attempt")
}

// TestApplySourceGated_DegradedVMNeverAutoRetried is the [REQUIRED TEST]
// guarding against #3802 accidentally widening scope: a VM surfaced as
// degraded (broken-but-not-seed-phase — isHealthyVMState false, no seed-phase
// failure record) must NEVER be auto-retried or auto-remediated. Only
// FailedFrom: creating/absent seed-phase failures are eligible for the bounded
// auto-retry added by this story; ADR-009 §2's degraded-class invariant
// (observed, never remediated) is untouched.
func TestApplySourceGated_DegradedVMNeverAutoRetried(t *testing.T) {
	transport := &testWinRMTransport{
		output: existingSourceVMJSON("stw-01", "Critical"),
	}
	m := provisionModuleWithTransport(t, transport)

	// The VM already carries a DEGRADED record from a prior convergence cycle
	// (not Failed, so failedDuringSeedPhase is false and the new retry gate
	// never even evaluates it).
	require.NoError(t, m.provisionStore.SetProvision(context.Background(), &ProvisionRecord{
		VMName:        "stw-01",
		State:         ProvisionStateDegraded,
		CorrelationID: "stw-01",
		StartedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		LastError:     "hyperv: VM in broken state: Critical",
	}))

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")}
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, callsContaining(calls, "New-VHD"),
		"a degraded (broken, non-seed-phase) VM must never trigger the seed-build auto-retry path")
	assert.Empty(t, callsContaining(calls, "Start-VM"),
		"a degraded VM must never be auto-started via the retry path")
	assert.Empty(t, callsContaining(calls, "Remove-VM"),
		"a degraded VM must never be torn down")
	assert.Empty(t, callsContaining(calls, "New-VM"),
		"a degraded VM must never be recreated")

	rec, err := m.provisionStore.GetProvision(context.Background(), "stw-01")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateDegraded, rec.State, "degraded stays degraded — never auto-remediated")
	assert.Equal(t, 0, rec.RetryCount, "RetryCount must not be touched by the degraded path")
}

// TestApplySourceGated_FailedAfterInstallingStillConverges is the companion
// [REQUIRED TEST] to the seed-phase gate: a Failed record that already passed
// through installing (FailedFrom=installing — a post-power-on failure class such
// as a controller-side completion timeout, completion/reconciler.go) must NOT
// hit the new gate. The existing, healthy-but-off VM keeps converging to its
// desired running state exactly as before (#2467 AC2 — no regression).
func TestApplySourceGated_FailedAfterInstallingStillConverges(t *testing.T) {
	transport := &testWinRMTransport{
		output: existingSourceVMJSON("stw-01", "Off"),
	}
	m := provisionModuleWithTransport(t, transport)

	require.NoError(t, m.provisionStore.SetProvision(context.Background(), &ProvisionRecord{
		VMName:        "stw-01",
		State:         ProvisionStateFailed,
		FailedFrom:    ProvisionStateInstalling, // failed AFTER the guest began installing
		CorrelationID: "stw-01",
		StartedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		LastError:     "completion.timeout elapsed",
	}))

	cfg := rawConfigState{m: sourceVMConfigMap(2, "linux")} // state: running
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", cfg))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.NotEmpty(t, callsContaining(calls, "Start-VM"),
		"a post-installing failure must keep converging: the off VM is started to its desired running state")
	assert.Empty(t, callsContaining(calls, "Remove-VM"),
		"convergence must still never destroy the existing VM")
}

// TestReconcile_DeleteRemovesSeedMedia guards the seed-media half of the #3168
// cleanup story. Hyper-V's Remove-VM deletes the VM object but NEVER its backing
// disks, so the module must delete the seed VHDX itself on state: absent —
// otherwise every provisioned-then-deleted VM leaves a seed file behind.
//
// This matters beyond disk usage: the live incident left seed VHDXs on all three
// lab hosts, and one of them was still ATTACHED to the host days after its VM was
// gone — which is what then failed the next VM's Add-VMHardDiskDrive. The
// try/finally fix removes the cause of the stuck mount; this test pins the
// deletion that stops the files accumulating in the first place.
func TestReconcile_DeleteRemovesSeedMedia(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{existingSourceVMJSON("stw-01", "Off")},
	}
	m := provisionModuleWithTransport(t, transport)

	cfgMap := cloudInitVMConfigMap(2)
	cfgMap["vhd_path"] = `C:\ClusterStorage\CSV01\stw-01.vhdx`
	cfgMap["state"] = "absent"
	require.NoError(t, m.Set(context.Background(), "vm:stw-01", rawConfigState{m: cfgMap}))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.NotEmpty(t, callsContaining(calls, "Remove-VM"),
		"state: absent must remove the VM object")
	assert.NotEmpty(t, callsContaining(calls, psDeleteSeedMedia),
		"deleting a VM must also delete its seed media — Remove-VM never deletes "+
			"backing disks, so the seed VHDX would otherwise be orphaned on the host")
}
