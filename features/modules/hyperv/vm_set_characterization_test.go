// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package hyperv

import (
	"context"
	"errors"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Characterization tests for setVM, applyVMState and applySourceGated (Issue
// #5821). They pin the observable behavior (transport call order, recorded
// per-VM state, early returns) so the complexity refactor of those functions
// is provably behavior-preserving.

// vmsetCharIdx returns the index of the first recorded call that used the given
// psCommand const, or -1.
func vmsetCharIdx(tr *testPSTransport, psCommand string) int {
	for i, sb := range scriptBlocks(tr) {
		if sb == psCommand {
			return i
		}
	}
	return -1
}

// vmsetCharCallCount returns the number of recorded transport calls.
func vmsetCharCallCount(tr *testPSTransport) int {
	return len(scriptBlocks(tr))
}

func TestVmsetChar_Set_NilTransport(t *testing.T) {
	m := vmModuleWithTransport(nil, "t")
	m.transport = nil
	err := m.setVM(context.Background(), "vm:a", mapConfigState{"state": "running"})
	assert.ErrorIs(t, err, modules.ErrNotImplemented)
}

func TestVmsetChar_Set_MalformedResourceID(t *testing.T) {
	transport := &testPSTransport{}
	m := vmModuleWithTransport(transport, "t")
	err := m.setVM(context.Background(), "no-colon", mapConfigState{"state": "running"})
	assert.ErrorIs(t, err, modules.ErrNotImplemented)
	assert.Equal(t, 0, vmsetCharCallCount(transport), "a malformed resource id must not reach the transport")
}

func TestVmsetChar_Set_RecordsKeyedCheckpointAndVHDPath(t *testing.T) {
	transport := &testPSTransport{perCallOutputs: []string{
		hostVMJSON("vm-a", "running", 2, 4096),
		hostVMJSON("vm-b", "running", 2, 4096),
	}}
	m := vmModuleWithTransport(transport, "t")
	cp := map[string]interface{}{"mode": "disabled"}

	require.NoError(t, m.setVM(context.Background(), "vm:vm-a", mapConfigState{
		"state": "running", "cpu_count": 2, "memory_mb": 4096,
		"vhd_path": `C:\VMs\a.vhdx`, "checkpoints": cp,
	}))
	// vm-b declares no vhd_path and no checkpoints.
	require.NoError(t, m.setVM(context.Background(), "vm:vm-b", mapConfigState{
		"state": "running", "cpu_count": 2, "memory_mb": 4096,
	}))

	m.checkpointDesiredMu.Lock()
	defer m.checkpointDesiredMu.Unlock()
	assert.Equal(t, cp, m.checkpointDesired["vm-a"])
	val, present := m.checkpointDesired["vm-b"]
	assert.True(t, present, "checkpoint record is keyed per VM even when nothing is authored")
	assert.Nil(t, val)

	m.vhdPathDesiredMu.Lock()
	defer m.vhdPathDesiredMu.Unlock()
	assert.Equal(t, `C:\VMs\a.vhdx`, m.vhdPathDesired["vm-a"])
	_, bPresent := m.vhdPathDesired["vm-b"]
	assert.False(t, bPresent, "an unset vhd_path is not recorded")
}

func TestVmsetChar_Set_ValidateFailsBeforeTransport(t *testing.T) {
	transport := &testPSTransport{}
	m := vmModuleWithTransport(transport, "t")
	err := m.setVM(context.Background(), "vm:bad;name", mapConfigState{"state": "running"})
	require.Error(t, err)
	assert.Equal(t, 0, vmsetCharCallCount(transport))
}

func TestVmsetChar_Set_ExistenceCheckErrorWrapped(t *testing.T) {
	transport := &testPSTransport{execErr: errors.New("transport down")}
	m := vmModuleWithTransport(transport, "t")
	err := m.setVM(context.Background(), "vm:vm-a", mapConfigState{"state": "running"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `check VM "vm-a" existence`)
}

func TestVmsetChar_Set_DeleteFlowOrder(t *testing.T) {
	const vhd = `C:\ClusterStorage\CSV01\stw-01.vhdx`
	transport := &testPSTransport{output: existingSourceVMJSON("stw-01", "Running")}
	m := provisionModuleWithTransport(t, transport)
	ctx := context.Background()
	// A provisioning record that the delete flow must remove.
	_, err := m.loadOrInitProvision(ctx, &VMConfig{Name: "stw-01"}, "stw-01")
	require.NoError(t, err)

	require.NoError(t, m.setVM(ctx, "vm:stw-01", mapConfigState{"state": "absent"}))

	calls := transport.calls
	removeIdx := -1
	for i, c := range calls {
		if c.scriptBlock == psRemoveVM {
			removeIdx = i
		}
	}
	seedIdx := deleteSeedMediaCallIndex(calls, seedVHDPath("stw-01", vhd, ""))
	require.NotEqual(t, -1, removeIdx, "Remove-VM must run")
	require.NotEqual(t, -1, seedIdx, "seed media must be swept using the observed vhd path")
	assert.Less(t, removeIdx, seedIdx, "seed sweep follows the VM removal")

	_, getErr := m.provisionStore.GetProvision(ctx, "stw-01")
	assert.ErrorIs(t, getErr, ErrProvisionNotFound, "the provisioning record is deleted by the delete flow")
}

func TestVmsetChar_Set_DeleteFlowRemoveErrorStopsBeforeCleanup(t *testing.T) {
	// call 0 getVM ok; call 1 Remove-VM fails.
	transport := &testPSTransport{
		perCallOutputs: []string{existingSourceVMJSON("stw-01", "Running")},
		perCallErrors:  []error{nil, errors.New("remove failed")},
	}
	m := provisionModuleWithTransport(t, transport)
	err := m.setVM(context.Background(), "vm:stw-01", mapConfigState{"state": "absent"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remove VM")
	assert.Equal(t, 2, vmsetCharCallCount(transport), "no seed sweep after a failed Remove-VM")
}

func TestVmsetChar_Set_ExistingVMConvergesAndRecordsNothingExtra(t *testing.T) {
	transport := &testPSTransport{perCallOutputs: []string{hostVMJSON("vm-a", "stopped", 2, 4096)}}
	m := vmModuleWithTransport(transport, "t")
	require.NoError(t, m.setVM(context.Background(), "vm:vm-a", mapConfigState{
		"state": "running", "cpu_count": 2, "memory_mb": 4096,
	}))
	assert.Equal(t, 1, countCmd(transport, psStartVM))
	assert.Equal(t, 0, countCmd(transport, psCreateVM), "an existing VM is never created")
}

func TestVmsetChar_Set_MissingVMIsCreatedThenStarted(t *testing.T) {
	transport := &testPSTransport{perCallOutputs: []string{`{"found":false}`}}
	m := vmModuleWithTransport(transport, "t")
	require.NoError(t, m.setVM(context.Background(), "vm:vm-new", mapConfigState{
		"state": "running", "cpu_count": 2, "memory_mb": 4096, "vhd_path": `C:\VMs\new.vhdx`,
	}))
	newIdx, startIdx := vmsetCharIdx(transport, psCreateVM), vmsetCharIdx(transport, psStartVM)
	require.NotEqual(t, -1, newIdx)
	require.NotEqual(t, -1, startIdx)
	assert.Less(t, newIdx, startIdx, "create precedes start")
	m.vmsMu.Lock()
	defer m.vmsMu.Unlock()
	assert.Contains(t, m.vms, "vm-new", "write-through cache updated on create")
}

func TestVmsetChar_Set_MissingVMStoppedIsNotStarted(t *testing.T) {
	transport := &testPSTransport{perCallOutputs: []string{`{"found":false}`}}
	m := vmModuleWithTransport(transport, "t")
	require.NoError(t, m.setVM(context.Background(), "vm:vm-new", mapConfigState{
		"state": "stopped", "cpu_count": 2, "memory_mb": 4096, "vhd_path": `C:\VMs\new.vhdx`,
	}))
	assert.Equal(t, 1, countCmd(transport, psCreateVM))
	assert.Equal(t, 0, countCmd(transport, psStartVM))
}

// ─── applySourceGated ──────────────────────────────────────────────────────────

func TestVmsetChar_SourceGated_NonRecreateNeverRemovesExistingVM(t *testing.T) {
	for _, onExisting := range []string{"", "never", "ignore", "Recreate", "something-else"} {
		invalid := onExisting != "" && onExisting != "never"
		t.Run("on_existing="+onExisting, func(t *testing.T) {
			transport := &testPSTransport{output: existingSourceVMJSON("stw-01", "Running")}
			m := provisionModuleWithTransport(t, transport)
			configMap := sourceVMConfigMap(2, "linux")
			if onExisting != "" {
				configMap["source"].(map[string]interface{})["on_existing"] = onExisting
			}
			err := m.setVM(context.Background(), "vm:stw-01", rawConfigState{m: configMap})
			if invalid {
				require.Error(t, err, "an unrecognised on_existing is rejected by validation")
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, 0, countCmd(transport, psRemoveVM), "an existing VM is never removed unless on_existing is recreate")
			assert.Equal(t, 0, countCmd(transport, psCreateVM))
		})
	}
}

func TestVmsetChar_SourceGated_AbsentVMProvisionsAndCaches(t *testing.T) {
	transport := &testPSTransport{perCallOutputs: []string{`{"found":false}`}}
	m := provisionModuleWithTransport(t, transport)
	err := m.setVM(context.Background(), "vm:stw-01", rawConfigState{m: sourceVMConfigMap(2, "linux")})
	require.NoError(t, err)
	m.vmsMu.Lock()
	cached, ok := m.vms["stw-01"]
	m.vmsMu.Unlock()
	rec, recErr := m.provisionStore.GetProvision(context.Background(), "stw-01")
	require.True(t, ok, "write-through cache updated on create")
	assert.Equal(t, "stw-01", cached.Name)
	assert.Equal(t, "running", cached.State)
	require.NoError(t, recErr, "a provisioning record is persisted for the created VM")
	assert.Equal(t, ProvisionStateInstalling, rec.State)
	assert.Equal(t, 1, countCmd(transport, psCreateVM), "an absent VM is created from source")
	assert.Equal(t, 0, countCmd(transport, psRemoveVM))
}

func TestVmsetChar_SourceGated_AbsentCreateErrorPropagates(t *testing.T) {
	transport := &testPSTransport{
		perCallOutputs: []string{`{"found":false}`},
		execErr:        errors.New("boom"),
		perCallErrors:  []error{nil},
	}
	m := provisionModuleWithTransport(t, transport)
	err := m.setVM(context.Background(), "vm:stw-01", rawConfigState{m: sourceVMConfigMap(2, "linux")})
	require.Error(t, err)
}

func TestVmsetChar_SourceGated_BrokenVMDegradedNotDestroyed(t *testing.T) {
	transport := &testPSTransport{output: existingSourceVMJSON("stw-01", "Critical")}
	m := provisionModuleWithTransport(t, transport)
	require.NoError(t, m.setVM(context.Background(), "vm:stw-01", rawConfigState{m: sourceVMConfigMap(2, "linux")}))
	rec, err := m.provisionStore.GetProvision(context.Background(), "stw-01")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateDegraded, rec.State)
	assert.Equal(t, 0, countCmd(transport, psRemoveVM))
	assert.Equal(t, 0, countCmd(transport, psStartVM), "a degraded VM gets no lifecycle convergence")
}

// ─── applyVMState ──────────────────────────────────────────────────────────────

func vmsetCharPlainModule(transport *testPSTransport) *hypervModule {
	return vmModuleWithTransport(transport, "t-5821")
}

func TestVmsetChar_ApplyVMState_OwnerProbeErrorReturnsQuietly(t *testing.T) {
	transport := &testPSTransport{perCallErrors: []error{errors.New("cluster hiccup")}}
	m := vmsetCharPlainModule(transport)
	m.nodeHostname = "NODE1"
	desired := &VMConfig{Name: "ha-vm", CPUCount: 4, MemoryMB: 8192, HARole: &HARoleConfig{ClusterName: "lab-hv"}}
	current := &VMConfig{Name: "ha-vm", CPUCount: 2, MemoryMB: 4096, State: "stopped"}

	require.NoError(t, m.applyVMState(context.Background(), "ha-vm", "ha-vm", desired, current, "running"))
	assert.Equal(t, 1, vmsetCharCallCount(transport), "only the failed probe; no lifecycle action")
}

func TestVmsetChar_ApplyVMState_ScopeCapMismatchFailsLoud(t *testing.T) {
	transport := &testPSTransport{}
	m := vmsetCharPlainModule(transport)
	m.clusterName = "declared"
	desired := &VMConfig{Name: "ha-vm", HARole: &HARoleConfig{ClusterName: "other"}}
	err := m.applyVMState(context.Background(), "ha-vm", "ha-vm", desired, &VMConfig{Name: "ha-vm"}, "running")
	assert.ErrorIs(t, err, ErrClusterNotDeclared)
	assert.Equal(t, 0, vmsetCharCallCount(transport))
}

func TestVmsetChar_ApplyVMState_Demote(t *testing.T) {
	transport := &testPSTransport{perCallOutputs: []string{
		`{"owner":"NODE1"}`,                    // ownership helper: CNO owner
		`{"owners":{"vm-d":"NODE1"}}`,          // ownership helper: role owners
		hostVMJSON("vm-d", "running", 2, 4096), // host-ownership probe: this node hosts the VM
		``,                                     // Remove-ClusterResource
	}}
	m := vmsetCharPlainModule(transport)
	m.nodeHostname = "NODE1"
	desired := &VMConfig{Name: "vm-d", CPUCount: 2, MemoryMB: 4096}
	current := &VMConfig{Name: "vm-d", CPUCount: 2, MemoryMB: 4096, State: "running", HARole: &HARoleConfig{ClusterName: "lab-hv"}}
	err := m.applyVMState(context.Background(), "vm-d", "vm-d", desired, current, "running")
	require.NoError(t, err)
	assert.Equal(t, 1, countCmd(transport, psRemoveClusterResource), "demote removes the clustered role")
	assert.Equal(t, 0, countCmd(transport, psAddClusterVMRole), "demote never registers a role")
	assert.Equal(t, 0, countCmd(transport, psRemoveVM), "demote never removes the VM")
	assert.Equal(t, 4, vmsetCharCallCount(transport), "demote returns after the role removal")
	assert.Equal(t, 0, countCmd(transport, psStartVM)+countCmd(transport, psStopVM), "demote runs no power action")
}

func TestVmsetChar_ApplyVMState_PowerAndResizeMatrix(t *testing.T) {
	cases := []struct {
		name                          string
		state, curState               string
		desCPU, curCPU                int
		desMem, curMem                int64
		stops, starts, cpus, mems     int
		stopBeforeCPU, startAfterResz bool
		wantCache                     string
	}{
		{name: "running_noop", state: "running", curState: "running", desCPU: 2, curCPU: 2, desMem: 4096, curMem: 4096, wantCache: "running"},
		{name: "running_start_only", state: "running", curState: "stopped", desCPU: 2, curCPU: 2, desMem: 4096, curMem: 4096, starts: 1, wantCache: "running"},
		{name: "running_resize_cpu_from_running", state: "running", curState: "running", desCPU: 4, curCPU: 2, desMem: 4096, curMem: 4096, stops: 1, starts: 1, cpus: 1, stopBeforeCPU: true, startAfterResz: true, wantCache: "running"},
		{name: "running_resize_both_from_stopped", state: "running", curState: "stopped", desCPU: 4, curCPU: 2, desMem: 8192, curMem: 4096, starts: 1, cpus: 1, mems: 1, startAfterResz: true, wantCache: "running"},
		{name: "running_resize_mem_only", state: "running", curState: "running", desCPU: 2, curCPU: 2, desMem: 8192, curMem: 4096, stops: 1, starts: 1, mems: 1, wantCache: "running"},
		{name: "running_zero_desired_means_no_resize", state: "running", curState: "running", desCPU: 0, curCPU: 2, desMem: 0, curMem: 4096, wantCache: "running"},
		{name: "stopped_noop", state: "stopped", curState: "stopped", desCPU: 2, curCPU: 2, desMem: 4096, curMem: 4096, wantCache: "stopped"},
		{name: "stopped_stop_only", state: "stopped", curState: "running", desCPU: 2, curCPU: 2, desMem: 4096, curMem: 4096, stops: 1, wantCache: "stopped"},
		{name: "stopped_resize_both", state: "stopped", curState: "running", desCPU: 4, curCPU: 2, desMem: 8192, curMem: 4096, stops: 1, cpus: 1, mems: 1, wantCache: "stopped"},
		{name: "other_state_no_power_action", state: "", curState: "running", desCPU: 4, curCPU: 2, desMem: 4096, curMem: 4096},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			transport := &testPSTransport{}
			m := vmsetCharPlainModule(transport)
			desired := &VMConfig{Name: "vm-p", CPUCount: tc.desCPU, MemoryMB: tc.desMem}
			current := &VMConfig{Name: "vm-p", CPUCount: tc.curCPU, MemoryMB: tc.curMem, State: tc.curState}

			require.NoError(t, m.applyVMState(context.Background(), "vm-p", "vm-p", desired, current, tc.state))

			assert.Equal(t, tc.stops, countCmd(transport, psStopVM), "Stop-VM count")
			assert.Equal(t, tc.starts, countCmd(transport, psStartVM), "Start-VM count")
			assert.Equal(t, tc.cpus, countCmd(transport, psSetVMProcessor), "Set-VMProcessor count")
			assert.Equal(t, tc.mems, countCmd(transport, psSetVMMemory), "Set-VMMemory count")
			if tc.stopBeforeCPU {
				assert.Less(t, vmsetCharIdx(transport, psStopVM), vmsetCharIdx(transport, psSetVMProcessor))
			}
			if tc.startAfterResz {
				assert.Greater(t, vmsetCharIdx(transport, psStartVM), vmsetCharIdx(transport, psSetVMProcessor))
			}
			m.vmsMu.Lock()
			cached, ok := m.vms["vm-p"]
			m.vmsMu.Unlock()
			if tc.wantCache == "" {
				assert.False(t, ok, "no cache write for an unrecognised state")
			} else {
				require.True(t, ok)
				assert.Equal(t, tc.wantCache, cached.State)
			}
		})
	}
}

func TestVmsetChar_ApplyVMState_StepErrorsPropagateAndStop(t *testing.T) {
	boom := errors.New("ps failed")
	cases := []struct {
		name             string
		state, curState  string
		desCPU, desMem   int
		failCall         int
		wantCalls        int
		wantErrSubstring string
	}{
		{"running_stop_fails", "running", "running", 4, 4096, 0, 1, "Stop-VM"},
		{"running_cpu_fails", "running", "stopped", 4, 4096, 0, 1, "Set-VMProcessor"},
		{"running_mem_fails", "running", "stopped", 2, 8192, 0, 1, "Set-VMMemory"},
		{"running_start_after_resize_fails", "running", "stopped", 4, 4096, 1, 2, "Start-VM"},
		{"running_start_fails", "running", "stopped", 2, 4096, 0, 1, "Start-VM"},
		{"stopped_stop_fails", "stopped", "running", 2, 4096, 0, 1, "Stop-VM"},
		{"stopped_cpu_fails", "stopped", "stopped", 4, 4096, 0, 1, "Set-VMProcessor"},
		{"stopped_mem_fails", "stopped", "stopped", 2, 8192, 0, 1, "Set-VMMemory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := make([]error, tc.failCall+1)
			errs[tc.failCall] = boom
			transport := &testPSTransport{perCallErrors: errs}
			m := vmsetCharPlainModule(transport)
			desired := &VMConfig{Name: "vm-e", CPUCount: tc.desCPU, MemoryMB: int64(tc.desMem)}
			current := &VMConfig{Name: "vm-e", CPUCount: 2, MemoryMB: 4096, State: tc.curState}
			err := m.applyVMState(context.Background(), "vm-e", "vm-e", desired, current, tc.state)
			require.ErrorIs(t, err, boom)
			assert.Contains(t, err.Error(), tc.wantErrSubstring)
			assert.Equal(t, tc.wantCalls, vmsetCharCallCount(transport), "later steps must not run after a failure")
			m.vmsMu.Lock()
			_, cached := m.vms["vm-e"]
			m.vmsMu.Unlock()
			assert.False(t, cached, "no cache write on failure")
		})
	}
}

func TestVmsetChar_ApplyVMState_NetworkReconcileRunsBeforePower(t *testing.T) {
	transport := &testPSTransport{}
	m := vmsetCharPlainModule(transport)
	desired := &VMConfig{Name: "vm-n", CPUCount: 2, MemoryMB: 4096, SwitchName: "sw-new"}
	desired.normalizeSwitches()
	current := &VMConfig{Name: "vm-n", CPUCount: 2, MemoryMB: 4096, State: "stopped", SwitchName: "sw-old"}
	current.normalizeSwitches()

	require.NoError(t, m.applyVMState(context.Background(), "vm-n", "vm-n", desired, current, "running"))

	connect, disconnect, start := vmsetCharIdx(transport, psConnectVMNic), vmsetCharIdx(transport, psDisconnectVMNic), vmsetCharIdx(transport, psStartVM)
	require.NotEqual(t, -1, connect)
	require.NotEqual(t, -1, disconnect)
	require.NotEqual(t, -1, start)
	assert.Less(t, connect, start)
	assert.Less(t, disconnect, start)
	assert.Equal(t, []string{"sw-new"}, []string(current.SwitchNames), "current reflects the converged switch set")
}

func TestVmsetChar_ApplyVMState_NetworkErrorStopsBeforePower(t *testing.T) {
	boom := errors.New("nic failed")
	transport := &testPSTransport{perCallErrors: []error{boom}}
	m := vmsetCharPlainModule(transport)
	desired := &VMConfig{Name: "vm-n", SwitchName: "sw-new"}
	desired.normalizeSwitches()
	current := &VMConfig{Name: "vm-n", State: "stopped"}
	err := m.applyVMState(context.Background(), "vm-n", "vm-n", desired, current, "running")
	require.ErrorIs(t, err, boom)
	assert.Equal(t, 0, countCmd(transport, psStartVM))
}
