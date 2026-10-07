// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── #2411 declarative VM storage location ────────────────────────────────────
//
// The directory containing the declared vhd_path is the VM's home: creation
// places configuration files and VHD there; location drift on an existing VM
// converges via a live, non-destructive Move-VMStorage driven through an async
// MoveRecord in the durable store (the executor per-call deadline forbids a
// synchronous multi-minute migration).

// homeVMJSON builds getVM-shaped host JSON with an explicit disk path and
// configuration location, for storage-location drift scenarios.
func homeVMJSON(name, state, diskPath, configLocation string) string {
	hvState := "Off"
	if state == "running" {
		hvState = "Running"
	}
	return `{"found":true,"Name":"` + name + `","MemoryStartupBytes":1073741824,"ProcessorCount":2,"Generation":2,` +
		`"Path":"` + jsonEscapeBackslashes(diskPath) + `","ConfigurationLocation":"` + jsonEscapeBackslashes(configLocation) + `",` +
		`"SwitchName":"","SwitchNames":[],"State":"` + hvState + `"}`
}

func jsonEscapeBackslashes(s string) string {
	out := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			out = append(out, '\\', '\\')
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// callsByScript returns the indexes of recorded transport calls whose
// scriptBlock equals the given psXxx const.
func callsByScript(calls []winRMCall, script string) []int {
	var out []int
	for i, c := range calls {
		if c.scriptBlock == script {
			out = append(out, i)
		}
	}
	return out
}

// ─── vmHomeDir / path comparison ──────────────────────────────────────────────

func TestVMHomeDir(t *testing.T) {
	cases := map[string]string{
		`C:\VMs\a.vhdx`:                         `C:\VMs`,
		`C:\ClusterStorage\CSV01\vm1\vm1.vhdx`:  `C:\ClusterStorage\CSV01\vm1`,
		`C:/ClusterStorage/CSV01/vm1/disk.vhdx`: `C:/ClusterStorage/CSV01/vm1`,
		`no-separator.vhdx`:                     ``,
		``:                                      ``,
	}
	for in, want := range cases {
		assert.Equal(t, want, vmHomeDir(in), "vmHomeDir(%q)", in)
	}
}

func TestSameWindowsPath(t *testing.T) {
	assert.True(t, sameWindowsPath(`C:\VMs\vm1`, `c:\vms\vm1`), "case-insensitive")
	assert.True(t, sameWindowsPath(`C:\VMs\vm1\`, `C:\VMs\vm1`), "trailing separator")
	assert.True(t, sameWindowsPath(`C:/VMs/vm1`, `C:\VMs\vm1`), "mixed separators")
	assert.False(t, sameWindowsPath(`C:\VMs\vm1`, `C:\VMs\vm2`))
	assert.False(t, sameWindowsPath(``, `C:\VMs`), "empty never matches")
}

// ─── MoveStore CRUD ───────────────────────────────────────────────────────────

// TestMoveStore_CRUD exercises Get/Set/Delete/ErrMoveNotFound on the in-memory
// store, and confirms move records are independent of provision records.
func TestMoveStore_CRUD(t *testing.T) {
	ctx := context.Background()
	store := NewMemProvisionStore()

	_, err := store.GetMove(ctx, "vm1")
	require.ErrorIs(t, err, ErrMoveNotFound)

	rec := &MoveRecord{
		VMName:    "vm1",
		State:     MoveStateMoving,
		DestDir:   `C:\ClusterStorage\CSV01\vm1`,
		StartedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	require.NoError(t, store.SetMove(ctx, rec))

	got, err := store.GetMove(ctx, "vm1")
	require.NoError(t, err)
	assert.Equal(t, MoveStateMoving, got.State)
	assert.Equal(t, rec.DestDir, got.DestDir)

	// A move record must NOT satisfy a provision-record read for the same VM.
	_, err = store.GetProvision(ctx, "vm1")
	assert.ErrorIs(t, err, ErrProvisionNotFound,
		"move records must live in a separate keyspace from provision records")

	require.NoError(t, store.DeleteMove(ctx, "vm1"))
	_, err = store.GetMove(ctx, "vm1")
	require.ErrorIs(t, err, ErrMoveNotFound)

	// Deleting an absent record is reported, matching DeleteProvision.
	err = store.DeleteMove(ctx, "vm1")
	require.ErrorIs(t, err, ErrMoveNotFound)
}

// TestMoveStore_Durable_SurvivesReopen verifies the flatfile-backed store
// persists move records across a close/reopen — a move in flight across a
// steward restart must be re-observed, not re-dispatched blindly (#2371).
func TestMoveStore_Durable_SurvivesReopen(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	store1, err := NewFlatFileProvisionStore(root)
	require.NoError(t, err)
	ms1, ok := store1.(MoveStore)
	require.True(t, ok, "durable provision store must implement MoveStore")

	rec := &MoveRecord{
		VMName:    "vm-restart",
		State:     MoveStateMoving,
		DestDir:   `C:\ClusterStorage\CSV01\vm-restart`,
		StartedAt: time.Now().UTC().Truncate(time.Second),
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, ms1.SetMove(ctx, rec))

	store2, err := NewFlatFileProvisionStore(root)
	require.NoError(t, err)
	ms2 := store2.(MoveStore)
	got, err := ms2.GetMove(ctx, "vm-restart")
	require.NoError(t, err, "move record must survive a store reopen")
	assert.Equal(t, MoveStateMoving, got.State)
	assert.Equal(t, rec.DestDir, got.DestDir)
}

// ─── Create path: -Path + explicit home move ──────────────────────────────────

// TestCreateVM_PlacesConfigAtVHDHome is the [REQUIRED TEST] for the create
// path: a fresh VM is created with New-VM -Path <dir(vhd_path)> and its
// configuration files are then homed at exactly dir(vhd_path) (New-VM appends
// a VM-name subfolder to -Path, so an explicit config-only Move-VMStorage to
// the declared home follows — verified live on cfg-lab 2026-07-07).
func TestCreateVM_PlacesConfigAtVHDHome(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"found":false}`, // getVM: absent → create path
			"",                // New-VM
			"",                // Cfgms-SetVMHome
		},
	}
	m := vmModuleWithTransport(transport, "t")

	const home = `C:\ClusterStorage\CSV01\newvm`
	require.NoError(t, m.Set(context.Background(), "vm:newvm", mapConfigState{
		"name":      "newvm",
		"state":     "stopped",
		"memory_mb": 1024,
		"cpu_count": 2,
		"vhd_path":  home + `\newvm.vhdx`,
	}))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	createIdxs := callsByScript(calls, psCreateVM)
	require.Len(t, createIdxs, 1, "exactly one New-VM call")
	// psArgs keys sorted: CPU, Generation, MemoryMB, Name, Path, SwitchName, VHDPath
	createArgs := calls[createIdxs[0]].args
	assert.Contains(t, createArgs, home, "New-VM must receive -Path dir(vhd_path)")

	homeIdxs := callsByScript(calls, psSetVMHome)
	require.Len(t, homeIdxs, 1, "exactly one config-home move after create")
	assert.Greater(t, homeIdxs[0], createIdxs[0], "home move must follow New-VM")
	assert.Contains(t, calls[homeIdxs[0]].args, home,
		"config home move must target dir(vhd_path)")
}

// TestGetVM_ReportsConfigurationLocation: the observed state and the Get/DNA
// surface expose the VM's configuration-file location.
func TestGetVM_ReportsConfigurationLocation(t *testing.T) {
	const cfgLoc = `C:\VMs\vm7`
	transport := &testWinRMTransport{
		output: homeVMJSON("vm7", "running", `C:\VMs\vm7\vm7.vhdx`, cfgLoc),
	}
	m := vmModuleWithTransport(transport, "t")

	state, err := m.Get(context.Background(), "vm:vm7")
	require.NoError(t, err)
	got := state.AsMap()
	assert.Equal(t, cfgLoc, got["configuration_location"],
		"Get must expose the observed ConfigurationLocation")
}

// ─── Converge path: async live move ───────────────────────────────────────────

// TestLocationDrift_DispatchesExactlyOneMove is the [REQUIRED TEST] for the
// converge path: location drift on an existing VM runs the free-space
// preflight, dispatches Move-VMStorage exactly once, records an in-flight
// MoveRecord — and never stops, deletes, or recreates the VM.
func TestLocationDrift_DispatchesExactlyOneMove(t *testing.T) {
	const home = `C:\ClusterStorage\CSV01\mv1`
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			homeVMJSON("mv1", "running", `C:\VMs\mv1.vhdx`, `C:\VMs\mv1`), // getVM: local home
			`{"required_bytes":1073741824,"free_bytes":269386489856}`,     // preflight: plenty free
			"", // clear stale error marker
			"", // detached Move-VMStorage dispatch
		},
	}
	m := vmModuleWithTransport(transport, "t")

	require.NoError(t, m.Set(context.Background(), "vm:mv1", mapConfigState{
		"name":      "mv1",
		"state":     "running",
		"memory_mb": 1024,
		"cpu_count": 2,
		"vhd_path":  home + `\mv1.vhdx`,
	}))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	moveIdxs := callsByScript(calls, psMoveVMStorage)
	require.Len(t, moveIdxs, 1, "exactly one Move-VMStorage dispatch")
	moveArgs := calls[moveIdxs[0]].args
	assert.Contains(t, moveArgs, home,
		"move must target the declared home (disks follow at home\\<current leaf>)")

	preIdxs := callsByScript(calls, psVMStorageMovePreflight)
	require.Len(t, preIdxs, 1, "free-space preflight must run before dispatch")
	assert.Less(t, preIdxs[0], moveIdxs[0])

	clearIdxs := callsByScript(calls, psClearVMMoveError)
	require.Len(t, clearIdxs, 1, "stale error marker must be cleared before dispatch")
	assert.Less(t, clearIdxs[0], moveIdxs[0])

	for _, c := range calls {
		assert.NotContains(t, c.scriptBlock, "Remove-VM", "the VM must never be deleted by the move path")
		assert.NotContains(t, c.scriptBlock, "Stop-VM", "the VM must never be stopped by the move path")
	}

	rec, err := m.moveStore().GetMove(context.Background(), "mv1")
	require.NoError(t, err, "an in-flight MoveRecord must exist after dispatch")
	assert.Equal(t, MoveStateMoving, rec.State)
	assert.Equal(t, home, rec.DestDir)
}

// TestLocationDrift_InFlightMoveIsNoOp is the [REQUIRED TEST] idempotency
// half: a converge that observes an in-flight record does NOT dispatch a
// second move — the cycle is a cheap no-op (getVM + error probe only).
func TestLocationDrift_InFlightMoveIsNoOp(t *testing.T) {
	const home = `C:\ClusterStorage\CSV01\mv2`
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			homeVMJSON("mv2", "running", `C:\VMs\mv2.vhdx`, `C:\VMs\mv2`), // still at old location
			`{"error":""}`, // no failure surfaced by the detached move
		},
	}
	m := vmModuleWithTransport(transport, "t")
	require.NoError(t, m.moveStore().SetMove(context.Background(), &MoveRecord{
		VMName:    "mv2",
		State:     MoveStateMoving,
		DestDir:   home,
		StartedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))

	require.NoError(t, m.Set(context.Background(), "vm:mv2", mapConfigState{
		"name":      "mv2",
		"state":     "running",
		"memory_mb": 1024,
		"cpu_count": 2,
		"vhd_path":  home + `\mv2.vhdx`,
	}))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	assert.Empty(t, callsByScript(calls, psMoveVMStorage), "no duplicate Move-VMStorage dispatch")
	assert.Empty(t, callsByScript(calls, psVMStorageMovePreflight), "no re-preflight while in flight")
	require.Len(t, calls, 2, "in-flight cycle must be cheap: getVM + error probe only")

	rec, err := m.moveStore().GetMove(context.Background(), "mv2")
	require.NoError(t, err)
	assert.Equal(t, MoveStateMoving, rec.State, "record stays in flight")
}

// TestLocationDrift_CompletionClearsRecord: when the observed location matches
// the declared home, the in-flight record completes (is removed) and the
// normal lifecycle proceeds.
func TestLocationDrift_CompletionClearsRecord(t *testing.T) {
	const home = `C:\ClusterStorage\CSV01\mv3`
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			homeVMJSON("mv3", "running", home+`\mv3.vhdx`, home), // converged
		},
	}
	m := vmModuleWithTransport(transport, "t")
	require.NoError(t, m.moveStore().SetMove(context.Background(), &MoveRecord{
		VMName:    "mv3",
		State:     MoveStateMoving,
		DestDir:   home,
		StartedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))

	require.NoError(t, m.Set(context.Background(), "vm:mv3", mapConfigState{
		"name":      "mv3",
		"state":     "running",
		"memory_mb": 1024,
		"cpu_count": 2,
		"vhd_path":  home + `\mv3.vhdx`,
	}))

	_, err := m.moveStore().GetMove(context.Background(), "mv3")
	assert.ErrorIs(t, err, ErrMoveNotFound, "completed move record must be cleared")

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()
	assert.Empty(t, callsByScript(calls, psMoveVMStorage), "no move dispatch when converged")
}

// TestMovePreflight_InsufficientSpace is the [REQUIRED TEST] safety half:
// insufficient destination space fails the move BEFORE dispatch, loudly, on
// the record.
func TestMovePreflight_InsufficientSpace(t *testing.T) {
	const home = `C:\ClusterStorage\CSV01\mv4`
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			homeVMJSON("mv4", "running", `C:\VMs\mv4.vhdx`, `C:\VMs\mv4`),
			`{"required_bytes":1073741824,"free_bytes":1024}`, // destination nearly full
		},
	}
	m := vmModuleWithTransport(transport, "t")

	err := m.Set(context.Background(), "vm:mv4", mapConfigState{
		"name":      "mv4",
		"state":     "running",
		"memory_mb": 1024,
		"cpu_count": 2,
		"vhd_path":  home + `\mv4.vhdx`,
	})
	require.Error(t, err, "preflight failure must surface loudly")
	assert.Contains(t, err.Error(), "insufficient")

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()
	assert.Empty(t, callsByScript(calls, psMoveVMStorage),
		"Move-VMStorage must NOT be dispatched when the preflight fails")

	rec, recErr := m.moveStore().GetMove(context.Background(), "mv4")
	require.NoError(t, recErr, "the failure must be recorded")
	assert.Equal(t, MoveStateFailed, rec.State)
	assert.Contains(t, rec.LastError, "insufficient")
}

// TestMoveFailure_SurfacesOnRecord is the [REQUIRED TEST] failure half: a
// dispatched-move failure (surfaced by the detached process's error marker)
// flips the record to failed with the error, and Set returns the error.
func TestMoveFailure_SurfacesOnRecord(t *testing.T) {
	const home = `C:\ClusterStorage\CSV01\mv5`
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			homeVMJSON("mv5", "running", `C:\VMs\mv5.vhdx`, `C:\VMs\mv5`), // still at source
			`{"error":"Move-VMStorage : migration failed"}`,               // error marker
		},
	}
	m := vmModuleWithTransport(transport, "t")
	require.NoError(t, m.moveStore().SetMove(context.Background(), &MoveRecord{
		VMName:    "mv5",
		State:     MoveStateMoving,
		DestDir:   home,
		StartedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))

	err := m.Set(context.Background(), "vm:mv5", mapConfigState{
		"name":      "mv5",
		"state":     "running",
		"memory_mb": 1024,
		"cpu_count": 2,
		"vhd_path":  home + `\mv5.vhdx`,
	})
	require.Error(t, err, "a failed move must surface loudly")
	assert.Contains(t, err.Error(), "migration failed")

	rec, recErr := m.moveStore().GetMove(context.Background(), "mv5")
	require.NoError(t, recErr)
	assert.Equal(t, MoveStateFailed, rec.State)
	assert.Contains(t, rec.LastError, "migration failed")
}

// TestMoveFailure_NextConvergeRetriesOnce: a failed record retries — exactly
// one new dispatch on the next converge cycle (bounded retry).
func TestMoveFailure_NextConvergeRetriesOnce(t *testing.T) {
	const home = `C:\ClusterStorage\CSV01\mv6`
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			homeVMJSON("mv6", "running", `C:\VMs\mv6.vhdx`, `C:\VMs\mv6`),
			`{"required_bytes":1073741824,"free_bytes":269386489856}`,
			"", // clear error marker
			"", // Move-VMStorage retry dispatch
		},
	}
	m := vmModuleWithTransport(transport, "t")
	require.NoError(t, m.moveStore().SetMove(context.Background(), &MoveRecord{
		VMName:    "mv6",
		State:     MoveStateFailed,
		DestDir:   home,
		StartedAt: time.Now().UTC().Add(-time.Hour),
		UpdatedAt: time.Now().UTC().Add(-time.Hour),
		LastError: "previous attempt failed",
	}))

	require.NoError(t, m.Set(context.Background(), "vm:mv6", mapConfigState{
		"name":      "mv6",
		"state":     "running",
		"memory_mb": 1024,
		"cpu_count": 2,
		"vhd_path":  home + `\mv6.vhdx`,
	}))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()
	require.Len(t, callsByScript(calls, psMoveVMStorage), 1,
		"exactly one retry dispatch per converge cycle")

	rec, err := m.moveStore().GetMove(context.Background(), "mv6")
	require.NoError(t, err)
	assert.Equal(t, MoveStateMoving, rec.State, "retry returns the record to in-flight")
	assert.Empty(t, rec.LastError, "retry clears the previous error")
}

// TestMoveStalled_FailsRecord: an in-flight record older than the stall bound
// with no observable completion and no error marker is failed loudly (covers a
// move interrupted by a host reboot, where the detached process left no error).
func TestMoveStalled_FailsRecord(t *testing.T) {
	const home = `C:\ClusterStorage\CSV01\mv7`
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			homeVMJSON("mv7", "running", `C:\VMs\mv7.vhdx`, `C:\VMs\mv7`),
			`{"error":""}`, // no error marker — the move just never completed
		},
	}
	m := vmModuleWithTransport(transport, "t")
	require.NoError(t, m.moveStore().SetMove(context.Background(), &MoveRecord{
		VMName:    "mv7",
		State:     MoveStateMoving,
		DestDir:   home,
		StartedAt: time.Now().UTC().Add(-moveStallTimeout - time.Minute),
		UpdatedAt: time.Now().UTC().Add(-moveStallTimeout - time.Minute),
	}))

	err := m.Set(context.Background(), "vm:mv7", mapConfigState{
		"name":      "mv7",
		"state":     "running",
		"memory_mb": 1024,
		"cpu_count": 2,
		"vhd_path":  home + `\mv7.vhdx`,
	})
	require.Error(t, err, "a stalled move must surface loudly")

	rec, recErr := m.moveStore().GetMove(context.Background(), "mv7")
	require.NoError(t, recErr)
	assert.Equal(t, MoveStateFailed, rec.State)
}

// TestSetVM_Absent_DeletesMoveRecord: deleting a VM clears any move record so
// a later same-named VM starts clean (mirrors the provision-record cleanup).
func TestSetVM_Absent_DeletesMoveRecord(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			homeVMJSON("mv8", "running", `C:\VMs\mv8.vhdx`, `C:\VMs\mv8`), // before-snapshot
			"", // Remove-VM
		},
	}
	m := vmModuleWithTransport(transport, "t")
	require.NoError(t, m.moveStore().SetMove(context.Background(), &MoveRecord{
		VMName:    "mv8",
		State:     MoveStateMoving,
		DestDir:   `C:\ClusterStorage\CSV01\mv8`,
		StartedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))

	require.NoError(t, m.Set(context.Background(), "vm:mv8", mapConfigState{
		"name":  "mv8",
		"state": "absent",
	}))

	_, err := m.moveStore().GetMove(context.Background(), "mv8")
	assert.ErrorIs(t, err, ErrMoveNotFound, "VM deletion must clear the move record")
}

// TestNoLocationDrift_NoMoveMachinery: a VM whose config and disk already sit
// at the declared home runs the plain lifecycle with zero storage-location
// calls (no probe, no preflight, no dispatch).
func TestNoLocationDrift_NoMoveMachinery(t *testing.T) {
	const home = `C:\ClusterStorage\CSV01\mv9`
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			homeVMJSON("mv9", "running", home+`\mv9.vhdx`, home),
		},
	}
	m := vmModuleWithTransport(transport, "t")

	require.NoError(t, m.Set(context.Background(), "vm:mv9", mapConfigState{
		"name":      "mv9",
		"state":     "running",
		"memory_mb": 1024,
		"cpu_count": 2,
		"vhd_path":  home + `\mv9.vhdx`,
	}))

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()
	require.Len(t, calls, 1, "converged VM: getVM only — no storage-location machinery")
}
