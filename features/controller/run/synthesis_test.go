// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package run

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	scriptmodule "github.com/cfgis/cfgms/features/modules/script"
)

// staticFleetQuery is a real FleetQuery implementation that returns a fixed set
// of StewardResults. Used in synthesis tests to avoid mocks.
type staticFleetQuery struct {
	results []fleet.StewardResult
}

func (q *staticFleetQuery) Search(_ context.Context, _ fleet.Filter) ([]fleet.StewardResult, error) {
	return q.results, nil
}

func (q *staticFleetQuery) Count(_ context.Context, _ fleet.Filter) (int, error) {
	return len(q.results), nil
}

// newTestExecutionQueue creates a real ExecutionQueue backed by an InMemoryQueueStore.
func newTestExecutionQueue() *scriptmodule.ExecutionQueue {
	monitor := scriptmodule.NewExecutionMonitor()
	keyManager := scriptmodule.NewEphemeralKeyManager()
	return scriptmodule.NewExecutionQueue(monitor, keyManager, 0, "", nil, nil, 0)
}

// newTestSynthesisManager creates a Manager backed by an in-memory SQLite store.
func newTestSynthesisManager(t *testing.T) *Manager {
	t.Helper()
	store := newTestRunStore(t)
	return NewManager(store, nil)
}

// ---- SynthesizeScriptRun tests ----------------------------------------------

func TestSynthesizeScriptRun_TwoDevices_CreatesTwoJobs(t *testing.T) {
	ctx := context.Background()
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()

	fq := &staticFleetQuery{
		results: []fleet.StewardResult{
			{ID: "device-001", TenantID: "tenant-abc"},
			{ID: "device-002", TenantID: "tenant-abc"},
		},
	}

	runID, err := SynthesizeScriptRun(
		ctx, manager, queue, fq,
		"tenant-abc", "user-1",
		fleet.Filter{},
		"scripts/deploy.sh", "v1.0.0",
		scriptmodule.ShellBash,
		map[string]string{"env": "prod"},
	)
	require.NoError(t, err)
	assert.NotEmpty(t, runID)

	// Run record must exist and have status=running
	run, err := manager.GetRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, RunStatusRunning, run.Status)
	assert.Equal(t, 2, run.JobCount)
	assert.Equal(t, "tenant-abc", run.TenantID)
	assert.Equal(t, "user-1", run.CreatedBy)
	assert.Equal(t, "scripts/deploy.sh", run.ScriptRef)
	assert.Equal(t, "tenant-abc", run.Filter.TenantID, "filter.TenantID must be scoped to tenantID")

	// Two job records must exist, one per device
	jobs, err := manager.ListRunJobs(ctx, runID)
	require.NoError(t, err)
	require.Len(t, jobs, 2)

	deviceIDs := map[string]bool{}
	for _, j := range jobs {
		assert.Equal(t, runID, j.RunID)
		assert.NotEmpty(t, j.JobID)
		assert.NotEmpty(t, j.ExecutionID)
		assert.Equal(t, JobStatusPending, j.Status)
		deviceIDs[j.DeviceID] = true
	}
	assert.True(t, deviceIDs["device-001"], "job for device-001 must exist")
	assert.True(t, deviceIDs["device-002"], "job for device-002 must exist")

	// Two executions must be queued — one per device
	exec1 := queue.PeekForDevice("device-001")
	exec2 := queue.PeekForDevice("device-002")
	require.Len(t, exec1, 1, "device-001 must have one queued execution")
	require.Len(t, exec2, 1, "device-002 must have one queued execution")

	// Metadata must carry the workflow_run_id and job_id
	for _, e := range []*scriptmodule.QueuedExecution{exec1[0], exec2[0]} {
		assert.Equal(t, runID, e.Metadata["workflow_run_id"], "workflow_run_id must be the run ID")
		assert.NotEmpty(t, e.Metadata["job_id"], "job_id must be set")
	}
}

func TestSynthesizeScriptRun_QueuedExecutionIDs_MatchJobRecords(t *testing.T) {
	ctx := context.Background()
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()

	fq := &staticFleetQuery{
		results: []fleet.StewardResult{
			{ID: "device-A", TenantID: "tenant-test"},
		},
	}

	runID, err := SynthesizeScriptRun(
		ctx, manager, queue, fq,
		"tenant-test", "user-x",
		fleet.Filter{},
		"scripts/check.sh", "",
		scriptmodule.ShellBash,
		nil,
	)
	require.NoError(t, err)

	jobs, err := manager.ListRunJobs(ctx, runID)
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	queued := queue.PeekForDevice("device-A")
	require.Len(t, queued, 1)

	// The execution_id in the queue must match the job record
	assert.Equal(t, jobs[0].ExecutionID, queued[0].ExecutionID,
		"execution_id in queue must match the job record")
	assert.Equal(t, jobs[0].JobID, queued[0].Metadata["job_id"],
		"job_id in queue metadata must match the job record")
}

func TestSynthesizeScriptRun_NoDevices_CreatesEmptyRun(t *testing.T) {
	ctx := context.Background()
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()

	fq := &staticFleetQuery{results: []fleet.StewardResult{}}

	runID, err := SynthesizeScriptRun(
		ctx, manager, queue, fq,
		"tenant-abc", "user-1",
		fleet.Filter{},
		"scripts/noop.sh", "",
		scriptmodule.ShellBash,
		nil,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, runID)

	run, err := manager.GetRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, 0, run.JobCount)
	assert.Equal(t, RunStatusRunning, run.Status)

	jobs, err := manager.ListRunJobs(ctx, runID)
	require.NoError(t, err)
	assert.Empty(t, jobs)
}

func TestSynthesizeScriptRun_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	// Use a RunStoreSQL directly so we can inspect stored runs.
	sqlStore := newTestRunStore(t)
	manager := NewManager(sqlStore, nil)
	queue := newTestExecutionQueue()

	// Even if caller passes an empty filter, tenant scoping must be applied.
	fq := &staticFleetQuery{
		results: []fleet.StewardResult{
			{ID: "device-isolated", TenantID: "tenant-xyz"},
		},
	}

	runID, err := SynthesizeScriptRun(
		ctx, manager, queue, fq,
		"tenant-xyz", "user-2",
		fleet.Filter{}, // no explicit tenantID
		"scripts/test.sh", "",
		scriptmodule.ShellBash,
		nil,
	)
	require.NoError(t, err)

	// The stored run must belong to tenant-xyz and filter.TenantID must be set.
	run, err := sqlStore.GetRun(runID)
	require.NoError(t, err)
	assert.Equal(t, "tenant-xyz", run.TenantID)
	assert.Equal(t, "tenant-xyz", run.Filter.TenantID,
		"filter.TenantID must be overwritten with tenantID even when filter was empty")
}

// ---- SynthesizeCommandRun tests ---------------------------------------------

func TestSynthesizeCommandRun_TwoDevices_CreatesTwoJobs(t *testing.T) {
	ctx := context.Background()
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()

	fq := &staticFleetQuery{
		results: []fleet.StewardResult{
			{ID: "device-cmd-1", TenantID: "tenant-abc"},
			{ID: "device-cmd-2", TenantID: "tenant-abc"},
		},
	}

	runID, err := SynthesizeCommandRun(
		ctx, manager, queue, fq,
		"tenant-abc", "user-1",
		fleet.Filter{},
		"#!/bin/bash\necho hello",
		scriptmodule.ShellBash,
		nil,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, runID)

	run, err := manager.GetRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, RunStatusRunning, run.Status)
	assert.Equal(t, 2, run.JobCount)
	assert.Equal(t, "#!/bin/bash\necho hello", run.InlineContent)
	assert.Empty(t, run.ScriptRef, "script_ref must be empty for command runs")

	jobs, err := manager.ListRunJobs(ctx, runID)
	require.NoError(t, err)
	require.Len(t, jobs, 2)

	// Inline content must be stored in queue metadata
	for _, deviceID := range []string{"device-cmd-1", "device-cmd-2"} {
		queued := queue.PeekForDevice(deviceID)
		require.Len(t, queued, 1, "device %s must have one queued execution", deviceID)
		assert.Equal(t, "#!/bin/bash\necho hello",
			queued[0].Metadata["inline_script_content"],
			"inline content must be in queue metadata for device %s", deviceID)
		assert.Equal(t, runID, queued[0].Metadata["workflow_run_id"])
	}
}

func TestSynthesizeCommandRun_QueuedExecutionIDs_MatchJobRecords(t *testing.T) {
	ctx := context.Background()
	manager := newTestSynthesisManager(t)
	queue := newTestExecutionQueue()

	fq := &staticFleetQuery{
		results: []fleet.StewardResult{
			{ID: "device-cmd-A", TenantID: "tenant-test"},
		},
	}

	runID, err := SynthesizeCommandRun(
		ctx, manager, queue, fq,
		"tenant-test", "user-cmd",
		fleet.Filter{},
		"echo test",
		scriptmodule.ShellBash,
		nil,
	)
	require.NoError(t, err)

	jobs, err := manager.ListRunJobs(ctx, runID)
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	queued := queue.PeekForDevice("device-cmd-A")
	require.Len(t, queued, 1)

	assert.Equal(t, jobs[0].ExecutionID, queued[0].ExecutionID,
		"execution_id in queue must match the job record")
	assert.Equal(t, jobs[0].JobID, queued[0].Metadata["job_id"])
}
