// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package run

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	scriptmodule "github.com/cfgis/cfgms/features/modules/script"
	_ "modernc.org/sqlite"
)

// newTestRunStore opens an in-memory SQLite database, initializes the RunStoreSQL
// schema, and returns the store. The database is closed automatically via t.Cleanup.
func newTestRunStore(t *testing.T) *RunStoreSQL {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err, "open in-memory sqlite")
	t.Cleanup(func() { _ = db.Close() })

	store := NewRunStoreSQL(db)
	require.NoError(t, store.Init(context.Background()), "Init must succeed")
	return store
}

// sampleRun returns a populated RunRecord suitable for tests.
func sampleRun(runID, tenantID string) *RunRecord {
	return &RunRecord{
		RunID:     runID,
		TenantID:  tenantID,
		CreatedBy: "user-1",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		Status:    RunStatusPending,
		Filter:    fleet.Filter{TenantID: tenantID, OS: "linux"},
		ScriptRef: "scripts/deploy.sh",
		Shell:     scriptmodule.ShellBash,
		JobCount:  2,
	}
}

// sampleJob returns a populated JobRecord suitable for tests.
func sampleJob(jobID, runID, deviceID string) *JobRecord {
	return &JobRecord{
		JobID:     jobID,
		RunID:     runID,
		DeviceID:  deviceID,
		Status:    JobStatusPending,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
}

// ---- RunStoreSQL tests -------------------------------------------------------

func TestRunStoreSQL_Init_Idempotent(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	store := NewRunStoreSQL(db)

	require.NoError(t, store.Init(context.Background()), "first Init must succeed")
	require.NoError(t, store.Init(context.Background()), "second Init must succeed (idempotent)")

	// Tables must exist
	var count int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM script_runs").Scan(&count))
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM script_run_jobs").Scan(&count))

	// Index must exist
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='script_run_jobs'`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var indexFound bool
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		if name == "idx_srj_run_id" {
			indexFound = true
		}
	}
	require.NoError(t, rows.Err())
	assert.True(t, indexFound, "idx_srj_run_id index must exist")
}

func TestRunStoreSQL_CreateRun_GetRun(t *testing.T) {
	store := newTestRunStore(t)

	run := sampleRun("run-001", "tenant-abc")
	require.NoError(t, store.CreateRun(run))

	got, err := store.GetRun("run-001")
	require.NoError(t, err)

	assert.Equal(t, run.RunID, got.RunID)
	assert.Equal(t, run.TenantID, got.TenantID)
	assert.Equal(t, run.CreatedBy, got.CreatedBy)
	assert.Equal(t, run.Status, got.Status)
	assert.Equal(t, run.ScriptRef, got.ScriptRef)
	assert.Equal(t, run.Shell, got.Shell)
	assert.Equal(t, run.JobCount, got.JobCount)
	assert.Equal(t, run.Filter.OS, got.Filter.OS)
	assert.Equal(t, run.Filter.TenantID, got.Filter.TenantID)
}

func TestRunStoreSQL_GetRun_NotFound(t *testing.T) {
	store := newTestRunStore(t)

	_, err := store.GetRun("nonexistent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound), "expected ErrNotFound, got %v", err)
}

func TestRunStoreSQL_CreateRun_InlineContent(t *testing.T) {
	store := newTestRunStore(t)

	run := &RunRecord{
		RunID:         "run-inline",
		TenantID:      "tenant-x",
		CreatedAt:     time.Now().UTC(),
		Status:        RunStatusPending,
		InlineContent: "#!/bin/bash\necho hello",
		Shell:         scriptmodule.ShellBash,
	}
	require.NoError(t, store.CreateRun(run))

	got, err := store.GetRun("run-inline")
	require.NoError(t, err)
	assert.Equal(t, run.InlineContent, got.InlineContent)
}

func TestRunStoreSQL_CreateJob_And_ListRunJobs(t *testing.T) {
	store := newTestRunStore(t)

	run := sampleRun("run-002", "tenant-abc")
	require.NoError(t, store.CreateRun(run))

	j1 := sampleJob("job-001", "run-002", "device-alpha")
	j2 := sampleJob("job-002", "run-002", "device-beta")
	j2.CreatedAt = j2.CreatedAt.Add(time.Second) // ensure ordering

	require.NoError(t, store.CreateJob(j1))
	require.NoError(t, store.CreateJob(j2))

	jobs, err := store.ListRunJobs("run-002")
	require.NoError(t, err)
	require.Len(t, jobs, 2)

	// Ordered by created_at ASC
	assert.Equal(t, "job-001", jobs[0].JobID)
	assert.Equal(t, "job-002", jobs[1].JobID)
	assert.Equal(t, "device-alpha", jobs[0].DeviceID)
	assert.Equal(t, "device-beta", jobs[1].DeviceID)
	assert.Equal(t, "run-002", jobs[0].RunID)
}

func TestRunStoreSQL_ListRunJobs_EmptyForUnknownRun(t *testing.T) {
	store := newTestRunStore(t)

	jobs, err := store.ListRunJobs("no-such-run")
	require.NoError(t, err)
	assert.Empty(t, jobs)
}

func TestRunStoreSQL_UpdateJobStatus_NonTerminal(t *testing.T) {
	store := newTestRunStore(t)

	run := sampleRun("run-003", "tenant-abc")
	require.NoError(t, store.CreateRun(run))

	j := sampleJob("job-003", "run-003", "device-gamma")
	require.NoError(t, store.CreateJob(j))

	require.NoError(t, store.UpdateJobStatus("job-003", JobStatusRunning, "exec-xyz"))

	jobs, err := store.ListRunJobs("run-003")
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	assert.Equal(t, JobStatusRunning, jobs[0].Status)
	assert.Equal(t, "exec-xyz", jobs[0].ExecutionID)
	assert.Nil(t, jobs[0].CompletedAt, "completed_at must remain nil for non-terminal status")
}

func TestRunStoreSQL_UpdateJobStatus_Terminal_SetsCompletedAt(t *testing.T) {
	store := newTestRunStore(t)

	run := sampleRun("run-004", "tenant-abc")
	require.NoError(t, store.CreateRun(run))

	j := sampleJob("job-004", "run-004", "device-delta")
	require.NoError(t, store.CreateJob(j))

	before := time.Now().UTC().Add(-time.Second)
	require.NoError(t, store.UpdateJobStatus("job-004", JobStatusCompleted, "exec-done"))
	after := time.Now().UTC().Add(time.Second)

	jobs, err := store.ListRunJobs("run-004")
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	assert.Equal(t, JobStatusCompleted, jobs[0].Status)
	require.NotNil(t, jobs[0].CompletedAt, "completed_at must be set for terminal status")
	assert.True(t, jobs[0].CompletedAt.After(before) && jobs[0].CompletedAt.Before(after),
		"completed_at must be set to approximately now")
}

func TestRunStoreSQL_UpdateRunStatus(t *testing.T) {
	store := newTestRunStore(t)

	run := sampleRun("run-005", "tenant-abc")
	require.NoError(t, store.CreateRun(run))

	require.NoError(t, store.UpdateRunStatus("run-005", RunStatusRunning))

	got, err := store.GetRun("run-005")
	require.NoError(t, err)
	assert.Equal(t, RunStatusRunning, got.Status)
}

func TestRunStoreSQL_UpdateRunCounts(t *testing.T) {
	store := newTestRunStore(t)

	run := sampleRun("run-006", "tenant-abc")
	require.NoError(t, store.CreateRun(run))

	require.NoError(t, store.UpdateRunCounts("run-006", 1, 1))

	got, err := store.GetRun("run-006")
	require.NoError(t, err)
	assert.Equal(t, 1, got.CompletedJobs)
	assert.Equal(t, 1, got.FailedJobs)
}

func TestRunStoreSQL_CreateJob_WithExecutionID(t *testing.T) {
	store := newTestRunStore(t)

	run := sampleRun("run-007", "tenant-abc")
	require.NoError(t, store.CreateRun(run))

	j := sampleJob("job-007", "run-007", "device-epsilon")
	j.ExecutionID = "exec-pre-assigned"
	require.NoError(t, store.CreateJob(j))

	jobs, err := store.ListRunJobs("run-007")
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	assert.Equal(t, "exec-pre-assigned", jobs[0].ExecutionID)
}

// ---- RunStatus / JobStatus helpers ------------------------------------------

func TestRunStatus_IsTerminal(t *testing.T) {
	assert.False(t, RunStatusPending.IsTerminal())
	assert.False(t, RunStatusRunning.IsTerminal())
	assert.True(t, RunStatusCompleted.IsTerminal())
	assert.True(t, RunStatusFailed.IsTerminal())
	assert.True(t, RunStatusCancelled.IsTerminal())
}

func TestJobStatus_IsTerminal(t *testing.T) {
	assert.False(t, JobStatusPending.IsTerminal())
	assert.False(t, JobStatusRunning.IsTerminal())
	assert.True(t, JobStatusCompleted.IsTerminal())
	assert.True(t, JobStatusFailed.IsTerminal())
	assert.True(t, JobStatusCancelled.IsTerminal())
}

// ---- Manager tests ----------------------------------------------------------

func newTestManager(t *testing.T) (*Manager, *RunStoreSQL) {
	t.Helper()
	store := newTestRunStore(t)
	manager := NewManager(store, nil)
	return manager, store
}

func TestManager_GetRun_NotFound(t *testing.T) {
	manager, _ := newTestManager(t)

	_, err := manager.GetRun(context.Background(), "no-such-run")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

func TestManager_GetRun_Found(t *testing.T) {
	manager, store := newTestManager(t)

	run := sampleRun("run-mgr-1", "tenant-abc")
	require.NoError(t, store.CreateRun(run))

	got, err := manager.GetRun(context.Background(), "run-mgr-1")
	require.NoError(t, err)
	assert.Equal(t, "run-mgr-1", got.RunID)
}

func TestManager_ListRunJobs_NotFound(t *testing.T) {
	manager, _ := newTestManager(t)

	_, err := manager.ListRunJobs(context.Background(), "no-such-run")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

func TestManager_ListRunJobs_ReturnsJobs(t *testing.T) {
	manager, store := newTestManager(t)

	run := sampleRun("run-mgr-2", "tenant-abc")
	require.NoError(t, store.CreateRun(run))
	require.NoError(t, store.CreateJob(sampleJob("job-mgr-1", "run-mgr-2", "dev-a")))
	require.NoError(t, store.CreateJob(sampleJob("job-mgr-2", "run-mgr-2", "dev-b")))

	jobs, err := manager.ListRunJobs(context.Background(), "run-mgr-2")
	require.NoError(t, err)
	assert.Len(t, jobs, 2)
}

func TestManager_CancelRun_NotFound(t *testing.T) {
	manager, _ := newTestManager(t)

	err := manager.CancelRun(context.Background(), "no-such-run")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
}

func TestManager_CancelRun_AlreadyTerminal(t *testing.T) {
	manager, store := newTestManager(t)

	run := sampleRun("run-term", "tenant-abc")
	run.Status = RunStatusCompleted
	require.NoError(t, store.CreateRun(run))

	err := manager.CancelRun(context.Background(), "run-term")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAlreadyTerminal))
}

func TestManager_CancelRun_CancelsRunAndJobs(t *testing.T) {
	manager, store := newTestManager(t)

	run := sampleRun("run-cancel", "tenant-abc")
	run.Status = RunStatusRunning
	require.NoError(t, store.CreateRun(run))

	j1 := sampleJob("job-c1", "run-cancel", "dev-alpha")
	j1.Status = JobStatusRunning
	j2 := sampleJob("job-c2", "run-cancel", "dev-beta")
	j2.Status = JobStatusCompleted // already terminal — must NOT be overwritten

	require.NoError(t, store.CreateJob(j1))
	require.NoError(t, store.CreateJob(j2))

	require.NoError(t, manager.CancelRun(context.Background(), "run-cancel"))

	// Run must be cancelled
	got, err := store.GetRun("run-cancel")
	require.NoError(t, err)
	assert.Equal(t, RunStatusCancelled, got.Status)

	// Non-terminal job must be cancelled
	jobs, err := store.ListRunJobs("run-cancel")
	require.NoError(t, err)
	require.Len(t, jobs, 2)

	jobsByID := map[string]*JobRecord{}
	for _, j := range jobs {
		jobsByID[j.JobID] = j
	}

	assert.Equal(t, JobStatusCancelled, jobsByID["job-c1"].Status, "running job must be cancelled")
	assert.Equal(t, JobStatusCompleted, jobsByID["job-c2"].Status, "completed job must remain completed")
}

func TestManager_CancelRun_AlreadyCancelled(t *testing.T) {
	manager, store := newTestManager(t)

	run := sampleRun("run-already-cancelled", "tenant-abc")
	run.Status = RunStatusCancelled
	require.NoError(t, store.CreateRun(run))

	err := manager.CancelRun(context.Background(), "run-already-cancelled")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAlreadyTerminal))
}

// ---- Close tests ------------------------------------------------------------

// TestRunStoreSQL_Close_ReleasesDBHandle verifies that Close releases the
// underlying connection. A leaked file-backed connection blocks temp-directory
// cleanup on Windows (Issue #1673 CI regression), so the file must be removable
// once Close has run.
func TestRunStoreSQL_Close_ReleasesDBHandle(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "runs.db")

	db, err := sql.Open("sqlite", "file:"+dbPath)
	require.NoError(t, err, "open file-backed sqlite")

	store := NewRunStoreSQL(db)
	require.NoError(t, store.Init(context.Background()), "Init must succeed")
	require.NoError(t, store.CreateRun(sampleRun("run-close-1", "tenant-abc")))

	require.NoError(t, store.Close(), "Close must succeed")

	// After Close the connection is released — operations must fail.
	_, err = store.GetRun("run-close-1")
	require.Error(t, err, "GetRun must fail after Close")

	// The DB file must be removable now that no handle is held open.
	require.NoError(t, os.Remove(dbPath), "db file must be removable after Close")
}

// TestRunStoreSQL_Close_NilDB verifies Close is safe on a zero-value store.
func TestRunStoreSQL_Close_NilDB(t *testing.T) {
	store := &RunStoreSQL{}
	require.NoError(t, store.Close())
}

// TestManager_Close_ClosesStore verifies Manager.Close propagates to a store
// that implements io.Closer.
func TestManager_Close_ClosesStore(t *testing.T) {
	store := newTestRunStore(t)
	manager := NewManager(store, nil)

	require.NoError(t, manager.Close(), "Manager.Close must succeed")

	_, err := store.GetRun("anything")
	require.Error(t, err, "store must be closed after Manager.Close")
}

// closerlessStore is a RunStore that does not implement io.Closer; used to
// verify Manager.Close is a no-op for non-closable stores.
type closerlessStore struct{ RunStore }

func TestManager_Close_NonClosableStore(t *testing.T) {
	manager := NewManager(closerlessStore{}, nil)
	require.NoError(t, manager.Close(), "Manager.Close must be a no-op for non-closable store")
}
