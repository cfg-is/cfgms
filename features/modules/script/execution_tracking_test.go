// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestTrackingStore opens an in-memory SQLite database, initializes the
// ExecutionTrackingStore schema, and returns the store. The test is skipped
// if CGO is not available (SQLite requires CGO).
func newTestTrackingStore(t *testing.T) *ExecutionTrackingStore {
	t.Helper()
	testutil.SkipWithoutCGO(t)

	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err, "open in-memory sqlite3")
	t.Cleanup(func() { _ = db.Close() })

	store := NewExecutionTrackingStore(db)
	require.NoError(t, store.Init(context.Background()), "Init must succeed")
	return store
}

// sampleRecord returns a populated ExecutionRecord suitable for use in tests.
func sampleRecord(executionID, deviceID, workflowRunID string) *ExecutionRecord {
	now := time.Now().UTC().Truncate(time.Second)
	return &ExecutionRecord{
		ExecutionID:   executionID,
		DeviceID:      deviceID,
		WorkflowRunID: workflowRunID,
		WorkflowName:  "test-workflow",
		ScriptRef:     "scripts/deploy.sh",
		ScriptVersion: "v1.2.3",
		Shell:         "bash",
		ExitCode:      0,
		State:         "completed",
		Stdout:        "ok",
		Stderr:        "",
		DurationMs:    1234,
		QueuedAt:      now.Add(-10 * time.Second),
		DispatchedAt:  now.Add(-5 * time.Second),
		CompletedAt:   now,
	}
}

// TestExecutionTrackingStore_Init verifies that calling Init creates the table
// and both indexes, and that calling Init a second time is idempotent.
func TestExecutionTrackingStore_Init(t *testing.T) {
	testutil.SkipWithoutCGO(t)

	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	store := NewExecutionTrackingStore(db)

	// First Init: must succeed
	require.NoError(t, store.Init(context.Background()), "first Init must succeed")

	// Table exists — a trivial query must not error
	var count int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM script_execution_results").Scan(&count))

	// Indexes exist — querying sqlite_master is reliable across SQLite versions
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='script_execution_results'`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	indexNames := map[string]bool{}
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		indexNames[name] = true
	}
	require.NoError(t, rows.Err())
	assert.True(t, indexNames["idx_ser_device"], "idx_ser_device index must exist")
	assert.True(t, indexNames["idx_ser_workflow"], "idx_ser_workflow index must exist")

	// Second Init: must also succeed (idempotent)
	require.NoError(t, store.Init(context.Background()), "second Init must succeed (idempotent)")
}

// TestExecutionTrackingStore_Record_Basic verifies that a record can be stored
// and retrieved, and that all fields round-trip correctly.
func TestExecutionTrackingStore_Record_Basic(t *testing.T) {
	store := newTestTrackingStore(t)

	rec := sampleRecord("exec-1", "device-a", "wf-run-1")
	require.NoError(t, store.Record(context.Background(), rec))

	results, err := store.QueryByDevice(context.Background(), "device-a", 10)
	require.NoError(t, err)
	require.Len(t, results, 1)

	got := results[0]
	assert.Equal(t, rec.ExecutionID, got.ExecutionID)
	assert.Equal(t, rec.DeviceID, got.DeviceID)
	assert.Equal(t, rec.WorkflowRunID, got.WorkflowRunID)
	assert.Equal(t, rec.WorkflowName, got.WorkflowName)
	assert.Equal(t, rec.ScriptRef, got.ScriptRef)
	assert.Equal(t, rec.ScriptVersion, got.ScriptVersion)
	assert.Equal(t, rec.Shell, got.Shell)
	assert.Equal(t, rec.ExitCode, got.ExitCode)
	assert.Equal(t, rec.State, got.State)
	assert.Equal(t, rec.Stdout, got.Stdout)
	assert.Equal(t, rec.DurationMs, got.DurationMs)
}

// TestExecutionTrackingStore_Record_Idempotent verifies that inserting the same
// (execution_id, device_id) pair twice does not error and does not create a
// duplicate row.
func TestExecutionTrackingStore_Record_Idempotent(t *testing.T) {
	store := newTestTrackingStore(t)

	rec := sampleRecord("exec-idem", "device-b", "wf-run-2")

	// First insert
	require.NoError(t, store.Record(context.Background(), rec), "first Record must succeed")

	// Second insert — identical key, updated state (simulates re-delivery)
	rec.State = "failed"
	require.NoError(t, store.Record(context.Background(), rec), "second Record must succeed (idempotent)")

	// Only one row must exist
	results, err := store.QueryByDevice(context.Background(), "device-b", 10)
	require.NoError(t, err)
	require.Len(t, results, 1, "idempotent insert must not duplicate the row")
	assert.Equal(t, "failed", results[0].State, "second write must win (INSERT OR REPLACE)")
}

// TestExecutionTrackingStore_QueryByDevice verifies that QueryByDevice returns
// only records for the requested device, ordered by completed_at DESC, and
// respects the limit.
func TestExecutionTrackingStore_QueryByDevice(t *testing.T) {
	store := newTestTrackingStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second)

	// Insert 5 records for device-alpha (different completion times)
	for i := 0; i < 5; i++ {
		rec := &ExecutionRecord{
			ExecutionID: fmt.Sprintf("exec-da-%d", i),
			DeviceID:    "device-alpha",
			ScriptRef:   "scripts/check.sh",
			State:       "completed",
			CompletedAt: base.Add(time.Duration(i) * time.Second),
		}
		require.NoError(t, store.Record(ctx, rec))
	}

	// Insert a record for a different device — must not appear in results
	otherRec := &ExecutionRecord{
		ExecutionID: "exec-other",
		DeviceID:    "device-beta",
		ScriptRef:   "scripts/check.sh",
		State:       "completed",
		CompletedAt: base,
	}
	require.NoError(t, store.Record(ctx, otherRec))

	// Query with limit 3
	results, err := store.QueryByDevice(ctx, "device-alpha", 3)
	require.NoError(t, err)
	require.Len(t, results, 3, "limit must be respected")

	for _, r := range results {
		assert.Equal(t, "device-alpha", r.DeviceID, "must return only device-alpha records")
	}

	// Results must be ordered completed_at DESC (most recent first)
	assert.Equal(t, "exec-da-4", results[0].ExecutionID, "first result must be the most recent")
	assert.Equal(t, "exec-da-3", results[1].ExecutionID)
	assert.Equal(t, "exec-da-2", results[2].ExecutionID)
}

// TestExecutionTrackingStore_QueryByDevice_ReturnsEmptyForUnknownDevice verifies
// that an empty slice (not an error) is returned when no records exist for a device.
func TestExecutionTrackingStore_QueryByDevice_ReturnsEmptyForUnknownDevice(t *testing.T) {
	store := newTestTrackingStore(t)

	results, err := store.QueryByDevice(context.Background(), "unknown-device", 10)
	require.NoError(t, err, "unknown device must not error")
	assert.Empty(t, results, "unknown device must return empty slice")
}

// TestExecutionTrackingStore_QueryByWorkflowRun verifies that
// QueryByWorkflowRun returns all device records for the run, regardless of
// device ID, and excludes records from other runs.
func TestExecutionTrackingStore_QueryByWorkflowRun(t *testing.T) {
	store := newTestTrackingStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second)

	// Three devices in workflow run "wf-run-42"
	for _, deviceID := range []string{"dev-1", "dev-2", "dev-3"} {
		rec := &ExecutionRecord{
			ExecutionID:   "exec-" + deviceID,
			DeviceID:      deviceID,
			WorkflowRunID: "wf-run-42",
			ScriptRef:     "scripts/deploy.sh",
			State:         "completed",
			CompletedAt:   base,
		}
		require.NoError(t, store.Record(ctx, rec))
	}

	// A different workflow run — must not appear in results
	noise := &ExecutionRecord{
		ExecutionID:   "exec-noise",
		DeviceID:      "dev-4",
		WorkflowRunID: "wf-run-99",
		ScriptRef:     "scripts/deploy.sh",
		State:         "completed",
		CompletedAt:   base,
	}
	require.NoError(t, store.Record(ctx, noise))

	results, err := store.QueryByWorkflowRun(ctx, "wf-run-42")
	require.NoError(t, err)
	require.Len(t, results, 3, "must return all three device records for wf-run-42")

	for _, r := range results {
		assert.Equal(t, "wf-run-42", r.WorkflowRunID, "all results must belong to wf-run-42")
	}
}

// TestExecutionTrackingStore_AdHocExecution verifies that an ExecutionRecord
// with an empty WorkflowRunID is stored and retrieved without error.
func TestExecutionTrackingStore_AdHocExecution(t *testing.T) {
	store := newTestTrackingStore(t)
	ctx := context.Background()

	// Ad-hoc execution: no workflow run ID
	rec := &ExecutionRecord{
		ExecutionID: "exec-adhoc",
		DeviceID:    "device-c",
		ScriptRef:   "scripts/adhoc.sh",
		State:       "completed",
		CompletedAt: time.Now().UTC(),
	}
	require.NoError(t, store.Record(ctx, rec), "ad-hoc record (empty WorkflowRunID) must be stored")

	// Device view must find it
	byDevice, err := store.QueryByDevice(ctx, "device-c", 10)
	require.NoError(t, err)
	require.Len(t, byDevice, 1)
	assert.Equal(t, "", byDevice[0].WorkflowRunID, "WorkflowRunID must round-trip as empty string")

	// Workflow-run view with empty string must not match NULLs
	byRun, err := store.QueryByWorkflowRun(ctx, "")
	require.NoError(t, err)
	for _, r := range byRun {
		assert.NotEqual(t, "exec-adhoc", r.ExecutionID,
			"ad-hoc record (NULL workflow_run_id) must not appear in empty-string workflow-run query")
	}
}

// TestExecutionTrackingStore_NoDataDuplication verifies that writing the same
// record three times results in exactly one row.
func TestExecutionTrackingStore_NoDataDuplication(t *testing.T) {
	store := newTestTrackingStore(t)
	ctx := context.Background()

	rec := &ExecutionRecord{
		ExecutionID: "exec-dup",
		DeviceID:    "device-d",
		ScriptRef:   "scripts/dup.sh",
		State:       "completed",
		CompletedAt: time.Now().UTC(),
	}

	// Simulate three re-deliveries of the same terminal event
	for i := 0; i < 3; i++ {
		require.NoError(t, store.Record(ctx, rec))
	}

	results, err := store.QueryByDevice(ctx, "device-d", 10)
	require.NoError(t, err)
	assert.Len(t, results, 1, "repeated Record calls must not create duplicate rows")
}

// TestExecutionTrackingStore_DualIndexLookup verifies both query paths against
// the same data — the no-duplication invariant across indexes.
func TestExecutionTrackingStore_DualIndexLookup(t *testing.T) {
	store := newTestTrackingStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second)

	// Two devices in the same workflow run
	for i, deviceID := range []string{"dev-x", "dev-y"} {
		rec := &ExecutionRecord{
			ExecutionID:   fmt.Sprintf("exec-%s", deviceID),
			DeviceID:      deviceID,
			WorkflowRunID: "wf-run-dual",
			ScriptRef:     "scripts/dual.sh",
			State:         "completed",
			CompletedAt:   base.Add(time.Duration(i) * time.Second),
		}
		require.NoError(t, store.Record(ctx, rec))
	}

	// Device-view for dev-x: must return only dev-x record
	byDevX, err := store.QueryByDevice(ctx, "dev-x", 10)
	require.NoError(t, err)
	require.Len(t, byDevX, 1)
	assert.Equal(t, "dev-x", byDevX[0].DeviceID)

	// Workflow-run view: must return both records (no duplication)
	byRun, err := store.QueryByWorkflowRun(ctx, "wf-run-dual")
	require.NoError(t, err)
	require.Len(t, byRun, 2, "both device records must be present exactly once")

	// Verify no record appears twice
	seen := map[string]int{}
	for _, r := range byRun {
		seen[r.ExecutionID]++
	}
	for id, count := range seen {
		assert.Equal(t, 1, count, "execution %s must appear exactly once", id)
	}
}
