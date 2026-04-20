// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestCommandStore opens an in-memory SQLite CommandStore for tests.
func newTestCommandStore(t *testing.T) *SQLiteCommandStore {
	t.Helper()
	db, err := openAndInit(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return &SQLiteCommandStore{db: db}
}

// testCommandRecord returns a CommandRecord with sensible defaults.
func testCommandRecord(id string) *business.CommandRecord {
	return &business.CommandRecord{
		ID:        id,
		Type:      "sync_config",
		StewardID: "steward-001",
		TenantID:  "tenant-001",
		Payload: map[string]interface{}{
			"modules": []string{"dns", "firewall"},
		},
		IssuedBy: "admin@example.com",
	}
}

// ---------------------------------------------------------------------------
// Happy-path lifecycle tests
// ---------------------------------------------------------------------------

func TestSQLiteCommandStore_CreateAndGet(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	rec := testCommandRecord("cmd-001")
	require.NoError(t, store.CreateCommandRecord(ctx, rec))

	got, err := store.GetCommandRecord(ctx, "cmd-001")
	require.NoError(t, err)
	assert.Equal(t, "cmd-001", got.ID)
	assert.Equal(t, "sync_config", got.Type)
	assert.Equal(t, "steward-001", got.StewardID)
	assert.Equal(t, "tenant-001", got.TenantID)
	assert.Equal(t, business.CommandStatusPending, got.Status)
	assert.Equal(t, "admin@example.com", got.IssuedBy)
	assert.Nil(t, got.StartedAt)
	assert.Nil(t, got.CompletedAt)
}

func TestSQLiteCommandStore_LifecycleAuditTrail(t *testing.T) {
	// Contract test: create → executing → completed; audit trail has three entries.
	store := newTestCommandStore(t)
	ctx := context.Background()

	rec := testCommandRecord("cmd-lifecycle")
	require.NoError(t, store.CreateCommandRecord(ctx, rec))

	require.NoError(t, store.UpdateCommandStatus(ctx, "cmd-lifecycle",
		business.CommandStatusExecuting, nil, ""))

	result := map[string]interface{}{"exit_code": float64(0)}
	require.NoError(t, store.UpdateCommandStatus(ctx, "cmd-lifecycle",
		business.CommandStatusCompleted, result, ""))

	// Verify final state.
	got, err := store.GetCommandRecord(ctx, "cmd-lifecycle")
	require.NoError(t, err)
	assert.Equal(t, business.CommandStatusCompleted, got.Status)
	assert.NotNil(t, got.StartedAt)
	assert.NotNil(t, got.CompletedAt)

	// Verify audit trail has exactly three entries in order.
	trail, err := store.GetCommandAuditTrail(ctx, "cmd-lifecycle")
	require.NoError(t, err)
	require.Len(t, trail, 3)
	assert.Equal(t, business.CommandStatusPending, trail[0].Status)
	assert.Equal(t, business.CommandStatusExecuting, trail[1].Status)
	assert.Equal(t, business.CommandStatusCompleted, trail[2].Status)

	// Timestamps must be non-zero and in chronological order.
	assert.False(t, trail[0].Timestamp.IsZero())
	assert.True(t, !trail[1].Timestamp.Before(trail[0].Timestamp))
	assert.True(t, !trail[2].Timestamp.Before(trail[1].Timestamp))
}

// ---------------------------------------------------------------------------
// Restart simulation
// ---------------------------------------------------------------------------

func TestSQLiteCommandStore_RestartSweep(t *testing.T) {
	// Acceptance criterion: mark a command executing, create a NEW store instance
	// on the same DB, run the startup sweep, verify record is failed with
	// "controller_restart" reason.
	db, err := openAndInit(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	store1 := &SQLiteCommandStore{db: db}

	rec := testCommandRecord("cmd-restart")
	require.NoError(t, store1.CreateCommandRecord(ctx, rec))
	require.NoError(t, store1.UpdateCommandStatus(ctx, "cmd-restart",
		business.CommandStatusExecuting, nil, ""))

	// Simulate restart: new store instance on the same DB.
	store2 := &SQLiteCommandStore{db: db}

	// Startup sweep: flip all "executing" records to "failed" with controller_restart reason.
	executing, err := store2.ListCommandsByStatus(ctx, business.CommandStatusExecuting)
	require.NoError(t, err)
	require.Len(t, executing, 1)

	for _, cmd := range executing {
		err = store2.UpdateCommandStatus(ctx, cmd.ID,
			business.CommandStatusFailed, nil, "controller_restart")
		require.NoError(t, err)
	}

	got, err := store2.GetCommandRecord(ctx, "cmd-restart")
	require.NoError(t, err)
	assert.Equal(t, business.CommandStatusFailed, got.Status)
	assert.Equal(t, "controller_restart", got.ErrorMessage)
}

// ---------------------------------------------------------------------------
// List methods
// ---------------------------------------------------------------------------

func TestSQLiteCommandStore_ListCommandsByDevice(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	for i, id := range []string{"c1", "c2", "c3"} {
		rec := testCommandRecord(id)
		if i == 2 {
			rec.StewardID = "steward-002"
		}
		require.NoError(t, store.CreateCommandRecord(ctx, rec))
	}

	list, err := store.ListCommandsByDevice(ctx, "steward-001")
	require.NoError(t, err)
	assert.Len(t, list, 2)
	for _, r := range list {
		assert.Equal(t, "steward-001", r.StewardID)
	}
}

func TestSQLiteCommandStore_ListCommandsByStatus(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	require.NoError(t, store.CreateCommandRecord(ctx, testCommandRecord("s1")))
	require.NoError(t, store.CreateCommandRecord(ctx, testCommandRecord("s2")))
	require.NoError(t, store.UpdateCommandStatus(ctx, "s1", business.CommandStatusExecuting, nil, ""))

	pending, err := store.ListCommandsByStatus(ctx, business.CommandStatusPending)
	require.NoError(t, err)
	assert.Len(t, pending, 1)
	assert.Equal(t, "s2", pending[0].ID)

	executing, err := store.ListCommandsByStatus(ctx, business.CommandStatusExecuting)
	require.NoError(t, err)
	assert.Len(t, executing, 1)
	assert.Equal(t, "s1", executing[0].ID)
}

func TestSQLiteCommandStore_ListCommandRecords_Filter(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	r1 := testCommandRecord("f1")
	r1.TenantID = "tenant-A"
	r2 := testCommandRecord("f2")
	r2.TenantID = "tenant-B"
	require.NoError(t, store.CreateCommandRecord(ctx, r1))
	require.NoError(t, store.CreateCommandRecord(ctx, r2))

	results, err := store.ListCommandRecords(ctx, &business.CommandFilter{TenantID: "tenant-A"})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "f1", results[0].ID)
}

// ---------------------------------------------------------------------------
// PurgeExpiredRecords
// ---------------------------------------------------------------------------

func TestSQLiteCommandStore_PurgeExpiredRecords(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	// Create records with explicit past issued_at times.
	old := testCommandRecord("old-completed")
	old.IssuedAt = time.Now().Add(-48 * time.Hour)
	require.NoError(t, store.CreateCommandRecord(ctx, old))
	require.NoError(t, store.UpdateCommandStatus(ctx, "old-completed",
		business.CommandStatusCompleted, nil, ""))

	recent := testCommandRecord("recent-completed")
	recent.IssuedAt = time.Now().Add(-1 * time.Hour)
	require.NoError(t, store.CreateCommandRecord(ctx, recent))
	require.NoError(t, store.UpdateCommandStatus(ctx, "recent-completed",
		business.CommandStatusCompleted, nil, ""))

	still := testCommandRecord("still-executing")
	still.IssuedAt = time.Now().Add(-48 * time.Hour)
	require.NoError(t, store.CreateCommandRecord(ctx, still))
	require.NoError(t, store.UpdateCommandStatus(ctx, "still-executing",
		business.CommandStatusExecuting, nil, ""))

	// Purge records older than 24 hours.
	cutoff := time.Now().Add(-24 * time.Hour)
	deleted, err := store.PurgeExpiredRecords(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted, "only the old completed record should be purged")

	// old-completed should be gone.
	_, err = store.GetCommandRecord(ctx, "old-completed")
	assert.Error(t, err, "old-completed should not exist after purge")

	// recent-completed must remain.
	_, err = store.GetCommandRecord(ctx, "recent-completed")
	assert.NoError(t, err, "recent-completed should still exist")

	// still-executing must remain (never purged regardless of age).
	_, err = store.GetCommandRecord(ctx, "still-executing")
	assert.NoError(t, err, "executing record should never be purged")
}

// ---------------------------------------------------------------------------
// Error path tests
// ---------------------------------------------------------------------------

func TestSQLiteCommandStore_CreateRecord_NilRecord(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	err := store.CreateCommandRecord(ctx, nil)
	require.Error(t, err)
}

func TestSQLiteCommandStore_CreateRecord_EmptyID(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	rec := testCommandRecord("")
	err := store.CreateCommandRecord(ctx, rec)
	require.Error(t, err)
}

func TestSQLiteCommandStore_CreateRecord_EmptyStewardID(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	rec := testCommandRecord("cmd-no-steward")
	rec.StewardID = ""
	err := store.CreateCommandRecord(ctx, rec)
	require.Error(t, err)
}

func TestSQLiteCommandStore_GetRecord_NotFound(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	_, err := store.GetCommandRecord(ctx, "nonexistent")
	require.Error(t, err)
}

func TestSQLiteCommandStore_UpdateStatus_NotFound(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	err := store.UpdateCommandStatus(ctx, "nonexistent", business.CommandStatusCompleted, nil, "")
	require.Error(t, err)
}

func TestSQLiteCommandStore_UpdateStatus_EmptyID(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	err := store.UpdateCommandStatus(ctx, "", business.CommandStatusCompleted, nil, "")
	require.Error(t, err)
}

func TestSQLiteCommandStore_GetAuditTrail_EmptyID(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	_, err := store.GetCommandAuditTrail(ctx, "")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// HealthCheck
// ---------------------------------------------------------------------------

func TestSQLiteCommandStore_HealthCheck(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	require.NoError(t, store.HealthCheck(ctx))
}

// ---------------------------------------------------------------------------
// Duplicate ID
// ---------------------------------------------------------------------------

func TestSQLiteCommandStore_CreateRecord_DuplicateID(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	rec := testCommandRecord("dup")
	require.NoError(t, store.CreateCommandRecord(ctx, rec))
	err := store.CreateCommandRecord(ctx, rec)
	require.Error(t, err, "duplicate command ID must be rejected")
}
