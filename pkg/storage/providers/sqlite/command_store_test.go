// SPDX-License-Identifier: AGPL-3.0-only
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

// ---------------------------------------------------------------------------
// Delivery lifecycle (Issue #3757, ADR-031 Decision 2)
// ---------------------------------------------------------------------------

func TestSQLiteCommandStore_CreateRecord_DeliveryStatusDefaultsPending(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	rec := testCommandRecord("delivery-default")
	require.NoError(t, store.CreateCommandRecord(ctx, rec))

	got, err := store.GetCommandRecord(ctx, "delivery-default")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusPending, got.DeliveryStatus)
	assert.Empty(t, got.DeliveryDetail)
}

func TestSQLiteCommandStore_UpdateDeliveryStatus(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	rec := testCommandRecord("delivery-lifecycle")
	require.NoError(t, store.CreateCommandRecord(ctx, rec))

	require.NoError(t, store.UpdateDeliveryStatus(ctx, "delivery-lifecycle", business.DeliveryStatusDelivered, ""))
	got, err := store.GetCommandRecord(ctx, "delivery-lifecycle")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusDelivered, got.DeliveryStatus)
	// Execution status is untouched by a delivery-status transition.
	assert.Equal(t, business.CommandStatusPending, got.Status)

	require.NoError(t, store.UpdateDeliveryStatus(ctx, "delivery-lifecycle", business.DeliveryStatusAcknowledged, ""))
	got, err = store.GetCommandRecord(ctx, "delivery-lifecycle")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusAcknowledged, got.DeliveryStatus)

	// UpdateDeliveryStatus does not append to the CommandStatus audit trail.
	trail, err := store.GetCommandAuditTrail(ctx, "delivery-lifecycle")
	require.NoError(t, err)
	assert.Len(t, trail, 1, "only the initial pending transition should exist")
}

func TestSQLiteCommandStore_UpdateDeliveryStatus_Failed_RecordsDetail(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	rec := testCommandRecord("delivery-failed")
	require.NoError(t, store.CreateCommandRecord(ctx, rec))

	require.NoError(t, store.UpdateDeliveryStatus(ctx, "delivery-failed",
		business.DeliveryStatusFailed, "steward deregistered"))

	got, err := store.GetCommandRecord(ctx, "delivery-failed")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusFailed, got.DeliveryStatus)
	assert.Equal(t, "steward deregistered", got.DeliveryDetail)
}

func TestSQLiteCommandStore_UpdateDeliveryStatus_NotFound(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	err := store.UpdateDeliveryStatus(ctx, "nonexistent", business.DeliveryStatusDelivered, "")
	require.ErrorIs(t, err, business.ErrCommandNotFound)
}

func TestSQLiteCommandStore_UpdateDeliveryStatus_EmptyID(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	err := store.UpdateDeliveryStatus(ctx, "", business.DeliveryStatusDelivered, "")
	require.Error(t, err)
}

func TestSQLiteCommandStore_ListPendingDeliveries(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	r1 := testCommandRecord("pd-1")
	r2 := testCommandRecord("pd-2")
	r3 := testCommandRecord("pd-3")
	r3.StewardID = "steward-002"
	require.NoError(t, store.CreateCommandRecord(ctx, r1))
	require.NoError(t, store.CreateCommandRecord(ctx, r2))
	require.NoError(t, store.CreateCommandRecord(ctx, r3))

	// Mark one of steward-001's records delivered — it must drop out of the pending list.
	require.NoError(t, store.UpdateDeliveryStatus(ctx, "pd-1", business.DeliveryStatusDelivered, ""))

	pending, err := store.ListPendingDeliveries(ctx, "steward-001", "tenant-001")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, "pd-2", pending[0].ID)

	otherPending, err := store.ListPendingDeliveries(ctx, "steward-002", "tenant-001")
	require.NoError(t, err)
	require.Len(t, otherPending, 1)
	assert.Equal(t, "pd-3", otherPending[0].ID)
}

func TestSQLiteCommandStore_ListPendingDeliveries_EmptyStewardID(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	_, err := store.ListPendingDeliveries(ctx, "", "tenant-001")
	require.Error(t, err)
}

// TestSQLiteCommandStore_ListPendingDeliveries_EmptyTenantFailsClosed proves the
// tenant argument is mandatory: an empty tenant is refused rather than silently
// widening the query to every tenant's rows for that steward ID.
func TestSQLiteCommandStore_ListPendingDeliveries_EmptyTenantFailsClosed(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateCommandRecord(ctx, testCommandRecord("pd-no-tenant")))

	_, err := store.ListPendingDeliveries(ctx, "steward-001", "")
	require.ErrorIs(t, err, business.ErrCommandTenantIDRequired)
}

// TestSQLiteCommandStore_ListPendingDeliveries_ExcludesForeignTenant is the
// storage-layer half of the cross-tenant isolation guarantee. A steward's tenant
// binding is mutable (Issue #2341), so rows written under a previous tenant stay
// attached to the same steward_id; filtering on steward_id alone would hand them
// to the steward's new tenant, and SQLite has no RLS to compensate.
func TestSQLiteCommandStore_ListPendingDeliveries_ExcludesForeignTenant(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	current := testCommandRecord("pd-current-tenant")
	current.TenantID = "tenant-new"
	previous := testCommandRecord("pd-previous-tenant") // same steward, old tenant
	previous.TenantID = "tenant-old"
	require.NoError(t, store.CreateCommandRecord(ctx, current))
	require.NoError(t, store.CreateCommandRecord(ctx, previous))

	pending, err := store.ListPendingDeliveries(ctx, "steward-001", "tenant-new")
	require.NoError(t, err)
	require.Len(t, pending, 1, "only the record stamped with the steward's current tenant is returned")
	assert.Equal(t, "pd-current-tenant", pending[0].ID)
}

// TestSQLiteCommandStore_ListPendingDeliveries_IncludesAncestorTenant proves the
// filter does not break subtree pushes: handleConfigPush stamps a record with the
// config's tenant, which for a fan-out is an ancestor of the targeted steward's
// own tenant. Those rows must still drain.
func TestSQLiteCommandStore_ListPendingDeliveries_IncludesAncestorTenant(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	own := testCommandRecord("pd-own")
	own.TenantID = "root/msp-a/client-1"
	ancestor := testCommandRecord("pd-ancestor")
	ancestor.TenantID = "root/msp-a"
	sibling := testCommandRecord("pd-sibling")
	sibling.TenantID = "root/msp-a/client-2"
	require.NoError(t, store.CreateCommandRecord(ctx, own))
	require.NoError(t, store.CreateCommandRecord(ctx, ancestor))
	require.NoError(t, store.CreateCommandRecord(ctx, sibling))

	pending, err := store.ListPendingDeliveries(ctx, "steward-001", "root/msp-a/client-1")
	require.NoError(t, err)

	ids := make([]string, 0, len(pending))
	for _, rec := range pending {
		ids = append(ids, rec.ID)
	}
	assert.ElementsMatch(t, []string{"pd-own", "pd-ancestor"}, ids,
		"own and ancestor tenants drain; a sibling tenant's row never does")
}

// TestSQLiteCommandStore_CreateCommandRecords_Atomic proves the batch create is
// truly transactional: a duplicate ID partway through the batch rolls back every
// record in the call, not just the one that failed (Issue #3757 required test).
func TestSQLiteCommandStore_CreateCommandRecords_Atomic(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	// Pre-seed one record so the batch below collides with it.
	require.NoError(t, store.CreateCommandRecord(ctx, testCommandRecord("batch-2")))

	batch := []*business.CommandRecord{
		testCommandRecord("batch-1"),
		testCommandRecord("batch-2"), // duplicate of the pre-seeded record — must fail
		testCommandRecord("batch-3"),
	}

	err := store.CreateCommandRecords(ctx, batch)
	require.Error(t, err, "a duplicate ID anywhere in the batch must fail the whole call")

	// batch-1 and batch-3 must NOT have been committed despite being inserted
	// before the failing row — proves the batch is one transaction.
	_, err = store.GetCommandRecord(ctx, "batch-1")
	assert.ErrorIs(t, err, business.ErrCommandNotFound, "batch-1 must not survive a rolled-back batch")
	_, err = store.GetCommandRecord(ctx, "batch-3")
	assert.ErrorIs(t, err, business.ErrCommandNotFound, "batch-3 must not survive a rolled-back batch")
}

func TestSQLiteCommandStore_CreateCommandRecords_Success(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	batch := []*business.CommandRecord{
		testCommandRecord("ok-1"),
		testCommandRecord("ok-2"),
		testCommandRecord("ok-3"),
	}
	require.NoError(t, store.CreateCommandRecords(ctx, batch))

	for _, id := range []string{"ok-1", "ok-2", "ok-3"} {
		got, err := store.GetCommandRecord(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, business.DeliveryStatusPending, got.DeliveryStatus)
	}
}

func TestSQLiteCommandStore_CreateCommandRecords_Empty(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateCommandRecords(ctx, nil))
}

// testPushRecordForCommandStore returns a minimal PushRecord for
// CreatePushAndCommandRecords tests.
func testPushRecordForCommandStore(id string) *business.PushRecord {
	return &business.PushRecord{
		ID:       id,
		ConfigID: "cfg-atomic",
		TenantID: "tenant-001",
		Version:  "v1",
		Status:   business.PushStatusInProgress,
		Data:     []byte("{}"),
	}
}

// TestSQLiteCommandStore_CreatePushAndCommandRecords_Atomic proves the seam
// handleConfigPush uses (Issue #3757, ADR-031 Decision 2 required test): the
// push record (the "config write") and its per-steward delivery rows commit or
// roll back together as one transaction, not as two independently-committing
// writes. Both failure directions are exercised: a delivery-row failure must
// roll back the push, and a push-row failure must roll back the deliveries.
func TestSQLiteCommandStore_CreatePushAndCommandRecords_Atomic(t *testing.T) {
	t.Run("delivery row failure rolls back the push record", func(t *testing.T) {
		store := newTestCommandStore(t)
		ctx := context.Background()

		// Pre-seed a command record so the batch below collides with it and fails.
		require.NoError(t, store.CreateCommandRecord(ctx, testCommandRecord("push-fail-cmd-1")))

		push := testPushRecordForCommandStore("push-rollback-1")
		records := []*business.CommandRecord{
			testCommandRecord("push-fail-cmd-1"), // duplicate — must fail the whole tx
		}

		err := store.CreatePushAndCommandRecords(ctx, push, records)
		require.Error(t, err, "a failing delivery row must fail the whole call")

		pushStore := &SQLitePushStore{db: store.db}
		_, getErr := pushStore.GetPush(ctx, "push-rollback-1")
		assert.ErrorIs(t, getErr, business.ErrPushNotFound,
			"the push record must not survive a batch whose delivery rows rolled back")
	})

	t.Run("push row failure rolls back the delivery records", func(t *testing.T) {
		store := newTestCommandStore(t)
		ctx := context.Background()

		// Pre-seed a push record so CreatePushAndCommandRecords collides with it.
		pushStore := &SQLitePushStore{db: store.db}
		require.NoError(t, pushStore.CreatePush(ctx, testPushRecordForCommandStore("push-collide-1")))

		push := testPushRecordForCommandStore("push-collide-1") // duplicate ID — must fail
		records := []*business.CommandRecord{
			testCommandRecord("push-fail-cmd-2"),
		}

		err := store.CreatePushAndCommandRecords(ctx, push, records)
		require.Error(t, err, "a failing push row must fail the whole call")

		_, getErr := store.GetCommandRecord(ctx, "push-fail-cmd-2")
		assert.ErrorIs(t, getErr, business.ErrCommandNotFound,
			"delivery rows must not survive a batch whose push row rolled back")
	})

	t.Run("push record and delivery rows commit together", func(t *testing.T) {
		store := newTestCommandStore(t)
		ctx := context.Background()

		push := testPushRecordForCommandStore("push-success-1")
		records := []*business.CommandRecord{
			testCommandRecord("push-success-cmd-1"),
			testCommandRecord("push-success-cmd-2"),
		}

		require.NoError(t, store.CreatePushAndCommandRecords(ctx, push, records))

		pushStore := &SQLitePushStore{db: store.db}
		gotPush, err := pushStore.GetPush(ctx, "push-success-1")
		require.NoError(t, err)
		assert.Equal(t, business.PushStatusInProgress, gotPush.Status)

		for _, id := range []string{"push-success-cmd-1", "push-success-cmd-2"} {
			got, err := store.GetCommandRecord(ctx, id)
			require.NoError(t, err)
			assert.Equal(t, business.DeliveryStatusPending, got.DeliveryStatus)
		}
	})
}

// TestSQLiteCommandStore_PendingSurvivesRestart proves a pending delivery row is
// never touched by anything at the storage layer across a simulated controller
// restart (Issue #3757 required test): reopening a store instance against the
// same on-disk database must not alter DeliveryStatus.
func TestSQLiteCommandStore_PendingSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/restart.db"

	db, err := openAndInit(dbPath)
	require.NoError(t, err)
	store1 := &SQLiteCommandStore{db: db}

	rec := testCommandRecord("restart-pending")
	require.NoError(t, store1.CreateCommandRecord(context.Background(), rec))
	require.NoError(t, db.Close())

	// Simulate a controller restart: reopen the same on-disk database fresh.
	db2, err := openAndInit(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db2.Close() })
	store2 := &SQLiteCommandStore{db: db2}

	got, err := store2.GetCommandRecord(context.Background(), "restart-pending")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusPending, got.DeliveryStatus,
		"a pending delivery row must survive a controller restart unmodified")
}
