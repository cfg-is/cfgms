// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides delivery-lifecycle tests for DatabaseCommandStore
// (Issue #3757, ADR-031 Decision 2). Requires a live Postgres instance (same
// setup as plugin_test.go / stores_integration_test.go) and is skipped when
// CFGMS_TEST_DB_PASSWORD is unset, unreachable, or short mode is active.
package database

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ---------------------------------------------------------------------------
// Delivery lifecycle
// ---------------------------------------------------------------------------

func TestDatabaseCommandStore_CreateRecord_DeliveryStatusDefaultsPending(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	cmd := makeSampleCommand("delivery-default", "sw-delivery", "tenant-delivery")
	require.NoError(t, store.CreateCommandRecord(ctx, cmd))

	got, err := store.GetCommandRecord(ctx, "delivery-default")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusPending, got.DeliveryStatus)
	assert.Empty(t, got.DeliveryDetail)
}

func TestDatabaseCommandStore_UpdateDeliveryStatus(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	cmd := makeSampleCommand("delivery-lc", "sw-delivery-lc", "tenant-delivery-lc")
	require.NoError(t, store.CreateCommandRecord(ctx, cmd))

	require.NoError(t, store.UpdateDeliveryStatus(ctx, "delivery-lc", business.DeliveryStatusDelivered, ""))
	got, err := store.GetCommandRecord(ctx, "delivery-lc")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusDelivered, got.DeliveryStatus)
	// Execution status is untouched by a delivery-status transition.
	assert.Equal(t, business.CommandStatusPending, got.Status)

	require.NoError(t, store.UpdateDeliveryStatus(ctx, "delivery-lc", business.DeliveryStatusFailed, "transport: connection refused"))
	got, err = store.GetCommandRecord(ctx, "delivery-lc")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusFailed, got.DeliveryStatus)
	assert.Equal(t, "transport: connection refused", got.DeliveryDetail)
}

func TestDatabaseCommandStore_UpdateDeliveryStatus_NotFound(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	err := store.UpdateDeliveryStatus(ctx, "nonexistent-delivery", business.DeliveryStatusDelivered, "")
	assert.ErrorIs(t, err, business.ErrCommandNotFound)
}

func TestDatabaseCommandStore_ListPendingDeliveries(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	r1 := makeSampleCommand("pd-db-1", "sw-pd-db", "tenant-pd-db")
	r2 := makeSampleCommand("pd-db-2", "sw-pd-db", "tenant-pd-db")
	require.NoError(t, store.CreateCommandRecord(ctx, r1))
	require.NoError(t, store.CreateCommandRecord(ctx, r2))
	require.NoError(t, store.UpdateDeliveryStatus(ctx, "pd-db-1", business.DeliveryStatusDelivered, ""))

	pending, err := store.ListPendingDeliveries(ctx, "sw-pd-db", "tenant-pd-db")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, "pd-db-2", pending[0].ID)
}

func TestDatabaseCommandStore_ListPendingDeliveries_EmptyStewardID(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	_, err := store.ListPendingDeliveries(ctx, "", "tenant-pd-db")
	require.Error(t, err)
}

// TestDatabaseCommandStore_ListPendingDeliveries_EmptyTenantFailsClosed proves
// the tenant argument is mandatory rather than an optional narrowing.
func TestDatabaseCommandStore_ListPendingDeliveries_EmptyTenantFailsClosed(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	_, err := store.ListPendingDeliveries(ctx, "sw-pd-db", "")
	require.ErrorIs(t, err, business.ErrCommandTenantIDRequired)
}

// TestDatabaseCommandStore_ListPendingDeliveries_TenantScoped proves the query
// filters on tenant_id as well as steward_id. RLS does not cover this read — it
// runs without setTenantLocal and the SELECT policy is permissive when
// app.current_tenant is unset — so a row left behind by a previous tenant
// binding (Issue #2341) would otherwise be returned to the steward's new tenant.
// Records stamped with an ancestor of the steward's tenant (subtree pushes) must
// still drain.
func TestDatabaseCommandStore_ListPendingDeliveries_TenantScoped(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	own := makeSampleCommand("pd-scope-own", "sw-pd-scope", "root/msp-a/client-1")
	ancestor := makeSampleCommand("pd-scope-ancestor", "sw-pd-scope", "root/msp-a")
	foreign := makeSampleCommand("pd-scope-foreign", "sw-pd-scope", "root/msp-b/client-9")
	for _, rec := range []*business.CommandRecord{own, ancestor, foreign} {
		require.NoError(t, store.CreateCommandRecord(ctx, rec))
	}

	pending, err := store.ListPendingDeliveries(ctx, "sw-pd-scope", "root/msp-a/client-1")
	require.NoError(t, err)

	ids := make([]string, 0, len(pending))
	for _, rec := range pending {
		ids = append(ids, rec.ID)
	}
	assert.ElementsMatch(t, []string{"pd-scope-own", "pd-scope-ancestor"}, ids,
		"a record stamped with another tenant is never returned for this steward")
}

// TestDatabaseCommandStore_CreateCommandRecords_Atomic proves the batch create
// is truly transactional at the database layer: a duplicate ID partway through
// the batch rolls back every record in the call, not just the offending one
// (Issue #3757 required test — "transactional atomicity: the state-change write
// and its delivery row commit or roll back together").
func TestDatabaseCommandStore_CreateCommandRecords_Atomic(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	// Pre-seed one record so the batch below collides with it.
	require.NoError(t, store.CreateCommandRecord(ctx, makeSampleCommand("atomic-2", "sw-atomic", "tenant-atomic")))

	batch := []*business.CommandRecord{
		makeSampleCommand("atomic-1", "sw-atomic", "tenant-atomic"),
		makeSampleCommand("atomic-2", "sw-atomic", "tenant-atomic"), // duplicate — must fail
		makeSampleCommand("atomic-3", "sw-atomic", "tenant-atomic"),
	}

	err := store.CreateCommandRecords(ctx, batch)
	require.Error(t, err, "a duplicate ID anywhere in the batch must fail the whole call")

	// atomic-1 and atomic-3 must NOT have been committed despite being inserted
	// before the failing row — proves the batch is one transaction, all-or-nothing.
	_, err = store.GetCommandRecord(ctx, "atomic-1")
	assert.ErrorIs(t, err, business.ErrCommandNotFound, "atomic-1 must not survive a rolled-back batch")
	_, err = store.GetCommandRecord(ctx, "atomic-3")
	assert.ErrorIs(t, err, business.ErrCommandNotFound, "atomic-3 must not survive a rolled-back batch")
}

func TestDatabaseCommandStore_CreateCommandRecords_Success(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()

	batch := []*business.CommandRecord{
		makeSampleCommand("batch-ok-1", "sw-batch-ok", "tenant-batch-ok"),
		makeSampleCommand("batch-ok-2", "sw-batch-ok", "tenant-batch-ok"),
		makeSampleCommand("batch-ok-3", "sw-batch-ok", "tenant-batch-ok"),
	}
	require.NoError(t, store.CreateCommandRecords(ctx, batch))

	for _, id := range []string{"batch-ok-1", "batch-ok-2", "batch-ok-3"} {
		got, err := store.GetCommandRecord(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, business.DeliveryStatusPending, got.DeliveryStatus)
	}
}

// testPushRecordForCommandStore returns a minimal PushRecord for
// CreatePushAndCommandRecords tests.
func testPushRecordForCommandStore(id string) *business.PushRecord {
	return &business.PushRecord{
		ID:       id,
		ConfigID: "cfg-atomic",
		TenantID: "tenant-atomic",
		Version:  "v1",
		Status:   business.PushStatusInProgress,
	}
}

// TestDatabaseCommandStore_CreatePushAndCommandRecords_Atomic proves the seam
// handleConfigPush uses (Issue #3757, ADR-031 Decision 2 required test): the
// push record (the "config write") and its per-steward delivery rows commit or
// roll back together as one transaction, not as two independently-committing
// writes. Both failure directions are exercised: a delivery-row failure must
// roll back the push, and a push-row failure must roll back the deliveries.
func TestDatabaseCommandStore_CreatePushAndCommandRecords_Atomic(t *testing.T) {
	t.Run("delivery row failure rolls back the push record", func(t *testing.T) {
		store := newTestCommandStore(t)
		ctx := context.Background()

		require.NoError(t, store.CreateCommandRecord(ctx, makeSampleCommand("push-fail-cmd-1", "sw-atomic", "tenant-atomic")))

		push := testPushRecordForCommandStore("push-rollback-1")
		records := []*business.CommandRecord{
			makeSampleCommand("push-fail-cmd-1", "sw-atomic", "tenant-atomic"), // duplicate — must fail the whole tx
		}

		err := store.CreatePushAndCommandRecords(ctx, push, records)
		require.Error(t, err, "a failing delivery row must fail the whole call")

		pushStore := &DatabasePushStore{db: store.db}
		_, getErr := pushStore.GetPush(ctx, "push-rollback-1")
		assert.ErrorIs(t, getErr, business.ErrPushNotFound,
			"the push record must not survive a batch whose delivery rows rolled back")
	})

	t.Run("push row failure rolls back the delivery records", func(t *testing.T) {
		store := newTestCommandStore(t)
		ctx := context.Background()

		pushStore := &DatabasePushStore{db: store.db}
		require.NoError(t, pushStore.CreatePush(ctx, testPushRecordForCommandStore("push-collide-1")))

		push := testPushRecordForCommandStore("push-collide-1") // duplicate ID — must fail
		records := []*business.CommandRecord{
			makeSampleCommand("push-fail-cmd-2", "sw-atomic", "tenant-atomic"),
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
			makeSampleCommand("push-success-cmd-1", "sw-atomic", "tenant-atomic"),
			makeSampleCommand("push-success-cmd-2", "sw-atomic", "tenant-atomic"),
		}

		require.NoError(t, store.CreatePushAndCommandRecords(ctx, push, records))

		pushStore := &DatabasePushStore{db: store.db}
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

// TestDatabaseCommandStore_PendingSurvivesRestart proves a pending delivery row
// is never touched by anything at the storage layer across a simulated
// controller restart (Issue #3757 required test): opening a fresh
// DatabaseCommandStore instance against the same database — re-running
// initializeSchema exactly as a real process restart would — must not alter a
// pre-existing row's DeliveryStatus. This is the storage-layer half of "a
// controller restart never fails a queued delivery" (ADR-031 Decision 2); the
// database provider has no startup sweep at all, unlike the steward-side
// execution-status sweep in features/steward/commands.Handler.
func TestDatabaseCommandStore_PendingSurvivesRestart(t *testing.T) {
	store1 := newTestCommandStore(t)
	ctx := context.Background()

	cmd := makeSampleCommand("restart-pending-db", "sw-restart-db", "tenant-restart-db")
	require.NoError(t, store1.CreateCommandRecord(ctx, cmd))

	// Simulate a controller restart: open a brand new *sql.DB against the same
	// test database (not setupTestDatabase, which would drop store1's tables)
	// and construct a fresh DatabaseCommandStore on it. NewDatabaseCommandStore
	// re-runs initializeSchema exactly as a fresh process boot would.
	db2 := getTestDB(t)
	t.Cleanup(func() { _ = db2.Close() })
	store2, err := NewDatabaseCommandStore(db2, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store2.Close() })

	got, err := store2.GetCommandRecord(ctx, "restart-pending-db")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusPending, got.DeliveryStatus,
		"a pending delivery row must survive a controller restart unmodified")
	assert.Equal(t, business.CommandStatusPending, got.Status)
}
