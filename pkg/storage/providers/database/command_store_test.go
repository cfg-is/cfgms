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

	pending, err := store.ListPendingDeliveries(ctx, "sw-pd-db")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, "pd-db-2", pending[0].ID)
}

func TestDatabaseCommandStore_ListPendingDeliveries_EmptyStewardID(t *testing.T) {
	store := newTestCommandStore(t)
	ctx := context.Background()
	_, err := store.ListPendingDeliveries(ctx, "")
	require.Error(t, err)
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

	// Simulate a controller restart: open a brand new DatabaseCommandStore
	// instance against the same DSN. NewDatabaseCommandStore re-runs
	// initializeSchema exactly as a fresh process boot would.
	dsn := buildTestDSN()
	store2, err := NewDatabaseCommandStore(dsn, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store2.Close() })

	got, err := store2.GetCommandRecord(ctx, "restart-pending-db")
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusPending, got.DeliveryStatus,
		"a pending delivery row must survive a controller restart unmodified")
	assert.Equal(t, business.CommandStatusPending, got.Status)
}
