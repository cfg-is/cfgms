// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides unit tests for the PostgreSQL PendingRegistrationStore
// (Issue #1696, status-filtered ListPending: Issue #3173).
package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestPendingRegistrationStore creates a PendingRegistrationStore backed by the test
// Postgres database. The schema is initialised fresh; the test is skipped when Postgres
// is unavailable (matches the established pattern for this package).
func newTestPendingRegistrationStore(t *testing.T) *DatabasePendingRegistrationStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	require.NoError(t, schemas.CreatePendingRegistrationsTable(context.Background(), db))

	store, err := NewDatabasePendingRegistrationStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// testDBPendingEntry returns a PendingRegistrationEntry with sensible defaults.
func testDBPendingEntry(pendingID, tenantID string) *business.PendingRegistrationEntry {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &business.PendingRegistrationEntry{
		PendingID:    pendingID,
		StewardID:    "steward-" + pendingID,
		TenantID:     tenantID,
		TokenStr:     "cfgms_reg_tok_" + pendingID,
		SourceIP:     "10.0.0.5",
		RegisteredAt: now,
		ExpiresAt:    now.Add(5 * 24 * time.Hour),
		Status:       business.PendingRegistrationStatusPending,
	}
}

// TestDatabasePendingRegistrationStore_AddAndGetByID verifies round-trip persistence
// including the token lookup-key hashing performed on write.
func TestDatabasePendingRegistrationStore_AddAndGetByID(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	entry := testDBPendingEntry("pr-db-1", "tenant-db-1")
	require.NoError(t, store.AddPending(ctx, entry))

	got, err := store.GetPendingByID(ctx, "pr-db-1")
	require.NoError(t, err)
	assert.Equal(t, "pr-db-1", got.PendingID)
	assert.Equal(t, "steward-pr-db-1", got.StewardID)
	assert.Equal(t, "tenant-db-1", got.TenantID)
	assert.Equal(t, business.RegistrationTokenLookupKey("cfgms_reg_tok_pr-db-1"), got.TokenStr)
	assert.Equal(t, business.PendingRegistrationStatusPending, got.Status)
	assert.Nil(t, got.ClaimedAt)
}

// TestDatabasePendingRegistrationStore_GetByIDNotFound verifies the sentinel error.
func TestDatabasePendingRegistrationStore_GetByIDNotFound(t *testing.T) {
	store := newTestPendingRegistrationStore(t)

	_, err := store.GetPendingByID(context.Background(), "no-such-pending-id")
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}

// TestDatabasePendingRegistrationStore_UpdateStatus verifies a status transition is
// durable and observable through GetPendingByID.
func TestDatabasePendingRegistrationStore_UpdateStatus(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-status", "tenant-db-status")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-status", business.PendingRegistrationStatusApproved))

	got, err := store.GetPendingByID(ctx, "pr-db-status")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusApproved, got.Status)
}

// TestDatabasePendingRegistrationStore_ListPending_ExcludesResolved verifies that
// ListPending returns only entries in "pending" status — approved, denied, claimed,
// and expired entries must be excluded (Issue #3173).
func TestDatabasePendingRegistrationStore_ListPending_ExcludesResolved(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	// pending — must appear
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-keep", "tenant-db-resolved")))

	// approved — must NOT appear
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-appr", "tenant-db-resolved")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-appr", business.PendingRegistrationStatusApproved))

	// claimed — must NOT appear (claimed is only reachable from approved)
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-claim", "tenant-db-resolved")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-claim", business.PendingRegistrationStatusApproved))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-claim", business.PendingRegistrationStatusClaimed))

	// denied — must NOT appear
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-deny", "tenant-db-resolved")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-deny", business.PendingRegistrationStatusDenied))

	// expired — must NOT appear
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-exp", "tenant-db-resolved")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-exp", business.PendingRegistrationStatusExpired))

	entries, err := store.ListPending(ctx, "")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "pr-db-keep", entries[0].PendingID)
	assert.Equal(t, business.PendingRegistrationStatusPending, entries[0].Status)
}

// TestDatabasePendingRegistrationStore_ListPending_PendingWithTenantFilter is a
// regression guard: tenant scoping must still work after the status filter was added
// (Issue #3173).
func TestDatabasePendingRegistrationStore_ListPending_PendingWithTenantFilter(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	// pending in tenant-1 — must appear
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-t1-pend", "tenant-db-1")))

	// approved in tenant-1 — must NOT appear (resolved)
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-t1-appr", "tenant-db-1")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-t1-appr", business.PendingRegistrationStatusApproved))

	// pending in tenant-2 — must NOT appear (different tenant)
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-t2-pend", "tenant-db-2")))

	entries, err := store.ListPending(ctx, "tenant-db-1")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "pr-db-t1-pend", entries[0].PendingID)
	assert.Equal(t, business.PendingRegistrationStatusPending, entries[0].Status)
}

// TestDatabasePendingRegistrationStore_ListPending_OrdersByRegisteredAt verifies the
// ascending registered_at ordering contract survives the status predicate.
func TestDatabasePendingRegistrationStore_ListPending_OrdersByRegisteredAt(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Millisecond)

	newest := testDBPendingEntry("pr-db-order-newest", "tenant-db-order")
	newest.RegisteredAt = now
	require.NoError(t, store.AddPending(ctx, newest))

	oldest := testDBPendingEntry("pr-db-order-oldest", "tenant-db-order")
	oldest.RegisteredAt = now.Add(-2 * time.Hour)
	require.NoError(t, store.AddPending(ctx, oldest))

	middle := testDBPendingEntry("pr-db-order-middle", "tenant-db-order")
	middle.RegisteredAt = now.Add(-time.Hour)
	require.NoError(t, store.AddPending(ctx, middle))

	entries, err := store.ListPending(ctx, "tenant-db-order")
	require.NoError(t, err)
	require.Len(t, entries, 3)
	assert.Equal(t, "pr-db-order-oldest", entries[0].PendingID)
	assert.Equal(t, "pr-db-order-middle", entries[1].PendingID)
	assert.Equal(t, "pr-db-order-newest", entries[2].PendingID)
}

// TestDatabasePendingRegistrationStore_ExpireStale_RemovesFromListPending verifies the
// end-to-end effect of expiry on the operator list view.
func TestDatabasePendingRegistrationStore_ExpireStale_RemovesFromListPending(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	now := time.Now().UTC()

	stale := testDBPendingEntry("pr-db-stale", "tenant-db-expiry")
	stale.ExpiresAt = now.Add(-time.Minute)
	require.NoError(t, store.AddPending(ctx, stale))

	fresh := testDBPendingEntry("pr-db-fresh", "tenant-db-expiry")
	fresh.ExpiresAt = now.Add(time.Hour)
	require.NoError(t, store.AddPending(ctx, fresh))

	n, err := store.ExpireStale(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	entries, err := store.ListPending(ctx, "tenant-db-expiry")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "pr-db-fresh", entries[0].PendingID)
}
