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

// TestDatabasePendingRegistrationStore_ListAll_IncludesEveryStatus verifies that
// ListAll, unlike ListPending, returns entries in every lifecycle status. Storage
// migration relies on this full-fidelity enumeration path (Issue #3173).
func TestDatabasePendingRegistrationStore_ListAll_IncludesEveryStatus(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-all-pend", "tenant-db-all")))

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-all-appr", "tenant-db-all")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-all-appr", business.PendingRegistrationStatusApproved))

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-all-claim", "tenant-db-all")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-all-claim", business.PendingRegistrationStatusApproved))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-all-claim", business.PendingRegistrationStatusClaimed))

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-all-deny", "tenant-db-all")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-all-deny", business.PendingRegistrationStatusDenied))

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-all-exp", "tenant-db-all")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-all-exp", business.PendingRegistrationStatusExpired))

	entries, err := store.ListAll(ctx, "tenant-db-all")
	require.NoError(t, err)

	byID := make(map[string]*business.PendingRegistrationEntry, len(entries))
	for _, e := range entries {
		byID[e.PendingID] = e
	}
	require.Len(t, byID, 5, "ListAll must return entries in every status")
	assert.Equal(t, business.PendingRegistrationStatusPending, byID["pr-db-all-pend"].Status)
	assert.Equal(t, business.PendingRegistrationStatusApproved, byID["pr-db-all-appr"].Status)
	assert.Equal(t, business.PendingRegistrationStatusClaimed, byID["pr-db-all-claim"].Status)
	assert.Equal(t, business.PendingRegistrationStatusDenied, byID["pr-db-all-deny"].Status)
	assert.Equal(t, business.PendingRegistrationStatusExpired, byID["pr-db-all-exp"].Status)
}

// TestDatabasePendingRegistrationStore_ListAll_TenantFilter verifies ListAll's
// optional tenant_id predicate scopes results without also filtering by status.
func TestDatabasePendingRegistrationStore_ListAll_TenantFilter(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-allt-t1-pend", "tenant-db-allt-1")))

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-allt-t1-appr", "tenant-db-allt-1")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-allt-t1-appr", business.PendingRegistrationStatusApproved))

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-allt-t2-pend", "tenant-db-allt-2")))

	entries, err := store.ListAll(ctx, "tenant-db-allt-1")
	require.NoError(t, err)

	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.PendingID)
	}
	assert.ElementsMatch(t, []string{"pr-db-allt-t1-pend", "pr-db-allt-t1-appr"}, ids)
}

// TestDatabasePendingRegistrationStore_AddDuplicate verifies that adding a second
// entry with the same PendingID returns an error, matching the SQLite implementation's
// contract so the migrator's idempotent retry (which pre-checks via GetPendingByID)
// continues to work.
func TestDatabasePendingRegistrationStore_AddDuplicate(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	entry := testDBPendingEntry("pr-db-dup", "tenant-db-dup")
	require.NoError(t, store.AddPending(ctx, entry), "first insert must succeed")

	err := store.AddPending(ctx, entry)
	require.Error(t, err, "duplicate PendingID must return an error")
}

// TestDatabasePendingRegistrationStore_GetPendingByToken verifies that GetPendingByToken
// finds an entry by hashed token and returns ErrPendingRegistrationNotFound for
// an unknown token.
func TestDatabasePendingRegistrationStore_GetPendingByToken(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	entry := testDBPendingEntry("pr-db-tok", "tenant-db-tok")
	rawToken := "cfgms_reg_tok_pr-db-tok"
	entry.TokenStr = rawToken
	require.NoError(t, store.AddPending(ctx, entry))

	got, err := store.GetPendingByToken(ctx, rawToken)
	require.NoError(t, err)
	assert.Equal(t, "pr-db-tok", got.PendingID)
	assert.Equal(t, business.RegistrationTokenLookupKey(rawToken), got.TokenStr)

	_, err = store.GetPendingByToken(ctx, "no-such-token")
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}

// TestDatabasePendingRegistrationStore_UpdateStatus_NotFound verifies that
// UpdateStatus returns ErrPendingRegistrationNotFound when no row matches.
func TestDatabasePendingRegistrationStore_UpdateStatus_NotFound(t *testing.T) {
	store := newTestPendingRegistrationStore(t)

	err := store.UpdateStatus(context.Background(), "no-such-id", business.PendingRegistrationStatusApproved)
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}

// TestDatabasePendingRegistrationStore_UpdateStatus_Claimed_SetsClaimed verifies that
// transitioning to "claimed" also sets claimed_at to a non-nil time.
func TestDatabasePendingRegistrationStore_UpdateStatus_Claimed_SetsClaimed(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-claimed-at", "tenant-db-claimed")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-claimed-at", business.PendingRegistrationStatusApproved))
	require.NoError(t, store.UpdateStatus(ctx, "pr-db-claimed-at", business.PendingRegistrationStatusClaimed))

	got, err := store.GetPendingByID(ctx, "pr-db-claimed-at")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusClaimed, got.Status)
	require.NotNil(t, got.ClaimedAt, "claimed_at must be set when status transitions to claimed")
}

// TestDatabasePendingRegistrationStore_TenantScoping verifies the three-way scoping
// contract for ListPending: an unscoped caller (empty tenantID) sees all entries,
// a tenant-scoped caller sees only its own, and a cross-tenant lookup is empty.
func TestDatabasePendingRegistrationStore_TenantScoping(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-scope-t1a", "tenant-scope-1")))
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-scope-t1b", "tenant-scope-1")))
	require.NoError(t, store.AddPending(ctx, testDBPendingEntry("pr-db-scope-t2a", "tenant-scope-2")))

	// Unscoped caller sees all three.
	all, err := store.ListPending(ctx, "")
	require.NoError(t, err)
	ids := make([]string, 0, len(all))
	for _, e := range all {
		ids = append(ids, e.PendingID)
	}
	assert.ElementsMatch(t, []string{"pr-db-scope-t1a", "pr-db-scope-t1b", "pr-db-scope-t2a"}, ids, "unscoped caller must see all tenants")

	// Tenant-1 scoped caller sees only its own two entries.
	t1Entries, err := store.ListPending(ctx, "tenant-scope-1")
	require.NoError(t, err)
	require.Len(t, t1Entries, 2)
	for _, e := range t1Entries {
		assert.Equal(t, "tenant-scope-1", e.TenantID)
	}

	// Cross-tenant negative: tenant-2 caller must not see tenant-1 entries.
	t2Entries, err := store.ListPending(ctx, "tenant-scope-2")
	require.NoError(t, err)
	require.Len(t, t2Entries, 1)
	assert.Equal(t, "pr-db-scope-t2a", t2Entries[0].PendingID)
}
