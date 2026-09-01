// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides unit tests for the PostgreSQL PendingRefreshStore (Issue #2329).
package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestPendingRefreshStore creates a PendingRefreshStore backed by the test Postgres
// database. The schema is initialised fresh; the test is skipped when Postgres is unavailable.
func newTestPendingRefreshStore(t *testing.T) *DatabasePendingRefreshStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreatePendingRefreshRequestsTable(ctx, db))

	store, err := NewDatabasePendingRefreshStore(db, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func makeSamplePendingRefresh(pendingID, deviceID, tenantID string) *business.PendingRefreshEntry {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &business.PendingRefreshEntry{
		PendingID:               pendingID,
		DeviceID:                deviceID,
		TenantID:                tenantID,
		SourceIP:                "10.0.0.1",
		ProvenanceMatchedFields: 3,
		ProvenanceTotalFields:   5,
		Status:                  business.PendingRefreshStatusPending,
		CreatedAt:               now,
		ExpiresAt:               now.Add(24 * time.Hour),
	}
}

// TestDatabasePendingRefreshStore_AddAndGet verifies round-trip for AddPendingRefresh
// and GetPendingRefreshByID.
func TestDatabasePendingRefreshStore_AddAndGet(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	entry := makeSamplePendingRefresh("pr-001", "dev-001", "tenant-pr-a")
	entry.ClaimBundle = []byte(`{"key":"val"}`)

	require.NoError(t, store.AddPendingRefresh(ctx, entry))

	got, err := store.GetPendingRefreshByID(ctx, "pr-001")
	require.NoError(t, err)
	assert.Equal(t, "pr-001", got.PendingID)
	assert.Equal(t, "dev-001", got.DeviceID)
	assert.Equal(t, "tenant-pr-a", got.TenantID)
	assert.Equal(t, "10.0.0.1", got.SourceIP)
	assert.Equal(t, 3, got.ProvenanceMatchedFields)
	assert.Equal(t, 5, got.ProvenanceTotalFields)
	assert.Equal(t, business.PendingRefreshStatusPending, got.Status)
	assert.Equal(t, []byte(`{"key":"val"}`), got.ClaimBundle)
	assert.Nil(t, got.ResolvedAt)
}

// TestDatabasePendingRefreshStore_NotFound verifies ErrPendingRefreshNotFound is
// returned when the record does not exist.
func TestDatabasePendingRefreshStore_NotFound(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	_, err := store.GetPendingRefreshByID(ctx, "nonexistent-pending-id")
	assert.ErrorIs(t, err, business.ErrPendingRefreshNotFound)
}

// TestDatabasePendingRefreshStore_DuplicateAdd verifies that adding an entry with
// the same PendingID returns a descriptive error.
func TestDatabasePendingRefreshStore_DuplicateAdd(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	entry := makeSamplePendingRefresh("pr-dup", "dev-dup", "tenant-pr-dup")
	require.NoError(t, store.AddPendingRefresh(ctx, entry))

	err := store.AddPendingRefresh(ctx, entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

// TestDatabasePendingRefreshStore_UpdateStatus verifies UpdateRefreshStatus changes
// the status for a non-terminal transition.
func TestDatabasePendingRefreshStore_UpdateStatus(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	entry := makeSamplePendingRefresh("pr-status", "dev-status", "tenant-pr-status")
	require.NoError(t, store.AddPendingRefresh(ctx, entry))

	require.NoError(t, store.UpdateRefreshStatus(ctx, "pr-status", business.PendingRefreshStatusExpired))

	got, err := store.GetPendingRefreshByID(ctx, "pr-status")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusExpired, got.Status)
	assert.Nil(t, got.ResolvedAt, "non-terminal status must not set resolved_at")
}

// TestDatabasePendingRefreshStore_TerminalStatusSetsResolvedAt verifies that
// terminal statuses (approved, rejected) cause resolved_at to be set.
func TestDatabasePendingRefreshStore_TerminalStatusSetsResolvedAt(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	entry := makeSamplePendingRefresh("pr-terminal", "dev-term", "tenant-pr-term")
	require.NoError(t, store.AddPendingRefresh(ctx, entry))

	require.NoError(t, store.UpdateRefreshStatus(ctx, "pr-terminal", business.PendingRefreshStatusApproved))

	got, err := store.GetPendingRefreshByID(ctx, "pr-terminal")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusApproved, got.Status)
	require.NotNil(t, got.ResolvedAt, "approved terminal status must set resolved_at")
}

// TestDatabasePendingRefreshStore_UpdateStatusNotFound verifies ErrPendingRefreshNotFound
// when updating a non-existent record.
func TestDatabasePendingRefreshStore_UpdateStatusNotFound(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	err := store.UpdateRefreshStatus(ctx, "nonexistent", business.PendingRefreshStatusApproved)
	assert.ErrorIs(t, err, business.ErrPendingRefreshNotFound)
}

// TestDatabasePendingRefreshStore_ListAll verifies ListPendingRefresh with an empty
// tenantID returns all entries across tenants.
func TestDatabasePendingRefreshStore_ListAll(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	for i, tid := range []string{"tenant-list-a", "tenant-list-b"} {
		e := makeSamplePendingRefresh(
			"pr-list-all-"+tid,
			"dev-list-"+tid,
			tid,
		)
		e.CreatedAt = time.Now().UTC().Add(time.Duration(i) * time.Millisecond)
		require.NoError(t, store.AddPendingRefresh(ctx, e))
	}

	list, err := store.ListPendingRefresh(ctx, "")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(list), 2)
}

// TestDatabasePendingRefreshStore_ListByTenant verifies that ListPendingRefresh
// with a tenantID filters results to that tenant only.
func TestDatabasePendingRefreshStore_ListByTenant(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	eA := makeSamplePendingRefresh("pr-tenant-filter-a", "dev-fa", "tenant-filter-a")
	eB := makeSamplePendingRefresh("pr-tenant-filter-b", "dev-fb", "tenant-filter-b")
	require.NoError(t, store.AddPendingRefresh(ctx, eA))
	require.NoError(t, store.AddPendingRefresh(ctx, eB))

	listA, err := store.ListPendingRefresh(ctx, "tenant-filter-a")
	require.NoError(t, err)
	for _, e := range listA {
		assert.Equal(t, "tenant-filter-a", e.TenantID)
	}
	assert.GreaterOrEqual(t, len(listA), 1)

	listB, err := store.ListPendingRefresh(ctx, "tenant-filter-b")
	require.NoError(t, err)
	for _, e := range listB {
		assert.Equal(t, "tenant-filter-b", e.TenantID)
	}
	assert.GreaterOrEqual(t, len(listB), 1)
}

// TestDatabasePendingRefreshStore_ExpireStale verifies ExpireStaleRefresh marks
// pending entries with expires_at in the past as expired.
func TestDatabasePendingRefreshStore_ExpireStale(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	stale := makeSamplePendingRefresh("pr-stale", "dev-stale", "tenant-stale")
	stale.ExpiresAt = now.Add(-time.Minute) // already expired
	require.NoError(t, store.AddPendingRefresh(ctx, stale))

	fresh := makeSamplePendingRefresh("pr-fresh", "dev-fresh", "tenant-fresh")
	fresh.ExpiresAt = now.Add(time.Hour) // not yet expired
	require.NoError(t, store.AddPendingRefresh(ctx, fresh))

	n, err := store.ExpireStaleRefresh(ctx, now)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, n, 1)

	got, err := store.GetPendingRefreshByID(ctx, "pr-stale")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusExpired, got.Status)
	require.NotNil(t, got.ResolvedAt)

	gotFresh, err := store.GetPendingRefreshByID(ctx, "pr-fresh")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusPending, gotFresh.Status)
}

// TestDatabasePendingRefreshStore_StoreClaimBundle verifies that StoreClaimBundle
// updates the claim_bundle field for an existing entry.
func TestDatabasePendingRefreshStore_StoreClaimBundle(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	entry := makeSamplePendingRefresh("pr-bundle", "dev-bundle", "tenant-bundle")
	require.NoError(t, store.AddPendingRefresh(ctx, entry))

	bundle := []byte(`{"proof":"signed-data"}`)
	require.NoError(t, store.StoreClaimBundle(ctx, "pr-bundle", bundle))

	got, err := store.GetPendingRefreshByID(ctx, "pr-bundle")
	require.NoError(t, err)
	assert.Equal(t, bundle, got.ClaimBundle)
}

// TestDatabasePendingRefreshStore_StoreClaimBundleNotFound verifies
// ErrPendingRefreshNotFound when storing a bundle for a non-existent entry.
func TestDatabasePendingRefreshStore_StoreClaimBundleNotFound(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	err := store.StoreClaimBundle(ctx, "nonexistent-pending", []byte(`{}`))
	assert.ErrorIs(t, err, business.ErrPendingRefreshNotFound)
}
