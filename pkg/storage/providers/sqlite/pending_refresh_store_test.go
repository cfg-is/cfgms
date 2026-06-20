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

// newTestPendingRefreshStore opens an in-memory SQLite store for testing.
func newTestPendingRefreshStore(t *testing.T) *SQLitePendingRefreshStore {
	t.Helper()
	db, err := openAndInit(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return &SQLitePendingRefreshStore{db: db}
}

// testRefreshEntry returns a PendingRefreshEntry with sensible defaults.
func testRefreshEntry(pendingID, deviceID, tenantID string) *business.PendingRefreshEntry {
	now := time.Now().UTC().Truncate(time.Second)
	return &business.PendingRefreshEntry{
		PendingID:               pendingID,
		DeviceID:                deviceID,
		TenantID:                tenantID,
		SourceIP:                "10.0.0.5",
		ProvenanceMatchedFields: 3,
		ProvenanceTotalFields:   5,
		Status:                  business.PendingRefreshStatusPending,
		CreatedAt:               now,
		ExpiresAt:               now.Add(65 * time.Second),
	}
}

// TestPendingRefreshStore_RoundTrip verifies Add → Get → StoreClaimBundle →
// UpdateRefreshStatus with full field fidelity (Issue #2093 AC).
func TestPendingRefreshStore_RoundTrip(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	const deviceID = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	entry := testRefreshEntry("pr-rt-1", deviceID, "tenant-rt")

	// Add
	require.NoError(t, store.AddPendingRefresh(ctx, entry))

	// Get — verify field fidelity
	got, err := store.GetPendingRefreshByID(ctx, "pr-rt-1")
	require.NoError(t, err)
	assert.Equal(t, "pr-rt-1", got.PendingID)
	assert.Equal(t, deviceID, got.DeviceID)
	assert.Equal(t, "tenant-rt", got.TenantID)
	assert.Equal(t, "10.0.0.5", got.SourceIP)
	assert.Equal(t, 3, got.ProvenanceMatchedFields)
	assert.Equal(t, 5, got.ProvenanceTotalFields)
	assert.Equal(t, business.PendingRefreshStatusPending, got.Status)
	assert.WithinDuration(t, entry.CreatedAt, got.CreatedAt, time.Second)
	assert.WithinDuration(t, entry.ExpiresAt, got.ExpiresAt, time.Second)
	assert.Nil(t, got.ResolvedAt)
	assert.Empty(t, got.ClaimBundle)

	// StoreClaimBundle
	bundle := []byte(`{"nonce":"abc123","signature":"deadbeef"}`)
	require.NoError(t, store.StoreClaimBundle(ctx, "pr-rt-1", bundle))

	got2, err := store.GetPendingRefreshByID(ctx, "pr-rt-1")
	require.NoError(t, err)
	assert.Equal(t, bundle, got2.ClaimBundle)

	// UpdateRefreshStatus to approved (terminal — sets resolved_at)
	before := time.Now().UTC()
	require.NoError(t, store.UpdateRefreshStatus(ctx, "pr-rt-1", business.PendingRefreshStatusApproved))

	got3, err := store.GetPendingRefreshByID(ctx, "pr-rt-1")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusApproved, got3.Status)
	require.NotNil(t, got3.ResolvedAt)
	assert.WithinDuration(t, before, *got3.ResolvedAt, 2*time.Second)
}

func TestPendingRefreshStore_GetByID_NotFound(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	_, err := store.GetPendingRefreshByID(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, business.ErrPendingRefreshNotFound)
}

func TestPendingRefreshStore_AddNil(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	err := store.AddPendingRefresh(context.Background(), nil)
	require.Error(t, err)
}

func TestPendingRefreshStore_AddEmptyPendingID(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	entry := testRefreshEntry("", "devid", "t1")
	err := store.AddPendingRefresh(context.Background(), entry)
	require.Error(t, err)
}

func TestPendingRefreshStore_AddEmptyDeviceID(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	entry := testRefreshEntry("pr-1", "", "t1")
	err := store.AddPendingRefresh(context.Background(), entry)
	require.Error(t, err)
}

func TestPendingRefreshStore_AddDuplicate(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	entry := testRefreshEntry("pr-dup", "devid1", "t1")
	require.NoError(t, store.AddPendingRefresh(ctx, entry))
	err := store.AddPendingRefresh(ctx, entry)
	require.Error(t, err, "duplicate pending_id must fail")
}

func TestPendingRefreshStore_UpdateRefreshStatus_NotFound(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	err := store.UpdateRefreshStatus(context.Background(), "missing", business.PendingRefreshStatusApproved)
	assert.ErrorIs(t, err, business.ErrPendingRefreshNotFound)
}

func TestPendingRefreshStore_UpdateRefreshStatus_Rejected(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	entry := testRefreshEntry("pr-rej", "devid2", "t1")
	require.NoError(t, store.AddPendingRefresh(ctx, entry))

	before := time.Now().UTC()
	require.NoError(t, store.UpdateRefreshStatus(ctx, "pr-rej", business.PendingRefreshStatusRejected))

	got, err := store.GetPendingRefreshByID(ctx, "pr-rej")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusRejected, got.Status)
	require.NotNil(t, got.ResolvedAt)
	assert.WithinDuration(t, before, *got.ResolvedAt, 2*time.Second)
}

func TestPendingRefreshStore_StoreClaimBundle_NotFound(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	err := store.StoreClaimBundle(context.Background(), "ghost", []byte("bundle"))
	assert.ErrorIs(t, err, business.ErrPendingRefreshNotFound)
}

func TestPendingRefreshStore_ListPendingRefresh_AllTenants(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPendingRefresh(ctx, testRefreshEntry("pr-a", "dev-a", "tenant-1")))
	require.NoError(t, store.AddPendingRefresh(ctx, testRefreshEntry("pr-b", "dev-b", "tenant-2")))

	entries, err := store.ListPendingRefresh(ctx, "")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestPendingRefreshStore_ListPendingRefresh_FilterByTenant(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPendingRefresh(ctx, testRefreshEntry("pr-t1", "dev-t1", "tenant-1")))
	require.NoError(t, store.AddPendingRefresh(ctx, testRefreshEntry("pr-t2", "dev-t2", "tenant-2")))

	entries, err := store.ListPendingRefresh(ctx, "tenant-2")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "pr-t2", entries[0].PendingID)
}

func TestPendingRefreshStore_ExpireStaleRefresh(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	past := time.Now().UTC().Add(-2 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)

	stale := testRefreshEntry("pr-stale", "dev-stale", "tenant-1")
	stale.ExpiresAt = past
	require.NoError(t, store.AddPendingRefresh(ctx, stale))

	active := testRefreshEntry("pr-active", "dev-active", "tenant-1")
	active.ExpiresAt = future
	require.NoError(t, store.AddPendingRefresh(ctx, active))

	count, err := store.ExpireStaleRefresh(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	got, err := store.GetPendingRefreshByID(ctx, "pr-stale")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusExpired, got.Status)
	assert.NotNil(t, got.ResolvedAt)

	activeGot, err := store.GetPendingRefreshByID(ctx, "pr-active")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusPending, activeGot.Status)
}

func TestPendingRefreshStore_ExpireStaleRefresh_SkipsNonPending(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	past := time.Now().UTC().Add(-1 * time.Hour)
	entry := testRefreshEntry("pr-appr", "dev-appr", "tenant-1")
	entry.ExpiresAt = past
	require.NoError(t, store.AddPendingRefresh(ctx, entry))
	require.NoError(t, store.UpdateRefreshStatus(ctx, "pr-appr", business.PendingRefreshStatusApproved))

	count, err := store.ExpireStaleRefresh(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, 0, count, "approved entries must not be expired")

	got, err := store.GetPendingRefreshByID(ctx, "pr-appr")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRefreshStatusApproved, got.Status)
}

func TestPendingRefreshStore_AddEmptyTenantID(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	entry := testRefreshEntry("pr-notenant", "dev-1", "")
	err := store.AddPendingRefresh(context.Background(), entry)
	require.Error(t, err, "empty tenant_id must return an error")
}
