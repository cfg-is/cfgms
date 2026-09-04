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

// testRefreshCSRPEM is a representative PEM CERTIFICATE REQUEST body for the
// csr_pem column (Issue #3781). Its exact bytes are what must survive the
// round-trip; the store treats the value as opaque text.
const testRefreshCSRPEM = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBTESTCSRBODY\n-----END CERTIFICATE REQUEST-----\n"

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
		CSRPEM:                  testRefreshCSRPEM,
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
	// csr_pem sits between claim_bundle and status in the INSERT and in all three
	// SELECT column lists (Issue #3781); asserting it alongside its neighbours is
	// what catches a scan-order slip in either scan function.
	assert.Equal(t, testRefreshCSRPEM, got.CSRPEM)
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
	assert.Equal(t, testRefreshCSRPEM, got2.CSRPEM,
		"storing the claim bundle must not disturb the adjacent csr_pem column")

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

// TestPendingRefreshStore_CSRPEM_ListRoundTrip covers the second scan function:
// ListPendingRefresh reads csr_pem through scanRefreshRow rather than
// scanRefreshEntry, so a column-position slip there is invisible to the
// GetPendingRefreshByID round-trip. Per-entry distinct CSR bodies also prove the
// value is not being read from a neighbouring column.
func TestPendingRefreshStore_CSRPEM_ListRoundTrip(t *testing.T) {
	store := newTestPendingRefreshStore(t)
	ctx := context.Background()

	first := testRefreshEntry("pr-csr-1", "dev-csr-1", "tenant-csr")
	first.CSRPEM = "-----BEGIN CERTIFICATE REQUEST-----\nfirst\n-----END CERTIFICATE REQUEST-----\n"
	require.NoError(t, store.AddPendingRefresh(ctx, first))

	// An entry written without a CSR must come back empty, not carrying the
	// previous row's value or a neighbouring column's.
	second := testRefreshEntry("pr-csr-2", "dev-csr-2", "tenant-csr")
	second.CSRPEM = ""
	second.CreatedAt = second.CreatedAt.Add(time.Second)
	require.NoError(t, store.AddPendingRefresh(ctx, second))

	entries, err := store.ListPendingRefresh(ctx, "tenant-csr")
	require.NoError(t, err)
	require.Len(t, entries, 2)

	byID := map[string]*business.PendingRefreshEntry{}
	for _, e := range entries {
		byID[e.PendingID] = e
	}
	require.Contains(t, byID, "pr-csr-1")
	require.Contains(t, byID, "pr-csr-2")
	assert.Equal(t, first.CSRPEM, byID["pr-csr-1"].CSRPEM)
	assert.Equal(t, business.PendingRefreshStatusPending, byID["pr-csr-1"].Status,
		"status must not be shifted by the csr_pem column")
	assert.Empty(t, byID["pr-csr-2"].CSRPEM, "an entry stored without a CSR must read back empty")
	assert.Equal(t, business.PendingRefreshStatusPending, byID["pr-csr-2"].Status)
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
