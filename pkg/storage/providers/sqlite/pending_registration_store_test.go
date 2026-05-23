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

// newTestPendingRegistrationStore opens an in-memory SQLite store for testing.
func newTestPendingRegistrationStore(t *testing.T) *SQLitePendingRegistrationStore {
	t.Helper()
	db, err := openAndInit(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return &SQLitePendingRegistrationStore{db: db}
}

// testPendingEntry returns a PendingRegistrationEntry with sensible defaults.
func testPendingEntry(pendingID, tenantID string) *business.PendingRegistrationEntry {
	now := time.Now().UTC().Truncate(time.Second)
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

func TestPendingRegistrationStore_AddAndGetByID(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	entry := testPendingEntry("pr-1", "tenant-1")
	require.NoError(t, store.AddPending(ctx, entry))

	got, err := store.GetPendingByID(ctx, "pr-1")
	require.NoError(t, err)
	assert.Equal(t, "pr-1", got.PendingID)
	assert.Equal(t, "tenant-1", got.TenantID)
	assert.Equal(t, "cfgms_reg_tok_pr-1", got.TokenStr)
	assert.Equal(t, business.PendingRegistrationStatusPending, got.Status)
	assert.WithinDuration(t, entry.ExpiresAt, got.ExpiresAt, time.Second)
	assert.Nil(t, got.ClaimedAt)
}

func TestPendingRegistrationStore_GetByToken(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	entry := testPendingEntry("pr-tok", "tenant-1")
	require.NoError(t, store.AddPending(ctx, entry))

	got, err := store.GetPendingByToken(ctx, "cfgms_reg_tok_pr-tok")
	require.NoError(t, err)
	assert.Equal(t, "pr-tok", got.PendingID)
}

func TestPendingRegistrationStore_GetByToken_NotFound(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	_, err := store.GetPendingByToken(context.Background(), "nonexistent-token")
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}

func TestPendingRegistrationStore_AddNil(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	err := store.AddPending(context.Background(), nil)
	require.Error(t, err)
}

func TestPendingRegistrationStore_AddEmptyPendingID(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	entry := testPendingEntry("", "tenant-1")
	err := store.AddPending(context.Background(), entry)
	require.Error(t, err)
}

func TestPendingRegistrationStore_AddDuplicate(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testPendingEntry("pr-dup", "tenant-1")))
	err := store.AddPending(ctx, testPendingEntry("pr-dup", "tenant-1"))
	require.Error(t, err, "creating a record with a duplicate pending_id must fail")
}

func TestPendingRegistrationStore_GetByID_NotFound(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	_, err := store.GetPendingByID(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}

func TestPendingRegistrationStore_UpdateStatus_Approved(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testPendingEntry("pr-appr", "tenant-1")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-appr", business.PendingRegistrationStatusApproved))

	got, err := store.GetPendingByID(ctx, "pr-appr")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusApproved, got.Status)
	assert.Nil(t, got.ClaimedAt, "claimed_at must remain nil for approved status")
}

func TestPendingRegistrationStore_UpdateStatus_Claimed_SetsClaimed(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testPendingEntry("pr-claim", "tenant-1")))
	// Must be approved first — UpdateStatus("claimed") has AND status='approved' guard.
	require.NoError(t, store.UpdateStatus(ctx, "pr-claim", business.PendingRegistrationStatusApproved))

	before := time.Now().UTC()
	require.NoError(t, store.UpdateStatus(ctx, "pr-claim", business.PendingRegistrationStatusClaimed))

	got, err := store.GetPendingByID(ctx, "pr-claim")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusClaimed, got.Status)
	require.NotNil(t, got.ClaimedAt, "claimed_at must be set when status is claimed")
	assert.WithinDuration(t, before, *got.ClaimedAt, 2*time.Second)
}

func TestPendingRegistrationStore_UpdateStatus_Denied(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testPendingEntry("pr-deny", "tenant-1")))
	require.NoError(t, store.UpdateStatus(ctx, "pr-deny", business.PendingRegistrationStatusDenied))

	got, err := store.GetPendingByID(ctx, "pr-deny")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusDenied, got.Status)
}

func TestPendingRegistrationStore_UpdateStatus_NotFound(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	err := store.UpdateStatus(context.Background(), "missing", business.PendingRegistrationStatusApproved)
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}

func TestPendingRegistrationStore_ListPending_AllTenants(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testPendingEntry("pr-a", "tenant-1")))
	require.NoError(t, store.AddPending(ctx, testPendingEntry("pr-b", "tenant-2")))

	entries, err := store.ListPending(ctx, "")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestPendingRegistrationStore_ListPending_FilterByTenant(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.AddPending(ctx, testPendingEntry("pr-t1", "tenant-1")))
	require.NoError(t, store.AddPending(ctx, testPendingEntry("pr-t2", "tenant-2")))

	entries, err := store.ListPending(ctx, "tenant-2")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "pr-t2", entries[0].PendingID)
}

func TestPendingRegistrationStore_ExpireStale(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	past := time.Now().UTC().Add(-2 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)

	stale := testPendingEntry("pr-stale", "tenant-1")
	stale.ExpiresAt = past
	require.NoError(t, store.AddPending(ctx, stale))

	active := testPendingEntry("pr-active", "tenant-1")
	active.ExpiresAt = future
	require.NoError(t, store.AddPending(ctx, active))

	count, err := store.ExpireStale(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	got, err := store.GetPendingByID(ctx, "pr-stale")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusExpired, got.Status)

	activeGot, err := store.GetPendingByID(ctx, "pr-active")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusPending, activeGot.Status)
}

func TestPendingRegistrationStore_ExpireStale_SkipsNonPending(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	past := time.Now().UTC().Add(-1 * time.Hour)

	approved := testPendingEntry("pr-appr", "tenant-1")
	approved.ExpiresAt = past
	require.NoError(t, store.AddPending(ctx, approved))
	require.NoError(t, store.UpdateStatus(ctx, "pr-appr", business.PendingRegistrationStatusApproved))

	count, err := store.ExpireStale(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, 0, count, "approved entries must not be expired")

	got, err := store.GetPendingByID(ctx, "pr-appr")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusApproved, got.Status)
}

// TestPendingRegistrationStore_PersistAcrossInit verifies durability: an entry
// added to one store instance is retrievable after the store is closed and
// re-opened using the same on-disk file (Issue #1696 AC).
func TestPendingRegistrationStore_PersistAcrossInit(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/test.db"

	// Open first store instance, add an entry, then close.
	db1, err := openAndInit(dbPath)
	require.NoError(t, err)
	store1 := &SQLitePendingRegistrationStore{db: db1}

	ctx := context.Background()
	entry := testPendingEntry("pr-persist", "tenant-durable")
	require.NoError(t, store1.AddPending(ctx, entry))
	require.NoError(t, store1.UpdateStatus(ctx, "pr-persist", business.PendingRegistrationStatusApproved))
	require.NoError(t, store1.Close())

	// Open a fresh store instance pointing to the same file.
	db2, err := openAndInit(dbPath)
	require.NoError(t, err)
	store2 := &SQLitePendingRegistrationStore{db: db2}
	t.Cleanup(func() { _ = store2.Close() })

	got, err := store2.GetPendingByID(ctx, "pr-persist")
	require.NoError(t, err)
	assert.Equal(t, "pr-persist", got.PendingID)
	assert.Equal(t, "tenant-durable", got.TenantID)
	assert.Equal(t, business.PendingRegistrationStatusApproved, got.Status)
}
