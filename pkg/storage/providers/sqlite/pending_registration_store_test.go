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

// newTestPendingRegistrationStore creates an in-memory SQLite PendingRegistrationStore for tests.
func newTestPendingRegistrationStore(t *testing.T) *SQLitePendingRegistrationStore {
	t.Helper()
	db, err := openAndInit(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return &SQLitePendingRegistrationStore{db: db}
}

// testPendingRecord returns a PendingRegistrationData with sensible defaults.
func testPendingRecord(id string) *business.PendingRegistrationData {
	now := time.Now().UTC()
	return &business.PendingRegistrationData{
		ID:          id,
		StewardID:   "",
		TenantID:    "tenant-1",
		SourceIP:    "10.0.0.5",
		TokenPrefix: "tok-abcd",
		Status:      business.PendingRegistrationStatusPending,
		CreatedAt:   now,
		ExpiresAt:   now.Add(24 * time.Hour),
	}
}

func TestPendingRegistrationStore_CreateAndGet(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	record := testPendingRecord("pr-1")
	require.NoError(t, store.CreatePending(ctx, record))

	got, err := store.GetPending(ctx, "pr-1")
	require.NoError(t, err)
	assert.Equal(t, "pr-1", got.ID)
	assert.Equal(t, "tenant-1", got.TenantID)
	assert.Equal(t, "10.0.0.5", got.SourceIP)
	assert.Equal(t, "tok-abcd", got.TokenPrefix)
	assert.Equal(t, business.PendingRegistrationStatusPending, got.Status)
	assert.WithinDuration(t, record.ExpiresAt, got.ExpiresAt, time.Second)
}

func TestPendingRegistrationStore_CreateNil(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	err := store.CreatePending(context.Background(), nil)
	require.Error(t, err)
}

func TestPendingRegistrationStore_CreateEmptyID(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	record := testPendingRecord("")
	err := store.CreatePending(context.Background(), record)
	require.Error(t, err)
}

func TestPendingRegistrationStore_CreateDuplicate(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.CreatePending(ctx, testPendingRecord("pr-dup")))
	err := store.CreatePending(ctx, testPendingRecord("pr-dup"))
	require.Error(t, err, "creating a record with a duplicate ID must fail")
}

func TestPendingRegistrationStore_GetNotFound(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	_, err := store.GetPending(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}

func TestPendingRegistrationStore_ListNoFilter(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.CreatePending(ctx, testPendingRecord("pr-a")))
	require.NoError(t, store.CreatePending(ctx, testPendingRecord("pr-b")))

	records, err := store.ListPending(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, records, 2)
}

func TestPendingRegistrationStore_ListFilterByStatus(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.CreatePending(ctx, testPendingRecord("pr-pending")))
	denied := testPendingRecord("pr-denied")
	denied.Status = business.PendingRegistrationStatusDenied
	require.NoError(t, store.CreatePending(ctx, denied))

	pending := business.PendingRegistrationStatusPending
	records, err := store.ListPending(ctx, &business.PendingRegistrationFilter{Status: &pending})
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "pr-pending", records[0].ID)
}

func TestPendingRegistrationStore_ListFilterByTenant(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.CreatePending(ctx, testPendingRecord("pr-t1")))
	other := testPendingRecord("pr-t2")
	other.TenantID = "tenant-2"
	require.NoError(t, store.CreatePending(ctx, other))

	tenant := "tenant-2"
	records, err := store.ListPending(ctx, &business.PendingRegistrationFilter{TenantID: &tenant})
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "pr-t2", records[0].ID)
}

func TestPendingRegistrationStore_ListFilterExpired(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	expired := testPendingRecord("pr-expired")
	expired.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
	require.NoError(t, store.CreatePending(ctx, expired))

	active := testPendingRecord("pr-active")
	active.ExpiresAt = time.Now().UTC().Add(24 * time.Hour)
	require.NoError(t, store.CreatePending(ctx, active))

	now := time.Now().UTC()
	records, err := store.ListPending(ctx, &business.PendingRegistrationFilter{ExpiresBeforeOrAt: &now})
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "pr-expired", records[0].ID)
}

func TestPendingRegistrationStore_UpdateStatus(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.CreatePending(ctx, testPendingRecord("pr-upd")))
	require.NoError(t, store.UpdatePendingStatus(ctx, "pr-upd", business.PendingRegistrationStatusDenied, "policy violation"))

	got, err := store.GetPending(ctx, "pr-upd")
	require.NoError(t, err)
	assert.Equal(t, business.PendingRegistrationStatusDenied, got.Status)
	assert.Equal(t, "policy violation", got.DenyReason)
}

func TestPendingRegistrationStore_UpdateStatusNotFound(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	err := store.UpdatePendingStatus(context.Background(), "missing", business.PendingRegistrationStatusApproved, "")
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}

func TestPendingRegistrationStore_Delete(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	ctx := context.Background()

	require.NoError(t, store.CreatePending(ctx, testPendingRecord("pr-del")))
	require.NoError(t, store.DeletePending(ctx, "pr-del"))

	_, err := store.GetPending(ctx, "pr-del")
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}

func TestPendingRegistrationStore_DeleteNotFound(t *testing.T) {
	store := newTestPendingRegistrationStore(t)
	err := store.DeletePending(context.Background(), "missing")
	assert.ErrorIs(t, err, business.ErrPendingRegistrationNotFound)
}
