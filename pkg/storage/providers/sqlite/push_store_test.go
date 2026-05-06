// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestPushStore creates an in-memory SQLite PushStore for tests.
func newTestPushStore(t *testing.T) *SQLitePushStore {
	t.Helper()
	db, err := openAndInit(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return &SQLitePushStore{db: db}
}

// testPushRecord returns a PushRecord with sensible defaults.
func testPushRecord(id string) *business.PushRecord {
	return &business.PushRecord{
		ID:          id,
		ConfigID:    "cfg-" + id,
		TenantID:    "tenant-1",
		Version:     "v1.0.0",
		Status:      business.PushStatusPending,
		InitiatedBy: "user@example.com",
		Data:        []byte(`{"steward_id":"` + id + `"}`),
	}
}

func TestPushStore_CreateAndRetrieve(t *testing.T) {
	store := newTestPushStore(t)
	ctx := context.Background()

	rec := testPushRecord("push-001")
	require.NoError(t, store.CreatePush(ctx, rec))

	got, err := store.GetPush(ctx, "push-001")
	require.NoError(t, err)

	assert.Equal(t, "push-001", got.ID)
	assert.Equal(t, "cfg-push-001", got.ConfigID)
	assert.Equal(t, "tenant-1", got.TenantID)
	assert.Equal(t, "v1.0.0", got.Version)
	assert.Equal(t, business.PushStatusPending, got.Status)
	assert.Equal(t, "user@example.com", got.InitiatedBy)
	assert.Equal(t, rec.Data, got.Data)
	assert.False(t, got.CreatedAt.IsZero(), "CreatedAt should be set")
	assert.False(t, got.UpdatedAt.IsZero(), "UpdatedAt should be set")
}

func TestPushStore_GetPendingPushes(t *testing.T) {
	store := newTestPushStore(t)
	ctx := context.Background()

	pending := testPushRecord("push-pending")
	pending.Status = business.PushStatusPending
	require.NoError(t, store.CreatePush(ctx, pending))

	inProgress := testPushRecord("push-inprogress")
	inProgress.Status = business.PushStatusInProgress
	require.NoError(t, store.CreatePush(ctx, inProgress))

	completed := testPushRecord("push-completed")
	completed.Status = business.PushStatusCompleted
	require.NoError(t, store.CreatePush(ctx, completed))

	results, err := store.GetPendingPushes(ctx)
	require.NoError(t, err)
	require.Len(t, results, 2, "only pending and in_progress records should be returned")

	ids := make(map[string]bool)
	for _, r := range results {
		ids[r.ID] = true
	}
	assert.True(t, ids["push-pending"], "pending record should be included")
	assert.True(t, ids["push-inprogress"], "in_progress record should be included")
	assert.False(t, ids["push-completed"], "completed record should not be included")
}

func TestPushStore_GetPendingPushes_FailedExcluded(t *testing.T) {
	store := newTestPushStore(t)
	ctx := context.Background()

	failed := testPushRecord("push-failed")
	failed.Status = business.PushStatusFailed
	require.NoError(t, store.CreatePush(ctx, failed))

	results, err := store.GetPendingPushes(ctx)
	require.NoError(t, err)
	assert.Empty(t, results, "failed records should not be returned")
}

func TestPushStore_GetPendingPushes_Empty(t *testing.T) {
	store := newTestPushStore(t)
	results, err := store.GetPendingPushes(context.Background())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestPushStore_GetPush_NotFound(t *testing.T) {
	store := newTestPushStore(t)
	_, err := store.GetPush(context.Background(), "does-not-exist")
	assert.ErrorIs(t, err, business.ErrPushNotFound)
}

func TestPushStore_UpdatePushStatus(t *testing.T) {
	store := newTestPushStore(t)
	ctx := context.Background()

	require.NoError(t, store.CreatePush(ctx, testPushRecord("push-upd")))
	require.NoError(t, store.UpdatePushStatus(ctx, "push-upd", business.PushStatusInProgress))

	got, err := store.GetPush(ctx, "push-upd")
	require.NoError(t, err)
	assert.Equal(t, business.PushStatusInProgress, got.Status)
	assert.False(t, got.UpdatedAt.IsZero())
}

func TestPushStore_UpdatePushStatus_NotFound(t *testing.T) {
	store := newTestPushStore(t)
	err := store.UpdatePushStatus(context.Background(), "ghost", business.PushStatusFailed)
	assert.ErrorIs(t, err, business.ErrPushNotFound)
}

func TestPushStore_CreatePush_NilRecord(t *testing.T) {
	store := newTestPushStore(t)
	err := store.CreatePush(context.Background(), nil)
	assert.Error(t, err)
}

func TestPushStore_CreatePush_EmptyID(t *testing.T) {
	store := newTestPushStore(t)
	err := store.CreatePush(context.Background(), &business.PushRecord{})
	assert.Error(t, err)
}

func TestPushStore_RestartPersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "push.db")
	ctx := context.Background()

	db1, err := openAndInit(dbPath)
	require.NoError(t, err)
	store1 := &SQLitePushStore{db: db1}

	require.NoError(t, store1.CreatePush(ctx, testPushRecord("push-persist")))
	require.NoError(t, store1.UpdatePushStatus(ctx, "push-persist", business.PushStatusInProgress))
	require.NoError(t, store1.Close())

	db2, err := openAndInit(dbPath)
	require.NoError(t, err)
	store2 := &SQLitePushStore{db: db2}
	defer func() { _ = store2.Close() }()

	got, err := store2.GetPush(ctx, "push-persist")
	require.NoError(t, err)
	assert.Equal(t, "push-persist", got.ID)
	assert.Equal(t, business.PushStatusInProgress, got.Status)

	pending, err := store2.GetPendingPushes(ctx)
	require.NoError(t, err)
	assert.Len(t, pending, 1)
	assert.Equal(t, "push-persist", pending[0].ID)
}

func TestPushStore_Initialize(t *testing.T) {
	store := newTestPushStore(t)
	assert.NoError(t, store.Initialize(context.Background()))
	assert.NoError(t, store.Initialize(context.Background()))
}
