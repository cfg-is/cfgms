// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

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

func TestPushStore_ListPushesByConfigID(t *testing.T) {
	t.Run("returns pushes in descending created_at order", func(t *testing.T) {
		store := newTestPushStore(t)
		ctx := context.Background()

		r1 := testPushRecord("push-a")
		r1.ConfigID = "cfg-target"
		r1.Status = business.PushStatusCompleted
		require.NoError(t, store.CreatePush(ctx, r1))

		r2 := testPushRecord("push-b")
		r2.ConfigID = "cfg-target"
		r2.Status = business.PushStatusFailed
		require.NoError(t, store.CreatePush(ctx, r2))

		results, err := store.ListPushesByConfigID(ctx, "cfg-target", "tenant-1")
		require.NoError(t, err)
		require.Len(t, results, 2)
		// Most recent (push-b was inserted last) comes first.
		assert.Equal(t, "push-b", results[0].ID)
		assert.Equal(t, "push-a", results[1].ID)
	})

	t.Run("breaks created_at ties by insertion order (most recent first)", func(t *testing.T) {
		// Two pushes created at the identical timestamp — the situation that
		// arises on low-resolution clocks (e.g. Windows CI) when records are
		// inserted in quick succession. ORDER BY created_at alone is then
		// nondeterministic; the rowid tiebreaker must keep the last-inserted
		// record first.
		store := newTestPushStore(t)
		ctx := context.Background()

		sameTime := time.Date(2026, 5, 21, 8, 0, 0, 0, time.UTC)

		r1 := testPushRecord("push-a")
		r1.ConfigID = "cfg-target"
		r1.CreatedAt = sameTime
		require.NoError(t, store.CreatePush(ctx, r1))

		r2 := testPushRecord("push-b")
		r2.ConfigID = "cfg-target"
		r2.CreatedAt = sameTime
		require.NoError(t, store.CreatePush(ctx, r2))

		results, err := store.ListPushesByConfigID(ctx, "cfg-target", "tenant-1")
		require.NoError(t, err)
		require.Len(t, results, 2)
		assert.Equal(t, "push-b", results[0].ID, "last-inserted record must come first on a created_at tie")
		assert.Equal(t, "push-a", results[1].ID)
	})

	t.Run("returns empty slice for unknown config ID", func(t *testing.T) {
		store := newTestPushStore(t)
		results, err := store.ListPushesByConfigID(context.Background(), "no-such-config", "tenant-1")
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("does not return pushes for other config IDs", func(t *testing.T) {
		store := newTestPushStore(t)
		ctx := context.Background()

		target := testPushRecord("push-target")
		target.ConfigID = "cfg-target"
		require.NoError(t, store.CreatePush(ctx, target))

		other := testPushRecord("push-other")
		other.ConfigID = "cfg-other"
		require.NoError(t, store.CreatePush(ctx, other))

		results, err := store.ListPushesByConfigID(ctx, "cfg-target", "tenant-1")
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "push-target", results[0].ID)
	})

	t.Run("does not return pushes for other tenants (cross-tenant isolation)", func(t *testing.T) {
		store := newTestPushStore(t)
		ctx := context.Background()

		tenantA := testPushRecord("push-tenant-a")
		tenantA.ConfigID = "cfg-shared"
		tenantA.TenantID = "tenant-a"
		require.NoError(t, store.CreatePush(ctx, tenantA))

		tenantB := testPushRecord("push-tenant-b")
		tenantB.ConfigID = "cfg-shared"
		tenantB.TenantID = "tenant-b"
		require.NoError(t, store.CreatePush(ctx, tenantB))

		results, err := store.ListPushesByConfigID(ctx, "cfg-shared", "tenant-a")
		require.NoError(t, err)
		require.Len(t, results, 1, "must not return records from other tenants")
		assert.Equal(t, "push-tenant-a", results[0].ID)
		assert.Equal(t, "tenant-a", results[0].TenantID)
	})
}
