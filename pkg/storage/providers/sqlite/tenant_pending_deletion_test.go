// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newTenantStoreAtPath creates a new SQLiteTenantStore pointing at the given .db file.
// Multiple calls with the same path open distinct *sql.DB connections to the same file,
// which is what the cross-connection race test needs.
func newTenantStoreAtPath(t *testing.T, dbPath string) business.TenantStore {
	t.Helper()
	p := sqlite.NewSQLiteProvider(filepath.Dir(dbPath))
	store, err := p.CreateTenantStore(map[string]interface{}{"path": dbPath})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func suspendedTenant(id, parentID string) *business.TenantData {
	now := time.Now().UTC().Truncate(time.Second)
	return &business.TenantData{
		ID:                id,
		Name:              id,
		ParentID:          parentID,
		Status:            business.TenantStatusSuspended,
		DirectlySuspended: true,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

func TestPendingDeletion_RequestAndGet(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()

	require.NoError(t, store.CreateTenant(ctx, suspendedTenant("root", "")))

	now := time.Now()
	pending := &business.PendingDeletion{
		SubtreeRootID:   "root",
		RequestedBy:     "alice",
		RequestedAt:     now,
		EligibleAt:      now.Add(720 * time.Hour),
		State:           business.DeletionStateHold,
		PinnedMemberIDs: []string{"root"},
	}
	require.NoError(t, store.RequestDeletion(ctx, pending))

	got, err := store.GetPendingDeletion(ctx, "root")
	require.NoError(t, err)
	assert.Equal(t, "root", got.SubtreeRootID)
	assert.Equal(t, "alice", got.RequestedBy)
	assert.Equal(t, business.DeletionStateHold, got.State)
	assert.Equal(t, []string{"root"}, got.PinnedMemberIDs)
}

func TestPendingDeletion_RequestDuplicate(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, suspendedTenant("root", "")))

	now := time.Now()
	pending := &business.PendingDeletion{
		SubtreeRootID:   "root",
		RequestedBy:     "alice",
		RequestedAt:     now,
		EligibleAt:      now.Add(720 * time.Hour),
		State:           business.DeletionStateHold,
		PinnedMemberIDs: []string{"root"},
	}
	require.NoError(t, store.RequestDeletion(ctx, pending))

	err := store.RequestDeletion(ctx, pending)
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrPendingDeletionExists)
}

func TestPendingDeletion_GetNotFound(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()

	_, err := store.GetPendingDeletion(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound)
}

func TestPendingDeletion_Cancel(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, suspendedTenant("root", "")))

	now := time.Now()
	pending := &business.PendingDeletion{
		SubtreeRootID:   "root",
		RequestedBy:     "alice",
		RequestedAt:     now,
		EligibleAt:      now.Add(720 * time.Hour),
		State:           business.DeletionStateHold,
		PinnedMemberIDs: []string{"root"},
	}
	require.NoError(t, store.RequestDeletion(ctx, pending))
	require.NoError(t, store.CancelDeletion(ctx, "root"))

	_, err := store.GetPendingDeletion(ctx, "root")
	assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound)

	// Tenant is still present (cancel does not delete tenants).
	_, err = store.GetTenant(ctx, "root")
	require.NoError(t, err)
}

func TestPendingDeletion_CancelNotFound(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()

	err := store.CancelDeletion(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound)
}

func TestPendingDeletion_ApproveHoldNotElapsed(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, suspendedTenant("root", "")))

	now := time.Now()
	pending := &business.PendingDeletion{
		SubtreeRootID:   "root",
		RequestedBy:     "alice",
		RequestedAt:     now,
		EligibleAt:      now.Add(720 * time.Hour), // far future
		State:           business.DeletionStateHold,
		PinnedMemberIDs: []string{"root"},
	}
	require.NoError(t, store.RequestDeletion(ctx, pending))

	_, err := store.ApproveDeletion(ctx, "root", "bob", true, now)
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrHoldNotElapsed)
}

func TestPendingDeletion_ApproveSameApprover(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, suspendedTenant("root", "")))

	now := time.Now()
	pending := &business.PendingDeletion{
		SubtreeRootID:   "root",
		RequestedBy:     "alice",
		RequestedAt:     now.Add(-721 * time.Hour),
		EligibleAt:      now.Add(-1 * time.Hour), // already eligible
		State:           business.DeletionStateEligible,
		PinnedMemberIDs: []string{"root"},
	}
	require.NoError(t, store.RequestDeletion(ctx, pending))

	_, err := store.ApproveDeletion(ctx, "root", "alice", true, now)
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrSameApprover)
}

func TestPendingDeletion_ApproveSameApproverDualControlDisabled(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, suspendedTenant("root", "")))

	now := time.Now()
	pending := &business.PendingDeletion{
		SubtreeRootID:   "root",
		RequestedBy:     "alice",
		RequestedAt:     now.Add(-721 * time.Hour),
		EligibleAt:      now.Add(-1 * time.Hour),
		State:           business.DeletionStateEligible,
		PinnedMemberIDs: []string{"root"},
	}
	require.NoError(t, store.RequestDeletion(ctx, pending))

	// requireDualControl=false allows same principal to approve.
	deleted, err := store.ApproveDeletion(ctx, "root", "alice", false, now)
	require.NoError(t, err)
	assert.Equal(t, []string{"root"}, deleted)

	// Tenant should be gone.
	_, err = store.GetTenant(ctx, "root")
	assert.ErrorIs(t, err, business.ErrTenantDoesNotExist)
}

func TestPendingDeletion_ApproveMembershipChanged(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, suspendedTenant("root", "")))

	now := time.Now()
	// Pin only "root", but "child" was added after the request.
	pending := &business.PendingDeletion{
		SubtreeRootID:   "root",
		RequestedBy:     "alice",
		RequestedAt:     now.Add(-721 * time.Hour),
		EligibleAt:      now.Add(-1 * time.Hour),
		State:           business.DeletionStateEligible,
		PinnedMemberIDs: []string{"root"},
	}
	require.NoError(t, store.RequestDeletion(ctx, pending))

	// Add a child that was not pinned.
	require.NoError(t, store.CreateTenant(ctx, suspendedTenant("child", "root")))

	_, err := store.ApproveDeletion(ctx, "root", "bob", true, now)
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrMembershipChanged)
}

func TestPendingDeletion_ApproveSuccess(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, suspendedTenant("root", "")))
	require.NoError(t, store.CreateTenant(ctx, suspendedTenant("child", "root")))

	now := time.Now()
	pending := &business.PendingDeletion{
		SubtreeRootID:   "root",
		RequestedBy:     "alice",
		RequestedAt:     now.Add(-721 * time.Hour),
		EligibleAt:      now.Add(-1 * time.Hour),
		State:           business.DeletionStateEligible,
		PinnedMemberIDs: []string{"root", "child"},
	}
	require.NoError(t, store.RequestDeletion(ctx, pending))

	deleted, err := store.ApproveDeletion(ctx, "root", "bob", true, now)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"root", "child"}, deleted)

	// Both tenants must be gone.
	_, err = store.GetTenant(ctx, "root")
	assert.ErrorIs(t, err, business.ErrTenantDoesNotExist)
	_, err = store.GetTenant(ctx, "child")
	assert.ErrorIs(t, err, business.ErrTenantDoesNotExist)

	// Pending record must be gone.
	_, err = store.GetPendingDeletion(ctx, "root")
	assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound)
}

// TestPendingDeletion_DefaultTenantProtection pins where the "default" tenant guard
// lives: in the manager, NOT in the store. The store must treat "default" as an
// ordinary ID so the guard has exactly one enforcement point. If a store-level guard
// were ever added, ApproveDeletion would refuse here and this test would fail —
// which is the signal that the invariant moved.
func TestPendingDeletion_DefaultTenantProtection(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, suspendedTenant("default", "")))

	now := time.Now()
	require.NoError(t, store.RequestDeletion(ctx, &business.PendingDeletion{
		SubtreeRootID:   "default",
		RequestedBy:     "alice",
		RequestedAt:     now.Add(-721 * time.Hour),
		EligibleAt:      now.Add(-1 * time.Hour),
		State:           business.DeletionStateEligible,
		PinnedMemberIDs: []string{"default"},
	}))

	deleted, err := store.ApproveDeletion(ctx, "default", "bob", true, now)
	require.NoError(t, err, "the store must not carry a default-tenant guard; that guard belongs to the manager")
	assert.Equal(t, []string{"default"}, deleted)

	_, err = store.GetTenant(ctx, "default")
	assert.ErrorIs(t, err, business.ErrTenantDoesNotExist,
		"store-level approval must hard-delete the default tenant row like any other")
}

// TestPendingDeletion_CrossConnectionRace is the critical atomicity test required by the
// AC: "tested with a genuine cross-connection race (two separate *sql.DB connections/store
// instances racing an approval and a restore), not two goroutines against one store instance".
//
// Two separate *sql.DB connections (store1 and store2) both call ApproveDeletion concurrently.
// Exactly one must succeed and one must fail; neither must return a partial result.
func TestPendingDeletion_CrossConnectionRace(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "race.db")

	// store1 and store2 are distinct *sql.DB connections to the same on-disk file.
	store1 := newTenantStoreAtPath(t, dbPath)
	store2 := newTenantStoreAtPath(t, dbPath)
	ctx := context.Background()

	require.NoError(t, store1.CreateTenant(ctx, suspendedTenant("root", "")))

	now := time.Now()
	pending := &business.PendingDeletion{
		SubtreeRootID:   "root",
		RequestedBy:     "alice",
		RequestedAt:     now.Add(-721 * time.Hour),
		EligibleAt:      now.Add(-1 * time.Hour),
		State:           business.DeletionStateEligible,
		PinnedMemberIDs: []string{"root"},
	}
	require.NoError(t, store1.RequestDeletion(ctx, pending))

	var (
		wg       sync.WaitGroup
		results  [2]error
		deleteds [2][]string
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		deleteds[0], results[0] = store1.ApproveDeletion(ctx, "root", "bob", true, now)
	}()
	go func() {
		defer wg.Done()
		deleteds[1], results[1] = store2.ApproveDeletion(ctx, "root", "bob", true, now)
	}()
	wg.Wait()

	// Exactly one must succeed.
	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
		}
	}
	assert.Equal(t, 1, successes, "exactly one of the two concurrent approvals must succeed")

	// The loser must return a meaningful error (not a nil result with missing rows).
	for i, err := range results {
		if err != nil {
			isExpected := errors.Is(err, business.ErrPendingDeletionNotFound) ||
				errors.Is(err, business.ErrMembershipChanged)
			assert.True(t, isExpected,
				"losing approval [%d] must return ErrPendingDeletionNotFound or ErrMembershipChanged, got: %v", i, err)
		}
	}

	// The winner's deleted slice must be non-empty.
	for i, deleted := range deleteds {
		if results[i] == nil {
			assert.NotEmpty(t, deleted, "winning approval must return non-empty deleted list")
		}
	}
}
