// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database — pending-deletion tests for the PostgreSQL TenantStore
// (ADR-027 Decisions 3-4, Issue #3182).
//
// This suite mirrors pkg/storage/providers/sqlite/tenant_pending_deletion_test.go
// case for case so both TenantStore providers are held to the same contract. The
// PostgreSQL implementation differs materially from SQLite — BEGIN / SELECT ...
// FOR UPDATE / COMMIT, a recursive CTE membership comparison and a multi-statement
// delete inside one transaction — so it needs its own coverage rather than
// inheriting confidence from the SQLite suite.
//
// Every test requires a live Postgres instance and is skipped by setupTestDatabase
// when one is not reachable (the same convention plugin_test.go uses).
package database

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// purgeTenantTables removes every tenant and pending-deletion row so each test starts
// from a known state. cfgms_tenants.parent_id is ON DELETE RESTRICT, and RESTRICT is
// checked per row rather than at end-of-statement, so a single unqualified DELETE
// fails whenever a parent and its child are both in the table. Deleting leaves
// repeatedly drains the hierarchy bottom-up instead.
func purgeTenantTables(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()

	_, err := db.ExecContext(ctx, `DELETE FROM cfgms_tenant_pending_deletions`)
	require.NoError(t, err)

	for {
		res, err := db.ExecContext(ctx, `
			DELETE FROM cfgms_tenants t
			WHERE NOT EXISTS (SELECT 1 FROM cfgms_tenants c WHERE c.parent_id = t.id)`)
		require.NoError(t, err)
		n, err := res.RowsAffected()
		require.NoError(t, err)
		if n == 0 {
			return
		}
	}
}

// newTestTenantStore returns a DatabaseTenantStore backed by the test Postgres
// database, with the tenant tables created and emptied. The test is skipped when
// Postgres is unavailable.
func newTestTenantStore(t *testing.T) *DatabaseTenantStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	require.NoError(t, NewDatabaseSchemas().CreateTenantTables(ctx, db))
	purgeTenantTables(t, db)
	t.Cleanup(func() { purgeTenantTables(t, db) })

	store, err := NewDatabaseTenantStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// newTenantStoreOnSharedDB opens an additional DatabaseTenantStore against the same
// Postgres database. Each call produces a distinct *sql.DB pool, which is what the
// cross-connection race test needs: two independent connections, not two goroutines
// sharing one store's mutex.
func newTenantStoreOnSharedDB(t *testing.T) *DatabaseTenantStore {
	t.Helper()
	store, err := NewDatabaseTenantStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// pendingDeletionTenant builds a suspended TenantData suitable for the deletion pipeline.
func pendingDeletionTenant(id, parentID string) *business.TenantData {
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

// eligiblePending builds a PendingDeletion whose hold period has already elapsed.
func eligiblePending(rootID string, members ...string) *business.PendingDeletion {
	now := time.Now()
	return &business.PendingDeletion{
		SubtreeRootID:   rootID,
		RequestedBy:     "alice",
		RequestedAt:     now.Add(-721 * time.Hour),
		EligibleAt:      now.Add(-1 * time.Hour),
		State:           business.DeletionStateEligible,
		PinnedMemberIDs: members,
	}
}

func TestDatabasePendingDeletion_RequestAndGet(t *testing.T) {
	store := newTestTenantStore(t)
	ctx := context.Background()

	require.NoError(t, store.CreateTenant(ctx, pendingDeletionTenant("root", "")))

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
	assert.WithinDuration(t, now.Add(720*time.Hour), got.EligibleAt, time.Second,
		"eligible_at must survive the TIMESTAMPTZ round-trip")
}

func TestDatabasePendingDeletion_RequestDuplicate(t *testing.T) {
	store := newTestTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, pendingDeletionTenant("root", "")))

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

	// The primary-key violation must surface as the typed sentinel, not a raw pq error.
	err := store.RequestDeletion(ctx, pending)
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrPendingDeletionExists)
}

func TestDatabasePendingDeletion_GetNotFound(t *testing.T) {
	store := newTestTenantStore(t)
	ctx := context.Background()

	_, err := store.GetPendingDeletion(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound)
}

func TestDatabasePendingDeletion_Cancel(t *testing.T) {
	store := newTestTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, pendingDeletionTenant("root", "")))

	now := time.Now()
	require.NoError(t, store.RequestDeletion(ctx, &business.PendingDeletion{
		SubtreeRootID:   "root",
		RequestedBy:     "alice",
		RequestedAt:     now,
		EligibleAt:      now.Add(720 * time.Hour),
		State:           business.DeletionStateHold,
		PinnedMemberIDs: []string{"root"},
	}))
	require.NoError(t, store.CancelDeletion(ctx, "root"))

	_, err := store.GetPendingDeletion(ctx, "root")
	assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound)

	// Tenant is still present (cancel does not delete tenants).
	_, err = store.GetTenant(ctx, "root")
	require.NoError(t, err)
}

func TestDatabasePendingDeletion_CancelNotFound(t *testing.T) {
	store := newTestTenantStore(t)
	ctx := context.Background()

	err := store.CancelDeletion(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound)
}

func TestDatabasePendingDeletion_ApproveHoldNotElapsed(t *testing.T) {
	store := newTestTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, pendingDeletionTenant("root", "")))

	now := time.Now()
	require.NoError(t, store.RequestDeletion(ctx, &business.PendingDeletion{
		SubtreeRootID:   "root",
		RequestedBy:     "alice",
		RequestedAt:     now,
		EligibleAt:      now.Add(720 * time.Hour), // far future
		State:           business.DeletionStateHold,
		PinnedMemberIDs: []string{"root"},
	}))

	_, err := store.ApproveDeletion(ctx, "root", "bob", true, now)
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrHoldNotElapsed)

	// The rolled-back transaction must leave both the tenant and the record intact.
	_, err = store.GetTenant(ctx, "root")
	require.NoError(t, err)
	_, err = store.GetPendingDeletion(ctx, "root")
	require.NoError(t, err)
}

func TestDatabasePendingDeletion_ApproveSameApprover(t *testing.T) {
	store := newTestTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, pendingDeletionTenant("root", "")))
	require.NoError(t, store.RequestDeletion(ctx, eligiblePending("root", "root")))

	_, err := store.ApproveDeletion(ctx, "root", "alice", true, time.Now())
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrSameApprover)

	// Dual-control refusal must not delete anything.
	_, err = store.GetTenant(ctx, "root")
	require.NoError(t, err)
}

func TestDatabasePendingDeletion_ApproveSameApproverDualControlDisabled(t *testing.T) {
	store := newTestTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, pendingDeletionTenant("root", "")))
	require.NoError(t, store.RequestDeletion(ctx, eligiblePending("root", "root")))

	// requireDualControl=false allows the same principal to approve.
	deleted, err := store.ApproveDeletion(ctx, "root", "alice", false, time.Now())
	require.NoError(t, err)
	assert.Equal(t, []string{"root"}, deleted)

	_, err = store.GetTenant(ctx, "root")
	assert.ErrorIs(t, err, business.ErrTenantDoesNotExist)
}

func TestDatabasePendingDeletion_ApproveMembershipChanged(t *testing.T) {
	store := newTestTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, pendingDeletionTenant("root", "")))

	// Pin only "root", then add "child" after the request was recorded.
	require.NoError(t, store.RequestDeletion(ctx, eligiblePending("root", "root")))
	require.NoError(t, store.CreateTenant(ctx, pendingDeletionTenant("child", "root")))

	// The recursive CTE must see "child" and refuse the stale pinned set.
	_, err := store.ApproveDeletion(ctx, "root", "bob", true, time.Now())
	require.Error(t, err)
	assert.ErrorIs(t, err, business.ErrMembershipChanged)

	// Nothing may be deleted when membership drifted.
	_, err = store.GetTenant(ctx, "root")
	require.NoError(t, err)
	_, err = store.GetTenant(ctx, "child")
	require.NoError(t, err)
}

func TestDatabasePendingDeletion_ApproveSuccess(t *testing.T) {
	store := newTestTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, pendingDeletionTenant("root", "")))
	require.NoError(t, store.CreateTenant(ctx, pendingDeletionTenant("child", "root")))
	require.NoError(t, store.RequestDeletion(ctx, eligiblePending("root", "root", "child")))

	deleted, err := store.ApproveDeletion(ctx, "root", "bob", true, time.Now())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"root", "child"}, deleted)

	// Both tenants must be gone.
	_, err = store.GetTenant(ctx, "root")
	assert.ErrorIs(t, err, business.ErrTenantDoesNotExist)
	_, err = store.GetTenant(ctx, "child")
	assert.ErrorIs(t, err, business.ErrTenantDoesNotExist)

	// Pending record must be gone — the same transaction removed it.
	_, err = store.GetPendingDeletion(ctx, "root")
	assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound)
}

// TestDatabasePendingDeletion_DefaultTenantProtection pins where the "default" tenant
// guard lives: in the manager, NOT in the store. The store must treat "default" as an
// ordinary ID so the guard has exactly one enforcement point.
func TestDatabasePendingDeletion_DefaultTenantProtection(t *testing.T) {
	store := newTestTenantStore(t)
	ctx := context.Background()
	require.NoError(t, store.CreateTenant(ctx, pendingDeletionTenant("default", "")))
	require.NoError(t, store.RequestDeletion(ctx, eligiblePending("default", "default")))

	deleted, err := store.ApproveDeletion(ctx, "default", "bob", true, time.Now())
	require.NoError(t, err, "the store must not carry a default-tenant guard; that guard belongs to the manager")
	assert.Equal(t, []string{"default"}, deleted)

	_, err = store.GetTenant(ctx, "default")
	assert.ErrorIs(t, err, business.ErrTenantDoesNotExist)
}

// TestDatabasePendingDeletion_CrossConnectionRace is the critical atomicity test required
// by the AC: "tested with a genuine cross-connection race (two separate *sql.DB
// connections/store instances racing an approval and a restore), not two goroutines
// against one store instance".
//
// store1 and store2 are distinct DatabaseTenantStore instances, each with its own
// *sql.DB pool, so neither the Go-level mutex nor a shared connection can serialise
// them — only the BEGIN / SELECT ... FOR UPDATE / COMMIT boundary in ApproveDeletion
// can. Exactly one approval must win; the loser must fail cleanly with a typed
// sentinel and no partial deletion may be observable afterwards.
func TestDatabasePendingDeletion_CrossConnectionRace(t *testing.T) {
	store1 := newTestTenantStore(t)
	store2 := newTenantStoreOnSharedDB(t)
	ctx := context.Background()

	require.NoError(t, store1.CreateTenant(ctx, pendingDeletionTenant("root", "")))
	require.NoError(t, store1.CreateTenant(ctx, pendingDeletionTenant("child", "root")))
	require.NoError(t, store1.RequestDeletion(ctx, eligiblePending("root", "root", "child")))

	now := time.Now()
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

	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
		}
	}
	assert.Equal(t, 1, successes, "exactly one of the two concurrent approvals must succeed")

	// The loser must return a meaningful typed error, never a silent nil result.
	for i, err := range results {
		if err == nil {
			assert.ElementsMatch(t, []string{"root", "child"}, deleteds[i],
				"winning approval must return the full pinned member set")
			continue
		}
		isExpected := errors.Is(err, business.ErrPendingDeletionNotFound) ||
			errors.Is(err, business.ErrMembershipChanged)
		assert.True(t, isExpected,
			"losing approval [%d] must return ErrPendingDeletionNotFound or ErrMembershipChanged, got: %v", i, err)
	}

	// The subtree must be fully deleted — not half-deleted by an interleaved transaction.
	_, err := store1.GetTenant(ctx, "root")
	assert.ErrorIs(t, err, business.ErrTenantDoesNotExist)
	_, err = store1.GetTenant(ctx, "child")
	assert.ErrorIs(t, err, business.ErrTenantDoesNotExist)
	_, err = store1.GetPendingDeletion(ctx, "root")
	assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound)
}

// TestDatabasePendingDeletion_ApprovalVsRestore_CrossConnectionRace is the race the AC
// names literally: "racing an approval and a restore" (not two concurrent approvals). It
// races ApproveDeletion against the store-level write RestoreTenant performs (UpdateTenant
// flipping the tenant back to Active) from a second, independent *sql.DB pool.
//
// Before the fix this could silently hard-delete a tenant a concurrent restore had just
// reactivated: ApproveDeletion's membership check compared only ID sets, never status, and
// took no lock on the pinned tenant rows. FOR UPDATE now locks them, so the racing UPDATE
// either commits first (and the approval sees the new status and backs off) or blocks until
// the approval's transaction ends (and then finds the row gone). What must never happen is
// both succeeding: a tenant reported as restored while it was actually deleted underneath.
func TestDatabasePendingDeletion_ApprovalVsRestore_CrossConnectionRace(t *testing.T) {
	store1 := newTestTenantStore(t)       // performs the approval
	store2 := newTenantStoreOnSharedDB(t) // performs the restore
	ctx := context.Background()

	require.NoError(t, store1.CreateTenant(ctx, pendingDeletionTenant("root", "")))
	require.NoError(t, store1.RequestDeletion(ctx, eligiblePending("root", "root")))

	restored, err := store2.GetTenant(ctx, "root")
	require.NoError(t, err)
	restored.DirectlySuspended = false
	restored.Status = business.TenantStatusActive

	now := time.Now()
	var (
		wg         sync.WaitGroup
		approveErr error
		deleted    []string
		restoreErr error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		deleted, approveErr = store1.ApproveDeletion(ctx, "root", "bob", true, now)
	}()
	go func() {
		defer wg.Done()
		restoreErr = store2.UpdateTenant(ctx, restored)
	}()
	wg.Wait()

	switch restoreErr {
	case nil:
		// The restore committed and is visible: approval must not have deleted the
		// tenant out from under it.
		require.Error(t, approveErr, "approval must not silently delete a concurrently-restored tenant")
		assert.ErrorIs(t, approveErr, business.ErrMembershipChanged)
		tenant, err := store1.GetTenant(ctx, "root")
		require.NoError(t, err, "restored tenant must still exist")
		assert.Equal(t, business.TenantStatusActive, tenant.Status)
	default:
		// The restore lost the race — blocked out by the FOR UPDATE lock, then found
		// the row gone once it unblocked. Either way the approval must have won cleanly.
		assert.ErrorIs(t, restoreErr, business.ErrTenantDoesNotExist,
			"a losing restore must fail because the row is gone, not for an unrelated reason: %v", restoreErr)
		require.NoError(t, approveErr)
		assert.Contains(t, deleted, "root")
		_, err := store1.GetTenant(ctx, "root")
		assert.ErrorIs(t, err, business.ErrTenantDoesNotExist)
	}
}
