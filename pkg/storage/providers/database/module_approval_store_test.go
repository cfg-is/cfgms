// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
// Package database provides unit tests for the PostgreSQL ModuleApprovalStore (Issue #3886).
package database

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestModuleApprovalStore creates a ModuleApprovalStore backed by the test
// Postgres database. Skipped when Postgres is unavailable.
func newTestModuleApprovalStore(t *testing.T) *DatabaseModuleApprovalStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewDatabaseModuleApprovalStore(db, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// seedModuleApproval records addr's first status through the ingestion primitive
// and asserts the record did not already exist, so a test that means "start from
// this status" cannot silently start from another.
func seedModuleApproval(t *testing.T, store *DatabaseModuleApprovalStore, addr string, status business.ModuleApprovalStatus) {
	t.Helper()
	effective, err := store.PutApprovalStatusIfAbsent(context.Background(), addr, status)
	require.NoError(t, err)
	require.Equal(t, status, effective, "seeded address %q already carried a status", addr)
}

func TestDatabaseModuleApprovalStore_GetApprovalStatus_NotFound(t *testing.T) {
	store := newTestModuleApprovalStore(t)

	_, found, err := store.GetApprovalStatus(context.Background(), "cfgms/hyperv/0.2.1/abc")
	require.NoError(t, err)
	assert.False(t, found)
}

func TestDatabaseModuleApprovalStore_PutIfAbsentThenGet(t *testing.T) {
	store := newTestModuleApprovalStore(t)
	ctx := context.Background()

	seedModuleApproval(t, store, "cfgms/hyperv/0.2.1/abc", business.ModuleApprovalPending)

	status, found, err := store.GetApprovalStatus(ctx, "cfgms/hyperv/0.2.1/abc")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, business.ModuleApprovalPending, status)
}

// TestDatabaseModuleApprovalStore_PutIfAbsentPreservesExistingStatus is the
// provider-level guard on the ON CONFLICT DO NOTHING clause: the same bundle is
// ingested on every controller node that resolves it, so an upsert here would
// reset an operator's rejection to pending cluster-wide and let the bundle be
// auto-approved by the next node that saw it.
func TestDatabaseModuleApprovalStore_PutIfAbsentPreservesExistingStatus(t *testing.T) {
	store := newTestModuleApprovalStore(t)
	ctx := context.Background()

	seedModuleApproval(t, store, "addr-1", business.ModuleApprovalPending)
	ok, err := store.CompareAndSetApprovalStatus(ctx, "addr-1", business.ModuleApprovalPending, business.ModuleApprovalRejected)
	require.NoError(t, err)
	require.True(t, ok)

	effective, err := store.PutApprovalStatusIfAbsent(ctx, "addr-1", business.ModuleApprovalPending)
	require.NoError(t, err)
	assert.Equal(t, business.ModuleApprovalRejected, effective,
		"re-ingestion must report the standing decision, not the status it tried to write")

	status, found, err := store.GetApprovalStatus(ctx, "addr-1")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, business.ModuleApprovalRejected, status,
		"re-ingestion must not erase an operator's rejection")
}

func TestDatabaseModuleApprovalStore_CompareAndSetSucceedsOnMatch(t *testing.T) {
	store := newTestModuleApprovalStore(t)
	ctx := context.Background()
	seedModuleApproval(t, store, "addr-1", business.ModuleApprovalPending)

	ok, err := store.CompareAndSetApprovalStatus(ctx, "addr-1", business.ModuleApprovalPending, business.ModuleApprovalApproved)
	require.NoError(t, err)
	assert.True(t, ok)

	status, found, err := store.GetApprovalStatus(ctx, "addr-1")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, business.ModuleApprovalApproved, status)
}

func TestDatabaseModuleApprovalStore_CompareAndSetFailsOnMismatch(t *testing.T) {
	store := newTestModuleApprovalStore(t)
	ctx := context.Background()
	seedModuleApproval(t, store, "addr-1", business.ModuleApprovalApproved)

	ok, err := store.CompareAndSetApprovalStatus(ctx, "addr-1", business.ModuleApprovalPending, business.ModuleApprovalRejected)
	require.NoError(t, err)
	assert.False(t, ok, "a CAS against a stale expected status must not overwrite the current one")

	status, found, err := store.GetApprovalStatus(ctx, "addr-1")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, business.ModuleApprovalApproved, status, "the mismatched CAS must leave the stored status untouched")
}

func TestDatabaseModuleApprovalStore_CompareAndSetFailsWhenNoRecordExists(t *testing.T) {
	store := newTestModuleApprovalStore(t)
	ctx := context.Background()

	ok, err := store.CompareAndSetApprovalStatus(ctx, "never-set", business.ModuleApprovalPending, business.ModuleApprovalApproved)
	require.NoError(t, err)
	assert.False(t, ok, "a CAS against an address with no record must never create one")

	_, found, err := store.GetApprovalStatus(ctx, "never-set")
	require.NoError(t, err)
	assert.False(t, found)
}

func TestDatabaseModuleApprovalStore_EmptyAddressRejected(t *testing.T) {
	store := newTestModuleApprovalStore(t)
	ctx := context.Background()

	_, err := store.PutApprovalStatusIfAbsent(ctx, "", business.ModuleApprovalPending)
	assert.Error(t, err)

	_, err = store.CompareAndSetApprovalStatus(ctx, "", business.ModuleApprovalPending, business.ModuleApprovalApproved)
	assert.Error(t, err)
}

// TestDatabaseModuleApprovalStore_CrossInstanceHandoff proves a status written
// through one *DatabaseModuleApprovalStore instance is observed through a second,
// independent instance backed by the same Postgres database — simulating two
// controller nodes.
func TestDatabaseModuleApprovalStore_CrossInstanceHandoff(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, NewDatabaseSchemas().CreateModuleApprovalsTable(context.Background(), db))

	dbA := getTestDB(t)
	t.Cleanup(func() { _ = dbA.Close() })
	nodeA, err := NewDatabaseModuleApprovalStore(dbA, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeA.Close() })

	dbB := getTestDB(t)
	t.Cleanup(func() { _ = dbB.Close() })
	nodeB, err := NewDatabaseModuleApprovalStore(dbB, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeB.Close() })

	ctx := context.Background()
	seedModuleApproval(t, nodeA, "handoff-addr", business.ModuleApprovalPending)

	status, found, err := nodeB.GetApprovalStatus(ctx, "handoff-addr")
	require.NoError(t, err)
	require.True(t, found, "a status written on node A must be visible on node B without a restart")
	assert.Equal(t, business.ModuleApprovalPending, status)

	ok, err := nodeB.CompareAndSetApprovalStatus(ctx, "handoff-addr", business.ModuleApprovalPending, business.ModuleApprovalApproved)
	require.NoError(t, err)
	assert.True(t, ok)

	finalStatus, found, err := nodeA.GetApprovalStatus(ctx, "handoff-addr")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, business.ModuleApprovalApproved, finalStatus, "node A must observe node B's transition with no restart")
}

// TestDatabaseModuleApprovalStore_ConcurrentApproveReject is the [REQUIRED TEST]
// for Issue #3886: two goroutines race a CompareAndSetApprovalStatus approve vs.
// reject against the same address from pending, each opening its own connection
// to simulate two distinct controller nodes. Exactly one must win; the loser's
// call must return false with no error, never silently overwriting the winner.
// Run with -race.
func TestDatabaseModuleApprovalStore_ConcurrentApproveReject(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, NewDatabaseSchemas().CreateModuleApprovalsTable(context.Background(), db))

	seed, err := NewDatabaseModuleApprovalStore(getTestDB(t), getTestConfig())
	require.NoError(t, err)
	seedModuleApproval(t, seed, "race-addr", business.ModuleApprovalPending)
	require.NoError(t, seed.Close())

	var wg sync.WaitGroup
	wg.Add(2)

	var approveOK, rejectOK bool
	var approveErr, rejectErr error

	go func() {
		defer wg.Done()
		store, err := NewDatabaseModuleApprovalStore(getTestDB(t), getTestConfig())
		if err != nil {
			approveErr = err
			return
		}
		defer func() { _ = store.Close() }()
		approveOK, approveErr = store.CompareAndSetApprovalStatus(context.Background(), "race-addr", business.ModuleApprovalPending, business.ModuleApprovalApproved)
	}()

	go func() {
		defer wg.Done()
		store, err := NewDatabaseModuleApprovalStore(getTestDB(t), getTestConfig())
		if err != nil {
			rejectErr = err
			return
		}
		defer func() { _ = store.Close() }()
		rejectOK, rejectErr = store.CompareAndSetApprovalStatus(context.Background(), "race-addr", business.ModuleApprovalPending, business.ModuleApprovalRejected)
	}()

	wg.Wait()

	require.NoError(t, approveErr)
	require.NoError(t, rejectErr)

	assert.NotEqual(t, approveOK, rejectOK, "exactly one of the concurrent approve/reject transitions must win")

	reader, err := NewDatabaseModuleApprovalStore(db, getTestConfig())
	require.NoError(t, err)
	finalStatus, found, err := reader.GetApprovalStatus(context.Background(), "race-addr")
	require.NoError(t, err)
	require.True(t, found)

	if approveOK {
		assert.Equal(t, business.ModuleApprovalApproved, finalStatus, "the winning approve must be the persisted status")
	} else {
		assert.Equal(t, business.ModuleApprovalRejected, finalStatus, "the winning reject must be the persisted status")
	}
}
