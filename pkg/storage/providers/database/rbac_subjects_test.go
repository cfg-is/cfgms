// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Tests for DatabaseRBACStore.DeleteSubject (Issue #4351). DeleteSubject acquires
// the store's write lock and then called GetSubject, which acquires a read lock on
// the same sync.RWMutex — not reentrant in Go, so the read lock blocked forever
// behind the held write lock and DeleteSubject never returned. This is the same
// shape as Issue #4322's DeleteRole fix. These run against the real PostgreSQL
// test database and skip when it is unavailable, following the setupTestDatabase
// convention used by the sibling store tests in this package.
package database

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

func newDeleteSubjectTestStore(t *testing.T) *DatabaseRBACStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewDatabaseRBACStore(db, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestDatabaseRBACStore_DeleteSubject_DoesNotDeadlockOnClosedDB reproduces the
// deadlock at the sync.RWMutex level directly, independent of a live Postgres
// instance being reachable: the original bug was DeleteSubject's write lock
// blocking its own nested GetSubject read lock, and that blocking happens in the
// Go runtime before any query ever reaches the database. A *sql.DB that is
// already closed fails any query immediately (sql.ErrConnDone) rather than
// dialing out, so this test proves the lock is released even where no
// Postgres instance is available to satisfy the functional tests below.
func TestDatabaseRBACStore_DeleteSubject_DoesNotDeadlockOnClosedDB(t *testing.T) {
	db, err := sql.Open("postgres", "dbname=unused")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	store := &DatabaseRBACStore{db: db, schemas: NewDatabaseSchemas()}
	ctx := ctxkeys.WithSystem(context.Background())

	err = callWithTimeout(t, 5*time.Second, func() error {
		return store.DeleteSubject(ctx, "any-id")
	})
	require.Error(t, err, "a closed DB must fail the query, not hang")
}

// TestDatabaseRBACStore_DeleteSubject_Succeeds guards the core deadlock
// regression: DeleteSubject must return (not hang) for a subject that exists in
// the caller's tenant.
func TestDatabaseRBACStore_DeleteSubject_Succeeds(t *testing.T) {
	store := newDeleteSubjectTestStore(t)
	ctx := ctxkeys.WithSystem(context.Background())

	subject := &common.Subject{
		Id:          "delete-subject-succeeds",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Deletable",
		TenantId:    "tenant-delete",
		IsActive:    true,
	}
	require.NoError(t, store.StoreSubject(ctx, subject))

	err := callWithTimeout(t, 5*time.Second, func() error {
		return store.DeleteSubject(ctx, subject.Id)
	})
	require.NoError(t, err)

	_, err = store.GetSubject(ctx, subject.Id)
	assert.Error(t, err, "subject must actually be gone after DeleteSubject")
}

// TestDatabaseRBACStore_DeleteSubject_ReleasesLock proves the write lock
// DeleteSubject takes is actually released: a deadlocked DeleteSubject would
// leave the mutex held forever, and every subsequent store operation (including
// one on an unrelated subject) would hang too.
func TestDatabaseRBACStore_DeleteSubject_ReleasesLock(t *testing.T) {
	store := newDeleteSubjectTestStore(t)
	ctx := ctxkeys.WithSystem(context.Background())

	subject := &common.Subject{
		Id:          "delete-subject-releases-lock",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Deletable",
		TenantId:    "tenant-delete",
		IsActive:    true,
	}
	require.NoError(t, store.StoreSubject(ctx, subject))

	err := callWithTimeout(t, 5*time.Second, func() error {
		return store.DeleteSubject(ctx, subject.Id)
	})
	require.NoError(t, err)

	other := &common.Subject{
		Id:          "post-delete-store-subject",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "After Delete",
		TenantId:    "tenant-delete",
		IsActive:    true,
	}
	err = callWithTimeout(t, 5*time.Second, func() error {
		return store.StoreSubject(ctx, other)
	})
	require.NoError(t, err, "a store operation after DeleteSubject must complete, proving the lock was released")

	got, err := store.GetSubject(ctx, other.Id)
	require.NoError(t, err)
	assert.Equal(t, other.Id, got.Id)
}

// TestDatabaseRBACStore_DeleteSubject_CrossTenantDenied preserves the H-TENANT-1
// tenant validation DeleteSubject performs via GetSubject (now
// getSubjectLocked): deleting a subject outside the caller's tenant must be
// refused, not just made non-deadlocking.
func TestDatabaseRBACStore_DeleteSubject_CrossTenantDenied(t *testing.T) {
	store := newDeleteSubjectTestStore(t)
	ctx := ctxkeys.WithSystem(context.Background())

	subject := &common.Subject{
		Id:          "cross-tenant-delete-subject",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Owned By Tenant A",
		TenantId:    "tenant-a",
		IsActive:    true,
	}
	require.NoError(t, store.StoreSubject(ctx, subject))

	callerCtx := context.WithValue(ctx, ctxkeys.TenantID, "tenant-b")
	err := callWithTimeout(t, 5*time.Second, func() error {
		return store.DeleteSubject(callerCtx, subject.Id)
	})
	require.Error(t, err, "deleting a subject outside the caller's tenant must be refused")
	assert.ErrorIs(t, err, ErrCrossTenantAccessDenied)

	// The subject must still exist: the denied delete must not have partially applied.
	got, err := store.GetSubject(ctx, subject.Id)
	require.NoError(t, err)
	assert.Equal(t, subject.Id, got.Id)
}
