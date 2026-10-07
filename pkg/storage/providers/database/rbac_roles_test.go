// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Tests for DatabaseRBACStore.DeleteRole (Issue #4322). DeleteRole acquires the
// store's write lock and then called GetRole, which acquires a read lock on the
// same sync.RWMutex — not reentrant in Go, so the read lock blocked forever
// behind the held write lock and DeleteRole never returned. These run against
// the real PostgreSQL test database and skip when it is unavailable, following
// the setupTestDatabase convention used by the sibling store tests in this
// package.
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

func newDeleteRoleTestStore(t *testing.T) *DatabaseRBACStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewDatabaseRBACStore(db, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// callWithTimeout runs fn on its own goroutine and fails the test rather than
// hanging the suite if a lock-then-call regression reintroduces the deadlock:
// without this, a reintroduced bug would hang until the package-level `go
// test` timeout, taking every other test in the package down with it.
func callWithTimeout(t *testing.T, timeout time.Duration, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		t.Fatalf("call did not return within %s — likely a reintroduced lock-then-call deadlock", timeout)
		return nil
	}
}

// TestDatabaseRBACStore_DeleteRole_DoesNotDeadlockOnClosedDB reproduces the
// deadlock at the sync.RWMutex level directly, independent of a live Postgres
// instance being reachable: the original bug was DeleteRole's write lock
// blocking its own nested GetRole read lock, and that blocking happens in the
// Go runtime before any query ever reaches the database. A *sql.DB that is
// already closed fails any query immediately (sql.ErrConnDone) rather than
// dialing out, so this test proves the lock is released even where no
// Postgres instance is available to satisfy the functional tests below.
func TestDatabaseRBACStore_DeleteRole_DoesNotDeadlockOnClosedDB(t *testing.T) {
	db, err := sql.Open("postgres", "dbname=unused")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	store := &DatabaseRBACStore{db: db, schemas: NewDatabaseSchemas()}
	ctx := ctxkeys.WithSystem(context.Background())

	err = callWithTimeout(t, 5*time.Second, func() error {
		return store.DeleteRole(ctx, "any-id")
	})
	require.Error(t, err, "a closed DB must fail the query, not hang")
}

// TestDatabaseRBACStore_DeleteRole_Succeeds guards the core deadlock regression:
// DeleteRole must return (not hang) for a role that exists in the caller's tenant.
func TestDatabaseRBACStore_DeleteRole_Succeeds(t *testing.T) {
	store := newDeleteRoleTestStore(t)
	ctx := ctxkeys.WithSystem(context.Background())

	role := &common.Role{
		Id:       "delete-role-succeeds",
		Name:     "Deletable",
		TenantId: "tenant-delete",
	}
	require.NoError(t, store.StoreRole(ctx, role))

	err := callWithTimeout(t, 5*time.Second, func() error {
		return store.DeleteRole(ctx, role.Id)
	})
	require.NoError(t, err)

	_, err = store.GetRole(ctx, role.Id)
	assert.Error(t, err, "role must actually be gone after DeleteRole")
}

// TestDatabaseRBACStore_DeleteRole_ReleasesLock proves the write lock DeleteRole
// takes is actually released: a deadlocked DeleteRole would leave the mutex held
// forever, and every subsequent store operation (including one on an unrelated
// role) would hang too.
func TestDatabaseRBACStore_DeleteRole_ReleasesLock(t *testing.T) {
	store := newDeleteRoleTestStore(t)
	ctx := ctxkeys.WithSystem(context.Background())

	role := &common.Role{
		Id:       "delete-role-releases-lock",
		Name:     "Deletable",
		TenantId: "tenant-delete",
	}
	require.NoError(t, store.StoreRole(ctx, role))

	err := callWithTimeout(t, 5*time.Second, func() error {
		return store.DeleteRole(ctx, role.Id)
	})
	require.NoError(t, err)

	other := &common.Role{
		Id:       "post-delete-store-role",
		Name:     "After Delete",
		TenantId: "tenant-delete",
	}
	err = callWithTimeout(t, 5*time.Second, func() error {
		return store.StoreRole(ctx, other)
	})
	require.NoError(t, err, "a store operation after DeleteRole must complete, proving the lock was released")

	got, err := store.GetRole(ctx, other.Id)
	require.NoError(t, err)
	assert.Equal(t, other.Id, got.Id)
}

// TestDatabaseRBACStore_DeleteRole_CrossTenantDenied preserves the H-TENANT-1
// tenant validation DeleteRole performs via GetRole (now getRoleLocked):
// deleting a role outside the caller's tenant must be refused, not just made
// non-deadlocking.
func TestDatabaseRBACStore_DeleteRole_CrossTenantDenied(t *testing.T) {
	store := newDeleteRoleTestStore(t)
	ctx := ctxkeys.WithSystem(context.Background())

	role := &common.Role{
		Id:       "cross-tenant-delete-role",
		Name:     "Owned By Tenant A",
		TenantId: "tenant-a",
	}
	require.NoError(t, store.StoreRole(ctx, role))

	callerCtx := context.WithValue(ctx, ctxkeys.TenantID, "tenant-b")
	err := callWithTimeout(t, 5*time.Second, func() error {
		return store.DeleteRole(callerCtx, role.Id)
	})
	require.Error(t, err, "deleting a role outside the caller's tenant must be refused")
	assert.ErrorIs(t, err, ErrCrossTenantAccessDenied)

	// The role must still exist: the denied delete must not have partially applied.
	got, err := store.GetRole(ctx, role.Id)
	require.NoError(t, err)
	assert.Equal(t, role.Id, got.Id)
}

// TestDatabaseRBACStore_NoCallerContextDenied guards Issue #4665: a context with
// neither a caller nor the ctxkeys.WithSystem mark is refused for a tenant's
// role, instead of being read as an internal component with unrestricted reach.
func TestDatabaseRBACStore_NoCallerContextDenied(t *testing.T) {
	store := newDeleteRoleTestStore(t)
	role := &common.Role{Id: "no-caller-role", Name: "Tenant Role", TenantId: "tenant-a"}
	require.NoError(t, store.StoreRole(ctxkeys.WithSystem(context.Background()), role))

	err := store.StoreRole(context.Background(), &common.Role{Id: "no-caller-role-2", Name: "Other", TenantId: "tenant-a"})
	assert.ErrorIs(t, err, ErrCrossTenantAccessDenied)
	_, err = store.GetRole(context.Background(), role.Id)
	assert.ErrorIs(t, err, ErrCrossTenantAccessDenied)
}
