// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Lease-store wiring tests (ADR-031 Decision 5, Issue #3760). These live in the
// external interfaces_test package because the real LeaseStore implementations
// ship in pkg/storage/providers/*, which import pkg/storage/interfaces — an
// in-package test importing them would be an import cycle.
package interfaces_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestCreateOSSStorageManager_LeaseStore verifies the OSS storage manager wires a
// real SQLite LeaseStore and that a claim round-trips through the accessor. This
// tier's lease is a single-node claim primitive: the database is a file on one
// node's disk, so the store must report itself node-local and never be accepted as
// cluster leadership authority (ADR-031 Decision 5).
func TestCreateOSSStorageManager_LeaseStore(t *testing.T) {
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "oss-leases.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	store := sm.GetLeaseStore()
	require.NotNil(t, store, "GetLeaseStore must be wired — the SQLite provider supplies it")
	assert.True(t, sm.HasStore(interfaces.StoreNameLease))
	assert.False(t, business.LeaseStoreIsNodeShared(store),
		"a per-node SQLite file excludes no other node and must not report a shared substrate")

	ctx := context.Background()
	state, err := store.AcquireOrRenew(ctx, "wiring-test-lease", "node-a", time.Minute)
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.True(t, state.Acquired)
	assert.Equal(t, "node-a", state.HolderID)
	assert.NotZero(t, state.Token, "a fenced lease must issue a non-zero token")

	read, err := store.GetLease(ctx, "wiring-test-lease")
	require.NoError(t, err)
	assert.Equal(t, state.Token, read.Token)
	assert.True(t, read.Valid)
}

// TestCreateClusterStorageManager_LeaseStore verifies the cluster (Postgres) tier —
// the tier a real multi-node deployment runs on — wires the database LeaseStore.
// Skipped when PostgreSQL is not reachable.
func TestCreateClusterStorageManager_LeaseStore(t *testing.T) {
	dsn := skipIfNoPostgres(t)

	sm, err := interfaces.CreateClusterStorageManager(dsn, testSessionHMACKey(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	store := sm.GetLeaseStore()
	require.NotNil(t, store, "GetLeaseStore must be wired — the database provider supplies it")
	assert.True(t, sm.HasStore(interfaces.StoreNameLease))
	assert.True(t, business.LeaseStoreIsNodeShared(store),
		"every cluster node connects to this one PostgreSQL instance, so its lease store must declare the shared substrate that makes cluster leadership possible")

	ctx := context.Background()
	state, err := store.AcquireOrRenew(ctx, "cluster-wiring-test-lease", "node-a", time.Minute)
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.True(t, state.Acquired)
	assert.NotZero(t, state.Token)

	require.NoError(t, store.Release(ctx, "cluster-wiring-test-lease", "node-a", state.Token))
}
