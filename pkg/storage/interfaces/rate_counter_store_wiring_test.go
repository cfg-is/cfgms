// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Rate-counter-store wiring tests (ADR-031 Decision 1, Issue #3896). These cover
// CreateClusterStorageManager's RateCounterStoreCreator branch and the
// StorageManager accessors it writes through — the glue that makes the controller's
// abuse-budget counters cluster-visible, replacing Issue #3761's clusterBudgetDivisor
// even-distribution approximation with a real fleet-wide count. Mirrors
// module_approval_store_wiring_test.go's shape for ModuleApprovalStoreCreator
// (Issue #3886) and cert_store_wiring_test.go's for the #3852 pair.
//
// They live in the external interfaces_test package because the real store
// implementation ships in pkg/storage/providers/database, which imports
// pkg/storage/interfaces — an in-package test importing it would be an import cycle.
package interfaces_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// TestDatabaseProvider_SatisfiesRateCounterStoreCreator pins the type assertion
// CreateClusterStorageManager makes, on the value it actually makes it on: the
// provider the registry hands back for "database". The failed-assertion failure mode
// is silent — the store is never created, GetRateCounterStore stays nil, and every
// clustered controller quietly keeps counting abuse budgets per process.
func TestDatabaseProvider_SatisfiesRateCounterStoreCreator(t *testing.T) {
	provider, err := interfaces.GetStorageProvider("database")
	require.NoError(t, err, "the database provider must be registered (blank-imported in providers_test.go)")

	_, ok := provider.(interfaces.RateCounterStoreCreator)
	assert.True(t, ok,
		"the database provider must satisfy RateCounterStoreCreator — CreateClusterStorageManager wires the cluster-visible rate counter store through exactly this assertion")
}

// TestOSSStorageManager_RateCounterStoreUnwiredAndSettable covers the other side of
// the wiring contract, without a database: a provider that does not implement the
// creator extension leaves the accessor nil, which is the signal the server-startup
// wiring reads to leave the API server's limiters and sign throttle on their
// in-memory counters (single-node deployments see no behavioural change). The
// Set/Get accessors then round-trip a real store, since those setters are the only
// path by which the created store reaches the manager.
func TestOSSStorageManager_RateCounterStoreUnwiredAndSettable(t *testing.T) {
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "oss-rate-counter.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	assert.Nil(t, sm.GetRateCounterStore(),
		"the OSS tier's providers implement no RateCounterStoreCreator, so the accessor must stay nil and callers must fall back to their in-memory counters")

	// Round-trip through the setter with a real implementation (pkg/testing's
	// in-process reference store — no mock framework).
	store := pkgtesting.SetupTestRateCounterStore()
	sm.SetRateCounterStore(store)

	assert.Same(t, store, sm.GetRateCounterStore(),
		"GetRateCounterStore must return the store SetRateCounterStore was handed")
}

// TestCreateClusterStorageManager_RateCounterStore verifies the cluster tier — the
// tier a real multi-node deployment runs on — wires a working, cluster-visible
// counter store through CreateClusterStorageManager itself rather than through a
// hand-constructed store.
//
// Two independently created StorageManagers over the same DSN stand in for two
// controller nodes: attempts recorded through node A's wired store are counted
// against the same fixed window by node B's wired store, with no restart and no
// shared in-process state. That accumulation is the whole point of the story — it is
// what makes the configured budget fleet-wide rather than per node. Skipped when
// PostgreSQL is not reachable.
func TestCreateClusterStorageManager_RateCounterStore(t *testing.T) {
	dsn := skipIfNoPostgres(t)

	nodeA, err := interfaces.CreateClusterStorageManager(dsn, testSessionHMACKey(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeA.Close() })

	storeA := nodeA.GetRateCounterStore()
	require.NotNil(t, storeA,
		"GetRateCounterStore must be wired — the database provider supplies it, and a nil here silently drops a clustered controller back to per-node abuse budgets")

	nodeB, err := interfaces.CreateClusterStorageManager(dsn, testSessionHMACKey(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeB.Close() })

	storeB := nodeB.GetRateCounterStore()
	require.NotNil(t, storeB)

	ctx := context.Background()
	const window = time.Minute
	// Unique per run: the counter table persists rows for the length of their
	// window, so a fixed key could inherit a count from a previous run.
	key := fmt.Sprintf("wiring-test/rate-counter/%d", time.Now().UnixNano())
	t.Cleanup(func() { deleteRateCounterRow(t, dsn, key) })

	countA, retryAfterA, err := storeA.Increment(ctx, key, window)
	require.NoError(t, err)
	assert.Equal(t, 1, countA, "the first attempt through a wired store opens a fresh window at 1")
	assert.Greater(t, retryAfterA, time.Duration(0), "a fresh window must report time remaining")

	countB, _, err := storeB.Increment(ctx, key, window)
	require.NoError(t, err)
	assert.Equal(t, 2, countB,
		"an attempt recorded through one node's wired store must count against the same window on another node — otherwise the budget is per node, not fleet-wide")

	peeked, _, found, err := storeA.Peek(ctx, key, window)
	require.NoError(t, err)
	require.True(t, found, "node A must observe node B's attempt, with no restart")
	assert.Equal(t, 2, peeked)

	// Peek must not itself be an attempt: the sign-ceremony throttle reads the
	// count before deciding whether an attempt may proceed.
	peekedAgain, _, found, err := storeB.Peek(ctx, key, window)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, 2, peekedAgain, "Peek must not increment the shared count")
}

// deleteRateCounterRow removes a test key from the shared cluster database so
// repeated runs against a persistent test Postgres start clean.
func deleteRateCounterRow(t *testing.T, dsn, key string) {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Logf("cleanup: open postgres: %v", err)
		return
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DELETE FROM cfgms_rate_counters WHERE key = $1`, key); err != nil {
		t.Logf("cleanup: delete rate counter row: %v", err)
	}
}
