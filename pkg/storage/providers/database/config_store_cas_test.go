// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Tests for DatabaseConfigStore.CompareAndSwapConfig, the conditional-write
// primitive a cross-node compare-and-set is built on (Issue #3775). These run
// against the real PostgreSQL test database and skip when it is unavailable,
// following the setupTestDatabase convention used by the sibling store tests in
// this package — the guarantee under test is PostgreSQL's own concurrency
// behaviour, so there is nothing to learn from exercising it against anything else.
package database

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

func newCASTestStore(t *testing.T) *DatabaseConfigStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewDatabaseConfigStore(db, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func casTestEntry(name, data string) *cfgconfig.ConfigEntry {
	return &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{
			TenantID:  "tenant-cas",
			Namespace: "secrets",
			Name:      name,
		},
		Data:      []byte(data),
		CreatedBy: "cas-test",
		UpdatedBy: "cas-test",
	}
}

// TestDatabaseConfigStore_CompareAndSwapConfig_Semantics covers create-if-absent,
// rejection of a stale expected version, and version chaining.
func TestDatabaseConfigStore_CompareAndSwapConfig_Semantics(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}
	store := newCASTestStore(t)
	ctx := context.Background()

	v1, ok, err := store.CompareAndSwapConfig(ctx, casTestEntry("claim", "v1"), 0)
	require.NoError(t, err)
	require.True(t, ok, "create-if-absent must succeed against a key that has never been written")
	assert.Equal(t, int64(1), v1)

	// A second create-if-absent must lose, with a nil error — the caller has to be
	// able to tell a lost race from a storage failure.
	_, ok, err = store.CompareAndSwapConfig(ctx, casTestEntry("claim", "attacker"), 0)
	require.NoError(t, err, "a lost race must be ok=false with a nil error")
	assert.False(t, ok)

	stored, err := store.GetConfig(ctx, casTestEntry("claim", "").Key)
	require.NoError(t, err)
	assert.Equal(t, "v1", string(stored.Data), "the losing write must never be observed")
	assert.Equal(t, int64(1), stored.Version)

	// A stale non-zero expected version is refused the same way.
	_, ok, err = store.CompareAndSwapConfig(ctx, casTestEntry("claim", "stale"), 99)
	require.NoError(t, err)
	assert.False(t, ok)

	v2, ok, err := store.CompareAndSwapConfig(ctx, casTestEntry("claim", "v2"), v1)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, int64(2), v2)

	stored, err = store.GetConfig(ctx, casTestEntry("claim", "").Key)
	require.NoError(t, err)
	assert.Equal(t, "v2", string(stored.Data))
	assert.Equal(t, int64(2), stored.Version)
}

// TestDatabaseConfigStore_CompareAndSwapConfig_ConcurrentCreateHasOneWinner is the
// proof that matters for cluster mode: many callers — standing in for many
// controller nodes, since they reach PostgreSQL over independent connections
// exactly as separate nodes do — race the same create-if-absent, and exactly one
// wins.
//
// StoreConfig cannot pass this test by construction: it reads the current version
// and then upserts, so two callers both read N and both commit N+1. That lost
// update is what would let two nodes both win one approved->collected transition
// and both mint a client certificate.
func TestDatabaseConfigStore_CompareAndSwapConfig_ConcurrentCreateHasOneWinner(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}
	store := newCASTestStore(t)
	ctx := context.Background()

	const attempts = 12
	var wg sync.WaitGroup
	var successes int64
	errs := make([]error, attempts)

	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			_, ok, err := store.CompareAndSwapConfig(ctx, casTestEntry("race", fmt.Sprintf("node-%d", i)), 0)
			errs[i] = err
			if ok {
				atomic.AddInt64(&successes, 1)
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "attempt %d must report a lost race as ok=false, never an error", i)
	}
	assert.Equal(t, int64(1), successes,
		"exactly one of %d concurrent create-if-absent writes for the same key must succeed", attempts)

	stored, err := store.GetConfig(ctx, casTestEntry("race", "").Key)
	require.NoError(t, err)
	assert.Equal(t, int64(1), stored.Version, "the winner's write must be the only one applied")
}

// TestDatabaseConfigStore_CompareAndSwapConfig_ConcurrentUpdateHasOneWinner proves
// the same for the non-zero expected version: several callers holding the same
// version N cannot all advance it.
func TestDatabaseConfigStore_CompareAndSwapConfig_ConcurrentUpdateHasOneWinner(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}
	store := newCASTestStore(t)
	ctx := context.Background()

	base, ok, err := store.CompareAndSwapConfig(ctx, casTestEntry("update-race", "seed"), 0)
	require.NoError(t, err)
	require.True(t, ok)

	const attempts = 12
	var wg sync.WaitGroup
	var successes int64
	errs := make([]error, attempts)

	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			_, ok, err := store.CompareAndSwapConfig(ctx, casTestEntry("update-race", fmt.Sprintf("node-%d", i)), base)
			errs[i] = err
			if ok {
				atomic.AddInt64(&successes, 1)
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "attempt %d must report a lost race as ok=false, never an error", i)
	}
	assert.Equal(t, int64(1), successes,
		"exactly one of %d concurrent writers holding version %d must win", attempts, base)

	stored, err := store.GetConfig(ctx, casTestEntry("update-race", "").Key)
	require.NoError(t, err)
	assert.Equal(t, base+1, stored.Version, "the version must advance by exactly one, not once per writer")
}

// TestDatabaseConfigStore_ImplementsConditionalConfigStore pins the capability
// signal callers gate on. SOPSSecretStore decides at construction whether its
// compare-and-swap is cluster-atomic purely from this type assertion, so losing the
// interface here would silently downgrade the controller's cluster guarantee.
func TestDatabaseConfigStore_ImplementsConditionalConfigStore(t *testing.T) {
	var store interface{} = (*DatabaseConfigStore)(nil)
	_, ok := store.(cfgconfig.ConditionalConfigStore)
	assert.True(t, ok, "DatabaseConfigStore must implement cfgconfig.ConditionalConfigStore")
}
