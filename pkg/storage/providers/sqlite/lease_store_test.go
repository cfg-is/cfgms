// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func newTestLeaseStore(t *testing.T) *SQLiteLeaseStore {
	t.Helper()
	db, err := openAndInit(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return &SQLiteLeaseStore{db: db}
}

func TestSQLiteLeaseStore_GetLease_NotFound(t *testing.T) {
	store := newTestLeaseStore(t)
	_, err := store.GetLease(context.Background(), "never-acquired")
	require.ErrorIs(t, err, business.ErrLeaseNotFound)
}

func TestSQLiteLeaseStore_AcquireOrRenew_FirstAcquisition(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	state, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Second)
	require.NoError(t, err)
	assert.True(t, state.Acquired)
	assert.Equal(t, uint64(1), state.Token)
}

func TestSQLiteLeaseStore_AcquireOrRenew_RenewByCurrentHolderKeepsToken(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Second)
	require.NoError(t, err)

	second, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Second)
	require.NoError(t, err)
	assert.True(t, second.Acquired)
	assert.Equal(t, first.Token, second.Token)
}

func TestSQLiteLeaseStore_AcquireOrRenew_ContendedByDifferentHolder(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Minute)
	require.NoError(t, err)
	require.True(t, first.Acquired)

	second, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-2", time.Minute)
	require.NoError(t, err)
	assert.False(t, second.Acquired)
	assert.Equal(t, "holder-1", second.HolderID)
	assert.Equal(t, first.Token, second.Token)
}

func TestSQLiteLeaseStore_AcquireOrRenew_ExpiredLeaseAllowsTakeoverWithHigherToken(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", 10*time.Millisecond)
	require.NoError(t, err)
	require.True(t, first.Acquired)

	time.Sleep(20 * time.Millisecond)

	second, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-2", time.Second)
	require.NoError(t, err)
	require.True(t, second.Acquired)
	assert.Greater(t, second.Token, first.Token)
}

// The store reports validity itself, evaluated against the clock that wrote
// expires_at, so callers never compare the stored timestamp to their own
// notion of "now" (business.LeaseStore's "one clock only" contract). For this
// provider that clock is the local process's, since the store and its data
// live in one process.
func TestSQLiteLeaseStore_ReportsValidityAgainstItsOwnClock(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	fresh, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Minute)
	require.NoError(t, err)
	assert.True(t, fresh.Valid, "a freshly acquired lease must be reported valid")

	read, err := store.GetLease(ctx, "singleton-x")
	require.NoError(t, err)
	assert.True(t, read.Valid)

	shortLived, err := store.AcquireOrRenew(ctx, "singleton-y", "holder-1", 10*time.Millisecond)
	require.NoError(t, err)
	require.True(t, shortLived.Acquired)
	time.Sleep(30 * time.Millisecond)

	expired, err := store.GetLease(ctx, "singleton-y")
	require.NoError(t, err)
	assert.False(t, expired.Valid, "a lapsed lease must be reported invalid")
	assert.Equal(t, "holder-1", expired.HolderID, "the last holder stays visible on an expired row")
}

func TestSQLiteLeaseStore_Release_PreservesTokenAsHighWaterMark(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Minute)
	require.NoError(t, err)

	require.NoError(t, store.Release(ctx, "singleton-x", "holder-1", first.Token))

	second, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-2", time.Minute)
	require.NoError(t, err)
	require.True(t, second.Acquired)
	assert.Greater(t, second.Token, first.Token)
}

func TestSQLiteLeaseStore_Release_StaleTokenIsNoOp(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	first, err := store.AcquireOrRenew(ctx, "singleton-x", "holder-1", time.Minute)
	require.NoError(t, err)

	require.NoError(t, store.Release(ctx, "singleton-x", "holder-1", first.Token+1))

	current, err := store.GetLease(ctx, "singleton-x")
	require.NoError(t, err)
	assert.Equal(t, "holder-1", current.HolderID)
	assert.Equal(t, first.Token, current.Token)
}

// TestSQLiteLeaseStore_ConcurrentAcquire_ExactlyOneWinner exercises the same
// UPSERT-with-WHERE contention path as the PostgreSQL provider's required
// concurrency test, against the shared in-memory SQLite connection pool
// (openAndInit pins in-memory DBs to a single connection; SQLite itself
// serializes writers at the database level).
func TestSQLiteLeaseStore_ConcurrentAcquire_ExactlyOneWinner(t *testing.T) {
	store := newTestLeaseStore(t)
	ctx := context.Background()

	const n = 10
	var wg sync.WaitGroup
	results := make([]*business.LeaseState, n)
	errs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			holderID := "holder-" + string(rune('A'+i))
			results[i], errs[i] = store.AcquireOrRenew(ctx, "contended", holderID, time.Minute)
		}(i)
	}
	wg.Wait()

	winners := 0
	for i := 0; i < n; i++ {
		require.NoError(t, errs[i])
		if results[i].Acquired {
			winners++
		}
	}
	assert.Equal(t, 1, winners, "exactly one goroutine must win contention for a fresh lease")
}
