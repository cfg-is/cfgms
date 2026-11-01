// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
// Package database provides unit tests for the PostgreSQL RateCounterStore (Issue #3896).
package database

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestRateCounterStore creates a RateCounterStore backed by the test
// Postgres database. Skipped when Postgres is unavailable.
func newTestRateCounterStore(t *testing.T) *DatabaseRateCounterStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewDatabaseRateCounterStore(db, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// newTestRateCounterStoreWithConfig creates a store with extra configuration
// (tracked-key cap, sweep interval) layered over the test database config.
func newTestRateCounterStoreWithConfig(t *testing.T, extra map[string]interface{}) *DatabaseRateCounterStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })

	config := getTestConfig()
	for k, v := range extra {
		config[k] = v
	}
	store, err := NewDatabaseRateCounterStore(db, config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// countRateCounterRows reports how many rows the shared table currently holds.
func countRateCounterRows(t *testing.T, store *DatabaseRateCounterStore) int {
	t.Helper()
	var rows int
	require.NoError(t, store.db.QueryRowContext(context.Background(),
		"SELECT count(*) FROM cfgms_rate_counters").Scan(&rows))
	return rows
}

// TestDatabaseRateCounterStore_PruneExpiredReclaimsDeadRows is the [REQUIRED TEST]
// for the growth bound: a key whose window has fully elapsed must be deleted, not
// left for an Increment that never comes. Keys here include the source address of
// unauthenticated routes, so an attacker rotating addresses never repeats a key and
// overwrite-in-place reclaims nothing — every distinct address would otherwise leave
// a permanent row in the shared cluster database.
func TestDatabaseRateCounterStore_PruneExpiredReclaimsDeadRows(t *testing.T) {
	store := newTestRateCounterStoreWithConfig(t, nil)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_, _, err := store.Increment(ctx, fmt.Sprintf("route-a:rotating-%d", i), 50*time.Millisecond)
		require.NoError(t, err)
	}
	_, _, err := store.Increment(ctx, "route-a:long-lived", time.Hour)
	require.NoError(t, err)
	require.Equal(t, 6, countRateCounterRows(t, store))

	time.Sleep(100 * time.Millisecond) // well past the 50ms window

	deleted, err := store.PruneExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, 5, deleted, "every row whose window has fully elapsed must be reclaimed")
	assert.Equal(t, 1, countRateCounterRows(t, store),
		"a key whose window is still open must survive the sweep")
	assert.NoError(t, store.LastPruneError())

	count, _, found, err := store.Peek(ctx, "route-a:long-lived", time.Hour)
	require.NoError(t, err)
	require.True(t, found, "pruning must not disturb a live counter")
	assert.Equal(t, 1, count)
}

// TestDatabaseRateCounterStore_IncrementSweepsExpiredRows proves the sweep is
// actually driven by traffic — the growth bound cannot depend on an operator
// remembering to call PruneExpired.
func TestDatabaseRateCounterStore_IncrementSweepsExpiredRows(t *testing.T) {
	store := newTestRateCounterStoreWithConfig(t, map[string]interface{}{
		"rate_counter_sweep_interval": 10 * time.Millisecond,
	})
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		_, _, err := store.Increment(ctx, fmt.Sprintf("route-a:swept-%d", i), 20*time.Millisecond)
		require.NoError(t, err)
	}
	require.Equal(t, 4, countRateCounterRows(t, store))

	time.Sleep(50 * time.Millisecond) // past both the window and the sweep interval

	_, _, err := store.Increment(ctx, "route-a:trigger", time.Minute)
	require.NoError(t, err)

	assert.Equal(t, 1, countRateCounterRows(t, store),
		"an Increment past the sweep interval must reclaim the dead rows, leaving only the key it just tracked")
}

// TestDatabaseRateCounterStore_IncrementFailsClosedAtCapacity is the [REQUIRED TEST]
// for the tracked-key backstop that the in-memory limiter enforces with
// maxTrackedKeys: past the cap a brand-new key is declined with
// ErrRateCounterCapacityExhausted (callers deny) rather than inserted, so a flood of
// distinct keys cannot grow the shared database without bound.
func TestDatabaseRateCounterStore_IncrementFailsClosedAtCapacity(t *testing.T) {
	const maxRows = 4
	store := newTestRateCounterStoreWithConfig(t, map[string]interface{}{
		"rate_counter_max_rows": maxRows,
		// Sweep on every call so the row count behind the cap is exact at each
		// step: the assertions are about the cap itself, not about how stale
		// the count may be between the production sweep interval's ticks.
		"rate_counter_sweep_interval": time.Nanosecond,
	})
	ctx := context.Background()

	for i := 0; i < maxRows; i++ {
		_, _, err := store.Increment(ctx, fmt.Sprintf("route-a:key-%d", i), time.Hour)
		require.NoError(t, err, "a key within the cap must be tracked")
	}

	_, retryAfter, err := store.Increment(ctx, "route-a:one-too-many", time.Hour)
	require.Error(t, err, "a brand-new key past the cap must be declined, never tracked")
	assert.ErrorIs(t, err, business.ErrRateCounterCapacityExhausted)
	assert.Greater(t, retryAfter, time.Duration(0), "a declined caller must be told how long to back off")
	assert.NotContains(t, err.Error(), "one-too-many", "the declined key must not be echoed back in the error")
	assert.Equal(t, maxRows, countRateCounterRows(t, store), "the declined key must not have been stored")

	// Keys already tracked keep counting, so live budgets stay enforced under a flood.
	count, _, err := store.Increment(ctx, "route-a:key-0", time.Hour)
	require.NoError(t, err, "a key already tracked must keep incrementing while the table is at its cap")
	assert.Equal(t, 2, count)
}

// TestDatabaseRateCounterStore_CapacityRecoversAfterPrune proves the cap is a bound
// on live keys, not a permanent ceiling: once expired rows are reclaimed, new keys
// are tracked again.
func TestDatabaseRateCounterStore_CapacityRecoversAfterPrune(t *testing.T) {
	const maxRows = 3
	store := newTestRateCounterStoreWithConfig(t, map[string]interface{}{
		"rate_counter_max_rows":       maxRows,
		"rate_counter_sweep_interval": time.Nanosecond,
	})
	ctx := context.Background()

	for i := 0; i < maxRows; i++ {
		_, _, err := store.Increment(ctx, fmt.Sprintf("route-a:short-%d", i), 50*time.Millisecond)
		require.NoError(t, err)
	}
	_, _, err := store.Increment(ctx, "route-a:denied", time.Hour)
	require.ErrorIs(t, err, business.ErrRateCounterCapacityExhausted)

	time.Sleep(100 * time.Millisecond)
	deleted, err := store.PruneExpired(ctx)
	require.NoError(t, err)
	require.Equal(t, maxRows, deleted)

	count, _, err := store.Increment(ctx, "route-a:accepted", time.Hour)
	require.NoError(t, err, "capacity reclaimed by a sweep must be usable by a new key")
	assert.Equal(t, 1, count)
}

func TestDatabaseRateCounterStore_IncrementCountsUp(t *testing.T) {
	store := newTestRateCounterStore(t)
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		count, retryAfter, err := store.Increment(ctx, "route-a:1.2.3.4", time.Minute)
		require.NoError(t, err)
		assert.Equal(t, i, count)
		assert.Greater(t, retryAfter, time.Duration(0))
		assert.LessOrEqual(t, retryAfter, time.Minute)
	}
}

func TestDatabaseRateCounterStore_IncrementEmptyKeyRejected(t *testing.T) {
	store := newTestRateCounterStore(t)
	_, _, err := store.Increment(context.Background(), "", time.Minute)
	assert.Error(t, err)
}

func TestDatabaseRateCounterStore_KeysAreIndependent(t *testing.T) {
	store := newTestRateCounterStore(t)
	ctx := context.Background()

	countA, _, err := store.Increment(ctx, "route-a:src-a", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 1, countA)

	countB, _, err := store.Increment(ctx, "route-a:src-b", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 1, countB, "an independent key must start its own window at count 1")

	countA2, _, err := store.Increment(ctx, "route-a:src-a", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 2, countA2)
}

// TestDatabaseRateCounterStore_WindowResets is the [REQUIRED TEST] proving the
// fixed-window semantics: once the configured window has fully elapsed since
// the window began, the next Increment starts a fresh window at count 1
// rather than continuing to accumulate — the same behavior sourceRateLimiter's
// in-memory record provides.
func TestDatabaseRateCounterStore_WindowResets(t *testing.T) {
	store := newTestRateCounterStore(t)
	ctx := context.Background()
	key := "route-a:window-reset"

	count, _, err := store.Increment(ctx, key, 50*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	count, _, err = store.Increment(ctx, key, 50*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	time.Sleep(100 * time.Millisecond) // well past the 50ms window

	count, _, err = store.Increment(ctx, key, 50*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "a fully-elapsed window must reset the count rather than keep accumulating")
}

func TestDatabaseRateCounterStore_PeekWithoutIncrementing(t *testing.T) {
	store := newTestRateCounterStore(t)
	ctx := context.Background()
	key := "route-a:peek"

	count, retryAfter, found, err := store.Peek(ctx, key, time.Minute)
	require.NoError(t, err)
	assert.False(t, found, "a never-incremented key must report found=false")
	assert.Equal(t, 0, count)
	assert.Zero(t, retryAfter)

	_, _, err = store.Increment(ctx, key, time.Minute)
	require.NoError(t, err)
	_, _, err = store.Increment(ctx, key, time.Minute)
	require.NoError(t, err)

	count, retryAfter, found, err = store.Peek(ctx, key, time.Minute)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, 2, count, "Peek must report the count without incrementing it")
	assert.Greater(t, retryAfter, time.Duration(0))

	count, _, found, err = store.Peek(ctx, key, time.Minute)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, 2, count, "a second Peek must observe the same count — Peek itself must never increment")
}

// TestDatabaseRateCounterStore_PeekReportsElapsedWindowAsNotFound proves Peek
// applies the same window-reset condition as Increment: a row whose window has
// fully elapsed must not be reported as a live count.
func TestDatabaseRateCounterStore_PeekReportsElapsedWindowAsNotFound(t *testing.T) {
	store := newTestRateCounterStore(t)
	ctx := context.Background()
	key := "route-a:peek-stale"

	_, _, err := store.Increment(ctx, key, 50*time.Millisecond)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	_, _, found, err := store.Peek(ctx, key, 50*time.Millisecond)
	require.NoError(t, err)
	assert.False(t, found, "a row whose window has fully elapsed must not be reported as a live count")
}

// TestDatabaseRateCounterStore_CrossInstanceHandoff proves an increment via one
// *DatabaseRateCounterStore instance is observed via a second, independent
// instance backed by the same Postgres database — simulating two controller
// nodes sharing the counter (Issue #3896 AC).
func TestDatabaseRateCounterStore_CrossInstanceHandoff(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, NewDatabaseSchemas().CreateRateCountersTable(context.Background(), db))

	dbA := getTestDB(t)
	t.Cleanup(func() { _ = dbA.Close() })
	nodeA, err := NewDatabaseRateCounterStore(dbA, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeA.Close() })

	dbB := getTestDB(t)
	t.Cleanup(func() { _ = dbB.Close() })
	nodeB, err := NewDatabaseRateCounterStore(dbB, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeB.Close() })

	ctx := context.Background()
	key := "cross-node-key"

	count, _, err := nodeA.Increment(ctx, key, time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	count, _, found, err := nodeB.Peek(ctx, key, time.Minute)
	require.NoError(t, err)
	require.True(t, found, "node A's increment must be visible to node B without a restart")
	assert.Equal(t, 1, count)

	count, _, err = nodeB.Increment(ctx, key, time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "node B's increment must build on node A's count, never restart at 1")
}

// TestDatabaseRateCounterStore_ConcurrentIncrementsNeverLoseAnAttempt is the
// [REQUIRED TEST] proving the atomicity claim: N concurrent Increment calls
// against the same key — including calls interleaved across two independent
// store instances sharing one database, modelling two controller nodes — must
// produce exactly N distinct counts (1..N with no duplicates), never a lost
// update from an unserialized read-modify-write. Run with -race.
func TestDatabaseRateCounterStore_ConcurrentIncrementsNeverLoseAnAttempt(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, NewDatabaseSchemas().CreateRateCountersTable(context.Background(), db))

	dbA := getTestDB(t)
	t.Cleanup(func() { _ = dbA.Close() })
	nodeA, err := NewDatabaseRateCounterStore(dbA, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeA.Close() })

	dbB := getTestDB(t)
	t.Cleanup(func() { _ = dbB.Close() })
	nodeB, err := NewDatabaseRateCounterStore(dbB, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeB.Close() })

	const attempts = 40
	key := "concurrent-key"
	ctx := context.Background()

	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[int]int) // count -> occurrences
	var errCount int32

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		node := nodeA
		if i%2 == 0 {
			node = nodeB
		}
		go func(node *DatabaseRateCounterStore) {
			defer wg.Done()
			count, _, incErr := node.Increment(ctx, key, time.Minute)
			if incErr != nil {
				atomic.AddInt32(&errCount, 1)
				return
			}
			mu.Lock()
			seen[count]++
			mu.Unlock()
		}(node)
	}
	wg.Wait()

	require.Equal(t, int32(0), errCount, "no Increment call should fail against a reachable database")
	require.Len(t, seen, attempts, "every count from 1..%d must appear exactly once — a repeated count means two callers lost the race and observed the same value", attempts)
	for count := 1; count <= attempts; count++ {
		assert.Equal(t, 1, seen[count], "count %d must have been observed exactly once", count)
	}
}

// TestClampRetryAfter_BoundsToWindow pins the [0, window] contract on the
// remaining-window duration Increment and Peek return.
//
// The upper bound is the one that matters and the one that was missing: a
// PostgreSQL timestamptz stores microseconds while a Go time.Time carries
// nanoseconds, so writing now into window_start rounds it to the nearest
// microsecond and the value read back can land up to 500ns after now. The
// resulting window - now.Sub(windowStart) is then slightly more than a full
// window. CI observed 1m0.000000096s against a 1m window and evicted the PR
// from the merge queue. Callers surface this value as Retry-After, whose
// contract is at most one window, so it is clamped at the source.
func TestClampRetryAfter_BoundsToWindow(t *testing.T) {
	const window = time.Minute

	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"negative window already elapsed", -5 * time.Second, 0},
		{"zero", 0, 0},
		{"inside the window", 30 * time.Second, 30 * time.Second},
		{"exactly one window", window, window},
		{"timestamptz rounding overshoot", window + 96*time.Nanosecond, window},
		{"half-microsecond overshoot ceiling", window + 500*time.Nanosecond, window},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clampRetryAfter(tt.in, window)
			assert.Equal(t, tt.want, got)
			assert.GreaterOrEqual(t, got, time.Duration(0), "retryAfter must never be negative")
			assert.LessOrEqual(t, got, window, "retryAfter must never exceed one window")
		})
	}
}
