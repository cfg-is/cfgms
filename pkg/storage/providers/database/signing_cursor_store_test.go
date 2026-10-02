// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides unit tests for the PostgreSQL SigningCursorStore (Issue #3852).
package database

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
)

// newTestSigningCursorStore creates a SigningCursorStore backed by the test
// Postgres database. Skipped when Postgres is unavailable.
func newTestSigningCursorStore(t *testing.T) *DatabaseSigningCursorStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewDatabaseSigningCursorStore(db, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestDatabaseSigningCursorStore_LoadCursor_NoRotationYet(t *testing.T) {
	store := newTestSigningCursorStore(t)

	cursor, err := store.LoadCursor(context.Background())
	require.NoError(t, err)
	assert.Nil(t, cursor, "no rotation has occurred yet, so LoadCursor must return nil")
}

func TestDatabaseSigningCursorStore_FirstTransition(t *testing.T) {
	store := newTestSigningCursorStore(t)
	ctx := context.Background()

	cursor, err := store.TransitionCursor(ctx, "serial-v1", 30, false)
	require.NoError(t, err)
	require.NotNil(t, cursor)
	assert.Equal(t, "serial-v1", cursor.CurrentSerial)
	assert.Empty(t, cursor.RotatingSerial)
	assert.Equal(t, 30, cursor.OverlapWindowDays)

	loaded, err := store.LoadCursor(ctx)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "serial-v1", loaded.CurrentSerial)
}

func TestDatabaseSigningCursorStore_BlockedByActiveRotation(t *testing.T) {
	store := newTestSigningCursorStore(t)
	ctx := context.Background()

	_, err := store.TransitionCursor(ctx, "serial-v1", 30, false)
	require.NoError(t, err)

	// Second transition immediately after: RotatingSerial is empty (first
	// transition never sets it), so this one succeeds and sets RotatingSerial.
	_, err = store.TransitionCursor(ctx, "serial-v2", 30, false)
	require.NoError(t, err)

	// Third transition: RotatingSerial is now set and the 30-day overlap
	// window has not elapsed, so this must be rejected.
	_, err = store.TransitionCursor(ctx, "serial-v3", 30, false)
	require.Error(t, err)
	assert.True(t, errors.Is(err, certinterfaces.ErrSigningRotationInProgress))

	loaded, err := store.LoadCursor(ctx)
	require.NoError(t, err)
	assert.Equal(t, "serial-v2", loaded.CurrentSerial, "cursor must be unchanged after a rejected transition")
	assert.Equal(t, "serial-v1", loaded.RotatingSerial)
}

func TestDatabaseSigningCursorStore_ForceBypassesInProgress(t *testing.T) {
	store := newTestSigningCursorStore(t)
	ctx := context.Background()

	_, err := store.TransitionCursor(ctx, "serial-v1", 30, false)
	require.NoError(t, err)
	_, err = store.TransitionCursor(ctx, "serial-v2", 30, false)
	require.NoError(t, err)

	// Non-force is blocked (RotatingSerial set, window open).
	_, err = store.TransitionCursor(ctx, "serial-v3", 30, false)
	require.Error(t, err)

	// Force succeeds despite the active in-progress cursor.
	cursor, err := store.TransitionCursor(ctx, "serial-v3", 7, true)
	require.NoError(t, err)
	require.NotNil(t, cursor)
	assert.Equal(t, "serial-v3", cursor.CurrentSerial)
	assert.Equal(t, "serial-v2", cursor.RotatingSerial)
	assert.Equal(t, 7, cursor.OverlapWindowDays)
}

func TestDatabaseSigningCursorStore_EmptySerialRejected(t *testing.T) {
	store := newTestSigningCursorStore(t)
	_, err := store.TransitionCursor(context.Background(), "", 30, false)
	assert.Error(t, err)
}

// TestDatabaseSigningCursorStore_CrossInstanceHandoff proves the AC4-shaped
// requirement for the signing cursor: a transition via one
// *DatabaseSigningCursorStore instance is observed via a second, independent
// instance backed by the same Postgres database — simulating two controller
// nodes.
func TestDatabaseSigningCursorStore_CrossInstanceHandoff(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, NewDatabaseSchemas().CreateSigningCursorTable(context.Background(), db))

	dbA := getTestDB(t)
	t.Cleanup(func() { _ = dbA.Close() })
	nodeA, err := NewDatabaseSigningCursorStore(dbA, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeA.Close() })

	dbB := getTestDB(t)
	t.Cleanup(func() { _ = dbB.Close() })
	nodeB, err := NewDatabaseSigningCursorStore(dbB, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeB.Close() })

	ctx := context.Background()
	_, err = nodeA.TransitionCursor(ctx, "issued-by-a", 30, false)
	require.NoError(t, err)

	loaded, err := nodeB.LoadCursor(ctx)
	require.NoError(t, err)
	require.NotNil(t, loaded, "a cursor transitioned on node A must be visible on node B without a restart")
	assert.Equal(t, "issued-by-a", loaded.CurrentSerial)

	// A transition attempted from node B must see node A's state, not diverge from it.
	_, err = nodeB.TransitionCursor(ctx, "issued-by-b", 30, false)
	require.NoError(t, err)

	finalA, err := nodeA.LoadCursor(ctx)
	require.NoError(t, err)
	finalB, err := nodeB.LoadCursor(ctx)
	require.NoError(t, err)
	assert.Equal(t, finalA.CurrentSerial, finalB.CurrentSerial, "both nodes must converge on one cursor")
	assert.Equal(t, "issued-by-b", finalA.CurrentSerial)
	assert.Equal(t, "issued-by-a", finalA.RotatingSerial)
}

// TestDatabaseSigningCursorStore_ConcurrentTransitionsConverge is the AC6
// [REQUIRED TEST]: concurrent TransitionCursor calls from independent store
// instances (simulating two controller nodes) must converge on exactly one
// winner, with every other caller rejected — never two divergent cursors.
// Run under -race.
func TestDatabaseSigningCursorStore_ConcurrentTransitionsConverge(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, NewDatabaseSchemas().CreateSigningCursorTable(context.Background(), db))

	// Establish an initial cursor so every goroutine below is contending on
	// the guarded (second) transition, not the always-succeeds first one.
	seed, err := NewDatabaseSigningCursorStore(getTestDB(t), getTestConfig())
	require.NoError(t, err)
	_, err = seed.TransitionCursor(context.Background(), "seed-serial", 30, false)
	require.NoError(t, err)
	require.NoError(t, seed.Close())

	const goroutines = 10
	var wg sync.WaitGroup
	results := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each goroutine opens its own connection, simulating a distinct
			// controller node rather than goroutines sharing one pool.
			store, err := NewDatabaseSigningCursorStore(getTestDB(t), getTestConfig())
			if err != nil {
				results <- err
				return
			}
			defer func() { _ = store.Close() }()
			_, err = store.TransitionCursor(context.Background(), "contender", 30, false)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)

	var successes, inProgress int
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, certinterfaces.ErrSigningRotationInProgress) {
			inProgress++
		} else {
			require.NoError(t, err, "unexpected error type")
		}
	}
	assert.Equal(t, 1, successes, "exactly one concurrent transition must win")
	assert.Equal(t, goroutines-1, inProgress, "every other concurrent transition must be rejected as in-progress")

	reader, err := NewDatabaseSigningCursorStore(db, getTestConfig())
	require.NoError(t, err)
	final, err := reader.LoadCursor(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "contender", final.CurrentSerial, "the single winner's serial must be the persisted cursor")
	assert.Equal(t, "seed-serial", final.RotatingSerial)
}
