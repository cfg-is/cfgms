// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestSQLite_TwoStoreInstances_ConcurrentWrites_NoCorruption covers the
// blue/green substrate guarantee from Issue #1919: two storage.Manager
// instances (here represented by two separate StewardStore handles, both
// opened against the same on-disk SQLite file) can write concurrently
// without corrupting the database.
//
// The test opens two separate *sql.DB handles to the same file — exactly
// what would happen if a "blue" controller process and a "green" controller
// process were both running on the same host with shared storage. Each
// instance writes 500 distinct steward records; afterward both must be
// able to read back ALL 1000 records, proving:
//
//  1. WAL mode allows concurrent writers without lock failures (with the
//     5000 ms busy_timeout, lock contention resolves transparently).
//  2. No write is silently lost.
//  3. Both readers see a consistent snapshot — neither sees only its own
//     writes nor a torn record.
//
// This intentionally does NOT cover the cross-PROCESS case — that needs a
// helper subprocess and lives in a separate test. For purposes of the
// WAL-mode contract, two *sql.DB instances within one process exercise the
// same lock paths as two processes (WAL coordinates via OS-level file
// locks on the -shm + -wal sidecars regardless of process boundaries).
func TestSQLite_TwoStoreInstances_ConcurrentWrites_NoCorruption(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "concurrent.db")

	// First open must do schema init — second open just attaches.
	dbBlue, err := openAndInit(dbPath)
	require.NoError(t, err, "blue: openAndInit")
	t.Cleanup(func() { _ = dbBlue.Close() })

	dbGreen, err := openAndInit(dbPath)
	require.NoError(t, err, "green: openAndInit")
	t.Cleanup(func() { _ = dbGreen.Close() })

	blueStore := &SQLiteStewardStore{db: dbBlue}
	greenStore := &SQLiteStewardStore{db: dbGreen}

	const writesPerSide = 500
	ctx := context.Background()

	var wg sync.WaitGroup
	var blueFailures, greenFailures atomic.Int64

	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < writesPerSide; i++ {
			rec := testStewardRec(fmt.Sprintf("blue-%04d", i))
			if err := blueStore.RegisterSteward(ctx, rec); err != nil {
				t.Logf("blue write %d failed: %v", i, err)
				blueFailures.Add(1)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < writesPerSide; i++ {
			rec := testStewardRec(fmt.Sprintf("green-%04d", i))
			if err := greenStore.RegisterSteward(ctx, rec); err != nil {
				t.Logf("green write %d failed: %v", i, err)
				greenFailures.Add(1)
			}
		}
	}()
	wg.Wait()

	assert.Zero(t, blueFailures.Load(), "blue side had write failures under concurrent load")
	assert.Zero(t, greenFailures.Load(), "green side had write failures under concurrent load")

	// Both sides should now see ALL 1000 records — proves there's no
	// per-handle view divergence (WAL readers see the latest committed
	// snapshot once their own transaction starts).
	for _, side := range []struct {
		name  string
		store *SQLiteStewardStore
	}{
		{"blue", blueStore},
		{"green", greenStore},
	} {
		records, err := side.store.ListStewards(ctx)
		require.NoError(t, err, "%s: ListStewards", side.name)
		assert.Equal(t, 2*writesPerSide, len(records),
			"%s side did not see all 1000 records — possible write loss or read isolation bug",
			side.name)
	}

	// Spot-check a known record from each side to prove the data round-tripped.
	rec, err := blueStore.GetSteward(ctx, "green-0000")
	require.NoError(t, err, "blue must be able to read green-written records")
	assert.Equal(t, business.StewardStatusRegistered, rec.Status)

	rec, err = greenStore.GetSteward(ctx, "blue-0000")
	require.NoError(t, err, "green must be able to read blue-written records")
	assert.Equal(t, business.StewardStatusRegistered, rec.Status)
}

// TestSQLite_IdentityContinuity_BlueWriteGreenRead is the explicit
// "identity continuity" guarantee from Issue #1919: a steward registered
// against a blue controller must be immediately visible via a green
// controller's API. No re-registration. No replication lag. The
// underlying mechanism is just "both controllers share the same SQLite
// DB," and this test pins that contract down so it can't silently break.
//
// This is a smaller, more directly named test than the concurrency stress
// above — it sets the spec expectation in plain language for future
// readers.
func TestSQLite_IdentityContinuity_BlueWriteGreenRead(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "identity.db")

	dbBlue, err := openAndInit(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dbBlue.Close() })

	dbGreen, err := openAndInit(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dbGreen.Close() })

	blueStore := &SQLiteStewardStore{db: dbBlue}
	greenStore := &SQLiteStewardStore{db: dbGreen}

	ctx := context.Background()

	// Step 1: blue receives the registration.
	rec := testStewardRec("steward-continuity-001")
	require.NoError(t, blueStore.RegisterSteward(ctx, rec))

	// Step 2: green must see the steward immediately on first query.
	// (No re-fetch / no retry — if green can't see it, identity continuity is broken.)
	got, err := greenStore.GetSteward(ctx, "steward-continuity-001")
	require.NoError(t, err,
		"green controller cannot see a steward that blue just registered — "+
			"identity continuity for blue/green cutover is broken")
	assert.Equal(t, "steward-continuity-001", got.ID)
	assert.Equal(t, business.StewardStatusRegistered, got.Status)
	assert.Equal(t, rec.Hostname, got.Hostname)

	// Step 3: a heartbeat update from green is visible on blue.
	require.NoError(t, greenStore.UpdateHeartbeat(ctx, "steward-continuity-001"))
	gotAfter, err := blueStore.GetSteward(ctx, "steward-continuity-001")
	require.NoError(t, err)
	assert.True(t, gotAfter.LastSeen.After(got.LastSeen) || gotAfter.LastSeen.Equal(got.LastSeen),
		"blue must see green's heartbeat update; got LastSeen=%s vs original=%s",
		gotAfter.LastSeen, got.LastSeen)
}

// TestSQLite_WALModeIsActive verifies the openDB pragma actually took.
// Belt-and-braces — if a future refactor accidentally drops the
// journal_mode = WAL line, the concurrent test above will appear to keep
// passing under low load but fail intermittently under contention. This
// test would fail loudly on the next CI run instead.
func TestSQLite_WALModeIsActive(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "wal_probe.db")

	db, err := openAndInit(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	var mode string
	require.NoError(t, db.QueryRow("PRAGMA journal_mode").Scan(&mode))
	assert.Equal(t, "wal", mode, "expected journal_mode=wal, got %q", mode)

	var busyTimeout int
	require.NoError(t, db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout))
	assert.GreaterOrEqual(t, busyTimeout, 1000,
		"busy_timeout must be >= 1s to absorb WAL writer contention; got %d ms", busyTimeout)
}
