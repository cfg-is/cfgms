// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestHelperProcess is the helper invoked by the cross-process SQLite
// concurrency test. The parent test re-exec's this binary with
// GO_WANT_HELPER_PROCESS=1 plus SQLITE_HELPER_*= controls so two real
// processes can hammer the same on-disk SQLite file concurrently.
//
// Environment knobs (all required):
//
//	SQLITE_HELPER_DB        Path to the shared .db file.
//	SQLITE_HELPER_PREFIX    Steward-ID prefix unique to this process
//	                        (e.g. "blue" / "green") so the two writers
//	                        don't collide on primary key.
//	SQLITE_HELPER_COUNT     How many RegisterSteward calls this process
//	                        should make.
//
// Exit codes: 0 on success; 2 on missing env / setup failure; 3 if any
// RegisterSteward returns an error. Errors are logged to stderr for the
// parent test to surface.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	dbPath := os.Getenv("SQLITE_HELPER_DB")
	prefix := os.Getenv("SQLITE_HELPER_PREFIX")
	countStr := os.Getenv("SQLITE_HELPER_COUNT")
	count, _ := strconv.Atoi(countStr)
	if dbPath == "" || prefix == "" || count <= 0 {
		fmt.Fprintln(os.Stderr, "helper: missing required env (SQLITE_HELPER_DB / _PREFIX / _COUNT)")
		os.Exit(2)
	}

	db, err := openAndInit(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper %s: openAndInit: %v\n", prefix, err)
		os.Exit(2)
	}
	defer db.Close()

	store := &SQLiteStewardStore{db: db}
	ctx := context.Background()
	for i := 0; i < count; i++ {
		rec := &business.StewardRecord{
			ID:        fmt.Sprintf("%s-%04d", prefix, i),
			Hostname:  fmt.Sprintf("host-%s-%04d", prefix, i),
			Platform:  "linux",
			Arch:      "amd64",
			Version:   "1.0.0",
			IPAddress: "10.0.0.1",
			Status:    business.StewardStatusRegistered,
		}
		if err := store.RegisterSteward(ctx, rec); err != nil {
			fmt.Fprintf(os.Stderr, "helper %s iter %d: RegisterSteward: %v\n", prefix, i, err)
			os.Exit(3)
		}
	}
	os.Exit(0)
}

// TestSQLite_TwoProcesses_ConcurrentWrites_NoCorruption closes the
// Story #1919 acceptance criterion that the in-process test alone
// could not satisfy: literally TWO operating-system processes both
// writing to the same SQLite file concurrently must succeed without
// corruption.
//
// WAL mode coordinates via shared-memory (-shm) and write-ahead log
// (-wal) sidecar files using OS-level file locks. Those locks are
// process-scoped on every supported OS, so the same SQLite contract
// that holds for two *sql.DB handles in one Go process also holds for
// two OS processes — the lock-acquisition paths are byte-identical.
// What this test verifies that the in-process variant doesn't is that
// nothing in the cfgms openDB code path (pragma application, schema
// init) accidentally serialises through process-local state that
// would break under genuine multi-process operation.
//
// Method: re-exec the test binary twice with disjoint steward-ID
// prefixes ("blue" / "green"), 500 RegisterSteward calls each. Wait
// for both to exit cleanly, then open the DB from the parent and
// verify ALL 1000 records are present + readable.
func TestSQLite_TwoProcesses_ConcurrentWrites_NoCorruption(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "two_processes.db")

	// Seed the schema in the parent so both children attach to an
	// already-initialised file. This avoids the schema-init race that
	// would otherwise need its own synchronisation (and isn't what we're
	// testing here — we're testing concurrent WRITES, not concurrent
	// initialisation).
	db, err := openAndInit(dbPath)
	require.NoError(t, err, "seed schema")
	require.NoError(t, db.Close())

	exe, err := os.Executable()
	require.NoError(t, err, "os.Executable")

	const writesPerSide = 500
	spawn := func(prefix string) *exec.Cmd {
		cmd := exec.Command(exe, "-test.run=TestHelperProcess") //nolint:gosec // test infra
		cmd.Env = append(os.Environ(),
			"GO_WANT_HELPER_PROCESS=1",
			"SQLITE_HELPER_DB="+dbPath,
			"SQLITE_HELPER_PREFIX="+prefix,
			"SQLITE_HELPER_COUNT="+strconv.Itoa(writesPerSide),
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd
	}

	blue := spawn("blue")
	green := spawn("green")
	require.NoError(t, blue.Start(), "blue.Start")
	require.NoError(t, green.Start(), "green.Start")

	var (
		wg                sync.WaitGroup
		blueErr, greenErr error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		blueErr = blue.Wait()
	}()
	go func() {
		defer wg.Done()
		greenErr = green.Wait()
	}()
	wg.Wait()

	assert.NoError(t, blueErr, "blue subprocess failed — see helper stderr above")
	assert.NoError(t, greenErr, "green subprocess failed — see helper stderr above")

	// Read the file back from the PARENT — a third process — and
	// confirm all 1000 records are present.
	db, err = openAndInit(dbPath)
	require.NoError(t, err)
	defer db.Close()
	store := &SQLiteStewardStore{db: db}
	records, err := store.ListStewards(context.Background())
	require.NoError(t, err, "parent ListStewards")
	assert.Equal(t, 2*writesPerSide, len(records),
		"parent must see all %d records written by blue + green; got %d — "+
			"either WAL corruption or a write was silently lost",
		2*writesPerSide, len(records))

	// Spot-check one record from each side to prove cross-process write
	// AND read both worked end-to-end.
	for _, id := range []string{"blue-0000", "blue-0499", "green-0000", "green-0499"} {
		rec, err := store.GetSteward(context.Background(), id)
		require.NoError(t, err, "GetSteward(%q)", id)
		assert.Equal(t, business.StewardStatusRegistered, rec.Status)
	}
}
