// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFenceRatchet_SurvivesRestart verifies that both ratchet fields — the
// ratchet-set flag and the high-water term — survive a steward process restart.
//
// The test sets the ratchet at term 7 (simulating acceptance of a stamped
// command that established a baseline via #3436's checkTermFence logic), then
// reconstructs the component under test from its persisted directory (simulating
// a steward restart), and asserts that a subsequent command carrying term 3 would
// still be rejected — proving both fields survived, not just one.
func TestFenceRatchet_SurvivesRestart(t *testing.T) {
	dir := t.TempDir()

	// First "process instance": accept a stamped command at term 7.
	// This is what checkTermFence does when it admits a stamped command:
	// it sets ratchetSet=true and records the term as the high-water mark.
	r1 := NewFenceRatchet(dir)
	require.NoError(t, r1.Save(true, 7), "Save must succeed")

	// Simulate a steward process restart: construct a fresh FenceRatchet
	// from the same persisted directory rather than continuing r1.
	r2 := NewFenceRatchet(dir)
	ratchetSet, highestTermSeen, err := r2.Load()
	require.NoError(t, err, "Load must succeed after restart")

	// Both fields must survive individually.
	assert.True(t, ratchetSet, "ratchet-set flag must survive restart")
	assert.Equal(t, uint64(7), highestTermSeen, "high-water term must survive restart")

	// A command at term 3 (below the pre-restart high-water of 7) must still be
	// rejected — this mirrors the three-state rejection logic in checkTermFence:
	// when ratchetSet is true and the incoming term is below highestTermSeen,
	// the command is refused. Both fields must survive for this to hold.
	const staleCommandTerm = uint64(3)
	wouldBeRejected := ratchetSet && staleCommandTerm < highestTermSeen
	assert.True(t, wouldBeRejected,
		"command with term %d must be rejected after restart (high-water %d, ratchet-set %v)",
		staleCommandTerm, highestTermSeen, ratchetSet)
}

// TestFenceRatchet_FreshStateOnNoFile verifies that Load returns zero values
// when no state file exists (first boot or after ClearRatchet).
func TestFenceRatchet_FreshStateOnNoFile(t *testing.T) {
	r := NewFenceRatchet(t.TempDir())
	ratchetSet, highestTermSeen, err := r.Load()
	require.NoError(t, err)
	assert.False(t, ratchetSet)
	assert.Equal(t, uint64(0), highestTermSeen)
}

// TestFenceRatchet_MemoryOnlyWhenDirEmpty verifies that a zero-dir FenceRatchet
// never performs I/O: Load returns zero values, Save and ClearRatchet are no-ops.
func TestFenceRatchet_MemoryOnlyWhenDirEmpty(t *testing.T) {
	r := NewFenceRatchet("")
	require.NoError(t, r.Save(true, 42))
	require.NoError(t, r.ClearRatchet())

	ratchetSet, highestTermSeen, err := r.Load()
	require.NoError(t, err)
	assert.False(t, ratchetSet)
	assert.Equal(t, uint64(0), highestTermSeen)
}

// TestFenceRatchet_ClearRatchet_ResetsState verifies that ClearRatchet removes
// the persisted state so a subsequent Load returns zero values.
func TestFenceRatchet_ClearRatchet_ResetsState(t *testing.T) {
	dir := t.TempDir()
	r := NewFenceRatchet(dir)
	require.NoError(t, r.Save(true, 5))

	require.NoError(t, r.ClearRatchet())

	ratchetSet, highestTermSeen, err := r.Load()
	require.NoError(t, err)
	assert.False(t, ratchetSet, "ratchet-set flag must be zero after ClearRatchet")
	assert.Equal(t, uint64(0), highestTermSeen, "high-water term must be zero after ClearRatchet")
}

// TestFenceRatchet_ClearRatchet_IdempotentWhenNoFile verifies that ClearRatchet
// is a no-op (not an error) when no state file exists.
func TestFenceRatchet_ClearRatchet_IdempotentWhenNoFile(t *testing.T) {
	r := NewFenceRatchet(t.TempDir())
	assert.NoError(t, r.ClearRatchet())
	assert.NoError(t, r.ClearRatchet()) // second call also safe
}

// TestFenceRatchet_SaveIsAtomic verifies that the persisted file contains the
// most-recently saved state when Save is called multiple times.
func TestFenceRatchet_SaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	r := NewFenceRatchet(dir)

	require.NoError(t, r.Save(true, 3))
	require.NoError(t, r.Save(true, 9)) // advance the high-water mark

	_, highestTermSeen, err := r.Load()
	require.NoError(t, err)
	assert.Equal(t, uint64(9), highestTermSeen, "most-recent Save wins")
}

// TestFenceRatchet_LoadReportsReadFailure covers the non-IsNotExist I/O failure
// branch of Load: the state path exists but cannot be read as a file. A directory
// is planted at the ratchet path, which makes os.ReadFile fail with an error that
// is not os.IsNotExist on every supported platform (chmod-based revocation is not
// usable here: it is a no-op for root and has no equivalent on Windows).
//
// The distinction matters because the two branches have opposite meanings: a
// missing file is a legitimate first boot and must load as zero state, while an
// unreadable file is an error the caller must see rather than silently treat as
// "no fence has ever been set".
func TestFenceRatchet_LoadReportsReadFailure(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, fenceRatchetFileName), 0700),
		"planting a directory at the ratchet path must succeed")

	r := NewFenceRatchet(dir)
	ratchetSet, highestTermSeen, err := r.Load()

	require.Error(t, err, "an unreadable ratchet path must surface as an error, not as fresh state")
	assert.False(t, os.IsNotExist(err), "the failure must not be reported as a missing file")
	assert.Contains(t, err.Error(), "read fence ratchet", "error must identify the failing operation")
	assert.False(t, ratchetSet, "no ratchet state may be claimed from a failed read")
	assert.Equal(t, uint64(0), highestTermSeen, "no term may be claimed from a failed read")
}

// TestFenceRatchet_LoadReportsCorruptState covers the json.Unmarshal failure
// branch of Load: the state file exists and is readable but does not contain
// valid JSON (truncated write, disk corruption, tampering).
func TestFenceRatchet_LoadReportsCorruptState(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, fenceRatchetFileName), []byte("{not-json}"), 0600))

	r := NewFenceRatchet(dir)
	ratchetSet, highestTermSeen, err := r.Load()

	require.Error(t, err, "a corrupt ratchet file must surface as an error")
	assert.Contains(t, err.Error(), "parse fence ratchet", "error must identify the failing operation")
	assert.False(t, ratchetSet, "no ratchet state may be claimed from an unparseable file")
	assert.Equal(t, uint64(0), highestTermSeen, "no term may be claimed from an unparseable file")
}

// TestFenceRatchet_LoadReportsEmptyState covers the corrupt-state branch for the
// specific shape a truncated write leaves behind: a zero-length file. Empty input
// is not valid JSON, so it must be reported rather than parsed as zero state —
// zero state would silently open the fence.
func TestFenceRatchet_LoadReportsEmptyState(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, fenceRatchetFileName), nil, 0600))

	r := NewFenceRatchet(dir)
	_, _, err := r.Load()
	require.Error(t, err, "a zero-length ratchet file must surface as an error")
}

// TestFenceRatchet_SaveNeverLowersPersistedTerm verifies Save's monotonic guard.
// Inbound commands are dispatched one goroutine per command, so two accepted
// commands carrying terms 10 and 11 can reach Save in either order. If the later
// call for term 10 were allowed to overwrite 11, the next boot would come up with
// a high-water mark below what the previous process already fenced out — the exact
// restart downgrade this ratchet exists to close.
func TestFenceRatchet_SaveNeverLowersPersistedTerm(t *testing.T) {
	dir := t.TempDir()
	r := NewFenceRatchet(dir)

	require.NoError(t, r.Save(true, 11))
	require.NoError(t, r.Save(true, 10), "a late low-term Save must be ignored, not fail")

	ratchetSet, highestTermSeen, err := r.Load()
	require.NoError(t, err)
	assert.True(t, ratchetSet)
	assert.Equal(t, uint64(11), highestTermSeen, "persisted high-water mark must not regress")

	// The ratchet-set flag must not be cleared either: clearing it would make an
	// unstamped command acceptable again after a restart.
	require.NoError(t, r.Save(false, 0), "a zeroing Save must be ignored, not fail")
	ratchetSet, highestTermSeen, err = r.Load()
	require.NoError(t, err)
	assert.True(t, ratchetSet, "ratchet-set flag must not be cleared by a Save")
	assert.Equal(t, uint64(11), highestTermSeen)
}

// TestFenceRatchet_SaveGuardSeedsFromDisk verifies the monotonic guard holds for a
// FenceRatchet whose first call is Save rather than Load — the state after a
// startup Load that failed. The guard must consult disk before overwriting it.
func TestFenceRatchet_SaveGuardSeedsFromDisk(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, NewFenceRatchet(dir).Save(true, 9))

	// Fresh instance, no Load first.
	require.NoError(t, NewFenceRatchet(dir).Save(true, 4))

	_, highestTermSeen, err := NewFenceRatchet(dir).Load()
	require.NoError(t, err)
	assert.Equal(t, uint64(9), highestTermSeen, "guard must be seeded from disk, not from an empty struct")
}

// TestFenceRatchet_SaveAfterClearRatchetStartsFresh verifies that the enrollment
// reset is the sanctioned way past the monotonic guard: after ClearRatchet, a
// lower term is persisted normally (a rebuilt controller cluster legitimately
// restarts its Raft terms from a low value).
func TestFenceRatchet_SaveAfterClearRatchetStartsFresh(t *testing.T) {
	dir := t.TempDir()
	r := NewFenceRatchet(dir)
	require.NoError(t, r.Save(true, 20))

	require.NoError(t, r.ClearRatchet())
	require.NoError(t, r.Save(true, 2), "post-reset Save must persist the new low term")

	ratchetSet, highestTermSeen, err := r.Load()
	require.NoError(t, err)
	assert.True(t, ratchetSet)
	assert.Equal(t, uint64(2), highestTermSeen, "reset must allow the ratchet to restart low")
}

// TestFenceRatchet_ConcurrentSavesKeepHighestTerm exercises the real concurrency
// shape of the command path: many goroutines saving different terms at once
// against one FenceRatchet. Two properties must hold afterwards:
//
//   - the file is always parseable (no concurrent saver published a truncated or
//     empty file — that would make the next boot's Load fail and leave the fence
//     wide open), and
//   - the persisted term is the highest saved, regardless of completion order.
//
// Run with -race, this also covers the internal state the guard depends on.
func TestFenceRatchet_ConcurrentSavesKeepHighestTerm(t *testing.T) {
	dir := t.TempDir()
	r := NewFenceRatchet(dir)

	const savers = 64
	var wg sync.WaitGroup
	errs := make([]error, savers)
	start := make(chan struct{})
	for i := 0; i < savers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = r.Save(true, uint64(i+1))
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "concurrent Save %d must not fail", i)
	}

	// A reader must always see a complete file, whichever instance reads it.
	ratchetSet, highestTermSeen, err := NewFenceRatchet(dir).Load()
	require.NoError(t, err, "concurrent saves must never leave an unparseable file")
	assert.True(t, ratchetSet)
	assert.Equal(t, uint64(savers), highestTermSeen, "highest saved term must win regardless of ordering")

	// No temp file may survive a successful save: each save renames its own
	// uniquely named temp file over the target rather than sharing a fixed path.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var leftovers []string
	for _, e := range entries {
		if e.Name() != fenceRatchetFileName {
			leftovers = append(leftovers, e.Name())
		}
	}
	assert.Empty(t, leftovers, "no temp files may be left behind after successful saves")
}

// TestFenceRatchet_ConcurrentLoadAndSave verifies that a reader running alongside
// writers never observes a partial write — the restart path (Load) and the command
// path (Save) touch the same file from different goroutines.
func TestFenceRatchet_ConcurrentLoadAndSave(t *testing.T) {
	dir := t.TempDir()
	r := NewFenceRatchet(dir)
	require.NoError(t, r.Save(true, 1))

	var wg sync.WaitGroup
	loadErrs := make([]error, 32)
	saveErrs := make([]error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			saveErrs[i] = r.Save(true, uint64(i+2))
		}(i)
		go func(i int) {
			defer wg.Done()
			_, _, loadErrs[i] = NewFenceRatchet(dir).Load()
		}(i)
	}
	wg.Wait()

	for i := range loadErrs {
		require.NoError(t, saveErrs[i], "concurrent Save %d must not fail", i)
		require.NoError(t, loadErrs[i], "concurrent Load %d must never see a partial write", i)
	}
}
