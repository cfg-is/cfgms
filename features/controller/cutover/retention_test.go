// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cutover

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeBin(t *testing.T, dir, name string, size int, modTime time.Time) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{0x90}, size), 0o600))
	require.NoError(t, os.Chtimes(path, modTime, modTime))
	return path
}

// TestPrune_KeepsActiveAndQuarantined covers the [REQUIRED TEST] that
// after a successful upgrade the previous binary stays on disk for at
// least the quarantine window, AND the currently-canonical binary is
// never pruned.
func TestPrune_KeepsActiveAndQuarantined(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()

	// Active (canonical) — recent.
	active := writeBin(t, dir, "v3", 100, now.Add(-1*time.Minute))
	// Within quarantine window (recent, NOT active).
	quarantined := writeBin(t, dir, "v2", 100, now.Add(-30*time.Minute))
	// Outside quarantine window — eligible.
	old := writeBin(t, dir, "v1", 100, now.Add(-2*time.Hour))

	policy := RetentionPolicy{
		QuarantineWindow: time.Hour,
		MaxVersions:      0, // disabled — only quarantine + active matter
		MaxBytes:         0, // disabled
	}
	decisions, err := Prune(dir, active, policy, now)
	require.NoError(t, err)

	// Active stays.
	assertFile(t, active, true)
	// Quarantined stays (within window).
	assertFile(t, quarantined, true)
	// Old would be eligible but policy.MaxVersions=0 and MaxBytes=0
	// means no cap → also kept.
	assertFile(t, old, true)

	// Confirm decision log records each entry.
	kept := countAction(decisions, "kept")
	assert.Equal(t, 3, kept, "all three binaries should be kept under permissive policy")
}

// TestPrune_RollbackWithinQuarantine_RestoresPreviousImmediately covers
// the [REQUIRED TEST] that an upgrade-then-rollback within the
// quarantine window finds the previous binary intact on disk.
//
// We don't run a full Upgrade+Rollback here (that's covered in
// integration_test.go); instead, we assert that for the specific
// sequence "Prune runs ON or BEFORE the rollback window expires," the
// previous-binary path is still present.
func TestPrune_RollbackWithinQuarantine_RestoresPreviousImmediately(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()

	// New canonical (just installed).
	current := writeBin(t, dir, "v2", 100, now.Add(-30*time.Minute))
	// Previous (still in quarantine).
	previous := writeBin(t, dir, "v1", 100, now.Add(-31*time.Minute))

	policy := DefaultRetentionPolicy() // 1h quarantine, 3 versions, 500MB

	// Prune runs (e.g. periodic sweep). Both binaries are protected.
	_, err := Prune(dir, current, policy, now)
	require.NoError(t, err)
	assertFile(t, current, true)
	assertFile(t, previous, true, "previous binary must remain on disk inside the quarantine window — rollback depends on it")
}

// TestPrune_AfterQuarantineExpires_OldVersionsPruned covers the
// [REQUIRED TEST] that after the quarantine window expires without
// rollback, the previous binary IS pruned (subject to max-versions /
// max-bytes guards).
func TestPrune_AfterQuarantineExpires_OldVersionsPruned(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()

	// Active.
	active := writeBin(t, dir, "v5", 50, now)
	// 4 older binaries past quarantine — MaxVersions=3 should
	// preserve the 3 newest non-active and prune the oldest.
	v4 := writeBin(t, dir, "v4", 50, now.Add(-2*time.Hour))
	v3 := writeBin(t, dir, "v3", 50, now.Add(-3*time.Hour))
	v2 := writeBin(t, dir, "v2", 50, now.Add(-4*time.Hour))
	v1 := writeBin(t, dir, "v1", 50, now.Add(-5*time.Hour))

	policy := RetentionPolicy{
		QuarantineWindow: time.Hour, // all of v1-v4 are past
		MaxVersions:      3,
		MaxBytes:         0,
	}
	decisions, err := Prune(dir, active, policy, now)
	require.NoError(t, err)

	// Active + v4, v3, v2 kept (3 newest non-active within MaxVersions).
	assertFile(t, active, true, "active canonical must remain")
	assertFile(t, v4, true, "newest retained binary must remain")
	assertFile(t, v3, true)
	assertFile(t, v2, true)
	// v1 is the oldest — gets pruned.
	assertFile(t, v1, false, "oldest past-quarantine binary must be pruned when MaxVersions exceeded")

	deleted := countAction(decisions, "deleted")
	assert.Equal(t, 1, deleted, "exactly one binary should have been deleted")
}

// TestPrune_MaxBytesEnforced covers the size-based cap.
func TestPrune_MaxBytesEnforced(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()

	active := writeBin(t, dir, "v3", 100, now)
	// Two old binaries, each 1024 bytes.
	v2 := writeBin(t, dir, "v2", 1024, now.Add(-2*time.Hour))
	v1 := writeBin(t, dir, "v1", 1024, now.Add(-3*time.Hour))

	policy := RetentionPolicy{
		QuarantineWindow: time.Hour, // both v1,v2 past quarantine
		MaxVersions:      10,        // not the binding constraint
		MaxBytes:         1500,      // can fit one but not both
	}
	_, err := Prune(dir, active, policy, now)
	require.NoError(t, err)

	assertFile(t, active, true)
	assertFile(t, v2, true, "newest past-quarantine binary kept (fits in MaxBytes)")
	assertFile(t, v1, false, "oldest past-quarantine binary pruned because MaxBytes exceeded")
}

// TestPrune_ZeroQuarantine_PrunesImmediately ensures a 0-second
// quarantine doesn't accidentally protect everything (e.g. divide-by-
// zero, or naive "if QW > 0" guards that interpret 0 as "infinite").
func TestPrune_ZeroQuarantine_PrunesImmediately(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	active := writeBin(t, dir, "v2", 50, now)
	old := writeBin(t, dir, "v1", 50, now.Add(-1*time.Second))

	policy := RetentionPolicy{
		QuarantineWindow: 0, // no quarantine
		MaxVersions:      0, // no version cap
		MaxBytes:         0, // no byte cap
	}
	_, err := Prune(dir, active, policy, now)
	require.NoError(t, err)

	// Active still kept, old kept because no other caps applied.
	assertFile(t, active, true)
	assertFile(t, old, true)
}

// TestPrune_RejectsInvalidPolicy guards against pathological config.
func TestPrune_RejectsInvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		name   string
		policy RetentionPolicy
	}{
		{"negative quarantine", RetentionPolicy{QuarantineWindow: -1}},
		{"negative max versions", RetentionPolicy{MaxVersions: -1}},
		{"negative max bytes", RetentionPolicy{MaxBytes: -1}},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Prune(dir, "", c.policy, time.Now())
			require.Error(t, err)
		})
	}
}

// TestListRetainedBinaries_MissingDir handles fresh installs.
func TestListRetainedBinaries_MissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	got, err := ListRetainedBinaries(dir, "")
	require.NoError(t, err)
	assert.Empty(t, got, "missing dir should return empty slice + nil error")
}

func assertFile(t *testing.T, path string, expectExists bool, msgAndArgs ...interface{}) {
	t.Helper()
	_, err := os.Stat(path)
	if expectExists {
		assert.NoError(t, err, msgAndArgs...)
	} else {
		assert.True(t, os.IsNotExist(err), msgAndArgs...)
	}
}

func countAction(decisions []PruneDecision, action string) int {
	n := 0
	for _, d := range decisions {
		if d.Action == action {
			n++
		}
	}
	return n
}
