// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cutover

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPersistedState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cutover.state.json")

	// Missing file → zero value + nil error (caller treats as "no upgrade yet").
	ps, err := LoadPersistedState(path)
	require.NoError(t, err)
	assert.Empty(t, ps.CanonicalBinary)

	// Round-trip through Save + Load.
	original := PersistedState{
		CanonicalBinary:      "/opt/cfgms/cfgms-controller-v0.5.11",
		CanonicalStartedAt:   time.Now().UTC().Truncate(time.Second),
		QuarantinedBinary:    "/opt/cfgms/cfgms-controller-v0.5.10",
		QuarantinedStartedAt: time.Now().UTC().Truncate(time.Second).Add(-1 * time.Hour),
		QuarantineExpiresAt:  time.Now().UTC().Truncate(time.Second).Add(1 * time.Hour),
	}
	require.NoError(t, SavePersistedState(path, original))

	got, err := LoadPersistedState(path)
	require.NoError(t, err)
	assert.Equal(t, original, got)
}

func TestSavePersistedState_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "dirs", "cutover.state.json")

	require.NoError(t, SavePersistedState(path, PersistedState{
		CanonicalBinary: "/opt/cfgms/cfgms-controller",
	}))

	got, err := LoadPersistedState(path)
	require.NoError(t, err)
	assert.Equal(t, "/opt/cfgms/cfgms-controller", got.CanonicalBinary)
}

func TestSavePersistedState_RejectsEmptyPath(t *testing.T) {
	assert.Error(t, SavePersistedState("", PersistedState{}))
}

func TestSnapshotToPersisted_Roundtrip(t *testing.T) {
	now := time.Now().UTC()
	snap := Snapshot{
		State:                StateQuarantined,
		CanonicalBinary:      "green",
		CanonicalStartedAt:   now,
		QuarantinedBinary:    "blue",
		QuarantinedStartedAt: now.Add(-time.Hour),
		QuarantineExpiresAt:  now.Add(time.Hour),
	}
	ps := SnapshotToPersisted(snap)
	assert.Equal(t, "green", ps.CanonicalBinary)
	assert.Equal(t, "blue", ps.QuarantinedBinary)
	assert.Equal(t, now, ps.CanonicalStartedAt)
	assert.Equal(t, now.Add(-time.Hour), ps.QuarantinedStartedAt)
	assert.Equal(t, now.Add(time.Hour), ps.QuarantineExpiresAt)
}

// TestSetQuarantinedForRollback_OnlyAppliesFromIdle covers the safety
// guard: the helper must not corrupt an in-flight upgrade.
func TestSetQuarantinedForRollback_OnlyAppliesFromIdle(t *testing.T) {
	// Reuse the fakes/stubs defined in cutover_test.go (same package).
	o, _, _, _ := newOrchForTest(t)

	quarantined := newFakeHandle("v-old")
	SetQuarantinedForRollback(o, quarantined, time.Now(), time.Now().Add(time.Hour))
	assert.Equal(t, StateQuarantined, o.Status().State)
	assert.Equal(t, "v-old", o.Status().QuarantinedBinary)

	// Now in StateQuarantined: re-applying must NOT corrupt.
	other := newFakeHandle("v-other")
	SetQuarantinedForRollback(o, other, time.Now(), time.Now().Add(time.Hour))
	assert.Equal(t, StateQuarantined, o.Status().State)
	assert.Equal(t, "v-old", o.Status().QuarantinedBinary,
		"SetQuarantinedForRollback must be a no-op when state != StateIdle")
}
