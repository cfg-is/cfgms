// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cutover

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOrchestrator_WithHistory_EmitsEventsForFullCutover wires the
// History into the orchestrator and verifies the full set of expected
// events is recorded across a happy-path upgrade + rollback.
//
// Closes part of the Story #1921 acceptance criterion that "Structured
// upgrade events show up in the existing log pipeline so existing
// alerting can match on them."
func TestOrchestrator_WithHistory_EmitsEventsForFullCutover(t *testing.T) {
	dir := t.TempDir()
	historyPath := filepath.Join(dir, "history.jsonl")
	hist := NewHistory(historyPath)

	o, _, _, _ := newOrchForTest(t)
	o.History = hist

	require.NoError(t, o.Upgrade(context.Background(), "green.exe"))
	require.Equal(t, StateQuarantined, o.Status().State)

	events, err := hist.Recent(0)
	require.NoError(t, err)

	// Expected order (newest first): committed → smoketest_passed → staged.
	require.GreaterOrEqual(t, len(events), 3, "happy-path upgrade must emit at least 3 events")

	// Build a set of event types in order.
	types := make([]string, len(events))
	for i, ev := range events {
		types[i] = ev.EventType
	}
	assert.Contains(t, types, EventStaged)
	assert.Contains(t, types, EventSmoketestPassed)
	assert.Contains(t, types, EventCommitted)

	// Now exercise rollback — rolled_back event must appear.
	require.NoError(t, o.Rollback(context.Background()))

	events, err = hist.Recent(0)
	require.NoError(t, err)
	types = types[:0]
	for _, ev := range events {
		types = append(types, ev.EventType)
	}
	assert.Contains(t, types, EventRolledBack, "Rollback must emit a rolled_back event")
}

// TestOrchestrator_WithHistory_FailedSmoketest_Emits exercises the
// failed-smoketest path: only Staged + SmoketestFailed events are
// emitted (no Committed, no RolledBack).
func TestOrchestrator_WithHistory_FailedSmoketest_Emits(t *testing.T) {
	dir := t.TempDir()
	hist := NewHistory(filepath.Join(dir, "history.jsonl"))

	o, _, _, _ := newOrchForTest(t)
	o.smoke = stubSmoke{err: errOpaque("control plane unreachable")}
	o.History = hist

	err := o.Upgrade(context.Background(), "broken.exe")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrSmoketestFailed)

	events, err := hist.Recent(0)
	require.NoError(t, err)

	types := map[string]bool{}
	for _, ev := range events {
		types[ev.EventType] = true
	}
	assert.True(t, types[EventStaged], "Staged must be emitted before smoketest")
	assert.True(t, types[EventSmoketestFailed], "SmoketestFailed must be emitted on probe error")
	assert.False(t, types[EventCommitted], "Committed must NOT appear after smoketest failure")
	assert.False(t, types[EventRolledBack], "RolledBack must NOT appear after a failed cutover")
}

// TestOrchestrator_WithHistory_FinalizeQuarantine_EmitsExpired covers
// the FinalizeQuarantine path.
func TestOrchestrator_WithHistory_FinalizeQuarantine_EmitsExpired(t *testing.T) {
	dir := t.TempDir()
	hist := NewHistory(filepath.Join(dir, "history.jsonl"))

	o, _, _, _ := newOrchForTest(t)
	o.History = hist

	require.NoError(t, o.Upgrade(context.Background(), "green.exe"))
	o.FinalizeQuarantine(context.Background())

	events, err := hist.Recent(0)
	require.NoError(t, err)
	found := false
	for _, ev := range events {
		if ev.EventType == EventQuarantineExpired {
			found = true
			break
		}
	}
	assert.True(t, found, "FinalizeQuarantine must emit quarantine_expired")
}

// TestRetention_IntegratedWithHistory ties retention pruning to the
// history log. After Prune runs, an upgrade.pruned event SHOULD be
// emitted for each deleted binary so operators can correlate disk
// usage drops with prune events.
//
// This test directly exercises the Prune + History contract — there's
// no production wiring yet that calls them together (the Story C MVP
// doesn't have a scheduler), but the surface is here so a follow-up
// cron / periodic-task hook can use both.
func TestRetention_IntegratedWithHistory(t *testing.T) {
	dir := t.TempDir()
	hist := NewHistory(filepath.Join(dir, "history.jsonl"))
	archiveDir := t.TempDir()

	now := time.Now().UTC()
	active := writeBin(t, archiveDir, "v2", 100, now)
	oldBin := writeBin(t, archiveDir, "v1", 100, now.Add(-2*time.Hour))
	_ = oldBin

	policy := RetentionPolicy{
		QuarantineWindow: time.Hour, // v1 outside window
		MaxVersions:      0,         // disable version cap
		MaxBytes:         50,        // forces deletion of v1
	}
	decisions, err := Prune(archiveDir, active, policy, now)
	require.NoError(t, err)

	// Emit pruned event for each deletion.
	for _, d := range decisions {
		if d.Action == "deleted" {
			require.NoError(t, hist.Append(UpgradeEvent{
				EventType:  EventPruned,
				BinaryPath: d.Binary.Path,
				Reason:     d.Reason,
				Timestamp:  d.PrunedAt,
			}))
		}
	}

	events, err := hist.Recent(0)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(events), 1)
	assert.Equal(t, EventPruned, events[0].EventType)
}

// errOpaque is a minimal error type for tests that don't want to
// import "errors".
type errOpaque string

func (e errOpaque) Error() string { return string(e) }
