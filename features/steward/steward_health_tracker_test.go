// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package steward

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// newTestTracker creates a StewardHealthTracker backed by a real flat-file StewardStore.
func newTestTracker(t *testing.T) *StewardHealthTracker {
	t.Helper()
	store, err := flatfile.NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	logger := logging.NewLogger("debug")
	return NewStewardHealthTracker(store, logger)
}

// testRecord returns a minimal StewardRecord for use in tracker tests.
func testRecord(id string) *interfaces.StewardRecord {
	return &interfaces.StewardRecord{
		ID:       id,
		Hostname: "host-" + id,
		Platform: "linux",
		Arch:     "amd64",
		Version:  "1.0.0",
	}
}

func TestStewardHealthTracker_RegisterAndGet(t *testing.T) {
	tracker := newTestTracker(t)
	ctx := context.Background()

	require.NoError(t, tracker.RegisterSteward(ctx, testRecord("s-001")))

	rec, err := tracker.GetSteward(ctx, "s-001")
	require.NoError(t, err)
	assert.Equal(t, "s-001", rec.ID)
	assert.Equal(t, "linux", rec.Platform)
}

func TestStewardHealthTracker_RegisterDuplicate(t *testing.T) {
	tracker := newTestTracker(t)
	ctx := context.Background()

	require.NoError(t, tracker.RegisterSteward(ctx, testRecord("s-dup")))
	err := tracker.RegisterSteward(ctx, testRecord("s-dup"))
	assert.ErrorIs(t, err, interfaces.ErrStewardAlreadyExists)
}

func TestStewardHealthTracker_UpdateHeartbeat_PromotesToActive(t *testing.T) {
	tracker := newTestTracker(t)
	ctx := context.Background()

	require.NoError(t, tracker.RegisterSteward(ctx, testRecord("s-hb")))

	// On registration, status is "registered"
	rec, err := tracker.GetSteward(ctx, "s-hb")
	require.NoError(t, err)
	assert.Equal(t, interfaces.StewardStatusRegistered, rec.Status)

	// After first heartbeat, status should be promoted to "active"
	require.NoError(t, tracker.UpdateHeartbeat(ctx, "s-hb"))

	rec, err = tracker.GetSteward(ctx, "s-hb")
	require.NoError(t, err)
	assert.Equal(t, interfaces.StewardStatusActive, rec.Status)
}

func TestStewardHealthTracker_UpdateHeartbeat_UpdatesEphemeralMetrics(t *testing.T) {
	tracker := newTestTracker(t)
	ctx := context.Background()

	require.NoError(t, tracker.RegisterSteward(ctx, testRecord("s-metrics")))
	require.NoError(t, tracker.UpdateHeartbeat(ctx, "s-metrics"))

	metrics := tracker.GetEphemeralMetrics("s-metrics")
	require.NotNil(t, metrics)
	assert.True(t, metrics.ControllerConnected)
	assert.Equal(t, 0, metrics.HeartbeatErrors)
	assert.False(t, metrics.LastHeartbeat.IsZero())
}

func TestStewardHealthTracker_UpdateHeartbeat_NotFound(t *testing.T) {
	tracker := newTestTracker(t)
	err := tracker.UpdateHeartbeat(context.Background(), "ghost")
	assert.ErrorIs(t, err, interfaces.ErrStewardNotFound)
}

func TestStewardHealthTracker_MarkLost(t *testing.T) {
	tracker := newTestTracker(t)
	ctx := context.Background()

	require.NoError(t, tracker.RegisterSteward(ctx, testRecord("s-lost")))
	require.NoError(t, tracker.MarkLost(ctx, "s-lost"))

	rec, err := tracker.GetSteward(ctx, "s-lost")
	require.NoError(t, err)
	assert.Equal(t, interfaces.StewardStatusLost, rec.Status)
}

func TestStewardHealthTracker_DeregisterSteward(t *testing.T) {
	tracker := newTestTracker(t)
	ctx := context.Background()

	require.NoError(t, tracker.RegisterSteward(ctx, testRecord("s-dereg")))
	require.NoError(t, tracker.DeregisterSteward(ctx, "s-dereg"))

	rec, err := tracker.GetSteward(ctx, "s-dereg")
	require.NoError(t, err)
	// Record retained for audit, status changed
	assert.Equal(t, interfaces.StewardStatusDeregistered, rec.Status)
}

func TestStewardHealthTracker_ListStewards(t *testing.T) {
	tracker := newTestTracker(t)
	ctx := context.Background()

	for _, id := range []string{"s-a", "s-b", "s-c"} {
		require.NoError(t, tracker.RegisterSteward(ctx, testRecord(id)))
	}

	all, err := tracker.ListStewards(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 3)
}

func TestStewardHealthTracker_ListActiveStewards(t *testing.T) {
	tracker := newTestTracker(t)
	ctx := context.Background()

	require.NoError(t, tracker.RegisterSteward(ctx, testRecord("s-reg")))
	require.NoError(t, tracker.RegisterSteward(ctx, testRecord("s-active")))
	require.NoError(t, tracker.UpdateHeartbeat(ctx, "s-active")) // promotes to active

	active, err := tracker.ListActiveStewards(ctx)
	require.NoError(t, err)
	assert.Len(t, active, 1)
	assert.Equal(t, "s-active", active[0].ID)
}

func TestStewardHealthTracker_EphemeralMetricsNotPersisted(t *testing.T) {
	// Verify that ephemeral metrics are NOT persisted across tracker instances
	// (they survive only in-memory within a single process lifetime)
	root := t.TempDir()
	ctx := context.Background()

	store1, err := flatfile.NewFlatFileStewardStore(root)
	require.NoError(t, err)
	logger := logging.NewLogger("debug")

	tracker1 := NewStewardHealthTracker(store1, logger)
	require.NoError(t, tracker1.RegisterSteward(ctx, testRecord("s-ep")))
	tracker1.RecordTaskLatency("s-ep", 50*time.Millisecond)
	tracker1.RecordConfigError("s-ep")

	metrics1 := tracker1.GetEphemeralMetrics("s-ep")
	require.NotNil(t, metrics1)
	assert.Equal(t, 1, metrics1.TaskCount)
	assert.Equal(t, 1, metrics1.ConfigErrors)
	_ = store1.Close()

	// New tracker instance, same storage root — simulates controller restart
	store2, err := flatfile.NewFlatFileStewardStore(root)
	require.NoError(t, err)
	defer func() { _ = store2.Close() }()

	tracker2 := NewStewardHealthTracker(store2, logger)

	// Durable record is present
	rec, err := tracker2.GetSteward(ctx, "s-ep")
	require.NoError(t, err)
	assert.Equal(t, "s-ep", rec.ID)

	// Ephemeral metrics are gone (reset on restart — expected behavior)
	metrics2 := tracker2.GetEphemeralMetrics("s-ep")
	assert.Nil(t, metrics2, "ephemeral metrics should not survive a tracker restart")
}

func TestStewardHealthTracker_RecordTaskLatency(t *testing.T) {
	tracker := newTestTracker(t)
	ctx := context.Background()

	require.NoError(t, tracker.RegisterSteward(ctx, testRecord("s-latency")))
	tracker.RecordTaskLatency("s-latency", 50*time.Millisecond)
	tracker.RecordTaskLatency("s-latency", 100*time.Millisecond)

	metrics := tracker.GetEphemeralMetrics("s-latency")
	require.NotNil(t, metrics)
	assert.Equal(t, 2, metrics.TaskCount)
	assert.Equal(t, 75*time.Millisecond, metrics.AverageTaskLatency)
}

func TestStewardHealthTracker_RecordConfigError(t *testing.T) {
	tracker := newTestTracker(t)
	ctx := context.Background()

	require.NoError(t, tracker.RegisterSteward(ctx, testRecord("s-cfg-err")))
	tracker.RecordConfigError("s-cfg-err")
	tracker.RecordConfigError("s-cfg-err")

	metrics := tracker.GetEphemeralMetrics("s-cfg-err")
	require.NotNil(t, metrics)
	assert.Equal(t, 2, metrics.ConfigErrors)
}

func TestStewardHealthTracker_GetEphemeralMetrics_UnknownSteward(t *testing.T) {
	tracker := newTestTracker(t)
	// Steward exists in store but no in-memory metrics yet — returns nil
	metrics := tracker.GetEphemeralMetrics("never-registered")
	assert.Nil(t, metrics)
}
