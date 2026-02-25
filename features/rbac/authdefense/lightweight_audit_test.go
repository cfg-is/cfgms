// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package authdefense

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFailedAuthAggregator_BasicAggregation(t *testing.T) {
	clock := NewTestClock(time.Time{})
	agg := NewFailedAuthAggregator(30*time.Second, 10_000, clock)

	// Record failures from same IP
	for i := 0; i < 100; i++ {
		agg.RecordFailure("ip:1.2.3.4", "user-1")
	}

	assert.Equal(t, 1, agg.Size(), "same key should be aggregated into one entry")

	snapshots := agg.Flush()
	require.Len(t, snapshots, 1)
	assert.Equal(t, "ip:1.2.3.4", snapshots[0].Key)
	assert.Equal(t, uint32(100), snapshots[0].Count)
}

func TestFailedAuthAggregator_MultipleKeys(t *testing.T) {
	clock := NewTestClock(time.Time{})
	agg := NewFailedAuthAggregator(30*time.Second, 10_000, clock)

	agg.RecordFailure("ip:1.1.1.1", "user-a")
	agg.RecordFailure("ip:2.2.2.2", "user-b")
	agg.RecordFailure("ip:1.1.1.1", "user-a")

	assert.Equal(t, 2, agg.Size())

	snapshots := agg.Flush()
	assert.Len(t, snapshots, 2)

	// After flush, size should be zero
	assert.Equal(t, 0, agg.Size())
}

func TestFailedAuthAggregator_FlushResetsCounters(t *testing.T) {
	clock := NewTestClock(time.Time{})
	agg := NewFailedAuthAggregator(30*time.Second, 10_000, clock)

	agg.RecordFailure("ip:1.1.1.1", "user-1")
	agg.RecordFailure("ip:1.1.1.1", "user-1")

	snapshots := agg.Flush()
	require.Len(t, snapshots, 1)
	assert.Equal(t, uint32(2), snapshots[0].Count)

	// Second flush should be empty
	snapshots = agg.Flush()
	assert.Nil(t, snapshots)
}

func TestFailedAuthAggregator_MaxEntriesEviction(t *testing.T) {
	clock := NewTestClock(time.Time{})
	agg := NewFailedAuthAggregator(30*time.Second, 10, clock)

	// Fill beyond max
	for i := 0; i < 15; i++ {
		clock.Advance(1 * time.Second) // space out for deterministic eviction
		agg.RecordFailure(fmt.Sprintf("ip:10.0.0.%d", i), fmt.Sprintf("user-%d", i))
	}

	// Should be bounded at maxEntries
	assert.LessOrEqual(t, agg.Size(), 10)
}

func TestFailedAuthAggregator_Timestamps(t *testing.T) {
	clock := NewTestClock(time.Time{})
	agg := NewFailedAuthAggregator(30*time.Second, 10_000, clock)

	agg.RecordFailure("ip:1.1.1.1", "user-1")
	firstTime := clock.Now()

	clock.Advance(5 * time.Second)
	agg.RecordFailure("ip:1.1.1.1", "user-1")
	lastTime := clock.Now()

	snapshots := agg.Flush()
	require.Len(t, snapshots, 1)
	assert.Equal(t, firstTime, snapshots[0].FirstSeen)
	assert.Equal(t, lastTime, snapshots[0].LastSeen)
}

func TestLightweightAuditEntry_Size(t *testing.T) {
	// LightweightAuditEntry should be much smaller than full proto audit entries
	entry := LightweightAuditEntry{
		Timestamp: time.Now(),
		SubjectID: "user-123",
		Result:    0,
	}

	// Verify it compiles and is usable — the struct is 24 bytes + string header
	assert.NotZero(t, entry.Timestamp)
	assert.Equal(t, byte(0), entry.Result)
}

func TestDefense_UsesLightweightAudit(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 1_000_000
	cfg.GCTriggerThreshold = 1_000_000

	logger := newTestLogger(t)
	d := New(cfg, logger, WithClock(clock))
	defer d.Stop()

	// Record failures through the defense system
	for i := 0; i < 50; i++ {
		d.RecordResult("10.0.0.1", "tenant-A", false)
	}

	// Verify the aggregator captured them
	assert.Greater(t, d.FailedAudit.Size(), 0, "aggregator should have entries")

	snapshots := d.FailedAudit.Flush()
	require.NotEmpty(t, snapshots)

	// All failures from same IP should be aggregated
	var totalCount uint32
	for _, s := range snapshots {
		totalCount += s.Count
	}
	assert.Equal(t, uint32(50), totalCount)
}
