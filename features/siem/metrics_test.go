// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package siem

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLatencyTracker_CircularBuffer_OldestDropped verifies that after 1500
// Record calls only the most recent 1000 samples influence percentile results.
func TestLatencyTracker_CircularBuffer_OldestDropped(t *testing.T) {
	lt := NewLatencyTracker()

	// Record values 1ms through 1500ms sequentially.
	// After 1500 writes the circular buffer holds only the last 1000: 501ms–1500ms.
	for i := 1; i <= 1500; i++ {
		lt.Record(time.Duration(i) * time.Millisecond)
	}

	// The minimum of the retained window is 501ms, not 1ms.
	p0 := lt.GetPercentile(0.0)
	require.InDelta(t, 501.0, p0, 0.01,
		"p0 must reflect oldest retained sample (501ms), not earliest ever (1ms)")

	// The maximum must be the last value written.
	p100 := lt.GetPercentile(1.0)
	require.InDelta(t, 1500.0, p100, 0.01,
		"p100 must equal most-recent sample (1500ms)")

	// count must be capped at 1000.
	lt.mutex.RLock()
	count := lt.count
	lt.mutex.RUnlock()
	assert.Equal(t, 1000, count, "count must be capped at 1000 regardless of total writes")
}

// TestLatencyTracker_Percentiles_KnownDistribution checks p50/p95/p99 against
// exact linear-interpolation results for a monotonic 1-through-100 ms input.
func TestLatencyTracker_Percentiles_KnownDistribution(t *testing.T) {
	lt := NewLatencyTracker()

	for i := 1; i <= 100; i++ {
		lt.Record(time.Duration(i) * time.Millisecond)
	}

	// For sorted [1..100] (100 elements):
	//   p50 index = 0.50 * 99 = 49.5 → interpolate(50, 51, 0.5) = 50.5
	//   p95 index = 0.95 * 99 = 94.05 → interpolate(95, 96, 0.05) = 95.05
	//   p99 index = 0.99 * 99 = 98.01 → interpolate(99, 100, 0.01) = 99.01
	assert.InDelta(t, 50.5, lt.GetPercentile(0.50), 1e-9, "p50 mismatch")
	assert.InDelta(t, 95.05, lt.GetPercentile(0.95), 1e-9, "p95 mismatch")
	assert.InDelta(t, 99.01, lt.GetPercentile(0.99), 1e-9, "p99 mismatch")

	// GetStats must return the same values without re-sorting via GetPercentile.
	stats := lt.GetStats()
	assert.InDelta(t, 50.5, stats["p50_ms"], 1e-9, "GetStats p50 mismatch")
	assert.InDelta(t, 95.05, stats["p95_ms"], 1e-9, "GetStats p95 mismatch")
	assert.InDelta(t, 99.01, stats["p99_ms"], 1e-9, "GetStats p99 mismatch")
}

// TestLatencyTracker_ConcurrentRecord exercises concurrent writes under -race.
// The test passes if no data race is detected; it makes no ordering assertions
// since samples are interleaved non-deterministically.
func TestLatencyTracker_ConcurrentRecord(t *testing.T) {
	lt := NewLatencyTracker()

	const goroutines = 20
	const recordsPerGoroutine = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < recordsPerGoroutine; i++ {
				lt.Record(time.Millisecond)
			}
		}()
	}
	wg.Wait()

	// Sanity-check that count is capped correctly after concurrent writes.
	lt.mutex.RLock()
	count := lt.count
	lt.mutex.RUnlock()
	assert.LessOrEqual(t, count, 1000, "count must never exceed buffer capacity")

	// GetPercentile and GetAverage must not panic or return nonsense under load.
	p50 := lt.GetPercentile(0.50)
	assert.GreaterOrEqual(t, p50, 0.0, "p50 must be non-negative after concurrent writes")

	avg := lt.GetAverage()
	assert.GreaterOrEqual(t, avg, 0.0, "average must be non-negative after concurrent writes")
}
