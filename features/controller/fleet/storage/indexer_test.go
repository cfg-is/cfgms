// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// dummyRecord builds a minimal DNARecord suitable for exercising
// MemoryIndexer.IndexRecord without touching the DNA payload itself.
func dummyRecord(deviceID string) *DNARecord {
	return &DNARecord{
		DeviceID:       deviceID,
		ContentHash:    "hash-" + deviceID,
		ShardID:        "shard-0",
		Version:        1,
		CompressedSize: 128,
	}
}

// TestMemoryIndexerIndexRecordCostIsIndependentOfIndexSize is a direct,
// component-level guard for the defect behind Issue #4239: MemoryIndexer used
// to recompute TotalEntries/UniqueDevices by iterating the entire deviceIndex
// map on every single IndexRecord call (see the former updateIndexStats,
// called unconditionally from IndexRecord). That made every write's cost
// proportional to the number of devices already indexed, so total cost across
// a run of N writes was O(n^2) — exactly the "per-write cost grew with
// dataset size" failure TestScalabilityScenario caught on windows-latest.
//
// TestScalabilityScenario guards the property end-to-end (through the
// collector, the adapter, SQLite, and compression) using a wall-clock ratio
// between two halves of one run of ~1150 writes. This test isolates the one
// component that actually had the O(n) defect (no SQLite I/O, no JSON
// marshal, no compression) and compares a small fixed batch of writes into an
// empty index against the same fixed batch into an index pre-seeded with 50x
// as many devices — a far larger size disparity than "first half vs second
// half" gives a much stronger signal-to-noise ratio for the same underlying
// property. (An earlier draft of this test used testing.Benchmark's
// self-calibrating loop instead of a fixed batch; that let both the "cold"
// and "warm" runs grow their own index by tens of thousands of devices while
// still measuring, which blurred the two cases together and let the O(n)
// regression pass at ~2.7x instead of the 30x+ it actually costs — recorded
// here so the fixed-batch approach isn't "simplified" back into that trap.)
//
// If IndexRecord's cost depended on the number of devices already indexed,
// warm's per-op cost would be orders of magnitude larger than cold's
// (matching the 34x measured on windows-latest for the full stack). With the
// O(1) stats update, both must land in the same ballpark.
func TestMemoryIndexerIndexRecordCostIsIndependentOfIndexSize(t *testing.T) {
	const preSeededDevices = 50_000
	const batchSize = 2_000

	ctx := context.Background()
	logger := logging.NewNoopLogger()
	config := DefaultConfig()

	newIndexer := func(t *testing.T) *MemoryIndexer {
		t.Helper()
		idx, err := NewMemoryIndexer(config, logger)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, idx.Close()) })
		return idx
	}

	timeBatch := func(idx *MemoryIndexer, keyPrefix string) time.Duration {
		start := time.Now()
		for n := 0; n < batchSize; n++ {
			require.NoError(t, idx.IndexRecord(ctx, dummyRecord(fmt.Sprintf("%s-%d", keyPrefix, n))))
		}
		return time.Since(start)
	}

	cold := newIndexer(t)
	coldDuration := timeBatch(cold, "cold")
	coldPerWrite := coldDuration / batchSize

	warm := newIndexer(t)
	for i := 0; i < preSeededDevices; i++ {
		require.NoError(t, warm.IndexRecord(ctx, dummyRecord(fmt.Sprintf("seed-%d", i))))
	}
	warmDuration := timeBatch(warm, "warm")
	warmPerWrite := warmDuration / batchSize

	t.Logf("cold per-write (empty index): %v, warm per-write (%d pre-seeded devices): %v",
		coldPerWrite, preSeededDevices, warmPerWrite)

	require.Positive(t, coldPerWrite, "no measurable per-write cost to compare against")

	// A generous bound: an O(1) write path should land within a small constant
	// factor regardless of scheduler/allocator noise between the two runs. An
	// O(n) write path blows this by more than an order of magnitude at 50k
	// pre-seeded devices, not by a small factor.
	const maxSlowdown = 5
	require.Lessf(t, warmPerWrite, maxSlowdown*coldPerWrite,
		"IndexRecord cost grew with existing index size: cold=%v/write warm(%d devices)=%v/write",
		coldPerWrite, preSeededDevices, warmPerWrite)

	// Stats tracking itself must stay correct under the incremental update.
	stats, err := warm.GetGlobalStats(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(preSeededDevices+batchSize), stats.TotalEntries)
	require.Equal(t, int64(preSeededDevices+batchSize), stats.UniqueDevices)
}
