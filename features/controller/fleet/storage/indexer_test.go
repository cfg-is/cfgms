// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"runtime/debug"
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
//
// Measuring that with a wall clock needs two confounders removed, both of
// which hit the warm case harder than the cold one and both of which produced
// a false failure in CI (cold=5.683µs/write, warm=36.52µs/write on a run where
// the write path was provably O(1)):
//
//   - A GC cycle landing inside a timed batch. A batch is ~10ms of work, a
//     mark phase over warm's 50k live devices is a large fraction of that, and
//     the mark cost scales with the live heap — so the noise itself looks like
//     the defect being guarded against. Each timed batch therefore runs with
//     the collector off (restored immediately after), having just collected;
//     one batch's worth of retained garbage is ~batchSize records.
//   - Losing the P to an unrelated package's tests. `make test` runs this
//     package alongside the rest of the tree under `go test -race`, so a
//     single batch can be preempted for milliseconds at a time. Both cases are
//     therefore measured `rounds` times, interleaved so they see the same
//     contention, and compared on the *minimum* per-write cost of each — an
//     interference-free round only needs to happen once per case, whereas a
//     mean is dragged by every round that was interrupted.
func TestMemoryIndexerIndexRecordCostIsIndependentOfIndexSize(t *testing.T) {
	const preSeededDevices = 50_000
	const batchSize = 2_000
	const rounds = 5

	// minSampleElapsed is the floor a timed sample must clear before its
	// duration is trusted. A single batchSize batch runs in low single-digit
	// milliseconds, well under a coarse platform timer's resolution (observed
	// as a 0 duration on Windows runners, Issue #4464) -- 0s/write then fails
	// require.Positive below. 20ms sits comfortably above any such tick.
	const minSampleElapsed = 20 * time.Millisecond

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

	seed := func(idx *MemoryIndexer, n int, keyPrefix string) {
		for i := 0; i < n; i++ {
			require.NoError(t, idx.IndexRecord(ctx, dummyRecord(fmt.Sprintf("%s-%d", keyPrefix, i))))
		}
	}

	indexBatch := func(idx *MemoryIndexer, keyPrefix string) {
		seed(idx, batchSize, keyPrefix)
	}

	// timePerWrite returns the wall-clock cost of one IndexRecord call, with
	// the collector quiesced for the duration of every batch it runs (see the
	// GC note above). idx receives exactly one batch of batchSize writes --
	// warm's resulting record count is checked against an exact total via
	// GetGlobalStats below, so idx must never receive more than that one
	// batch. If that single batch doesn't clear minSampleElapsed, additional
	// batches run against padIdx instead -- a same-shape indexer whose record
	// count nothing depends on -- until the elapsed time measured since
	// before the first batch clears the floor. padIdx must already be the
	// same order of magnitude (empty vs. tens of thousands of devices) as
	// idx: padding a "warm" sample with writes into an empty index would
	// dilute away the very O(n) slowdown this test exists to catch.
	timePerWrite := func(idx, padIdx *MemoryIndexer, keyPrefix string) time.Duration {
		runtime.GC()
		defer debug.SetGCPercent(debug.SetGCPercent(-1))

		start := time.Now()
		indexBatch(idx, keyPrefix)
		writes := int64(batchSize)

		for rep := 0; time.Since(start) < minSampleElapsed; rep++ {
			indexBatch(padIdx, fmt.Sprintf("%s-pad-%d", keyPrefix, rep))
			writes += batchSize
		}

		return time.Since(start) / time.Duration(writes)
	}

	warm := newIndexer(t)
	seed(warm, preSeededDevices, "seed")

	// warmPadding stands in for warm whenever a round's single batch needs
	// padding to clear minSampleElapsed. It starts at the same size as warm
	// and only ever grows, so it never dilutes the warm sample with
	// artificially-fast writes into a small index.
	warmPadding := newIndexer(t)
	seed(warmPadding, preSeededDevices, "padseed")

	coldPerWrite, warmPerWrite := time.Duration(math.MaxInt64), time.Duration(math.MaxInt64)
	for r := 0; r < rounds; r++ {
		// A fresh indexer per round keeps the cold case's index empty; the warm
		// case keeps accumulating on top of its pre-seeded devices. Any padding
		// the cold round needs reuses that same fresh indexer -- a few thousand
		// extra writes within one round keep it orders of magnitude smaller
		// than warm, so it stays representative of "empty index" cost.
		coldIdx := newIndexer(t)
		roundCold := timePerWrite(coldIdx, coldIdx, fmt.Sprintf("cold-%d", r))
		roundWarm := timePerWrite(warm, warmPadding, fmt.Sprintf("warm-%d", r))
		t.Logf("round %d: cold (empty index) %v/write, warm (>=%d devices) %v/write",
			r, roundCold, preSeededDevices, roundWarm)

		// Explicit comparisons rather than the min builtin: this package
		// declares its own min(int, int) (sqlite_backend.go), which shadows the
		// builtin and does not accept a time.Duration.
		if roundCold < coldPerWrite {
			coldPerWrite = roundCold
		}
		if roundWarm < warmPerWrite {
			warmPerWrite = roundWarm
		}
	}

	t.Logf("best-of-%d cold per-write (empty index): %v, warm per-write (%d+ pre-seeded devices): %v",
		rounds, coldPerWrite, preSeededDevices, warmPerWrite)

	require.Positive(t, coldPerWrite, "no measurable per-write cost to compare against")

	// A generous bound: an O(1) write path should land within a small constant
	// factor regardless of residual scheduler noise and of warm's worse cache
	// locality (a 50k-entry map and 50k one-element slices miss where an empty
	// index hits). Measured parity on an uncontended host is ~1.1x
	// (cold 4.08-4.13µs/write, warm 4.34-4.57µs/write). Restoring the O(n)
	// stats recomputation this test guards against was measured at 56x
	// (cold 51.41µs/write, warm 2.886181ms/write), so 8x sits most of an order
	// of magnitude clear of the defect it has to catch while leaving room for a
	// contended two-vCPU runner.
	const maxSlowdown = 8
	require.Lessf(t, warmPerWrite, maxSlowdown*coldPerWrite,
		"IndexRecord cost grew with existing index size: cold=%v/write warm(%d+ devices)=%v/write",
		coldPerWrite, preSeededDevices, warmPerWrite)

	// Stats tracking itself must stay correct under the incremental update.
	stats, err := warm.GetGlobalStats(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(preSeededDevices+rounds*batchSize), stats.TotalEntries)
	require.Equal(t, int64(preSeededDevices+rounds*batchSize), stats.UniqueDevices)
}
