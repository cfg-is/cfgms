// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package authdefense

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/pkg/logging"
)

func TestMemory_Requests(t *testing.T) {
	// ThreadSanitizer (race detector) maintains 5-10x shadow memory per byte of
	// application memory. On Windows CI runners, cumulative TSan shadow memory from
	// 90+ test packages exhausts the commit charge limit. Use -short to reduce volume.
	numRequests := 50_000
	if testing.Short() {
		numRequests = 5_000
	}

	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPMaxTracked = numRequests
	cfg.GCTriggerThreshold = 1_000_000

	logger := logging.NewLogger("error")
	d := New(cfg, logger, WithClock(clock))
	defer d.Stop()

	// Force GC to get clean baseline
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)

	for i := range numRequests {
		ip := fmt.Sprintf("10.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256)
		d.CheckRequest(ip, "")
		d.RecordResult(ip, fmt.Sprintf("tenant-%d", i%100), i%10 != 0)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	allocMB := float64(after.Alloc-baseline.Alloc) / (1024 * 1024)
	t.Logf("Memory after %d requests: %.2f MB (alloc)", numRequests, allocMB)

	assert.Less(t, after.Alloc, uint64(100*1024*1024), "memory should stay under 100MB")
}

func TestMemory_NoLeaks(t *testing.T) {
	numRequests := 10_000
	if testing.Short() {
		numRequests = 1_000
	}

	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPMaxTracked = 1_000
	cfg.TenantMaxTracked = 100
	cfg.IPRateWindow = 1 * time.Second
	cfg.GCTriggerThreshold = int64(numRequests) + 1000

	logger := logging.NewLogger("error")
	d := New(cfg, logger, WithClock(clock))
	defer d.Stop()

	runtime.GC()
	var baselineStats runtime.MemStats
	runtime.ReadMemStats(&baselineStats)

	for i := range numRequests {
		ip := fmt.Sprintf("10.0.%d.%d", (i/256)%256, i%256)
		d.CheckRequest(ip, "")
		d.RecordResult(ip, "tenant-0", true)
	}

	// Advance time past all windows so entries can expire
	clock.Advance(10 * time.Minute)

	// Force GC and let cache cleanup run
	runtime.GC()

	var afterStats runtime.MemStats
	runtime.ReadMemStats(&afterStats)

	// Memory should return near baseline (within 20MB tolerance)
	diff := int64(afterStats.Alloc) - int64(baselineStats.Alloc)
	t.Logf("Memory delta after load+GC: %d bytes (%.2f MB)", diff, float64(diff)/(1024*1024))

	// We allow some growth due to cache structure overhead, but it should be bounded
	assert.Less(t, afterStats.Alloc, baselineStats.Alloc+20*1024*1024,
		"memory should return near baseline after load completes and GC runs")
}
