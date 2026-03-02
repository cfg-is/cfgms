// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package authdefense

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/pkg/logging"
)

func TestPerformance_Throughput(t *testing.T) {
	iterations := 10_000
	if testing.Short() {
		iterations = 1_000
	}

	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.GCTriggerThreshold = 1_000_000 // don't trigger GC during perf test

	logger := logging.NewLogger("error")
	d := New(cfg, logger, WithClock(clock))
	defer d.Stop()

	start := time.Now()

	for i := 0; i < iterations; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", (i/256)%256, i%256)
		d.CheckRequest(ip, "")
	}

	elapsed := time.Since(start)
	perOp := elapsed / time.Duration(iterations)

	t.Logf("Throughput: %d ops in %v (%.0f ns/op)", iterations, elapsed, float64(perOp.Nanoseconds()))

	// Rate limiting check should be sub-microsecond
	assert.Less(t, perOp, 10*time.Microsecond, "CheckRequest should be < 10us per operation")
}

func TestPerformance_Concurrent(t *testing.T) {
	goroutines := 50
	opsPerGoroutine := 200
	if testing.Short() {
		goroutines = 10
		opsPerGoroutine = 50
	}

	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 1_000_000 // high to avoid blocks during perf test
	cfg.GCTriggerThreshold = 1_000_000

	logger := logging.NewLogger("error")
	d := New(cfg, logger, WithClock(clock))
	defer d.Stop()

	var wg sync.WaitGroup
	start := time.Now()

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				ip := fmt.Sprintf("10.%d.%d.%d", id, (j/256)%256, j%256)
				tenantID := fmt.Sprintf("tenant-%d", id%10)

				d.CheckRequest(ip, tenantID)
				d.RecordResult(ip, tenantID, j%3 != 0)
			}
		}(g)
	}

	wg.Wait()
	elapsed := time.Since(start)

	totalOps := goroutines * opsPerGoroutine * 2 // check + record
	t.Logf("Concurrent: %d total ops from %d goroutines in %v", totalOps, goroutines, elapsed)

	// Verify no deadlocks — if we got here, no deadlock occurred
	snap := d.GetMetrics()
	assert.Greater(t, snap.TotalProcessed, int64(0), "should have processed requests")
}
