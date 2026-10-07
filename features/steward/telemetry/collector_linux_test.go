// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package telemetry

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findPID returns the snapshot for pid, or nil if absent.
func findPID(procs []ProcessSnapshot, pid int) *ProcessSnapshot {
	for i := range procs {
		if procs[i].PID == pid {
			return &procs[i]
		}
	}
	return nil
}

// busyLoop burns CPU on the current process for at least d, so a subsequent
// Snapshot observes a non-zero CPU delta for our own PID.
func busyLoop(d time.Duration) {
	deadline := time.Now().Add(d)
	x := 0
	for time.Now().Before(deadline) {
		for i := 0; i < 1_000_000; i++ {
			x += i * i
		}
	}
	_ = x
}

// selfCPUSeconds returns this process's cumulative CPU time (user+system) in
// seconds, read from /proc/self/stat via the production helpers.
func selfCPUSeconds(t *testing.T) float64 {
	t.Helper()
	_, ticks, ok := readProcStat(os.Getpid())
	require.True(t, ok, "must read own /proc/self CPU ticks")
	return float64(ticks) / float64(readClockTicks())
}

// TestLinuxSnapshot_RealProcessValues is the REQUIRED test: it asserts real,
// non-fabricated values for the running test process — real PID, its own image
// name, non-zero RSS, a correctly shaped fragment id, and a non-zero CPU delta
// after the process burns CPU between two snapshots. This matches the evidence
// style of CONSUME_FEASIBILITY_LINUX.md (real PIDs, real RSS/CPU).
func TestLinuxSnapshot_RealProcessValues(t *testing.T) {
	c := NewCollector()
	ctx := context.Background()

	// First snapshot establishes the CPU baseline: every CPUPercent is 0 because
	// there is no prior sample to delta against.
	first, err := c.Snapshot(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, first.Processes, "the process table must not be empty")
	assert.Greater(t, len(first.Processes), 5, "a live host has many processes")

	self := findPID(first.Processes, os.Getpid())
	require.NotNil(t, self, "the test process itself must appear in the snapshot")
	assert.NotEmpty(t, self.Name, "the process must have a comm name")
	assert.Greater(t, self.MemoryBytes, uint64(0), "the test process has non-zero RSS")
	assert.Equal(t, "process:"+self.Name, self.FragmentID, "fragment id is process:<name>")
	assert.Equal(t, 0.0, self.CPUPercent, "first snapshot has no CPU baseline yet")

	// Burn CPU, then take a second snapshot: our PID must show a real CPU delta.
	busyLoop(300 * time.Millisecond)
	second, err := c.Snapshot(ctx)
	require.NoError(t, err)
	self2 := findPID(second.Processes, os.Getpid())
	require.NotNil(t, self2, "the test process must still be present")
	assert.Greater(t, self2.CPUPercent, 0.0, "a CPU-burning process shows non-zero CPU on the delta snapshot")
	assert.Greater(t, self2.MemoryBytes, uint64(0))
}

// TestLinuxSnapshot_Services asserts systemd service listing when a system bus is
// reachable. It skips cleanly on a headless/container host without systemd
// (services are a best-effort snapshot facet, and D-Bus is often absent in CI
// containers) rather than failing.
func TestLinuxSnapshot_Services(t *testing.T) {
	c := NewCollector()
	tel, err := c.Snapshot(context.Background())
	require.NoError(t, err)
	if len(tel.Services) == 0 {
		t.Skip("no systemd/D-Bus services reachable (headless or non-systemd host)")
	}
	for _, s := range tel.Services {
		assert.True(t, strings.HasSuffix(s.Name, ".service"), "only .service units are reported: %q", s.Name)
		assert.NotEmpty(t, s.State, "service %q must carry a state", s.Name)
		assert.True(t, strings.HasPrefix(s.FragmentID, "service:"), "fragment id shape for %q", s.Name)
		assert.NotContains(t, s.FragmentID, ".service", "the .service suffix is trimmed from the fragment id")
	}
}

// TestLinuxCollector_CPUBudget proves the collector stays within the sub-1%
// sustained single-core CPU budget. It measures the real CPU TIME (from
// /proc/self/stat — load-independent, unlike wall-clock %) consumed across many
// back-to-back Snapshot calls to get a stable per-snapshot cost, then asserts the
// amortized cost at the 1 Hz operational cadence story #2764 wires for a live
// "task manager" view. Measuring per-snapshot CPU time avoids the noise of a
// short wall-clock window on a busy CI host.
func TestLinuxCollector_CPUBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("CPU budget measurement skipped in -short mode")
	}
	c := NewCollector()
	ctx := context.Background()
	// Prime the delta baseline so the measured iterations reflect steady state.
	_, err := c.Snapshot(ctx)
	require.NoError(t, err)

	const iterations = 50
	const cadenceHz = 1.0 // operational live-view poll rate (#2764)

	cpuStart := selfCPUSeconds(t)
	for i := 0; i < iterations; i++ {
		_, err := c.Snapshot(ctx)
		require.NoError(t, err)
	}
	perSnapshotSec := (selfCPUSeconds(t) - cpuStart) / float64(iterations)
	sustainedPct := perSnapshotSec * cadenceHz * 100.0

	t.Logf("per-snapshot %.2f ms CPU → %.3f%% single-core at %.0f Hz sustained (%d iterations)",
		perSnapshotSec*1000, sustainedPct, cadenceHz, iterations)
	assert.Less(t, sustainedPct, 1.0, "sustained %.0f Hz snapshot polling must stay within the 1%% single-core budget", cadenceHz)
}
