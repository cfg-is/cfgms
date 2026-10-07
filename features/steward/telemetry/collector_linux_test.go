// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package telemetry

import (
	"context"
	"fmt"
	"math"
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

// writeHostFixture builds a procfs/sysfs fixture tree for the host-total readers.
func writeHostFixture(t *testing.T, root string, cpuBusy, cpuIdle, rdSectors, wrSectors, rx, tx uint64) {
	t.Helper()
	require.NoError(t, os.MkdirAll(root+"/proc/net", 0o750))
	require.NoError(t, os.MkdirAll(root+"/sys/block/sda", 0o750))
	write := func(name, content string) {
		require.NoError(t, os.WriteFile(root+"/proc/"+name, []byte(content), 0o600))
	}
	write("stat", fmt.Sprintf("cpu  %d 0 0 %d 0 0 0 0 0 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n", cpuBusy, cpuIdle))
	write("meminfo", "MemTotal:       8000000 kB\nMemFree: 1000000 kB\nMemAvailable:   2000000 kB\n")
	write("diskstats", fmt.Sprintf("   8  0 sda 1 0 %d 0 1 0 %d 0 0 0 0\n   8  1 sda1 1 0 999999 0 1 0 999999 0 0 0 0\n   7  0 loop0 1 0 999999 0 1 0 999999 0 0 0 0\n", rdSectors, wrSectors))
	write("net/dev", fmt.Sprintf("Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n    lo: 5000 1 0 0 0 0 0 0 5000 1 0 0 0 0 0 0\n  eth0: %d 1 0 0 0 0 0 0 %d 1 0 0 0 0 0 0\n", rx, tx))
	write("mounts", "")
}

func newFixtureCollector(root string) *linuxCollector {
	return &linuxCollector{
		clkTck:       100,
		prev:         map[int]uint64{},
		procRoot:     root + "/proc",
		sysBlockRoot: root + "/sys/block",
	}
}

// TestIsWholeDisk_RejectsNonComponentNames proves a device name that is not a
// single path component never resolves to a sysfs entry, even when the joined
// path would exist on disk.
func TestIsWholeDisk_RejectsNonComponentNames(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(root+"/sys/block/sda", 0o750))
	require.NoError(t, os.MkdirAll(root+"/sys/escape", 0o750))
	c := newFixtureCollector(root)

	assert.True(t, c.isWholeDisk("sda"))
	for _, name := range []string{"", ".", "..", "../escape", "sda/..", `..\escape`, "sda\x00"} {
		assert.False(t, c.isWholeDisk(name), "name %q must be rejected", name)
	}
}

// TestLinuxHostTotals_RatesFromDeltas is the REQUIRED test: the first snapshot's
// rates are zero, the second's come from the delta between the two readings.
func TestLinuxHostTotals_RatesFromDeltas(t *testing.T) {
	root := t.TempDir()
	c := newFixtureCollector(root)

	writeHostFixture(t, root, 100, 900, 1000, 2000, 10_000, 20_000)
	first := c.collectHost()
	assert.Equal(t, uint64(8000000*1024), first.MemoryTotalBytes)
	assert.Equal(t, uint64(6000000*1024), first.MemoryUsedBytes)
	assert.Zero(t, first.CPUPercent)
	assert.Zero(t, first.NetRxBytesPerSec)
	assert.Zero(t, first.NetTxBytesPerSec)
	assert.Zero(t, first.DiskReadBytesPerSec)
	assert.Zero(t, first.DiskWriteBytesPerSec)

	time.Sleep(20 * time.Millisecond)
	// +100 busy of +200 total ticks => 50%; loopback and partition/loop devices ignored.
	writeHostFixture(t, root, 200, 1000, 3000, 6000, 110_000, 220_000)
	second := c.collectHost()
	assert.InDelta(t, 50.0, second.CPUPercent, 0.001)
	assert.Greater(t, second.NetRxBytesPerSec, 0.0)
	assert.Greater(t, second.NetTxBytesPerSec, 0.0)
	assert.InDelta(t, 2.0, second.NetTxBytesPerSec/second.NetRxBytesPerSec, 0.001, "tx delta is 200000 vs rx 100000")
	assert.InDelta(t, 2.0, second.DiskWriteBytesPerSec/second.DiskReadBytesPerSec, 0.001, "write delta 4000 sectors vs read 2000")
}

// TestLinuxHostTotals_CounterResetYieldsZero is the REQUIRED wrap/reset test.
func TestLinuxHostTotals_CounterResetYieldsZero(t *testing.T) {
	root := t.TempDir()
	c := newFixtureCollector(root)
	writeHostFixture(t, root, 500, 500, 5000, 5000, 1_000_000, 1_000_000)
	c.collectHost()
	time.Sleep(10 * time.Millisecond)
	writeHostFixture(t, root, 1, 1, 1, 1, 1, 1) // every counter went backwards
	h := c.collectHost()
	for name, v := range map[string]float64{
		"cpu": h.CPUPercent, "diskRead": h.DiskReadBytesPerSec, "diskWrite": h.DiskWriteBytesPerSec,
		"netRx": h.NetRxBytesPerSec, "netTx": h.NetTxBytesPerSec,
	} {
		assert.Equal(t, 0.0, v, name)
		assert.False(t, math.IsNaN(v) || math.IsInf(v, 0), name)
	}
}

// TestLinuxSnapshot_HostNetworkTotalsReal asserts the live collector reports a
// non-zero network total on a host that has any non-loopback traffic counters.
func TestLinuxSnapshot_HostNetworkTotalsReal(t *testing.T) {
	data, err := os.ReadFile("/proc/net/dev")
	require.NoError(t, err)
	rx, tx := parseNetDev(string(data))
	c := NewCollector()
	snap, err := c.Snapshot(context.Background())
	require.NoError(t, err)
	require.NotNil(t, snap.Host)
	if rx+tx > 0 {
		// Cumulative counters are non-zero, so a delta over real traffic is
		// observable; the rate itself needs sustained traffic, which a test host
		// cannot guarantee, so assert the raw totals reach the collector instead.
		cur := c.(*linuxCollector).hostPrev
		assert.NotZero(t, cur.netRx+cur.netTx, "non-loopback totals must be read from /proc/net/dev")
	}
	assert.NotZero(t, snap.Host.MemoryTotalBytes)
	assert.NotZero(t, snap.Host.DiskTotalBytes)
	assert.LessOrEqual(t, snap.Host.MemoryUsedBytes, snap.Host.MemoryTotalBytes)
}

func TestUnescapeMountPath(t *testing.T) {
	assert.Equal(t, "/mnt/my disk", unescapeMountPath(`/mnt/my\040disk`))
	assert.Equal(t, "/plain", unescapeMountPath("/plain"))
}
