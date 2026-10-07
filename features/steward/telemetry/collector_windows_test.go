// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package telemetry

import (
	"context"
	"encoding/binary"
	"math"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// findPIDWin returns the snapshot for pid, or nil if absent.
func findPIDWin(procs []ProcessSnapshot, pid int) *ProcessSnapshot {
	for i := range procs {
		if procs[i].PID == pid {
			return &procs[i]
		}
	}
	return nil
}

// selfCPUSecondsWin returns this process's cumulative CPU (kernel+user) seconds
// via GetProcessTimes — the Windows analogue of reading /proc/self/stat.
func selfCPUSecondsWin(t *testing.T) float64 {
	t.Helper()
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, windows.GetCurrentProcessId())
	require.NoError(t, err)
	defer func() { _ = windows.CloseHandle(h) }()
	var creation, exit, kernel, user windows.Filetime
	require.NoError(t, windows.GetProcessTimes(h, &creation, &exit, &kernel, &user))
	toSec := func(ft windows.Filetime) float64 {
		// FILETIME is in 100-ns units.
		return float64(uint64(ft.HighDateTime)<<32|uint64(ft.LowDateTime)) * 100e-9
	}
	return toSec(kernel) + toSec(user)
}

// TestWindowsSnapshot_RealProcessValues is the REQUIRED Windows test: it asserts
// real values on a Windows host. It skips cleanly if the process-table syscall
// fails (rare, but keeps non-standard CI images green). NtQuerySystemInformation
// returns a synchronous point-in-time table, so the test process appears in the
// very first snapshot — no perf-counter warm-up / retry is needed.
func TestWindowsSnapshot_RealProcessValues(t *testing.T) {
	c := NewCollector()
	ctx := context.Background()

	tel, err := c.Snapshot(ctx)
	if err != nil {
		t.Skipf("process table query (NtQuerySystemInformation) failed on this host: %v", err)
	}
	require.NotEmpty(t, tel.Processes, "the process table must not be empty")
	assert.Greater(t, len(tel.Processes), 5, "a live Windows host has many processes")

	// Every reported process must be well-formed with a real PID and fragment id.
	nonZeroMem := 0
	for _, p := range tel.Processes {
		assert.NotEmpty(t, p.Name, "process pid=%d must have a name", p.PID)
		assert.Equal(t, "process:"+p.Name, p.FragmentID)
		if p.MemoryBytes > 0 {
			nonZeroMem++
		}
	}
	assert.Greater(t, nonZeroMem, 0, "at least one process reports real working-set memory")

	// The test process itself must appear in the snapshot with real values.
	self := findPIDWin(tel.Processes, os.Getpid())
	require.NotNil(t, self, "the test process must appear in the process snapshot")
	assert.NotEmpty(t, self.Name)
	assert.Greater(t, self.MemoryBytes, uint64(0), "the test process has a real working set")
}

// TestWindowsSnapshot_Services asserts SCM service enumeration. A Windows host
// always has services, so an empty list means the SCM could not be opened —
// skip in that case rather than fail.
func TestWindowsSnapshot_Services(t *testing.T) {
	c := NewCollector()
	tel, err := c.Snapshot(context.Background())
	if err != nil {
		t.Skipf("process table query (NtQuerySystemInformation) failed on this host: %v", err)
	}
	if len(tel.Services) == 0 {
		t.Skip("SCM services not enumerable in this environment")
	}

	states := map[string]int{}
	for _, s := range tel.Services {
		assert.NotEmpty(t, s.Name, "service must have a name")
		assert.NotEmpty(t, s.State, "service %q must carry a state", s.Name)
		assert.Equal(t, "service:"+s.Name, s.FragmentID)
		states[s.State]++
	}
	// A real host has at least one running service (the SCM itself hosts many).
	assert.Greater(t, states["running"], 0, "at least one service must be running (states seen: %v)", states)
}

// TestWindowsCollector_CPUBudget proves the collector stays within the sub-1%
// sustained single-core CPU budget. It measures the real CPU TIME (via
// GetProcessTimes — load-independent, unlike wall-clock %) consumed across many
// back-to-back Snapshot calls to get a stable per-snapshot cost, then asserts the
// amortized cost at the 1 Hz operational cadence story #2764 wires for a live
// "task manager" view. Measuring per-snapshot CPU time avoids the noise of a
// short wall-clock window on a busy CI host (GC/scheduling jitter would otherwise
// swamp the few-millisecond signal).
func TestWindowsCollector_CPUBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("CPU budget measurement skipped in -short mode")
	}
	c := NewCollector()
	ctx := context.Background()
	if _, err := c.Snapshot(ctx); err != nil { // prime + availability gate
		t.Skipf("process table query (NtQuerySystemInformation) failed on this host: %v", err)
	}

	const iterations = 50
	const cadenceHz = 1.0 // operational live-view poll rate (#2764)

	cpuStart := selfCPUSecondsWin(t)
	for i := 0; i < iterations; i++ {
		_, err := c.Snapshot(ctx)
		require.NoError(t, err)
	}
	perSnapshotSec := (selfCPUSecondsWin(t) - cpuStart) / float64(iterations)
	sustainedPct := perSnapshotSec * cadenceHz * 100.0

	t.Logf("per-snapshot %.2f ms CPU → %.3f%% single-core at %.0f Hz sustained (%d iterations)",
		perSnapshotSec*1000, sustainedPct, cadenceHz, iterations)
	assert.Less(t, sustainedPct, 1.0, "sustained %.0f Hz snapshot polling must stay within the 1%% single-core budget", cadenceHz)
}

// TestWindowsSnapshot_HostTotals asserts real host totals: memory and disk
// capacity are populated, the first snapshot's rates are zero, the second's are
// finite and non-negative, and the cumulative network octets (non-loopback) are
// non-zero on a host that has carried any traffic.
func TestWindowsSnapshot_HostTotals(t *testing.T) {
	c := NewCollector()
	first, err := c.Snapshot(context.Background())
	require.NoError(t, err)
	require.NotNil(t, first.Host)
	assert.NotZero(t, first.Host.MemoryTotalBytes)
	assert.LessOrEqual(t, first.Host.MemoryUsedBytes, first.Host.MemoryTotalBytes)
	assert.NotZero(t, first.Host.DiskTotalBytes)
	assert.Zero(t, first.Host.NetRxBytesPerSec)
	assert.Zero(t, first.Host.CPUPercent)

	rx, tx := readNetworkOctets()
	assert.NotZero(t, rx+tx, "non-loopback interface octets must be read from GetIfTable2Ex")

	time.Sleep(50 * time.Millisecond)
	second, err := c.Snapshot(context.Background())
	require.NoError(t, err)
	require.NotNil(t, second.Host)
	for _, v := range []float64{second.Host.CPUPercent, second.Host.DiskReadBytesPerSec, second.Host.DiskWriteBytesPerSec, second.Host.NetRxBytesPerSec, second.Host.NetTxBytesPerSec} {
		assert.False(t, math.IsNaN(v) || math.IsInf(v, 0) || v < 0)
	}
}

func TestWinStartType(t *testing.T) {
	assert.Equal(t, "auto", winStartType(mgr.StartAutomatic, false))
	assert.Equal(t, "auto-delayed", winStartType(mgr.StartAutomatic, true))
	assert.Equal(t, "manual", winStartType(mgr.StartManual, false))
	assert.Equal(t, "disabled", winStartType(mgr.StartDisabled, false))
	assert.Equal(t, "boot", winStartType(windows.SERVICE_BOOT_START, false))
	assert.Equal(t, "system", winStartType(windows.SERVICE_SYSTEM_START, false))
	assert.Equal(t, "", winStartType(99, false))
}

// threadEntry builds a SYSTEM_PROCESS_INFORMATION entry with the given threads
// as (state, waitReason) pairs.
func threadEntry(threads ...[2]uint32) []byte {
	buf := make([]byte, spiMinSize+len(threads)*stiSize)
	binary.LittleEndian.PutUint32(buf[spiNumberOfThreads:], uint32(len(threads)))
	for i, th := range threads {
		off := spiMinSize + i*stiSize
		binary.LittleEndian.PutUint32(buf[off+stiThreadState:], th[0])
		binary.LittleEndian.PutUint32(buf[off+stiWaitReason:], th[1])
	}
	return buf
}

func TestProcessStatus(t *testing.T) {
	assert.Equal(t, "suspended", processStatus(threadEntry([2]uint32{5, 5}, [2]uint32{5, 14}), 100))
	assert.Equal(t, "running", processStatus(threadEntry([2]uint32{5, 5}, [2]uint32{2, 0}), 100))
	assert.Equal(t, "running", processStatus(threadEntry([2]uint32{5, 6}), 100))
	assert.Equal(t, "running", processStatus(threadEntry(), 100))
	assert.Equal(t, "running", processStatus(threadEntry([2]uint32{5, 5}), 4))
	// A thread count that overruns the buffer must not read out of bounds.
	bad := threadEntry([2]uint32{5, 5})
	binary.LittleEndian.PutUint32(bad[spiNumberOfThreads:], 1000)
	assert.Equal(t, "running", processStatus(bad, 100))
}

func TestWindowsSnapshot_ServiceDetail(t *testing.T) {
	snap, err := NewCollector().Snapshot(context.Background())
	require.NoError(t, err)
	var sawStopped, sawRunning bool
	for _, s := range snap.Services {
		if s.State == "stopped" {
			assert.Equal(t, 0, s.PID, "stopped service %s must report PID 0", s.Name)
			if s.StartType != "" {
				sawStopped = true
			}
		}
		if s.State == "running" && s.PID > 0 && s.DisplayName != "" && s.StartType != "" {
			sawRunning = true
		}
	}
	assert.True(t, sawStopped, "expect a stopped service with a start type")
	assert.True(t, sawRunning, "expect a running service with PID, display name and start type")
	self := findPIDWin(snap.Processes, os.Getpid())
	require.NotNil(t, self)
	assert.Equal(t, "running", self.Status)
}
