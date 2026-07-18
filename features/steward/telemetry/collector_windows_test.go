// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package telemetry

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
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
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(windows.GetCurrentProcessId()))
	require.NoError(t, err)
	defer windows.CloseHandle(h)
	var creation, exit, kernel, user windows.Filetime
	require.NoError(t, windows.GetProcessTimes(h, &creation, &exit, &kernel, &user))
	toSec := func(ft windows.Filetime) float64 {
		// FILETIME is in 100-ns units.
		return float64(uint64(ft.HighDateTime)<<32|uint64(ft.LowDateTime)) * 100e-9
	}
	return toSec(kernel) + toSec(user)
}

// TestWindowsSnapshot_RealProcessValues is the REQUIRED Windows test: it asserts
// real values on a Windows host. It skips cleanly when the WMI performance
// provider is unavailable (rare, but keeps non-standard CI images green). The
// PerfProc counters refresh on an interval, so the just-launched test process
// may take a sample or two to appear — hence the short retry.
func TestWindowsSnapshot_RealProcessValues(t *testing.T) {
	c := NewCollector()
	ctx := context.Background()

	tel, err := c.Snapshot(ctx)
	if err != nil {
		t.Skipf("WMI process provider unavailable on this host: %v", err)
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

	// The test process itself should appear once the perf provider samples it.
	var self *ProcessSnapshot
	for attempt := 0; attempt < 3 && self == nil; attempt++ {
		if self = findPIDWin(tel.Processes, os.Getpid()); self != nil {
			break
		}
		time.Sleep(1200 * time.Millisecond)
		tel, err = c.Snapshot(ctx)
		require.NoError(t, err)
	}
	require.NotNil(t, self, "the test process must appear in the WMI process snapshot")
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
		t.Skipf("WMI process provider unavailable on this host: %v", err)
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
// sustained single-core CPU budget at a realistic 1 Hz live-view cadence,
// measuring this process's real CPU delta via GetProcessTimes.
func TestWindowsCollector_CPUBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("CPU budget measurement skipped in -short mode")
	}
	c := NewCollector()
	ctx := context.Background()
	if _, err := c.Snapshot(ctx); err != nil {
		t.Skipf("WMI process provider unavailable on this host: %v", err)
	}

	const pollInterval = 1 * time.Second
	const window = 5 * time.Second

	cpuStart := selfCPUSecondsWin(t)
	wallStart := time.Now()
	deadline := wallStart.Add(window)
	n := 0
	for time.Now().Before(deadline) {
		_, err := c.Snapshot(ctx)
		require.NoError(t, err)
		n++
		time.Sleep(pollInterval)
	}
	cpuPct := (selfCPUSecondsWin(t) - cpuStart) / time.Since(wallStart).Seconds() * 100.0

	t.Logf("collector overhead: %.3f%% single-core over %.1fs (%d snapshots at %s cadence)", cpuPct, time.Since(wallStart).Seconds(), n, pollInterval)
	require.Greater(t, n, 1, "must have taken multiple snapshots")
	assert.Less(t, cpuPct, 1.0, "sustained %s-cadence snapshot polling must stay within the 1%% single-core budget", pollInterval)
}
