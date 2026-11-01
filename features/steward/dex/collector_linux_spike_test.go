// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux && spike

package dex

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Unit: PSI parser ─────────────────────────────────────────────────────────

func TestLinuxParsePSIValid(t *testing.T) {
	input := "some avg10=1.64 avg60=2.68 avg300=5.08 total=16969107941\n" +
		"full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
	s, err := parsePSI(input)
	require.NoError(t, err)
	assert.InDelta(t, 1.64, s.Some.Avg10, 0.001)
	assert.InDelta(t, 2.68, s.Some.Avg60, 0.001)
	assert.InDelta(t, 5.08, s.Some.Avg300, 0.001)
	assert.Equal(t, uint64(16969107941), s.Some.Total)
	assert.InDelta(t, 0.0, s.Full.Avg10, 0.001)
	assert.Equal(t, uint64(0), s.Full.Total)
}

func TestLinuxParsePSICPUOnlySomeLine(t *testing.T) {
	// CPU pressure only has a "some" line (CPU is never fully stalled).
	input := "some avg10=3.54 avg60=3.66 avg300=4.93 total=16971810727\n"
	s, err := parsePSI(input)
	require.NoError(t, err)
	assert.InDelta(t, 3.54, s.Some.Avg10, 0.001)
	assert.InDelta(t, 0.0, s.Full.Avg10, 0.001)
}

func TestLinuxParsePSIEmpty(t *testing.T) {
	_, err := parsePSI("")
	assert.Error(t, err, "empty input must return an error")
}

func TestLinuxParsePSIMalformed(t *testing.T) {
	// Non-PSI content — no "some" or "full" lines → must error.
	_, err := parsePSI("random garbage\nno psi fields\n")
	assert.Error(t, err)
}

func TestLinuxParsePSIRealFile(t *testing.T) {
	data, err := os.ReadFile("/proc/pressure/cpu")
	if err != nil {
		t.Skipf("PSI not available: %v", err)
	}
	s, err := parsePSI(string(data))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, s.Some.Avg10, 0.0)
	assert.GreaterOrEqual(t, s.Some.Total, uint64(0))
}

// ─── Unit: clock ticks ────────────────────────────────────────────────────────

func TestLinuxReadClockTicks(t *testing.T) {
	ticks := readClockTicks()
	// AT_CLKTCK is 100 on x86_64, ARM64, RISC-V Linux (universal since 2.6).
	assert.Equal(t, uint64(100), ticks, "expected AT_CLKTCK=100 on this platform")
}

// ─── Unit: self CPU measurement ───────────────────────────────────────────────

func TestLinuxProcSelfCPUTicksNonDecreasing(t *testing.T) {
	t1, err := procSelfCPUTicks()
	require.NoError(t, err)
	// t1 may legitimately be 0 if the process hasn't consumed a full 10ms tick yet.
	// We only require the read doesn't error and the value is uint64 (always >= 0).

	// Burn enough CPU to advance at least one 10ms clock tick (100 Hz = 10ms/tick).
	sum := 0
	for i := 0; i < 50_000_000; i++ {
		sum += i
	}
	_ = sum

	t2, err := procSelfCPUTicks()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, t2, t1, "CPU ticks must be non-decreasing")
	// After 50M iterations, at least 1 tick should have elapsed.
	assert.Greater(t, t2, uint64(0), "CPU ticks must be positive after burning CPU")
}

// ─── Unit: RSS measurement ───────────────────────────────────────────────────

func TestLinuxProcSelfRSSKiB(t *testing.T) {
	rss, err := procSelfRSSKiB()
	require.NoError(t, err)
	// A Go test binary has at least a few MiB of resident pages.
	assert.Greater(t, rss, uint64(1024), "RSS must be > 1 MiB for a Go test binary")
}

// ─── Unit: /proc attribution ──────────────────────────────────────────────────

func TestLinuxAttributePIDSelf(t *testing.T) {
	pid := os.Getpid()
	attr := attributePID(pid)
	assert.NotEmpty(t, attr.Comm, "comm must be non-empty for the running process")
	assert.GreaterOrEqual(t, attr.UID, 0, "UID must be >= 0")
	// On a cgroup v2 system (which we confirmed this host is), CgroupV2 is set.
	assert.NotEmpty(t, attr.CgroupV2, "cgroup v2 path must be present on this host")
}

func TestLinuxAttributePIDExePath(t *testing.T) {
	pid := os.Getpid()
	attr := attributePID(pid)
	// The Go test binary should resolve its exe symlink. Exe is best-effort:
	// it may be "" on hardened systems with ptrace restrictions, but when
	// present it must be an absolute path (/proc/<pid>/exe resolves a symlink).
	assert.True(t, attr.Exe == "" || filepath.IsAbs(attr.Exe),
		"Exe must be empty or an absolute path, got %q", attr.Exe)
}

func TestLinuxAttributePIDMissing(t *testing.T) {
	// PID 999999999 does not exist; attribution must not panic.
	attr := attributePID(999999999)
	assert.Empty(t, attr.Comm, "missing PID must return empty Comm")
	assert.Empty(t, attr.CgroupV2, "missing PID must return empty CgroupV2")
}

func TestLinuxAttributePIDPID1(t *testing.T) {
	// PID 1 should be readable on a non-hardened container host.
	attr := attributePID(1)
	// Comm may or may not be readable depending on namespace/hardening, but the
	// accessor must never return a non-empty value that is malformed: /proc comm
	// is a single trimmed line with no embedded newlines.
	assert.True(t, attr.Comm == "" || !strings.ContainsRune(attr.Comm, '\n'),
		"Comm must be empty or a single trimmed line, got %q", attr.Comm)
}

// ─── Unit: container ID extraction ────────────────────────────────────────────

func TestLinuxExtractContainerIDNone(t *testing.T) {
	// Root cgroup → not in a container.
	assert.Empty(t, extractContainerID("/"))
	assert.Empty(t, extractContainerID(""))
	assert.Empty(t, extractContainerID("/system.slice/myservice.service"))
}

func TestLinuxExtractContainerIDDocker(t *testing.T) {
	id := "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
	path := "/docker/" + id
	got := extractContainerID(path)
	assert.Equal(t, id, got)
}

func TestLinuxExtractContainerIDDockerScope(t *testing.T) {
	id := "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
	path := "/system.slice/docker-" + id + ".scope"
	got := extractContainerID(path)
	assert.Equal(t, id, got)
}

func TestLinuxExtractContainerIDCRI(t *testing.T) {
	// containerd/CRI-O: /kubepods/besteffort/pod.../abc123...64hexchars
	id := "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
	path := "/kubepods/besteffort/pod-uuid/" + id
	got := extractContainerID(path)
	assert.Equal(t, id, got)
}

// ─── Unit: /proc disk stats ───────────────────────────────────────────────────

func TestLinuxReadDiskStats(t *testing.T) {
	stats := readDiskStats()
	if len(stats) == 0 {
		t.Skip("no real block devices visible in /proc/diskstats")
	}
	for dev, row := range stats {
		assert.NotEmpty(t, dev)
		// Sectors are non-negative (trivially true for uint64, but verify not
		// wrapped — values should be sane order of magnitude).
		assert.Less(t, row.ReadSectors, uint64(1<<60), "sector count implausibly large for %s", dev)
	}
}

// ─── Unit: /proc net stats ────────────────────────────────────────────────────

func TestLinuxReadNetStats(t *testing.T) {
	stats := readNetStats()
	require.NotEmpty(t, stats, "/proc/net/dev must expose at least lo")
	lo, ok := stats["lo"]
	if !ok {
		t.Skip("lo interface not found in /proc/net/dev")
	}
	// loopback RX bytes must equal TX bytes.
	assert.Equal(t, lo.RxBytes, lo.TxBytes, "loopback RX must equal TX")
}

// ─── Unit: netlink connector probe ────────────────────────────────────────────

func TestLinuxNetlinkConnectorProbe(t *testing.T) {
	cfg := DefaultLinuxConfig()
	var buf bytes.Buffer
	sink := NewSink(&buf)
	col := NewLinuxCollector(cfg, sink)
	result := col.probeNetlinkReachability()

	// The result must always be a valid ReachabilityResult — no panic, no crash.
	assert.Equal(t, SignalLinuxProcExec, result.Class)
	assert.Equal(t, MechanismNetlinkConnector, result.Mechanism)
	assert.Equal(t, "CN_IDX_PROC", result.Provider)

	if result.Reachable {
		t.Log("NETLINK_CONNECTOR: reachable (running with CAP_NET_ADMIN or root)")
	} else {
		t.Logf("NETLINK_CONNECTOR: not reachable: %s (expected in non-privileged containers)", result.Error)
	}
}

// ─── Unit: proc snapshot ──────────────────────────────────────────────────────

func TestLinuxProcSnapshot(t *testing.T) {
	pids := procSnapshot()
	require.NotEmpty(t, pids, "procSnapshot must return at least one PID")
	// The current process must be in the snapshot.
	selfPID := os.Getpid()
	_, hasSelf := pids[selfPID]
	assert.True(t, hasSelf, "procSnapshot must include current process PID %d", selfPID)
}

// ─── Integration: probeAll ────────────────────────────────────────────────────

func TestLinuxCollectorProbeAll(t *testing.T) {
	cfg := DefaultLinuxConfig()
	var buf bytes.Buffer
	sink := NewSink(&buf)
	col := NewLinuxCollector(cfg, sink)
	results := col.probeAll()
	require.NotEmpty(t, results, "probeAll must return at least one result")

	// Every Linux-mandatory source must have a probe result.
	classMap := make(map[SignalClass]bool)
	for _, r := range results {
		classMap[r.Class] = true
	}

	mandatory := []SignalClass{
		SignalLinuxProcExec, // proc connector or proc poll
		SignalLinuxPSICPU,
		SignalLinuxPSIMem,
		SignalLinuxPSIIO,
		SignalLinuxDiskIO,
		SignalLinuxNet,
		SignalLinuxThermal,
	}
	for _, class := range mandatory {
		assert.True(t, classMap[class], "class %q must appear in probeAll results", class)
	}

	// At least the /proc-based sources must be reachable (no privilege needed).
	reachable := 0
	for _, r := range results {
		if r.Reachable {
			reachable++
		}
	}
	assert.GreaterOrEqual(t, reachable, 4, "at least 4 sources must be reachable without privilege")
}

// ─── Integration: RunShort ────────────────────────────────────────────────────

// TestLinuxCollectorRunShort runs the full collection spike for 5 seconds and
// verifies the invariants of the report: non-zero event count, overhead within
// budget, valid JSON output, correct source set.
func TestLinuxCollectorRunShort(t *testing.T) {
	cfg := DefaultLinuxConfig()
	cfg.OverheadWindowSec = 5
	cfg.MaxEventsPerClass = 20

	var buf bytes.Buffer
	sink := NewSink(&buf)
	col := NewLinuxCollector(cfg, sink)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := col.Run(ctx)
	require.NoError(t, err)

	// All signal classes must have been probed.
	classMap := make(map[SignalClass]bool)
	for _, r := range report.Reachability {
		classMap[r.Class] = true
	}
	for _, class := range allLinuxSignalClasses {
		assert.True(t, classMap[class], "signal class %q missing from report", class)
	}

	// Overhead budget check.
	assert.Equal(t, 1.0, report.Overhead.BudgetPercent, "budget must be 1.0%%")
	assert.Greater(t, report.Overhead.DurationSec, 0.0, "duration must be positive")
	assert.True(t, report.Overhead.WithinBudget,
		"CPU overhead %.3f%% exceeds 1.0%% budget", report.Overhead.CPUPercent)

	// RSS must be positive.
	assert.Greater(t, report.RSSKiB, uint64(0), "RSS must be positive")

	// At least some events must have been captured from /proc/pressure, diskstats, net, thermal.
	assert.Greater(t, report.TotalEvents, 0, "must have captured at least one event")

	// All output must be valid JSON lines.
	rawLines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	for i, line := range rawLines {
		if line == "" {
			continue
		}
		var rec SpikeRecord
		assert.NoError(t, json.Unmarshal([]byte(line), &rec),
			"line %d is not valid JSON: %s", i, line)
	}

	t.Logf("Linux spike results:")
	t.Logf("  events captured:  %d (%.2f/s)", report.TotalEvents, report.EventsPerSec)
	t.Logf("  dropped events:   %d", report.DroppedEvents)
	t.Logf("  CPU overhead:     %.4f%% (budget 1.0%%)", report.Overhead.CPUPercent)
	t.Logf("  RSS peak:         %d KiB", report.RSSKiB)
	t.Logf("  sources active:   %v", report.SourcesActive)
	t.Logf("  clock ticks/s:    %d", report.ClkTck)
}

// ─── Integration: context cancellation ───────────────────────────────────────

func TestLinuxCollectorRunContextCancel(t *testing.T) {
	cfg := DefaultLinuxConfig()
	cfg.OverheadWindowSec = 60 // would take 60s without cancellation

	var buf bytes.Buffer
	col := NewLinuxCollector(cfg, NewSink(&buf))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var report LinuxSpikeReport
	var runErr error
	go func() {
		report, runErr = col.Run(ctx)
		close(done)
	}()

	// Wait for Run to launch all collection goroutines, then cancel — well
	// within the 60s window. Using the startup signal instead of a sleep makes
	// the cancellation test deterministic under CI load.
	select {
	case <-col.Started():
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not signal startup within 5s")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return within 5s of context cancellation")
	}
	require.NoError(t, runErr, "Run() must not return an error on context cancellation")
	// Duration must reflect the actual elapsed time (< 60s).
	assert.Less(t, report.Overhead.DurationSec, 10.0, "must have stopped well before the 60s window")
}

// ─── Integration: LinuxSpikeReport JSON round-trip ───────────────────────────

func TestLinuxSpikeReportJSONRoundtrip(t *testing.T) {
	report := LinuxSpikeReport{
		SpikeReport: SpikeReport{
			Reachability: []ReachabilityResult{
				{Class: SignalLinuxPSICPU, Mechanism: MechanismPSI, Provider: "/proc/pressure/cpu", Reachable: true},
				{Class: SignalLinuxProcExec, Mechanism: MechanismNetlinkConnector, Provider: "CN_IDX_PROC",
					Reachable: false, Error: "subscribe: connection refused"},
			},
			Overhead: OverheadSample{
				DurationSec:   60.0,
				CPUPercent:    0.023,
				BudgetPercent: 1.0,
				WithinBudget:  true,
			},
			TotalEvents: 1234,
		},
		RSSKiB:        8192,
		DroppedEvents: 0,
		EventsPerSec:  20.57,
		SourcesActive: []string{"proc_poll", "psi", "diskstats", "net_dev", "thermal_sysfs"},
		ClkTck:        100,
	}

	data, err := json.Marshal(report)
	require.NoError(t, err)

	var decoded LinuxSpikeReport
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, report.TotalEvents, decoded.TotalEvents)
	assert.InDelta(t, report.EventsPerSec, decoded.EventsPerSec, 0.001)
	assert.Equal(t, report.SourcesActive, decoded.SourcesActive)
	assert.Equal(t, report.ClkTck, decoded.ClkTck)
	assert.Equal(t, report.RSSKiB, decoded.RSSKiB)
	assert.Len(t, decoded.Reachability, 2)
	assert.False(t, decoded.Reachability[1].Reachable)
	assert.Equal(t, "subscribe: connection refused", decoded.Reachability[1].Error)
}

// ─── Integration: sustained stability (10-minute analog) ──────────────────────

// TestLinuxCollectorStability runs the collector for a longer window to prove
// Part 5 (sustained stability): no crash, no upward memory trend, bounded drops.
//
// Gated on LINUX_SPIKE_LONGRUN=1 so it doesn't run in standard CI
// (which times out after 30s). Run explicitly for the feasibility report:
//
//	LINUX_SPIKE_LONGRUN=1 go test -tags spike -v -run TestLinuxCollectorStability \
//	  -timeout 900s ./features/steward/dex/
func TestLinuxCollectorStability(t *testing.T) {
	if os.Getenv("LINUX_SPIKE_LONGRUN") != "1" {
		t.Skip("set LINUX_SPIKE_LONGRUN=1 to run the sustained stability window (10 min)")
	}

	cfg := DefaultLinuxConfig()
	cfg.OverheadWindowSec = 600 // 10 minutes
	cfg.MaxEventsPerClass = 100_000
	cfg.ProcPollInterval = 100 * time.Millisecond
	cfg.PSISampleInterval = 5 * time.Second
	cfg.DiskStatInterval = 5 * time.Second

	// Use io.Discard as the sink: this simulates a real streaming consumer where
	// events are forwarded/written and not accumulated in memory. Using bytes.Buffer
	// would accumulate all event JSON and inflate RSS, masking true memory stability.
	col := NewLinuxCollector(cfg, NewSink(io.Discard))

	ctx, cancel := context.WithTimeout(context.Background(), 620*time.Second)
	defer cancel()

	// Sample RSS every 60 seconds to detect upward memory trend.
	rssSamples := make([]uint64, 0, 12)
	rssErrCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rss, err := procSelfRSSKiB()
				if err == nil {
					rssSamples = append(rssSamples, rss)
					t.Logf("RSS at minute %d: %d KiB", len(rssSamples), rss)
				}
			case <-rssErrCh:
				return
			}
		}
	}()

	report, err := col.Run(ctx)
	close(rssErrCh)
	require.NoError(t, err, "Run() must not error during sustained stability window")

	t.Logf("=== 10-minute stability results ===")
	t.Logf("events captured:  %d (%.2f/s)", report.TotalEvents, report.EventsPerSec)
	t.Logf("dropped events:   %d", report.DroppedEvents)
	t.Logf("CPU overhead:     %.4f%% (budget 1.0%%)", report.Overhead.CPUPercent)
	t.Logf("RSS peak:         %d KiB", report.RSSKiB)
	t.Logf("sources active:   %v", report.SourcesActive)
	t.Logf("RSS samples:      %v", rssSamples)

	// Stability assertions.
	assert.True(t, report.Overhead.WithinBudget,
		"CPU overhead %.3f%% must be within 1.0%% budget", report.Overhead.CPUPercent)
	assert.Zero(t, report.DroppedEvents, "zero drops expected on /proc sources")

	// Memory trend: no sample should be >2x the first sample (rough leak check).
	if len(rssSamples) >= 2 {
		first := rssSamples[0]
		last := rssSamples[len(rssSamples)-1]
		assert.Less(t, last, first*2,
			"RSS grew from %d to %d KiB — possible memory leak", first, last)
	}
}

// ─── Unit: netlink message helpers ────────────────────────────────────────────

func TestLinuxAlignNL(t *testing.T) {
	cases := []struct{ n, want int }{
		{0, 0}, {1, 4}, {3, 4}, {4, 4}, {5, 8}, {16, 16}, {17, 20},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, alignNL(tc.n), "alignNL(%d)", tc.n)
	}
}

func TestLinuxProcEventDecodeNocrash(t *testing.T) {
	cfg := DefaultLinuxConfig()
	col := NewLinuxCollector(cfg, NewSink(bytes.NewBuffer(nil)))

	// Truncated buffer — must not panic.
	col.decodeProcEvent([]byte{})
	col.decodeProcEvent([]byte{1, 2, 3})

	// Well-formed fork event (48 bytes: 16-byte hdr + 16-byte fork + padding).
	buf := make([]byte, 48)
	// what = PROC_EVENT_FORK (0x00000001), little-endian
	buf[0] = 0x01
	col.decodeProcEvent(buf)

	// Well-formed exec event.
	buf2 := make([]byte, 32)
	buf2[0] = 0x02 // PROC_EVENT_EXEC
	col.decodeProcEvent(buf2)

	// Unknown event type — must be silently ignored.
	buf3 := make([]byte, 32)
	buf3[0] = 0xFF
	col.decodeProcEvent(buf3)
}

func TestLinuxParseProcConnectorMessages(t *testing.T) {
	cfg := DefaultLinuxConfig()
	col := NewLinuxCollector(cfg, NewSink(bytes.NewBuffer(nil)))

	// Completely empty buffer — must not panic.
	col.parseProcConnectorMessages([]byte{})

	// Truncated nlmsghdr — must not panic.
	col.parseProcConnectorMessages([]byte{1, 2, 3})

	// Valid nlmsghdr with Len=16 and empty payload — must not panic.
	hdr := make([]byte, 16)
	hdr[0] = 16 // Len (little-endian)
	col.parseProcConnectorMessages(hdr)
}
