// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux && spike

// This file implements the Linux DEX acquisition feasibility spike (Issue #2572).
// It is a throwaway PoC behind the "spike" AND "linux" build tags — never compiled
// into the production steward.
//
// Source architecture chosen (evaluated and measured on the real host):
//   - /proc polling (50 ms interval): process lifecycle detection
//   - /proc/pressure/{cpu,memory,io}: PSI health signals (kernel 4.20+)
//   - /proc/diskstats: disk I/O deltas
//   - /proc/net/dev: network interface deltas
//   - /sys/class/thermal/thermal_zone*/temp: thermal sensors
//   - /proc/[pid]/{comm,status,cgroup}: per-PID attribution (PID→process+user+cgroup v2)
//   - /proc/self/stat + /proc/self/status: overhead measurement
//   - NETLINK_CONNECTOR (CN_IDX_PROC): proc connector for process events — included
//     with graceful fallback; requires CAP_NET_ADMIN or root in the initial namespace
//     (blocked in non-privileged containers; works on the real steward host)
//
// eBPF envelope assessment (cross-cutting requirement):
//   eBPF (cilium/ebpf CO-RE) loads a kernel BPF object at runtime. This
//   constitutes "runtime code composition" per the CLAUDE.md threat model
//   ("no runtime code composition"). It is therefore ENVELOPE-INCOMPATIBLE in
//   the steward's deployment context UNLESS the BPF object (.o) is:
//   (a) compiled at build time and included in the signed steward package, and
//   (b) loaded from a declared, signed path — not generated or modified at runtime.
//   Under that constraint (cilium/ebpf CO-RE with a build-time .o), the loading
//   pattern is closer to "declared executable" than "runtime code composition" and
//   could satisfy the envelope. Additionally: CO-RE requires BTF (kernel 5.4+ with
//   CONFIG_DEBUG_INFO_BTF) and CAP_BPF + CAP_PERFMON (kernel 5.8+). Target kernel
//   range (RHEL 6 / kernel 2.6.32 at the low end) makes eBPF non-universal.
//   VERDICT: eBPF is conditionally envelope-compatible for kernel 5.8+ targets with
//   signed build-time BPF objects, but the /proc + PSI path is preferred for the
//   spike because it is universally available, envelope-unambiguous, and covers the
//   target signal set for headless Linux DEX targets.
//   See CONSUME_FEASIBILITY_LINUX.md for the full assessment.

package dex

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// ─── Linux-specific signal classes ───────────────────────────────────────────

const (
	// SignalLinuxProcExec covers process fork/exec/exit detected via /proc polling
	// or (when available) NETLINK_CONNECTOR proc connector events.
	SignalLinuxProcExec SignalClass = "linux_proc_exec"

	// SignalLinuxPSICPU covers CPU pressure stall information from /proc/pressure/cpu.
	SignalLinuxPSICPU SignalClass = "linux_psi_cpu"

	// SignalLinuxPSIMem covers memory pressure stall information from /proc/pressure/memory.
	SignalLinuxPSIMem SignalClass = "linux_psi_mem"

	// SignalLinuxPSIIO covers I/O pressure stall information from /proc/pressure/io.
	SignalLinuxPSIIO SignalClass = "linux_psi_io"

	// SignalLinuxDiskIO covers disk I/O deltas from /proc/diskstats.
	SignalLinuxDiskIO SignalClass = "linux_disk_io"

	// SignalLinuxNet covers network interface deltas from /proc/net/dev.
	SignalLinuxNet SignalClass = "linux_net"

	// SignalLinuxThermal covers thermal zone temperatures from /sys/class/thermal.
	SignalLinuxThermal SignalClass = "linux_thermal"
)

// ─── Linux-specific provider mechanisms ──────────────────────────────────────

const (
	// MechanismProcFS covers /proc filesystem polling for process events and attribution.
	MechanismProcFS ProviderMechanism = "procfs"

	// MechanismNetlinkConnector covers the NETLINK_CONNECTOR proc connector.
	MechanismNetlinkConnector ProviderMechanism = "netlink_connector"

	// MechanismPSI covers /proc/pressure/* pressure stall information.
	MechanismPSI ProviderMechanism = "psi"

	// MechanismSysFS covers /sys filesystem (thermal zones, hwmon).
	MechanismSysFS ProviderMechanism = "sysfs"
)

// ─── Netlink proc connector constants ────────────────────────────────────────
// These mirror the kernel's connector.h and cn_proc.h definitions.

const (
	nlMsgDone = uint16(0x3) // NLMSG_DONE

	cnIdxProc = uint32(1) // CN_IDX_PROC
	cnValProc = uint32(1) // CN_VAL_PROC

	procCnMcastListen = uint32(1) // PROC_CN_MCAST_LISTEN

	procEventNone uint32 = 0x00000000
	procEventFork uint32 = 0x00000001
	procEventExec uint32 = 0x00000002
	procEventExit uint32 = 0x80000000
)

// nlMsgHdr mirrors struct nlmsghdr (16 bytes, little-endian).
type nlMsgHdr struct {
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

// cnMsg mirrors struct cn_msg (20 bytes, little-endian).
type cnMsg struct {
	Idx   uint32
	Val   uint32
	Seq   uint32
	Ack   uint32
	Len   uint16
	Flags uint16
}

// procEventHdr mirrors the fixed header of struct proc_event:
//   what(4) + cpu(4) + timestamp_ns(8, aligned to 8)
// Total: 16 bytes.
type procEventHdr struct {
	What        uint32
	CPU         uint32
	TimestampNs uint64
}

// forkInfo mirrors proc_event.event_data.fork (16 bytes).
type forkInfo struct {
	ParentPid  int32
	ParentTgid int32
	ChildPid   int32
	ChildTgid  int32
}

// execInfo mirrors proc_event.event_data.exec (8 bytes).
type execInfo struct {
	ProcessPid  int32
	ProcessTgid int32
}

// exitInfo mirrors proc_event.event_data.exit (16 bytes).
type exitInfo struct {
	ProcessPid  int32
	ProcessTgid int32
	ExitCode    uint32
	ExitSignal  uint32
}

// ─── LinuxSpikeConfig ─────────────────────────────────────────────────────────

// LinuxSpikeConfig extends SpikeConfig with Linux-specific tuning knobs.
type LinuxSpikeConfig struct {
	SpikeConfig
	// ProcPollInterval is how often /proc is scanned for new processes.
	// Shorter intervals detect short-lived processes more reliably but add
	// /proc scanning overhead. Default: 50ms.
	ProcPollInterval time.Duration
	// PSISampleInterval is how often PSI pressure files are read.
	// Default: 1s.
	PSISampleInterval time.Duration
	// DiskStatInterval is how often /proc/diskstats deltas are computed.
	// Default: 1s.
	DiskStatInterval time.Duration
}

// DefaultLinuxConfig returns sensible defaults for a Linux PoC run.
func DefaultLinuxConfig() LinuxSpikeConfig {
	return LinuxSpikeConfig{
		SpikeConfig:       DefaultConfig(),
		ProcPollInterval:  50 * time.Millisecond,
		PSISampleInterval: 1 * time.Second,
		DiskStatInterval:  1 * time.Second,
	}
}

// ─── LinuxSpikeReport ─────────────────────────────────────────────────────────

// LinuxSpikeReport extends SpikeReport with Linux-specific measurements.
type LinuxSpikeReport struct {
	SpikeReport
	// RSSKiB is the peak resident set size (kibibytes) observed during collection.
	RSSKiB uint64 `json:"rss_kib"`
	// DroppedEvents is the count of events lost due to ring buffer exhaustion or
	// ENOBUFS on the netlink socket.
	DroppedEvents int64 `json:"dropped_events"`
	// EventsPerSec is the average event throughput during the collection window.
	EventsPerSec float64 `json:"events_per_sec"`
	// SourcesActive lists which sources successfully produced events.
	SourcesActive []string `json:"sources_active"`
	// ClkTck is the kernel's clock-tick frequency (AT_CLKTCK from /proc/self/auxv).
	ClkTck uint64 `json:"clk_tck"`
}

// ─── LinuxCollector ───────────────────────────────────────────────────────────

// LinuxCollector is the top-level Linux DEX feasibility spike entry point.
// It orchestrates multiple kernel data sources to prove that in-process, stable,
// low-overhead event consumption is achievable within the steward's service context.
type LinuxCollector struct {
	cfg        LinuxSpikeConfig
	sink       *Sink
	total      atomic.Int64  // events successfully written to sink
	dropped    atomic.Int64  // events dropped (ENOBUFS / ring exhaustion)
	sinkErrors atomic.Int64  // sink write failures

	mu           sync.Mutex
	sourcesActive []string

	// started is closed by Run once all collection goroutines have been
	// launched, giving callers a deterministic startup signal instead of an
	// arbitrary sleep. Consumed via Started().
	started chan struct{}
}

// NewLinuxCollector returns a LinuxCollector configured with cfg.
func NewLinuxCollector(cfg LinuxSpikeConfig, sink *Sink) *LinuxCollector {
	return &LinuxCollector{cfg: cfg, sink: sink, started: make(chan struct{})}
}

// Started returns a channel that Run closes once every collection goroutine has
// been launched. Callers (e.g. cancellation tests) wait on it to synchronize
// with Run's steady state without relying on wall-clock sleeps.
func (c *LinuxCollector) Started() <-chan struct{} {
	return c.started
}

// Run executes the full Linux spike: probes all sources, collects events for
// cfg.OverheadWindowSec, measures CPU + RSS overhead, and returns a LinuxSpikeReport.
func (c *LinuxCollector) Run(ctx context.Context) (LinuxSpikeReport, error) {
	clkTck := readClockTicks()

	// 1. Probe source availability.
	reach := c.probeAll()
	for _, r := range reach {
		if err := c.sink.WriteReachability(r); err != nil {
			return LinuxSpikeReport{}, fmt.Errorf("dex: sink write reachability: %w", err)
		}
	}

	// 2. Snapshot overhead baselines.
	cpuBefore, err := procSelfCPUTicks()
	if err != nil {
		return LinuxSpikeReport{}, fmt.Errorf("dex: read CPU ticks before: %w", err)
	}
	wallBefore := time.Now()
	rssPeak, _ := procSelfRSSKiB()

	// 3. Run collection sources for the overhead window.
	collectCtx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.OverheadWindowSec)*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// Proc connector (best-effort — requires CAP_NET_ADMIN / root in initial ns).
	if ok := c.probeNetlinkConnector(); ok {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runProcConnector(collectCtx)
		}()
	}

	// /proc polling for process lifecycle.
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runProcPoller(collectCtx)
	}()

	// PSI health signals.
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runPSIReader(collectCtx)
	}()

	// Disk I/O deltas.
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runDiskStatsReader(collectCtx)
	}()

	// Network interface deltas.
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runNetStatsReader(collectCtx)
	}()

	// Thermal sensors.
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runThermalReader(collectCtx)
	}()

	// RSS monitor — sample peak RSS every 5 s.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-collectCtx.Done():
				return
			case <-ticker.C:
				if rss, err := procSelfRSSKiB(); err == nil && rss > rssPeak {
					rssPeak = rss
				}
			}
		}
	}()

	// All collection goroutines are launched — signal startup completion so
	// callers can synchronize deterministically (e.g. before cancelling ctx).
	close(c.started)

	wg.Wait()

	// 4. Compute overhead.
	cpuAfter, err := procSelfCPUTicks()
	if err != nil {
		return LinuxSpikeReport{}, fmt.Errorf("dex: read CPU ticks after: %w", err)
	}
	wallElapsed := time.Since(wallBefore).Seconds()

	// Convert tick delta to CPU percent relative to one logical core.
	// clkTck ticks = 1 second; each tick = 1/clkTck of a core.
	cpuTickDelta := float64(cpuAfter - cpuBefore)
	cpuPct := 0.0
	if wallElapsed > 0 && clkTck > 0 {
		cpuPct = (cpuTickDelta / float64(clkTck) / wallElapsed) * 100.0
	}

	const budgetPct = 1.0
	overhead := OverheadSample{
		DurationSec:   wallElapsed,
		CPUPercent:    cpuPct,
		BudgetPercent: budgetPct,
		WithinBudget:  cpuPct <= budgetPct,
	}
	if err := c.sink.WriteOverhead(overhead); err != nil {
		return LinuxSpikeReport{}, fmt.Errorf("dex: sink write overhead: %w", err)
	}

	totalEvts := int(c.total.Load())
	evtsPerSec := 0.0
	if wallElapsed > 0 {
		evtsPerSec = float64(totalEvts) / wallElapsed
	}

	c.mu.Lock()
	activeSources := make([]string, len(c.sourcesActive))
	copy(activeSources, c.sourcesActive)
	c.mu.Unlock()

	return LinuxSpikeReport{
		SpikeReport: SpikeReport{
			Reachability: reach,
			Overhead:     overhead,
			TotalEvents:  totalEvts,
			SinkErrors:   int(c.sinkErrors.Load()),
		},
		RSSKiB:        rssPeak,
		DroppedEvents: c.dropped.Load(),
		EventsPerSec:  evtsPerSec,
		SourcesActive: activeSources,
		ClkTck:        clkTck,
	}, nil
}

// ─── Source probing ───────────────────────────────────────────────────────────

func (c *LinuxCollector) probeAll() []ReachabilityResult {
	var results []ReachabilityResult

	// Proc connector (NETLINK_CONNECTOR).
	results = append(results, c.probeNetlinkReachability())

	// /proc filesystem.
	results = append(results, c.probeProcFS())

	// PSI.
	for _, resource := range []string{"cpu", "memory", "io"} {
		results = append(results, c.probePSI(resource))
	}

	// Diskstats.
	results = append(results, c.probeDiskStats())

	// Net dev.
	results = append(results, c.probeNetDev())

	// Thermal.
	results = append(results, c.probeThermal())

	return results
}

func (c *LinuxCollector) probeNetlinkReachability() ReachabilityResult {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return ReachabilityResult{
			Class:     SignalLinuxProcExec,
			Mechanism: MechanismNetlinkConnector,
			Provider:  "CN_IDX_PROC",
			Reachable: false,
			Error:     "socket: " + err.Error(),
		}
	}
	defer unix.Close(fd)

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc}
	if err := unix.Bind(fd, sa); err != nil {
		return ReachabilityResult{
			Class:     SignalLinuxProcExec,
			Mechanism: MechanismNetlinkConnector,
			Provider:  "CN_IDX_PROC",
			Reachable: false,
			Error:     "bind: " + err.Error(),
		}
	}

	// Try sending the subscribe message.
	subscribeErr := nlConnectorSubscribe(fd)
	if subscribeErr != nil {
		return ReachabilityResult{
			Class:     SignalLinuxProcExec,
			Mechanism: MechanismNetlinkConnector,
			Provider:  "CN_IDX_PROC",
			Reachable: false,
			Error:     "subscribe: " + subscribeErr.Error(),
		}
	}

	return ReachabilityResult{
		Class:     SignalLinuxProcExec,
		Mechanism: MechanismNetlinkConnector,
		Provider:  "CN_IDX_PROC",
		Reachable: true,
	}
}

// probeNetlinkConnector returns true if NETLINK_CONNECTOR is available.
func (c *LinuxCollector) probeNetlinkConnector() bool {
	r := c.probeNetlinkReachability()
	return r.Reachable
}

func (c *LinuxCollector) probeProcFS() ReachabilityResult {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ReachabilityResult{
			Class: SignalLinuxProcExec, Mechanism: MechanismProcFS,
			Provider: "/proc", Reachable: false, Error: err.Error(),
		}
	}
	pidCount := 0
	for _, e := range entries {
		if e.IsDir() {
			if _, err := strconv.Atoi(e.Name()); err == nil {
				pidCount++
			}
		}
	}
	return ReachabilityResult{
		Class: SignalLinuxProcExec, Mechanism: MechanismProcFS,
		Provider: fmt.Sprintf("/proc (%d PIDs visible)", pidCount), Reachable: true,
	}
}

func (c *LinuxCollector) probePSI(resource string) ReachabilityResult {
	path := "/proc/pressure/" + resource
	var class SignalClass
	switch resource {
	case "cpu":
		class = SignalLinuxPSICPU
	case "memory":
		class = SignalLinuxPSIMem
	default:
		class = SignalLinuxPSIIO
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ReachabilityResult{
			Class: class, Mechanism: MechanismPSI,
			Provider: path, Reachable: false, Error: err.Error(),
		}
	}
	if _, err := parsePSI(string(data)); err != nil {
		return ReachabilityResult{
			Class: class, Mechanism: MechanismPSI,
			Provider: path, Reachable: false, Error: "parse: " + err.Error(),
		}
	}
	return ReachabilityResult{
		Class: class, Mechanism: MechanismPSI, Provider: path, Reachable: true,
	}
}

func (c *LinuxCollector) probeDiskStats() ReachabilityResult {
	data, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return ReachabilityResult{
			Class: SignalLinuxDiskIO, Mechanism: MechanismProcFS,
			Provider: "/proc/diskstats", Reachable: false, Error: err.Error(),
		}
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	realDevs := 0
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) > 2 && !strings.HasPrefix(fields[2], "loop") {
			realDevs++
		}
	}
	return ReachabilityResult{
		Class: SignalLinuxDiskIO, Mechanism: MechanismProcFS,
		Provider: fmt.Sprintf("/proc/diskstats (%d real devs)", realDevs), Reachable: true,
	}
}

func (c *LinuxCollector) probeNetDev() ReachabilityResult {
	_, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return ReachabilityResult{
			Class: SignalLinuxNet, Mechanism: MechanismProcFS,
			Provider: "/proc/net/dev", Reachable: false, Error: err.Error(),
		}
	}
	return ReachabilityResult{
		Class: SignalLinuxNet, Mechanism: MechanismProcFS, Provider: "/proc/net/dev", Reachable: true,
	}
}

func (c *LinuxCollector) probeThermal() ReachabilityResult {
	zones, err := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	if err != nil || len(zones) == 0 {
		return ReachabilityResult{
			Class: SignalLinuxThermal, Mechanism: MechanismSysFS,
			Provider: "/sys/class/thermal", Reachable: false,
			Error: "no thermal zones found",
		}
	}
	return ReachabilityResult{
		Class: SignalLinuxThermal, Mechanism: MechanismSysFS,
		Provider: fmt.Sprintf("/sys/class/thermal (%d zones)", len(zones)), Reachable: true,
	}
}

// ─── Proc connector source ────────────────────────────────────────────────────

// runProcConnector drains NETLINK_CONNECTOR proc events for the duration of ctx.
// Requires CAP_NET_ADMIN or root in the initial network namespace.
func (c *LinuxCollector) runProcConnector(ctx context.Context) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return
	}
	defer unix.Close(fd)

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc}
	if err := unix.Bind(fd, sa); err != nil {
		return
	}
	if err := nlConnectorSubscribe(fd); err != nil {
		return
	}

	c.mu.Lock()
	c.sourcesActive = append(c.sourcesActive, "netlink_connector")
	c.mu.Unlock()

	// Set a short receive deadline so we can check ctx.Done().
	buf := make([]byte, 8192)
	for {
		if ctx.Err() != nil {
			return
		}
		// Set a 100ms receive timeout via SO_RCVTIMEO so Recvfrom returns
		// promptly and the loop can observe ctx cancellation. If this fails,
		// Recvfrom would block indefinitely and defeat context cancellation, so
		// treat the failure as fatal for this goroutine rather than swallowing it.
		tv := unix.Timeval{Sec: 0, Usec: 100_000}
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			return
		}

		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			if err == unix.ENOBUFS {
				c.dropped.Add(1)
				continue
			}
			return
		}
		c.parseProcConnectorMessages(buf[:n])
	}
}

// parseProcConnectorMessages decodes one or more NLMSG records in buf and emits
// process events to the sink.
func (c *LinuxCollector) parseProcConnectorMessages(buf []byte) {
	for len(buf) >= 16 {
		var hdr nlMsgHdr
		if err := binary.Read(bytes.NewReader(buf[:16]), binary.LittleEndian, &hdr); err != nil {
			return
		}
		msgLen := int(hdr.Len)
		if msgLen < 16 || msgLen > len(buf) {
			return
		}
		payload := buf[16:msgLen]
		buf = buf[alignNL(msgLen):]

		if len(payload) < 20 {
			continue
		}
		var cn cnMsg
		if err := binary.Read(bytes.NewReader(payload[:20]), binary.LittleEndian, &cn); err != nil {
			continue
		}
		if cn.Idx != cnIdxProc || cn.Val != cnValProc {
			continue
		}
		evtBuf := payload[20:]
		if len(evtBuf) < 16 {
			continue
		}
		c.decodeProcEvent(evtBuf)
	}
}

// decodeProcEvent decodes a single proc_event from the payload following cn_msg.
func (c *LinuxCollector) decodeProcEvent(buf []byte) {
	if len(buf) < 16 {
		return
	}
	r := bytes.NewReader(buf)
	var hdr procEventHdr
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return
	}

	var fields map[string]any
	switch hdr.What {
	case procEventFork:
		if len(buf) < 16+16 {
			return
		}
		var fi forkInfo
		if err := binary.Read(r, binary.LittleEndian, &fi); err != nil {
			return
		}
		attr := attributePID(int(fi.ChildPid))
		fields = map[string]any{
			"event":       "fork",
			"parent_pid":  fi.ParentPid,
			"child_pid":   fi.ChildPid,
			"ts_ns":       hdr.TimestampNs,
		}
		mergeAttribution(fields, attr)

	case procEventExec:
		if len(buf) < 16+8 {
			return
		}
		var ei execInfo
		if err := binary.Read(r, binary.LittleEndian, &ei); err != nil {
			return
		}
		attr := attributePID(int(ei.ProcessPid))
		fields = map[string]any{
			"event":   "exec",
			"pid":     ei.ProcessPid,
			"ts_ns":   hdr.TimestampNs,
		}
		mergeAttribution(fields, attr)

	case procEventExit:
		if len(buf) < 16+16 {
			return
		}
		var xi exitInfo
		if err := binary.Read(r, binary.LittleEndian, &xi); err != nil {
			return
		}
		fields = map[string]any{
			"event":       "exit",
			"pid":         xi.ProcessPid,
			"exit_code":   xi.ExitCode,
			"exit_signal": xi.ExitSignal,
			"ts_ns":       hdr.TimestampNs,
		}

	default:
		return // unhandled event type
	}

	if c.total.Load() >= int64(c.cfg.MaxEventsPerClass)*int64(len(allLinuxSignalClasses)) {
		return
	}
	if err := c.sink.WriteEvent(SignalLinuxProcExec, fields); err != nil {
		c.sinkErrors.Add(1)
	} else {
		c.total.Add(1)
	}
}

// ─── /proc poller source ──────────────────────────────────────────────────────

// runProcPoller polls /proc at cfg.ProcPollInterval to detect process creation
// and exit, attributing each new PID via /proc/[pid]/{comm,status,cgroup}.
func (c *LinuxCollector) runProcPoller(ctx context.Context) {
	knownPIDs := procSnapshot()

	c.mu.Lock()
	c.sourcesActive = append(c.sourcesActive, "proc_poll")
	c.mu.Unlock()

	ticker := time.NewTicker(c.cfg.ProcPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.total.Load() >= int64(c.cfg.MaxEventsPerClass)*int64(len(allLinuxSignalClasses)) {
				continue
			}
			current := procSnapshot()
			// Detect new processes.
			for pid := range current {
				if _, seen := knownPIDs[pid]; seen {
					continue
				}
				attr := attributePID(pid)
				fields := map[string]any{"event": "exec", "pid": pid}
				mergeAttribution(fields, attr)
				if err := c.sink.WriteEvent(SignalLinuxProcExec, fields); err != nil {
					c.sinkErrors.Add(1)
				} else {
					c.total.Add(1)
				}
			}
			// Detect exited processes (don't emit for all exits; just track counts).
			for pid := range knownPIDs {
				if _, still := current[pid]; !still {
					fields := map[string]any{"event": "exit", "pid": pid}
					if err := c.sink.WriteEvent(SignalLinuxProcExec, fields); err != nil {
						c.sinkErrors.Add(1)
					} else {
						c.total.Add(1)
					}
				}
			}
			knownPIDs = current
		}
	}
}

// procSnapshot returns the current set of PIDs visible in /proc.
func procSnapshot() map[int]struct{} {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	pids := make(map[int]struct{}, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids[pid] = struct{}{}
		}
	}
	return pids
}

// ─── PSI source ───────────────────────────────────────────────────────────────

func (c *LinuxCollector) runPSIReader(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.PSISampleInterval)
	defer ticker.Stop()

	c.mu.Lock()
	c.sourcesActive = append(c.sourcesActive, "psi")
	c.mu.Unlock()

	type psiDef struct {
		path  string
		class SignalClass
	}
	sources := []psiDef{
		{"/proc/pressure/cpu", SignalLinuxPSICPU},
		{"/proc/pressure/memory", SignalLinuxPSIMem},
		{"/proc/pressure/io", SignalLinuxPSIIO},
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, s := range sources {
				if c.total.Load() >= int64(c.cfg.MaxEventsPerClass)*int64(len(allLinuxSignalClasses)) {
					break
				}
				data, err := os.ReadFile(s.path)
				if err != nil {
					continue
				}
				psi, err := parsePSI(string(data))
				if err != nil {
					continue
				}
				fields := map[string]any{
					"some_avg10":  psi.Some.Avg10,
					"some_avg60":  psi.Some.Avg60,
					"some_avg300": psi.Some.Avg300,
					"some_total":  psi.Some.Total,
					"full_avg10":  psi.Full.Avg10,
					"full_avg60":  psi.Full.Avg60,
					"full_avg300": psi.Full.Avg300,
					"full_total":  psi.Full.Total,
				}
				if err := c.sink.WriteEvent(s.class, fields); err != nil {
					c.sinkErrors.Add(1)
				} else {
					c.total.Add(1)
				}
			}
		}
	}
}

// ─── Disk stats source ────────────────────────────────────────────────────────

type diskStatRow struct {
	ReadSectors  uint64
	WriteSectors uint64
	ReadMs       uint64
	WriteMs      uint64
}

func (c *LinuxCollector) runDiskStatsReader(ctx context.Context) {
	prev := readDiskStats()

	c.mu.Lock()
	c.sourcesActive = append(c.sourcesActive, "diskstats")
	c.mu.Unlock()

	ticker := time.NewTicker(c.cfg.DiskStatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.total.Load() >= int64(c.cfg.MaxEventsPerClass)*int64(len(allLinuxSignalClasses)) {
				continue
			}
			curr := readDiskStats()
			for dev, cur := range curr {
				prv, ok := prev[dev]
				if !ok {
					continue
				}
				deltaReadSec := cur.ReadSectors - prv.ReadSectors
				deltaWriteSec := cur.WriteSectors - prv.WriteSectors
				deltaReadMs := cur.ReadMs - prv.ReadMs
				deltaWriteMs := cur.WriteMs - prv.WriteMs
				if deltaReadSec == 0 && deltaWriteSec == 0 {
					continue
				}
				fields := map[string]any{
					"dev":            dev,
					"read_sectors":   deltaReadSec,
					"write_sectors":  deltaWriteSec,
					"read_ms":        deltaReadMs,
					"write_ms":       deltaWriteMs,
				}
				if err := c.sink.WriteEvent(SignalLinuxDiskIO, fields); err != nil {
					c.sinkErrors.Add(1)
				} else {
					c.total.Add(1)
				}
			}
			prev = curr
		}
	}
}

// readDiskStats parses /proc/diskstats into a map keyed by device name.
// Field layout (1-indexed in kernel docs, 0-indexed here after major/minor/name):
//   0=reads_completed, 1=reads_merged, 2=sectors_read, 3=time_reading_ms,
//   4=writes_completed, 5=writes_merged, 6=sectors_written, 7=time_writing_ms, ...
func readDiskStats() map[string]diskStatRow {
	data, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return nil
	}
	result := make(map[string]diskStatRow)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		dev := fields[2]
		// Skip loop devices and ram devices.
		if strings.HasPrefix(dev, "loop") || strings.HasPrefix(dev, "ram") {
			continue
		}
		var row diskStatRow
		row.ReadSectors, _ = strconv.ParseUint(fields[5], 10, 64)
		row.WriteSectors, _ = strconv.ParseUint(fields[9], 10, 64)
		row.ReadMs, _ = strconv.ParseUint(fields[6], 10, 64)
		row.WriteMs, _ = strconv.ParseUint(fields[10], 10, 64)
		result[dev] = row
	}
	return result
}

// ─── Network stats source ─────────────────────────────────────────────────────

type netStatRow struct {
	RxBytes uint64
	TxBytes uint64
	RxPkts  uint64
	TxPkts  uint64
}

func (c *LinuxCollector) runNetStatsReader(ctx context.Context) {
	prev := readNetStats()

	c.mu.Lock()
	c.sourcesActive = append(c.sourcesActive, "net_dev")
	c.mu.Unlock()

	ticker := time.NewTicker(c.cfg.DiskStatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.total.Load() >= int64(c.cfg.MaxEventsPerClass)*int64(len(allLinuxSignalClasses)) {
				continue
			}
			curr := readNetStats()
			for iface, cur := range curr {
				prv, ok := prev[iface]
				if !ok {
					continue
				}
				deltaRxBytes := cur.RxBytes - prv.RxBytes
				deltaTxBytes := cur.TxBytes - prv.TxBytes
				if deltaRxBytes == 0 && deltaTxBytes == 0 {
					continue
				}
				fields := map[string]any{
					"iface":    iface,
					"rx_bytes": deltaRxBytes,
					"tx_bytes": deltaTxBytes,
					"rx_pkts":  cur.RxPkts - prv.RxPkts,
					"tx_pkts":  cur.TxPkts - prv.TxPkts,
				}
				if err := c.sink.WriteEvent(SignalLinuxNet, fields); err != nil {
					c.sinkErrors.Add(1)
				} else {
					c.total.Add(1)
				}
			}
			prev = curr
		}
	}
}

// readNetStats parses /proc/net/dev.
// Format after the 2-line header: iface: rx_bytes rx_pkts ... tx_bytes tx_pkts ...
func readNetStats() map[string]netStatRow {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil
	}
	result := make(map[string]netStatRow)
	for i, line := range strings.Split(string(data), "\n") {
		if i < 2 { // skip header lines
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		var row netStatRow
		row.RxBytes, _ = strconv.ParseUint(fields[0], 10, 64)
		row.RxPkts, _ = strconv.ParseUint(fields[1], 10, 64)
		row.TxBytes, _ = strconv.ParseUint(fields[8], 10, 64)
		row.TxPkts, _ = strconv.ParseUint(fields[9], 10, 64)
		result[iface] = row
	}
	return result
}

// ─── Thermal source ───────────────────────────────────────────────────────────

func (c *LinuxCollector) runThermalReader(ctx context.Context) {
	zones, err := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	if err != nil || len(zones) == 0 {
		return
	}

	c.mu.Lock()
	c.sourcesActive = append(c.sourcesActive, "thermal_sysfs")
	c.mu.Unlock()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	readZones := func() {
		for _, path := range zones {
			if c.total.Load() >= int64(c.cfg.MaxEventsPerClass)*int64(len(allLinuxSignalClasses)) {
				return
			}
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			milliC, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
			if err != nil {
				continue
			}
			// Extract zone number from path (thermal_zone0 → "0")
			zone := filepath.Base(filepath.Dir(path))
			zone = strings.TrimPrefix(zone, "thermal_zone")

			// Read zone type if available
			zoneType := ""
			if typeData, err := os.ReadFile(filepath.Dir(path) + "/type"); err == nil {
				zoneType = strings.TrimSpace(string(typeData))
			}

			fields := map[string]any{
				"zone":       zone,
				"type":       zoneType,
				"temp_mc":    milliC,      // milli-Celsius
				"temp_c":     float64(milliC) / 1000.0,
			}
			if err := c.sink.WriteEvent(SignalLinuxThermal, fields); err != nil {
				c.sinkErrors.Add(1)
			} else {
				c.total.Add(1)
			}
		}
	}

	readZones() // sample immediately on start
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			readZones()
		}
	}
}

// ─── Attribution helpers ──────────────────────────────────────────────────────

// procAttribution holds per-PID attribution data read from /proc.
type procAttribution struct {
	Comm      string // /proc/[pid]/comm — short process name (≤15 chars)
	Exe       string // /proc/[pid]/exe symlink target
	UID       int    // real UID from /proc/[pid]/status
	CgroupV2  string // cgroup v2 path from /proc/[pid]/cgroup (line "0::/...")
	Container string // container ID extracted from cgroup path ("" if not containerised)
}

// attributePID reads /proc/[pid]/* to build per-process attribution.
// Returns a zero-value attribution if the PID has already exited.
func attributePID(pid int) procAttribution {
	base := fmt.Sprintf("/proc/%d", pid)
	var attr procAttribution

	if comm, err := os.ReadFile(base + "/comm"); err == nil {
		attr.Comm = strings.TrimSpace(string(comm))
	}

	if exe, err := os.Readlink(base + "/exe"); err == nil {
		attr.Exe = exe
	}

	if statusData, err := os.ReadFile(base + "/status"); err == nil {
		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					attr.UID, _ = strconv.Atoi(fields[1])
				}
				break
			}
		}
	}

	if cgroupData, err := os.ReadFile(base + "/cgroup"); err == nil {
		// cgroup v2: single line "0::/path/to/slice"
		// cgroup v1: multiple lines "N:subsystem:/path"
		for _, line := range strings.Split(string(cgroupData), "\n") {
			if strings.HasPrefix(line, "0::") {
				attr.CgroupV2 = strings.TrimPrefix(line, "0::")
				attr.Container = extractContainerID(attr.CgroupV2)
				break
			}
		}
	}

	return attr
}

// extractContainerID parses a cgroup v2 path for a Docker/containerd container ID.
// Returns "" for host or non-container paths.
// Example paths:
//   /docker/abc123def456...   → "abc123def456..."
//   /system.slice/docker-abc123.scope → "abc123"
//   /                          → ""
func extractContainerID(cgroupPath string) string {
	parts := strings.Split(strings.Trim(cgroupPath, "/"), "/")
	for _, part := range parts {
		// Docker: /docker/<64-char hex ID>
		if strings.HasPrefix(part, "docker") && len(part) > 7 {
			id := strings.TrimPrefix(part, "docker-")
			id = strings.TrimSuffix(id, ".scope")
			if isHexID(id) {
				return id
			}
		}
		// containerd/CRI-O: last path component may be a 64-char hex ID
		if len(part) == 64 && isHexID(part) {
			return part
		}
	}
	return ""
}

// isHexID returns true if s consists of lowercase hex characters.
func isHexID(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return len(s) >= 12
}

// mergeAttribution copies attribution fields into a fields map.
func mergeAttribution(fields map[string]any, attr procAttribution) {
	if attr.Comm != "" {
		fields["comm"] = attr.Comm
	}
	if attr.Exe != "" {
		fields["exe"] = attr.Exe
	}
	fields["uid"] = attr.UID
	if attr.CgroupV2 != "" {
		fields["cgroup"] = attr.CgroupV2
	}
	if attr.Container != "" {
		fields["container_id"] = attr.Container
	}
}

// ─── PSI parser ───────────────────────────────────────────────────────────────

// psiSample holds parsed /proc/pressure/* values.
type psiSample struct {
	Some struct {
		Avg10  float64
		Avg60  float64
		Avg300 float64
		Total  uint64
	}
	Full struct {
		Avg10  float64
		Avg60  float64
		Avg300 float64
		Total  uint64
	}
}

// parsePSI parses /proc/pressure/{cpu,memory,io} content into a psiSample.
func parsePSI(data string) (psiSample, error) {
	var s psiSample
	parsed := 0
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var target *struct {
			Avg10  float64
			Avg60  float64
			Avg300 float64
			Total  uint64
		}
		switch fields[0] {
		case "some":
			target = &s.Some
		case "full":
			target = &s.Full
		default:
			continue
		}
		for _, kv := range fields[1:] {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				continue
			}
			switch parts[0] {
			case "avg10":
				target.Avg10, _ = strconv.ParseFloat(parts[1], 64)
			case "avg60":
				target.Avg60, _ = strconv.ParseFloat(parts[1], 64)
			case "avg300":
				target.Avg300, _ = strconv.ParseFloat(parts[1], 64)
			case "total":
				target.Total, _ = strconv.ParseUint(parts[1], 10, 64)
			}
		}
		parsed++
	}
	if parsed == 0 {
		return s, fmt.Errorf("no PSI lines found")
	}
	return s, nil
}

// ─── Overhead helpers ─────────────────────────────────────────────────────────

// procSelfCPUTicks reads utime + stime from /proc/self/stat.
// Fields after the closing ')' of comm: state ppid pgrp session tty tpgid flags
// minflt cminflt majflt cmajflt utime(11) stime(12) ...
func procSelfCPUTicks() (uint64, error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 || end+2 >= len(data) {
		return 0, fmt.Errorf("malformed /proc/self/stat")
	}
	fields := strings.Fields(string(data[end+2:]))
	if len(fields) < 13 {
		return 0, fmt.Errorf("insufficient fields in /proc/self/stat: %d", len(fields))
	}
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("utime: %w", err)
	}
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("stime: %w", err)
	}
	return utime + stime, nil
}

// procSelfRSSKiB reads VmRSS from /proc/self/status in kibibytes.
func procSelfRSSKiB() (uint64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strconv.ParseUint(fields[1], 10, 64)
			}
		}
	}
	return 0, fmt.Errorf("VmRSS not found in /proc/self/status")
}

// readClockTicks reads AT_CLKTCK from /proc/self/auxv.
// Returns 100 (correct for x86_64 Linux) if the entry is not found.
func readClockTicks() uint64 {
	data, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return 100
	}
	const atClkTck = 17
	for i := 0; i+16 <= len(data); i += 16 {
		typ := binary.LittleEndian.Uint64(data[i:])
		val := binary.LittleEndian.Uint64(data[i+8:])
		if typ == atClkTck {
			if val == 0 {
				return 100
			}
			return val
		}
		if typ == 0 {
			break
		}
	}
	return 100
}

// ─── Netlink helpers ──────────────────────────────────────────────────────────

// nlConnectorSubscribe sends the PROC_CN_MCAST_LISTEN message on fd.
func nlConnectorSubscribe(fd int) error {
	pid := uint32(os.Getpid())

	// Build subscribe message: nlmsghdr(16) + cn_msg(20) + uint32(PROC_CN_MCAST_LISTEN)
	const payloadSize = 20 + 4 // cn_msg + op
	const totalSize = 16 + payloadSize

	buf := make([]byte, totalSize)
	w := bytes.NewBuffer(buf[:0])

	// nlmsghdr
	_ = binary.Write(w, binary.LittleEndian, nlMsgHdr{
		Len:  totalSize,
		Type: nlMsgDone,
		Pid:  pid,
	})
	// cn_msg
	_ = binary.Write(w, binary.LittleEndian, cnMsg{
		Idx: cnIdxProc,
		Val: cnValProc,
		Len: 4,
	})
	// PROC_CN_MCAST_LISTEN
	_ = binary.Write(w, binary.LittleEndian, procCnMcastListen)

	dst := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	return unix.Sendto(fd, w.Bytes(), 0, dst)
}

// alignNL rounds n up to the next NLMSG_ALIGNTO (4-byte) boundary.
func alignNL(n int) int {
	const nlmsgAlignTo = 4
	return (n + nlmsgAlignTo - 1) &^ (nlmsgAlignTo - 1)
}

// allLinuxSignalClasses lists every Linux spike signal class, used for
// per-class event cap calculations.
var allLinuxSignalClasses = []SignalClass{
	SignalLinuxProcExec,
	SignalLinuxPSICPU,
	SignalLinuxPSIMem,
	SignalLinuxPSIIO,
	SignalLinuxDiskIO,
	SignalLinuxNet,
	SignalLinuxThermal,
}
