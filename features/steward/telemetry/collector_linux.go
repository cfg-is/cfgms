// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package telemetry

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// linuxCollector reads the process table from /proc and services from the
// systemd Manager over the D-Bus system bus. It is usermode only — no eBPF, no
// netlink, no shelling out — matching the settled DEX Linux collection
// architecture (features/steward/dex/collector_linux_spike.go, /proc path).
//
// CPU percent is a delta between consecutive Snapshot calls: /proc/[pid]/stat
// exposes cumulative CPU ticks, so a single read cannot yield a rate. The
// collector caches the previous per-PID tick counts and wall clock; the first
// Snapshot therefore reports CPUPercent 0 for every process, and each subsequent
// Snapshot reports usage over the interval since the previous call. This is the
// same delta shape the spike's poll loop proved.
type linuxCollector struct {
	mu       sync.Mutex
	clkTck   float64        // kernel clock ticks per second (AT_CLKTCK)
	prev     map[int]uint64 // pid -> cumulative CPU ticks at the previous Snapshot
	prevWall time.Time      // wall clock at the previous Snapshot
}

// NewCollector returns a Linux telemetry collector.
func NewCollector() Collector {
	return &linuxCollector{
		clkTck: float64(readClockTicks()),
		prev:   make(map[int]uint64),
	}
}

// Snapshot collects the current process table (/proc) and systemd service list
// (D-Bus). A missing/unreachable system bus is a soft failure: processes are
// still returned and Services is nil (a headless container without systemd is a
// valid environment, not a collection error). A failure to read /proc — the
// core of the snapshot — is a hard error.
func (c *linuxCollector) Snapshot(ctx context.Context) (Telemetry, error) {
	if err := ctx.Err(); err != nil {
		return Telemetry{}, err
	}
	procs, err := c.collectProcesses()
	if err != nil {
		return Telemetry{}, err
	}
	// Services are best-effort: absence of systemd/D-Bus must not fail the whole
	// snapshot (the required process telemetry already succeeded).
	svcs := collectSystemdServices(ctx)
	return Telemetry{Processes: procs, Services: svcs}, nil
}

// collectProcesses walks /proc and builds one ProcessSnapshot per live PID,
// computing CPU percent from the delta against the previous Snapshot.
func (c *linuxCollector) collectProcesses() ([]ProcessSnapshot, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	prevWall := c.prevWall
	wallElapsed := now.Sub(prevWall).Seconds()
	havePrev := !prevWall.IsZero() && wallElapsed > 0

	next := make(map[int]uint64, len(entries))
	out := make([]ProcessSnapshot, 0, len(entries))

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, convErr := strconv.Atoi(e.Name())
		if convErr != nil {
			continue
		}
		name, ticks, ok := readProcStat(pid)
		if !ok {
			continue // process exited between ReadDir and read; skip cleanly
		}
		next[pid] = ticks

		cpuPct := 0.0
		if havePrev {
			if prevTicks, seen := c.prev[pid]; seen && ticks >= prevTicks {
				cpuSec := float64(ticks-prevTicks) / c.clkTck
				cpuPct = cpuSec / wallElapsed * 100.0
			}
			// ticks < prevTicks ⇒ PID reused since the last sample; report 0
			// rather than a spurious spike.
		}

		rd, wr := readProcIO(pid)
		out = append(out, ProcessSnapshot{
			PID:            pid,
			Name:           name,
			FragmentID:     processFragmentID(name),
			CPUPercent:     cpuPct,
			MemoryBytes:    readProcRSSBytes(pid),
			DiskReadBytes:  rd,
			DiskWriteBytes: wr,
			// NetRxBytes/NetTxBytes reserved — see ProcessSnapshot doc.
		})
	}

	c.prev = next
	c.prevWall = now
	return out, nil
}

// readProcStat returns the comm name and cumulative CPU ticks (utime+stime) for
// pid from /proc/[pid]/stat. comm is the field between the first '(' and the
// LAST ')', because a process name may itself contain parentheses/spaces.
func readProcStat(pid int) (name string, ticks uint64, ok bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", 0, false
	}
	open := bytes.IndexByte(data, '(')
	closeIdx := bytes.LastIndexByte(data, ')')
	if open < 0 || closeIdx < 0 || closeIdx <= open || closeIdx+2 >= len(data) {
		return "", 0, false
	}
	name = string(data[open+1 : closeIdx])
	// Fields after the closing ')': state ppid pgrp session tty tpgid flags
	// minflt cminflt majflt cmajflt utime(idx 11) stime(idx 12) …
	fields := strings.Fields(string(data[closeIdx+2:]))
	if len(fields) < 13 {
		return "", 0, false
	}
	utime, err1 := strconv.ParseUint(fields[11], 10, 64)
	stime, err2 := strconv.ParseUint(fields[12], 10, 64)
	if err1 != nil || err2 != nil {
		return "", 0, false
	}
	return name, utime + stime, true
}

// pageSize is the system page size, resolved once, used to convert the
// /proc/[pid]/statm resident-page count to bytes.
var pageSize = uint64(os.Getpagesize())

// readProcRSSBytes returns the resident set size in bytes from /proc/[pid]/statm.
// statm is used in preference to /proc/[pid]/status (VmRSS): it is a single tiny
// line of space-separated page counts ("size resident shared text lib data dt"),
// so it is markedly cheaper to read and parse per PID than the ~50-line status
// file — the per-snapshot CPU budget matters because #2764 polls repeatedly.
// Field index 1 is the resident page count. Returns 0 when unreadable.
func readProcRSSBytes(pid int) uint64 {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}
	residentPages, _ := strconv.ParseUint(fields[1], 10, 64)
	return residentPages * pageSize
}

// readProcIO reads cumulative storage read_bytes/write_bytes from
// /proc/[pid]/io. That file is readable only for the caller's own processes
// unless the caller is privileged (the steward runs as root); for processes it
// cannot read it returns (0, 0) rather than failing the whole snapshot.
func readProcIO(pid int) (readBytes, writeBytes uint64) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/io")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "read_bytes:":
			readBytes, _ = strconv.ParseUint(fields[1], 10, 64)
		case "write_bytes:":
			writeBytes, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}
	return readBytes, writeBytes
}

// ─── systemd services (D-Bus) ──────────────────────────────────────────────────

// systemdUnit mirrors the struct returned by org.freedesktop.systemd1.Manager.
// ListUnits (field order is part of the D-Bus API contract).
type systemdUnit struct {
	Name        string
	Description string
	LoadState   string
	ActiveState string
	SubState    string
	Following   string
	UnitPath    dbus.ObjectPath
	JobID       uint32
	JobType     string
	JobPath     dbus.ObjectPath
}

// collectSystemdServices returns one ServiceSnapshot per loaded systemd
// `.service` unit via the Manager.ListUnits D-Bus call. It degrades to nil (not
// an error) when the system bus or systemd is unavailable — a headless
// non-systemd host is valid, and services are a best-effort facet of the
// snapshot. Only `.service` units are reported (the task-manager "services"
// surface); sockets, targets, mounts, and devices are omitted.
func collectSystemdServices(ctx context.Context) []ServiceSnapshot {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	obj := conn.Object("org.freedesktop.systemd1", dbus.ObjectPath("/org/freedesktop/systemd1"))
	call := obj.CallWithContext(ctx, "org.freedesktop.systemd1.Manager.ListUnits", 0)
	if call.Err != nil {
		return nil
	}
	var units []systemdUnit
	if err := call.Store(&units); err != nil {
		return nil
	}

	out := make([]ServiceSnapshot, 0, len(units))
	for _, u := range units {
		if !strings.HasSuffix(u.Name, ".service") {
			continue
		}
		out = append(out, ServiceSnapshot{
			Name: u.Name,
			// Trim the systemd ".service" suffix so the entity id matches how the
			// `service` stdlib module / osquery address the same daemon (service:sshd).
			State:      systemdState(u.SubState, u.ActiveState),
			FragmentID: serviceFragmentID(strings.TrimSuffix(u.Name, ".service")),
		})
	}
	return out
}

// systemdState prefers the fine-grained sub-state ("running", "dead", "exited",
// "failed", …) and falls back to the active-state ("active"/"inactive"/"failed")
// when the sub-state is empty. Returned lower-cased, as systemd already emits it.
func systemdState(subState, activeState string) string {
	if subState != "" {
		return subState
	}
	return activeState
}

// ─── clock ticks ───────────────────────────────────────────────────────────────

// readClockTicks reads AT_CLKTCK from /proc/self/auxv (ticks per second used by
// /proc/[pid]/stat CPU fields). Defaults to 100 (the x86_64 Linux default) when
// the entry is absent, matching the DEX spike's readClockTicks.
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
