// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package telemetry

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

	procRoot     string       // procfs mount (overridden in tests with a fixture tree)
	sysBlockRoot string       // sysfs block directory, used to tell whole disks from partitions
	hostPrev     hostCounters // host counters at the previous Snapshot
	hostPrevWall time.Time    // wall clock of hostPrev; zero before the first Snapshot
}

// NewCollector returns a Linux telemetry collector.
func NewCollector() Collector {
	return &linuxCollector{
		clkTck: float64(readClockTicks()),
		prev:   make(map[int]uint64),

		procRoot:     "/proc",
		sysBlockRoot: "/sys/block",
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
	return Telemetry{Processes: procs, Services: svcs, Host: c.collectHost()}, nil
}

// collectHost reads the host-level totals. Each source is best-effort: an
// unreadable file leaves its fields at zero rather than failing the snapshot
// (the process table is the required facet). Rates are 0 on the first call.
func (c *linuxCollector) collectHost() *HostTotals {
	now := time.Now()
	cur := hostCounters{}
	h := &HostTotals{}

	if data, err := os.ReadFile(c.procRoot + "/stat"); err == nil {
		cur.cpuBusy, cur.cpuTotal = parseProcStatCPU(string(data))
	}
	if data, err := os.ReadFile(c.procRoot + "/meminfo"); err == nil {
		h.MemoryUsedBytes, h.MemoryTotalBytes = parseMeminfo(string(data))
	}
	if data, err := os.ReadFile(c.procRoot + "/diskstats"); err == nil {
		cur.diskRead, cur.diskWrite = parseDiskstats(string(data), c.isWholeDisk)
	}
	if data, err := os.ReadFile(c.procRoot + "/net/dev"); err == nil {
		cur.netRx, cur.netTx = parseNetDev(string(data))
	}
	h.DiskUsedBytes, h.DiskTotalBytes = c.readFilesystemUsage()

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hostPrevWall.IsZero() {
		applyRates(h, c.hostPrev, cur, now.Sub(c.hostPrevWall).Seconds())
	}
	c.hostPrev = cur
	c.hostPrevWall = now
	return h
}

// parseProcStatCPU returns (busy, total) jiffies from the aggregate "cpu" line
// of /proc/stat. idle and iowait count as idle; guest time is already included
// in user/nice so it is not added again.
func parseProcStatCPU(data string) (busy, total uint64) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var v [8]uint64 // user nice system idle iowait irq softirq steal
		for i := 0; i < len(v) && i+1 < len(fields); i++ {
			v[i], _ = strconv.ParseUint(fields[i+1], 10, 64)
		}
		for _, x := range v {
			total += x
		}
		idle := v[3] + v[4]
		if idle > total {
			return 0, total
		}
		return total - idle, total
	}
	return 0, 0
}

// parseMeminfo returns (used, total) physical memory in bytes. Used is
// MemTotal-MemAvailable (what Task Manager style views show); when the kernel
// predates MemAvailable it falls back to free+buffers+cached.
func parseMeminfo(data string) (used, total uint64) {
	vals := map[string]uint64{}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		vals[strings.TrimSuffix(fields[0], ":")] = v * 1024 // values are in kB
	}
	total = vals["MemTotal"]
	avail, ok := vals["MemAvailable"]
	if !ok {
		avail = vals["MemFree"] + vals["Buffers"] + vals["Cached"]
	}
	if avail > total {
		avail = total
	}
	return total - avail, total
}

// diskstatsSectorBytes is the fixed unit /proc/diskstats reports sectors in,
// regardless of the device's physical sector size.
const diskstatsSectorBytes = 512

// parseDiskstats sums cumulative bytes read and written across the devices for
// which include returns true.
func parseDiskstats(data string, include func(name string) bool) (readBytes, writeBytes uint64) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		// major minor name reads merged sectors-read ms writes merged sectors-written ...
		if len(fields) < 10 || !include(fields[2]) {
			continue
		}
		rs, err1 := strconv.ParseUint(fields[5], 10, 64)
		ws, err2 := strconv.ParseUint(fields[9], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		readBytes += rs * diskstatsSectorBytes
		writeBytes += ws * diskstatsSectorBytes
	}
	return readBytes, writeBytes
}

// virtualDiskPrefixes are block devices that either have no storage behind them
// or sit on top of other listed devices, so counting them would double count.
var virtualDiskPrefixes = []string{"loop", "ram", "zram", "dm-", "md", "sr", "fd", "nbd"}

// isWholeDisk reports whether name is a physical, top-level block device: it has
// an entry in sysfs's block directory (partitions do not) and is not virtual.
func (c *linuxCollector) isWholeDisk(name string) bool {
	// name comes from /proc/diskstats. A kernel device name is a single path
	// component; anything else cannot name a sysfs block entry and must never be
	// joined into a path, so it is rejected rather than cleaned.
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return false
	}
	for _, p := range virtualDiskPrefixes {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	// #nosec G703 -- name is validated above to be a single path component (no
	// separators, NUL, "." or ".."), so the path cannot leave sysBlockRoot; the
	// call is an existence check only and reads no file contents.
	_, err := os.Stat(filepath.Join(c.sysBlockRoot, name))
	return err == nil
}

// parseNetDev sums received and transmitted bytes across every interface except
// loopback.
func parseNetDev(data string) (rx, tx uint64) {
	for _, line := range strings.Split(data, "\n") {
		name, rest, found := strings.Cut(line, ":")
		if !found {
			continue // header lines
		}
		if strings.TrimSpace(name) == "lo" {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 9 {
			continue
		}
		r, err1 := strconv.ParseUint(fields[0], 10, 64)
		t, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		rx += r
		tx += t
	}
	return rx, tx
}

// readFilesystemUsage sums used/total bytes over the distinct block-device
// backed filesystems in /proc/mounts. Bind mounts of one device count once. If
// the host exposes none (e.g. a container with an overlay root) it falls back to
// the root filesystem.
func (c *linuxCollector) readFilesystemUsage() (used, total uint64) {
	seen := map[string]bool{}
	if data, err := os.ReadFile(c.procRoot + "/mounts"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || !strings.HasPrefix(fields[0], "/dev/") || seen[fields[0]] {
				continue
			}
			u, t, ok := statfsUsage(unescapeMountPath(fields[1]))
			if !ok {
				continue
			}
			seen[fields[0]] = true
			used += u
			total += t
		}
	}
	if len(seen) == 0 {
		if u, t, ok := statfsUsage("/"); ok {
			return u, t
		}
	}
	return used, total
}

// unescapeMountPath decodes the octal escapes (\040 for space, etc.) that
// /proc/mounts applies to the mount point field.
func unescapeMountPath(p string) string {
	if !strings.Contains(p, "\\") {
		return p
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' && i+3 < len(p) {
			if n, err := strconv.ParseUint(p[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(p[i])
	}
	return b.String()
}

func statfsUsage(path string) (used, total uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	bs := uint64(st.Bsize) // #nosec G115 -- block size is a small positive value
	total = st.Blocks * bs
	free := st.Bfree * bs
	if free > total {
		return 0, total, true
	}
	return total - free, total, true
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
		name, state, ticks, ok := readProcStat(pid)
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
			Status:         procStatusFromState(state),
			// NetRxBytes/NetTxBytes reserved — see ProcessSnapshot doc.
		})
	}

	c.prev = next
	c.prevWall = now
	return out, nil
}

// readProcStat returns the comm name and cumulative CPU ticks (utime+stime) for
// pid from /proc/[pid]/stat, plus the one-letter process state. comm is the field between the first '(' and the
// LAST ')', because a process name may itself contain parentheses/spaces.
func readProcStat(pid int) (name string, state byte, ticks uint64, ok bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", 0, 0, false
	}
	open := bytes.IndexByte(data, '(')
	closeIdx := bytes.LastIndexByte(data, ')')
	if open < 0 || closeIdx < 0 || closeIdx <= open || closeIdx+2 >= len(data) {
		return "", 0, 0, false
	}
	name = string(data[open+1 : closeIdx])
	// Fields after the closing ')': state ppid pgrp session tty tpgid flags
	// minflt cminflt majflt cmajflt utime(idx 11) stime(idx 12) …
	fields := strings.Fields(string(data[closeIdx+2:]))
	if len(fields) < 13 || fields[0] == "" {
		return "", 0, 0, false
	}
	utime, err1 := strconv.ParseUint(fields[11], 10, 64)
	stime, err2 := strconv.ParseUint(fields[12], 10, 64)
	if err1 != nil || err2 != nil {
		return "", 0, 0, false
	}
	return name, fields[0][0], utime + stime, true
}

// procStatusFromState maps the /proc/[pid]/stat state letter onto the wire
// vocabulary: stopped (T, by signal) and tracing-stop (t) are "suspended";
// every other state (running, sleeping, disk-wait, zombie, idle) is "running".
func procStatusFromState(state byte) string {
	if state == 'T' || state == 't' {
		return "suspended"
	}
	return "running"
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

	fileStates := systemdUnitFileStates(ctx, obj)

	out := make([]ServiceSnapshot, 0, len(units))
	for _, u := range units {
		if !strings.HasSuffix(u.Name, ".service") {
			continue
		}
		pid := uint32(0)
		// MainPID is only meaningful (and only worth a D-Bus round trip) for a
		// unit that has a process: active, activating or deactivating.
		if u.ActiveState != "inactive" && u.ActiveState != "failed" {
			pid = systemdMainPID(ctx, conn, u.UnitPath)
		}
		out = append(out, newSystemdService(u, fileStates[u.Name], pid))
	}
	return out
}

// newSystemdService builds one ServiceSnapshot from a ListUnits row, the
// unit's UnitFileState and its MainPID (0 for a unit with no process).
func newSystemdService(u systemdUnit, unitFileState string, mainPID uint32) ServiceSnapshot {
	return ServiceSnapshot{
		Name: u.Name,
		// Trim the systemd ".service" suffix so the entity id matches how the
		// `service` stdlib module / osquery address the same daemon (service:sshd).
		State:       systemdState(u.SubState, u.ActiveState),
		DisplayName: u.Description,
		StartType:   systemdStartType(unitFileState),
		PID:         int(mainPID), // #nosec G115 -- a PID fits in int32 on Linux (pid_max <= 2^22)
		FragmentID:  serviceFragmentID(strings.TrimSuffix(u.Name, ".service")),
	}
}

// systemdStartType maps a systemd UnitFileState onto the cross-platform start
// type vocabulary: "enabled"/"enabled-runtime"/"alias"/"linked" units start
// automatically ("auto"); "disabled" stays "disabled"; "masked" units cannot
// start ("disabled"); "static"/"indirect"/"generated"/"transient" units are only
// started on demand ("manual"). Empty or unrecognised input yields "".
func systemdStartType(unitFileState string) string {
	switch unitFileState {
	case "enabled", "enabled-runtime":
		return "auto"
	case "disabled", "masked", "masked-runtime", "bad":
		return "disabled"
	case "static", "indirect", "generated", "transient", "linked", "linked-runtime", "alias":
		return "manual"
	default:
		return ""
	}
}

// systemdUnitFile mirrors one row of Manager.ListUnitFiles.
type systemdUnitFile struct {
	Path  string
	State string
}

// systemdUnitFileStates returns unit name -> UnitFileState for every installed
// unit file, in one D-Bus call. Best-effort: nil on failure.
func systemdUnitFileStates(ctx context.Context, obj dbus.BusObject) map[string]string {
	call := obj.CallWithContext(ctx, "org.freedesktop.systemd1.Manager.ListUnitFiles", 0)
	if call.Err != nil {
		return nil
	}
	var files []systemdUnitFile
	if err := call.Store(&files); err != nil {
		return nil
	}
	out := make(map[string]string, len(files))
	for _, f := range files {
		out[filepath.Base(f.Path)] = f.State
	}
	return out
}

// systemdMainPID reads the Service.MainPID property of one unit; 0 on failure.
func systemdMainPID(ctx context.Context, conn *dbus.Conn, path dbus.ObjectPath) uint32 {
	var pid uint32
	obj := conn.Object("org.freedesktop.systemd1", path)
	call := obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.systemd1.Service", "MainPID")
	if call.Err != nil {
		return 0
	}
	var v dbus.Variant
	if err := call.Store(&v); err != nil {
		return 0
	}
	if p, ok := v.Value().(uint32); ok {
		pid = p
	}
	return pid
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
