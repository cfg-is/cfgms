// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package telemetry

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// windowsCollector reads the process table from NtQuerySystemInformation and
// services from the Service Control Manager. Both are usermode, in-process OS
// syscalls (no ETW, no kernel driver, no `tasklist`/`wmic` shell-out) — the
// posture CLAUDE.md prescribes for steward-resident collectors.
//
// NtQuerySystemInformation(SystemProcessInformation) is deliberately chosen over
// WMI Win32_PerfFormattedData_PerfProc_Process (the mechanism the story sketched):
// the WMI perf-object query measured ~360 ms of CPU per call on a live host —
// ~20× the sub-1% sustained budget at a 1 Hz cadence — whereas this returns the
// entire process table (image name, CPU times, working set, I/O byte counters)
// in one cheap syscall that fills a caller buffer. The measured budget is a hard
// acceptance gate, so the cheaper native path is used. It is the same source
// Task Manager / Process Explorer read.
//
// CPU percent is delta-based (like the Linux collector): the kernel exposes
// cumulative per-process CPU time, so the first Snapshot reports 0 and each
// subsequent one reports usage over the interval since the previous call.
type windowsCollector struct {
	mu       sync.Mutex
	prev     map[int]uint64 // pid -> cumulative CPU (100 ns units) at previous Snapshot
	prevWall time.Time

	hostPrev     hostCounters // host counters at the previous Snapshot
	hostPrevWall time.Time    // wall clock of hostPrev; zero before the first Snapshot
}

// NewCollector returns a Windows telemetry collector.
func NewCollector() Collector {
	return &windowsCollector{prev: make(map[int]uint64)}
}

// Snapshot collects the process table (NtQuerySystemInformation) and the service
// list (SCM). A process-table failure is a hard error; an SCM failure degrades
// Services to nil with a nil error, mirroring the Linux systemd-absent behavior.
func (c *windowsCollector) Snapshot(ctx context.Context) (Telemetry, error) {
	if err := ctx.Err(); err != nil {
		return Telemetry{}, err
	}
	procs, err := c.collectProcesses()
	if err != nil {
		return Telemetry{}, err
	}
	return Telemetry{Processes: procs, Services: collectSCMServices(), Host: c.collectHost()}, nil
}

// ─── processes (NtQuerySystemInformation) ──────────────────────────────────────

var (
	modntdll                     = windows.NewLazySystemDLL("ntdll.dll")
	procNtQuerySystemInformation = modntdll.NewProc("NtQuerySystemInformation")
)

const (
	systemProcessInformationClass = 5          // SYSTEM_INFORMATION_CLASS.SystemProcessInformation
	statusInfoLengthMismatch      = 0xC0000004 // STATUS_INFO_LENGTH_MISMATCH

	// SYSTEM_PROCESS_INFORMATION field byte offsets (64-bit layout — amd64 and
	// arm64, the only steward targets, share it; CFGMS ships no 32-bit steward).
	spiUserTime         = 40  // LARGE_INTEGER, 100 ns
	spiKernelTime       = 48  // LARGE_INTEGER, 100 ns
	spiImageNameLength  = 56  // UNICODE_STRING.Length  (uint16)
	spiImageNameBuffer  = 64  // UNICODE_STRING.Buffer  (pointer)
	spiUniqueProcessID  = 80  // HANDLE (carries the PID)
	spiWorkingSetSize   = 144 // SIZE_T, bytes
	spiReadTransferCnt  = 232 // LARGE_INTEGER, bytes (IO_COUNTERS.ReadTransferCount)
	spiWriteTransferCnt = 240 // LARGE_INTEGER, bytes (IO_COUNTERS.WriteTransferCount)
	spiMinSize          = 256 // the fixed struct spans through the IO_COUNTERS block
)

// collectProcesses parses the SystemProcessInformation buffer into one
// ProcessSnapshot per process, computing CPU percent from the delta against the
// previous Snapshot.
func (c *windowsCollector) collectProcesses() ([]ProcessSnapshot, error) {
	buf, err := querySystemProcessInfo()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	wallElapsed := now.Sub(c.prevWall).Seconds()
	havePrev := !c.prevWall.IsZero() && wallElapsed > 0

	next := make(map[int]uint64)
	var out []ProcessSnapshot

	base := uintptr(unsafe.Pointer(&buf[0]))
	offset := 0
	for offset+spiMinSize <= len(buf) {
		entry := buf[offset:]

		pid := int(binary.LittleEndian.Uint64(entry[spiUniqueProcessID:]))
		cpu100ns := binary.LittleEndian.Uint64(entry[spiUserTime:]) + binary.LittleEndian.Uint64(entry[spiKernelTime:])
		name := readImageName(buf, base, entry)
		if name == "" && pid == 0 {
			name = "Idle" // System Idle Process carries no image name
		}

		next[pid] = cpu100ns
		cpuPct := 0.0
		if havePrev {
			if prev, seen := c.prev[pid]; seen && cpu100ns >= prev {
				// 100 ns units → seconds: ×1e-7. Percent of one core over the wall window.
				cpuSec := float64(cpu100ns-prev) * 1e-7
				cpuPct = cpuSec / wallElapsed * 100.0
			}
		}

		out = append(out, ProcessSnapshot{
			PID:            pid,
			Name:           name,
			FragmentID:     processFragmentID(name),
			CPUPercent:     cpuPct,
			MemoryBytes:    binary.LittleEndian.Uint64(entry[spiWorkingSetSize:]),
			DiskReadBytes:  binary.LittleEndian.Uint64(entry[spiReadTransferCnt:]),
			DiskWriteBytes: binary.LittleEndian.Uint64(entry[spiWriteTransferCnt:]),
			// NetRxBytes/NetTxBytes reserved — see ProcessSnapshot doc.
		})

		nextOffset := binary.LittleEndian.Uint32(entry[0:])
		if nextOffset == 0 {
			break
		}
		offset += int(nextOffset)
	}

	c.prev = next
	c.prevWall = now
	return out, nil
}

// readImageName decodes the UNICODE_STRING image name for one entry. The kernel
// writes ImageName.Buffer as an absolute pointer into our own buffer; it is
// converted to an in-buffer offset and bounds-checked so no out-of-slice memory
// is read.
func readImageName(buf []byte, base uintptr, entry []byte) string {
	length := int(binary.LittleEndian.Uint16(entry[spiImageNameLength:])) // bytes
	ptr := uintptr(binary.LittleEndian.Uint64(entry[spiImageNameBuffer:]))
	if length == 0 || ptr == 0 {
		return ""
	}
	if ptr < base {
		return ""
	}
	off := int(ptr - base)
	if off < 0 || off+length > len(buf) {
		return ""
	}
	u16 := make([]uint16, length/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(buf[off+i*2:])
	}
	return windows.UTF16ToString(u16)
}

// querySystemProcessInfo calls NtQuerySystemInformation for the process table,
// growing the buffer until it fits (the table can change size between calls).
func querySystemProcessInfo() ([]byte, error) {
	size := uint32(512 * 1024) // 512 KB is enough for a few thousand processes
	for attempt := 0; attempt < 6; attempt++ {
		buf := make([]byte, size)
		var retLen uint32
		status, _, _ := procNtQuerySystemInformation.Call(
			uintptr(systemProcessInformationClass),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&retLen)),
		)
		if status == 0 { // STATUS_SUCCESS
			return buf, nil
		}
		if uint32(status) == statusInfoLengthMismatch {
			// Grow to the required length (plus headroom for growth between calls).
			if retLen > size {
				size = retLen + 64*1024
			} else {
				size *= 2
			}
			continue
		}
		return nil, fmt.Errorf("NtQuerySystemInformation: status 0x%X", uint32(status))
	}
	return nil, fmt.Errorf("NtQuerySystemInformation: buffer did not stabilize")
}

// ─── services (SCM) ────────────────────────────────────────────────────────────

// collectSCMServices enumerates installed services from the Service Control
// Manager and reports each one's run state. The SCM and each service are opened
// with LEAST-PRIVILEGE read rights (SC_MANAGER_ENUMERATE_SERVICE /
// SERVICE_QUERY_STATUS) so this works without administrator elevation and never
// acquires mutate rights it does not need. Returns nil (not an error) if the SCM
// cannot be opened — services are a best-effort facet of the snapshot.
func collectSCMServices() []ServiceSnapshot {
	handle, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil
	}
	m := &mgr.Mgr{Handle: handle}
	defer func() { _ = m.Disconnect() }()

	names, err := m.ListServices()
	if err != nil {
		return nil
	}

	out := make([]ServiceSnapshot, 0, len(names))
	for _, name := range names {
		out = append(out, ServiceSnapshot{
			Name:       name,
			State:      queryServiceState(handle, name),
			FragmentID: serviceFragmentID(name),
		})
	}
	return out
}

// queryServiceState opens one service with query-only rights and returns its
// current run state as a lower-case string ("running", "stopped", …), or
// "unknown" when it cannot be queried (e.g. a service that deleted itself
// between enumeration and open).
func queryServiceState(scm windows.Handle, name string) string {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "unknown"
	}
	h, err := windows.OpenService(scm, namePtr, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return "unknown"
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer func() { _ = s.Close() }()

	status, err := s.Query()
	if err != nil {
		return "unknown"
	}
	return svcStateString(status.State)
}

// svcStateString maps a Windows service-state code to a stable label aligned
// with the Linux systemd state vocabulary ("running"/"stopped"/…).
func svcStateString(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start-pending"
	case svc.StopPending:
		return "stop-pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue-pending"
	case svc.PausePending:
		return "pause-pending"
	case svc.Paused:
		return "paused"
	default:
		return "unknown"
	}
}

// ─── host totals ───────────────────────────────────────────────────────────────

var (
	modkernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes   = modkernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStat = modkernel32.NewProc("GlobalMemoryStatusEx")
)

const systemPerformanceInformationClass = 2 // SYSTEM_INFORMATION_CLASS.SystemPerformanceInformation

// SYSTEM_PERFORMANCE_INFORMATION field byte offsets (LARGE_INTEGER, bytes). The
// kernel's cumulative host-wide I/O transfer counters — the same source the
// "Disk" row of Task Manager is derived from, covering every volume.
const (
	spiPerfIoReadTransferCount  = 8
	spiPerfIoWriteTransferCount = 16
	spiPerfMinSize              = 24
)

// memoryStatusEx mirrors the Win32 MEMORYSTATUSEX struct.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// collectHost reads the host-level totals through in-process APIs only
// (GetSystemTimes, GlobalMemoryStatusEx, NtQuerySystemInformation, GetIfTable2Ex,
// GetDiskFreeSpaceEx). Each source is best-effort: a failing call leaves its
// fields zero. Rates are 0 on the first call.
func (c *windowsCollector) collectHost() *HostTotals {
	now := time.Now()
	cur := hostCounters{}
	h := &HostTotals{}

	cur.cpuBusy, cur.cpuTotal = readSystemTimes()
	h.MemoryUsedBytes, h.MemoryTotalBytes = readMemoryStatus()
	cur.diskRead, cur.diskWrite = readSystemIOCounters()
	cur.netRx, cur.netTx = readNetworkOctets()
	h.DiskUsedBytes, h.DiskTotalBytes = readFixedDriveUsage()

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hostPrevWall.IsZero() {
		applyRates(h, c.hostPrev, cur, now.Sub(c.hostPrevWall).Seconds())
	}
	c.hostPrev = cur
	c.hostPrevWall = now
	return h
}

func filetimeToUint64(ft windows.Filetime) uint64 {
	return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
}

// readSystemTimes returns (busy, total) 100 ns CPU ticks across all cores.
// GetSystemTimes' kernel time includes idle time.
func readSystemTimes() (busy, total uint64) {
	var idle, kernel, user windows.Filetime
	r, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if r == 0 {
		return 0, 0
	}
	total = filetimeToUint64(kernel) + filetimeToUint64(user)
	i := filetimeToUint64(idle)
	if i > total {
		return 0, total
	}
	return total - i, total
}

// readMemoryStatus returns (used, total) physical memory in bytes.
func readMemoryStatus() (used, total uint64) {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	r, _, _ := procGlobalMemoryStat.Call(uintptr(unsafe.Pointer(&m)))
	if r == 0 {
		return 0, 0
	}
	avail := m.AvailPhys
	if avail > m.TotalPhys {
		avail = m.TotalPhys
	}
	return m.TotalPhys - avail, m.TotalPhys
}

// readSystemIOCounters returns the kernel's cumulative host-wide I/O read and
// write transfer byte counts.
func readSystemIOCounters() (readBytes, writeBytes uint64) {
	buf := make([]byte, 512) // SYSTEM_PERFORMANCE_INFORMATION is ~312 bytes on x64
	var retLen uint32
	status, _, _ := procNtQuerySystemInformation.Call(
		uintptr(systemPerformanceInformationClass),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 || len(buf) < spiPerfMinSize+spiPerfIoWriteTransferCount {
		return 0, 0
	}
	return binary.LittleEndian.Uint64(buf[spiPerfIoReadTransferCount:]),
		binary.LittleEndian.Uint64(buf[spiPerfIoWriteTransferCount:])
}

// readNetworkOctets sums received and transmitted octets across every interface
// except software loopback.
func readNetworkOctets() (rx, tx uint64) {
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormal, &table); err != nil || table == nil {
		return 0, 0
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	rows := unsafe.Slice(&table.Table[0], int(table.NumEntries))
	for i := range rows {
		if rows[i].Type == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		rx += rows[i].InOctets
		tx += rows[i].OutOctets
	}
	return rx, tx
}

// readFixedDriveUsage sums used/total bytes over the local fixed drives.
func readFixedDriveUsage() (used, total uint64) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return 0, 0
	}
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root, perr := windows.UTF16PtrFromString(string(rune('A'+i)) + `:\`)
		if perr != nil || windows.GetDriveType(root) != windows.DRIVE_FIXED {
			continue
		}
		var avail, tot, free uint64
		if windows.GetDiskFreeSpaceEx(root, &avail, &tot, &free) != nil {
			continue
		}
		if free > tot {
			free = tot
		}
		total += tot
		used += tot - free
	}
	return used, total
}
