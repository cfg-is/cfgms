// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package telemetry is the production home for steward-side, on-demand process
// and service telemetry collection (Issue #2763, epic #2738 — Web UI live
// operations "task manager"). It is distinct from features/steward/dex, which is
// the DEX experience-signal acquisition spike (ETW/PSI event streams); this
// package exposes a cheap, point-in-time SNAPSHOT of running processes and
// services that a controller subscriber polls on an interval (wired by #2764).
//
// # Contract
//
// A [Collector] returns a [Telemetry] snapshot via [Collector.Snapshot]. The
// collector does NO work unless invoked — there is no background goroutine, no
// event stream, nothing running between calls. Story #2764 attaches it to a
// subscription so it only runs while a controller subscriber is attached.
//
// # Platform coverage
//
//   - Linux (build: linux): process table from /proc, services from systemd D-Bus.
//   - Windows (build: windows): process table from WMI Win32_PerfFormattedData_
//     PerfProc_Process, services from the Service Control Manager (svc/mgr).
//   - Everything else (build: !windows && !linux, e.g. macOS): [NewCollector]
//     returns a collector whose Snapshot yields [ErrPlatformNotSupported]. macOS
//     collection (libproc/IOKit) is deferred — no macOS CI runner — but the
//     interface compiles cleanly there.
//
// # Overhead
//
// Snapshot is usermode only (no kernel driver, no eBPF, no ETW) and cheap enough
// to poll repeatedly, staying within the DEX sub-1% sustained single-core CPU
// budget (features/steward/dex/CONSUME_FEASIBILITY_LINUX.md Part 4/5). It never
// shells out (no `ps`/`tasklist`/`systemctl`/`wmic`) — in-process APIs only, per
// the CLAUDE.md steward execution-path posture.
package telemetry

import (
	"context"
	"errors"
)

// ErrPlatformNotSupported is returned by [Collector.Snapshot] on platforms with
// no telemetry implementation (currently anything other than Linux and Windows).
var ErrPlatformNotSupported = errors.New("telemetry: platform not supported")

// ProcessSnapshot is a point-in-time view of one running process.
//
// The network counters (NetRxBytes/NetTxBytes) are structurally present so the
// wire format is stable for #2764/#2765, but are NOT populated by this usermode
// collector: per-process network byte accounting requires kernel-assisted
// tracing (eBPF on Linux, the Kernel-Network ETW provider on Windows), both of
// which the epic's Implementation Notes place out of scope ("usermode only, no
// eBPF … this collector doesn't touch ETW at all"). They are reserved for a
// future kernel-assisted story and remain zero here.
type ProcessSnapshot struct {
	// PID is the operating-system process id.
	PID int `json:"pid"`
	// Name is the executable/image name (e.g. "sshd", "chrome.exe").
	Name string `json:"name"`
	// FragmentID is the ADR-017 object-canonical entity reference for this
	// process ("process:<name>"), carried so #2764/#2765 can join telemetry
	// against DNA + the topology graph without redesigning the wire format.
	// Nothing in this package writes DNA.
	FragmentID string `json:"fragment_id"`
	// CPUPercent is the process CPU usage as a percentage of ONE logical core
	// (may exceed 100 on a multi-threaded process spanning cores). On Linux it
	// is a delta between consecutive Snapshot calls (0 on the first call, since
	// there is no prior sample); on Windows it is the formatted PercentProcessorTime
	// perf counter.
	CPUPercent float64 `json:"cpu_percent"`
	// MemoryBytes is the process resident/working-set memory in bytes.
	MemoryBytes uint64 `json:"memory_bytes"`
	// DiskReadBytes / DiskWriteBytes are cumulative (Linux, /proc/[pid]/io) or
	// rate-per-second (Windows PerfProc IO counters, which aggregate file+device
	// I/O — the closest usermode per-process I/O available) storage I/O.
	DiskReadBytes  uint64 `json:"disk_read_bytes"`
	DiskWriteBytes uint64 `json:"disk_write_bytes"`
	// NetRxBytes / NetTxBytes — reserved; always zero (see type doc).
	NetRxBytes uint64 `json:"net_rx_bytes"`
	NetTxBytes uint64 `json:"net_tx_bytes"`
}

// ServiceSnapshot is a point-in-time view of one installed service / systemd unit.
type ServiceSnapshot struct {
	// Name is the service/unit name (e.g. "sshd.service", "Spooler").
	Name string `json:"name"`
	// State is the read-only run state ("running", "stopped", "failed",
	// "start-pending", …). Values are the platform's native state strings,
	// lower-cased where practical; callers should treat them as opaque labels.
	State string `json:"state"`
	// FragmentID is the ADR-017 object-canonical entity reference
	// ("service:<name-without-.service>"), matching how the `service` stdlib
	// module and osquery address the same entity, so a controller can join this
	// observation to managed/observed DNA for the same service.
	FragmentID string `json:"fragment_id"`
}

// Telemetry bundles the process and service snapshots from one collection.
type Telemetry struct {
	Processes []ProcessSnapshot `json:"processes"`
	Services  []ServiceSnapshot `json:"services"`
}

// Collector returns point-in-time telemetry snapshots. Implementations are
// platform-specific; obtain one via [NewCollector]. A Collector is safe for
// sequential reuse (the Linux implementation caches the previous CPU sample to
// compute deltas); concurrent calls to Snapshot on the same Collector are not
// supported.
type Collector interface {
	// Snapshot returns the current process and service telemetry, or an error if
	// the platform-level collection fails. ctx bounds any blocking platform call
	// (e.g. the systemd D-Bus round-trip). A partial result with a nil error is
	// permitted when one facet (e.g. services) is unavailable but processes were
	// collected — see the platform implementations for the exact degradation rules.
	Snapshot(ctx context.Context) (Telemetry, error)
}

// processFragmentID returns the ADR-017 fragment_id for a process image name.
func processFragmentID(name string) string {
	if name == "" {
		return "process:unknown"
	}
	return "process:" + name
}

// serviceFragmentID returns the ADR-017 fragment_id for a service/unit name.
// The caller passes the canonical daemon name: on Linux the collector trims the
// systemd ".service" suffix first (so a unit and a `service` module managing the
// same daemon resolve to the identical object-canonical id — service:sshd, not
// service:sshd.service); on Windows the SCM name is already canonical and is
// used verbatim (a Windows service literally named "com.docker.service" keeps
// its ".service" — that is its real name, not a systemd suffix).
func serviceFragmentID(name string) string {
	if name == "" {
		return "service:unknown"
	}
	return "service:" + name
}
