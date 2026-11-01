// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package dex implements DEX (Digital Employee Experience) acquisition feasibility
// spikes for Windows and Linux endpoints.
//
// This package is a feasibility spike set — its sole purpose is to measure whether
// CFGMS can acquire the target DEX signals within a sub-1% sustained CPU budget,
// using pure Go (no cgo, no kernel driver).
//
// # Scope
//
// Acquisition and overhead measurement ONLY. All output goes to a throwaway
// local sink (JSON lines written to an io.Writer / stdout). There is no
// persistence into DNA, the temporal store, or any controller-side storage —
// those decisions are gated on the storage-shape ADR + ADR-017 Amendment 1.
//
// # Platform coverage
//
// Windows (build: windows): ETW + WMI acquisition (#2516, #2571).
// Linux (build: linux && spike): /proc + PSI + SysFS + NETLINK_CONNECTOR (#2572).
// Non-spike Linux builds compile cleanly and return [ErrPlatformNotSupported].
// macOS collection (IOKit/libproc) is a separate story gated on a macOS CI runner.
//
// # Windows signal surface
//
// | Signal class          | Mechanism                                   |
// |-----------------------|---------------------------------------------|
// | App hang / UI resp.   | ETW Microsoft-Windows-Win32k                |
// | SMART predict         | WMI root\wmi MSStorageDriver_FailurePredictData |
// | Thermal / throttle    | WMI root\wmi MSAcpi_ThermalZoneTemperature  |
// | Disk I/O wait / queue | ETW Microsoft-Windows-Kernel-Disk           |
// | Hard-fault paging     | ETW Microsoft-Windows-Kernel-PerfInfo       |
// | Network latency / DNS | ETW Microsoft-Windows-DNS-Client            |
//
// # Linux signal surface (spike build only)
//
// | Signal class     | Mechanism                                        |
// |------------------|--------------------------------------------------|
// | Process exec     | /proc polling + NETLINK_CONNECTOR (if privileged)|
// | CPU pressure     | /proc/pressure/cpu (PSI, kernel 4.20+)           |
// | Memory pressure  | /proc/pressure/memory                            |
// | I/O pressure     | /proc/pressure/io                                |
// | Disk I/O stats   | /proc/diskstats (per-device read/write deltas)   |
// | Network stats    | /proc/net/dev (per-interface byte/packet deltas) |
// | Thermal          | /sys/class/thermal/thermal_zone*/temp            |
//
// # CPU overhead
//
// Measured against a sub-1% sustained single-core budget. The overhead report
// is emitted to the sink alongside signals.
//
// # Related: production process/service telemetry
//
// This package is the DEX experience-SIGNAL acquisition spike (ETW/PSI event
// streams, reachability + overhead measurement). It is NOT the home for
// point-in-time process/service telemetry. The production "task manager"
// collector — an on-demand snapshot of running processes (CPU/memory/disk) and
// services (name/state) for the Web UI live-operations view — lives in
// [github.com/cfgis/cfgms/features/steward/telemetry] (Issue #2763, epic #2738).
// That collector reuses the proven mechanisms here (the /proc read shape on
// Linux, the usermode-only WMI/OS-syscall posture on Windows) but is a separate,
// non-spike package on the production build path.
package dex
