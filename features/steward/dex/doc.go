// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package dex implements the DEX (Digital Employee Experience) acquisition spike
// for Windows endpoints (Issue #2516).
//
// This package is a feasibility spike — its sole purpose is to measure whether
// CFGMS can acquire the target DEX signals via in-box usermode ETW + WMI on
// Windows 10/11 within a sub-1% sustained CPU budget, using pure Go (no cgo,
// no kernel driver).
//
// # Scope
//
// Acquisition and overhead measurement ONLY. All output goes to a throwaway
// local sink (JSON lines written to an io.Writer / stdout). There is no
// persistence into DNA, the temporal store, or any controller-side storage —
// those decisions are gated on the storage-shape ADR + ADR-017 Amendment 1.
//
// # Signal surface
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
// # CPU overhead
//
// Measured against a sub-1% sustained single-core budget. The overhead report
// is emitted to the sink alongside signals.
//
// # Platform support
//
// Windows-only acquisition (ETW + WMI are Windows-specific). Non-Windows builds
// compile cleanly but return [ErrPlatformNotSupported] from all collection
// entry points. macOS collection (IOKit/libproc) is a separate story gated on
// a macOS CI runner.
package dex
