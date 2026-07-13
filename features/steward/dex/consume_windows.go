// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows && dexconsume

// consume_windows.go — Go side of the DEX in-process ETW consume feasibility PoC
// (#2571). Drives the non-reentrant C-callback consumer (consume_etw_windows.c):
// starts a real-time ETW session (reusing the collector's session/provider
// helpers), runs C ProcessTrace on a locked-OS-thread goroutine, and drains the
// C ring on a separate goroutine — counting, attributing (pid -> image), and
// measuring real overhead at volume.
//
// Behind the `dexconsume` build tag: this is a throwaway spike that pulls in cgo,
// so it is NEVER compiled into the production steward (CGO_ENABLED=0) path.

package dex

/*
#cgo LDFLAGS: -ltdh -ladvapi32
#include <stdlib.h>
#include "consume_etw_windows.h"
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── psapi binding for working-set measurement ───────────────────────────────

var (
	modpsapi                 = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo = modpsapi.NewProc("GetProcessMemoryInfo")
)

type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func workingSetBytes() uint64 {
	handle, err := windows.OpenProcess(processQueryLimitedInformation, false, uint32(windows.GetCurrentProcessId()))
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(handle)
	var pmc processMemoryCounters
	pmc.CB = uint32(unsafe.Sizeof(pmc))
	ret, _, _ := procGetProcessMemoryInfo.Call(uintptr(handle), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.CB))
	if ret == 0 {
		return 0
	}
	return uint64(pmc.WorkingSetSize)
}

// ─── ControlTrace QUERY for ETW lost-event counts ────────────────────────────

var procControlTraceW = modadvapi32.NewProc("ControlTraceW")

const eventTraceControlQuery uint32 = 0

// queryLostEvents reads the session's EventsLost + RealTimeBuffersLost via
// ControlTraceW(QUERY). Must be called while the session still exists (before
// StopTrace). Best-effort: returns (0,0) on error.
func queryLostEvents(sessionName string) (eventsLost, rtBuffersLost uint32) {
	nameUTF16, err := windows.UTF16FromString(sessionName)
	if err != nil {
		return 0, 0
	}
	nameBytes := len(nameUTF16) * 2
	totalSize := uint32(unsafe.Sizeof(eventTraceProperties{}) + uintptr(nameBytes))
	buf := make([]byte, totalSize)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = totalSize
	props.Wnode.Flags = wnodeFlagTracedGUID
	props.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))

	ret, _, _ := procControlTraceW.Call(
		0,
		uintptr(unsafe.Pointer(&nameUTF16[0])),
		uintptr(unsafe.Pointer(props)),
		uintptr(eventTraceControlQuery),
	)
	if ret != 0 {
		return 0, 0
	}
	return props.EventsLost, props.RealTimeBuffersLost
}

// ─── consume config + report ─────────────────────────────────────────────────

// ConsumeConfig parameterises a single consume run.
type ConsumeConfig struct {
	SessionName  string
	Duration     time.Duration
	DrainEveryMS int      // drain cadence
	Providers    []string // provider names to enable (must match etwProviders[].name); empty = all non-Win32k
}

// ProviderCount is a per-provider drained-event tally.
type ProviderCount struct {
	Provider string `json:"provider"`
	Events   int    `json:"events"`
}

// AttributedProc is a pid -> image attribution sample entry.
type AttributedProc struct {
	PID   uint32 `json:"pid"`
	Image string `json:"image"`
	Count int    `json:"count"`
}

// MemSample is a point-in-time working-set + progress reading, sampled through
// the run so a 10-minute stability window can show whether memory trends upward.
type MemSample struct {
	ElapsedSec   float64 `json:"elapsed_sec"`
	WorkingSetMB float64 `json:"working_set_mb"`
	Drained      uint64  `json:"drained"`
	DroppedRing  uint64  `json:"dropped_ring"`
}

// ConsumeReport is the machine-readable result of a consume run — the evidence
// backing the feasibility verdicts.
type ConsumeReport struct {
	Host             string           `json:"host"`
	Timestamp        string           `json:"timestamp"`
	DurationSec      float64          `json:"duration_sec"`
	ProvidersEnabled []string         `json:"providers_enabled"`
	SessionStartErr  string           `json:"session_start_err,omitempty"`
	TotalSeen        uint64           `json:"total_seen"`         // events the C callback observed
	TotalDrained     uint64           `json:"total_drained"`      // events Go pulled from the ring
	DroppedRing      uint64           `json:"dropped_ring"`       // ring-full drops in the callback
	ETWEventsLost    uint32           `json:"etw_events_lost"`    // kernel-side lost (buffers overrun)
	ETWBuffersLost   uint32           `json:"etw_buffers_lost"`   // real-time buffers lost
	ThroughputPerSec float64          `json:"throughput_per_sec"` // drained / duration
	PerProvider      []ProviderCount  `json:"per_provider"`
	DistinctPIDs     int              `json:"distinct_pids"`
	Attribution      []AttributedProc `json:"attribution_sample"`
	DecodeSample     []string         `json:"decode_sample"`
	CPUPercent       float64          `json:"cpu_percent"`
	BudgetPercent    float64          `json:"budget_percent"`
	WithinBudget     bool             `json:"within_budget"`
	WorkingSetMB     float64          `json:"working_set_mb"`
	MemSamples       []MemSample      `json:"mem_samples,omitempty"` // periodic trend (Part 5)
	Crashed          bool             `json:"crashed"`               // always false if we returned (proof of no runtime crash)
}

// ─── the consumer ────────────────────────────────────────────────────────────

// consumeProviderSet is the provider set for the consume PoC: the four reachable
// providers proven in #2540 plus Microsoft-Windows-Kernel-File, a very high-rate
// provider used to stress the consumer (Part 1 / Part 4). Win32k stays in the set
// for the session-0 reachability determination (Part 6) but emits nothing in
// session 0.
func consumeProviderSet() []etwProvider {
	set := make([]etwProvider, 0, len(etwProviders)+1)
	set = append(set, etwProviders...)
	set = append(set, etwProvider{
		// Kernel-File fires on nearly every file-system operation host-wide — the
		// highest-rate readily-available manifest provider, ideal for a consume
		// stress test. Reuses SignalDiskIO so it is flagged as a TDH decode target.
		class:    SignalDiskIO,
		name:     "Microsoft-Windows-Kernel-File",
		guidStr:  "{edd08927-9cc4-4e65-b970-c2560fb5c289}",
		matchAny: 0,
	})
	return set
}

// selectConsumeProviders returns the etwProvider entries whose name is in want
// (or all of consumeProviderSet when want is empty). Order is preserved so the
// registered idx is stable within a run.
func selectConsumeProviders(want []string) []etwProvider {
	all := consumeProviderSet()
	if len(want) == 0 {
		return all
	}
	set := make(map[string]bool, len(want))
	for _, w := range want {
		set[w] = true
	}
	out := make([]etwProvider, 0, len(want))
	for _, p := range all {
		if set[p.name] {
			out = append(out, p)
		}
	}
	return out
}

// RunConsume executes one consume run and returns the evidence report. It never
// panics out to the caller on a consume error; a failure to start the session is
// reported in SessionStartErr with zeroed counts.
func RunConsume(ctx context.Context, cfg ConsumeConfig) ConsumeReport {
	if cfg.DrainEveryMS <= 0 {
		cfg.DrainEveryMS = 20
	}
	host, _ := os.Hostname()
	providers := selectConsumeProviders(cfg.Providers)

	report := ConsumeReport{
		Host:          host,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		DurationSec:   cfg.Duration.Seconds(),
		BudgetPercent: 1.0,
	}
	for _, p := range providers {
		report.ProvidersEnabled = append(report.ProvidersEnabled, p.name)
	}

	// 1. Start the real-time session.
	handle, err := startNamedTrace(cfg.SessionName, eventTraceRealTimeMode)
	if err != nil {
		report.SessionStartErr = err.Error()
		return report
	}

	// 2. Register providers with the C callback and enable them on the session.
	for idx, p := range providers {
		guid, gerr := parseGUID(p.guidStr)
		if gerr != nil {
			continue
		}
		decodeTarget := 0
		if p.class == SignalDiskIO || p.class == SignalNetwork {
			decodeTarget = 1 // manifest/MOF providers that TDH-decode into named fields
		}
		C.cfgms_register_provider(
			(*C.uchar)(unsafe.Pointer(&guid)),
			C.int(idx),
			C.int(decodeTarget),
		)
		procEnableTraceEx2.Call( //nolint:errcheck // best-effort; reachability proven in #2540
			handle,
			uintptr(unsafe.Pointer(&guid)),
			1,
			uintptr(traceLevelInformation),
			uintptr(p.matchAny),
			0, 0, 0,
		)
	}

	// 3. Producer goroutine: C ProcessTrace blocks here for the whole run. The
	// session name is copied into C memory so it outlives the blocking call
	// regardless of Go GC.
	nameUTF16, _ := windows.UTF16FromString(cfg.SessionName)
	cName := C.malloc(C.size_t(len(nameUTF16) * 2))
	defer C.free(cName)
	copy((*[1 << 16]byte)(cName)[:len(nameUTF16)*2], (*[1 << 16]byte)(unsafe.Pointer(&nameUTF16[0]))[:len(nameUTF16)*2])

	var producerWG sync.WaitGroup
	producerWG.Add(1)
	go func() {
		defer producerWG.Done()
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		C.cfgms_run((*C.ushort)(cName))
	}()

	// 4. Drain loop for the window (attribute + count).
	cpuBefore, _ := processTimesNs()
	wallBefore := time.Now()

	perProvider := make([]int, len(providers))
	pidCounts := make(map[uint32]int)
	imageCache := make(map[uint32]string)
	var totalDrained uint64

	const drainBatch = 4096
	buf := make([]C.CfgmsEvent, drainBatch)

	runCtx, cancel := context.WithTimeout(ctx, cfg.Duration)
	defer cancel()
	ticker := time.NewTicker(time.Duration(cfg.DrainEveryMS) * time.Millisecond)
	defer ticker.Stop()
	sampleTicker := time.NewTicker(30 * time.Second)
	defer sampleTicker.Stop()

	drain := func() {
		for {
			n := int(C.cfgms_drain(&buf[0], C.int(drainBatch)))
			if n == 0 {
				return
			}
			for i := 0; i < n; i++ {
				ev := buf[i]
				totalDrained++
				if int(ev.provider_idx) < len(perProvider) {
					perProvider[ev.provider_idx]++
				}
				pid := uint32(ev.pid)
				pidCounts[pid]++
				if _, ok := imageCache[pid]; !ok {
					imageCache[pid] = imageForPID(pid)
				}
			}
			if n < drainBatch {
				return
			}
		}
	}

drainLoop:
	for {
		select {
		case <-runCtx.Done():
			break drainLoop
		case <-ticker.C:
			drain()
		case <-sampleTicker.C:
			report.MemSamples = append(report.MemSamples, MemSample{
				ElapsedSec:   time.Since(wallBefore).Seconds(),
				WorkingSetMB: float64(workingSetBytes()) / (1024 * 1024),
				Drained:      totalDrained,
				DroppedRing:  uint64(C.cfgms_dropped_ring()),
			})
		}
	}

	// 5. Read ETW lost counts BEFORE tearing the session down, then stop.
	report.ETWEventsLost, report.ETWBuffersLost = queryLostEvents(cfg.SessionName)
	C.cfgms_stop()                              // CloseTrace → ProcessTrace returns
	_ = stopNamedTrace(handle, cfg.SessionName) //nolint:errcheck // best-effort teardown
	producerWG.Wait()
	drain() // final sweep of anything left in the ring

	cpuAfter, _ := processTimesNs()
	wallElapsed := time.Since(wallBefore).Seconds()

	// 6. Overhead.
	cpuNs := int64(cpuAfter) - int64(cpuBefore)
	if wallElapsed > 0 {
		report.CPUPercent = (float64(cpuNs) / (wallElapsed * float64(time.Second))) * 100.0
		report.ThroughputPerSec = float64(totalDrained) / wallElapsed
	}
	report.WithinBudget = report.CPUPercent <= report.BudgetPercent
	report.WorkingSetMB = float64(workingSetBytes()) / (1024 * 1024)
	report.DurationSec = wallElapsed

	// 7. Counters + per-provider + attribution + decode sample.
	report.TotalSeen = uint64(C.cfgms_total_seen())
	report.DroppedRing = uint64(C.cfgms_dropped_ring())
	report.TotalDrained = totalDrained
	for i, p := range providers {
		report.PerProvider = append(report.PerProvider, ProviderCount{Provider: p.name, Events: perProvider[i]})
	}
	report.DistinctPIDs = len(pidCounts)
	report.Attribution = topAttribution(pidCounts, imageCache, 15)
	report.DecodeSample = readDecodeSample()

	return report
}

// imageForPID resolves a PID to its full image path via
// QueryFullProcessImageName. Returns "" when the process is gone or access is
// denied (e.g. protected/system PIDs) — a real, expected attribution edge.
func imageForPID(pid uint32) string {
	if pid == 0 {
		return "System Idle (pid 0)"
	}
	if pid == 4 {
		return "System (pid 4)"
	}
	h, err := windows.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

// topAttribution returns the top-n pids by event count with their resolved image.
func topAttribution(counts map[uint32]int, images map[uint32]string, n int) []AttributedProc {
	out := make([]AttributedProc, 0, len(counts))
	for pid, c := range counts {
		out = append(out, AttributedProc{PID: pid, Image: images[pid], Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// readDecodeSample pulls the C-side TDH decode sample and splits it into lines.
func readDecodeSample() []string {
	cstr := C.cfgms_decode_sample()
	if cstr == nil {
		return nil
	}
	defer C.cfgms_free(cstr)
	s := C.GoString(cstr)
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				lines = append(lines, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// MarshalReport renders a ConsumeReport as indented JSON.
func MarshalReport(r ConsumeReport) string {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"marshal_error":%q}`, err.Error())
	}
	return string(b)
}
