// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package dex

// This file implements the Windows DEX acquisition spike (Issue #2516).
//
// Strategy (confirmed by prior research 2026-07-07):
//   - No kernel driver. All target signals are obtainable from usermode via
//     in-box ETW providers and WMI (same surface Microsoft Intune Endpoint
//     Analytics uses for boot/login/responsiveness/app-reliability metrics).
//   - Pure Go. ETW acquisition uses golang.org/x/sys/windows (already a direct
//     dependency). WMI uses github.com/go-ole/go-ole (also a direct dependency).
//     No cgo, no Rust/Zig.
//
// ETW architecture (spike):
//   StartTrace → EnableTraceEx2 (per provider) → [overhead window] → StopTrace.
//   Events flow into kernel-side buffers during the window; no consumer reads them.
//   A ProcessTrace consumer was removed due to a fatal sudog-cache corruption in
//   the windows.NewCallback → cgocallbackg path (see runETWConsumer).
//
// WMI architecture (SMART + thermal — push-style events are kernel-mode only):
//   CoInitializeEx → ConnectServer → ExecNotificationQuery (polling loop).
//
// CPU overhead (the spike's primary unknown):
//   Measured as the delta in GetProcessTimes.KernelTime+UserTime over a
//   OverheadWindowSec window, normalised to percent of one logical core.

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

// ─── ETW syscall bindings ────────────────────────────────────────────────────
// All ETW entry points live in advapi32.dll (Windows 7+). The session and
// enable functions use the Unicode (W) variants.

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procStartTraceW    = modadvapi32.NewProc("StartTraceW")
	procStopTraceW     = modadvapi32.NewProc("StopTraceW")
	procEnableTraceEx2 = modadvapi32.NewProc("EnableTraceEx2")
)

// ─── ETW constants ───────────────────────────────────────────────────────────

const (
	// EVENT_TRACE_REAL_TIME_MODE delivers events directly to the consumer.
	eventTraceRealTimeMode uint32 = 0x00000100

	// WNODE_FLAG_TRACED_GUID is required in EVENT_TRACE_PROPERTIES.Wnode.Flags.
	wnodeFlagTracedGUID uint32 = 0x00020000

	// TRACE_LEVEL_INFORMATION matches WINEVENT_LEVEL_INFO (level 4).
	traceLevelInformation uint8 = 4

	// PROCESS_QUERY_LIMITED_INFORMATION is the minimum right for GetProcessTimes.
	processQueryLimitedInformation uint32 = 0x1000
)

// ─── ETW provider registry ───────────────────────────────────────────────────

// etwProvider describes a single ETW provider we probe in the spike.
type etwProvider struct {
	class    SignalClass
	name     string // human-readable provider name
	guidStr  string // "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}"
	matchAny uint64 // keyword match-any mask (0 = all events)
}

// etwProviders is the candidate provider set for the DEX spike.
// Provider GUIDs are from the in-box Windows manifest (`wevtutil gp <name>`).
var etwProviders = []etwProvider{
	{
		// App-hang and UI-responsiveness events from the Win32 kernel subsystem.
		// EventID 1 = window-not-responding (hung-window detection),
		// EventID 14 = ghost-window-created (Windows has started replacing the
		// hung window with a ghost).
		class:    SignalAppHang,
		name:     "Microsoft-Windows-Win32k",
		guidStr:  "{8c416c79-d49b-4f01-a467-e56d3aa8234c}",
		matchAny: 0x0000000000002000, // kw 0x2000 = "Responsiveness"
	},
	{
		// Disk I/O completions with wait time and queue depth.
		// The kernel disk provider fires per-I/O events that include
		// IrpFlags, TransferSize, and — on 20H1+ — ResponseTime in µs.
		class:    SignalDiskIO,
		name:     "Microsoft-Windows-Kernel-Disk",
		guidStr:  "{3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}",
		matchAny: 0, // all keywords
	},
	{
		// Hard-fault paging: the kernel PerfInfo provider emits a HardFault
		// event (opcode 32) each time a thread takes a hard page fault.
		class:    SignalHardFault,
		name:     "Microsoft-Windows-Kernel-PerfInfo",
		guidStr:  "{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}",
		matchAny: 0x0000000000000020, // kw 0x20 = "PERF_HARD_FAULTS"
	},
	{
		// DNS resolution latency: the DNS client provider fires a
		// QueryCompleted event (EventID 3018 / 3020) with QueryResults and
		// QueryOptions. Jitter can be derived from inter-arrival time.
		class:    SignalNetwork,
		name:     "Microsoft-Windows-DNS-Client",
		guidStr:  "{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}",
		matchAny: 0,
	},
}

// ─── EVENT_TRACE_PROPERTIES layout ──────────────────────────────────────────
// Must be a single contiguous allocation: the struct followed immediately by
// the session-name string (UTF-16, null-terminated). The struct fields
// LogFileNameOffset and LoggerNameOffset are byte offsets from the start of
// the allocation.

type eventTraceProperties struct {
	Wnode struct {
		BufferSize        uint32
		ProviderId        uint32
		HistoricalContext uint64
		KernelHandle      windows.Handle
		Guid              windows.GUID
		ClientContext     uint32
		Flags             uint32
	}
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadId      windows.Handle
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// ─── WMI provider config ────────────────────────────────────────────────────

type wmiProvider struct {
	class     SignalClass
	namespace string
	wmiClass  string
	// query is the WQL to poll. SMART and thermal are not push providers in
	// usermode WMI — we poll at 60 s intervals for the spike.
	query string
}

var wmiProviders = []wmiProvider{
	{
		class:     SignalSMART,
		namespace: `root\wmi`,
		wmiClass:  "MSStorageDriver_FailurePredictData",
		query:     "SELECT InstanceName, PredictFailure, Reason FROM MSStorageDriver_FailurePredictData",
	},
	{
		class:     SignalThermal,
		namespace: `root\wmi`,
		wmiClass:  "MSAcpi_ThermalZoneTemperature",
		query:     "SELECT InstanceName, CurrentTemperature FROM MSAcpi_ThermalZoneTemperature",
	},
}

// ─── Collector ───────────────────────────────────────────────────────────────

// Collector is the top-level acquisition spike entry point.
type Collector struct {
	cfg        SpikeConfig
	sink       *Sink
	total      atomic.Int64 // WMI signal events successfully written to sink
	sinkErrors atomic.Int64 // sink write failures during collection
}

// NewCollector returns a Collector configured with cfg.
func NewCollector(cfg SpikeConfig, sink *Sink) *Collector {
	return &Collector{cfg: cfg, sink: sink}
}

// Run executes the full spike: probes all providers, collects events for
// cfg.OverheadWindowSec, measures CPU overhead, and returns a SpikeReport.
// ctx can be used to abort early.
func (c *Collector) Run(ctx context.Context) (SpikeReport, error) {
	// 1. Probe reachability for all signal classes.
	reach := c.probeAll(ctx)
	for _, r := range reach {
		if err := c.sink.WriteReachability(r); err != nil {
			return SpikeReport{}, fmt.Errorf("dex: sink write: %w", err)
		}
	}

	// 2. Start active collection (ETW + WMI polling) while measuring overhead.
	cpuBefore, err := processTimesNs()
	if err != nil {
		return SpikeReport{}, fmt.Errorf("dex: read process times before: %w", err)
	}
	wallBefore := time.Now()

	collectCtx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.OverheadWindowSec)*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// Start ETW session.
	sessionHandle, etwStartErr := c.startETWSession()
	if etwStartErr == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runETWConsumer(collectCtx, sessionHandle)
		}()
	}

	// Start WMI polling.
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runWMIPoller(collectCtx)
	}()

	wg.Wait()

	if sessionHandle != 0 {
		if stopErr := c.stopETWSession(sessionHandle); stopErr != nil {
			return SpikeReport{}, fmt.Errorf("dex: stop ETW session: %w", stopErr)
		}
	}

	cpuAfter, err := processTimesNs()
	if err != nil {
		return SpikeReport{}, fmt.Errorf("dex: read process times after: %w", err)
	}
	wallElapsed := time.Since(wallBefore).Seconds()

	// 3. Compute CPU percent relative to one logical core.
	cpuNs := int64(cpuAfter) - int64(cpuBefore)
	wallNs := wallElapsed * float64(time.Second)
	cpuPct := 0.0
	if wallNs > 0 {
		cpuPct = (float64(cpuNs) / wallNs) * 100.0
	}

	const budgetPct = 1.0
	overhead := OverheadSample{
		DurationSec:   wallElapsed,
		CPUPercent:    cpuPct,
		BudgetPercent: budgetPct,
		WithinBudget:  cpuPct <= budgetPct,
	}
	if err := c.sink.WriteOverhead(overhead); err != nil {
		return SpikeReport{}, fmt.Errorf("dex: sink write: %w", err)
	}

	return SpikeReport{
		Reachability: reach,
		Overhead:     overhead,
		TotalEvents:  int(c.total.Load()),
		SinkErrors:   int(c.sinkErrors.Load()),
	}, nil
}

// ─── Reachability probing ─────────────────────────────────────────────────────

func (c *Collector) probeAll(ctx context.Context) []ReachabilityResult {
	results := make([]ReachabilityResult, 0, len(etwProviders)+len(wmiProviders))
	for _, p := range etwProviders {
		results = append(results, c.probeETW(ctx, p))
	}
	for _, p := range wmiProviders {
		results = append(results, c.probeWMIWithTimeout(p))
	}
	return results
}

// probeETW attempts to start a transient ETW session to verify that the
// provider GUID is known to the OS (EnableTraceEx2 returns ERROR_SUCCESS or
// ERROR_TIMEOUT — not ERROR_NOT_FOUND / ERROR_INVALID_PARAMETER).
func (c *Collector) probeETW(_ context.Context, p etwProvider) ReachabilityResult {
	guid, err := parseGUID(p.guidStr)
	if err != nil {
		return ReachabilityResult{
			Class:     p.class,
			Mechanism: MechanismETW,
			Provider:  p.name,
			Reachable: false,
			Error:     "invalid GUID: " + err.Error(),
		}
	}

	probeName := c.cfg.SessionName + "-probe-" + string(p.class)
	handle, startErr := startNamedTrace(probeName, eventTraceRealTimeMode)
	if startErr != nil {
		return ReachabilityResult{
			Class:     p.class,
			Mechanism: MechanismETW,
			Provider:  p.name,
			Reachable: false,
			Error:     "StartTrace: " + startErr.Error(),
		}
	}
	defer func() { _ = stopNamedTrace(handle, probeName) }()

	ret, _, callErr := procEnableTraceEx2.Call( //nolint:staticcheck // SA4023: syscall.LazyProc.Call's error return is always a non-nil syscall.Errno (even success wraps Errno(0), whose Error() is "The operation completed successfully."), so callErr != nil is always true by design — the real check is the string comparison below.
		handle,
		uintptr(unsafe.Pointer(&guid)),
		1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
		uintptr(traceLevelInformation),
		uintptr(p.matchAny),
		0, // MatchAllKeyword
		0, // Timeout (0 = async)
		0, // EnableParameters
	)
	// ERROR_SUCCESS (0) or ERROR_TIMEOUT (1460) both mean the provider exists.
	// ERROR_INVALID_PARAMETER (87) or ERROR_NOT_FOUND (1168) mean it doesn't.
	reachable := ret == 0 || windows.Errno(ret) == windows.ERROR_TIMEOUT
	errStr := ""
	if !reachable {
		if callErr != nil && callErr.Error() != "The operation completed successfully." { //nolint:staticcheck // SA4023: see the Call() comment above — callErr is never a true nil here, the string comparison is the real check.
			errStr = callErr.Error()
		} else {
			errStr = fmt.Sprintf("EnableTraceEx2 returned %d", ret)
		}
	}

	return ReachabilityResult{
		Class:     p.class,
		Mechanism: MechanismETW,
		Provider:  p.name,
		Reachable: reachable,
		Error:     errStr,
	}
}

// probeWMIWithTimeout calls probeWMI in a goroutine and returns a
// ReachabilityResult within wmiOperationTimeout. On VMs where the WMI
// provider class is absent, ExecQuery can block indefinitely; the timeout
// prevents the probe loop from hanging.
func (c *Collector) probeWMIWithTimeout(p wmiProvider) ReachabilityResult {
	ch := make(chan ReachabilityResult, 1)
	go func() {
		ch <- c.probeWMI(p)
	}()
	select {
	case r := <-ch:
		return r
	case <-time.After(wmiOperationTimeout):
		return ReachabilityResult{
			Class:     p.class,
			Mechanism: MechanismWMI,
			Provider:  p.wmiClass,
			Reachable: false,
			Error:     "WMI probe timed out after 10s",
		}
	}
}

// probeWMI executes a WMI query against the target namespace and class to
// confirm the class exists and returns rows.
func (c *Collector) probeWMI(p wmiProvider) ReachabilityResult {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		oleErr, ok := err.(*ole.OleError)
		// S_FALSE (already initialised on this thread) is acceptable.
		if !ok || oleErr.Code() != uintptr(0x00000001) {
			return ReachabilityResult{
				Class:     p.class,
				Mechanism: MechanismWMI,
				Provider:  p.wmiClass,
				Reachable: false,
				Error:     "CoInitializeEx: " + err.Error(),
			}
		}
	}
	defer ole.CoUninitialize()

	locator, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return ReachabilityResult{
			Class:     p.class,
			Mechanism: MechanismWMI,
			Provider:  p.wmiClass,
			Reachable: false,
			Error:     "CreateObject SWbemLocator: " + err.Error(),
		}
	}
	defer locator.Release()

	wbem, err := locator.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return ReachabilityResult{
			Class:     p.class,
			Mechanism: MechanismWMI,
			Provider:  p.wmiClass,
			Reachable: false,
			Error:     "QueryInterface: " + err.Error(),
		}
	}
	defer wbem.Release()

	svcRaw, err := oleutil.CallMethod(wbem, "ConnectServer", nil, p.namespace)
	if err != nil {
		return ReachabilityResult{
			Class:     p.class,
			Mechanism: MechanismWMI,
			Provider:  p.wmiClass,
			Reachable: false,
			Error:     "ConnectServer " + p.namespace + ": " + err.Error(),
		}
	}
	svc := svcRaw.ToIDispatch()
	defer svc.Release()

	resultRaw, err := oleutil.CallMethod(svc, "ExecQuery", p.query)
	if err != nil {
		return ReachabilityResult{
			Class:     p.class,
			Mechanism: MechanismWMI,
			Provider:  p.wmiClass,
			Reachable: false,
			Error:     "ExecQuery: " + err.Error(),
		}
	}
	defer func() { _ = resultRaw.Clear() }()

	result := resultRaw.ToIDispatch()
	countRaw, err := oleutil.GetProperty(result, "Count")
	if err != nil {
		return ReachabilityResult{
			Class:     p.class,
			Mechanism: MechanismWMI,
			Provider:  p.wmiClass,
			// Query executed successfully — class exists even if 0 rows
			Reachable: true,
			Error:     "Count property: " + err.Error(),
		}
	}
	defer func() { _ = countRaw.Clear() }()

	return ReachabilityResult{
		Class:     p.class,
		Mechanism: MechanismWMI,
		Provider:  p.wmiClass,
		Reachable: true,
	}
}

// ─── ETW session management ──────────────────────────────────────────────────

// startETWSession starts the real-time ETW session and enables all providers.
// Returns the session handle (used with StopTrace after the overhead window).
func (c *Collector) startETWSession() (uintptr, error) {
	handle, err := startNamedTrace(c.cfg.SessionName, eventTraceRealTimeMode)
	if err != nil {
		return 0, err
	}

	for _, p := range etwProviders {
		guid, err := parseGUID(p.guidStr)
		if err != nil {
			continue
		}
		procEnableTraceEx2.Call( //nolint:errcheck // best-effort; probe already confirmed reachability
			handle,
			uintptr(unsafe.Pointer(&guid)),
			1,
			uintptr(traceLevelInformation),
			uintptr(p.matchAny),
			0, 0, 0,
		)
	}
	return handle, nil
}

// stopETWSession stops the named ETW session and releases its handle.
func (c *Collector) stopETWSession(handle uintptr) error {
	return stopNamedTrace(handle, c.cfg.SessionName)
}

// runETWConsumer waits for ctx to expire while the ETW session is active.
// The session generates events into kernel-side buffers during this window;
// overhead is measured via GetProcessTimes rather than Go-side event counting.
//
// A windows.NewCallback + ProcessTrace consumer was removed because the
// native→Go transition path on a locked OS thread corrupts the Go runtime's
// sudog cache (fatal: acquireSudog: found s.elem != nil in cache) when ETW
// fires callbacks during active collection. Restricting the callback body to
// atomic operations does not prevent the crash: the cgocallbackg entry path
// modifies per-P state that collides with the goroutine waiting in selectgo.
// Event counting is not required for the spike's goals (reachability + overhead).
func (c *Collector) runETWConsumer(ctx context.Context, _ uintptr) {
	<-ctx.Done()
}

// classForGUID maps a provider GUID back to its SignalClass.
func classForGUID(guid windows.GUID) SignalClass {
	s := guidString(guid)
	for _, p := range etwProviders {
		if strings.EqualFold(p.guidStr, s) {
			return p.class
		}
	}
	return ""
}

// guidString converts a windows.GUID to the {xxxxxxxx-...} string form.
func guidString(g windows.GUID) string {
	return fmt.Sprintf("{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1],
		g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7],
	)
}

// ─── WMI timeout ─────────────────────────────────────────────────────────────

// wmiOperationTimeout caps each WMI query. On GitHub-hosted Windows VMs the
// MSStorageDriver and MSAcpi WMI providers are often absent, causing ExecQuery
// to block until the WMI provider host times out (up to 30 s by default).
// A 10 s ceiling keeps test runs well within CI budgets.
const wmiOperationTimeout = 10 * time.Second

// ─── WMI polling ─────────────────────────────────────────────────────────────

// runWMIPoller polls WMI for SMART and thermal data every 60 seconds until ctx
// is done. COM is initialised per-query (inside queryWMIProvider goroutines)
// so this goroutine itself needs no COM apartment.
func (c *Collector) runWMIPoller(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	// Poll immediately on start, then on ticker.
	c.pollWMI(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.pollWMI(ctx)
		}
	}
}

func (c *Collector) pollWMI(ctx context.Context) {
	for _, p := range wmiProviders {
		if ctx.Err() != nil {
			return
		}
		if int(c.total.Load()) >= c.cfg.MaxEventsPerClass*len(wmiProviders) {
			return
		}
		c.pollWMIProviderWithTimeout(ctx, p)
	}
}

// pollWMIProviderWithTimeout runs the WMI query for p in a bounded goroutine
// and writes results to the sink only if they arrive before wmiOperationTimeout.
// The calling goroutine is never blocked past the timeout, even if ExecQuery
// hangs (e.g. when the WMI provider class is not registered on a VM).
func (c *Collector) pollWMIProviderWithTimeout(ctx context.Context, p wmiProvider) {
	ch := make(chan []map[string]any, 1)
	go func() {
		ch <- c.queryWMIProvider(p)
	}()

	var rows []map[string]any
	select {
	case rows = <-ch:
	case <-time.After(wmiOperationTimeout):
		return
	case <-ctx.Done():
		return
	}

	for _, fields := range rows {
		if c.sink.WriteEvent(p.class, fields) == nil {
			c.total.Add(1)
		} else {
			c.sinkErrors.Add(1)
		}
	}
}

// queryWMIProvider executes the WMI query for p and returns one field map per
// result row. COM is initialised on the goroutine's locked OS thread so all
// IDispatch calls happen on the correct apartment thread.
func (c *Collector) queryWMIProvider(p wmiProvider) []map[string]any {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		oleErr, ok := err.(*ole.OleError)
		// S_FALSE (0x1) means COM was already initialised on this thread; fine.
		if !ok || oleErr.Code() != uintptr(0x00000001) {
			return nil
		}
	}
	defer ole.CoUninitialize()

	locator, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return nil
	}
	defer locator.Release()

	wbem, err := locator.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil
	}
	defer wbem.Release()

	svcRaw, err := oleutil.CallMethod(wbem, "ConnectServer", nil, p.namespace)
	if err != nil {
		return nil
	}
	svc := svcRaw.ToIDispatch()
	defer svc.Release()

	resultRaw, err := oleutil.CallMethod(svc, "ExecQuery", p.query)
	if err != nil {
		return nil
	}
	defer func() { _ = resultRaw.Clear() }()

	result := resultRaw.ToIDispatch()
	countRaw, err := oleutil.GetProperty(result, "Count")
	if err != nil {
		return nil
	}
	count, ok := countRaw.Value().(int32)
	_ = countRaw.Clear()
	if !ok || count == 0 {
		return nil
	}

	rows := make([]map[string]any, 0, count)
	for i := int32(0); i < count; i++ {
		itemRaw, err := oleutil.CallMethod(result, "ItemIndex", i)
		if err != nil {
			continue
		}
		item := itemRaw.ToIDispatch()
		rows = append(rows, c.extractWMIFields(item, p))
		item.Release()
	}
	return rows
}

// extractWMIFields reads the interesting properties from a WMI result row.
func (c *Collector) extractWMIFields(item *ole.IDispatch, p wmiProvider) map[string]any {
	fields := make(map[string]any)

	switch p.class {
	case SignalSMART:
		if v, err := oleutil.GetProperty(item, "InstanceName"); err == nil {
			fields["instance"] = v.ToString()
			_ = v.Clear()
		}
		if v, err := oleutil.GetProperty(item, "PredictFailure"); err == nil {
			fields["predict_failure"] = v.Value()
			_ = v.Clear()
		}

	case SignalThermal:
		if v, err := oleutil.GetProperty(item, "InstanceName"); err == nil {
			fields["instance"] = v.ToString()
			_ = v.Clear()
		}
		// Temperature is in tenths of a Kelvin; convert to Celsius for readability.
		if v, err := oleutil.GetProperty(item, "CurrentTemperature"); err == nil {
			if deciK, ok := v.Value().(int32); ok {
				fields["temp_celsius"] = (float64(deciK) / 10.0) - 273.15
			}
			_ = v.Clear()
		}
	}

	return fields
}

// ─── CPU overhead measurement ─────────────────────────────────────────────────

// processTimesNs returns the sum of kernel + user CPU time consumed by the
// current process since its start, in nanoseconds.
func processTimesNs() (uint64, error) {
	handle, err := windows.OpenProcess(processQueryLimitedInformation, false, windows.GetCurrentProcessId())
	if err != nil {
		return 0, err
	}
	defer func() { _ = windows.CloseHandle(handle) }()

	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, err
	}

	// FILETIME is in 100-ns units.
	toNs := func(ft windows.Filetime) uint64 {
		return (uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)) * 100
	}
	return toNs(kernel) + toNs(user), nil
}

// ─── ETW helpers ──────────────────────────────────────────────────────────────

// startNamedTrace starts a new real-time ETW trace session with the given name
// and mode flags. Returns the session handle.
func startNamedTrace(name string, logFileMode uint32) (uintptr, error) {
	nameUTF16, err := windows.UTF16FromString(name)
	if err != nil {
		return 0, err
	}

	// Allocate: struct + name string (UTF-16, null-terminated).
	nameBytes := len(nameUTF16) * 2
	totalSize := uint32(unsafe.Sizeof(eventTraceProperties{}) + uintptr(nameBytes))

	buf := make([]byte, totalSize)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = totalSize
	props.Wnode.Flags = wnodeFlagTracedGUID
	props.LogFileMode = logFileMode
	props.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
	props.BufferSize = 64 // 64 KB per buffer
	props.MinimumBuffers = 4
	props.MaximumBuffers = 32

	// Copy the name after the struct.
	nameStart := unsafe.Pointer(&buf[props.LoggerNameOffset])
	copy((*[1 << 20]byte)(nameStart)[:nameBytes], (*[1 << 20]byte)(unsafe.Pointer(&nameUTF16[0]))[:nameBytes])

	var handle uintptr
	ret, _, callErr := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(&nameUTF16[0])),
		uintptr(unsafe.Pointer(props)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("StartTraceW: %w (code %d)", callErr, ret)
	}
	return handle, nil
}

// stopNamedTrace stops and frees the named ETW session.
func stopNamedTrace(handle uintptr, name string) error {
	nameUTF16, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}

	nameBytes := len(nameUTF16) * 2
	totalSize := uint32(unsafe.Sizeof(eventTraceProperties{}) + uintptr(nameBytes))
	buf := make([]byte, totalSize)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = totalSize
	props.Wnode.Flags = wnodeFlagTracedGUID
	props.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))

	nameStart := unsafe.Pointer(&buf[props.LoggerNameOffset])
	copy((*[1 << 20]byte)(nameStart)[:nameBytes], (*[1 << 20]byte)(unsafe.Pointer(&nameUTF16[0]))[:nameBytes])

	ret, _, callErr := procStopTraceW.Call(
		handle,
		uintptr(unsafe.Pointer(&nameUTF16[0])),
		uintptr(unsafe.Pointer(props)),
	)
	if ret != 0 {
		// ERROR_MORE_DATA (234) is benign — the buffer was too small to hold
		// the final properties, but the session was stopped.
		if windows.Errno(ret) == windows.ERROR_MORE_DATA {
			return nil
		}
		return fmt.Errorf("StopTraceW: %w (code %d)", callErr, ret)
	}
	return nil
}

// parseGUID parses a "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" string into a
// windows.GUID. This is a spike-local helper — the standard library provides
// no GUID parser.
func parseGUID(s string) (windows.GUID, error) {
	s = strings.TrimPrefix(strings.TrimSuffix(s, "}"), "{")
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return windows.GUID{}, fmt.Errorf("invalid GUID %q", s)
	}

	var g windows.GUID
	if _, err := fmt.Sscanf(parts[0], "%08x", &g.Data1); err != nil {
		return windows.GUID{}, fmt.Errorf("GUID Data1: %w", err)
	}
	if _, err := fmt.Sscanf(parts[1], "%04x", &g.Data2); err != nil {
		return windows.GUID{}, fmt.Errorf("GUID Data2: %w", err)
	}
	if _, err := fmt.Sscanf(parts[2], "%04x", &g.Data3); err != nil {
		return windows.GUID{}, fmt.Errorf("GUID Data3: %w", err)
	}

	d4str := parts[3] + parts[4]
	if len(d4str) != 16 {
		return windows.GUID{}, fmt.Errorf("GUID Data4: expected 16 hex chars, got %d", len(d4str))
	}
	for i := range g.Data4 {
		if _, err := fmt.Sscanf(d4str[i*2:i*2+2], "%02x", &g.Data4[i]); err != nil {
			return windows.GUID{}, fmt.Errorf("GUID Data4[%d]: %w", i, err)
		}
	}
	return g, nil
}
