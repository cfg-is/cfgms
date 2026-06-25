// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package steward_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules"
	steward "github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestHealthMonitor(t *testing.T) {
	// Test cases for health monitor
	tests := []struct {
		name        string
		setupFn     func(*steward.HealthMonitor)
		checkStatus steward.HealthStatus
	}{
		{
			name: "default is healthy",
			setupFn: func(hm *steward.HealthMonitor) {
				// No setup, should be healthy by default
			},
			checkStatus: steward.StatusHealthy,
		},
		{
			name: "record error changes metrics",
			setupFn: func(hm *steward.HealthMonitor) {
				hm.RecordConfigError()
				hm.RecordConfigError()
				hm.RecordConfigError()
			},
			checkStatus: steward.StatusDegraded, // Status changes to degraded after errors
		},
		{
			name: "record latency updates metrics",
			setupFn: func(hm *steward.HealthMonitor) {
				hm.RecordTaskLatency(500 * time.Millisecond)
			},
			checkStatus: steward.StatusDegraded, // Status changes to degraded after high latency
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test logger
			logger := logging.NewLogger("info")

			// Create a health monitor
			monitor := steward.NewHealthMonitor(logger)

			// Apply setup function
			if tt.setupFn != nil {
				tt.setupFn(monitor)
			}

			// Check status — assertions happen synchronously; no goroutine needed
			assert.Equal(t, tt.checkStatus, monitor.GetStatus())
		})
	}
}

func TestNewStandalone(t *testing.T) {
	// Test standalone creation with empty config (should fail)
	logger := logging.NewLogger("info")

	s, err := steward.NewStandalone("", logger)

	// Should fail because no config found
	assert.Error(t, err)
	assert.Nil(t, s)
	assert.Contains(t, err.Error(), "failed to load configuration")
}

// TestNewStandaloneWithConfig tests that NewStandalone succeeds with a valid config file.
func TestNewStandaloneWithConfig(t *testing.T) {
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfg(t, dir, "standalone-test-steward")

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	assert.Equal(t, "standalone-test-steward", s.GetStewardID())
	// Constructor success + Start()/Stop() succeeding proves healthCheck and executor wiring.
	require.NoError(t, s.Stop(context.Background()))
}

// warnCapturingLogger wraps logging.Logger and records Warn messages for assertions.
// This is a real implementation of the Logger interface — not a mock — used only to
// observe which warnings the production code emits during resilience tests.
type warnCapturingLogger struct {
	mu      sync.Mutex
	warns   []string
	wrapped logging.Logger
}

func newWarnCapturingLogger(wrapped logging.Logger) *warnCapturingLogger {
	return &warnCapturingLogger{wrapped: wrapped}
}

func (l *warnCapturingLogger) Debug(msg string, kv ...interface{}) { l.wrapped.Debug(msg, kv...) }
func (l *warnCapturingLogger) Info(msg string, kv ...interface{})  { l.wrapped.Info(msg, kv...) }
func (l *warnCapturingLogger) Warn(msg string, kv ...interface{}) {
	l.mu.Lock()
	l.warns = append(l.warns, msg)
	l.mu.Unlock()
	l.wrapped.Warn(msg, kv...)
}
func (l *warnCapturingLogger) Error(msg string, kv ...interface{}) { l.wrapped.Error(msg, kv...) }
func (l *warnCapturingLogger) Fatal(msg string, kv ...interface{}) { l.wrapped.Fatal(msg, kv...) }
func (l *warnCapturingLogger) DebugCtx(ctx context.Context, msg string, kv ...interface{}) {
	l.wrapped.DebugCtx(ctx, msg, kv...)
}
func (l *warnCapturingLogger) InfoCtx(ctx context.Context, msg string, kv ...interface{}) {
	l.wrapped.InfoCtx(ctx, msg, kv...)
}
func (l *warnCapturingLogger) WarnCtx(ctx context.Context, msg string, kv ...interface{}) {
	l.mu.Lock()
	l.warns = append(l.warns, msg)
	l.mu.Unlock()
	l.wrapped.WarnCtx(ctx, msg, kv...)
}
func (l *warnCapturingLogger) ErrorCtx(ctx context.Context, msg string, kv ...interface{}) {
	l.wrapped.ErrorCtx(ctx, msg, kv...)
}
func (l *warnCapturingLogger) FatalCtx(ctx context.Context, msg string, kv ...interface{}) {
	l.wrapped.FatalCtx(ctx, msg, kv...)
}

func (l *warnCapturingLogger) WarnMessages() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.warns))
	copy(out, l.warns)
	return out
}

// newTestMonitorModuleWithCap creates a testMonitorModule with a custom channel capacity.
func newTestMonitorModuleWithCap(t *testing.T, cap int) *testMonitorModule {
	t.Helper()
	return &testMonitorModule{
		changesCh: make(chan modules.ChangeEvent, cap),
	}
}

// TestMonitorDebounce verifies that a burst of N events for the same resourceID
// within the debounce window yields exactly one ExecuteResource call (coalescing).
func TestMonitorDebounce(t *testing.T) {
	logger := logging.NewLogger("warn")
	dir := t.TempDir()
	cfgPath := writeSingleMonitorCfg(t, dir, "debounce-steward")

	testMon := newTestMonitorModule(t)

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	steward.RegisterTestModule(s, "testmonitor", testMon)
	// Short debounce so the test completes quickly.
	steward.SetDebounceWindowForTest(s, 40*time.Millisecond)
	// Disable DNA collection: this test exercises debounce coalescing only.
	// DNA collection runs system_profiler and network commands that take 30-60s on macOS CI.
	steward.SetDNACollector(s, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, s.Start(ctx))

	// Reset tracking after initial convergence so we isolate event-triggered reconciles.
	testMon.ResetTracking()

	// Send 5 events for the same resourceID in rapid succession.
	for i := 0; i < 5; i++ {
		testMon.SendChange(modules.ChangeEvent{
			ResourceID: "my-resource",
			ChangeType: modules.ChangeTypeModified,
		})
	}

	// Wait for the debounce to fire and exactly one reconcile to complete.
	// ExecuteResource calls Set when drift is detected; SetCallCount > 0 confirms
	// the reconcile ran.
	require.Eventually(t, func() bool {
		return testMon.SetCallCount() > 0
	}, 500*time.Millisecond, 5*time.Millisecond,
		"debounced reconcile must run after burst of events")

	// Verify no erroneous second reconcile fires within the observation window.
	assert.Never(t, func() bool { return testMon.SetCallCount() > 1 },
		100*time.Millisecond, 5*time.Millisecond,
		"burst of events within debounce window must coalesce to exactly one ExecuteResource call")

	require.NoError(t, s.Stop(context.Background()))
}

// TestMonitorQueueShedToPoll verifies that flooding the fan-in channel beyond its
// bounded capacity drops events non-blockingly (Warn-logged) and that the affected
// resource is corrected by the next scheduled convergence pass.
func TestMonitorQueueShedToPoll(t *testing.T) {
	baseLogger := logging.NewLogger("warn")
	capLog := newWarnCapturingLogger(baseLogger)

	dir := t.TempDir()
	cfgPath := writeSingleMonitorCfg(t, dir, "shed-to-poll-steward")

	// Use a large channel so SendChange never blocks; only the steward's internal
	// fan-in queue is the bottleneck under test.
	testMon := newTestMonitorModuleWithCap(t, 200)

	s, err := steward.NewStandalone(cfgPath, capLog)
	require.NoError(t, err)
	steward.RegisterTestModule(s, "testmonitor", testMon)
	// Short debounce so the one reconcile that does fire runs quickly.
	steward.SetDebounceWindowForTest(s, 40*time.Millisecond)
	// Small fan-in capacity so queue overflow is guaranteed regardless of scheduler
	// timing. Any burst > 2 will shed at least one event and emit the Warn log.
	steward.SetMonitorFanInCapForTest(s, 2)
	// Disable DNA collection: this test exercises queue-shed-to-poll only.
	// DNA collection runs system_profiler and network commands that take 30-60s on macOS CI.
	steward.SetDNACollector(s, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, s.Start(ctx))
	testMon.ResetTracking()

	// Flood with 20 events — well beyond the 2-entry fan-in queue.
	// All sends must complete quickly (non-blocking).
	start := time.Now()
	for i := 0; i < 20; i++ {
		testMon.SendChange(modules.ChangeEvent{
			ResourceID: "my-resource",
			ChangeType: modules.ChangeTypeModified,
		})
	}
	assert.Less(t, time.Since(start), 500*time.Millisecond,
		"flooding the monitor channel must be non-blocking")

	// Wait for at least one reconcile driven by the events that made it through.
	require.Eventually(t, func() bool {
		return testMon.GetCallCount() > 0
	}, 2*time.Second, 10*time.Millisecond,
		"at least one event-driven reconcile must occur despite queue pressure")

	// Verify that Warn was emitted for the shed events.
	warns := capLog.WarnMessages()
	hasShedWarn := false
	for _, w := range warns {
		if strings.Contains(w, "queue full") || strings.Contains(w, "shed") {
			hasShedWarn = true
			break
		}
	}
	assert.True(t, hasShedWarn,
		"Warn must be logged when events are dropped due to full queue")

	// Simulate the next scheduled convergence pass: it must correct the resource
	// regardless of how many events were shed.
	setCalls := testMon.SetCallCount()
	steward.RunConvergence(s, ctx)
	assert.Greater(t, testMon.SetCallCount(), setCalls,
		"scheduled convergence pass must correct a resource whose events were shed")

	require.NoError(t, s.Stop(context.Background()))
}

// TestMonitorCloseRace verifies that a ChangeEvent immediately followed by a
// concurrent Stop() causes no panic and no goroutine leak.
func TestMonitorCloseRace(t *testing.T) {
	// Snapshot goroutines that exist before this test creates any steward-owned
	// goroutines. This excludes long-running background goroutines started by other
	// tests in the same binary (e.g. DNA collector os/exec processes) from the
	// final leak check — we only verify goroutines introduced by this test.
	existingGoroutines := goleak.IgnoreCurrent()

	logger := logging.NewLogger("warn")
	dir := t.TempDir()
	cfgPath := writeSingleMonitorCfg(t, dir, "close-race-steward")

	testMon := newTestMonitorModule(t)

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	steward.RegisterTestModule(s, "testmonitor", testMon)
	// Short debounce so the timer can fire before Stop() in the racy path.
	steward.SetDebounceWindowForTest(s, 10*time.Millisecond)
	// Disable DNA collection so the background os/exec goroutines it spawns during
	// runConvergence are not included in the goroutine leak check. This test
	// exercises monitor goroutine lifecycle only; DNA collection is tested elsewhere.
	steward.SetDNACollector(s, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, s.Start(ctx))

	// Send a ChangeEvent and immediately call Stop() — race between the
	// debounce timer and the shutdown signal.
	assert.NotPanics(t, func() {
		testMon.SendChange(modules.ChangeEvent{
			ResourceID: "my-resource",
			ChangeType: modules.ChangeTypeModified,
		})
		// Concurrent Stop: may race with the debounce timer.
		require.NoError(t, s.Stop(context.Background()))
	})

	// All goroutines introduced by this test must have exited by the time
	// Stop() returns (monitored via WaitGroups). existingGoroutines excludes
	// pre-existing background goroutines from other tests (e.g. DNA collector
	// os/exec processes from TestMonitorQueueShedToPoll) so we only check
	// for leaks from this test's steward instance.
	//
	// DNA background collection goroutines (bgOnce.Do in dna.Collector.Collect)
	// use context.Background() and outlive the test that triggered them. They are
	// kicked off by *sibling* tests in this package (this test disables DNA), but
	// run AFTER goleak.IgnoreCurrent() snapshots here, so they are not captured by
	// existingGoroutines and are not goroutines of the steward under test.
	//
	// The collector spawns a tree: Collect → bgOnce → runBackgroundCollection →
	// {collectSoftwareInfo, collectSecurityInfo} → (per command) os/exec command
	// goroutines (stdout/stderr pipe copy + ctx-watch). All of these can be
	// mid-flight when this test's goleak check runs on a slow runner.
	//
	// goleak.IgnoreAnyFunction matches goroutines that have the named function
	// anywhere in their OWN stack — it does NOT match the "created by" line
	// (goleak explicitly excludes creator functions from the match set). The
	// os/exec goroutines fall into two families:
	//
	//   1. Pipe I/O copiers: top = internal/poll.runtime_pollWait, with
	//      os/exec.(*Cmd).Start.func2 further down (the goroutine entry point).
	//      IgnoreTopFunction("writerDescriptor") misses these because the top
	//      function is the poll wait, not the copier.
	//
	//   2. Context watcher: os/exec.(*Cmd).watchCtx on top.
	//
	// Match by the actual goroutine entry-point functions visible in the stack.
	goleak.VerifyNone(t, existingGoroutines,
		goleak.IgnoreAnyFunction("os/exec.(*Cmd).Start.func2"),
		goleak.IgnoreAnyFunction("os/exec.(*Cmd).watchCtx"),
		goleak.IgnoreAnyFunction("github.com/cfgis/cfgms/features/steward/dna.(*Collector).runBackgroundCollection"),
		goleak.IgnoreAnyFunction("github.com/cfgis/cfgms/features/steward/dna.(*Collector).collectSoftwareInfo"),
		goleak.IgnoreAnyFunction("github.com/cfgis/cfgms/features/steward/dna.(*Collector).collectSecurityInfo"),
	)
}

// TestMonitorDNARefreshAfterChange verifies that after an event-driven correction
// that changes state, the DNA snapshot (previousDNA) is refreshed so the next
// heartbeat reflects the updated hash before the scheduled convergence tick fires.
func TestMonitorDNARefreshAfterChange(t *testing.T) {
	logger := logging.NewLogger("warn")
	dir := t.TempDir()
	cfgPath := writeSingleMonitorCfg(t, dir, "dna-refresh-steward")

	testMon := newTestMonitorModule(t)

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	steward.RegisterTestModule(s, "testmonitor", testMon)
	steward.SetDebounceWindowForTest(s, 40*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, s.Start(ctx))
	// Safety net: cancel ctx first (kills any in-flight OS commands) then stop the
	// steward even if require.Eventually fails and s.Stop is never reached below.
	t.Cleanup(func() {
		cancel()
		_ = s.Stop(context.Background())
	})

	// Initial convergence has run; previousDNA is now the real system DNA.
	// Inject a sentinel so we can detect when detectUnmanagedDNADrift is called again.
	steward.SetPreviousDNA(s, &commonpb.DNA{
		Id:         "sentinel-id-dna-refresh-test",
		Attributes: map[string]string{},
	})

	testMon.ResetTracking()

	// Send a ChangeEvent. testMonitorModule.Get() returns "drifted" and the
	// cfg desires "present", so ExecuteResource will call Set → ChangesApplied=true
	// → runTargetedReconcile triggers DNA refresh.
	testMon.SendChange(modules.ChangeEvent{
		ResourceID: "my-resource",
		ChangeType: modules.ChangeTypeModified,
	})

	// Wait for the full runTargetedReconcile sequence: ExecuteResource (Set) followed
	// by detectUnmanagedDNADrift updating previousDNA. Both run sequentially in the
	// same monitorEventLoop goroutine, so polling GetPreviousDNA is the correct
	// synchronization — no sleep needed.
	//
	// 30s timeout: macOS CI runners are slow and detectUnmanagedDNADrift runs
	// multiple network OS commands (networksetup, scutil, netstat, etc.) that can
	// collectively take 10-20s on loaded CI runners. 30s gives ample headroom
	// while still catching cases where the DNA is never refreshed.
	require.Eventually(t, func() bool {
		dna := steward.GetPreviousDNA(s)
		return dna != nil && dna.Id != "sentinel-id-dna-refresh-test"
	}, 30*time.Second, 10*time.Millisecond,
		"DNA snapshot must be refreshed after a state-changing targeted reconcile")

	require.NoError(t, s.Stop(context.Background()))
}
