// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package execution_test

// Issue #2435: module Monitor engine on Executor — controller-mode stewards.
//
// These tests cover the monitor machinery moved from features/steward.Steward to
// execution.Executor (Issue #2435). They use real modules.Module + modules.Monitor
// implementations (no mocks) and follow the same rigor as the Steward-level tests
// from Issue #2423.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ─── test module fixtures ────────────────────────────────────────────────────

// monitorTestModule is a real modules.Module + modules.Monitor whose Changes
// channel the test controls. Tracks Get/Set call counts and Monitor() calls.
type monitorTestModule struct {
	mu sync.Mutex

	getCalls   int
	setCalls   int
	setConfigs []map[string]interface{}
	setErr     error // when non-nil, Set returns this error instead of succeeding

	// converges, when true, makes Get report "present" (matching desired) after
	// the first successful Set — a genuinely healthy resource that stops
	// drifting once converged, rather than the default fixture's permanently
	// "drifted" Get (which exists so ordinary tests always see a reconcile
	// dispatch Set, but reads as perpetual remaining-drift/failure to a
	// consumer, such as Issue #3876's backoff tracking, that cares whether
	// convergence actually succeeded).
	converges bool
	setOK     bool

	monitorCalled     bool
	monitorResourceID string

	closeCalled int
	changesCh   chan modules.ChangeEvent
	closed      bool
}

func newMonitorTestModule() *monitorTestModule {
	return &monitorTestModule{changesCh: make(chan modules.ChangeEvent, 16)}
}

func (m *monitorTestModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	m.mu.Lock()
	m.getCalls++
	state := "drifted"
	if m.converges && m.setOK {
		state = "present"
	}
	m.mu.Unlock()
	// Return drifted state (by default) so a targeted reconcile detects drift
	// and calls Set; a converges-fixture reports "present" once Set has
	// actually succeeded.
	return execution.NewConfigState(map[string]interface{}{"state": state}), nil
}

func (m *monitorTestModule) Set(_ context.Context, _ string, cfg modules.ConfigState) error {
	m.mu.Lock()
	m.setCalls++
	m.setConfigs = append(m.setConfigs, cfg.AsMap())
	err := m.setErr
	m.setOK = err == nil
	m.mu.Unlock()
	return err
}

// SetSetError makes every subsequent Set call return err (nil to clear).
func (m *monitorTestModule) SetSetError(err error) {
	m.mu.Lock()
	m.setErr = err
	m.mu.Unlock()
}

// SetConverges makes Get report "present" after the next successful Set,
// instead of the fixture's default permanently-"drifted" response.
func (m *monitorTestModule) SetConverges(v bool) {
	m.mu.Lock()
	m.converges = v
	m.mu.Unlock()
}

func (m *monitorTestModule) Monitor(_ context.Context, resourceID string, _ modules.ConfigState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.monitorCalled = true
	m.monitorResourceID = resourceID
	return nil
}

func (m *monitorTestModule) Changes() <-chan modules.ChangeEvent { return m.changesCh }

func (m *monitorTestModule) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalled++
	if !m.closed {
		m.closed = true
		close(m.changesCh)
	}
	return nil
}

func (m *monitorTestModule) SendChange(evt modules.ChangeEvent) { m.changesCh <- evt }

func (m *monitorTestModule) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getCalls
}

func (m *monitorTestModule) SetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.setCalls
}

func (m *monitorTestModule) CloseCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closeCalled
}

func (m *monitorTestModule) MonitorCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.monitorCalled {
		return 1
	}
	return 0
}

func (m *monitorTestModule) ResetTracking() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getCalls = 0
	m.setCalls = 0
	m.setConfigs = nil
}

// noopModule implements modules.Module but NOT modules.Monitor. Get returns
// a state matching the desired cfg so no drift is detected.
type noopModule struct {
	mu       sync.Mutex
	getCalls int
}

func (m *noopModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	m.mu.Lock()
	m.getCalls++
	m.mu.Unlock()
	return execution.NewConfigState(map[string]interface{}{"state": "present"}), nil
}

func (m *noopModule) Set(_ context.Context, _ string, _ modules.ConfigState) error { return nil }

func (m *noopModule) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getCalls
}

// observableModule is a real modules.Module (NOT a Monitor) whose Get returns a
// fixed multi-field observed state that matches the desired `state` so no drift is
// detected. It proves module DNA is captured from the convergence-loop Get alone —
// no monitor engine, no change-events (#2520 mechanism 1 steady-state source).
type observableModule struct{ state map[string]interface{} }

func (m *observableModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	return execution.NewConfigState(m.state), nil
}
func (m *observableModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil
}

// TestExecuteConfiguration_CapturesModuleDNAAtSteadyState is the REQUIRED test for
// #2520 mechanism 1: a STABLE managed resource — no drift, no monitor, no
// change-event — still contributes module DNA, sourced from the convergence Get.
func TestExecuteConfiguration_CapturesModuleDNAAtSteadyState(t *testing.T) {
	e := newMonitorExecutor(t)
	execution.ExecutorFactory(e).RegisterModule("obs", &observableModule{
		state: map[string]interface{}{
			"state": "present",
			"owner": "n1",
			"nodes": []string{"n1", "n2"},
		},
	})

	// Full convergence pass — no StartMonitors, no change-events.
	report := e.ExecuteConfiguration(context.Background(),
		stewardconfig.StewardConfig{Resources: singleResourceCfg("res1", "obs")})
	require.Equal(t, 1, report.SuccessfulCount)

	attrs := e.CollectModuleDNAAttributes(context.Background())
	assert.Equal(t, "present", attrs["res1.state"],
		"a stable resource's observed state must reach module DNA via the convergence Get")
	assert.Equal(t, "n1", attrs["res1.owner"])
	assert.Equal(t, "n1,n2", attrs["res1.nodes"])
}

// TestModuleDNASnapshot_SurvivesExecutorReinit is the REQUIRED test for the
// reconnect-survival fix (#2520): the module DNA snapshot is shared across Executor
// instances, so DNA converged by one executor is still readable after the client
// re-initializes the executor (as happens on every reconnect). A per-executor
// snapshot would be lost, silently blanking module DNA on the controller.
func TestModuleDNASnapshot_SurvivesExecutorReinit(t *testing.T) {
	shared := execution.NewModuleDNASnapshot()
	mod := &observableModule{state: map[string]interface{}{"state": "present", "owner": "n1"}}

	// Executor #1 (pre-reconnect) converges and populates the SHARED store.
	e1 := newMonitorExecutorWithDNAStore(t, shared)
	execution.ExecutorFactory(e1).RegisterModule("obs", mod)
	e1.ExecuteConfiguration(context.Background(),
		stewardconfig.StewardConfig{Resources: singleResourceCfg("res1", "obs")})
	require.Equal(t, "n1", e1.CollectModuleDNAAttributes(context.Background())["res1.owner"])

	// Executor #2 (post-reconnect, fresh instance) shares the SAME store and must
	// see the DNA #1 converged — without re-running any convergence.
	e2 := newMonitorExecutorWithDNAStore(t, shared)
	assert.Equal(t, "n1", e2.CollectModuleDNAAttributes(context.Background())["res1.owner"],
		"a re-initialized executor sharing the store must still surface previously-converged module DNA")
}

// TestExecuteConfiguration_PrunesRemovedResourceFromDNA verifies a resource dropped
// from the config disappears from module DNA on the next full convergence pass.
func TestExecuteConfiguration_PrunesRemovedResourceFromDNA(t *testing.T) {
	e := newMonitorExecutor(t)
	execution.ExecutorFactory(e).RegisterModule("obs", &observableModule{
		state: map[string]interface{}{"state": "present", "owner": "n1"},
	})

	// First pass includes res1 → captured.
	e.ExecuteConfiguration(context.Background(),
		stewardconfig.StewardConfig{Resources: singleResourceCfg("res1", "obs")})
	require.Equal(t, "n1", e.CollectModuleDNAAttributes(context.Background())["res1.owner"])

	// Second pass with NO resources → res1 pruned.
	e.ExecuteConfiguration(context.Background(),
		stewardconfig.StewardConfig{Resources: nil})
	_, present := e.CollectModuleDNAAttributes(context.Background())["res1.owner"]
	assert.False(t, present, "a resource removed from config must be pruned from module DNA")
}

// ─── helpers ────────────────────────────────────────────────────────────────

// newMonitorExecutor creates a minimal Executor with an empty module factory.
func newMonitorExecutor(t *testing.T) *execution.Executor {
	t.Helper()
	logger := logging.NewLogger("debug")
	f := factory.New(nil, stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}, logger)
	e, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:  logger,
		Factory: f,
	})
	require.NoError(t, err)
	return e
}

// newMonitorExecutorWithLogger creates a minimal Executor whose logger is the
// caller-supplied one, so tests can assert on the Warn records the monitor
// engine emits (queue shedding, monitor start failure).
func newMonitorExecutorWithLogger(t *testing.T, logger logging.Logger) *execution.Executor {
	t.Helper()
	f := factory.New(nil, stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}, logger)
	e, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:  logger,
		Factory: f,
	})
	require.NoError(t, err)
	return e
}

// newMonitorExecutorWithDNAStore builds an Executor wired to a caller-supplied
// shared module-DNA snapshot, mirroring how the steward client injects one store
// into every executor it builds (#2520).
func newMonitorExecutorWithDNAStore(t *testing.T, store *execution.ModuleDNASnapshot) *execution.Executor {
	t.Helper()
	logger := logging.NewLogger("debug")
	f := factory.New(nil, stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}, logger)
	e, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:            logger,
		Factory:           f,
		ModuleDNASnapshot: store,
	})
	require.NoError(t, err)
	return e
}

// singleResourceCfg builds a minimal resource slice for the given module name.
func singleResourceCfg(name, moduleName string) []stewardconfig.ResourceConfig {
	return []stewardconfig.ResourceConfig{
		{
			Name:   name,
			Module: moduleName,
			Config: map[string]interface{}{"state": "present"},
		},
	}
}

// ─── Issue #2435 AC1: StartMonitors / StopMonitors / CollectModuleDNAAttributes ─

// TestExecutor_StartMonitors_CallsMonitorOnEligibleModule verifies that
// StartMonitors calls Monitor() on modules that implement the interface.
func TestExecutor_StartMonitors_CallsMonitorOnEligibleModule(t *testing.T) {
	e := newMonitorExecutor(t)
	mod := newMonitorTestModule()
	execution.ExecutorFactory(e).RegisterModule("testmon", mod)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := e.StartMonitors(ctx, singleResourceCfg("res1", "testmon"))
	require.NoError(t, err)
	defer e.StopMonitors()

	assert.Equal(t, 1, mod.MonitorCallCount(), "Monitor() must be called on eligible module")
	assert.Equal(t, "res1", mod.monitorResourceID)
}

// TestExecutor_StartMonitors_SkipsNonMonitorModules verifies that modules that
// don't implement Monitor are silently skipped.
func TestExecutor_StartMonitors_SkipsNonMonitorModules(t *testing.T) {
	e := newMonitorExecutor(t)
	noop := &noopModule{}
	execution.ExecutorFactory(e).RegisterModule("noop", noop)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := e.StartMonitors(ctx, singleResourceCfg("res1", "noop"))
	require.NoError(t, err)
	// No goroutines started — StopMonitors is a no-op but safe to call.
	e.StopMonitors()
}

// TestExecutor_StartMonitors_CachesChangeEventDetails verifies that a ChangeEvent
// sent through the module's Changes() channel is cached and returned by
// CollectModuleDNAAttributes with the expected flattened structure.
func TestExecutor_StartMonitors_CachesChangeEventDetails(t *testing.T) {
	e := newMonitorExecutor(t)
	mod := newMonitorTestModule()
	execution.ExecutorFactory(e).RegisterModule("testmon", mod)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, e.StartMonitors(ctx, singleResourceCfg("res1", "testmon")))
	defer e.StopMonitors()

	mod.SendChange(modules.ChangeEvent{
		ResourceID: "res1",
		ChangeType: modules.ChangeTypeModified,
		Details: execution.NewConfigState(map[string]interface{}{
			"nodes":  []string{"n1", "n2"},
			"owner":  "n1",
			"nested": map[string]interface{}{"leaf": "v"},
		}),
	})

	require.Eventually(t, func() bool {
		attrs := e.CollectModuleDNAAttributes(context.Background())
		return attrs["res1.owner"] == "n1"
	}, 2*time.Second, 10*time.Millisecond, "ChangeEvent must be cached and flattened")

	attrs := e.CollectModuleDNAAttributes(context.Background())
	assert.Equal(t, "n1,n2", attrs["res1.nodes"], "slice values join with ','")
	assert.Equal(t, "n1", attrs["res1.owner"])
	assert.Equal(t, "v", attrs["res1.nested.leaf"], "nested map keys join with '.'")
}

// TestExecutor_StartMonitors_SecondCallStopsPreviousMonitors is the REQUIRED TEST
// for Issue #2435 AC3: a second StartMonitors call closes every previously-started
// monitor before starting new ones — no duplicate Monitor() call on a cached module
// instance, no leaked goroutine.
func TestExecutor_StartMonitors_SecondCallStopsPreviousMonitors(t *testing.T) {
	e := newMonitorExecutor(t)

	// Two separate module instances to track which one is active after the restart.
	mod1 := newMonitorTestModule()
	mod2 := newMonitorTestModule()
	execution.ExecutorFactory(e).RegisterModule("testmon", mod1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First StartMonitors call — mod1 is used.
	require.NoError(t, e.StartMonitors(ctx, singleResourceCfg("res1", "testmon")))
	assert.Equal(t, 1, mod1.MonitorCallCount(), "Monitor() called once for first start")
	assert.Equal(t, 0, mod1.CloseCallCount(), "mod1 must not be closed yet")

	// Replace the module in the factory to simulate a new module instance being
	// returned for a second config push. In production the factory caches by name
	// (LoadModule returns the same instance), so Close() must be called before
	// Monitor() is called again on the same instance. Here we swap mod2 in to make
	// it observable that the OLD instance got Close()d and the NEW one got Monitor().
	execution.ExecutorFactory(e).RegisterModule("testmon", mod2)

	// Second StartMonitors call — must close mod1 before starting mod2.
	require.NoError(t, e.StartMonitors(ctx, singleResourceCfg("res1", "testmon")))

	// mod1 must have been closed (its goroutines stopped, Close() called).
	assert.Equal(t, 1, mod1.CloseCallCount(), "first monitor instance must be closed before restart")

	// mod2 must have Monitor() called exactly once.
	assert.Equal(t, 1, mod2.MonitorCallCount(), "Monitor() must be called on new module instance")

	// Stop the second engine cleanly.
	e.StopMonitors()
	assert.Equal(t, 1, mod2.CloseCallCount(), "second monitor instance must be closed by StopMonitors")

	// Verify no goroutine leak: monitorWg.Wait() inside StopMonitors would deadlock
	// if any goroutine were still running — the test itself proves no leak.
}

// TestExecutor_StartMonitors_ReconcileDispatch is the REQUIRED TEST for Issue #2435
// AC4: a ChangeEvent triggers ExecuteResource/Set on the Executor-hosted engine,
// proving the rewritten runTargetedReconcile uses the retained monitorEntry slice.
func TestExecutor_StartMonitors_ReconcileDispatch(t *testing.T) {
	e := newMonitorExecutor(t)
	// Set a very short debounce so the test doesn't wait 1500ms.
	e.SetMonitorDebounceWindow(20 * time.Millisecond)

	mod := newMonitorTestModule()
	execution.ExecutorFactory(e).RegisterModule("testmon", mod)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, e.StartMonitors(ctx, singleResourceCfg("res1", "testmon")))
	defer e.StopMonitors()

	// Record Get count after StartMonitors (no drift check yet).
	baseGet := mod.GetCallCount()

	// Send a ChangeEvent — the debounce loop must call ExecuteResource → Get → drift
	// detected → Set (since Get returns "drifted" vs desired "present").
	mod.SendChange(modules.ChangeEvent{
		ResourceID: "res1",
		ChangeType: modules.ChangeTypeModified,
	})

	// Wait for Set to be called — proves the full reconcile dispatch ran.
	require.Eventually(t, func() bool {
		return mod.SetCallCount() > 0
	}, 2*time.Second, 5*time.Millisecond,
		"targeted reconcile must call Set() after ChangeEvent through the Executor-hosted engine")

	assert.Greater(t, mod.GetCallCount(), baseGet,
		"Get must have been called to read actual current state during reconcile")
	assert.Equal(t, "present", mod.setConfigs[0]["state"],
		"Set must use cfg desired state ('present'), not event details")
}

// TestExecutor_StartMonitors_ReconcileObserverCalled verifies that a registered
// reconcile observer is invoked when ChangesApplied is true.
func TestExecutor_StartMonitors_ReconcileObserverCalled(t *testing.T) {
	e := newMonitorExecutor(t)
	e.SetMonitorDebounceWindow(20 * time.Millisecond)

	mod := newMonitorTestModule()
	execution.ExecutorFactory(e).RegisterModule("testmon", mod)

	var observedResourceID string
	var observerMu sync.Mutex
	e.SetMonitorReconcileObserver(func(_ context.Context, resourceID string) {
		observerMu.Lock()
		observedResourceID = resourceID
		observerMu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, e.StartMonitors(ctx, singleResourceCfg("res1", "testmon")))
	defer e.StopMonitors()

	mod.SendChange(modules.ChangeEvent{
		ResourceID: "res1",
		ChangeType: modules.ChangeTypeModified,
	})

	require.Eventually(t, func() bool {
		observerMu.Lock()
		defer observerMu.Unlock()
		return observedResourceID == "res1"
	}, 2*time.Second, 5*time.Millisecond,
		"reconcile observer must be called with the correct resourceID when changes are applied")
}

// TestExecutor_StopMonitors_ClearsState verifies that CollectModuleDNAAttributes
// returns an empty map after StopMonitors (cached state is cleared).
func TestExecutor_StopMonitors_ClearsState(t *testing.T) {
	e := newMonitorExecutor(t)
	mod := newMonitorTestModule()
	execution.ExecutorFactory(e).RegisterModule("testmon", mod)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, e.StartMonitors(ctx, singleResourceCfg("res1", "testmon")))

	mod.SendChange(modules.ChangeEvent{
		ResourceID: "res1",
		ChangeType: modules.ChangeTypeModified,
		Details:    execution.NewConfigState(map[string]interface{}{"x": "1"}),
	})

	require.Eventually(t, func() bool {
		return len(e.CollectModuleDNAAttributes(context.Background())) > 0
	}, 2*time.Second, 10*time.Millisecond)

	e.StopMonitors()

	assert.Empty(t, e.CollectModuleDNAAttributes(context.Background()),
		"CollectModuleDNAAttributes must return empty map after StopMonitors")
}

// TestExecutor_RunTargetedReconcile_UnmanagedResource verifies the unmanaged-resource
// early-exit: a resourceID not in monitorEntries performs no Get/Set.
func TestExecutor_RunTargetedReconcile_UnmanagedResource(t *testing.T) {
	e := newMonitorExecutor(t)
	mod := newMonitorTestModule()
	execution.ExecutorFactory(e).RegisterModule("testmon", mod)

	// Call RunTargetedReconcile WITHOUT calling StartMonitors first — monitorEntries is nil.
	e.RunTargetedReconcile(context.Background(), "not-in-cfg")

	assert.Equal(t, 0, mod.GetCallCount(), "Get must not be called for unmanaged resource")
	assert.Equal(t, 0, mod.SetCallCount(), "Set must not be called for unmanaged resource")
}

// ─── Issue #3876: unbounded monitor-driven create-retry loop ───────────────────

// absentResourceCfg builds a single-resource slice whose desired state is
// literally "absent" — the fixture for TestExecutor_RunTargetedReconcile_AbsentDesiredState_NeverReconciles.
func absentResourceCfg(name, moduleName string) []stewardconfig.ResourceConfig {
	return []stewardconfig.ResourceConfig{
		{
			Name:   name,
			Module: moduleName,
			Config: map[string]interface{}{"state": "absent"},
		},
	}
}

// TestExecutor_RunTargetedReconcile_AbsentDesiredState_NeverReconciles is the
// [REQUIRED TEST] for Issue #3876: a monitor-driven targeted reconcile can never
// take the create path for a resource whose last declared state was absent. A
// monitored resource whose retained desired config is state: absent must never
// call module.Get/Set via a targeted reconcile, however many change-events fire.
func TestExecutor_RunTargetedReconcile_AbsentDesiredState_NeverReconciles(t *testing.T) {
	e := newMonitorExecutor(t)
	e.SetMonitorDebounceWindow(20 * time.Millisecond)

	mod := newMonitorTestModule()
	execution.ExecutorFactory(e).RegisterModule("testmon", mod)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, e.StartMonitors(ctx, absentResourceCfg("res1", "testmon")))
	defer e.StopMonitors()

	mod.SendChange(modules.ChangeEvent{ResourceID: "res1", ChangeType: modules.ChangeTypeModified})

	// Give the debounce+dispatch pipeline ample time to have run if it were
	// going to — then assert it did not.
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, mod.GetCallCount(), "a resource declared absent must never be reconciled by the monitor engine")
	assert.Equal(t, 0, mod.SetCallCount(), "a resource declared absent must never take the create path")

	// A direct RunTargetedReconcile call (the same entry point a fired debounce
	// timer uses) must also refuse it.
	e.RunTargetedReconcile(context.Background(), "res1")
	assert.Equal(t, 0, mod.GetCallCount())
	assert.Equal(t, 0, mod.SetCallCount())
}

// TestExecutor_StartMonitors_RemovedResourceStopsBeingMonitored is the
// [REQUIRED TEST] for Issue #3876: a resource removed from the steward config
// stops being monitored on the next StartMonitors call — its monitor state is
// dropped rather than retained and reconciled — and this recovery requires only
// a fresh config, not a service restart.
func TestExecutor_StartMonitors_RemovedResourceStopsBeingMonitored(t *testing.T) {
	e := newMonitorExecutor(t)
	e.SetMonitorDebounceWindow(20 * time.Millisecond)

	mod := newMonitorTestModule()
	execution.ExecutorFactory(e).RegisterModule("testmon", mod)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, e.StartMonitors(ctx, singleResourceCfg("res1", "testmon")))
	mod.SendChange(modules.ChangeEvent{ResourceID: "res1", ChangeType: modules.ChangeTypeModified})
	require.Eventually(t, func() bool { return mod.SetCallCount() > 0 }, 2*time.Second, 5*time.Millisecond,
		"sanity: res1 must be reconciled while still declared")

	// A new config no longer declares res1 at all — the same shape as the
	// observed incident's step 3 (config replaced, resource entirely gone).
	require.NoError(t, e.StartMonitors(ctx, nil))
	defer e.StopMonitors()

	mod.ResetTracking()
	// A direct dispatch attempt for the now-undeclared resourceID must take the
	// unmanaged-resource path, not reconcile: it is no longer in monitorEntries,
	// so it is not retained and reconciled.
	e.RunTargetedReconcile(context.Background(), "res1")
	assert.Equal(t, 0, mod.GetCallCount(), "a resource no longer declared must not be reconciled")
	assert.Equal(t, 0, mod.SetCallCount())
}

// TestExecutor_RunTargetedReconcile_BacksOffAfterRepeatedFailures is the
// [REQUIRED TEST] for Issue #3876: a repeatedly-failing targeted reconcile backs
// off and stops after a bounded number of attempts, logging why, instead of
// retrying forever. Firing far more change-events than the failure budget must
// still only call Set exactly maxTargetedReconcileFailures times.
func TestExecutor_RunTargetedReconcile_BacksOffAfterRepeatedFailures(t *testing.T) {
	logger := logging.NewCapturingLogger()
	e := newMonitorExecutorWithLogger(t, logger)
	e.SetMonitorDebounceWindow(5 * time.Millisecond)

	mod := newMonitorTestModule()
	mod.SetSetError(errors.New("simulated persistent module failure"))
	execution.ExecutorFactory(e).RegisterModule("testmon", mod)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, e.StartMonitors(ctx, singleResourceCfg("res1", "testmon")))
	defer e.StopMonitors()

	// Fire far more events than the failure budget, waiting out the debounce
	// window between each so every fire dispatches its own reconcile attempt.
	for i := 0; i < 20; i++ {
		mod.SendChange(modules.ChangeEvent{ResourceID: "res1", ChangeType: modules.ChangeTypeModified})
		time.Sleep(15 * time.Millisecond)
	}

	assert.Equal(t, 5, mod.SetCallCount(),
		"exactly maxTargetedReconcileFailures attempts must be made, however many events fire afterward")

	entry, ok := logger.FindWarn("Targeted reconcile failure budget exhausted; no longer retrying until config changes")
	require.True(t, ok, "exhausting the failure budget must be logged once, explaining why reconciles stopped")
	assert.Equal(t, "res1", entry["resource_id"])

	// A fresh config (the operator's recovery path) resets the budget without a
	// service restart: a new StartMonitors call — closing the old, exhausted
	// module instance and starting a new (here, fixed) one, exactly as a real
	// config push swaps the factory's cached instance — must reconcile again
	// immediately rather than staying backed off.
	fixed := newMonitorTestModule()
	execution.ExecutorFactory(e).RegisterModule("testmon", fixed)
	require.NoError(t, e.StartMonitors(ctx, singleResourceCfg("res1", "testmon")))
	fixed.SendChange(modules.ChangeEvent{ResourceID: "res1", ChangeType: modules.ChangeTypeModified})
	require.Eventually(t, func() bool { return fixed.SetCallCount() > 0 }, 2*time.Second, 5*time.Millisecond,
		"pushing a corrected config must be a sufficient recovery, without a service restart")
}

// TestExecutor_RunTargetedReconcile_FailingResourceDoesNotStarveOthers is the
// [REQUIRED TEST] for Issue #3876: a failing reconcile for one resource cannot
// starve convergence of others. A second, healthy monitored resource must keep
// reconciling normally throughout — including after the failing resource's
// budget is exhausted and its events become no-ops.
func TestExecutor_RunTargetedReconcile_FailingResourceDoesNotStarveOthers(t *testing.T) {
	e := newMonitorExecutor(t)
	e.SetMonitorDebounceWindow(5 * time.Millisecond)

	bad := newMonitorTestModule()
	bad.SetSetError(errors.New("simulated persistent module failure"))
	good := newMonitorTestModule()
	good.SetConverges(true) // a genuinely healthy resource, not the fixture's default permanent drift
	execution.ExecutorFactory(e).RegisterModule("badmon", bad)
	execution.ExecutorFactory(e).RegisterModule("goodmon", good)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resources := []stewardconfig.ResourceConfig{
		{Name: "bad1", Module: "badmon", Config: map[string]interface{}{"state": "present"}},
		{Name: "good1", Module: "goodmon", Config: map[string]interface{}{"state": "present"}},
	}
	require.NoError(t, e.StartMonitors(ctx, resources))
	defer e.StopMonitors()

	// Interleave: fire the failing resource's event repeatedly (well past its
	// budget), and the healthy resource's event once after each.
	for i := 0; i < 10; i++ {
		bad.SendChange(modules.ChangeEvent{ResourceID: "bad1", ChangeType: modules.ChangeTypeModified})
		time.Sleep(15 * time.Millisecond)
		good.SendChange(modules.ChangeEvent{ResourceID: "good1", ChangeType: modules.ChangeTypeModified})
		time.Sleep(15 * time.Millisecond)
	}

	assert.LessOrEqual(t, bad.SetCallCount(), maxTargetedReconcileFailuresForTest,
		"the failing resource must have backed off, not retried on every one of the 10 fires")
	// good1 converges on its first Set, so later dispatches correctly find no
	// drift and never call Set again — GetCallCount (incremented on every
	// dispatched reconcile, converged or not) is the proof each of its 10
	// events was actually processed rather than starved behind bad1's noise.
	// >= rather than == : debounce-window timing can coalesce or split a fire
	// by one at these millisecond scales, which is not what this test is about.
	assert.GreaterOrEqual(t, good.GetCallCount(), 10,
		"the healthy resource must be reconciled for every one of its own events, unaffected by the failing resource")
}

const maxTargetedReconcileFailuresForTest = 5

// TestExecutor_RunTargetedReconcile_TimeoutAndRetryExhaustedCountAsFailures
// verifies isReconcileFailure's classification indirectly: StatusTimeout and
// StatusRetryExhausted must count toward the backoff budget exactly like
// StatusFailed — both describe "retrying this will not help" just as much as an
// outright module error, and a module already reporting its own exhausted
// bounded retry (Issue #3802) must not be re-driven by the monitor engine on
// top of it.
func TestExecutor_RunTargetedReconcile_TimeoutAndRetryExhaustedCountAsFailures(t *testing.T) {
	assert.True(t, execution.IsReconcileFailureForTest(execution.StatusFailed))
	assert.True(t, execution.IsReconcileFailureForTest(execution.StatusTimeout))
	assert.True(t, execution.IsReconcileFailureForTest(execution.StatusRetryExhausted))
	assert.False(t, execution.IsReconcileFailureForTest(execution.StatusDeferred),
		"a reboot-window deferral is an intentional, self-clearing wait, not a hammering failure")
	assert.False(t, execution.IsReconcileFailureForTest(execution.StatusSuccess))
	assert.False(t, execution.IsReconcileFailureForTest(execution.StatusNoChange))
	assert.False(t, execution.IsReconcileFailureForTest(execution.StatusNonCompliant))
}

// TestExecutor_CollectModuleDNAAttributes_EvictsOnChannelClose verifies that
// when the module's Changes() channel is closed (module Stop signal), the
// cached state for that resourceID is evicted.
func TestExecutor_CollectModuleDNAAttributes_EvictsOnChannelClose(t *testing.T) {
	e := newMonitorExecutor(t)
	mod := newMonitorTestModule()
	execution.ExecutorFactory(e).RegisterModule("testmon", mod)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, e.StartMonitors(ctx, singleResourceCfg("res1", "testmon")))
	defer e.StopMonitors()

	mod.SendChange(modules.ChangeEvent{
		ResourceID: "res1",
		ChangeType: modules.ChangeTypeModified,
		Details:    execution.NewConfigState(map[string]interface{}{"owner": "n1"}),
	})

	require.Eventually(t, func() bool {
		return len(e.CollectModuleDNAAttributes(context.Background())) > 0
	}, 2*time.Second, 10*time.Millisecond)

	// Close the channel — simulates the module stopping.
	// mod.Close() already closes the channel; we invoke it directly here.
	require.NoError(t, mod.Close())

	require.Eventually(t, func() bool {
		return len(e.CollectModuleDNAAttributes(context.Background())) == 0
	}, 2*time.Second, 10*time.Millisecond,
		"eviction must happen when the monitor channel closes")
}

// ─── Issue #3333: CollectModuleFragments for non-cluster resources ────────────

// TestCollectModuleFragments_EmitsFragmentForSteadyStateOnlyResource is the
// REQUIRED TEST for Issue #3333 AC3: a resource managed via ordinary convergence
// only (no monitor/ChangeEvent configured) produces a fragment from
// CollectModuleFragments after a successful ExecuteResource.
func TestCollectModuleFragments_EmitsFragmentForSteadyStateOnlyResource(t *testing.T) {
	e := newMonitorExecutor(t)
	// observableModule implements Module only (not Monitor) — steady-state path only.
	execution.ExecutorFactory(e).RegisterModule("file", &observableModule{
		state: map[string]interface{}{
			"state": "present",
			"owner": "root",
		},
	})

	// Full convergence — no StartMonitors, no ChangeEvents.
	report := e.ExecuteConfiguration(context.Background(),
		stewardconfig.StewardConfig{Resources: singleResourceCfg("res1", "file")})
	require.Equal(t, 1, report.SuccessfulCount)

	frags := e.CollectModuleFragments(context.Background())
	require.NotEmpty(t, frags, "a resource converged via steady-state path must produce a fragment")

	var fragForRes1 *commonpb.Fragment
	for _, f := range frags {
		if f.FragmentId == "res1" {
			fragForRes1 = f
			break
		}
	}
	require.NotNil(t, fragForRes1, "fragment with FragmentId 'res1' must be present")
	assert.Equal(t, "file", fragForRes1.Authority,
		"authority must be the module bundle name derived from the resource's module field")
	assert.NotEmpty(t, fragForRes1.CanonicalBytes, "canonical bytes must be non-nil")
	assert.NotEmpty(t, fragForRes1.FragmentHash, "fragment hash must be non-nil")
}

// TestCollectModuleFragments_ClusterFragmentRegressionUnchanged is the REQUIRED
// TEST for Issue #3333 AC4: existing cluster:* fragment behavior (authority,
// canonicalization, hash) is unchanged after the two-source union change.
// Regression coverage against the monitor-sourced path.
//
// The resource is named "cluster:cfg-lab" with untyped module "hyperv" so that
// getResourceIdentifier returns "cluster:cfg-lab", matching the ChangeEvent
// resourceID and allowing authority to be resolved from the monitorEntry.
func TestCollectModuleFragments_ClusterFragmentRegressionUnchanged(t *testing.T) {
	e := newMonitorExecutor(t)
	e.SetMonitorDebounceWindow(20 * time.Millisecond)

	// monitorTestModule implements both Module and Monitor.
	mod := newMonitorTestModule()
	// "hyperv" is the bundle name — mirrors production cluster fragment construction.
	execution.ExecutorFactory(e).RegisterModule("hyperv", mod)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use untyped "hyperv" (no ".") so getResourceIdentifier returns the name verbatim.
	// This makes monitorEntry.resourceID == "cluster:cfg-lab" == ChangeEvent.ResourceID,
	// so authority resolves to "hyperv" from the monitorEntry map.
	resources := []stewardconfig.ResourceConfig{{
		Name:   "cluster:cfg-lab",
		Module: "hyperv",
		Config: map[string]interface{}{"state": "drifted"},
	}}
	require.NoError(t, e.StartMonitors(ctx, resources))
	defer e.StopMonitors()

	clusterDetails := map[string]interface{}{
		"name":           "cfg-lab",
		"cno_owner_node": "CFG-70-02",
		"member_nodes":   []string{"CFG-70-02", "CFG-AB-02"},
		"found":          true,
	}

	mod.SendChange(modules.ChangeEvent{
		ResourceID: "cluster:cfg-lab",
		ChangeType: modules.ChangeTypeModified,
		Details:    execution.NewConfigState(clusterDetails),
	})

	// Wait for the debounced reconcile's Get to land in the steady-state cache.
	// "cluster:cfg-lab.state" cannot come from monitorState — the ChangeEvent carries
	// only name, cno_owner_node, member_nodes, found — so its presence in DNA attributes
	// proves cacheModuleDNAState has run for this resource. Asserting on fragment
	// existence alone would return before the reconcile lands, leaving the two-source
	// union in an unsettled state and producing one of two stable hashes intermittently.
	require.Eventually(t, func() bool {
		attrs := e.CollectModuleDNAAttributes(context.Background())
		_, ok := attrs["cluster:cfg-lab.state"]
		return ok
	}, 2*time.Second, 10*time.Millisecond,
		"cluster:cfg-lab.state must appear in DNA attributes — proves debounced reconcile landed")

	// Verify fragment fields.
	var clusterFrag *commonpb.Fragment
	for _, f := range e.CollectModuleFragments(context.Background()) {
		if f.FragmentId == "cluster:cfg-lab" {
			clusterFrag = f
			break
		}
	}
	require.NotNil(t, clusterFrag, "cluster:cfg-lab fragment must be present")
	assert.Equal(t, "hyperv", clusterFrag.Authority,
		"cluster fragment authority must be the module bundle name")
	assert.NotEmpty(t, clusterFrag.CanonicalBytes, "cluster canonical bytes must be non-nil")
	assert.NotEmpty(t, clusterFrag.FragmentHash, "cluster fragment hash must be non-nil")

	// Verify canonical bytes are deterministic: same state → same hash.
	// Build expected from the two-source union: clusterDetails from monitorState merged
	// with {"state": "drifted"} from moduleDNA (the Get result cached by the debounced
	// reconcile). Monitor fields win on collision (none here); steady-state supplies "state".
	// We confirmed both sources are settled above before collecting clusterFrag.
	mergedState := make(map[string]interface{}, len(clusterDetails)+1)
	for k, v := range clusterDetails {
		mergedState[k] = v
	}
	mergedState["state"] = "drifted"
	expected, err := sdna.NewFragment("cluster:cfg-lab", "hyperv", sdna.MapState(mergedState))
	require.NoError(t, err)
	assert.Equal(t, expected.FragmentHash, clusterFrag.FragmentHash,
		"fragment hash must match independently-constructed fragment for same state")
}

// TestCollectModuleFragments_OmitsFragmentBeforeFirstReconcile is the REQUIRED
// TEST for Issue #3527 resolution (a): a fragment must not be emitted for a
// resource that is declared in cfg and monitored while its first targeted
// reconcile is still outstanding. Its module.Get is pending and will add fields
// the ChangeEvent never carried, so a fragment emitted now carries a transient
// hash that changes when the Get lands — causing the controller to request a
// resync it did not need. Per ADR-017 clause 2a the fragment IS the module's Get
// output; per clause 5 identical observed state must produce identical canonical
// bytes. A fragment built from the ChangeEvent Details alone violates both.
//
// The test fails if the fix is reverted (the unconditional
// "merged[id] = monSnap" re-added in Step 3 of CollectModuleFragments): with it,
// monitorState alone introduces the resource into the merged map and the
// "cluster:cfg-lab must not appear" assertion fails.
//
// The complementary case — a resourceID with NO cfg declaration, for which no
// reconcile is pending or ever will be — is pinned by
// TestCollectModuleFragments_EmitsObservedOnlyResourceImmediately.
func TestCollectModuleFragments_OmitsFragmentBeforeFirstReconcile(t *testing.T) {
	e := newMonitorExecutor(t)
	// Long debounce so the targeted reconcile never fires during the test window.
	e.SetMonitorDebounceWindow(10 * time.Second)

	mod := newMonitorTestModule()
	execution.ExecutorFactory(e).RegisterModule("hyperv", mod)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resources := []stewardconfig.ResourceConfig{{
		Name:   "cluster:cfg-lab",
		Module: "hyperv",
		Config: map[string]interface{}{"state": "drifted"},
	}}
	require.NoError(t, e.StartMonitors(ctx, resources))
	defer e.StopMonitors()

	// Send a ChangeEvent: cacheMonitorState (called by the fan-in goroutine before
	// the debounce) will populate monitorState, but cacheModuleDNAState (called
	// only after the reconcile's module.Get) will never run — debounce is 10 s.
	mod.SendChange(modules.ChangeEvent{
		ResourceID: "cluster:cfg-lab",
		ChangeType: modules.ChangeTypeModified,
		Details: execution.NewConfigState(map[string]interface{}{
			"name":           "cfg-lab",
			"cno_owner_node": "CFG-70-02",
			"member_nodes":   []string{"CFG-70-02", "CFG-AB-02"},
			"found":          true,
		}),
	})

	// Wait for monitorState to be populated. CollectModuleDNAAttributes includes
	// orphan monitorState entries (intentionally), so "cluster:cfg-lab.name"
	// appearing there proves the fan-in goroutine has cached the event.
	require.Eventually(t, func() bool {
		attrs := e.CollectModuleDNAAttributes(context.Background())
		_, ok := attrs["cluster:cfg-lab.name"]
		return ok
	}, 1*time.Second, 5*time.Millisecond,
		"monitorState must be populated before asserting fragment absence")

	// At this point: monitorState has 4 fields, moduleDNA is empty (no reconcile
	// has run). CollectModuleFragments must NOT emit a fragment — the state is
	// incomplete and would produce a transient hash.
	for _, f := range e.CollectModuleFragments(context.Background()) {
		assert.NotEqual(t, "cluster:cfg-lab", f.FragmentId,
			"fragment must not be emitted before the first targeted reconcile (moduleDNA empty)")
	}
}

// TestCollectModuleFragments_EmitsObservedOnlyResourceImmediately pins the other
// side of the #3527 gate, and is the unit-level guard for the #2908 cluster path.
//
// A module monitoring "vm:web-01" also reports "cluster:cfg-lab" on its change
// stream — an object no cfg declares. runTargetedReconcile skips unmanaged
// resourceIDs, so no module.Get is pending for it and none ever will be: the
// change-event snapshot is that object's complete and final observed state.
// Gating it on a moduleDNA entry would withhold the fragment permanently, not
// briefly, which is the regression this asserts against.
//
// Determinism (the property #3527 exists to protect) is asserted directly: the
// emitted hash equals an independently-constructed fragment over the same state,
// and repeated collection over unchanged state yields the same hash.
func TestCollectModuleFragments_EmitsObservedOnlyResourceImmediately(t *testing.T) {
	e := newMonitorExecutor(t)
	// Long debounce: proves the fragment does not depend on any reconcile landing.
	e.SetMonitorDebounceWindow(10 * time.Second)

	mod := newMonitorTestModule()
	execution.ExecutorFactory(e).RegisterModule("hyperv", mod)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Only vm:web-01 is declared; cluster:cfg-lab is observed, never managed.
	resources := []stewardconfig.ResourceConfig{{
		Name:   "vm:web-01",
		Module: "hyperv",
		Config: map[string]interface{}{"state": "drifted"},
	}}
	require.NoError(t, e.StartMonitors(ctx, resources))
	defer e.StopMonitors()

	clusterDetails := map[string]interface{}{
		"name":           "cfg-lab",
		"cno_owner_node": "CFG-70-02",
		"member_nodes":   []string{"CFG-70-02", "CFG-AB-02"},
		"resource_owner": map[string]string{"web-01": "CFG-70-02"},
		"found":          true,
	}
	mod.SendChange(modules.ChangeEvent{
		ResourceID: "cluster:cfg-lab",
		ChangeType: modules.ChangeTypeModified,
		Details:    execution.NewConfigState(clusterDetails),
	})

	var clusterFrag *commonpb.Fragment
	require.Eventually(t, func() bool {
		for _, f := range e.CollectModuleFragments(context.Background()) {
			if f.GetFragmentId() == "cluster:cfg-lab" {
				clusterFrag = f
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond,
		"an observed-only resource must emit a fragment without waiting for a reconcile")

	expected, err := sdna.NewFragment("cluster:cfg-lab", clusterFrag.GetAuthority(), sdna.MapState(clusterDetails))
	require.NoError(t, err)
	assert.Equal(t, expected.FragmentHash, clusterFrag.FragmentHash,
		"the observed-only fragment must hash the change-event snapshot exactly, with no partial merge")

	// Unchanged state must not churn the hash across collections.
	for _, f := range e.CollectModuleFragments(context.Background()) {
		if f.GetFragmentId() == "cluster:cfg-lab" {
			assert.Equal(t, clusterFrag.FragmentHash, f.FragmentHash,
				"repeated collection over unchanged state must produce an identical hash")
		}
	}
}

// ─── CollectModuleFragments: steward-side emission bounds ────────────────────

// TestCollectModuleFragments_DropsOverSizedFragmentAndKeepsRest covers the
// error branch of the emission loop: a resource whose canonical state exceeds
// the per-fragment bound produces no fragment, is reported at Warn with a
// sanitized resource_id and error, and does not prevent the remaining resources
// from being emitted.
//
// The bound exists because the controller rejects an ENTIRE DNA snapshot that
// carries an over-sized fragment (dna_handler.go maxDNAFragmentBytes), so
// dropping one offender is what keeps the rest of the snapshot deliverable.
//
// The over-sized resource is deliberately named with an embedded newline: the
// resourceID reaches the log from module-adjacent cfg data, so the assertion
// also pins the sanitization of that value.
func TestCollectModuleFragments_DropsOverSizedFragmentAndKeepsRest(t *testing.T) {
	logger := logging.NewCapturingLogger()
	e := newMonitorExecutorWithLogger(t, logger)

	oversizedName := "bulky\nres"
	// One value alone past the per-fragment canonical-bytes bound.
	blob := strings.Repeat("x", execution.MaxModuleFragmentCanonicalBytes+1024)
	execution.ExecutorFactory(e).RegisterModule("bulky", &observableModule{
		state: map[string]interface{}{"state": "present", "blob": blob},
	})
	execution.ExecutorFactory(e).RegisterModule("small", &observableModule{
		state: map[string]interface{}{"state": "present", "owner": "root"},
	})

	report := e.ExecuteConfiguration(context.Background(), stewardconfig.StewardConfig{
		Resources: []stewardconfig.ResourceConfig{
			{Name: oversizedName, Module: "bulky", Config: map[string]interface{}{"state": "present"}},
			{Name: "small1", Module: "small", Config: map[string]interface{}{"state": "present"}},
		},
	})
	require.Equal(t, 2, report.SuccessfulCount)

	frags := e.CollectModuleFragments(context.Background())

	ids := make([]string, 0, len(frags))
	for _, f := range frags {
		ids = append(ids, f.GetFragmentId())
	}
	assert.NotContains(t, ids, oversizedName,
		"a resource whose canonical state exceeds the per-fragment bound must not be emitted")
	assert.Contains(t, ids, "small1",
		"the remaining resources must still be emitted after one is dropped")

	entry, ok := logger.FindWarn("CollectModuleFragments: fragment dropped")
	require.True(t, ok, "dropping a fragment must be reported at Warn, not silent")
	assert.Equal(t, logging.SanitizeLogValue(oversizedName), entry["resource_id"],
		"the logged resource_id must be sanitized")
	assert.NotContains(t, entry["resource_id"], "\n",
		"the logged resource_id must carry no newline (log-injection sink)")
	loggedErr, isStr := entry["error"].(string)
	require.True(t, isStr, "the Warn must carry the error text")
	assert.Contains(t, loggedErr, "per-fragment bound",
		"the Warn must say why the fragment was dropped")
	assert.Equal(t, logging.SanitizeLogValue(loggedErr), loggedErr,
		"the logged error value must be sanitized")
}

// TestCollectModuleFragments_BoundsFragmentCount covers the steward-side count
// bound. The controller rejects an entire DNA snapshot carrying more than
// maxDNATransferFragments (1024) fragments, so a steward managing more resources
// than the budget must emit a bounded subset rather than black-holing every full
// DNA sync.
//
// It also pins the two properties of the selection: cluster:* resources — the
// only fragments with a live controller-side consumer — survive the cut even
// when they sort last, and the selection is stable across calls so an unchanged
// host does not churn a new persisted DNA version per sync.
func TestCollectModuleFragments_BoundsFragmentCount(t *testing.T) {
	logger := logging.NewCapturingLogger()
	e := newMonitorExecutorWithLogger(t, logger)
	execution.ExecutorFactory(e).RegisterModule("file", &observableModule{
		state: map[string]interface{}{"state": "present", "owner": "root"},
	})

	// One over-budget cfg. The cluster resource sorts after every "res-NNNNNN"
	// name, so a plain sorted truncation would drop it.
	total := execution.MaxModuleFragments + 64
	resources := make([]stewardconfig.ResourceConfig, 0, total)
	resources = append(resources, stewardconfig.ResourceConfig{
		Name:   "cluster:zzz-lab",
		Module: "file",
		Config: map[string]interface{}{"state": "present"},
	})
	for i := 1; i < total; i++ {
		resources = append(resources, stewardconfig.ResourceConfig{
			Name:   fmt.Sprintf("res-%06d", i),
			Module: "file",
			Config: map[string]interface{}{"state": "present"},
		})
	}

	report := e.ExecuteConfiguration(context.Background(), stewardconfig.StewardConfig{Resources: resources})
	require.Equal(t, total, report.SuccessfulCount)

	frags := e.CollectModuleFragments(context.Background())
	require.Len(t, frags, execution.MaxModuleFragments,
		"emission must be capped at the steward-side fragment budget")

	ids := make([]string, 0, len(frags))
	for _, f := range frags {
		ids = append(ids, f.GetFragmentId())
	}
	assert.Contains(t, ids, "cluster:zzz-lab",
		"cluster fragments must survive the cap — they are the ones the controller registry parses")

	entry, ok := logger.FindWarn("CollectModuleFragments: resource count exceeds the fragment budget, emitting a bounded subset")
	require.True(t, ok, "truncating the fragment set must be reported at Warn, not silent")
	assert.Equal(t, total, entry["resource_count"])
	assert.Equal(t, total-execution.MaxModuleFragments, entry["dropped"])

	// Stability: a second call over unchanged state selects the same resourceIDs
	// in the same order, so the manifest and aggregate root do not churn.
	second := e.CollectModuleFragments(context.Background())
	require.Len(t, second, len(frags))
	for i := range frags {
		assert.Equal(t, frags[i].GetFragmentId(), second[i].GetFragmentId(),
			"fragment selection and order must be deterministic across calls")
	}
}

// TestCollectModuleFragments_UnderBudgetEmitsEveryResource pins the other side of
// the bound: a cfg within budget is unaffected by it — every managed resource
// still gets a fragment (Issue #3333 AC1) and nothing is reported as dropped.
func TestCollectModuleFragments_UnderBudgetEmitsEveryResource(t *testing.T) {
	logger := logging.NewCapturingLogger()
	e := newMonitorExecutorWithLogger(t, logger)
	execution.ExecutorFactory(e).RegisterModule("file", &observableModule{
		state: map[string]interface{}{"state": "present", "owner": "root"},
	})

	const count = 24
	resources := make([]stewardconfig.ResourceConfig, 0, count)
	for i := 0; i < count; i++ {
		resources = append(resources, stewardconfig.ResourceConfig{
			Name:   fmt.Sprintf("res-%03d", i),
			Module: "file",
			Config: map[string]interface{}{"state": "present"},
		})
	}

	report := e.ExecuteConfiguration(context.Background(), stewardconfig.StewardConfig{Resources: resources})
	require.Equal(t, count, report.SuccessfulCount)

	frags := e.CollectModuleFragments(context.Background())
	assert.Len(t, frags, count, "a cfg within budget must produce one fragment per managed resource")

	_, truncated := logger.FindWarn("CollectModuleFragments: resource count exceeds the fragment budget, emitting a bounded subset")
	assert.False(t, truncated, "an under-budget cfg must not report truncation")
	_, dropped := logger.FindWarn("CollectModuleFragments: fragment dropped")
	assert.False(t, dropped, "an under-budget cfg with small states must not drop any fragment")
}

// ─── fan-in queue shedding (SetMonitorFanInCap) ──────────────────────────────

// blockingGetModule is a real modules.Module + modules.Monitor whose Get blocks
// until Release is called. Parking Get parks the monitor event loop inside
// runTargetedReconcile, which is what lets a test fill the bounded fan-in queue
// deterministically instead of racing the dispatch loop.
//
// Its Changes channel is UNBUFFERED on purpose: a SendChange returns only once
// the fan-in goroutine has received the event, so a blocking (rather than
// shedding) send on a full queue would stall the producer and fail the test.
type blockingGetModule struct {
	mu       sync.Mutex
	getCalls int
	closed   bool

	changesCh chan modules.ChangeEvent
	release   chan struct{}
}

func newBlockingGetModule() *blockingGetModule {
	return &blockingGetModule{
		changesCh: make(chan modules.ChangeEvent),
		release:   make(chan struct{}),
	}
}

func (m *blockingGetModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	m.mu.Lock()
	m.getCalls++
	m.mu.Unlock()
	<-m.release
	// Matches the desired cfg state, so no Set is attempted during the reconcile.
	return execution.NewConfigState(map[string]interface{}{"state": "present"}), nil
}

func (m *blockingGetModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil
}

func (m *blockingGetModule) Monitor(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil
}

func (m *blockingGetModule) Changes() <-chan modules.ChangeEvent { return m.changesCh }

func (m *blockingGetModule) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.changesCh)
	}
	return nil
}

func (m *blockingGetModule) SendChange(evt modules.ChangeEvent) { m.changesCh <- evt }

func (m *blockingGetModule) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getCalls
}

// Release unblocks every current and future Get call. Idempotent.
func (m *blockingGetModule) Release() {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.release:
	default:
		close(m.release)
	}
}

// TestExecutor_StartMonitors_ShedsEventsWhenFanInQueueFull covers the bounded
// fan-in queue: with the dispatch loop parked inside a reconcile, a flood of
// events must (a) never block the producing monitor goroutine, (b) be shed with
// a Warn to the next scheduled convergence pass, and (c) still refresh the
// module DNA cache, because cacheMonitorState runs before the non-blocking send.
//
// SetMonitorFanInCap(1) is what makes this deterministic: with the production
// capacity of 64 the flood would fit and nothing would be shed, so the Warn
// assertion also proves the cap override is honoured by StartMonitors.
func TestExecutor_StartMonitors_ShedsEventsWhenFanInQueueFull(t *testing.T) {
	logger := logging.NewCapturingLogger()
	e := newMonitorExecutorWithLogger(t, logger)
	e.SetMonitorDebounceWindow(10 * time.Millisecond)
	e.SetMonitorFanInCap(1)

	mod := newBlockingGetModule()
	execution.ExecutorFactory(e).RegisterModule("blocking", mod)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, e.StartMonitors(ctx, singleResourceCfg("res1", "blocking")))
	t.Cleanup(func() {
		mod.Release()
		e.StopMonitors()
	})

	// First event drains through the queue and fires a targeted reconcile, whose
	// Get blocks — from here the dispatch loop consumes nothing from the fan-in.
	mod.SendChange(modules.ChangeEvent{
		ResourceID: "res1",
		ChangeType: modules.ChangeTypeModified,
		Details:    execution.NewConfigState(map[string]interface{}{"seq": "0"}),
	})
	require.Eventually(t, func() bool { return mod.GetCallCount() >= 1 }, 2*time.Second, 5*time.Millisecond,
		"the first event must reach runTargetedReconcile and park the dispatch loop in Get")

	// Flood: capacity is 1, so at most one of these buffers and the rest must be shed.
	const flood = 8
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		for i := 1; i <= flood; i++ {
			mod.SendChange(modules.ChangeEvent{
				ResourceID: "res1",
				ChangeType: modules.ChangeTypeModified,
				Details:    execution.NewConfigState(map[string]interface{}{"seq": fmt.Sprintf("%d", i)}),
			})
		}
	}()
	select {
	case <-sent:
	case <-time.After(5 * time.Second):
		t.Fatal("producer blocked on a full fan-in queue: the send must be non-blocking and shed the event")
	}

	// (b) shedding is reported, not silent.
	require.Eventually(t, func() bool {
		_, ok := logger.FindWarn("Monitor event queue full, event shed to scheduled poll")
		return ok
	}, 2*time.Second, 5*time.Millisecond,
		"a full fan-in queue must Warn that the event was shed to the scheduled poll")
	entry, ok := logger.FindWarn("Monitor event queue full, event shed to scheduled poll")
	require.True(t, ok)
	assert.Equal(t, "res1", entry["resource_id"], "the shed Warn must name the affected resource")

	// (c) a shed event still refreshes module DNA — the cache write happens before the send.
	require.Eventually(t, func() bool {
		return e.CollectModuleDNAAttributes(context.Background())["res1.seq"] == fmt.Sprintf("%d", flood)
	}, 2*time.Second, 5*time.Millisecond,
		"the last event's details must reach the DNA cache even though the event was shed")

	// Unblock the parked reconcile so the engine tears down cleanly.
	mod.Release()
}

// ─── StartMonitors: module Monitor() failure ─────────────────────────────────

// errMonitorStart is the failure a module reports when it cannot start watching.
var errMonitorStart = errors.New("watcher init failed: no inotify instances left")

// failingMonitorModule is a real modules.Module + modules.Monitor whose Monitor()
// always fails, exercising the skip-this-resource-and-continue branch of
// StartMonitors. Get/Set/Close are counted so the test can prove the resource was
// never retained as a monitor entry.
type failingMonitorModule struct {
	mu           sync.Mutex
	getCalls     int
	monitorCalls int
	closeCalls   int
	changesCh    chan modules.ChangeEvent
}

func newFailingMonitorModule() *failingMonitorModule {
	return &failingMonitorModule{changesCh: make(chan modules.ChangeEvent)}
}

func (m *failingMonitorModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	m.mu.Lock()
	m.getCalls++
	m.mu.Unlock()
	return execution.NewConfigState(map[string]interface{}{"state": "present"}), nil
}

func (m *failingMonitorModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil
}

func (m *failingMonitorModule) Monitor(_ context.Context, _ string, _ modules.ConfigState) error {
	m.mu.Lock()
	m.monitorCalls++
	m.mu.Unlock()
	return errMonitorStart
}

func (m *failingMonitorModule) Changes() <-chan modules.ChangeEvent { return m.changesCh }

func (m *failingMonitorModule) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalls++
	return nil
}

func (m *failingMonitorModule) MonitorCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.monitorCalls
}

func (m *failingMonitorModule) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getCalls
}

func (m *failingMonitorModule) CloseCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closeCalls
}

// TestExecutor_StartMonitors_SkipsResourceWhenMonitorFails covers the error
// branch in StartMonitors: a module whose Monitor() returns an error is logged,
// skipped, and NOT retained as a monitor entry — while the remaining resources
// in the same call still start. The failing resource is listed first so the test
// also proves the loop continues rather than aborting the whole engine.
func TestExecutor_StartMonitors_SkipsResourceWhenMonitorFails(t *testing.T) {
	logger := logging.NewCapturingLogger()
	e := newMonitorExecutorWithLogger(t, logger)

	bad := newFailingMonitorModule()
	good := newMonitorTestModule()
	execution.ExecutorFactory(e).RegisterModule("badmon", bad)
	execution.ExecutorFactory(e).RegisterModule("goodmon", good)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resources := []stewardconfig.ResourceConfig{
		{Name: "bad1", Module: "badmon", Config: map[string]interface{}{"state": "present"}},
		{Name: "good1", Module: "goodmon", Config: map[string]interface{}{"state": "present"}},
	}
	require.NoError(t, e.StartMonitors(ctx, resources),
		"a single module's Monitor() failure must not fail the whole StartMonitors call")

	assert.Equal(t, 1, bad.MonitorCallCount(), "Monitor() must have been attempted on the failing module")
	assert.Equal(t, 1, good.MonitorCallCount(), "the loop must continue and start the remaining resource")

	entry, ok := logger.FindWarn("Failed to start module monitor")
	require.True(t, ok, "the Monitor() failure must be logged at Warn")
	assert.Equal(t, "bad1", entry["resource"])
	assert.Equal(t, "bad1", entry["resource_id"])
	assert.Equal(t, errMonitorStart.Error(), entry["error"],
		"the module-supplied error text must be logged (sanitized, unchanged for control-char-free text)")

	// The failed resource is not a monitor entry: a targeted reconcile for it takes
	// the unmanaged-resource path and never touches the module.
	e.RunTargetedReconcile(context.Background(), "bad1")
	assert.Equal(t, 0, bad.GetCallCount(), "a resource whose monitor failed must not be dispatched a reconcile")

	// ...and it is not closed on teardown either, since it was never retained.
	e.StopMonitors()
	assert.Equal(t, 0, bad.CloseCallCount(), "a module whose Monitor() failed was never retained, so it is not closed")
	assert.Equal(t, 1, good.CloseCallCount(), "the successfully-started monitor must be closed by StopMonitors")
}
