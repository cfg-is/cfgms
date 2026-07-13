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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
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
	m.mu.Unlock()
	// Return drifted state so a targeted reconcile detects drift and calls Set.
	return execution.NewConfigState(map[string]interface{}{"state": "drifted"}), nil
}

func (m *monitorTestModule) Set(_ context.Context, _ string, cfg modules.ConfigState) error {
	m.mu.Lock()
	m.setCalls++
	m.setConfigs = append(m.setConfigs, cfg.AsMap())
	m.mu.Unlock()
	return nil
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
