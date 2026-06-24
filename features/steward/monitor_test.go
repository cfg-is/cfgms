// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package steward_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	steward "github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/execution"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"
)

// testMonitorModule is a real implementation of modules.Module + modules.Monitor
// for monitor consumer tests. It does not use any mock framework.
type testMonitorModule struct {
	mu sync.Mutex

	getCalls   int
	setConfigs []map[string]interface{} // config passed to each Set call

	monitorCalled     bool
	monitorResourceID string
	monitorDesired    modules.ConfigState

	changesCh chan modules.ChangeEvent
}

func newTestMonitorModule(t *testing.T) *testMonitorModule {
	t.Helper()
	return &testMonitorModule{
		changesCh: make(chan modules.ChangeEvent, 16),
	}
}

func (m *testMonitorModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	m.mu.Lock()
	m.getCalls++
	m.mu.Unlock()
	// Return a state that differs from the desired cfg state to ensure drift is detected.
	return execution.NewConfigState(map[string]interface{}{"state": "drifted"}), nil
}

func (m *testMonitorModule) Set(_ context.Context, _ string, cfg modules.ConfigState) error {
	m.mu.Lock()
	m.setConfigs = append(m.setConfigs, cfg.AsMap())
	m.mu.Unlock()
	return nil
}

func (m *testMonitorModule) Monitor(_ context.Context, resourceID string, desired modules.ConfigState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.monitorCalled = true
	m.monitorResourceID = resourceID
	m.monitorDesired = desired
	return nil
}

func (m *testMonitorModule) Changes() <-chan modules.ChangeEvent {
	return m.changesCh
}

func (m *testMonitorModule) Close() error {
	return nil
}

func (m *testMonitorModule) SendChange(evt modules.ChangeEvent) {
	m.changesCh <- evt
}

func (m *testMonitorModule) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getCalls
}

func (m *testMonitorModule) SetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.setConfigs)
}

func (m *testMonitorModule) GetSetConfigs() []map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]map[string]interface{}, len(m.setConfigs))
	copy(out, m.setConfigs)
	return out
}

func (m *testMonitorModule) MonitorCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.monitorCalled
}

func (m *testMonitorModule) MonitorResourceID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.monitorResourceID
}

func (m *testMonitorModule) ResetTracking() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getCalls = 0
	m.setConfigs = nil
}

// testNoopModule implements modules.Module but NOT modules.Monitor.
// Its Get returns a state that matches the cfg desired state so no drift is detected.
type testNoopModule struct {
	mu       sync.Mutex
	getCalls int
}

func newTestNoopModule() *testNoopModule { return &testNoopModule{} }

func (m *testNoopModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	m.mu.Lock()
	m.getCalls++
	m.mu.Unlock()
	return execution.NewConfigState(map[string]interface{}{"state": "present"}), nil
}

func (m *testNoopModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil
}

func (m *testNoopModule) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getCalls
}

// writeTwoResourceCfg writes a cfg with two resources: one for testmonitor and one for testnoop.
func writeTwoResourceCfg(t *testing.T, dir, id string) string {
	t.Helper()
	cfgData := `steward:
  id: ` + id + `
resources:
  - name: my-resource
    module: testmonitor
    config:
      state: present
  - name: other-resource
    module: testnoop
    config:
      state: present
`
	path := filepath.Join(dir, "test.cfg")
	require.NoError(t, os.WriteFile(path, []byte(cfgData), 0644))
	return path
}

// writeSingleMonitorCfg writes a cfg with one resource for the testmonitor module.
func writeSingleMonitorCfg(t *testing.T, dir, id string) string {
	t.Helper()
	cfgData := `steward:
  id: ` + id + `
resources:
  - name: my-resource
    module: testmonitor
    config:
      state: present
`
	path := filepath.Join(dir, "test.cfg")
	require.NoError(t, os.WriteFile(path, []byte(cfgData), 0644))
	return path
}

// TestMonitorConsumerWiring verifies that after startStandalone:
//   - every module in cfg.Resources implementing Monitor has had Monitor() called,
//   - its Changes() channel is consumed, and
//   - a ChangeEvent triggers ExecuteResource for that resourceID only
//     (not a full ExecuteConfiguration of all resources).
func TestMonitorConsumerWiring(t *testing.T) {
	logger := logging.NewLogger("debug")
	dir := t.TempDir()
	cfgPath := writeTwoResourceCfg(t, dir, "monitor-wiring-steward")

	testMon := newTestMonitorModule(t)
	testNoop := newTestNoopModule()

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	steward.RegisterTestModule(s, "testmonitor", testMon)
	steward.RegisterTestModule(s, "testnoop", testNoop)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, s.Start(ctx))

	// Monitor() must have been called with the correct resourceID.
	require.True(t, testMon.MonitorCalled(), "Monitor() must be called for testmonitor module")
	assert.Equal(t, "my-resource", testMon.MonitorResourceID())

	// testNoop does not implement Monitor — verify no Monitor call happened on it
	// (trivially true since testNoopModule has no Monitor method, but we still assert
	// that testnoop.GetCallCount is from initial convergence only, not a monitor start).

	// Record call counts after initial convergence.
	initialMonGet := testMon.GetCallCount()
	initialNoopGet := testNoop.GetCallCount()

	// Send a ChangeEvent — this must trigger a targeted reconcile for "my-resource" only.
	testMon.SendChange(modules.ChangeEvent{
		ResourceID: "my-resource",
		ChangeType: modules.ChangeTypeModified,
	})

	// Wait for the targeted reconcile to run (testMon.Get is called again).
	require.Eventually(t, func() bool {
		return testMon.GetCallCount() > initialMonGet
	}, 2*time.Second, 10*time.Millisecond, "targeted reconcile must run after ChangeEvent")

	// The other module must NOT have had an extra Get call — proving targeted, not full, convergence.
	assert.Equal(t, initialNoopGet, testNoop.GetCallCount(),
		"testnoop must not be called by a targeted reconcile for my-resource")

	require.NoError(t, s.Stop(context.Background()))
}

// TestMonitorEventIsHintNotTruth verifies that a ChangeEvent with a forged Details
// does not influence the Set decision. The reconcile must use module.Get() for
// current state and the cfg ResourceConfig for desired state; event.Details is ignored.
func TestMonitorEventIsHintNotTruth(t *testing.T) {
	logger := logging.NewLogger("debug")
	dir := t.TempDir()
	cfgPath := writeSingleMonitorCfg(t, dir, "monitor-hint-steward")

	testMon := newTestMonitorModule(t)

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	steward.RegisterTestModule(s, "testmonitor", testMon)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, s.Start(ctx))

	// Reset tracking after initial convergence so we isolate the event-triggered reconcile.
	testMon.ResetTracking()

	// Send a forged event whose Details claim a fabricated state that differs from both
	// current (Get returns "drifted") and desired cfg ("present").
	testMon.SendChange(modules.ChangeEvent{
		ResourceID: "my-resource",
		ChangeType: modules.ChangeTypeModified,
		Details:    execution.NewConfigState(map[string]interface{}{"state": "fabricated_evil_value"}),
	})

	// Wait for the Set call (drift detected → Set called in apply mode).
	require.Eventually(t, func() bool {
		return testMon.SetCallCount() > 0
	}, 2*time.Second, 10*time.Millisecond, "Set must be called after event-triggered reconcile")

	// Get must have been called — actual current state was read, not event.Details.
	assert.Greater(t, testMon.GetCallCount(), 0, "Get must be called to read actual current state")

	// Set must have been called with the cfg desired state ("present"), not event.Details ("fabricated_evil_value").
	setConfigs := testMon.GetSetConfigs()
	require.NotEmpty(t, setConfigs)
	lastSet := setConfigs[len(setConfigs)-1]
	assert.Equal(t, "present", lastSet["state"],
		"Set must use cfg desired state, not forged event Details")
	assert.NotEqual(t, "fabricated_evil_value", lastSet["state"],
		"forged event Details must never reach Set")
}

// TestMonitorModeNeverSets verifies that with DriftModeMonitor, a ChangeEvent
// reconcile never calls Set() and emits "drift.detected.monitor".
func TestMonitorModeNeverSets(t *testing.T) {
	logger := logging.NewLogger("debug")
	dir := t.TempDir()
	cfgPath := writeSingleMonitorCfg(t, dir, "monitor-mode-steward")

	testMon := newTestMonitorModule(t)

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	steward.RegisterTestModule(s, "testmonitor", testMon)

	// Set monitor mode BEFORE start so both initial convergence and event-triggered
	// reconciles run in monitor mode.
	steward.SetDriftModeForTest(s, config.DriftModeMonitor)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, s.Start(ctx))

	// Capture drift events AFTER start to isolate event-triggered reconciles.
	// startStandalone sets its own handler; we replace it here to record EventType.
	mu := &sync.Mutex{}
	var capturedEventTypes []string
	steward.SetDriftEventHandlerForTest(s, func(_ string, _ string, diff *stewardtesting.StateDiff) {
		mu.Lock()
		capturedEventTypes = append(capturedEventTypes, diff.EventType)
		mu.Unlock()
	})

	// Initial convergence ran in monitor mode — Set must not have been called.
	assert.Equal(t, 0, testMon.SetCallCount(), "Set must not be called in monitor mode during initial convergence")

	initialGetCount := testMon.GetCallCount()

	// Send a ChangeEvent to trigger a targeted reconcile.
	testMon.SendChange(modules.ChangeEvent{
		ResourceID: "my-resource",
		ChangeType: modules.ChangeTypeModified,
	})

	// Wait for the drift event rather than just GetCallCount. The handler fires
	// after Get→CompareStates inside the same ExecuteResource call, so polling
	// GetCallCount alone is a race: the test goroutine can be scheduled between
	// Get returning and the handler being invoked, causing capturedEventTypes to
	// be empty when we read it. Waiting for the event itself eliminates the race.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, et := range capturedEventTypes {
			if et == "drift.detected.monitor" {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "drift.detected.monitor must be emitted after ChangeEvent")

	// Get must have been called — reconcile read actual current state.
	assert.Greater(t, testMon.GetCallCount(), initialGetCount,
		"Get must be called during targeted reconcile")

	// Set must never have been called — monitor mode skips Set/Verify.
	assert.Equal(t, 0, testMon.SetCallCount(), "Set must never be called in monitor mode")

	// "drift.detected.monitor" must have been emitted (confirmed above via Eventually).
	mu.Lock()
	types := make([]string, len(capturedEventTypes))
	copy(types, capturedEventTypes)
	mu.Unlock()
	assert.Contains(t, types, "drift.detected.monitor",
		"drift.detected.monitor must be emitted for monitor-mode reconciles")

	require.NoError(t, s.Stop(context.Background()))
}

// TestMonitorUnmanagedResource verifies that a ChangeEvent whose ResourceID is not
// present in cfg performs no Set — the reconcile is skipped entirely.
func TestMonitorUnmanagedResource(t *testing.T) {
	logger := logging.NewLogger("debug")
	dir := t.TempDir()
	cfgPath := writeSingleMonitorCfg(t, dir, "monitor-unmanaged-steward")

	testMon := newTestMonitorModule(t)

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	steward.RegisterTestModule(s, "testmonitor", testMon)

	ctx := context.Background()

	// Call runTargetedReconcile directly with a resourceID not in cfg.
	// This tests the function's early-exit path without the async event loop.
	steward.RunTargetedReconcile(s, ctx, "nonexistent-resource-not-in-cfg")

	// No module was called — "nonexistent-resource" is not in cfg.
	assert.Equal(t, 0, testMon.GetCallCount(), "Get must not be called for unmanaged resource")
	assert.Equal(t, 0, testMon.SetCallCount(), "Set must not be called for unmanaged resource")

	require.NoError(t, s.Stop(ctx))
}
