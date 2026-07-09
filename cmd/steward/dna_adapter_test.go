// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Issue #2435: dnaCollectorAdapter post-construction wiring and end-to-end test.
package main

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ─── real module DNA source fixture ──────────────────────────────────────────

// newModuleDNAExecutor builds a real *execution.Executor — the same CFGMS
// component that satisfies moduleDNASource in production — wired to a
// Monitor-capable test module. It applies a config, starts monitors, and drives
// a synthetic ChangeEvent through the module's Changes() channel so that
// CollectModuleDNAAttributes returns the flattened, namespaced module attribute
// set keyed under resourceID (e.g. "<resourceID>.state"). No mocks: the returned
// executor is the production producer, exercised end to end.
func newModuleDNAExecutor(t *testing.T, logger logging.Logger, resourceID string, details map[string]interface{}) *execution.Executor {
	t.Helper()

	errCfg := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}
	const moduleName = "e2emon"
	f := factory.New(discovery.ModuleRegistry{}, errCfg, logger)
	mod := newE2EMonitorModule()
	f.RegisterModule(moduleName, mod)

	e, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:        logger,
		Factory:       f,
		ErrorHandling: errCfg,
	})
	require.NoError(t, err)
	// Short debounce so the change is coalesced and applied promptly.
	e.SetMonitorDebounceWindow(20 * time.Millisecond)

	configYAML := []byte(fmt.Sprintf(`
steward:
  id: dna-test-steward
resources:
  - name: %s
    module: %s
    config:
      state: present
`, resourceID, moduleName))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, applyErr := e.ApplyConfiguration(ctx, configYAML, "v1")
	require.NoError(t, applyErr)

	resources := []stewardconfig.ResourceConfig{
		{Name: resourceID, Module: moduleName, Config: map[string]interface{}{"state": "present"}},
	}
	require.NoError(t, e.StartMonitors(ctx, resources))
	t.Cleanup(e.StopMonitors)

	mod.SendChange(modules.ChangeEvent{
		ResourceID: resourceID,
		ChangeType: modules.ChangeTypeModified,
		Details:    execution.NewConfigState(details),
	})

	require.Eventually(t, func() bool {
		return len(e.CollectModuleDNAAttributes(ctx)) > 0
	}, 2*time.Second, 10*time.Millisecond,
		"real module DNA source must publish attributes before use")

	return e
}

// ─── Issue #2435 AC7: adapter with setModuleDNASource post-construction ───────

// TestDNACollectorAdapter_SetModuleDNASource_PurityTest verifies that
// setModuleDNASource is thread-safe and that the swapped-in source is the one
// actually read by the adapter on the next CollectAttributes call — proving the
// modules field is live (read under the RWMutex) and not captured at construction.
// Every assertion goes through adapter.CollectAttributes, not the source directly.
func TestDNACollectorAdapter_SetModuleDNASource_PurityTest(t *testing.T) {
	logger := logging.NewLogger("debug")
	adapter := newDNACollectorAdapter(logger, nil)
	ctx := context.Background()

	// Real executor #1 produces "res-a.state=running".
	src := newModuleDNAExecutor(t, logger, "res-a", map[string]interface{}{"state": "running"})
	adapter.setModuleDNASource(src)

	// Concurrently call CollectAttributes to exercise the RWMutex around modules.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = adapter.CollectAttributes(ctx)
		}()
	}
	wg.Wait()

	// Through the adapter, the wired source's module attribute must be present.
	attrs1, err := adapter.CollectAttributes(ctx)
	require.NoError(t, err)
	assert.Equal(t, "running", attrs1["res-a.state"],
		"adapter.CollectAttributes must surface the wired source's module attribute")

	// Swap to a second real executor producing a disjoint key.
	src2 := newModuleDNAExecutor(t, logger, "res-b", map[string]interface{}{"state": "healthy"})
	adapter.setModuleDNASource(src2)

	// The adapter must now read from src2 — proving setModuleDNASource stored src2
	// under the RWMutex and CollectAttributes reads the live field.
	attrs2, err := adapter.CollectAttributes(ctx)
	require.NoError(t, err)
	assert.Equal(t, "healthy", attrs2["res-b.state"],
		"setModuleDNASource must swap the live source read by adapter.CollectAttributes")
	_, hadOld := attrs2["res-a.state"]
	assert.False(t, hadOld, "after the swap the adapter must not read the previous source")
}

// ─── AC7 parity test: pre-wired vs post-wired adapter return identical result ─

// TestDNACollectorAdapter_PreWiredVsPostWired is the REQUIRED TEST for Issue #2435
// AC7: an adapter with moduleDNASource set post-construction produces the same
// module attribute map as one wired at construction time.
func TestDNACollectorAdapter_PreWiredVsPostWired(t *testing.T) {
	logger := logging.NewLogger("debug")
	ctx := context.Background()

	// One real executor shared by both adapters, producing a namespaced module set.
	src := newModuleDNAExecutor(t, logger, "res-x", map[string]interface{}{
		"state":   "running",
		"version": "3.2.1",
	})

	// Pre-wired adapter (construction-time wiring, as standalone mode does).
	preWired := newDNACollectorAdapter(logger, src)

	// Post-wired adapter (construction with nil, then setter, as controller mode does).
	postWired := newDNACollectorAdapter(logger, nil)
	postWired.setModuleDNASource(src)

	// Invoke each adapter's CollectAttributes — the actual production path.
	preAttrs, err := preWired.CollectAttributes(ctx)
	require.NoError(t, err)
	postAttrs, err := postWired.CollectAttributes(ctx)
	require.NoError(t, err)

	// The module-namespaced subset must be identical regardless of when the source
	// was wired. Compare against the executor's own output to avoid asserting on
	// host-dependent hardware facts.
	wantModule := src.CollectModuleDNAAttributes(ctx)
	require.NotEmpty(t, wantModule, "executor must produce module attributes")
	for k, v := range wantModule {
		assert.Equal(t, v, preAttrs[k],
			"pre-wired adapter must surface module attribute %s via CollectAttributes", k)
		assert.Equal(t, v, postAttrs[k],
			"post-wired adapter must surface module attribute %s via CollectAttributes", k)
	}
}

// ─── Issue #2435 AC8: real end-to-end controller-mode monitor → DNA ───────────

// e2eMonitorModule is a real modules.Module + modules.Monitor for the end-to-end test.
type e2eMonitorModule struct {
	mu          sync.Mutex
	changesCh   chan modules.ChangeEvent
	setCalled   bool
	closeCalled bool
}

func newE2EMonitorModule() *e2eMonitorModule {
	return &e2eMonitorModule{changesCh: make(chan modules.ChangeEvent, 16)}
}

func (m *e2eMonitorModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	// Return matching state so reconcile does not call Set during initial convergence.
	return execution.NewConfigState(map[string]interface{}{"state": "present"}), nil
}

func (m *e2eMonitorModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	m.mu.Lock()
	m.setCalled = true
	m.mu.Unlock()
	return nil
}

func (m *e2eMonitorModule) Monitor(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil
}

func (m *e2eMonitorModule) Changes() <-chan modules.ChangeEvent { return m.changesCh }

func (m *e2eMonitorModule) Close() error {
	m.mu.Lock()
	m.closeCalled = true
	close(m.changesCh)
	m.mu.Unlock()
	return nil
}

func (m *e2eMonitorModule) SendChange(evt modules.ChangeEvent) { m.changesCh <- evt }

// TestDNACollectorAdapter_EndToEnd_ControllerMode is the REQUIRED TEST for
// Issue #2435 AC8: a Monitor-capable test module registered into the executor's
// factory, a config applied via ApplyConfiguration (simulating syncConfigNow),
// a synthetic ChangeEvent sent through the module's Changes() channel, and the
// wired dnaCollectorAdapter.CollectModuleDNAAttributes returns the flattened
// module attribute — proving the controller-mode producer is live end-to-end.
func TestDNACollectorAdapter_EndToEnd_ControllerMode(t *testing.T) {
	logger := logging.NewLogger("debug")

	// Build factory with the Monitor-capable module.
	errCfg := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}
	f := factory.New(discovery.ModuleRegistry{}, errCfg, logger)
	mod := newE2EMonitorModule()
	f.RegisterModule("e2emon", mod)

	// Create the executor (mimics InitializeConfigExecutor in controller mode).
	e, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:        logger,
		Factory:       f,
		ErrorHandling: errCfg,
	})
	require.NoError(t, err)
	// Short debounce so the test doesn't wait 1500ms.
	e.SetMonitorDebounceWindow(20 * time.Millisecond)

	// Build the DNA adapter with nil moduleDNASource (as main.go does pre-wiring).
	adapter := newDNACollectorAdapter(logger, nil)

	// Wire the executor as the module DNA source (as main.go does post-InitializeConfigExecutor).
	adapter.setModuleDNASource(e)

	// Apply a config that includes the monitored resource (mimics syncConfigNow →
	// ApplyConfiguration → StartMonitors).
	configYAML := []byte(`
steward:
  id: e2e-test-steward
resources:
  - name: test-resource
    module: e2emon
    config:
      state: present
`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, applyErr := e.ApplyConfiguration(ctx, configYAML, "v1")
	require.NoError(t, applyErr)

	// Start monitors (mimics the StartMonitors call in syncConfigNow after ApplyConfiguration).
	resources := []stewardconfig.ResourceConfig{
		{
			Name:   "test-resource",
			Module: "e2emon",
			Config: map[string]interface{}{"state": "present"},
		},
	}
	require.NoError(t, e.StartMonitors(ctx, resources))
	defer e.StopMonitors()

	// Send a synthetic ChangeEvent through the module's Changes() channel.
	mod.SendChange(modules.ChangeEvent{
		ResourceID: "test-resource",
		ChangeType: modules.ChangeTypeModified,
		Details: execution.NewConfigState(map[string]interface{}{
			"state":   "running",
			"version": "2.1.0",
		}),
	})

	// The wired adapter must return the flattened module attribute after the event
	// is processed — proving the controller-mode producer is live end-to-end.
	require.Eventually(t, func() bool {
		attrs := e.CollectModuleDNAAttributes(ctx)
		return attrs["test-resource.state"] == "running"
	}, 2*time.Second, 10*time.Millisecond,
		"controller-mode monitor producer must populate DNA attributes end-to-end")

	attrs := e.CollectModuleDNAAttributes(ctx)
	assert.Equal(t, "running", attrs["test-resource.state"])
	assert.Equal(t, "2.1.0", attrs["test-resource.version"])

	// Verify the adapter.CollectModuleDNAAttributes (the wired source path) also
	// returns the same data — proving the wired chain works correctly.
	moduleAttrs := adapter.modules.CollectModuleDNAAttributes(ctx)
	assert.Equal(t, "running", moduleAttrs["test-resource.state"],
		"adapter.modules.CollectModuleDNAAttributes must return the executor's module DNA")
}
