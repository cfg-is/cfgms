// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package steward_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	steward "github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ─── Issue #2423: module Monitor ChangeEvent state as namespaced DNA attributes ─
//
// The latest ChangeEvent.Details per monitored resourceID is cached by the
// monitor fan-in and exposed as a flattened, namespaced map[string]string via
// Steward.CollectModuleDNAAttributes — fed into the existing DNA publish
// channel by the composite collector adapter (cmd/steward/main.go).

// dnaMonitorModule is a minimal real modules.Module + modules.Monitor whose
// Changes channel the test can close, to drive the eviction path. Get returns
// a state matching the desired cfg so no reconcile churn occurs.
type dnaMonitorModule struct {
	mu        sync.Mutex
	changesCh chan modules.ChangeEvent
	closed    bool
}

func newDNAMonitorModule() *dnaMonitorModule {
	return &dnaMonitorModule{changesCh: make(chan modules.ChangeEvent, 16)}
}

func (m *dnaMonitorModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	return execution.NewConfigState(map[string]interface{}{"state": "present"}), nil
}

func (m *dnaMonitorModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil
}

func (m *dnaMonitorModule) Monitor(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil
}

func (m *dnaMonitorModule) Changes() <-chan modules.ChangeEvent { return m.changesCh }

func (m *dnaMonitorModule) Close() error { return nil }

func (m *dnaMonitorModule) SendChange(evt modules.ChangeEvent) { m.changesCh <- evt }

// CloseChanges closes the Changes channel — the module's "Monitor stopped"
// signal, which must evict the resource's cached attributes.
func (m *dnaMonitorModule) CloseChanges() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.changesCh)
	}
}

// startMonitoredSteward builds a standalone Steward with one monitored
// resource backed by dnaMonitorModule, starts it, and registers cleanup.
func startMonitoredSteward(t *testing.T) (*steward.Steward, *dnaMonitorModule) {
	t.Helper()
	logger := logging.NewLogger("debug")
	dir := t.TempDir()
	cfgPath := writeSingleMonitorCfg(t, dir, "dna-attr-steward")

	mon := newDNAMonitorModule()
	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	steward.RegisterTestModule(s, "testmonitor", mon)
	// DNA hardware collection is irrelevant here and slow on some platforms.
	steward.SetDNACollector(s, nil)

	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, s.Start(ctx))
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		_ = s.Stop(stopCtx)
		cancel()
	})
	return s, mon
}

// TestSteward_CollectModuleDNAAttributes_FlattensChangeEvent is the REQUIRED
// TEST for #2423 AC3: a synthetic ChangeEvent whose ConfigState.AsMap() has a
// nested map AND a slice value flattens per the documented convention (nested
// keys joined with ".", slice values joined with ","), namespaced as
// <resourceID>.<field> with the resourceID VERBATIM (colon intact, no
// module-name prefix).
func TestSteward_CollectModuleDNAAttributes_FlattensChangeEvent(t *testing.T) {
	s, mon := startMonitoredSteward(t)

	mon.SendChange(modules.ChangeEvent{
		ResourceID: "cluster:cfg-lab",
		ChangeType: modules.ChangeTypeModified,
		Details: execution.NewConfigState(map[string]interface{}{
			"member_nodes":   []string{"CFG-70-02", "CFG-AB-02", "CFG-C3-02"},
			"resource_owner": map[string]string{"web-01": "CFG-70-02"},
			"cno_owner_node": "CFG-70-02",
			"quorum":         true,
			"node_count":     3,
			"nested": map[string]interface{}{
				"inner": map[string]interface{}{"leaf": "v"},
			},
		}),
	})

	// Wait for the specific change-event key, not merely len>0: the steward's
	// convergence loop now also seeds steady-state module DNA for managed
	// resources (#2520), so the map is non-empty before this ChangeEvent lands.
	var attrs map[string]string
	require.Eventually(t, func() bool {
		attrs = s.CollectModuleDNAAttributes(context.Background())
		return attrs["cluster:cfg-lab.member_nodes"] != ""
	}, 2*time.Second, 10*time.Millisecond, "cached module attributes must appear after the ChangeEvent")

	assert.Equal(t, "CFG-70-02,CFG-AB-02,CFG-C3-02", attrs["cluster:cfg-lab.member_nodes"],
		"slice values join with ','")
	assert.Equal(t, "CFG-70-02", attrs["cluster:cfg-lab.resource_owner.web-01"],
		"nested map keys join with '.'")
	assert.Equal(t, "CFG-70-02", attrs["cluster:cfg-lab.cno_owner_node"])
	assert.Equal(t, "true", attrs["cluster:cfg-lab.quorum"], "bools stringify")
	assert.Equal(t, "3", attrs["cluster:cfg-lab.node_count"], "ints stringify")
	assert.Equal(t, "v", attrs["cluster:cfg-lab.nested.inner.leaf"],
		"deeply nested maps flatten recursively")

	// The namespace is the resourceID verbatim — no module-name prefix, no
	// colon-to-dot conversion.
	for k := range attrs {
		assert.NotContains(t, k, "hyperv.", "no module-name prefix may be invented")
	}
}

// TestSteward_CollectModuleDNAAttributes_LastWriteWins: the cache holds only
// the latest ChangeEvent per resourceID — a second event replaces the first
// snapshot wholesale (a key absent from the newer Details disappears).
func TestSteward_CollectModuleDNAAttributes_LastWriteWins(t *testing.T) {
	s, mon := startMonitoredSteward(t)

	mon.SendChange(modules.ChangeEvent{
		ResourceID: "cluster:cfg-lab",
		ChangeType: modules.ChangeTypeModified,
		Details: execution.NewConfigState(map[string]interface{}{
			"cno_owner_node": "CFG-70-02",
			"transient":      "only-in-first-event",
		}),
	})
	require.Eventually(t, func() bool {
		return s.CollectModuleDNAAttributes(context.Background())["cluster:cfg-lab.cno_owner_node"] == "CFG-70-02"
	}, 2*time.Second, 10*time.Millisecond)

	mon.SendChange(modules.ChangeEvent{
		ResourceID: "cluster:cfg-lab",
		ChangeType: modules.ChangeTypeModified,
		Details: execution.NewConfigState(map[string]interface{}{
			"cno_owner_node": "CFG-AB-02",
		}),
	})
	require.Eventually(t, func() bool {
		return s.CollectModuleDNAAttributes(context.Background())["cluster:cfg-lab.cno_owner_node"] == "CFG-AB-02"
	}, 2*time.Second, 10*time.Millisecond, "newer event must replace the cached snapshot")

	_, transientPresent := s.CollectModuleDNAAttributes(context.Background())["cluster:cfg-lab.transient"]
	assert.False(t, transientPresent,
		"a key absent from the latest event must not linger from an older snapshot")
}

// TestSteward_CollectModuleDNAAttributes_EvictsOnMonitorStop is the REQUIRED
// TEST for #2423 AC5, updated for the #2520 steady-state model: a resource seen
// ONLY via the monitor change-event stream (never converged as a managed config
// resource) is evicted when its Monitor stops — its change-event keys stop
// appearing in subsequent CollectModuleDNAAttributes calls, which is what makes
// the key disappear from the next PublishDNAUpdate delta.
//
// Note the contract change: a MANAGED resource's steady-state DNA (sourced from
// the convergence Get, #2520) is NOT evicted on monitor stop — a config re-push
// stops+restarts monitors transiently and blanking DNA each time was the churn
// #2520 fixed. Managed-resource eviction is on config-removal (ExecuteConfiguration
// prune), covered by TestExecuteConfiguration_PrunesRemovedResourceFromDNA. Here
// "cluster:cfg-lab" is a monitor-only resource (no matching config resource), so
// its keys DO evict on monitor stop.
func TestSteward_CollectModuleDNAAttributes_EvictsOnMonitorStop(t *testing.T) {
	s, mon := startMonitoredSteward(t)

	mon.SendChange(modules.ChangeEvent{
		ResourceID: "cluster:cfg-lab",
		ChangeType: modules.ChangeTypeModified,
		Details: execution.NewConfigState(map[string]interface{}{
			"cno_owner_node": "CFG-70-02",
		}),
	})
	require.Eventually(t, func() bool {
		return s.CollectModuleDNAAttributes(context.Background())["cluster:cfg-lab.cno_owner_node"] != ""
	}, 2*time.Second, 10*time.Millisecond, "monitor-only attribute must be cached before the eviction check")

	mon.CloseChanges()

	// The monitor-only resource's change-event keys must disappear. The steady-
	// state DNA of the managed config resource may remain — eviction of managed
	// resources is on config-removal, not monitor stop.
	require.Eventually(t, func() bool {
		_, present := s.CollectModuleDNAAttributes(context.Background())["cluster:cfg-lab.cno_owner_node"]
		return !present
	}, 2*time.Second, 10*time.Millisecond,
		"a stopped monitor-only resource must be evicted from the change-event cache")
}

// TestSteward_CollectModuleDNAAttributes_NilDetailsSafe: an event with nil
// Details must not panic and must not cache anything for the resource.
func TestSteward_CollectModuleDNAAttributes_NilDetailsSafe(t *testing.T) {
	s, mon := startMonitoredSteward(t)

	mon.SendChange(modules.ChangeEvent{
		ResourceID: "cluster:cfg-lab",
		ChangeType: modules.ChangeTypeModified,
		Details:    nil,
	})
	// Follow with a valid event on another resource so we have a positive
	// signal that the loop processed past the nil-Details event.
	mon.SendChange(modules.ChangeEvent{
		ResourceID: "vm:web-01",
		ChangeType: modules.ChangeTypeModified,
		Details:    execution.NewConfigState(map[string]interface{}{"state": "running"}),
	})

	require.Eventually(t, func() bool {
		return s.CollectModuleDNAAttributes(context.Background())["vm:web-01.state"] == "running"
	}, 2*time.Second, 10*time.Millisecond)

	attrs := s.CollectModuleDNAAttributes(context.Background())
	for k := range attrs {
		assert.NotContains(t, k, "cluster:cfg-lab", "nil Details must cache nothing")
	}
}
