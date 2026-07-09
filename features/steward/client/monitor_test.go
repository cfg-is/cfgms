// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Issue #2435: TransportClient wires and stops module Monitor engine.
package client

import (
	"context"
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

// ─── real Monitor-capable module for client tests ────────────────────────────

type clientMonitorTestModule struct {
	mu            sync.Mutex
	monitorCalled bool
	closeCalled   int
	changesCh     chan modules.ChangeEvent
	closed        bool
}

func newClientMonitorTestModule() *clientMonitorTestModule {
	return &clientMonitorTestModule{changesCh: make(chan modules.ChangeEvent, 16)}
}

func (m *clientMonitorTestModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	return execution.NewConfigState(map[string]interface{}{"state": "present"}), nil
}

func (m *clientMonitorTestModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil
}

func (m *clientMonitorTestModule) Monitor(_ context.Context, _ string, _ modules.ConfigState) error {
	m.mu.Lock()
	m.monitorCalled = true
	m.mu.Unlock()
	return nil
}

func (m *clientMonitorTestModule) Changes() <-chan modules.ChangeEvent { return m.changesCh }

func (m *clientMonitorTestModule) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalled++
	if !m.closed {
		m.closed = true
		close(m.changesCh)
	}
	return nil
}

func (m *clientMonitorTestModule) IsMonitorCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.monitorCalled
}

func (m *clientMonitorTestModule) CloseCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closeCalled
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// newExecutorWithModule creates an Executor with the given module pre-registered.
func newExecutorWithModule(t *testing.T, name string, mod modules.Module) *execution.Executor {
	t.Helper()
	logger := logging.NewLogger("debug")
	errCfg := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}
	f := factory.New(discovery.ModuleRegistry{}, errCfg, logger)
	f.RegisterModule(name, mod)
	e, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:        logger,
		Factory:       f,
		ErrorHandling: errCfg,
	})
	require.NoError(t, err)
	return e
}

// ─── Issue #2435 AC5: Disconnect stops monitor engine ─────────────────────────

// TestTransportClient_Disconnect_StopsMonitors is the REQUIRED TEST for Issue #2435
// AC5: no monitor goroutine survives disconnect. The test exercises the Executor's
// monitor engine directly (StartMonitors + StopMonitors path wired by Disconnect),
// since TransportClient.Disconnect calls configExecutor.StopMonitors().
//
// We test the executor-level guarantee here (the path that Disconnect exercises)
// rather than the full TransportClient (which requires a live controller connection).
func TestTransportClient_Disconnect_StopsMonitors(t *testing.T) {
	mod := newClientMonitorTestModule()
	e := newExecutorWithModule(t, "testmon", mod)
	e.SetMonitorDebounceWindow(20 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resources := []stewardconfig.ResourceConfig{
		{
			Name:   "res1",
			Module: "testmon",
			Config: map[string]interface{}{"state": "present"},
		},
	}
	require.NoError(t, e.StartMonitors(ctx, resources))
	assert.True(t, mod.IsMonitorCalled(), "Monitor() must be called after StartMonitors")
	assert.Equal(t, 0, mod.CloseCallCount(), "monitor must not be closed yet")

	// Simulate what TransportClient.Disconnect calls.
	e.StopMonitors()

	// After StopMonitors (which Disconnect invokes), Close must have been called
	// and the engine must have stopped — monitorWg.Wait() inside StopMonitors
	// guarantees no goroutine outlives the call.
	assert.Equal(t, 1, mod.CloseCallCount(), "Close must be called exactly once on Disconnect path")

	// CollectModuleDNAAttributes must return empty map after stop.
	assert.Empty(t, e.CollectModuleDNAAttributes(context.Background()),
		"no module DNA attributes must survive after StopMonitors")
}

// TestTransportClient_GetConfigExecutor_ReturnsExecutorAfterInitialize verifies
// that GetConfigExecutor returns the executor set by InitializeConfigExecutor.
// This is the accessor used by main.go to wire the DNA adapter (Issue #2435).
func TestTransportClient_GetConfigExecutor_ReturnsExecutorAfterInitialize(t *testing.T) {
	q, err := NewOfflineQueue(OfflineQueueConfig{Logger: logging.NewLogger("debug")})
	require.NoError(t, err)

	c := &TransportClient{
		stewardID:       "test-steward",
		tenantID:        "test-tenant",
		heartbeatStop:   make(chan struct{}),
		convergenceStop: make(chan struct{}),
		dnaRefreshStop:  make(chan struct{}),
		offlineQueue:    q,
		logger:          logging.NewLogger("debug"),
	}

	// Before initialization, GetConfigExecutor returns nil.
	assert.Nil(t, c.GetConfigExecutor(), "GetConfigExecutor must return nil before InitializeConfigExecutor")

	// Wire the executor directly (simulating what InitializeConfigExecutor does).
	e, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: c.logger})
	require.NoError(t, err)
	c.mu.Lock()
	c.configExecutor = e
	c.mu.Unlock()

	assert.Equal(t, e, c.GetConfigExecutor(), "GetConfigExecutor must return the wired executor")
}
