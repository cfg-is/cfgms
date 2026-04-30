// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package steward

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

func TestHealthMonitorIntegration(t *testing.T) {
	logger := logging.NewLogger("debug")

	// Test health monitor directly
	monitor := NewHealthMonitor(logger)
	require.NotNil(t, monitor)

	// Test initial state
	assert.Equal(t, StatusHealthy, monitor.GetStatus())
	assert.False(t, monitor.IsRunning())

	// Test recording errors
	monitor.RecordConfigError()
	monitor.RecordConfigError()
	monitor.RecordConfigError()

	// Should be degraded after 3 errors (threshold)
	assert.Equal(t, StatusDegraded, monitor.GetStatus())

	// Test metrics
	metrics := monitor.GetMetrics()
	assert.Equal(t, 3, metrics.ConfigErrors)
	assert.Equal(t, StatusDegraded, metrics.Status)
}

func TestHealthMonitorControllerConnectivity(t *testing.T) {
	logger := logging.NewLogger("debug")

	monitor := NewHealthMonitor(logger)

	// Test controller connectivity
	monitor.UpdateControllerConnectivity(true)
	metrics := monitor.GetMetrics()
	assert.True(t, metrics.ControllerConnected)

	// Test disconnection
	monitor.UpdateControllerConnectivity(false)
	metrics = monitor.GetMetrics()
	assert.False(t, metrics.ControllerConnected)
	assert.Equal(t, StatusDegraded, metrics.Status)

	// Test heartbeat errors
	monitor.RecordHeartbeatError()
	monitor.RecordHeartbeatError()
	monitor.RecordHeartbeatError()

	metrics = monitor.GetMetrics()
	assert.Equal(t, 3, metrics.HeartbeatErrors)
	assert.False(t, metrics.ControllerConnected)

	// Test successful heartbeat
	monitor.RecordHeartbeatSuccess()
	metrics = monitor.GetMetrics()
	assert.Equal(t, 0, metrics.HeartbeatErrors)
	assert.True(t, metrics.ControllerConnected)
}

// TestStandaloneSubsystemsInitialized verifies that NewStandalone initializes all
// required subsystems. DNA/drift detection subsystem tests live in dna_drift_test.go.
func TestStandaloneSubsystemsInitialized(t *testing.T) {
	logger := logging.NewLogger("debug")
	dir := t.TempDir()
	cfgPath := writeMinimalCfg(t, dir, "subsystem-init-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	assert.NotNil(t, s.executor, "executor must be initialized")
	assert.NotNil(t, s.moduleFactory, "module factory must be initialized")
	assert.NotNil(t, s.healthCheck, "health check must be initialized")
	assert.NotNil(t, s.dnaCollector, "DNA collector must be initialized")
}
