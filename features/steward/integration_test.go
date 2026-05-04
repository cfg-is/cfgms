// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package steward_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	steward "github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestHealthMonitorIntegration(t *testing.T) {
	logger := logging.NewLogger("debug")

	// Test health monitor directly
	monitor := steward.NewHealthMonitor(logger)
	require.NotNil(t, monitor)

	// Test initial state
	assert.Equal(t, steward.StatusHealthy, monitor.GetStatus())
	assert.False(t, monitor.IsRunning())

	// Test recording errors
	monitor.RecordConfigError()
	monitor.RecordConfigError()
	monitor.RecordConfigError()

	// Should be degraded after 3 errors (threshold)
	assert.Equal(t, steward.StatusDegraded, monitor.GetStatus())

	// Test metrics
	metrics := monitor.GetMetrics()
	assert.Equal(t, 3, metrics.ConfigErrors)
	assert.Equal(t, steward.StatusDegraded, metrics.Status)
}

func TestHealthMonitorControllerConnectivity(t *testing.T) {
	logger := logging.NewLogger("debug")

	monitor := steward.NewHealthMonitor(logger)

	// Test controller connectivity
	monitor.UpdateControllerConnectivity(true)
	metrics := monitor.GetMetrics()
	assert.True(t, metrics.ControllerConnected)

	// Test disconnection
	monitor.UpdateControllerConnectivity(false)
	metrics = monitor.GetMetrics()
	assert.False(t, metrics.ControllerConnected)
	assert.Equal(t, steward.StatusDegraded, metrics.Status)

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
// required subsystems via behavioral assertions on the public API.
func TestStandaloneSubsystemsInitialized(t *testing.T) {
	logger := logging.NewLogger("debug")
	dir := t.TempDir()
	cfgPath := writeMinimalCfg(t, dir, "subsystem-init-steward")

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	ctx := context.Background()

	// Prove executor is initialized — ExecuteConfiguration calls s.executor.ExecuteConfiguration()
	// directly (no nil guard); a nil executor would panic here.
	_, execErr := s.ExecuteConfiguration(ctx)
	assert.NoError(t, execErr, "executor must be initialized and functional")

	// Prove dnaCollector is initialized — RunConvergence stores a DNA snapshot only when
	// dnaCollector is non-nil; a nil collector causes detectUnmanagedDNADrift to return early.
	steward.RunConvergence(s, ctx)
	prevDNA := steward.GetPreviousDNA(s)
	assert.NotNil(t, prevDNA, "dnaCollector must be initialized (DNA snapshot was captured)")

	// Prove healthCheck is initialized — Stop() calls s.healthCheck.Stop() unconditionally
	// (no nil guard); a nil healthCheck would panic here.
	require.NoError(t, s.Stop(ctx))
}
