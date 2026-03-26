// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package steward

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testutil"
)

func TestStewardStandaloneMode(t *testing.T) {
	logger := logging.NewLogger("debug")

	// Test creating steward in standalone mode
	// Note: This will fail with config loading since we don't have a hostname.cfg,
	// but it tests the basic construction
	_, err := NewStandalone("", logger)

	// We expect this to fail since we don't have configuration files
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load configuration")
}

func TestStewardControllerMode(t *testing.T) {
	logger := logging.NewLogger("debug")

	// Test creating steward in controller mode
	// This should work since we provide default config
	cfg := DefaultConfig()
	cfg.ControllerAddr = "localhost:9999" // Non-existent controller
	cfg.CertPath = "/tmp/nonexistent"     // Non-existent certs

	// This should fail during client creation - Story #198: controller mode deprecated
	_, err := New(cfg, logger)

	// We expect this to fail since controller mode is deprecated
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "deprecated")
}

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

func TestDriftServiceInitializedInControllerTestingMode(t *testing.T) {
	logger := logging.NewLogger("debug")

	testConfig := testutil.DefaultStewardTestConfig()
	testConfig.StewardID = "test-steward-drift"
	certDir, dataDir, cleanup := testutil.SetupTestEnvironment(t, testConfig)
	t.Cleanup(cleanup)

	cfg := &Config{
		ControllerAddr: testConfig.ControllerAddr,
		CertPath:       certDir,
		DataDir:        dataDir,
		LogLevel:       testConfig.LogLevel,
		ID:             testConfig.StewardID,
	}

	steward, err := NewForControllerTesting(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, steward)

	// Drift service and performance collector must be initialized
	assert.NotNil(t, steward.driftService, "drift service must be initialized")
	assert.NotNil(t, steward.perfCollector, "performance collector must be initialized")
	assert.NotNil(t, steward.driftDNACollector, "drift DNA collector must be initialized")
}

func TestDriftAndPerformanceSubsystemsStartAndStop(t *testing.T) {
	logger := logging.NewLogger("debug")

	testConfig := testutil.DefaultStewardTestConfig()
	testConfig.StewardID = "test-steward-subsystems"
	certDir, dataDir, cleanup := testutil.SetupTestEnvironment(t, testConfig)
	t.Cleanup(cleanup)

	cfg := &Config{
		ControllerAddr: testConfig.ControllerAddr,
		CertPath:       certDir,
		DataDir:        dataDir,
		LogLevel:       testConfig.LogLevel,
		ID:             testConfig.StewardID,
	}

	steward, err := NewForControllerTesting(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, steward)

	// Start via the drift monitor loop directly (controller testing Start requires network)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Start performance collector directly to verify it works
	perfErr := steward.perfCollector.Start(ctx)
	require.NoError(t, perfErr, "performance collector must start without error")

	// Give it a moment to collect initial metrics
	time.Sleep(50 * time.Millisecond)

	// Current metrics should be available after starting
	metrics, err := steward.perfCollector.GetCurrentMetrics()
	require.NoError(t, err, "current metrics must be available after start")
	assert.NotNil(t, metrics, "metrics must not be nil")

	// Stop the performance collector
	stopErr := steward.perfCollector.Stop()
	require.NoError(t, stopErr, "performance collector must stop without error")
}

func TestDriftServiceDetectorAvailable(t *testing.T) {
	logger := logging.NewLogger("debug")

	testConfig := testutil.DefaultStewardTestConfig()
	testConfig.StewardID = "test-steward-detector"
	certDir, dataDir, cleanup := testutil.SetupTestEnvironment(t, testConfig)
	t.Cleanup(cleanup)

	cfg := &Config{
		ControllerAddr: testConfig.ControllerAddr,
		CertPath:       certDir,
		DataDir:        dataDir,
		LogLevel:       testConfig.LogLevel,
		ID:             testConfig.StewardID,
	}

	steward, err := NewForControllerTesting(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, steward)

	// The drift service must expose a working detector
	detector := steward.driftService.GetDetector()
	require.NotNil(t, detector, "drift detector must be available")

	// Closing the drift service must not error
	err = steward.driftService.Close()
	require.NoError(t, err, "drift service Close must succeed")
}
