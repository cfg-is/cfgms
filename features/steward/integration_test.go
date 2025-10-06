package steward

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	
	"github.com/cfgis/cfgms/pkg/logging"
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