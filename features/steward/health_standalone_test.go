package steward

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// Test health monitoring functionality standalone
func TestHealthMonitorStandalone(t *testing.T) {
	logger := logging.NewLogger("debug")

	// Test health monitor creation
	monitor := NewHealthMonitor(logger)
	require.NotNil(t, monitor)

	// Test initial state
	assert.Equal(t, StatusHealthy, monitor.GetStatus())
	assert.False(t, monitor.IsRunning())

	// Test configuration error recording
	monitor.RecordConfigError()
	monitor.RecordConfigError()
	assert.Equal(t, StatusHealthy, monitor.GetStatus()) // Still healthy, below threshold

	// Cross threshold
	monitor.RecordConfigError()
	assert.Equal(t, StatusDegraded, monitor.GetStatus())

	// Test metrics retrieval
	metrics := monitor.GetMetrics()
	assert.Equal(t, 3, metrics.ConfigErrors)
	assert.Equal(t, StatusDegraded, metrics.Status)
	assert.False(t, metrics.ControllerConnected)
	assert.Equal(t, 0, metrics.HeartbeatErrors)

	// Test task latency recording
	monitor.RecordTaskLatency(50 * time.Millisecond)
	monitor.RecordTaskLatency(75 * time.Millisecond)

	metrics = monitor.GetMetrics()
	assert.Equal(t, 2, metrics.TaskCount)
	expectedLatency := float64(50+75) / 2 * float64(time.Millisecond)
	assert.InDelta(t, expectedLatency, float64(metrics.AverageTaskLatency), float64(time.Millisecond))

	// Test status reset
	monitor.ResetMetrics()
	metrics = monitor.GetMetrics()
	assert.Equal(t, StatusHealthy, metrics.Status)
	assert.Equal(t, 0, metrics.ConfigErrors)
	assert.Equal(t, 0, metrics.TaskCount)
}

func TestHealthMonitorControllerFeatures(t *testing.T) {
	logger := logging.NewLogger("debug")
	monitor := NewHealthMonitor(logger)

	// Test controller connectivity updates
	monitor.UpdateControllerConnectivity(true)
	metrics := monitor.GetMetrics()
	assert.True(t, metrics.ControllerConnected)
	assert.Equal(t, 0, metrics.HeartbeatErrors)

	// Test disconnection
	monitor.UpdateControllerConnectivity(false)
	metrics = monitor.GetMetrics()
	assert.False(t, metrics.ControllerConnected)
	assert.Equal(t, StatusDegraded, metrics.Status) // Should degrade on disconnect

	// Test heartbeat success
	monitor.RecordHeartbeatSuccess()
	metrics = monitor.GetMetrics()
	assert.True(t, metrics.ControllerConnected)
	assert.Equal(t, 0, metrics.HeartbeatErrors)
	assert.False(t, metrics.LastHeartbeat.IsZero())

	// Test heartbeat errors
	monitor.RecordHeartbeatError()
	monitor.RecordHeartbeatError()
	monitor.RecordHeartbeatError() // Should cross threshold

	metrics = monitor.GetMetrics()
	assert.Equal(t, 3, metrics.HeartbeatErrors)
	assert.False(t, metrics.ControllerConnected)
	assert.Equal(t, StatusDegraded, metrics.Status)
}
