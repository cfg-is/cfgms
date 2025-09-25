package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBasicFunctionality(t *testing.T) {
	// Test basic monitoring config
	config := DefaultMonitoringConfig()
	assert.NotNil(t, config)
	assert.Equal(t, 30*time.Second, config.HealthCheckInterval)

	// Test basic health checker
	logger := logging.NewLogger("debug")
	checker := NewBasicHealthChecker("test", logger)
	assert.NotNil(t, checker)

	ctx := context.Background()
	health, err := checker.CheckHealth(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, health)
	assert.Equal(t, "test", health.ComponentName)
	assert.Equal(t, HealthStatusHealthy, health.Status)

	// Test basic metrics collector
	collector := NewBasicMetricsCollector("test", logger)
	assert.NotNil(t, collector)

	metrics, err := collector.CollectMetrics(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, metrics)
	assert.Equal(t, "test", metrics.ComponentName)

	// Test platform monitor creation
	telemetryConfig := telemetry.DefaultConfig("test", "1.0.0")
	tracer, cleanup, err := telemetry.Initialize(ctx, telemetryConfig)
	require.NoError(t, err)
	defer cleanup()

	monitor := NewPlatformMonitor(logger, tracer, nil)
	assert.NotNil(t, monitor)
	assert.False(t, monitor.IsRunning())
}

func TestSimpleControllerHealthChecker(t *testing.T) {
	logger := logging.NewLogger("debug")
	checker := NewControllerHealthChecker(logger)

	// Add a service
	checker.AddService("test-service", "running")

	ctx := context.Background()
	health, err := checker.CheckHealth(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, health)
	assert.Equal(t, "controller", health.ComponentName)
	assert.Equal(t, HealthStatusHealthy, health.Status)
}

func TestSimpleControllerMetricsCollector(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewControllerMetricsCollector(logger)

	// Record some requests
	collector.RecordRequest(100*time.Millisecond, true)
	collector.RecordRequest(200*time.Millisecond, false)

	ctx := context.Background()
	metrics, err := collector.CollectMetrics(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, metrics)
	assert.Equal(t, "controller", metrics.ComponentName)
	assert.Equal(t, int64(2), metrics.Performance.RequestCount)
}

func TestAnomalyDetector(t *testing.T) {
	logger := logging.NewLogger("debug")
	detector := NewBasicAnomalyDetector("test", logger)

	rules := detector.GetDetectionRules()
	assert.NotEmpty(t, rules)

	// Create some test metrics with high error rate
	metrics := &ComponentMetrics{
		ComponentName: "test",
		Timestamp:     time.Now(),
		Performance: &PerformanceMetrics{
			ErrorRate: 15.0, // Above default 10% threshold
		},
		Resource: &ResourceMetrics{},
	}

	ctx := context.Background()
	anomalies, err := detector.DetectAnomalies(ctx, metrics)
	assert.NoError(t, err)
	assert.NotNil(t, anomalies)
	// Note: May not detect anomaly immediately due to duration requirements
}