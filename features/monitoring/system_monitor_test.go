package monitoring_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/monitoring"
	"github.com/cfgis/cfgms/features/monitoring/export"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/telemetry"
)

// MockCollector implements MetricsCollector for testing
type MockCollector struct {
	name         string
	metrics      map[string]interface{}
	healthStatus monitoring.HealthStatus
	collectError error
	healthError  error
}

func (mc *MockCollector) CollectMetrics(ctx context.Context) (map[string]interface{}, error) {
	if mc.collectError != nil {
		return nil, mc.collectError
	}
	return mc.metrics, nil
}

func (mc *MockCollector) GetComponentName() string {
	return mc.name
}

func (mc *MockCollector) GetHealthStatus(ctx context.Context) (monitoring.HealthStatus, error) {
	if mc.healthError != nil {
		return monitoring.HealthStatus{}, mc.healthError
	}
	return mc.healthStatus, nil
}

// MockWatcher implements SystemEventWatcher for testing
type MockWatcher struct {
	name   string
	events []monitoring.SystemEvent
	mutex  sync.RWMutex
}

func (mw *MockWatcher) OnSystemEvent(event monitoring.SystemEvent) {
	mw.mutex.Lock()
	defer mw.mutex.Unlock()
	mw.events = append(mw.events, event)
}

func (mw *MockWatcher) GetWatcherName() string {
	return mw.name
}

func (mw *MockWatcher) GetEvents() []monitoring.SystemEvent {
	mw.mutex.RLock()
	defer mw.mutex.RUnlock()
	// Return a copy to avoid race conditions
	eventsCopy := make([]monitoring.SystemEvent, len(mw.events))
	copy(eventsCopy, mw.events)
	return eventsCopy
}

func TestSystemMonitorCreation(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-monitor",
		Enabled:     false,
	})
	require.NoError(t, err)
	defer cleanup()

	t.Run("create with default config", func(t *testing.T) {
		monitor := monitoring.NewSystemMonitor(logger, tracer, nil)
		assert.NotNil(t, monitor)
	})

	t.Run("create with custom config", func(t *testing.T) {
		config := &monitoring.MonitorConfig{
			MetricsInterval:          10 * time.Second,
			ResourceInterval:         5 * time.Second,
			HealthCheckInterval:      30 * time.Second,
			EnableResourceMonitoring: true,
			CPUAlertThreshold:        75.0,
			MemoryAlertThreshold:     80.0,
		}

		monitor := monitoring.NewSystemMonitor(logger, tracer, config)
		assert.NotNil(t, monitor)
	})

	t.Run("create with export config", func(t *testing.T) {
		exportConfig := &export.ExportConfig{
			Enabled:        true,
			ExportInterval: 30 * time.Second,
			Exporters: map[string]export.ExporterConfig{
				"prometheus": {
					Enabled:  true,
					Endpoint: "localhost:2112",
				},
			},
		}

		config := &monitoring.MonitorConfig{
			ExportConfig: exportConfig,
		}

		monitor := monitoring.NewSystemMonitor(logger, tracer, config)
		assert.NotNil(t, monitor)
	})
}

func TestSystemMonitorLifecycle(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-monitor",
		Enabled:     false,
	})
	require.NoError(t, err)
	defer cleanup()

	t.Run("start and stop", func(t *testing.T) {
		monitor := monitoring.NewSystemMonitor(logger, tracer, nil)
		ctx := context.Background()

		// Start monitor
		err := monitor.Start(ctx)
		assert.NoError(t, err)

		// Starting again should fail
		err = monitor.Start(ctx)
		assert.Error(t, err)

		// Stop monitor
		err = monitor.Stop(ctx)
		assert.NoError(t, err)

		// Stopping again should be no-op
		err = monitor.Stop(ctx)
		assert.NoError(t, err)
	})

	t.Run("stop with timeout", func(t *testing.T) {
		monitor := monitoring.NewSystemMonitor(logger, tracer, nil)
		ctx := context.Background()

		err := monitor.Start(ctx)
		require.NoError(t, err)

		// Stop with short timeout context
		stopCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()

		err = monitor.Stop(stopCtx)
		// Should complete within timeout
		assert.NoError(t, err)
	})
}

func TestSystemMonitorCollectors(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-monitor",
		Enabled:     false,
	})
	require.NoError(t, err)
	defer cleanup()

	t.Run("register and collect metrics", func(t *testing.T) {
		config := monitoring.DefaultMonitorConfig()
		config.MetricsInterval = 100 * time.Millisecond
		monitor := monitoring.NewSystemMonitor(logger, tracer, config)

		// Register mock collector
		collector := &MockCollector{
			name: "test-component",
			metrics: map[string]interface{}{
				"requests_total": 100,
				"errors_total":   5,
			},
			healthStatus: monitoring.HealthStatus{
				Status:  "healthy",
				Message: "All good",
			},
		}

		monitor.RegisterCollector("test", collector)

		// Start monitor
		ctx := context.Background()
		err := monitor.Start(ctx)
		require.NoError(t, err)
		defer func() {
			if err := monitor.Stop(ctx); err != nil {
				t.Logf("Failed to stop monitor: %v", err)
			}
		}()

		// Wait for metrics collection
		time.Sleep(150 * time.Millisecond)

		// Get system metrics
		metrics := monitor.GetMetrics()
		assert.NotNil(t, metrics)
		assert.Contains(t, metrics.ComponentMetrics, "test")
	})

	t.Run("collector error handling", func(t *testing.T) {
		monitor := monitoring.NewSystemMonitor(logger, tracer, nil)

		// Register collector that returns error
		collector := &MockCollector{
			name:         "error-component",
			collectError: assert.AnError,
		}

		monitor.RegisterCollector("error", collector)

		// Metrics collection should handle error gracefully
		metrics := monitor.GetMetrics()
		assert.NotNil(t, metrics)
	})
}

func TestSystemMonitorWatchers(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-monitor",
		Enabled:     false,
	})
	require.NoError(t, err)
	defer cleanup()

	t.Run("register watcher and emit events", func(t *testing.T) {
		monitor := monitoring.NewSystemMonitor(logger, tracer, nil)
		ctx := context.Background()

		// Register watcher for startup events BEFORE starting
		watcher := &MockWatcher{name: "test-watcher"}
		monitor.RegisterWatcher(string(monitoring.EventSystemStartup), watcher)

		// Start monitor (should emit startup event)
		err := monitor.Start(ctx)
		require.NoError(t, err)
		defer func() {
			if err := monitor.Stop(ctx); err != nil {
				t.Logf("Failed to stop monitor: %v", err)
			}
		}()

		// Give time for event processing
		time.Sleep(50 * time.Millisecond)

		// Should have received startup event
		assert.NotEmpty(t, watcher.GetEvents())
	})

	t.Run("register all events watcher", func(t *testing.T) {
		monitor := monitoring.NewSystemMonitor(logger, tracer, nil)

		// Register watcher for all events
		watcher := &MockWatcher{name: "all-watcher"}
		monitor.RegisterWatcher("all", watcher)

		// Start monitor (generates startup event)
		ctx := context.Background()
		err := monitor.Start(ctx)
		require.NoError(t, err)
		defer func() {
			if err := monitor.Stop(ctx); err != nil {
				t.Logf("Failed to stop monitor: %v", err)
			}
		}()

		// Give time for event processing
		time.Sleep(50 * time.Millisecond)

		// Should have received events
		events := watcher.GetEvents()
		assert.NotEmpty(t, events)

		// Check for startup event
		hasStartup := false
		for _, event := range events {
			if event.Type == monitoring.EventSystemStartup {
				hasStartup = true
				break
			}
		}
		assert.True(t, hasStartup, "Should have received startup event")
	})
}

func TestSystemMonitorHealth(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-monitor",
		Enabled:     false,
	})
	require.NoError(t, err)
	defer cleanup()

	t.Run("get system health", func(t *testing.T) {
		monitor := monitoring.NewSystemMonitor(logger, tracer, nil)

		// Register collectors with different health states
		healthyCollector := &MockCollector{
			name: "healthy-component",
			healthStatus: monitoring.HealthStatus{
				Status:      "healthy",
				Message:     "Running smoothly",
				LastChecked: time.Now(),
			},
		}

		degradedCollector := &MockCollector{
			name: "degraded-component",
			healthStatus: monitoring.HealthStatus{
				Status:      "degraded",
				Message:     "High memory usage",
				LastChecked: time.Now(),
			},
		}

		monitor.RegisterCollector("healthy", healthyCollector)
		monitor.RegisterCollector("degraded", degradedCollector)

		// Get system health
		health := monitor.GetSystemHealth()
		assert.NotNil(t, health)
		assert.Len(t, health, 3) // 2 collectors + system_monitor
		assert.Equal(t, "healthy", health["healthy"].Status)
		assert.Equal(t, "degraded", health["degraded"].Status)
		assert.Equal(t, "healthy", health["system_monitor"].Status)
	})

	t.Run("health check with errors", func(t *testing.T) {
		monitor := monitoring.NewSystemMonitor(logger, tracer, nil)

		// Register collector that returns health error
		errorCollector := &MockCollector{
			name:        "error-component",
			healthError: assert.AnError,
		}

		monitor.RegisterCollector("error", errorCollector)

		// Should handle error gracefully
		health := monitor.GetSystemHealth()
		assert.NotNil(t, health)
		assert.Len(t, health, 2) // 1 collector + system_monitor
		assert.Equal(t, "unhealthy", health["error"].Status)
	})
}

func TestSystemMonitorResourceMetrics(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-monitor",
		Enabled:     false,
	})
	require.NoError(t, err)
	defer cleanup()

	t.Run("collect resource metrics", func(t *testing.T) {
		config := &monitoring.MonitorConfig{
			EnableResourceMonitoring: true,
			ResourceInterval:         100 * time.Millisecond,
		}

		monitor := monitoring.NewSystemMonitor(logger, tracer, config)
		ctx := context.Background()

		// Start monitor
		err := monitor.Start(ctx)
		require.NoError(t, err)
		defer func() {
			if err := monitor.Stop(ctx); err != nil {
				t.Logf("Failed to stop monitor: %v", err)
			}
		}()

		// Wait for resource collection
		time.Sleep(150 * time.Millisecond)

		// Get resource metrics
		metrics := monitor.GetResourceMetrics()
		assert.NotNil(t, metrics)
		assert.Greater(t, metrics.CPUCores, 0)
		assert.Greater(t, metrics.MemoryTotalBytes, uint64(0))
		assert.Greater(t, metrics.Goroutines, 0)
	})

	t.Run("resource alerts", func(t *testing.T) {
		config := &monitoring.MonitorConfig{
			EnableResourceMonitoring: true,
			ResourceInterval:         100 * time.Millisecond,
			CPUAlertThreshold:        0.1, // Very low threshold to trigger
			GoroutineAlertThreshold:  1,   // Very low threshold to trigger
		}

		monitor := monitoring.NewSystemMonitor(logger, tracer, config)

		// Register event watcher
		watcher := &MockWatcher{name: "alert-watcher"}
		monitor.RegisterWatcher(string(monitoring.EventResourceAlert), watcher)

		ctx := context.Background()
		err := monitor.Start(ctx)
		require.NoError(t, err)
		defer func() {
			if err := monitor.Stop(ctx); err != nil {
				t.Logf("Failed to stop monitor: %v", err)
			}
		}()

		// Wait for resource collection and alerts
		time.Sleep(150 * time.Millisecond)

		// Should have received resource alerts
		events := watcher.GetEvents()
		hasAlert := false
		for _, event := range events {
			if event.Type == monitoring.EventResourceAlert {
				hasAlert = true
				break
			}
		}
		assert.True(t, hasAlert, "Should have received resource alert")
	})
}

func TestSystemMonitorIntegration(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-monitor",
		Enabled:     true,
	})
	require.NoError(t, err)
	defer cleanup()

	t.Run("full monitoring flow", func(t *testing.T) {
		config := &monitoring.MonitorConfig{
			MetricsInterval:          100 * time.Millisecond,
			ResourceInterval:         100 * time.Millisecond,
			HealthCheckInterval:      100 * time.Millisecond,
			EnableResourceMonitoring: true,
			EnableEventCorrelation:   true,
		}

		monitor := monitoring.NewSystemMonitor(logger, tracer, config)
		ctx := context.Background()

		// Register components
		collector := &MockCollector{
			name: "test-service",
			metrics: map[string]interface{}{
				"requests": 1000,
				"latency":  25.5,
			},
			healthStatus: monitoring.HealthStatus{
				Status:  "healthy",
				Message: "Service operational",
			},
		}
		monitor.RegisterCollector("service", collector)

		watcher := &MockWatcher{name: "integration-watcher"}
		monitor.RegisterWatcher("all", watcher)

		// Start monitoring
		err := monitor.Start(ctx)
		require.NoError(t, err)

		// Let it run for a bit
		time.Sleep(250 * time.Millisecond)

		// Stop monitoring
		err = monitor.Stop(ctx)
		require.NoError(t, err)

		// Verify metrics collected
		systemMetrics := monitor.GetMetrics()
		assert.NotNil(t, systemMetrics)
		assert.Contains(t, systemMetrics.ComponentMetrics, "service")

		// Verify events received
		events := watcher.GetEvents()
		assert.NotEmpty(t, events)

		// Should have startup and shutdown events
		hasStartup := false
		hasShutdown := false
		for _, event := range events {
			if event.Type == monitoring.EventSystemStartup {
				hasStartup = true
			}
			if event.Type == monitoring.EventSystemShutdown {
				hasShutdown = true
			}
		}
		assert.True(t, hasStartup, "Should have startup event")
		assert.True(t, hasShutdown, "Should have shutdown event")

		// Verify health status
		health := monitor.GetSystemHealth()
		assert.Contains(t, health, "service")
		assert.Equal(t, "healthy", health["service"].Status)
	})
}

func BenchmarkSystemMonitorMetricsCollection(b *testing.B) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, _ := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "bench-monitor",
		Enabled:     false,
	})
	defer cleanup()

	monitor := monitoring.NewSystemMonitor(logger, tracer, nil)

	// Register multiple collectors
	for i := 0; i < 10; i++ {
		collector := &MockCollector{
			name: fmt.Sprintf("collector-%d", i),
			metrics: map[string]interface{}{
				"counter": i * 100,
				"gauge":   float64(i) * 1.5,
			},
			healthStatus: monitoring.HealthStatus{
				Status: "healthy",
			},
		}
		monitor.RegisterCollector(fmt.Sprintf("coll%d", i), collector)
	}

	ctx := context.Background()
	if err := monitor.Start(ctx); err != nil {
		b.Fatalf("Failed to start monitor: %v", err)
	}
	defer func() {
		if err := monitor.Stop(ctx); err != nil {
			b.Logf("Failed to stop monitor: %v", err)
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = monitor.GetMetrics()
	}
}

func BenchmarkSystemMonitorEventEmission(b *testing.B) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, _ := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "bench-monitor",
		Enabled:     false,
	})
	defer cleanup()

	monitor := monitoring.NewSystemMonitor(logger, tracer, nil)

	// Register watchers
	for i := 0; i < 5; i++ {
		watcher := &MockWatcher{name: fmt.Sprintf("watcher-%d", i)}
		monitor.RegisterWatcher("all", watcher)
	}

	ctx := context.Background()
	if err := monitor.Start(ctx); err != nil {
		b.Fatalf("Failed to start monitor: %v", err)
	}
	defer func() {
		if err := monitor.Stop(ctx); err != nil {
			b.Logf("Failed to stop monitor: %v", err)
		}
	}()

	// Note: This is testing internal event emission which isn't directly exposed
	// In a real scenario, you'd test through public APIs
	b.ResetTimer()
}
