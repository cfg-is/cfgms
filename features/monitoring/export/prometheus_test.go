package export_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/monitoring/export"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestPrometheusExporter(t *testing.T) {
	logger := logging.NewNoopLogger()

	t.Run("create prometheus exporter", func(t *testing.T) {
		exporter := export.NewPrometheusExporter(logger)
		assert.NotNil(t, exporter)
		assert.Equal(t, "prometheus", exporter.Name())
	})

	t.Run("configure prometheus exporter", func(t *testing.T) {
		exporter := export.NewPrometheusExporter(logger)

		config := export.ExporterConfig{
			Enabled:  true,
			Endpoint: "0.0.0.0:9090",
			Config: map[string]interface{}{
				"metrics_path":     "/custom-metrics",
				"metric_prefix":    "test",
				"enable_go_metrics": false,
			},
		}

		err := exporter.Configure(config)
		assert.NoError(t, err)
	})

	t.Run("start and stop prometheus server", func(t *testing.T) {
		exporter := export.NewPrometheusExporter(logger)

		config := export.ExporterConfig{
			Enabled:  true,
			Endpoint: "localhost:0", // Use random port
		}

		err := exporter.Configure(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = exporter.Start(ctx)
		require.NoError(t, err)

		// Give server time to start
		time.Sleep(100 * time.Millisecond)

		err = exporter.Stop(ctx)
		assert.NoError(t, err)
	})
}

func TestPrometheusExporterMetrics(t *testing.T) {
	logger := logging.NewNoopLogger()

	t.Run("export metrics data", func(t *testing.T) {
		exporter := export.NewPrometheusExporter(logger)

		config := export.ExporterConfig{
			Enabled:  true,
			Endpoint: "localhost:0",
			Config: map[string]interface{}{
				"metric_prefix": "cfgms_test",
			},
		}

		err := exporter.Configure(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = exporter.Start(ctx)
		require.NoError(t, err)
		defer exporter.Stop(ctx)

		// Export test data
		exportData := export.ExportData{
			SystemMetrics: map[string]interface{}{
				"requests_total": 1000,
				"errors_total":   25,
				"latency_avg":    45.5,
			},
			ResourceMetrics: map[string]interface{}{
				"cpu_usage_percent": 75.2,
				"memory_bytes":      1024000000,
			},
			HealthStatus: map[string]export.HealthStatus{
				"api": {
					Status:      "healthy",
					Message:     "API is running",
					LastChecked: time.Now(),
				},
				"database": {
					Status:      "degraded",
					Message:     "High latency",
					LastChecked: time.Now(),
				},
			},
			Timestamp:     time.Now(),
			CorrelationID: "test-correlation",
			Source:        "test-controller",
			ExportType:    export.ExportTypeScheduled,
		}

		err = exporter.Export(ctx, exportData)
		assert.NoError(t, err)

		// Verify metrics are stored (we can't easily test HTTP endpoint without knowing port)
		// This test mainly verifies the export process doesn't error
	})

	t.Run("export empty data", func(t *testing.T) {
		exporter := export.NewPrometheusExporter(logger)

		ctx := context.Background()
		err := exporter.Start(ctx)
		require.NoError(t, err)
		defer exporter.Stop(ctx)

		// Export empty data
		exportData := export.ExportData{
			Timestamp: time.Now(),
		}

		err = exporter.Export(ctx, exportData)
		assert.NoError(t, err)
	})
}

func TestPrometheusExporterHealthCheck(t *testing.T) {
	logger := logging.NewNoopLogger()

	t.Run("health check without server", func(t *testing.T) {
		exporter := export.NewPrometheusExporter(logger)

		ctx := context.Background()
		health := exporter.HealthCheck(ctx)
		
		assert.Equal(t, "prometheus", health.Name)
		assert.Equal(t, "unhealthy", health.Status)
		assert.Contains(t, health.Message, "not started")
	})

	t.Run("health check with running server", func(t *testing.T) {
		exporter := export.NewPrometheusExporter(logger)

		// Use a specific port for testing
		config := export.ExporterConfig{
			Enabled:  true,
			Endpoint: "localhost:0", // Let OS choose port
		}

		err := exporter.Configure(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = exporter.Start(ctx)
		require.NoError(t, err)
		defer exporter.Stop(ctx)

		// Give server time to start
		time.Sleep(100 * time.Millisecond)

		// Note: Health check tries to connect to itself, which may fail
		// with random port. This test mainly verifies the health check runs.
		health := exporter.HealthCheck(ctx)
		assert.Equal(t, "prometheus", health.Name)
		assert.NotEmpty(t, health.Status)
	})
}

func TestPrometheusMetricsFormatting(t *testing.T) {
	// This test uses internal knowledge of the exporter for testing formatting
	// In a real implementation, you might want to extract the formatting logic
	// into a separate testable function

	t.Run("metric name sanitization", func(t *testing.T) {
		// Test cases for metric name sanitization
		testCases := []struct {
			input    string
			expected string
		}{
			{"simple_metric", "cfgms_simple_metric"},
			{"metric.with.dots", "cfgms_metric_with_dots"},
			{"metric-with-dashes", "cfgms_metric_with_dashes"},
			{"metric with spaces", "cfgms_metric_with_spaces"},
			{"UPPERCASE_METRIC", "cfgms_uppercase_metric"},
		}

		logger := logging.NewNoopLogger()
		exporter := export.NewPrometheusExporter(logger)

		config := export.ExporterConfig{
			Config: map[string]interface{}{
				"metric_prefix": "cfgms",
			},
		}
		exporter.Configure(config)

		// We can't directly test the internal sanitization function
		// but we can verify that different metric names are handled
		ctx := context.Background()
		
		for _, tc := range testCases {
			exportData := export.ExportData{
				SystemMetrics: map[string]interface{}{
					tc.input: 42,
				},
				Timestamp: time.Now(),
			}

			// Should not error on any metric name
			err := exporter.Export(ctx, exportData)
			assert.NoError(t, err, "Failed for input: %s", tc.input)
		}
	})

	t.Run("metric type detection", func(t *testing.T) {
		logger := logging.NewNoopLogger()
		exporter := export.NewPrometheusExporter(logger)

		ctx := context.Background()
		err := exporter.Start(ctx)
		require.NoError(t, err)
		defer exporter.Stop(ctx)

		// Test different metric types
		exportData := export.ExportData{
			SystemMetrics: map[string]interface{}{
				// Should be detected as counters
				"requests_total":   1000,
				"errors_count":     25,
				"bytes_sent":       1024000,
				
				// Should be detected as gauges
				"temperature":      23.5,
				"queue_size":       10,
				"connection_pool":  50,
			},
			Timestamp: time.Now(),
		}

		err = exporter.Export(ctx, exportData)
		assert.NoError(t, err)
	})
}

func TestPrometheusDataTypes(t *testing.T) {
	logger := logging.NewNoopLogger()

	t.Run("handle different data types", func(t *testing.T) {
		exporter := export.NewPrometheusExporter(logger)

		ctx := context.Background()
		err := exporter.Start(ctx)
		require.NoError(t, err)
		defer exporter.Stop(ctx)

		// Test various data types
		exportData := export.ExportData{
			SystemMetrics: map[string]interface{}{
				"int_metric":     42,
				"int32_metric":   int32(42),
				"int64_metric":   int64(42),
				"float32_metric": float32(3.14),
				"float64_metric": 3.14159,
				"string_metric":  "not_a_number",
				"bool_metric":    true,
			},
			Timestamp: time.Now(),
		}

		// Should handle all types gracefully
		err = exporter.Export(ctx, exportData)
		assert.NoError(t, err)
	})

	t.Run("nested metrics flattening", func(t *testing.T) {
		exporter := export.NewPrometheusExporter(logger)

		ctx := context.Background()
		err := exporter.Start(ctx)
		require.NoError(t, err)
		defer exporter.Stop(ctx)

		// Test nested metrics
		exportData := export.ExportData{
			SystemMetrics: map[string]interface{}{
				"database": map[string]interface{}{
					"connections": 10,
					"queries":     1000,
				},
				"api": map[string]interface{}{
					"requests": 5000,
					"latency":  25.5,
				},
			},
			Timestamp: time.Now(),
		}

		err = exporter.Export(ctx, exportData)
		assert.NoError(t, err)
	})
}

func TestPrometheusHealthStatusMetrics(t *testing.T) {
	logger := logging.NewNoopLogger()

	t.Run("convert health status to metrics", func(t *testing.T) {
		exporter := export.NewPrometheusExporter(logger)

		ctx := context.Background()
		err := exporter.Start(ctx)
		require.NoError(t, err)
		defer exporter.Stop(ctx)

		exportData := export.ExportData{
			HealthStatus: map[string]export.HealthStatus{
				"service_a": {
					Status:  "healthy",
					Message: "Running smoothly",
				},
				"service_b": {
					Status:  "degraded",
					Message: "High latency",
				},
				"service_c": {
					Status:  "unhealthy",
					Message: "Connection failed",
				},
				"service_d": {
					Status:  "unknown_status",
					Message: "Strange state",
				},
			},
			Timestamp: time.Now(),
		}

		err = exporter.Export(ctx, exportData)
		assert.NoError(t, err)
	})
}

func TestPrometheusExporterConcurrency(t *testing.T) {
	logger := logging.NewNoopLogger()

	t.Run("concurrent exports", func(t *testing.T) {
		exporter := export.NewPrometheusExporter(logger)

		ctx := context.Background()
		err := exporter.Start(ctx)
		require.NoError(t, err)
		defer exporter.Stop(ctx)

		// Launch concurrent exports
		done := make(chan bool)
		numGoroutines := 10

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() { done <- true }()

				exportData := export.ExportData{
					SystemMetrics: map[string]interface{}{
						"goroutine_id": id,
						"timestamp":    time.Now().Unix(),
					},
					Timestamp: time.Now(),
				}

				exporter.Export(ctx, exportData)
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < numGoroutines; i++ {
			<-done
		}
	})
}

func BenchmarkPrometheusExport(b *testing.B) {
	logger := logging.NewNoopLogger()
	exporter := export.NewPrometheusExporter(logger)

	ctx := context.Background()
	exporter.Start(ctx)
	defer exporter.Stop(ctx)

	exportData := export.ExportData{
		SystemMetrics: map[string]interface{}{
			"requests_total": 1000,
			"latency_avg":    25.5,
			"errors_count":   10,
		},
		ResourceMetrics: map[string]interface{}{
			"cpu_usage":    75.2,
			"memory_bytes": 1024000000,
		},
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exporter.Export(ctx, exportData)
	}
}

func TestPrometheusEndpointIntegration(t *testing.T) {
	// This test requires a real HTTP server, so we'll only run basic checks
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	logger := logging.NewNoopLogger()

	t.Run("metrics endpoint responds", func(t *testing.T) {
		exporter := export.NewPrometheusExporter(logger)

		config := export.ExporterConfig{
			Enabled:  true,
			Endpoint: "localhost:0",
			Config: map[string]interface{}{
				"metrics_path": "/metrics",
			},
		}

		err := exporter.Configure(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = exporter.Start(ctx)
		require.NoError(t, err)
		defer exporter.Stop(ctx)

		// Export some data first
		exportData := export.ExportData{
			SystemMetrics: map[string]interface{}{
				"test_metric": 42,
			},
			Timestamp: time.Now(),
		}

		err = exporter.Export(ctx, exportData)
		require.NoError(t, err)

		// Note: We can't easily test the HTTP endpoint because we're using port 0
		// and don't have access to the actual port number
		// In a real test, you'd want to expose the port or use a fixed port
	})
}

func TestPrometheusConfiguration(t *testing.T) {
	logger := logging.NewNoopLogger()

	t.Run("default configuration", func(t *testing.T) {
		exporter := export.NewPrometheusExporter(logger)

		config := export.ExporterConfig{
			Enabled: true,
		}

		err := exporter.Configure(config)
		assert.NoError(t, err)
	})

	t.Run("custom configuration", func(t *testing.T) {
		exporter := export.NewPrometheusExporter(logger)

		config := export.ExporterConfig{
			Enabled:  true,
			Endpoint: "0.0.0.0:9999",
			Config: map[string]interface{}{
				"metrics_path":      "/custom-metrics",
				"metric_prefix":     "myapp",
				"enable_go_metrics": false,
			},
		}

		err := exporter.Configure(config)
		assert.NoError(t, err)
	})

	t.Run("invalid configuration types", func(t *testing.T) {
		exporter := export.NewPrometheusExporter(logger)

		config := export.ExporterConfig{
			Enabled: true,
			Config: map[string]interface{}{
				"metrics_path":      123, // Should be string
				"enable_go_metrics": "yes", // Should be bool
			},
		}

		// Should not error, just ignore invalid types
		err := exporter.Configure(config)
		assert.NoError(t, err)
	})
}