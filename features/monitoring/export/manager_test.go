package export_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/monitoring/export"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/telemetry"
)

// MockExporter implements MonitoringExporter for testing
type MockExporter struct {
	name            string
	config          export.ExporterConfig
	exportedData    []export.ExportData
	exportErrors    []error
	healthStatus    export.ExporterHealth
	isStarted       bool
	mu              sync.RWMutex
}

func NewMockExporter(name string) *MockExporter {
	return &MockExporter{
		name: name,
		healthStatus: export.ExporterHealth{
			Name:   name,
			Status: "healthy",
		},
	}
}

func (me *MockExporter) Name() string {
	return me.name
}

func (me *MockExporter) Export(ctx context.Context, data export.ExportData) error {
	me.mu.Lock()
	defer me.mu.Unlock()
	
	// Check for errors first, only add data if no error
	if len(me.exportErrors) > 0 {
		err := me.exportErrors[0]
		me.exportErrors = me.exportErrors[1:]
		return err
	}
	
	// Only add data if export succeeds
	me.exportedData = append(me.exportedData, data)
	return nil
}

func (me *MockExporter) Configure(config export.ExporterConfig) error {
	me.mu.Lock()
	defer me.mu.Unlock()
	me.config = config
	return nil
}

func (me *MockExporter) HealthCheck(ctx context.Context) export.ExporterHealth {
	me.mu.RLock()
	defer me.mu.RUnlock()
	return me.healthStatus
}

func (me *MockExporter) Start(ctx context.Context) error {
	me.mu.Lock()
	defer me.mu.Unlock()
	me.isStarted = true
	return nil
}

func (me *MockExporter) Stop(ctx context.Context) error {
	me.mu.Lock()
	defer me.mu.Unlock()
	me.isStarted = false
	return nil
}

func (me *MockExporter) GetExportedData() []export.ExportData {
	me.mu.RLock()
	defer me.mu.RUnlock()
	return append([]export.ExportData{}, me.exportedData...)
}

func (me *MockExporter) SetExportError(err error) {
	me.mu.Lock()
	defer me.mu.Unlock()
	me.exportErrors = append(me.exportErrors, err)
}

func (me *MockExporter) SetHealthStatus(status export.ExporterHealth) {
	me.mu.Lock()
	defer me.mu.Unlock()
	me.healthStatus = status
}

func (me *MockExporter) IsStarted() bool {
	me.mu.RLock()
	defer me.mu.RUnlock()
	return me.isStarted
}

func TestExportManagerCreation(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-export",
		Enabled:     false,
	})
	require.NoError(t, err)
	defer cleanup()

	t.Run("create with default config", func(t *testing.T) {
		manager := export.NewExportManager(logger, tracer, nil)
		assert.NotNil(t, manager)
	})

	t.Run("create with custom config", func(t *testing.T) {
		config := &export.ExportConfig{
			Enabled:        true,
			ExportInterval: 10 * time.Second,
			BufferSize:     500,
			MaxRetries:     5,
		}

		manager := export.NewExportManager(logger, tracer, config)
		assert.NotNil(t, manager)
	})
}

func TestExportManagerLifecycle(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-export",
		Enabled:     false,
	})
	require.NoError(t, err)
	defer cleanup()

	t.Run("start and stop", func(t *testing.T) {
		config := &export.ExportConfig{
			Enabled: true,
		}
		
		manager := export.NewExportManager(logger, tracer, config)
		ctx := context.Background()

		// Start manager
		err := manager.Start(ctx)
		assert.NoError(t, err)

		// Starting again should fail
		err = manager.Start(ctx)
		assert.Error(t, err)

		// Stop manager
		err = manager.Stop(ctx)
		assert.NoError(t, err)

		// Stopping again should be no-op
		err = manager.Stop(ctx)
		assert.NoError(t, err)
	})

	t.Run("start disabled manager", func(t *testing.T) {
		config := &export.ExportConfig{
			Enabled: false,
		}
		
		manager := export.NewExportManager(logger, tracer, config)
		ctx := context.Background()

		// Should succeed but do nothing
		err := manager.Start(ctx)
		assert.NoError(t, err)

		err = manager.Stop(ctx)
		assert.NoError(t, err)
	})
}

func TestExportManagerExporters(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-export",
		Enabled:     false,
	})
	require.NoError(t, err)
	defer cleanup()

	t.Run("register and configure exporters", func(t *testing.T) {
		config := &export.ExportConfig{
			Enabled: true,
			Exporters: map[string]export.ExporterConfig{
				"test-exporter": {
					Enabled:  true,
					Endpoint: "localhost:8080",
				},
			},
		}

		manager := export.NewExportManager(logger, tracer, config)
		mockExporter := NewMockExporter("test-exporter")

		err := manager.RegisterExporter("test-exporter", mockExporter)
		assert.NoError(t, err)

		// Exporter should be configured
		assert.Equal(t, "localhost:8080", mockExporter.config.Endpoint)
	})

	t.Run("register duplicate exporter", func(t *testing.T) {
		manager := export.NewExportManager(logger, tracer, nil)
		mockExporter1 := NewMockExporter("test")
		mockExporter2 := NewMockExporter("test")

		err := manager.RegisterExporter("test", mockExporter1)
		assert.NoError(t, err)

		err = manager.RegisterExporter("test", mockExporter2)
		assert.Error(t, err)
	})
}

func TestExportManagerDataExport(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-export",
		Enabled:     false,
	})
	require.NoError(t, err)
	defer cleanup()

	t.Run("export data to multiple exporters", func(t *testing.T) {
		config := &export.ExportConfig{
			Enabled:      true,
			BufferSize:   10,
			SamplingRate: 1.0, // Export everything
			Exporters: map[string]export.ExporterConfig{
				"exporter1": {Enabled: true},
				"exporter2": {Enabled: true},
			},
		}

		manager := export.NewExportManager(logger, tracer, config)
		
		exporter1 := NewMockExporter("exporter1")
		exporter2 := NewMockExporter("exporter2")
		
		err := manager.RegisterExporter("exporter1", exporter1)
		require.NoError(t, err)
		err = manager.RegisterExporter("exporter2", exporter2)
		require.NoError(t, err)

		ctx := context.Background()
		err = manager.Start(ctx)
		require.NoError(t, err)
		defer manager.Stop(ctx)
		
		// Verify exporters are started
		require.True(t, exporter1.IsStarted())
		require.True(t, exporter2.IsStarted())

		// Export test data
		exportData := export.ExportData{
			SystemMetrics: map[string]interface{}{
				"requests": 100,
				"errors":   5,
			},
			Timestamp:  time.Now(),
			Source:     "test",
			ExportType: export.ExportTypeManual,
		}

		err = manager.Export(exportData)
		assert.NoError(t, err)

		// Both exporters should have received data (synchronous for manual exports)
		data1 := exporter1.GetExportedData()
		data2 := exporter2.GetExportedData()
		
		assert.Len(t, data1, 1)
		assert.Len(t, data2, 1)
		assert.Equal(t, 100, data1[0].SystemMetrics["requests"])
		assert.Equal(t, 100, data2[0].SystemMetrics["requests"])
	})

	t.Run("export with sampling", func(t *testing.T) {
		config := &export.ExportConfig{
			Enabled:      true,
			SamplingRate: 0.0, // Never export (0% sampling)
			Exporters: map[string]export.ExporterConfig{
				"test": {Enabled: true},
			},
		}

		manager := export.NewExportManager(logger, tracer, config)
		exporter := NewMockExporter("test")
		manager.RegisterExporter("test", exporter)

		ctx := context.Background()
		manager.Start(ctx)
		defer manager.Stop(ctx)

		// Export data that should be sampled out
		exportData := export.ExportData{
			SystemMetrics: map[string]interface{}{"test": 1},
			Timestamp:     time.Now(),
			ExportType:    export.ExportTypeManual, // For synchronous testing
		}

		err := manager.Export(exportData)
		assert.NoError(t, err)

		time.Sleep(50 * time.Millisecond)

		// Should not have received data due to sampling
		data := exporter.GetExportedData()
		assert.Empty(t, data)
	})

	t.Run("export with buffer overflow", func(t *testing.T) {
		config := &export.ExportConfig{
			Enabled:    true,
			BufferSize: 1, // Very small buffer
			Exporters: map[string]export.ExporterConfig{
				"test": {Enabled: true},
			},
		}

		manager := export.NewExportManager(logger, tracer, config)
		exporter := NewMockExporter("test")
		manager.RegisterExporter("test", exporter)

		ctx := context.Background()
		manager.Start(ctx)
		defer manager.Stop(ctx)

		// Fill buffer beyond capacity
		for i := 0; i < 5; i++ {
			exportData := export.ExportData{
				SystemMetrics: map[string]interface{}{"test": i},
				Timestamp:     time.Now(),
			}
			manager.Export(exportData) // Some may fail due to buffer overflow
		}
	})
}

func TestExportManagerErrorHandling(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-export",
		Enabled:     false,
	})
	require.NoError(t, err)
	defer cleanup()

	t.Run("handle export errors with retry", func(t *testing.T) {
		config := &export.ExportConfig{
			Enabled:      true,
			MaxRetries:   2,
			RetryBackoff: 10 * time.Millisecond,
			SamplingRate: 1.0, // Export everything
			BufferSize:   10,   // Adequate buffer size
			Exporters: map[string]export.ExporterConfig{
				"error-exporter": {Enabled: true},
			},
		}

		manager := export.NewExportManager(logger, tracer, config)
		exporter := NewMockExporter("error-exporter")
		
		// Set up exporter to fail once, then succeed
		exporter.SetExportError(assert.AnError)
		
		manager.RegisterExporter("error-exporter", exporter)

		ctx := context.Background()
		manager.Start(ctx)
		defer manager.Stop(ctx)

		// Export data
		exportData := export.ExportData{
			SystemMetrics: map[string]interface{}{"test": 1},
			Timestamp:     time.Now(),
		}

		err := manager.Export(exportData)
		assert.NoError(t, err)

		// Give time for retry processing (initial attempt + up to 2 retries with 10ms backoff each)
		time.Sleep(200 * time.Millisecond)

		// Should eventually succeed on retry
		data := exporter.GetExportedData()
		assert.Len(t, data, 1)
	})
}

func TestExportManagerHealthChecks(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-export",
		Enabled:     false,
	})
	require.NoError(t, err)
	defer cleanup()

	t.Run("get exporter health", func(t *testing.T) {
		config := &export.ExportConfig{
			Enabled:             true,
			HealthCheckInterval: 50 * time.Millisecond,
			Exporters: map[string]export.ExporterConfig{
				"healthy": {Enabled: true},
				"unhealthy": {Enabled: true},
			},
		}

		manager := export.NewExportManager(logger, tracer, config)
		
		healthyExporter := NewMockExporter("healthy")
		unhealthyExporter := NewMockExporter("unhealthy")
		unhealthyExporter.SetHealthStatus(export.ExporterHealth{
			Name:   "unhealthy",
			Status: "unhealthy",
			Message: "Connection failed",
		})

		manager.RegisterExporter("healthy", healthyExporter)
		manager.RegisterExporter("unhealthy", unhealthyExporter)

		ctx := context.Background()
		manager.Start(ctx)
		defer manager.Stop(ctx)

		// Wait for health checks
		time.Sleep(100 * time.Millisecond)

		health := manager.GetExporterHealth()
		assert.Len(t, health, 2)
		assert.Equal(t, "healthy", health["healthy"].Status)
		assert.Equal(t, "unhealthy", health["unhealthy"].Status)
	})
}

func TestExportDataFiltering(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-export",
		Enabled:     false,
	})
	require.NoError(t, err)
	defer cleanup()

	t.Run("filter data types per exporter", func(t *testing.T) {
		config := &export.ExportConfig{
			Enabled:      true,
			SamplingRate: 1.0, // Export everything
			BufferSize:   10,   // Adequate buffer size
			Exporters: map[string]export.ExporterConfig{
				"metrics-only": {
					Enabled:   true,
					DataTypes: []string{"metrics"},
				},
				"logs-only": {
					Enabled:   true,
					DataTypes: []string{"logs"},
				},
			},
		}

		manager := export.NewExportManager(logger, tracer, config)
		
		metricsExporter := NewMockExporter("metrics-only")
		logsExporter := NewMockExporter("logs-only")
		
		manager.RegisterExporter("metrics-only", metricsExporter)
		manager.RegisterExporter("logs-only", logsExporter)

		ctx := context.Background()
		manager.Start(ctx)
		defer manager.Stop(ctx)

		// Export data with both metrics and logs
		exportData := export.ExportData{
			SystemMetrics: map[string]interface{}{"requests": 100},
			Logs: []export.LogEntry{
				{
					Timestamp: time.Now(),
					Level:     "info",
					Message:   "Test log",
				},
			},
			Timestamp: time.Now(),
		}

		err := manager.Export(exportData)
		assert.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		// Check filtered data
		metricsData := metricsExporter.GetExportedData()
		logsData := logsExporter.GetExportedData()

		assert.Len(t, metricsData, 1)
		assert.Len(t, logsData, 1)

		// Metrics exporter should only have metrics
		assert.NotEmpty(t, metricsData[0].SystemMetrics)
		assert.Empty(t, metricsData[0].Logs)

		// Logs exporter should only have logs
		assert.Empty(t, logsData[0].SystemMetrics)
		assert.NotEmpty(t, logsData[0].Logs)
	})
}

func TestExportManagerConcurrency(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-export",
		Enabled:     false,
	})
	require.NoError(t, err)
	defer cleanup()

	t.Run("concurrent exports", func(t *testing.T) {
		config := &export.ExportConfig{
			Enabled:    true,
			BufferSize: 100,
			Exporters: map[string]export.ExporterConfig{
				"test": {Enabled: true},
			},
		}

		manager := export.NewExportManager(logger, tracer, config)
		exporter := NewMockExporter("test")
		manager.RegisterExporter("test", exporter)

		ctx := context.Background()
		manager.Start(ctx)
		defer manager.Stop(ctx)

		// Launch concurrent exports
		var wg sync.WaitGroup
		numGoroutines := 10
		exportsPerGoroutine := 5

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < exportsPerGoroutine; j++ {
					exportData := export.ExportData{
						SystemMetrics: map[string]interface{}{
							"goroutine_id": id,
							"export_id":    j,
						},
						Timestamp: time.Now(),
					}
					manager.Export(exportData)
				}
			}(i)
		}

		wg.Wait()
		time.Sleep(200 * time.Millisecond)

		// Should have received all exports
		data := exporter.GetExportedData()
		assert.Equal(t, numGoroutines*exportsPerGoroutine, len(data))
	})
}

func BenchmarkExportManagerExport(b *testing.B) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, _ := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "bench-export",
		Enabled:     false,
	})
	defer cleanup()

	config := &export.ExportConfig{
		Enabled:    true,
		BufferSize: 10000,
	}

	manager := export.NewExportManager(logger, tracer, config)
	exporter := NewMockExporter("bench")
	manager.RegisterExporter("bench", exporter)

	ctx := context.Background()
	manager.Start(ctx)
	defer manager.Stop(ctx)

	exportData := export.ExportData{
		SystemMetrics: map[string]interface{}{
			"requests": 1000,
			"latency":  25.5,
		},
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.Export(exportData)
	}
}