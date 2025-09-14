package logging_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/logging/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Import providers for testing
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"
	_ "github.com/cfgis/cfgms/pkg/logging/providers/timescale"
)

// TestTimescaleLoggingIntegration tests end-to-end TimescaleDB logging integration
func TestTimescaleLoggingIntegration(t *testing.T) {
	if !isTimescaleIntegrationEnabled() {
		t.Skip("TimescaleDB integration tests disabled - set CFGMS_TEST_TIMESCALEDB_INTEGRATION=1 to enable")
	}

	t.Run("logging_manager_with_timescaledb", func(t *testing.T) {
		testLoggingManagerWithTimescaleDB(t)
	})

	t.Run("module_logger_with_timescaledb", func(t *testing.T) {
		testModuleLoggerWithTimescaleDB(t)
	})

	t.Run("concurrent_logging_performance", func(t *testing.T) {
		testConcurrentLoggingPerformance(t)
	})

	t.Run("timescale_features_validation", func(t *testing.T) {
		testTimescaleFeaturesValidation(t)
	})

	t.Run("multi_tenant_isolation", func(t *testing.T) {
		testMultiTenantIsolation(t)
	})
}

// testLoggingManagerWithTimescaleDB tests logging manager integration
func testLoggingManagerWithTimescaleDB(t *testing.T) {
	// Create logging configuration
	config := &logging.LoggingConfig{
		Provider:          "timescale",
		Config:            getTimescaleIntegrationConfig(),
		Level:             "DEBUG",
		ServiceName:       "integration-test-service",
		Component:         "test-component",
		BatchSize:         100,
		FlushInterval:     5 * time.Second,
		AsyncWrites:       true,
		BufferSize:        1000,
		TenantIsolation:   true,
		EnableCorrelation: true,
		EnableTracing:     true,
	}

	// Create logging manager
	manager, err := logging.NewLoggingManager(config)
	require.NoError(t, err)
	defer func() { _ = manager.Close() }()

	ctx := context.Background()

	// Test single entry logging
	entry := interfaces.LogEntry{
		Level:       "INFO",
		Message:     "Integration test message",
		ServiceName: "integration-test-service",
		Component:   "test-component",
		TenantID:    "test-tenant",
		SessionID:   "test-session",
		Fields: map[string]interface{}{
			"integration": true,
			"test_type":   "logging_manager",
			"timestamp":   time.Now().Unix(),
		},
	}

	err = manager.WriteEntry(ctx, entry)
	assert.NoError(t, err)

	// Test batch logging
	var batchEntries []interfaces.LogEntry
	baseTime := time.Now().Truncate(time.Second)

	for i := 0; i < 50; i++ {
		batchEntries = append(batchEntries, interfaces.LogEntry{
			Timestamp:   baseTime.Add(time.Duration(i) * time.Second),
			Level:       "INFO",
			Message:     fmt.Sprintf("Batch integration test message %d", i),
			ServiceName: "integration-test-service",
			Component:   "test-component",
			TenantID:    "test-tenant",
			Fields: map[string]interface{}{
				"batch_index": i,
				"test_type":   "batch_logging",
			},
		})
	}

	err = manager.WriteBatch(ctx, batchEntries)
	assert.NoError(t, err)

	// Wait for async writes to complete
	time.Sleep(2 * time.Second)

	// Query entries back
	query := interfaces.TimeRangeQuery{
		StartTime: baseTime.Add(-1 * time.Hour),
		EndTime:   baseTime.Add(1 * time.Hour),
		Filters: map[string]interface{}{
			"service_name": "integration-test-service",
		},
		Limit: 100,
	}

	results, err := manager.QueryTimeRange(ctx, query)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 51) // At least 1 single + 50 batch entries

	// Verify entries have expected fields
	for _, result := range results {
		assert.Equal(t, "integration-test-service", result.ServiceName)
		assert.Equal(t, "test-component", result.Component)
		assert.Equal(t, "test-tenant", result.TenantID)
		assert.NotEmpty(t, result.Fields)
	}

	// Test statistics
	stats, err := manager.GetStats(ctx)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, stats.TotalEntries, int64(51))
	assert.Greater(t, stats.StorageSize, int64(0))
}

// testModuleLoggerWithTimescaleDB tests module logger integration
func testModuleLoggerWithTimescaleDB(t *testing.T) {
	// Initialize global logging with TimescaleDB
	config := &logging.LoggingConfig{
		Provider:          "timescale",
		Config:            getTimescaleIntegrationConfig(),
		Level:             "DEBUG",
		ServiceName:       "module-test-service",
		Component:         "controller",
		BatchSize:         50,
		AsyncWrites:       false, // Synchronous for testing
		TenantIsolation:   true,
		EnableCorrelation: true,
	}

	err := logging.InitializeGlobalLogging(config)
	require.NoError(t, err)

	defer func() {
		if manager := logging.GetGlobalLoggingManager(); manager != nil {
			_ = manager.Close()
		}
	}()

	// Create module logger
	moduleLogger := logging.ForModule("integration-test-module").
		WithField("module_version", "1.0.0").
		WithField("test_id", "module-integration").
		WithTenant("test-tenant-123").
		WithSession("session-integration-test")

	// Test different log levels
	moduleLogger.Debug("Debug message from module logger", "debug_data", "test_value")
	moduleLogger.Info("Info message from module logger", "info_data", "test_value")
	moduleLogger.Warn("Warning message from module logger", "warn_data", "test_value")
	moduleLogger.Error("Error message from module logger", "error_code", 500)

	// Flush logs
	err = moduleLogger.Flush(context.Background())
	assert.NoError(t, err)

	// Wait for writes
	time.Sleep(1 * time.Second)

	// Query back the logged entries
	manager := logging.GetGlobalLoggingManager()
	require.NotNil(t, manager)

	query := interfaces.TimeRangeQuery{
		StartTime: time.Now().Add(-10 * time.Minute),
		EndTime:   time.Now().Add(1 * time.Minute),
		Filters: map[string]interface{}{
			"module": "integration-test-module",
		},
		Limit: 10,
	}

	results, err := manager.QueryTimeRange(context.Background(), query)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 4) // Should have at least 4 entries

	// Verify module context is preserved
	for _, result := range results {
		assert.Equal(t, "module-test-service", result.ServiceName)
		assert.Equal(t, "controller", result.Component)
		assert.Equal(t, "test-tenant-123", result.TenantID)
		assert.Equal(t, "session-integration-test", result.SessionID)
		assert.Equal(t, "integration-test-module", result.Fields["module"])
		assert.Equal(t, "1.0.0", result.Fields["module_version"])
		assert.Equal(t, "module-integration", result.Fields["test_id"])
	}
}

// testConcurrentLoggingPerformance tests concurrent logging performance
func testConcurrentLoggingPerformance(t *testing.T) {
	config := &logging.LoggingConfig{
		Provider:      "timescale",
		Config:        getTimescaleIntegrationConfig(),
		Level:         "INFO",
		ServiceName:   "performance-test-service",
		Component:     "performance-test",
		BatchSize:     1000,
		AsyncWrites:   true,
		BufferSize:    5000,
		FlushInterval: 1 * time.Second,
	}

	manager, err := logging.NewLoggingManager(config)
	require.NoError(t, err)
	defer func() { _ = manager.Close() }()

	ctx := context.Background()
	const numGoroutines = 10
	const entriesPerGoroutine = 1000
	const totalEntries = numGoroutines * entriesPerGoroutine

	startTime := time.Now()

	// Create channels for synchronization
	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines)

	// Start concurrent goroutines
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer func() { done <- true }()

			var entries []interfaces.LogEntry
			baseTime := time.Now().Truncate(time.Second)

			// Create entries for this goroutine
			for j := 0; j < entriesPerGoroutine; j++ {
				entries = append(entries, interfaces.LogEntry{
					Timestamp:   baseTime.Add(time.Duration(j) * time.Millisecond),
					Level:       "INFO",
					Message:     fmt.Sprintf("Concurrent test message from goroutine %d, entry %d", goroutineID, j),
					ServiceName: "performance-test-service",
					Component:   "performance-test",
					TenantID:    fmt.Sprintf("tenant-%d", goroutineID%5),
					Fields: map[string]interface{}{
						"goroutine_id": goroutineID,
						"entry_id":     j,
						"test_type":    "concurrent_performance",
					},
				})
			}

			// Write entries in batches
			batchSize := 100
			for k := 0; k < len(entries); k += batchSize {
				end := k + batchSize
				if end > len(entries) {
					end = len(entries)
				}

				if err := manager.WriteBatch(ctx, entries[k:end]); err != nil {
					errors <- err
					return
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		select {
		case <-done:
			// Goroutine completed successfully
		case err := <-errors:
			t.Fatalf("Goroutine failed with error: %v", err)
		case <-time.After(30 * time.Second):
			t.Fatal("Timeout waiting for goroutines to complete")
		}
	}

	writeTime := time.Since(startTime)

	// Wait for async writes to complete
	time.Sleep(5 * time.Second)

	// Measure write performance
	entriesPerSecond := float64(totalEntries) / writeTime.Seconds()
	t.Logf("Concurrent performance: %d entries in %v (%.0f entries/second)",
		totalEntries, writeTime, entriesPerSecond)

	// Verify performance meets requirements (should be at least 10,000 entries/second)
	assert.Greater(t, entriesPerSecond, 10000.0, "Concurrent write performance too slow")

	// Verify data integrity by querying back
	query := interfaces.TimeRangeQuery{
		StartTime: startTime.Add(-1 * time.Minute),
		EndTime:   time.Now().Add(1 * time.Minute),
		Filters: map[string]interface{}{
			"service_name": "performance-test-service",
		},
	}

	countQuery := interfaces.CountQuery{
		StartTime: query.StartTime,
		EndTime:   query.EndTime,
		Filters:   query.Filters,
	}

	count, err := manager.QueryCount(ctx, countQuery)
	assert.NoError(t, err)
	assert.Equal(t, int64(totalEntries), count, "Not all entries were written correctly")
}

// testTimescaleFeaturesValidation tests TimescaleDB-specific features
func testTimescaleFeaturesValidation(t *testing.T) {
	// This test validates that TimescaleDB features are properly configured
	provider := interfaces.GetRegisteredProviders()["timescale"]
	require.NotNil(t, provider)

	config := getTimescaleIntegrationConfig()
	config["table_name"] = "features_validation_test"

	err := provider.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = provider.Close() }()

	// Test capabilities
	capabilities := provider.GetCapabilities()
	assert.True(t, capabilities.SupportsCompression, "TimescaleDB should support compression")
	assert.True(t, capabilities.SupportsRetentionPolicies, "TimescaleDB should support retention policies")
	assert.True(t, capabilities.SupportsPartitioning, "TimescaleDB should support partitioning")
	assert.True(t, capabilities.SupportsIndexing, "TimescaleDB should support indexing")
	assert.True(t, capabilities.SupportsTransactions, "TimescaleDB should support transactions")

	// Test high throughput capability
	assert.Greater(t, capabilities.MaxEntriesPerSecond, int64(50000), "TimescaleDB should support high throughput")

	t.Logf("TimescaleDB capabilities validated: Max entries/sec: %d, Compression ratio: %.2f",
		capabilities.MaxEntriesPerSecond, capabilities.CompressionRatio)
}

// testMultiTenantIsolation tests tenant isolation in TimescaleDB
func testMultiTenantIsolation(t *testing.T) {
	config := &logging.LoggingConfig{
		Provider:        "timescale",
		Config:          getTimescaleIntegrationConfig(),
		Level:           "INFO",
		ServiceName:     "tenant-isolation-test",
		Component:       "isolation-test",
		TenantIsolation: true,
		AsyncWrites:     false,
	}

	manager, err := logging.NewLoggingManager(config)
	require.NoError(t, err)
	defer func() { _ = manager.Close() }()

	ctx := context.Background()
	baseTime := time.Now().Truncate(time.Second)

	// Create entries for different tenants
	tenants := []string{"tenant-a", "tenant-b", "tenant-c"}
	var allEntries []interfaces.LogEntry

	for _, tenant := range tenants {
		for i := 0; i < 10; i++ {
			allEntries = append(allEntries, interfaces.LogEntry{
				Timestamp:   baseTime.Add(time.Duration(i) * time.Minute),
				Level:       "INFO",
				Message:     fmt.Sprintf("Tenant isolation test message %d for %s", i, tenant),
				ServiceName: "tenant-isolation-test",
				Component:   "isolation-test",
				TenantID:    tenant,
				SessionID:   fmt.Sprintf("session-%s-%d", tenant, i),
				Fields: map[string]interface{}{
					"tenant":     tenant,
					"entry_id":   i,
					"test_type":  "tenant_isolation",
				},
			})
		}
	}

	// Write all entries
	err = manager.WriteBatch(ctx, allEntries)
	assert.NoError(t, err)

	time.Sleep(1 * time.Second)

	// Test tenant-specific queries
	for _, tenant := range tenants {
		tenantQuery := interfaces.TimeRangeQuery{
			StartTime: baseTime.Add(-1 * time.Hour),
			EndTime:   baseTime.Add(1 * time.Hour),
			Filters: map[string]interface{}{
				"tenant_id": tenant,
			},
			Limit: 20,
		}

		results, err := manager.QueryTimeRange(ctx, tenantQuery)
		assert.NoError(t, err)
		assert.Len(t, results, 10, "Each tenant should have exactly 10 entries")

		// Verify all results belong to the correct tenant
		for _, result := range results {
			assert.Equal(t, tenant, result.TenantID, "Tenant isolation violated")
			assert.Equal(t, tenant, result.Fields["tenant"], "Field-level tenant data incorrect")
		}
	}

	// Verify total count across all tenants
	totalQuery := interfaces.CountQuery{
		StartTime: baseTime.Add(-1 * time.Hour),
		EndTime:   baseTime.Add(1 * time.Hour),
		Filters: map[string]interface{}{
			"service_name": "tenant-isolation-test",
		},
	}

	totalCount, err := manager.QueryCount(ctx, totalQuery)
	assert.NoError(t, err)
	assert.Equal(t, int64(30), totalCount, "Total count should be 30 (10 per tenant)")
}

// Helper functions

// isTimescaleIntegrationEnabled checks if TimescaleDB integration tests should run
func isTimescaleIntegrationEnabled() bool {
	return os.Getenv("CFGMS_TEST_TIMESCALEDB_INTEGRATION") == "1"
}

// getTimescaleIntegrationConfig returns integration test configuration for TimescaleDB
func getTimescaleIntegrationConfig() map[string]interface{} {
	// Use environment variables if available, otherwise defaults for CI/testing
	host := os.Getenv("CFGMS_TEST_TIMESCALEDB_HOST")
	if host == "" {
		host = "localhost"
	}

	password := os.Getenv("CFGMS_TEST_TIMESCALEDB_PASSWORD")
	if password == "" {
		password = "cfgms_test_password"
	}

	return map[string]interface{}{
		"host":              host,
		"port":              5434,
		"database":          "cfgms_logs_test",
		"username":          "cfgms_logger_test",
		"password":          password,
		"ssl_mode":          "disable",
		"table_name":        "integration_test_entries",
		"schema_name":       "public",
		"chunk_interval":    "24h",
		"compression_after": "2h",  // Quick compression for testing
		"retention_after":   "168h", // 7 days retention for integration tests
		"batch_size":        500,
		"max_connections":   20,
		"create_schema":     true,
	}
}