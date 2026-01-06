//go:build integration

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// +build integration

package logging_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/logging/interfaces"

	// Import providers for testing
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"
)

// TestFileLoggingIntegration tests end-to-end file-based logging integration
func TestFileLoggingIntegration(t *testing.T) {
	t.Run("logging_manager_with_file_provider", func(t *testing.T) {
		testLoggingManagerWithFileProvider(t)
	})

	t.Run("module_logger_with_file_provider", func(t *testing.T) {
		testModuleLoggerWithFileProvider(t)
	})

	t.Run("concurrent_logging_performance", func(t *testing.T) {
		testConcurrentLoggingPerformanceFile(t)
	})

	t.Run("file_provider_features_validation", func(t *testing.T) {
		testFileProviderFeaturesValidation(t)
	})

	t.Run("multi_tenant_isolation", func(t *testing.T) {
		testMultiTenantIsolationFile(t)
	})

	t.Run("rotation_and_compression", func(t *testing.T) {
		testRotationAndCompression(t)
	})
}

// testLoggingManagerWithFileProvider tests logging manager integration with file provider
func testLoggingManagerWithFileProvider(t *testing.T) {
	// Create temporary directory for test logs
	logDir, err := os.MkdirTemp("", "cfgms-file-logging-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(logDir)

	// Create logging configuration
	config := &logging.LoggingConfig{
		Provider:          "file",
		Config:            getFileIntegrationConfig(logDir),
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
	assert.GreaterOrEqual(t, len(results), 50) // At least 50 batch entries (single entry might not be in query window)

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
	assert.GreaterOrEqual(t, stats.TotalEntries, int64(50))
	assert.Greater(t, stats.StorageSize, int64(0))

	// Verify log files were created
	logFiles, err := filepath.Glob(filepath.Join(logDir, "*.log*"))
	assert.NoError(t, err)
	assert.NotEmpty(t, logFiles, "Log files should be created in the directory")
}

// testModuleLoggerWithFileProvider tests module logger integration with file provider
func testModuleLoggerWithFileProvider(t *testing.T) {
	// Create temporary directory for test logs
	logDir, err := os.MkdirTemp("", "cfgms-file-module-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(logDir)

	// Initialize global logging with file provider
	config := &logging.LoggingConfig{
		Provider:          "file",
		Config:            getFileIntegrationConfig(logDir),
		Level:             "DEBUG",
		ServiceName:       "module-test-service",
		Component:         "controller",
		BatchSize:         50,
		AsyncWrites:       false, // Synchronous for testing
		TenantIsolation:   true,
		EnableCorrelation: true,
	}

	err = logging.InitializeGlobalLogging(config)
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
		// Note: File provider may not preserve all metadata fields exactly as configured
		// Check that module field is preserved (most important)
		assert.Equal(t, "integration-test-module", result.Fields["module"])
		assert.Equal(t, "1.0.0", result.Fields["module_version"])
		assert.Equal(t, "module-integration", result.Fields["test_id"])
		assert.Equal(t, "test-tenant-123", result.TenantID)
		assert.Equal(t, "session-integration-test", result.SessionID)
	}

	// Verify log files exist
	logFiles, err := filepath.Glob(filepath.Join(logDir, "*.log*"))
	assert.NoError(t, err)
	assert.NotEmpty(t, logFiles, "Module logging should create log files")
}

// testConcurrentLoggingPerformanceFile tests concurrent logging performance with file provider
func testConcurrentLoggingPerformanceFile(t *testing.T) {
	logDir, err := os.MkdirTemp("", "cfgms-file-perf-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(logDir)

	config := &logging.LoggingConfig{
		Provider:      "file",
		Config:        getFileIntegrationConfig(logDir),
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
	const entriesPerGoroutine = 500 // Reduced for file provider
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

	// Verify performance meets requirements for file provider (should be at least 5,000 entries/second)
	assert.Greater(t, entriesPerSecond, 5000.0, "Concurrent write performance too slow")

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

// testFileProviderFeaturesValidation tests file provider-specific features
func testFileProviderFeaturesValidation(t *testing.T) {
	// This test validates that file provider features are properly configured
	provider := interfaces.GetRegisteredProviders()["file"]
	require.NotNil(t, provider)

	logDir, err := os.MkdirTemp("", "cfgms-file-features-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(logDir)

	config := getFileIntegrationConfig(logDir)

	err = provider.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = provider.Close() }()

	// Test capabilities
	capabilities := provider.GetCapabilities()
	assert.True(t, capabilities.SupportsCompression, "File provider should support compression")
	assert.True(t, capabilities.SupportsRetentionPolicies, "File provider should support retention policies")
	assert.True(t, capabilities.SupportsBatchWrites, "File provider should support batch writes")
	assert.True(t, capabilities.SupportsTimeRangeQueries, "File provider should support time range queries")
	assert.True(t, capabilities.SupportsPartitioning, "File provider should support partitioning (time-based rotation)")
	assert.True(t, capabilities.SupportsFullTextSearch, "File provider should support full text search")
	assert.False(t, capabilities.SupportsIndexing, "File provider doesn't have built-in indexing")
	assert.False(t, capabilities.SupportsTransactions, "File provider doesn't support transactions")

	// Test throughput capability
	assert.Greater(t, capabilities.MaxEntriesPerSecond, 5000, "File provider should support reasonable throughput")

	t.Logf("File provider capabilities validated: Max entries/sec: %d, Compression ratio: %.2f",
		capabilities.MaxEntriesPerSecond, capabilities.CompressionRatio)
}

// testMultiTenantIsolationFile tests tenant isolation with file provider
func testMultiTenantIsolationFile(t *testing.T) {
	logDir, err := os.MkdirTemp("", "cfgms-file-tenant-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(logDir)

	config := &logging.LoggingConfig{
		Provider:        "file",
		Config:          getFileIntegrationConfig(logDir),
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
					"tenant":    tenant,
					"entry_id":  i,
					"test_type": "tenant_isolation",
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

// testRotationAndCompression tests file rotation and compression features
func testRotationAndCompression(t *testing.T) {
	logDir, err := os.MkdirTemp("", "cfgms-file-rotation-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(logDir)

	config := getFileIntegrationConfig(logDir)
	// Set very small max size to trigger rotation
	config["max_file_size"] = 1 * 1024 * 1024 // 1MB
	config["retention_days"] = 7
	config["max_files"] = 5
	config["compress_rotated"] = true

	fileConfig := &logging.LoggingConfig{
		Provider:    "file",
		Config:      config,
		Level:       "INFO",
		ServiceName: "rotation-test-service",
		Component:   "rotation-test",
		AsyncWrites: false,
	}

	manager, err := logging.NewLoggingManager(fileConfig)
	require.NoError(t, err)
	defer func() { _ = manager.Close() }()

	ctx := context.Background()

	// Write enough entries to trigger rotation (large messages)
	for i := 0; i < 1000; i++ {
		entry := interfaces.LogEntry{
			Timestamp:   time.Now(),
			Level:       "INFO",
			Message:     fmt.Sprintf("Large message for rotation test %d - %s", i, generateLargeString(500)),
			ServiceName: "rotation-test-service",
			Component:   "rotation-test",
			TenantID:    "test-tenant",
			Fields: map[string]interface{}{
				"index":     i,
				"test_type": "rotation",
			},
		}

		err := manager.WriteEntry(ctx, entry)
		assert.NoError(t, err)
	}

	// Wait for writes and potential rotation
	time.Sleep(2 * time.Second)

	// Check if rotation occurred (should have multiple log files)
	logFiles, err := filepath.Glob(filepath.Join(logDir, "*.log*"))
	assert.NoError(t, err)
	t.Logf("Found %d log files after rotation test", len(logFiles))

	// Verify we can still query all entries
	query := interfaces.TimeRangeQuery{
		StartTime: time.Now().Add(-1 * time.Hour),
		EndTime:   time.Now().Add(1 * time.Minute),
		Filters: map[string]interface{}{
			"service_name": "rotation-test-service",
		},
	}

	countQuery := interfaces.CountQuery{
		StartTime: query.StartTime,
		EndTime:   query.EndTime,
		Filters:   query.Filters,
	}

	count, err := manager.QueryCount(ctx, countQuery)
	assert.NoError(t, err)
	assert.Equal(t, int64(1000), count, "All entries should be queryable after rotation")
}

// Helper functions

// getFileIntegrationConfig returns integration test configuration for file provider
func getFileIntegrationConfig(logDir string) map[string]interface{} {
	return map[string]interface{}{
		"directory":         logDir,
		"file_prefix":       "cfgms-integration-test",
		"max_file_size":     100 * 1024 * 1024, // 100MB
		"max_files":         10,
		"retention_days":    30,
		"buffer_size":       4096,
		"flush_interval":    "1s",
		"compress_rotated":  true,
		"compression_level": 6,
		"file_mode":         0644,
		"dir_mode":          0755,
	}
}

// generateLargeString generates a string of specified size for testing
func generateLargeString(size int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, size)
	for i := range result {
		result[i] = chars[i%len(chars)]
	}
	return string(result)
}
