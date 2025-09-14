package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileProvider_BasicFunctionality(t *testing.T) {
	// Create temporary directory for test logs
	tmpDir, err := os.MkdirTemp("", "cfgms-logging-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create provider
	provider := &FileProvider{}
	
	// Test provider metadata
	assert.Equal(t, "file", provider.Name())
	assert.NotEmpty(t, provider.Description())
	assert.NotEmpty(t, provider.GetVersion())
	
	// Test capabilities
	capabilities := provider.GetCapabilities()
	assert.True(t, capabilities.SupportsCompression)
	assert.True(t, capabilities.SupportsRetentionPolicies)
	assert.True(t, capabilities.SupportsBatchWrites)
	assert.True(t, capabilities.SupportsTimeRangeQueries)
	assert.Greater(t, capabilities.MaxEntriesPerSecond, 0)
	assert.Greater(t, capabilities.MaxBatchSize, 0)
	
	// Configure provider
	config := map[string]interface{}{
		"directory":        tmpDir,
		"file_prefix":      "test",
		"max_file_size":    1024 * 1024, // 1MB
		"max_files":        5,
		"retention_days":   7,
		"compress_rotated": false, // Disable compression for easier testing
	}
	
	// Test initialization
	err = provider.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = provider.Close() }()
	
	// Test availability
	available, err := provider.Available()
	assert.True(t, available)
	assert.NoError(t, err)
}

func TestFileProvider_WriteAndQuery(t *testing.T) {
	// Create temporary directory for test logs
	tmpDir, err := os.MkdirTemp("", "cfgms-logging-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create and initialize provider
	provider := &FileProvider{}
	config := map[string]interface{}{
		"directory":        tmpDir,
		"file_prefix":      "test",
		"max_file_size":    1024 * 1024, // 1MB
		"max_files":        5,
		"retention_days":   7,
		"compress_rotated": false,
		"buffer_size":      1024,
		"flush_interval":   "1s",
	}
	
	err = provider.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = provider.Close() }()

	ctx := context.Background()
	
	// Test single entry write
	entry := interfaces.LogEntry{
		Timestamp:   time.Now(),
		Level:       "INFO",
		Message:     "Test log message",
		ServiceName: "test-service",
		Component:   "test-component",
		Fields: map[string]interface{}{
			"test_field": "test_value",
			"number":     42,
		},
	}
	
	err = provider.WriteEntry(ctx, entry)
	assert.NoError(t, err)
	
	// Flush to ensure data is written
	err = provider.Flush(ctx)
	assert.NoError(t, err)
	
	// Test batch write
	batchEntries := []interfaces.LogEntry{
		{
			Timestamp:   time.Now(),
			Level:       "DEBUG",
			Message:     "Debug message 1",
			ServiceName: "test-service",
			Component:   "test-component",
		},
		{
			Timestamp:   time.Now(),
			Level:       "ERROR",
			Message:     "Error message 1",
			ServiceName: "test-service",
			Component:   "test-component",
			Fields: map[string]interface{}{
				"error_code": 500,
			},
		},
		{
			Timestamp:   time.Now(),
			Level:       "WARN",
			Message:     "Warning message 1",
			ServiceName: "test-service",
			Component:   "test-component",
		},
	}
	
	err = provider.WriteBatch(ctx, batchEntries)
	assert.NoError(t, err)
	
	// Flush to ensure data is written
	err = provider.Flush(ctx)
	assert.NoError(t, err)
	
	// Verify log files were created
	files, err := filepath.Glob(filepath.Join(tmpDir, "test-*.log"))
	require.NoError(t, err)
	assert.Greater(t, len(files), 0, "Expected at least one log file to be created")
	
	// Test time range query
	startTime := time.Now().Add(-1 * time.Hour)
	endTime := time.Now().Add(1 * time.Hour)
	
	query := interfaces.TimeRangeQuery{
		StartTime: startTime,
		EndTime:   endTime,
		Limit:     10,
	}
	
	results, err := provider.QueryTimeRange(ctx, query)
	assert.NoError(t, err)
	assert.Len(t, results, 4, "Expected 4 log entries (1 single + 3 batch)")
	
	// Verify entry content
	foundInfo := false
	foundError := false
	for _, result := range results {
		if result.Level == "INFO" && result.Message == "Test log message" {
			foundInfo = true
			assert.Equal(t, "test-service", result.ServiceName)
			assert.Equal(t, "test-component", result.Component)
			assert.Equal(t, "test_value", result.Fields["test_field"])
			assert.Equal(t, float64(42), result.Fields["number"]) // JSON unmarshaling converts to float64
		}
		if result.Level == "ERROR" && result.Message == "Error message 1" {
			foundError = true
			assert.Equal(t, float64(500), result.Fields["error_code"])
		}
	}
	assert.True(t, foundInfo, "Expected to find INFO log entry")
	assert.True(t, foundError, "Expected to find ERROR log entry")
}

func TestFileProvider_LevelFiltering(t *testing.T) {
	// Create temporary directory for test logs
	tmpDir, err := os.MkdirTemp("", "cfgms-logging-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create and initialize provider
	provider := &FileProvider{}
	config := map[string]interface{}{
		"directory":   tmpDir,
		"file_prefix": "test",
	}
	
	err = provider.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = provider.Close() }()

	ctx := context.Background()
	
	// Write entries with different levels
	entries := []interfaces.LogEntry{
		{Timestamp: time.Now(), Level: "DEBUG", Message: "Debug message"},
		{Timestamp: time.Now(), Level: "INFO", Message: "Info message"},
		{Timestamp: time.Now(), Level: "WARN", Message: "Warning message"},
		{Timestamp: time.Now(), Level: "ERROR", Message: "Error message"},
	}
	
	err = provider.WriteBatch(ctx, entries)
	assert.NoError(t, err)
	
	err = provider.Flush(ctx)
	assert.NoError(t, err)
	
	// Test level-based query
	query := interfaces.LevelQuery{
		TimeRangeQuery: interfaces.TimeRangeQuery{
			StartTime: time.Now().Add(-1 * time.Hour),
			EndTime:   time.Now().Add(1 * time.Hour),
		},
		Levels: []string{"ERROR", "WARN"},
	}
	
	results, err := provider.QueryLevels(ctx, query)
	assert.NoError(t, err)
	assert.Len(t, results, 2, "Expected 2 log entries (ERROR and WARN)")
	
	// Verify only ERROR and WARN levels are returned
	for _, result := range results {
		assert.Contains(t, []string{"ERROR", "WARN"}, result.Level)
	}
}

func TestFileProvider_Stats(t *testing.T) {
	// Create temporary directory for test logs
	tmpDir, err := os.MkdirTemp("", "cfgms-logging-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create and initialize provider
	provider := &FileProvider{}
	config := map[string]interface{}{
		"directory":   tmpDir,
		"file_prefix": "test",
	}
	
	err = provider.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = provider.Close() }()

	ctx := context.Background()
	
	// Write some entries
	entries := []interfaces.LogEntry{
		{Timestamp: time.Now(), Level: "INFO", Message: "Message 1"},
		{Timestamp: time.Now(), Level: "INFO", Message: "Message 2"},
		{Timestamp: time.Now(), Level: "INFO", Message: "Message 3"},
	}
	
	err = provider.WriteBatch(ctx, entries)
	assert.NoError(t, err)
	
	err = provider.Flush(ctx)
	assert.NoError(t, err)
	
	// Get statistics
	stats, err := provider.GetStats(ctx)
	assert.NoError(t, err)
	
	// Verify stats
	assert.Equal(t, int64(3), stats.TotalEntries)
	assert.Greater(t, stats.StorageSize, int64(0))
	assert.Greater(t, stats.WriteLatencyMs, 0.0)
	assert.False(t, stats.LatestEntry.IsZero())
}

func TestFileProvider_ProviderRegistration(t *testing.T) {
	// Test that provider auto-registers
	providers := interfaces.GetRegisteredLoggingProviderNames()
	assert.Contains(t, providers, "file", "File provider should be auto-registered")
	
	// Test provider retrieval (don't try to get it since it needs configuration)
	// Instead, test the registry directly
	provider := &FileProvider{}
	assert.Equal(t, "file", provider.Name())
	assert.NotEmpty(t, provider.Description())
	assert.NotEmpty(t, provider.GetVersion())
	
	// Test availability with no config (should be false)
	available, err := provider.Available()
	assert.False(t, available)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not configured")
}