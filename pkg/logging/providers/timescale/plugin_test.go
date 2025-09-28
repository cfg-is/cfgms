package timescale

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "github.com/lib/pq" // PostgreSQL driver for cleanup
)

// TestTimescaleProvider_BasicFunctionality tests basic provider operations
func TestTimescaleProvider_BasicFunctionality(t *testing.T) {
	if !isTimescaleTestEnabled() {
		t.Skip("TimescaleDB tests disabled - set CFGMS_TEST_TIMESCALEDB=1 to enable")
	}

	// Test availability check before initialization
	provider := &TimescaleProvider{}
	available, err := provider.Available()
	assert.False(t, available) // Should be false before initialization
	assert.Error(t, err)

	// Create provider with automatic cleanup
	provider, _ = createTestProviderWithCleanup(t, "basic")

	// Test availability after initialization
	available, err = provider.Available()
	assert.True(t, available)
	assert.NoError(t, err)

	// Test provider metadata
	assert.Equal(t, "timescale", provider.Name())
	assert.Contains(t, provider.Description(), "TimescaleDB")
	assert.Equal(t, "1.0.0", provider.GetVersion())

	capabilities := provider.GetCapabilities()
	assert.True(t, capabilities.SupportsCompression)
	assert.True(t, capabilities.SupportsRetentionPolicies)
	assert.True(t, capabilities.SupportsRealTimeQueries)
	assert.True(t, capabilities.SupportsBatchWrites)
	assert.True(t, capabilities.SupportsTimeRangeQueries)
	assert.True(t, capabilities.SupportsTransactions)
	assert.True(t, capabilities.SupportsPartitioning)
	assert.True(t, capabilities.SupportsIndexing)
	assert.Greater(t, capabilities.MaxEntriesPerSecond, 50000)
}

// TestTimescaleProvider_WriteAndQuery tests writing and querying log entries
func TestTimescaleProvider_WriteAndQuery(t *testing.T) {
	if !isTimescaleTestEnabled() {
		t.Skip("TimescaleDB tests disabled - set CFGMS_TEST_TIMESCALEDB=1 to enable")
	}

	provider, _ := createTestProviderWithCleanup(t, "writequery")

	ctx := context.Background()

	// Create test entries
	baseTime := time.Now().Truncate(time.Second)
	testEntries := []interfaces.LogEntry{
		{
			Timestamp:   baseTime.Add(-2 * time.Hour),
			Level:       "INFO",
			Message:     "Test info message 1",
			ServiceName: "test-service",
			Component:   "test-component",
			TenantID:    "test-tenant-1",
			SessionID:   "session-123",
			Fields: map[string]interface{}{
				"test_field": "test_value_1",
				"number":     42,
			},
		},
		{
			Timestamp:   baseTime.Add(-1 * time.Hour),
			Level:       "WARN",
			Message:     "Test warning message",
			ServiceName: "test-service",
			Component:   "test-component",
			TenantID:    "test-tenant-1",
			SessionID:   "session-456",
			Fields: map[string]interface{}{
				"test_field": "test_value_2",
				"number":     100,
			},
		},
		{
			Timestamp:   baseTime,
			Level:       "ERROR",
			Message:     "Test error message",
			ServiceName: "test-service",
			Component:   "test-component",
			TenantID:    "test-tenant-2",
			SessionID:   "session-789",
			Fields: map[string]interface{}{
				"test_field": "test_value_3",
				"error_code": 500,
			},
		},
	}

	// Test single entry write
	err := provider.WriteEntry(ctx, testEntries[0])
	assert.NoError(t, err)

	// Test batch write
	err = provider.WriteBatch(ctx, testEntries[1:])
	assert.NoError(t, err)

	// Wait a bit for writes to complete
	time.Sleep(100 * time.Millisecond)

	// Test time range query
	query := interfaces.TimeRangeQuery{
		StartTime: baseTime.Add(-3 * time.Hour),
		EndTime:   baseTime.Add(1 * time.Hour),
		Limit:     10,
		OrderBy:   "timestamp",
		SortDesc:  false,
	}

	results, err := provider.QueryTimeRange(ctx, query)
	assert.NoError(t, err)
	assert.Len(t, results, 3)

	// Verify results are ordered by timestamp
	assert.True(t, results[0].Timestamp.Before(results[1].Timestamp))
	assert.True(t, results[1].Timestamp.Before(results[2].Timestamp))

	// Test filtering by level
	levelQuery := interfaces.LevelQuery{
		TimeRangeQuery: interfaces.TimeRangeQuery{
			StartTime: baseTime.Add(-3 * time.Hour),
			EndTime:   baseTime.Add(1 * time.Hour),
		},
		Levels: []string{"ERROR"},
	}

	errorResults, err := provider.QueryLevels(ctx, levelQuery)
	assert.NoError(t, err)
	assert.Len(t, errorResults, 1)
	assert.Equal(t, "ERROR", errorResults[0].Level)

	// Test filtering by tenant
	tenantQuery := interfaces.TimeRangeQuery{
		StartTime: baseTime.Add(-3 * time.Hour),
		EndTime:   baseTime.Add(1 * time.Hour),
		Filters: map[string]interface{}{
			"tenant_id": "test-tenant-1",
		},
	}

	tenantResults, err := provider.QueryTimeRange(ctx, tenantQuery)
	assert.NoError(t, err)
	assert.Len(t, tenantResults, 2)
	for _, result := range tenantResults {
		assert.Equal(t, "test-tenant-1", result.TenantID)
	}

	// Test count query
	countQuery := interfaces.CountQuery{
		StartTime: baseTime.Add(-3 * time.Hour),
		EndTime:   baseTime.Add(1 * time.Hour),
	}

	count, err := provider.QueryCount(ctx, countQuery)
	assert.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

// TestTimescaleProvider_LevelFiltering tests log level filtering
func TestTimescaleProvider_LevelFiltering(t *testing.T) {
	if !isTimescaleTestEnabled() {
		t.Skip("TimescaleDB tests disabled - set CFGMS_TEST_TIMESCALEDB=1 to enable")
	}

	provider, _ := createTestProviderWithCleanup(t, "level")

	ctx := context.Background()
	baseTime := time.Now().Truncate(time.Second)

	// Create entries with different levels
	levels := []string{"DEBUG", "INFO", "WARN", "ERROR", "FATAL"}
	var entries []interfaces.LogEntry

	for i, level := range levels {
		entries = append(entries, interfaces.LogEntry{
			Timestamp:   baseTime.Add(time.Duration(i) * time.Minute),
			Level:       level,
			Message:     fmt.Sprintf("Test %s message", level),
			ServiceName: "test-service",
			Component:   "test-component",
			Fields: map[string]interface{}{
				"level_index": i,
			},
		})
	}

	// Write all entries
	err := provider.WriteBatch(ctx, entries)
	assert.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Test single level filtering
	warnQuery := interfaces.LevelQuery{
		TimeRangeQuery: interfaces.TimeRangeQuery{
			StartTime: baseTime.Add(-1 * time.Hour),
			EndTime:   baseTime.Add(1 * time.Hour),
		},
		Levels: []string{"WARN"},
	}

	warnResults, err := provider.QueryLevels(ctx, warnQuery)
	assert.NoError(t, err)
	assert.Len(t, warnResults, 1)
	assert.Equal(t, "WARN", warnResults[0].Level)

	// Test multiple level filtering
	multiLevelQuery := interfaces.LevelQuery{
		TimeRangeQuery: interfaces.TimeRangeQuery{
			StartTime: baseTime.Add(-1 * time.Hour),
			EndTime:   baseTime.Add(1 * time.Hour),
		},
		Levels: []string{"ERROR", "FATAL"},
	}

	multiResults, err := provider.QueryLevels(ctx, multiLevelQuery)
	assert.NoError(t, err)
	assert.Len(t, multiResults, 2)

	resultLevels := make(map[string]bool)
	for _, result := range multiResults {
		resultLevels[result.Level] = true
	}
	assert.True(t, resultLevels["ERROR"])
	assert.True(t, resultLevels["FATAL"])
}

// TestTimescaleProvider_HighVolume tests high-volume logging performance
func TestTimescaleProvider_HighVolume(t *testing.T) {
	if !isTimescaleTestEnabled() {
		t.Skip("TimescaleDB tests disabled - set CFGMS_TEST_TIMESCALEDB=1 to enable")
	}

	provider, config := createTestProviderWithCleanup(t, "highvolume")
	config["batch_size"] = 1000

	ctx := context.Background()
	baseTime := time.Now().Truncate(time.Second)

	// Create 10,000 test entries
	const entryCount = 10000
	var entries []interfaces.LogEntry

	for i := 0; i < entryCount; i++ {
		entries = append(entries, interfaces.LogEntry{
			Timestamp:   baseTime.Add(time.Duration(i) * time.Millisecond),
			Level:       "INFO",
			Message:     fmt.Sprintf("High volume test message %d", i),
			ServiceName: "test-service",
			Component:   "performance-test",
			TenantID:    fmt.Sprintf("tenant-%d", i%10), // 10 different tenants
			Fields: map[string]interface{}{
				"batch_index": i,
				"test_data":   fmt.Sprintf("test_value_%d", i),
			},
		})
	}

	// Measure write performance
	start := time.Now()
	err := provider.WriteBatch(ctx, entries)
	writeTime := time.Since(start)

	assert.NoError(t, err)
	
	// Verify write performance (should be able to write 10k entries in under 10 seconds)
	assert.Less(t, writeTime.Seconds(), 10.0, "Write performance too slow: %v", writeTime)

	t.Logf("Wrote %d entries in %v (%.0f entries/second)", entryCount, writeTime, float64(entryCount)/writeTime.Seconds())

	// Wait for writes to complete
	time.Sleep(1 * time.Second)

	// Measure query performance
	queryStart := time.Now()
	query := interfaces.TimeRangeQuery{
		StartTime: baseTime.Add(-1 * time.Hour),
		EndTime:   baseTime.Add(1 * time.Hour),
		Limit:     1000, // Limit results for performance test
	}

	results, err := provider.QueryTimeRange(ctx, query)
	queryTime := time.Since(queryStart)

	assert.NoError(t, err)
	assert.Len(t, results, 1000) // Should return limited results

	// Verify query performance (should be able to query in under 5 seconds)
	assert.Less(t, queryTime.Seconds(), 5.0, "Query performance too slow: %v", queryTime)

	t.Logf("Queried %d entries in %v", len(results), queryTime)

	// Test count query performance
	countStart := time.Now()
	count, err := provider.QueryCount(ctx, interfaces.CountQuery{
		StartTime: baseTime.Add(-1 * time.Hour),
		EndTime:   baseTime.Add(1 * time.Hour),
	})
	countTime := time.Since(countStart)

	assert.NoError(t, err)
	assert.Equal(t, int64(entryCount), count)
	assert.Less(t, countTime.Seconds(), 2.0, "Count query too slow: %v", countTime)

	t.Logf("Count query returned %d in %v", count, countTime)
}

// TestTimescaleProvider_Stats tests statistics functionality
func TestTimescaleProvider_Stats(t *testing.T) {
	if !isTimescaleTestEnabled() {
		t.Skip("TimescaleDB tests disabled - set CFGMS_TEST_TIMESCALEDB=1 to enable")
	}

	provider, _ := createTestProviderWithCleanup(t, "stats")

	ctx := context.Background()
	baseTime := time.Now().Truncate(time.Second)

	// Write some test entries
	entries := []interfaces.LogEntry{
		{
			Timestamp:   baseTime.Add(-1 * time.Hour),
			Level:       "INFO",
			Message:     "Stats test message 1",
			ServiceName: "test-service",
			Component:   "test-component",
		},
		{
			Timestamp:   baseTime,
			Level:       "WARN",
			Message:     "Stats test message 2",
			ServiceName: "test-service",
			Component:   "test-component",
		},
	}

	err := provider.WriteBatch(ctx, entries)
	assert.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Get statistics
	stats, err := provider.GetStats(ctx)
	assert.NoError(t, err)

	// Verify basic statistics
	assert.Equal(t, int64(2), stats.TotalEntries)
	assert.Greater(t, stats.StorageSize, int64(0))
	assert.WithinDuration(t, baseTime.Add(-1*time.Hour), stats.OldestEntry, time.Minute)
	assert.WithinDuration(t, baseTime, stats.LatestEntry, time.Minute)
}

// TestTimescaleProvider_ProviderRegistration tests provider registration
func TestTimescaleProvider_ProviderRegistration(t *testing.T) {
	if !isTimescaleTestEnabled() {
		t.Skip("TimescaleDB tests disabled - set CFGMS_TEST_TIMESCALEDB=1 to enable")
	}

	// Test that the provider is registered
	provider, err := interfaces.CreateLoggingProviderFromConfig("timescale", getTestTimescaleConfig())
	assert.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, "timescale", provider.Name())

	// Clean up
	_ = provider.Close()
}

// Helper functions

// isTimescaleTestEnabled checks if TimescaleDB tests should run
func isTimescaleTestEnabled() bool {
	return os.Getenv("CFGMS_TEST_TIMESCALEDB") == "1"
}

// getTestTimescaleConfig returns test configuration for TimescaleDB with unique table names
func getTestTimescaleConfig() map[string]interface{} {
	return getTestTimescaleConfigWithTable("")
}

// getTestTimescaleConfigWithTable returns test configuration with a specific table name suffix
func getTestTimescaleConfigWithTable(tableSuffix string) map[string]interface{} {
	// Use environment variables if available, otherwise defaults
	host := os.Getenv("CFGMS_TEST_TIMESCALEDB_HOST")
	if host == "" {
		host = "localhost"
	}

	port := os.Getenv("CFGMS_TEST_TIMESCALEDB_PORT")
	if port == "" {
		port = "5434"
	}

	password := os.Getenv("CFGMS_TEST_TIMESCALEDB_PASSWORD")
	if password == "" {
		password = "cfgms_test_password"
	}

	// Generate unique table name using timestamp and suffix
	tableName := fmt.Sprintf("log_entries_test_%d", time.Now().UnixNano())
	if tableSuffix != "" {
		tableName = fmt.Sprintf("log_entries_test_%s_%d", tableSuffix, time.Now().UnixNano())
	}

	return map[string]interface{}{
		"host":              host,
		"port":              port,
		"database":          "cfgms_logs_test",
		"username":          "cfgms_logger_test",
		"password":          password,
		"ssl_mode":          "disable",
		"table_name":        tableName,
		"schema_name":       "test_logging",
		"chunk_interval":    "24h",
		"compression_after": "1h",  // Quick compression for testing
		"retention_after":   "48h", // Short retention for testing
		"batch_size":        100,
		"create_schema":     true,
	}
}

// cleanupTimescaleTestTable drops a test table and all associated TimescaleDB objects
func cleanupTimescaleTestTable(t *testing.T, config map[string]interface{}, tableName string) {
	t.Helper()

	// Build connection string
	dsn := fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=%s",
		config["host"], config["port"], config["database"],
		config["username"], config["password"], config["ssl_mode"])

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Logf("Failed to connect for cleanup: %v", err)
		return
	}
	defer func() { _ = db.Close() }()

	// Drop the hypertable (this also removes compression policies, retention policies, etc.)
	_, err = db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE", tableName))
	if err != nil {
		t.Logf("Failed to drop table %s: %v", tableName, err)
	} else {
		t.Logf("Successfully cleaned up table: %s", tableName)
	}
}

// createTestProviderWithCleanup creates a TimescaleDB provider with automatic cleanup
func createTestProviderWithCleanup(t *testing.T, tableSuffix string) (*TimescaleProvider, map[string]interface{}) {
	t.Helper()

	config := getTestTimescaleConfigWithTable(tableSuffix)
	provider := &TimescaleProvider{}

	err := provider.Initialize(config)
	require.NoError(t, err)

	// Set up cleanup to run when test finishes
	tableName := config["table_name"].(string)
	t.Cleanup(func() {
		_ = provider.Close()
		cleanupTimescaleTestTable(t, config, tableName)
	})

	return provider, config
}