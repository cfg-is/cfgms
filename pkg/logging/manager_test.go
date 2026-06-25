// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package logging

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"

	// Import providers for testing
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"
)

// TestLoggingManager_AsyncClose_NoBatchingRoutineRace verifies that Close() waits
// for the batchingRoutine goroutine to finish before closing shared resources.
// Without the batchingWg fix, this test exposes a race between the goroutine's
// final flushBatch→provider.WriteBatch and Close()'s provider.Close() when run
// with -race.
func TestLoggingManager_AsyncClose_NoBatchingRoutineRace(t *testing.T) {
	cfg := &LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":        t.TempDir(),
			"file_prefix":      "race-test",
			"max_file_size":    1024 * 1024,
			"retention_days":   1,
			"compress_rotated": false,
		},
		Level:         "DEBUG",
		ServiceName:   "race-test",
		Component:     "test",
		BatchSize:     2,         // small batch so batchingRoutine starts
		FlushInterval: time.Hour, // long interval so Close() triggers the stop path
		AsyncWrites:   true,
		BufferSize:    16,
	}

	manager, err := NewLoggingManager(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	// Fill the batch buffer so the batchingRoutine has work to do during Close.
	for i := 0; i < 5; i++ {
		require.NoError(t, manager.WriteEntry(ctx, interfaces.LogEntry{
			Timestamp: time.Now(),
			Level:     "INFO",
			Message:   "async-close-race",
		}))
	}

	// Close() must drain the batchingRoutine before touching the provider;
	// the race detector will catch any concurrent WriteBatch/Close on the provider.
	require.NoError(t, manager.Close())
}

// TestLoggingManager_FactoryProducesDistinctProviders verifies that factory-registered
// providers give each LoggingManager its own independent instance. Closing one manager
// must not race with the other manager's batchingRoutine (pre-fix root cause of the
// TestControllerLifecycle / TestControllerSingleHTTPServer data race).
func TestLoggingManager_FactoryProducesDistinctProviders(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	makeCfg := func(dir, svc string) *LoggingConfig {
		return &LoggingConfig{
			Provider: "file",
			Config: map[string]interface{}{
				"directory": dir, "file_prefix": svc,
				"retention_days": 1, "compress_rotated": false,
			},
			Level: "INFO", ServiceName: svc, Component: "comp",
			BatchSize: 2, FlushInterval: time.Hour, AsyncWrites: true, BufferSize: 16,
		}
	}

	mgr1, err := NewLoggingManager(makeCfg(dir1, "mgr1"))
	require.NoError(t, err)

	mgr2, err := NewLoggingManager(makeCfg(dir2, "mgr2"))
	require.NoError(t, err)

	// Core invariant: each manager must own a distinct provider instance.
	require.False(t, mgr1.GetProvider() == mgr2.GetProvider(),
		"factory must produce independent provider instances for each LoggingManager")

	ctx := context.Background()
	// Write entries so both batchingRoutines are active.
	for i := 0; i < 5; i++ {
		require.NoError(t, mgr1.WriteEntry(ctx, interfaces.LogEntry{Level: "INFO", Message: "entry"}))
		require.NoError(t, mgr2.WriteEntry(ctx, interfaces.LogEntry{Level: "INFO", Message: "entry"}))
	}

	// Closing mgr2 while mgr1's batchingRoutine is active must not race on shared provider
	// state. The race detector will catch any concurrent reads/writes on p.initialized.
	require.NoError(t, mgr2.Close())

	// mgr1's write path must remain functional after mgr2 is closed.
	err = mgr1.WriteEntry(ctx, interfaces.LogEntry{Level: "INFO", Message: "written after mgr2 closed"})
	assert.NoError(t, err, "mgr1 writes must succeed after mgr2 is independently closed")

	require.NoError(t, mgr1.Close())
}

func TestLoggingManager_BasicFunctionality(t *testing.T) {
	// Create temporary directory for test logs
	tmpDir, err := os.MkdirTemp("", "cfgms-logging-manager-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create logging manager configuration
	config := &LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":        tmpDir,
			"file_prefix":      "test",
			"max_file_size":    1024 * 1024, // 1MB
			"retention_days":   7,
			"compress_rotated": false,
		},
		Level:             "DEBUG", // Allow all levels for testing
		ServiceName:       "test-service",
		Component:         "test-component",
		BatchSize:         10,
		FlushInterval:     time.Second,
		AsyncWrites:       false, // Synchronous for testing
		BufferSize:        100,
		RetentionDays:     7,
		TenantIsolation:   true,
		EnableCorrelation: true,
		EnableTracing:     true,
	}

	// Create manager
	manager, err := NewLoggingManager(config)
	require.NoError(t, err)
	defer func() { _ = manager.Close() }()

	ctx := context.Background()

	// Test single entry write
	entry := interfaces.LogEntry{
		Level:   "INFO",
		Message: "Test message from manager",
		Fields: map[string]interface{}{
			"test_field": "test_value",
		},
	}

	err = manager.WriteEntry(ctx, entry)
	assert.NoError(t, err)

	// Test batch write
	batchEntries := []interfaces.LogEntry{
		{Level: "DEBUG", Message: "Debug message 1"},
		{Level: "INFO", Message: "Info message 1"},
		{Level: "WARN", Message: "Warning message 1"},
	}

	err = manager.WriteBatch(ctx, batchEntries)
	assert.NoError(t, err)

	// Flush to ensure data is written
	err = manager.Flush(ctx)
	assert.NoError(t, err)

	// Test query
	query := interfaces.TimeRangeQuery{
		StartTime: time.Now().Add(-1 * time.Hour),
		EndTime:   time.Now().Add(1 * time.Hour),
		Limit:     10,
	}

	results, err := manager.QueryTimeRange(ctx, query)
	assert.NoError(t, err)
	assert.Len(t, results, 4, "Expected 4 log entries (1 single + 3 batch)")

	// Test statistics
	stats, err := manager.GetStats(ctx)
	assert.NoError(t, err)
	assert.Equal(t, int64(4), stats.TotalEntries)
}

func TestGlobalLoggingManager(t *testing.T) {
	// Create temporary directory for test logs
	tmpDir, err := os.MkdirTemp("", "cfgms-global-logging-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create configuration
	config := &LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":      tmpDir,
			"file_prefix":    "global-test",
			"retention_days": 1,
		},
		Level:       "DEBUG",
		ServiceName: "global-test-service",
		Component:   "global-test-component",
		AsyncWrites: false,
	}

	// Initialize global logging
	err = InitializeGlobalLogging(config)
	require.NoError(t, err)

	// Test global manager retrieval
	manager := GetGlobalLoggingManager()
	require.NotNil(t, manager)
	assert.Equal(t, config.ServiceName, manager.config.ServiceName)
	assert.Equal(t, config.Component, manager.config.Component)

	// Test convenience functions
	ctx := context.Background()
	fields := map[string]interface{}{"test": "value"}

	err = Debug(ctx, "Debug message", fields)
	assert.NoError(t, err)

	err = Info(ctx, "Info message", fields)
	assert.NoError(t, err)

	err = Warn(ctx, "Warning message", fields)
	assert.NoError(t, err)

	err = Error(ctx, "Error message", fields)
	assert.NoError(t, err)

	// Flush and verify
	err = manager.Flush(ctx)
	assert.NoError(t, err)

	// Verify log files were created
	files, err := filepath.Glob(filepath.Join(tmpDir, "global-test-*.log"))
	require.NoError(t, err)
	assert.Greater(t, len(files), 0, "Expected at least one log file")

	// Clean up global state
	_ = manager.Close()
}

func TestModuleLogger(t *testing.T) {
	// Create temporary directory for test logs
	tmpDir, err := os.MkdirTemp("", "cfgms-module-logging-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Initialize global logging first
	config := &LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":      tmpDir,
			"file_prefix":    "module-test",
			"retention_days": 1,
		},
		Level:       "INFO",
		ServiceName: "module-test-service",
		Component:   "controller",
		AsyncWrites: false,
	}

	err = InitializeGlobalLogging(config)
	require.NoError(t, err)

	defer func() {
		if manager := GetGlobalLoggingManager(); manager != nil {
			_ = manager.Close()
		}
	}()

	// Initialize global logger factory
	InitializeGlobalLoggerFactory("module-test-service", "controller")

	// Test module logger creation
	moduleLogger := ForModule("test-module")
	require.NotNil(t, moduleLogger)
	assert.Equal(t, "test-module", moduleLogger.moduleName)
	assert.True(t, moduleLogger.IsProviderAvailable())

	// Test module logger with fields
	moduleLogger = moduleLogger.WithField("module_version", "1.0.0").
		WithTenant("test-tenant-123").
		WithSession("session-456")

	// Test logging methods
	moduleLogger.Info("Module started successfully", "startup_time", "500ms")
	moduleLogger.Warn("Module configuration missing, using defaults")
	moduleLogger.Error("Module encountered error", "error_code", 500)

	// Flush logs
	err = moduleLogger.Flush(context.Background())
	assert.NoError(t, err)

	// Verify logs were written
	manager := GetGlobalLoggingManager()
	require.NotNil(t, manager)

	query := interfaces.TimeRangeQuery{
		StartTime: time.Now().Add(-1 * time.Hour),
		EndTime:   time.Now().Add(1 * time.Hour),
		Filters: map[string]interface{}{
			"module": "test-module",
		},
		Limit: 10,
	}

	results, err := manager.QueryTimeRange(context.Background(), query)
	assert.NoError(t, err)
	assert.Len(t, results, 3, "Expected 3 log entries from module logger")

	// Verify module context is included
	foundModuleEntry := false
	for _, result := range results {
		if result.Message == "Module started successfully" {
			foundModuleEntry = true
			assert.Equal(t, "test-module", result.Fields["module"])
			assert.Equal(t, "1.0.0", result.Fields["module_version"])
			assert.Equal(t, "test-tenant-123", result.TenantID)
			assert.Equal(t, "session-456", result.SessionID)
			assert.Equal(t, "500ms", result.Fields["startup_time"])
		}
	}
	assert.True(t, foundModuleEntry, "Expected to find module log entry with context")
}

func TestBackwardCompatibility(t *testing.T) {
	// Test that legacy logger creation still works
	legacyLogger := NewLogger("info")
	require.NotNil(t, legacyLogger)

	// Test that we can call legacy methods
	legacyLogger.Info("Legacy info message", "key", "value")
	legacyLogger.Warn("Legacy warning message")
	legacyLogger.Error("Legacy error message")

	// Test with config
	config := DefaultConfig("test-service", "test-component")
	configLogger := NewLoggerWithConfig(config)
	require.NotNil(t, configLogger)

	configLogger.Info("Config logger message", "configured", true)

	// These should work without panicking (they'll use fallback stdout logging)
	ctx := context.Background()
	configLogger.InfoCtx(ctx, "Context-aware message", "context", "test")
}

func TestLoggingLevelFiltering(t *testing.T) {
	// Create temporary directory for test logs
	tmpDir, err := os.MkdirTemp("", "cfgms-level-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create configuration with WARN level (should filter out DEBUG and INFO)
	config := &LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":      tmpDir,
			"file_prefix":    "level-test",
			"retention_days": 1,
		},
		Level:       "WARN", // Only WARN, ERROR, FATAL should be logged
		ServiceName: "level-test-service",
		Component:   "test",
		AsyncWrites: false,
	}

	manager, err := NewLoggingManager(config)
	require.NoError(t, err)
	defer func() { _ = manager.Close() }()

	ctx := context.Background()

	// Write entries at different levels
	entries := []interfaces.LogEntry{
		{Level: "DEBUG", Message: "Debug message (should be filtered)"},
		{Level: "INFO", Message: "Info message (should be filtered)"},
		{Level: "WARN", Message: "Warning message (should be logged)"},
		{Level: "ERROR", Message: "Error message (should be logged)"},
	}

	for _, entry := range entries {
		err = manager.WriteEntry(ctx, entry)
		assert.NoError(t, err)
	}

	err = manager.Flush(ctx)
	assert.NoError(t, err)

	// Query all entries
	query := interfaces.TimeRangeQuery{
		StartTime: time.Now().Add(-1 * time.Hour),
		EndTime:   time.Now().Add(1 * time.Hour),
		Limit:     10,
	}

	results, err := manager.QueryTimeRange(ctx, query)
	assert.NoError(t, err)
	assert.Len(t, results, 2, "Expected only 2 entries (WARN and ERROR) due to level filtering")

	// Verify only WARN and ERROR entries are present
	levels := make([]string, len(results))
	for i, result := range results {
		levels[i] = result.Level
	}
	assert.Contains(t, levels, "WARN")
	assert.Contains(t, levels, "ERROR")
	assert.NotContains(t, levels, "DEBUG")
	assert.NotContains(t, levels, "INFO")
}
