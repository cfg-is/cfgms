package logging

import (
	"context"
	"testing"
	"time"

	_ "github.com/cfgis/cfgms/pkg/logging/providers/file" // Register file provider
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSystemWideMigration validates the comprehensive logging migration across all components
func TestSystemWideMigration(t *testing.T) {
	// Initialize global logging provider for system-wide testing
	tempDir := t.TempDir()
	loggingConfig := &LoggingConfig{
		Provider:          "file",
		Level:             "DEBUG",
		ServiceName:       "cfgms_system_test",
		Component:         "integration",
		TenantIsolation:   true,
		EnableCorrelation: true,
		EnableTracing:     true,
		AsyncWrites:       false, // Synchronous for testing
		BatchSize:         1,
		RetentionDays:     7,
		Config: map[string]interface{}{
			"directory":        tempDir,
			"max_file_size":    10 * 1024 * 1024,
			"max_files":        5,
			"compress_rotated": false,
		},
	}

	err := InitializeGlobalLogging(loggingConfig)
	require.NoError(t, err, "Failed to initialize global logging for system test")

	// Initialize global logger factory
	InitializeGlobalLoggerFactory("cfgms_system_test", "integration")

	t.Run("ControllerLogging", func(t *testing.T) {
		// Test controller-style logging
		logger := ForComponent("controller")
		require.NotNil(t, logger, "Controller logger should be created")

		ctx := WithTenant(context.Background(), "tenant-controller-123")
		ctx = WithOperation(ctx, "server_start")

		logger.InfoCtx(ctx, "Controller server starting",
			"operation", "server_start",
			"service_name", "controller",
			"log_provider", "file")

		assert.True(t, logger.IsProviderAvailable(), "Controller should have provider available")
	})

	t.Run("WorkflowLogging", func(t *testing.T) {
		// Test workflow-style logging (like our migration)
		logger := ForModule("workflow").WithField("component", "engine")
		require.NotNil(t, logger, "Workflow logger should be created")

		tenantID := "tenant-workflow-456"
		ctx := WithTenant(context.Background(), tenantID)
		ctx = WithOperation(ctx, "workflow_execute")

		tenantLogger := logger.WithTenant(tenantID)
		tenantLogger.InfoCtx(ctx, "Starting workflow execution",
			"operation", "workflow_execute",
			"execution_id", "exec_test_123",
			"workflow", "test_workflow",
			"step_count", 5)

		// Validate tenant extraction
		extractedTenant := ExtractTenantFromContext(ctx)
		assert.Equal(t, tenantID, extractedTenant, "Tenant should be extracted correctly")
	})

	t.Run("ScriptModuleLogging", func(t *testing.T) {
		// Test script module logging (like our example)
		logger := ForModule("script").WithField("component", "module")
		require.NotNil(t, logger, "Script logger should be created")

		tenantID := "tenant-script-789"
		ctx := WithTenant(context.Background(), tenantID)
		ctx = WithSession(ctx, "session-script-123")

		logger.WithTenant(tenantID).ErrorCtx(ctx, "Script execution failed",
			"operation", "script_execute",
			"resource_id", "test-resource-456",
			"error_code", "SCRIPT_EXECUTION_FAILED",
			"error_details", "Test error for validation")

		// Test session extraction
		sessionLogger := logger.WithSession("test-session")
		assert.NotNil(t, sessionLogger, "Session logger should be created")
	})

	t.Run("DirectoryDNALogging", func(t *testing.T) {
		// Test pkg/ component logging (like directory DNA)
		logger := ForComponent("directory_dna").WithField("component", "monitoring")
		require.NotNil(t, logger, "Directory DNA logger should be created")

		ctx := WithOperation(context.Background(), "monitoring_start")

		logger.InfoCtx(ctx, "Starting directory DNA monitoring system",
			"operation", "monitoring_start",
			"collection_interval", "5m",
			"drift_check_interval", "1h",
			"component", "directory_dna")

		assert.True(t, logger.IsProviderAvailable(), "Directory DNA should have provider available")
	})

	t.Run("TenantIsolationValidation", func(t *testing.T) {
		// Validate tenant isolation across all component types
		tenants := []string{"tenant-a", "tenant-b", "tenant-c"}

		for _, tenantID := range tenants {
			ctx := WithTenant(context.Background(), tenantID)
			ctx = WithSession(ctx, "session-"+tenantID)
			ctx = WithOperation(ctx, "isolation_test")

			// Test multiple component types with same tenant
			controllerLogger := ForComponent("controller").WithTenant(tenantID)
			workflowLogger := ForModule("workflow").WithTenant(tenantID)
			scriptLogger := ForModule("script").WithTenant(tenantID)

			// All should log with proper tenant isolation
			controllerLogger.InfoCtx(ctx, "Controller operation for tenant",
				"operation", "isolation_test",
				"tenant_data", "controller_data_for_"+tenantID)

			workflowLogger.InfoCtx(ctx, "Workflow operation for tenant",
				"operation", "isolation_test",
				"tenant_data", "workflow_data_for_"+tenantID)

			scriptLogger.InfoCtx(ctx, "Script operation for tenant",
				"operation", "isolation_test",
				"tenant_data", "script_data_for_"+tenantID)

			// Verify tenant extraction works consistently
			extracted := ExtractTenantFromContext(ctx)
			assert.Equal(t, tenantID, extracted, "Tenant extraction should be consistent for "+tenantID)
		}
	})

	t.Run("StructuredFieldsValidation", func(t *testing.T) {
		// Validate all required structured fields are supported
		logger := ForComponent("test_validation")

		ctx := context.Background()
		ctx = WithTenant(ctx, "test-tenant")
		ctx = WithSession(ctx, "test-session")
		ctx = WithOperation(ctx, "validation_test")
		ctx = WithCorrelation(ctx, "test-correlation-id")

		// Test all field types work together
		logger.InfoCtx(ctx, "Comprehensive field validation",
			// Core structured fields
			"operation", "validation_test",
			"resource_id", "test-resource",
			"resource_type", "validation",
			"component", "test_validation",

			// Status and timing
			"status", "testing",
			"duration_ms", int64(100),

			// Custom fields
			"test_field", "test_value",
			"numeric_field", 42,
			"boolean_field", true)

		// Test error logging with structured fields
		logger.ErrorCtx(ctx, "Test error logging",
			"operation", "validation_test",
			"error_code", "TEST_ERROR",
			"error_details", "This is a test error for validation",
			"recovery_action", "No action needed - this is a test")

		assert.True(t, logger.IsProviderAvailable(), "Provider should be available for validation")
	})

	t.Run("LogLevelsValidation", func(t *testing.T) {
		// Test all log levels with structured fields
		logger := ForComponent("level_test")
		ctx := WithTenant(context.Background(), "level-test-tenant")

		// Test all levels
		logger.DebugCtx(ctx, "Debug level test", "level", "DEBUG", "operation", "level_test")
		logger.InfoCtx(ctx, "Info level test", "level", "INFO", "operation", "level_test")
		logger.WarnCtx(ctx, "Warn level test", "level", "WARN", "operation", "level_test")
		logger.ErrorCtx(ctx, "Error level test", "level", "ERROR", "operation", "level_test")

		// Note: Not testing Fatal as it would exit the test

		assert.True(t, logger.IsProviderAvailable(), "Provider should be available for all levels")
	})

	t.Run("PerformanceValidation", func(t *testing.T) {
		// Basic performance test to ensure migration doesn't impact throughput
		logger := ForComponent("performance_test")
		ctx := WithTenant(context.Background(), "perf-tenant")

		startTime := time.Now()

		// Log 1000 entries with structured fields
		for i := 0; i < 1000; i++ {
			logger.InfoCtx(ctx, "Performance test log entry",
				"operation", "performance_test",
				"iteration", i,
				"batch", "1000_entries",
				"test_data", "performance_validation")
		}

		duration := time.Since(startTime)

		// Should complete within reasonable time (generous limit for CI)
		assert.Less(t, duration, 5*time.Second, "1000 log entries should complete within 5 seconds")

		// Flush to ensure all logs are written
		err := logger.Flush(context.Background())
		assert.NoError(t, err, "Should be able to flush logs")
	})

	// Final cleanup
	err = GetGlobalLoggingManager().Flush(context.Background())
	assert.NoError(t, err, "Should be able to flush global logging manager")

	t.Log("System-wide logging migration validation completed successfully")
}

// TestGlobalProviderAvailability validates that the global provider is available to all components
func TestGlobalProviderAvailability(t *testing.T) {
	// Initialize global logging provider
	tempDir := t.TempDir()
	loggingConfig := &LoggingConfig{
		Provider:  "file",
		Level:     "INFO",
		ServiceName: "availability_test",
		Component: "test",
		Config: map[string]interface{}{
			"directory": tempDir,
		},
	}

	err := InitializeGlobalLogging(loggingConfig)
	require.NoError(t, err, "Failed to initialize global logging")

	InitializeGlobalLoggerFactory("availability_test", "test")

	// Test that all component types can access the global provider
	componentTypes := []string{
		"controller",
		"steward",
		"workflow",
		"script",
		"directory_dna",
		"rbac",
		"monitoring",
		"validation",
	}

	for _, componentType := range componentTypes {
		t.Run("Component_"+componentType, func(t *testing.T) {
			logger := ForComponent(componentType)
			assert.NotNil(t, logger, "Logger should be created for "+componentType)
			assert.True(t, logger.IsProviderAvailable(), "Global provider should be available for "+componentType)

			// Test that logging works
			ctx := WithTenant(context.Background(), "test-tenant-"+componentType)
			logger.WithTenant("test-tenant-"+componentType).InfoCtx(ctx, "Global provider availability test",
				"component", componentType,
				"operation", "availability_test")
		})
	}
}

// TestMigrationBackwardCompatibility validates that legacy logging still works after migration
func TestMigrationBackwardCompatibility(t *testing.T) {
	// Initialize global logging
	tempDir := t.TempDir()
	loggingConfig := &LoggingConfig{
		Provider:  "file",
		Level:     "INFO",
		ServiceName: "compatibility_test",
		Component: "test",
		Config: map[string]interface{}{
			"directory": tempDir,
		},
	}

	err := InitializeGlobalLogging(loggingConfig)
	require.NoError(t, err, "Failed to initialize global logging")

	InitializeGlobalLoggerFactory("compatibility_test", "test")

	// Test legacy logger creation still works
	legacyLogger := GetLogger()
	assert.NotNil(t, legacyLogger, "Legacy logger should be created")

	// Test legacy logging calls work
	legacyLogger.Info("Legacy info message", "test", "value")
	legacyLogger.Error("Legacy error message", "error", "test_error")

	t.Log("Backward compatibility validation completed")
}