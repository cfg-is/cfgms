// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package script

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file" // Register file provider
)

// TestLoggingMigration validates that the script module uses the global logging provider correctly
func TestLoggingMigration(t *testing.T) {
	// Initialize global logging provider for testing
	tempDir := t.TempDir()
	loggingConfig := &logging.LoggingConfig{
		Provider:          "file", // Use file provider for testing
		Level:             "DEBUG",
		ServiceName:       "test",
		Component:         "script_test",
		TenantIsolation:   true,
		EnableCorrelation: true,
		EnableTracing:     true,
		AsyncWrites:       false, // Synchronous for testing
		BatchSize:         1,
		Config: map[string]interface{}{
			"directory":     tempDir,
			"max_file_size": 10 * 1024 * 1024, // 10MB
			"max_files":     5,
		},
	}

	err := logging.InitializeGlobalLogging(loggingConfig)
	require.NoError(t, err, "Failed to initialize global logging")

	// Initialize global logger factory
	logging.InitializeGlobalLoggerFactory("test", "script_test")

	// Ensure cleanup of logging provider on test completion (critical for Windows file locking)
	// Use t.Cleanup() to ensure this runs before t.TempDir() cleanup
	t.Cleanup(func() {
		if manager := logging.GetGlobalLoggingManager(); manager != nil {
			// Flush all pending writes
			_ = manager.Flush(context.Background())
			// Close the provider to release file handles
			_ = manager.Close()
			// On Windows, give the filesystem extra time to release the handle
			if runtime.GOOS == "windows" {
				time.Sleep(250 * time.Millisecond)
			}
		}
	})

	// Create a new module instance
	module := NewModule()

	// Verify that the module has a logger configured
	assert.NotNil(t, module.logger, "Module should have a logger configured")

	// Test that the logger is properly configured for the module
	assert.True(t, module.logger.IsProviderAvailable(), "Global logging provider should be available")

	// Create a context with tenant information
	tenantID := "test-tenant-123"
	sessionID := "test-session-456"
	ctx := context.Background()
	ctx = logging.WithTenant(ctx, tenantID)
	ctx = logging.WithSession(ctx, sessionID)
	ctx = logging.WithOperation(ctx, "test_operation")

	// Test that tenant context extraction works
	extractedTenant := logging.ExtractTenantFromContext(ctx)
	assert.Equal(t, tenantID, extractedTenant, "Tenant ID should be extracted correctly from context")

	// Create a test script configuration
	// Use platform-appropriate shell
	shell := ShellBash
	scriptContent := "echo 'Hello World'"
	if runtime.GOOS == "windows" {
		shell = ShellPowerShell
		scriptContent = "Write-Output 'Hello World'"
	}
	scriptConfig := &ScriptConfig{
		Content:       scriptContent,
		Shell:         shell,
		Timeout:       30 * time.Second,
		SigningPolicy: SigningPolicyNone,
	}

	// Test that the module logs properly during operation
	// This will trigger the logging in the Set method
	err = module.Set(ctx, "test-resource-123", scriptConfig)

	// The script execution might fail in test environment, but logging should work
	// We're primarily testing that no panics occur and the logging integration works
	t.Logf("Script execution result: %v", err)

	// Verify the module can flush logs if needed
	err = module.logger.Flush(context.Background())
	assert.NoError(t, err, "Should be able to flush logs without error")
}

// TestStructuredLoggingFields validates that structured logging fields are properly used
func TestStructuredLoggingFields(t *testing.T) {
	// Initialize global logging provider for testing
	tempDir := t.TempDir()
	loggingConfig := &logging.LoggingConfig{
		Provider:          "file",
		Level:             "DEBUG",
		ServiceName:       "test",
		Component:         "script_test",
		TenantIsolation:   true,
		EnableCorrelation: true,
		Config: map[string]interface{}{
			"directory":     tempDir,
			"max_file_size": 10 * 1024 * 1024,
			"max_files":     5,
		},
	}

	err := logging.InitializeGlobalLogging(loggingConfig)
	require.NoError(t, err, "Failed to initialize global logging")

	// Initialize global logger factory
	logging.InitializeGlobalLoggerFactory("test", "script_test")

	// Ensure cleanup of logging provider on test completion (critical for Windows file locking)
	// Use t.Cleanup() to ensure this runs before t.TempDir() cleanup
	t.Cleanup(func() {
		if manager := logging.GetGlobalLoggingManager(); manager != nil {
			// Flush all pending writes
			_ = manager.Flush(context.Background())
			// Close the provider to release file handles
			_ = manager.Close()
			// On Windows, give the filesystem extra time to release the handle
			if runtime.GOOS == "windows" {
				time.Sleep(250 * time.Millisecond)
			}
		}
	})

	// Create module with tenant context
	module := NewModule()
	tenantID := "test-tenant-456"
	resourceID := "test-resource-789"

	// Create context with multiple structured fields
	ctx := context.Background()
	ctx = logging.WithTenant(ctx, tenantID)
	ctx = logging.WithSession(ctx, "session-789")
	ctx = logging.WithOperation(ctx, "script_execute")
	ctx = logging.WithCorrelation(ctx, "correlation-456")

	// Test WithTenant method on logger
	tenantLogger := module.logger.WithTenant(tenantID)
	assert.NotNil(t, tenantLogger, "WithTenant should return a valid logger")

	// Test WithSession method on logger
	sessionLogger := module.logger.WithSession("test-session")
	assert.NotNil(t, sessionLogger, "WithSession should return a valid logger")

	// Test WithField method on logger
	fieldLogger := module.logger.WithField("test_field", "test_value")
	assert.NotNil(t, fieldLogger, "WithField should return a valid logger")

	// Test that structured logging doesn't cause panics
	tenantLogger.InfoCtx(ctx, "Test structured logging",
		"operation", "test",
		"resource_id", resourceID,
		"resource_type", "script",
		"test_field", "test_value")

	// Test error logging with structured fields
	tenantLogger.ErrorCtx(ctx, "Test error logging",
		"operation", "test",
		"resource_id", resourceID,
		"error_code", "TEST_ERROR",
		"error_details", "This is a test error")

	t.Log("Structured logging test completed successfully")
}

// TestTenantIsolation validates that tenant isolation works correctly
func TestTenantIsolation(t *testing.T) {
	// Initialize global logging provider for testing
	tempDir := t.TempDir()
	loggingConfig := &logging.LoggingConfig{
		Provider:          "file",
		Level:             "DEBUG",
		ServiceName:       "test",
		Component:         "script_test",
		TenantIsolation:   true, // Enable tenant isolation
		EnableCorrelation: true,
		Config: map[string]interface{}{
			"directory":     tempDir,
			"max_file_size": 10 * 1024 * 1024,
			"max_files":     5,
		},
	}

	err := logging.InitializeGlobalLogging(loggingConfig)
	require.NoError(t, err, "Failed to initialize global logging")

	logging.InitializeGlobalLoggerFactory("test", "script_test")

	// Ensure cleanup of logging provider on test completion (critical for Windows file locking)
	// Use t.Cleanup() to ensure this runs before t.TempDir() cleanup
	t.Cleanup(func() {
		if manager := logging.GetGlobalLoggingManager(); manager != nil {
			// Flush all pending writes
			_ = manager.Flush(context.Background())
			// Close the provider to release file handles
			_ = manager.Close()
			// On Windows, give the filesystem extra time to release the handle
			if runtime.GOOS == "windows" {
				time.Sleep(250 * time.Millisecond)
			}
		}
	})

	module := NewModule()

	// Test multiple tenants in isolation
	tenant1 := "tenant-1"
	tenant2 := "tenant-2"

	ctx1 := logging.WithTenant(context.Background(), tenant1)
	ctx2 := logging.WithTenant(context.Background(), tenant2)

	// Create tenant-specific loggers
	logger1 := module.logger.WithTenant(tenant1)
	logger2 := module.logger.WithTenant(tenant2)

	// Log operations for different tenants
	logger1.InfoCtx(ctx1, "Operation for tenant 1",
		"operation", "tenant_test",
		"resource_id", "resource-1",
		"tenant_specific_data", "data-for-tenant-1")

	logger2.InfoCtx(ctx2, "Operation for tenant 2",
		"operation", "tenant_test",
		"resource_id", "resource-2",
		"tenant_specific_data", "data-for-tenant-2")

	// Verify context extraction works correctly
	extracted1 := logging.ExtractTenantFromContext(ctx1)
	extracted2 := logging.ExtractTenantFromContext(ctx2)

	assert.Equal(t, tenant1, extracted1, "Should extract correct tenant ID for tenant 1")
	assert.Equal(t, tenant2, extracted2, "Should extract correct tenant ID for tenant 2")
	assert.NotEqual(t, extracted1, extracted2, "Different tenants should have different IDs")

	t.Log("Tenant isolation test completed successfully")
}
