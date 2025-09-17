//go:build !integration
// +build !integration

package logging_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/directory"
	"github.com/cfgis/cfgms/features/modules/file"
	"github.com/cfgis/cfgms/features/modules/firewall"
	package_module "github.com/cfgis/cfgms/features/modules/package"
	"github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestCentralLoggingValidation validates that all modules support centralized logging
// This test ensures Story #166 completion by verifying all components use the global provider
func TestCentralLoggingValidation(t *testing.T) {
	// Initialize global logging provider for testing
	loggingConfig := &logging.LoggingConfig{
		Provider:          "file",
		Level:             "DEBUG",
		ServiceName:       "test-service",
		Component:         "validation",
		TenantIsolation:   true,
		EnableCorrelation: true,
		EnableTracing:     true,
		AsyncWrites:       false, // Synchronous for testing
		BatchSize:         1,
		FlushInterval:     1 * time.Second,
		RetentionDays:     1,
		Config: map[string]interface{}{
			"directory":        "/tmp/cfgms-test-logs",
			"file_prefix":      "test",
			"max_file_size":    1024 * 1024,
			"max_files":        5,
			"compress_rotated": false,
		},
	}

	err := logging.InitializeGlobalLogging(loggingConfig)
	require.NoError(t, err, "global logging initialization should succeed")

	logging.InitializeGlobalLoggerFactory("test-service", "validation")

	t.Run("ModuleFactoryLoggerInjection", func(t *testing.T) {
		testModuleFactoryLoggerInjection(t)
	})

	t.Run("AllBuiltinModulesSupported", func(t *testing.T) {
		testAllBuiltinModulesSupported(t)
	})

	t.Run("StructuredLoggingCompliance", func(t *testing.T) {
		testStructuredLoggingCompliance(t)
	})

	t.Run("TenantIsolationValidation", func(t *testing.T) {
		testTenantIsolationValidation(t)
	})

	t.Run("CentralLoggingControllerVisibility", func(t *testing.T) {
		testCentralLoggingControllerVisibility(t)
	})
}

// testModuleFactoryLoggerInjection validates that the module factory properly injects loggers
func testModuleFactoryLoggerInjection(t *testing.T) {
	// Create test registry
	registry := discovery.ModuleRegistry{
		"directory": {Name: "directory", Path: "/test/directory"},
		"file":      {Name: "file", Path: "/test/file"},
		"firewall":  {Name: "firewall", Path: "/test/firewall"},
		"package":   {Name: "package", Path: "/test/package"},
		"script":    {Name: "script", Path: "/test/script"},
	}

	// Create factory with steward ID
	stewardID := "test-steward-001"
	errorConfig := config.ErrorHandlingConfig{
		ModuleLoadFailure: config.ActionFail,
	}
	moduleFactory := factory.NewWithStewardID(registry, errorConfig, stewardID)

	// Test each module type
	testCases := []struct {
		moduleName string
		newFunc    func() modules.Module
	}{
		{"directory", directory.New},
		{"file", file.New},
		{"firewall", firewall.New},
		{"package", package_module.New},
		{"script", script.New},
	}

	for _, tc := range testCases {
		t.Run(tc.moduleName, func(t *testing.T) {
			// Create module instance
			module := tc.newFunc()

			// Check if module supports injection
			injectable, supportsInjection := module.(modules.LoggingInjectable)
			assert.True(t, supportsInjection, "module %s should support logging injection", tc.moduleName)

			if supportsInjection {
				// Test factory injection
				injected, err := moduleFactory.InjectLogger(module, tc.moduleName)
				assert.NoError(t, err, "logger injection should succeed for %s", tc.moduleName)
				assert.True(t, injected, "logger should be injected for %s", tc.moduleName)

				// Verify injection
				logger, hasLogger := injectable.GetLogger()
				assert.True(t, hasLogger, "module %s should have injected logger", tc.moduleName)
				assert.NotNil(t, logger, "injected logger should not be nil for %s", tc.moduleName)

				// Test logging functionality
				ctx := context.Background()
				ctx = logging.WithTenant(ctx, "test-tenant")
				ctx = logging.WithSession(ctx, "test-session")

				// This should not panic and should work with injected logger
				logger.InfoCtx(ctx, "Test log entry from injected logger",
					"operation", "validation_test",
					"module", tc.moduleName,
					"test_type", "injection_validation")
			}
		})
	}

	// Test injection status tracking
	statuses := moduleFactory.ListModulesWithLoggers()
	assert.NotEmpty(t, statuses, "factory should track injection statuses")

	for moduleName := range registry {
		status, exists := statuses[moduleName]
		assert.True(t, exists, "status should exist for module %s", moduleName)
		assert.True(t, status.SupportsInject, "module %s should support injection", moduleName)
		assert.Equal(t, stewardID, status.StewardID, "steward ID should match for %s", moduleName)
	}
}

// testAllBuiltinModulesSupported validates that all built-in modules support logging injection
func testAllBuiltinModulesSupported(t *testing.T) {
	builtinModules := map[string]func() modules.Module{
		"directory": directory.New,
		"file":      file.New,
		"firewall":  firewall.New,
		"package":   package_module.New,
		"script":    script.New,
	}

	for moduleName, newFunc := range builtinModules {
		t.Run(moduleName, func(t *testing.T) {
			module := newFunc()

			// Verify module implements LoggingInjectable
			injectable, supportsInjection := module.(modules.LoggingInjectable)
			assert.True(t, supportsInjection, "module %s must support logging injection", moduleName)

			if supportsInjection {
				// Test injection capability
				logger := logging.ForModule(moduleName)
				err := injectable.SetLogger(logger)
				assert.NoError(t, err, "logger injection should work for %s", moduleName)

				// Verify injection worked
				retrievedLogger, hasLogger := injectable.GetLogger()
				assert.True(t, hasLogger, "module should report having logger")
				assert.NotNil(t, retrievedLogger, "retrieved logger should not be nil")
			}
		})
	}
}

// testStructuredLoggingCompliance validates structured logging field consistency
func testStructuredLoggingCompliance(t *testing.T) {
	// Create a mock logger to capture log entries
	mockLogger := &MockLogger{}

	// Test with directory module (representative of migrated modules)
	module := directory.New()
	injectable, ok := module.(modules.LoggingInjectable)
	require.True(t, ok, "directory module should support injection")

	err := injectable.SetLogger(mockLogger)
	require.NoError(t, err, "logger injection should succeed")

	// Create test context with required fields
	ctx := context.Background()
	ctx = logging.WithTenant(ctx, "test-tenant-123")
	ctx = logging.WithSession(ctx, "test-session-456")
	ctx = logging.WithOperation(ctx, "validation_test")

	// Create test configuration
	testConfig := &TestDirectoryConfig{
		Path:        "/tmp/test-directory",
		Permissions: 0755,
	}

	// Perform operation that should generate structured logs
	_ = module.Set(ctx, "test-resource-001", testConfig)
	// Note: This may fail due to actual filesystem operations, but we're testing logging

	// Verify structured log entries were created
	entries := mockLogger.GetEntries()
	assert.NotEmpty(t, entries, "module operation should generate log entries")

	for _, entry := range entries {
		// Verify required structured fields are present
		assert.Contains(t, entry.Fields, "operation", "log entry should contain operation field")
		assert.Contains(t, entry.Fields, "resource_id", "log entry should contain resource_id field")
		assert.Contains(t, entry.Fields, "tenant_id", "log entry should contain tenant_id field")
		assert.Contains(t, entry.Fields, "resource_type", "log entry should contain resource_type field")

		// Verify field values are correct
		assert.Equal(t, "test-tenant-123", entry.Fields["tenant_id"], "tenant_id should match context")
		assert.Equal(t, "test-resource-001", entry.Fields["resource_id"], "resource_id should match parameter")
		assert.Contains(t, entry.Fields["operation"], "directory", "operation should reference module")
	}
}

// testTenantIsolationValidation validates tenant isolation in logging
func testTenantIsolationValidation(t *testing.T) {
	mockLogger := &MockLogger{}

	module := script.New() // Script module has full tenant isolation support
	injectable, ok := module.(modules.LoggingInjectable)
	require.True(t, ok, "script module should support injection")

	err := injectable.SetLogger(mockLogger)
	require.NoError(t, err, "logger injection should succeed")

	// Test with different tenants
	tenants := []string{"tenant-001", "tenant-002", "tenant-003"}

	for _, tenantID := range tenants {
		ctx := context.Background()
		ctx = logging.WithTenant(ctx, tenantID)

		// Create minimal script config for testing
		scriptConfig := &TestScriptConfig{
			Content:       "echo 'test'",
			SigningPolicy: "none",
		}

		// Perform operation
		_ = module.Set(ctx, "script-resource", scriptConfig)
		// May fail due to execution, but logging should work
	}

	// Verify tenant isolation in log entries
	entries := mockLogger.GetEntries()
	tenantCounts := make(map[string]int)

	for _, entry := range entries {
		if tenantID, exists := entry.Fields["tenant_id"]; exists {
			if tid, ok := tenantID.(string); ok {
				tenantCounts[tid]++
			}
		}
	}

	// Verify all tenants are represented and isolated
	for _, tenantID := range tenants {
		count := tenantCounts[tenantID]
		assert.Greater(t, count, 0, "tenant %s should have log entries", tenantID)
	}

	// Verify no cross-tenant contamination
	for _, entry := range entries {
		tenantID := entry.Fields["tenant_id"].(string)
		assert.Contains(t, tenants, tenantID, "all tenant IDs should be from test set")
	}
}

// testCentralLoggingControllerVisibility validates controller visibility requirements
func testCentralLoggingControllerVisibility(t *testing.T) {
	// This test validates that the controller can see all steward activities
	// through the centralized logging system

	// Create multiple stewards with different IDs
	stewardIDs := []string{"steward-001", "steward-002", "steward-003"}
	factoryMap := make(map[string]*factory.ModuleFactory)

	registry := discovery.ModuleRegistry{
		"directory": {Name: "directory", Path: "/test/directory"},
		"script":    {Name: "script", Path: "/test/script"},
	}

	errorConfig := config.ErrorHandlingConfig{
		ModuleLoadFailure: config.ActionFail,
	}

	// Create factories for each steward
	for _, stewardID := range stewardIDs {
		moduleFactory := factory.NewWithStewardID(registry, errorConfig, stewardID)
		factoryMap[stewardID] = moduleFactory
	}

	// Simulate operations from each steward
	for stewardID, moduleFactory := range factoryMap {
		t.Run("steward_"+stewardID, func(t *testing.T) {
			// Load and test directory module
			module := directory.New()
			injected, err := moduleFactory.InjectLogger(module, "directory")
			assert.NoError(t, err, "injection should succeed")
			assert.True(t, injected, "logger should be injected")

			// Verify steward-specific context
			injectable := module.(modules.LoggingInjectable)
			logger, hasLogger := injectable.GetLogger()
			require.True(t, hasLogger, "module should have logger")
			require.NotNil(t, logger, "logger should not be nil")

			// Test logging with steward context
			ctx := context.Background()
			ctx = logging.WithTenant(ctx, "tenant-"+stewardID)

			logger.InfoCtx(ctx, "Steward operation for controller visibility",
				"operation", "central_visibility_test",
				"steward_id", stewardID,
				"module", "directory",
				"visibility", "controller_monitoring")
		})
	}

	// Verify controller can monitor all steward activities
	for stewardID, moduleFactory := range factoryMap {
		statuses := moduleFactory.ListModulesWithLoggers()
		assert.NotEmpty(t, statuses, "steward %s should have injection statuses", stewardID)

		for moduleName, status := range statuses {
			assert.Equal(t, stewardID, status.StewardID, "status should have correct steward ID")
			assert.True(t, status.Injected, "module %s should be injected in steward %s", moduleName, stewardID)
		}
	}
}

// Mock implementations for testing

type MockLogger struct {
	entries []MockLogEntry
}

type MockLogEntry struct {
	Level   string
	Message string
	Fields  map[string]interface{}
	Context context.Context
}

func (m *MockLogger) InfoCtx(ctx context.Context, msg string, fields ...interface{}) {
	entry := MockLogEntry{
		Level:   "INFO",
		Message: msg,
		Fields:  make(map[string]interface{}),
		Context: ctx,
	}

	// Parse fields
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			entry.Fields[key] = fields[i+1]
		}
	}

	m.entries = append(m.entries, entry)
}

func (m *MockLogger) ErrorCtx(ctx context.Context, msg string, fields ...interface{}) {
	entry := MockLogEntry{
		Level:   "ERROR",
		Message: msg,
		Fields:  make(map[string]interface{}),
		Context: ctx,
	}

	// Parse fields
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			entry.Fields[key] = fields[i+1]
		}
	}

	m.entries = append(m.entries, entry)
}

func (m *MockLogger) WarnCtx(ctx context.Context, msg string, fields ...interface{}) {
	entry := MockLogEntry{
		Level:   "WARN",
		Message: msg,
		Fields:  make(map[string]interface{}),
		Context: ctx,
	}

	// Parse fields
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			entry.Fields[key] = fields[i+1]
		}
	}

	m.entries = append(m.entries, entry)
}

func (m *MockLogger) DebugCtx(ctx context.Context, msg string, fields ...interface{}) {
	entry := MockLogEntry{
		Level:   "DEBUG",
		Message: msg,
		Fields:  make(map[string]interface{}),
		Context: ctx,
	}

	// Parse fields
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			entry.Fields[key] = fields[i+1]
		}
	}

	m.entries = append(m.entries, entry)
}

func (m *MockLogger) Debug(msg string, fields ...interface{}) {
	entry := MockLogEntry{
		Level:   "DEBUG",
		Message: msg,
		Fields:  make(map[string]interface{}),
		Context: context.Background(),
	}

	// Parse fields
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			entry.Fields[key] = fields[i+1]
		}
	}

	m.entries = append(m.entries, entry)
}

func (m *MockLogger) Info(msg string, fields ...interface{}) {
	entry := MockLogEntry{
		Level:   "INFO",
		Message: msg,
		Fields:  make(map[string]interface{}),
		Context: context.Background(),
	}

	// Parse fields
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			entry.Fields[key] = fields[i+1]
		}
	}

	m.entries = append(m.entries, entry)
}

func (m *MockLogger) Warn(msg string, fields ...interface{}) {
	entry := MockLogEntry{
		Level:   "WARN",
		Message: msg,
		Fields:  make(map[string]interface{}),
		Context: context.Background(),
	}

	// Parse fields
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			entry.Fields[key] = fields[i+1]
		}
	}

	m.entries = append(m.entries, entry)
}

func (m *MockLogger) Error(msg string, fields ...interface{}) {
	entry := MockLogEntry{
		Level:   "ERROR",
		Message: msg,
		Fields:  make(map[string]interface{}),
		Context: context.Background(),
	}

	// Parse fields
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			entry.Fields[key] = fields[i+1]
		}
	}

	m.entries = append(m.entries, entry)
}

func (m *MockLogger) Fatal(msg string, fields ...interface{}) {
	entry := MockLogEntry{
		Level:   "FATAL",
		Message: msg,
		Fields:  make(map[string]interface{}),
		Context: context.Background(),
	}

	// Parse fields
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			entry.Fields[key] = fields[i+1]
		}
	}

	m.entries = append(m.entries, entry)
}

func (m *MockLogger) FatalCtx(ctx context.Context, msg string, fields ...interface{}) {
	entry := MockLogEntry{
		Level:   "FATAL",
		Message: msg,
		Fields:  make(map[string]interface{}),
		Context: ctx,
	}

	// Parse fields
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			entry.Fields[key] = fields[i+1]
		}
	}

	m.entries = append(m.entries, entry)
}

func (m *MockLogger) WithField(key string, value interface{}) logging.Logger {
	return m // Simplified for testing
}

func (m *MockLogger) GetEntries() []MockLogEntry {
	return m.entries
}

// Test configuration implementations

type TestDirectoryConfig struct {
	Path        string
	Permissions int
}

func (c *TestDirectoryConfig) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"path":        c.Path,
		"permissions": c.Permissions,
	}
}

func (c *TestDirectoryConfig) ToYAML() ([]byte, error) {
	return []byte{}, nil
}

func (c *TestDirectoryConfig) FromYAML(data []byte) error {
	return nil
}

func (c *TestDirectoryConfig) Validate() error {
	return nil
}

func (c *TestDirectoryConfig) GetManagedFields() []string {
	return []string{"path", "permissions"}
}

type TestScriptConfig struct {
	Content       string
	SigningPolicy string
}

func (c *TestScriptConfig) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"content":        c.Content,
		"signing_policy": c.SigningPolicy,
	}
}

func (c *TestScriptConfig) ToYAML() ([]byte, error) {
	return []byte{}, nil
}

func (c *TestScriptConfig) FromYAML(data []byte) error {
	return nil
}

func (c *TestScriptConfig) Validate() error {
	return nil
}

func (c *TestScriptConfig) GetManagedFields() []string {
	return []string{"content", "signing_policy"}
}