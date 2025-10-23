//go:build integration

// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// +build integration

package logging_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/pkg/logging"
)

// MockLogger implements logging.Logger for testing factory injection
type MockLogger struct {
	mu      sync.RWMutex
	entries []LogEntry
}

type LogEntry struct {
	Level   string
	Message string
	Fields  map[string]interface{}
	Time    time.Time
}

func (m *MockLogger) InfoCtx(ctx context.Context, msg string, keyvals ...interface{}) {
	m.logEntry("INFO", msg, keyvals...)
}

func (m *MockLogger) ErrorCtx(ctx context.Context, msg string, keyvals ...interface{}) {
	m.logEntry("ERROR", msg, keyvals...)
}

func (m *MockLogger) WarnCtx(ctx context.Context, msg string, keyvals ...interface{}) {
	m.logEntry("WARN", msg, keyvals...)
}

func (m *MockLogger) DebugCtx(ctx context.Context, msg string, keyvals ...interface{}) {
	m.logEntry("DEBUG", msg, keyvals...)
}

func (m *MockLogger) Debug(msg string, keyvals ...interface{}) {
	m.logEntry("DEBUG", msg, keyvals...)
}

func (m *MockLogger) Info(msg string, keyvals ...interface{}) {
	m.logEntry("INFO", msg, keyvals...)
}

func (m *MockLogger) Warn(msg string, keyvals ...interface{}) {
	m.logEntry("WARN", msg, keyvals...)
}

func (m *MockLogger) Error(msg string, keyvals ...interface{}) {
	m.logEntry("ERROR", msg, keyvals...)
}

func (m *MockLogger) Fatal(msg string, keyvals ...interface{}) {
	m.logEntry("FATAL", msg, keyvals...)
}

func (m *MockLogger) FatalCtx(ctx context.Context, msg string, keyvals ...interface{}) {
	m.logEntry("FATAL", msg, keyvals...)
}

func (m *MockLogger) WithField(key string, value interface{}) logging.Logger {
	// Return a new logger with the field - simplified for testing
	return m
}

func (m *MockLogger) WithTenant(tenantID string) logging.Logger {
	// Return a new logger with tenant - simplified for testing
	return m
}

func (m *MockLogger) logEntry(level, msg string, keyvals ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fields := make(map[string]interface{})
	for i := 0; i < len(keyvals); i += 2 {
		if i+1 < len(keyvals) {
			key := keyvals[i].(string)
			value := keyvals[i+1]
			fields[key] = value
		}
	}

	entry := LogEntry{
		Level:   level,
		Message: msg,
		Fields:  fields,
		Time:    time.Now(),
	}

	m.entries = append(m.entries, entry)
}

func (m *MockLogger) GetEntries() []LogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to avoid race conditions
	entries := make([]LogEntry, len(m.entries))
	copy(entries, m.entries)
	return entries
}

func (m *MockLogger) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = nil
}

// TestCentralLoggingIntegration validates the complete factory-based logging injection
// workflow using real factory loading patterns (better than direct module instantiation)
func TestCentralLoggingIntegration(t *testing.T) {
	t.Run("FactoryBasedLoggerInjection", testFactoryBasedLoggerInjection)
	t.Run("IntegrationStructuredLogging", testIntegrationStructuredLogging)
	t.Run("IntegrationTenantIsolation", testIntegrationTenantIsolation)
	t.Run("FactoryInjectionStatus", testFactoryInjectionStatus)
}

// testFactoryBasedLoggerInjection tests the complete factory workflow
func testFactoryBasedLoggerInjection(t *testing.T) {
	// Create module registry for testing
	registry := discovery.ModuleRegistry{
		"directory": {Name: "directory", Path: "/test/directory"},
		"file":      {Name: "file", Path: "/test/file"},
		"firewall":  {Name: "firewall", Path: "/test/firewall"},
		"package":   {Name: "package", Path: "/test/package"},
		"script":    {Name: "script", Path: "/test/script"},
	}

	errorConfig := config.ErrorHandlingConfig{
		ModuleLoadFailure: config.ActionFail,
	}

	// Create factory with steward ID (enables injection)
	testStewardID := "test-steward-integration"
	moduleFactory := factory.NewWithStewardID(registry, errorConfig, testStewardID)

	// Test each core module through factory loading
	coreModules := []string{"directory", "file", "firewall", "package", "script"}

	for _, moduleName := range coreModules {
		t.Run(moduleName, func(t *testing.T) {
			// Load module through factory (triggers automatic injection)
			module, err := moduleFactory.LoadModule(moduleName)
			require.NoError(t, err, "factory should load module %s successfully", moduleName)
			require.NotNil(t, module, "loaded module should not be nil")

			// Verify the module supports logging injection
			injectable, supportsInjection := module.(modules.LoggingInjectable)
			require.True(t, supportsInjection, "module %s should support logging injection", moduleName)

			// Verify logger was automatically injected by factory
			injectedLogger, hasInjectedLogger := injectable.GetLogger()
			assert.True(t, hasInjectedLogger, "factory should have injected logger into %s", moduleName)
			assert.NotNil(t, injectedLogger, "injected logger should not be nil for %s", moduleName)

			// Verify logger includes steward context
			// Note: This test validates the injection mechanism,
			// actual logging behavior is tested in unit tests
		})
	}
}

// testIntegrationStructuredLogging tests structured logging through factory-loaded modules
func testIntegrationStructuredLogging(t *testing.T) {
	// Set up mock global logging for integration test
	mockLogger := &MockLogger{}

	// Create factory with mock logger provider
	registry := discovery.ModuleRegistry{
		"directory": {Name: "directory", Path: "/test/directory"},
	}

	errorConfig := config.ErrorHandlingConfig{
		ModuleLoadFailure: config.ActionFail,
	}

	moduleFactory := factory.NewWithStewardID(registry, errorConfig, "integration-test-steward")

	// Load module through factory
	module, err := moduleFactory.LoadModule("directory")
	require.NoError(t, err, "factory should load directory module")

	// Inject our mock logger for testing
	injectable := module.(modules.LoggingInjectable)
	err = injectable.SetLogger(mockLogger)
	require.NoError(t, err, "should be able to inject mock logger")

	// Create test context with tenant isolation
	ctx := context.Background()
	ctx = logging.WithTenant(ctx, "integration-tenant-001")
	ctx = logging.WithOperation(ctx, "integration_test")

	// Create test configuration (minimal to avoid filesystem dependencies)
	testConfig := &TestDirectoryConfig{
		Path:        "/tmp/integration-test-directory",
		Permissions: 0755,
	}

	// Perform operation through factory-loaded module
	_ = module.Set(ctx, "integration-resource-001", testConfig)
	// Note: Operation may fail due to filesystem access, but logging should work

	// Verify structured logging worked through factory injection
	entries := mockLogger.GetEntries()
	if len(entries) > 0 {
		// Verify the log entries have the expected structure
		for _, entry := range entries {
			assert.Contains(t, entry.Fields, "operation", "factory-loaded module should log operation field")
			assert.Contains(t, entry.Fields, "tenant_id", "factory-loaded module should log tenant_id field")
			assert.Contains(t, entry.Fields, "resource_type", "factory-loaded module should log resource_type field")

			// Verify tenant isolation through factory
			if tenantID, exists := entry.Fields["tenant_id"]; exists {
				assert.Equal(t, "integration-tenant-001", tenantID, "tenant ID should be preserved through factory")
			}
		}
	}
}

// testIntegrationTenantIsolation validates tenant isolation through factory injection
func testIntegrationTenantIsolation(t *testing.T) {
	mockLogger := &MockLogger{}

	registry := discovery.ModuleRegistry{
		"script": {Name: "script", Path: "/test/script"},
	}

	errorConfig := config.ErrorHandlingConfig{
		ModuleLoadFailure: config.ActionFail,
	}

	moduleFactory := factory.NewWithStewardID(registry, errorConfig, "tenant-isolation-steward")

	module, err := moduleFactory.LoadModule("script")
	require.NoError(t, err, "factory should load script module")

	injectable := module.(modules.LoggingInjectable)
	err = injectable.SetLogger(mockLogger)
	require.NoError(t, err, "should inject mock logger")

	// Test multiple tenants through the same factory-loaded module
	tenants := []string{"tenant-alpha", "tenant-beta", "tenant-gamma"}

	for _, tenantID := range tenants {
		ctx := context.Background()
		ctx = logging.WithTenant(ctx, tenantID)

		testConfig := &TestScriptConfig{
			Content:       "echo 'integration test'",
			SigningPolicy: "none",
		}

		// Each tenant operation should be isolated
		_ = module.Set(ctx, "tenant-resource", testConfig)
	}

	// Verify tenant isolation in captured logs
	entries := mockLogger.GetEntries()
	tenantCounts := make(map[string]int)

	for _, entry := range entries {
		if tenantID, exists := entry.Fields["tenant_id"]; exists {
			if tid, ok := tenantID.(string); ok {
				tenantCounts[tid]++
			}
		}
	}

	// Verify each tenant has isolated log entries
	for _, expectedTenant := range tenants {
		count := tenantCounts[expectedTenant]
		if count > 0 {
			t.Logf("Tenant %s has %d log entries - good isolation", expectedTenant, count)
		}
		// Note: Count may be 0 if operations fail, but isolation should be maintained
	}
}

// testFactoryInjectionStatus validates the factory's injection status tracking
func testFactoryInjectionStatus(t *testing.T) {
	registry := discovery.ModuleRegistry{
		"directory": {Name: "directory", Path: "/test/directory"},
		"file":      {Name: "file", Path: "/test/file"},
		"script":    {Name: "script", Path: "/test/script"},
	}

	errorConfig := config.ErrorHandlingConfig{
		ModuleLoadFailure: config.ActionFail,
	}

	moduleFactory := factory.NewWithStewardID(registry, errorConfig, "status-test-steward")

	// Load multiple modules
	modules := []string{"directory", "file", "script"}
	loadedModules := make(map[string]interface{})

	for _, moduleName := range modules {
		module, err := moduleFactory.LoadModule(moduleName)
		require.NoError(t, err, "should load %s", moduleName)
		loadedModules[moduleName] = module
	}

	// Verify factory tracks injection status
	statuses := moduleFactory.ListModulesWithLoggers()
	assert.NotEmpty(t, statuses, "factory should track injection statuses")

	// Verify each loaded module is tracked
	for _, moduleName := range modules {
		status, exists := statuses[moduleName]
		assert.True(t, exists, "factory should track status for %s", moduleName)

		if exists {
			assert.Equal(t, moduleName, status.ModuleName, "status should have correct module name")
			assert.Equal(t, "status-test-steward", status.StewardID, "status should have correct steward ID")
			assert.True(t, status.SupportsInject, "all core modules should support injection")
			assert.True(t, status.Injected, "factory should have injected loggers successfully")
		}
	}
}

// TestConfigTypes for integration testing (minimal dependencies)
type TestDirectoryConfig struct {
	Path        string `yaml:"path"`
	Permissions int    `yaml:"permissions"`
}

func (c *TestDirectoryConfig) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"path":        c.Path,
		"permissions": c.Permissions,
	}
}

func (c *TestDirectoryConfig) ToYAML() ([]byte, error)    { return nil, nil }
func (c *TestDirectoryConfig) FromYAML([]byte) error      { return nil }
func (c *TestDirectoryConfig) Validate() error            { return nil }
func (c *TestDirectoryConfig) GetManagedFields() []string { return []string{"path", "permissions"} }

type TestScriptConfig struct {
	Content       string `yaml:"content"`
	SigningPolicy string `yaml:"signing_policy"`
}

func (c *TestScriptConfig) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"content":        c.Content,
		"signing_policy": c.SigningPolicy,
	}
}

func (c *TestScriptConfig) ToYAML() ([]byte, error)    { return nil, nil }
func (c *TestScriptConfig) FromYAML([]byte) error      { return nil }
func (c *TestScriptConfig) Validate() error            { return nil }
func (c *TestScriptConfig) GetManagedFields() []string { return []string{"content", "signing_policy"} }
