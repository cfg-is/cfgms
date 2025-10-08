package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutor_ApplyConfiguration_Success(t *testing.T) {
	// Create temp directory for test files
	tempDir := t.TempDir()

	// Create logger
	logger := logging.ForModule("executor_test")

	// Create executor
	cfg := &Config{
		TenantID: "test-tenant",
		Logger:   logger,
	}
	executor, err := New(cfg)
	require.NoError(t, err, "Failed to create executor")

	// Test configuration YAML
	// Note: permissions use octal notation (0644, 0755)
	configYAML := `
version: "1.0"
modules:
  file:
    - name: "test-file"
      resource_id: "` + filepath.Join(tempDir, "test.txt") + `"
      state: "present"
      config:
        content: "Hello from executor test!\n"
        permissions: 0644

  directory:
    - name: "test-dir"
      resource_id: "` + filepath.Join(tempDir, "testdir") + `"
      state: "present"
      config:
        permissions: 0755
`

	// Apply configuration
	ctx := context.Background()
	report, err := executor.ApplyConfiguration(ctx, []byte(configYAML), "v1.0")
	require.NoError(t, err, "Configuration application failed")
	require.NotNil(t, report, "Report should not be nil")

	// Verify report
	assert.Equal(t, "v1.0", report.ConfigVersion)
	assert.Equal(t, "OK", report.Status)
	assert.NotEmpty(t, report.Modules)

	// Verify file module status
	fileStatus, ok := report.Modules["file"]
	assert.True(t, ok, "File module should be in report")
	assert.Equal(t, "OK", fileStatus.Status)

	// Verify directory module status
	dirStatus, ok := report.Modules["directory"]
	assert.True(t, ok, "Directory module should be in report")
	assert.Equal(t, "OK", dirStatus.Status)

	// Verify actual file was created
	fileContent, err := os.ReadFile(filepath.Join(tempDir, "test.txt"))
	require.NoError(t, err, "Should be able to read created file")
	assert.Equal(t, "Hello from executor test!\n", string(fileContent))

	// Verify actual directory was created
	dirInfo, err := os.Stat(filepath.Join(tempDir, "testdir"))
	require.NoError(t, err, "Directory should exist")
	assert.True(t, dirInfo.IsDir(), "Should be a directory")
}

func TestExecutor_ApplyConfiguration_WithErrors(t *testing.T) {
	// Create temp directory for test files
	tempDir := t.TempDir()

	// Create logger
	logger := logging.ForModule("executor_test")

	// Create executor
	cfg := &Config{
		TenantID: "test-tenant",
		Logger:   logger,
	}
	executor, err := New(cfg)
	require.NoError(t, err, "Failed to create executor")

	// Test configuration with invalid permissions
	configYAML := `
version: "1.0"
modules:
  file:
    - name: "invalid-perms-file"
      resource_id: "` + filepath.Join(tempDir, "invalid.txt") + `"
      state: "present"
      config:
        content: "This will fail\n"
        permissions: 999999

  directory:
    - name: "valid-dir"
      resource_id: "` + filepath.Join(tempDir, "validdir") + `"
      state: "present"
      config:
        permissions: 0755
`

	// Apply configuration
	ctx := context.Background()
	report, err := executor.ApplyConfiguration(ctx, []byte(configYAML), "v1.0-fail")

	// Configuration parsing should succeed but application should report errors
	require.NotNil(t, report, "Report should not be nil even with errors")

	// Verify report indicates errors
	assert.Equal(t, "ERROR", report.Status, "Overall status should be ERROR")
	assert.NotEmpty(t, report.Modules)

	// Verify file module reported error
	fileStatus, ok := report.Modules["file"]
	assert.True(t, ok, "File module should be in report")
	assert.Equal(t, "ERROR", fileStatus.Status, "File module should report ERROR")

	// Verify directory module succeeded despite file module failure
	dirStatus, ok := report.Modules["directory"]
	assert.True(t, ok, "Directory module should be in report")
	assert.Equal(t, "OK", dirStatus.Status, "Directory module should succeed")

	// Verify directory was actually created
	dirInfo, err := os.Stat(filepath.Join(tempDir, "validdir"))
	require.NoError(t, err, "Directory should exist despite file module failure")
	assert.True(t, dirInfo.IsDir())
}

func TestExecutor_ModuleRegistration(t *testing.T) {
	logger := logging.ForModule("executor_test")

	cfg := &Config{
		TenantID: "test-tenant",
		Logger:   logger,
	}
	executor, err := New(cfg)
	require.NoError(t, err, "Failed to create executor")

	// Verify built-in modules are registered
	executor.mu.RLock()
	defer executor.mu.RUnlock()

	assert.Contains(t, executor.modules, "file", "File module should be registered")
	assert.Contains(t, executor.modules, "directory", "Directory module should be registered")
	assert.Contains(t, executor.modules, "script", "Script module should be registered")
}
