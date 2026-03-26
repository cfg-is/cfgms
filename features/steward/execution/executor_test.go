// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package execution

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// testFileConfig returns a file resource config appropriate for the current platform.
// On Unix, includes permissions (0644 = 420 decimal). On Windows, omits permissions
// since NTFS does not support Unix-style permission bits.
func testFileConfig(path, content string) string {
	if runtime.GOOS == "windows" {
		return `{
        "path": "` + filepath.ToSlash(path) + `",
        "content": "` + content + `"
      }`
	}
	return `{
        "path": "` + filepath.ToSlash(path) + `",
        "content": "` + content + `",
        "permissions": 420
      }`
}

// testDirConfig returns a directory resource config appropriate for the current platform.
// On Unix, includes permissions (0755 = 493 decimal). On Windows, omits permissions.
func testDirConfig(path string) string {
	if runtime.GOOS == "windows" {
		return `{
        "path": "` + filepath.ToSlash(path) + `"
      }`
	}
	return `{
        "path": "` + filepath.ToSlash(path) + `",
        "permissions": 493
      }`
}

func TestNewExecutor(t *testing.T) {
	logger := logging.ForModule("executor_test")
	executor, err := NewExecutor(&ExecutorConfig{
		TenantID: "test-tenant",
		Logger:   logger,
	})
	require.NoError(t, err)
	assert.NotNil(t, executor)
	assert.NotNil(t, executor.engine)
}

func TestNewExecutor_RequiresLogger(t *testing.T) {
	_, err := NewExecutor(&ExecutorConfig{TenantID: "test"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

func TestExecutor_AllSevenModulesAvailable(t *testing.T) {
	logger := logging.ForModule("executor_test")
	executor, err := NewExecutor(&ExecutorConfig{Logger: logger})
	require.NoError(t, err)

	// All 7 built-in modules must be loadable via the factory
	modules := []string{"file", "directory", "script", "firewall", "package", "patch", "acme"}
	for _, name := range modules {
		mod, err := executor.engine.factory.LoadModule(name)
		assert.NoError(t, err, "module %q should be loadable", name)
		assert.NotNil(t, mod, "module %q should not be nil", name)
	}
}

func TestExecutor_ApplyConfiguration_Success(t *testing.T) {
	tempDir := t.TempDir()
	logger := logging.ForModule("executor_test")

	executor, err := NewExecutor(&ExecutorConfig{
		TenantID: "test-tenant",
		Logger:   logger,
	})
	require.NoError(t, err)

	configJSON := `{
  "steward": {
    "id": "test-steward",
    "mode": "controller"
  },
  "resources": [
    {
      "name": "test-file",
      "module": "file",
      "config": ` + testFileConfig(filepath.Join(tempDir, "test.txt"), "Hello from executor test!\\n") + `
    },
    {
      "name": "test-dir",
      "module": "directory",
      "config": ` + testDirConfig(filepath.Join(tempDir, "testdir")) + `
    }
  ]
}`

	ctx := context.Background()
	report, err := executor.ApplyConfiguration(ctx, []byte(configJSON), "v1.0")
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, "v1.0", report.ConfigVersion)
	assert.Equal(t, "OK", report.Status)
	assert.NotEmpty(t, report.Modules)

	fileStatus, ok := report.Modules["file"]
	assert.True(t, ok, "file module should be in report")
	assert.Equal(t, "OK", fileStatus.Status)

	dirStatus, ok := report.Modules["directory"]
	assert.True(t, ok, "directory module should be in report")
	assert.Equal(t, "OK", dirStatus.Status)

	// Verify file was actually created
	content, err := os.ReadFile(filepath.Join(tempDir, "test.txt"))
	require.NoError(t, err)
	assert.Equal(t, "Hello from executor test!\n", string(content))

	// Verify directory was actually created
	info, err := os.Stat(filepath.Join(tempDir, "testdir"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestExecutor_ApplyConfiguration_WithErrors(t *testing.T) {
	tempDir := t.TempDir()
	logger := logging.ForModule("executor_test")

	executor, err := NewExecutor(&ExecutorConfig{
		TenantID: "test-tenant",
		Logger:   logger,
	})
	require.NoError(t, err)

	// 999999 is an invalid permissions value (> 0777 octal) on all platforms
	configJSON := `{
  "steward": {
    "id": "test-steward",
    "mode": "controller"
  },
  "resources": [
    {
      "name": "invalid-perms-file",
      "module": "file",
      "config": {
        "path": "` + filepath.ToSlash(filepath.Join(tempDir, "invalid.txt")) + `",
        "content": "This will fail\n",
        "permissions": 999999
      }
    },
    {
      "name": "valid-dir",
      "module": "directory",
      "config": ` + testDirConfig(filepath.Join(tempDir, "validdir")) + `
    }
  ]
}`

	ctx := context.Background()
	report, _ := executor.ApplyConfiguration(ctx, []byte(configJSON), "v1.0-fail")

	require.NotNil(t, report, "report should not be nil even with errors")
	assert.Equal(t, "ERROR", report.Status, "overall status should be ERROR")
	assert.NotEmpty(t, report.Modules)

	fileStatus, ok := report.Modules["file"]
	assert.True(t, ok, "file module should be in report")
	assert.Equal(t, "ERROR", fileStatus.Status, "file module should report ERROR")

	dirStatus, ok := report.Modules["directory"]
	assert.True(t, ok, "directory module should be in report")
	assert.Equal(t, "OK", dirStatus.Status, "directory module should succeed")

	// Verify directory was created despite file module failure
	info, err := os.Stat(filepath.Join(tempDir, "validdir"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestExecutor_ApplyConfiguration_InvalidYAML(t *testing.T) {
	logger := logging.ForModule("executor_test")
	executor, err := NewExecutor(&ExecutorConfig{Logger: logger})
	require.NoError(t, err)

	// Use a truly invalid YAML document (tab character where spaces are required)
	invalidYAML := "steward:\n\t id: bad-tabs\n"
	ctx := context.Background()
	report, err := executor.ApplyConfiguration(ctx, []byte(invalidYAML), "v1.0")

	assert.Error(t, err)
	assert.NotNil(t, report)
	assert.Equal(t, "ERROR", report.Status)
}

func TestExecutor_GetCompareSetVerify_Workflow(t *testing.T) {
	// Verify the executor uses Get→Compare→Set→Verify by confirming idempotency:
	// applying the same config twice should succeed both times.
	tempDir := t.TempDir()
	logger := logging.ForModule("executor_test")

	executor, err := NewExecutor(&ExecutorConfig{Logger: logger})
	require.NoError(t, err)

	configJSON := `{
  "steward": {"id": "test-steward", "mode": "controller"},
  "resources": [
    {
      "name": "idempotent-file",
      "module": "file",
      "config": ` + testFileConfig(filepath.Join(tempDir, "idempotent.txt"), "stable content\\n") + `
    }
  ]
}`

	ctx := context.Background()

	// First application — creates the file
	report1, err := executor.ApplyConfiguration(ctx, []byte(configJSON), "v1.0")
	require.NoError(t, err)
	assert.Equal(t, "OK", report1.Status)

	// Second application — file already matches desired state, no change needed
	report2, err := executor.ApplyConfiguration(ctx, []byte(configJSON), "v1.0")
	require.NoError(t, err)
	assert.Equal(t, "OK", report2.Status)
}

func TestExecutor_ApplyConfiguration_PermissionsRejectedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	tempDir := t.TempDir()
	logger := logging.ForModule("executor_test")

	executor, err := NewExecutor(&ExecutorConfig{Logger: logger})
	require.NoError(t, err)

	// On Windows, specifying Unix permissions should produce an error
	configJSON := `{
  "steward": {"id": "test-steward", "mode": "controller"},
  "resources": [
    {
      "name": "perms-rejected",
      "module": "file",
      "config": {
        "path": "` + filepath.ToSlash(filepath.Join(tempDir, "rejected.txt")) + `",
        "content": "should fail on Windows\n",
        "permissions": 420
      }
    }
  ]
}`

	ctx := context.Background()
	report, _ := executor.ApplyConfiguration(ctx, []byte(configJSON), "v1.0")
	require.NotNil(t, report)
	assert.Equal(t, "ERROR", report.Status)

	fileStatus, ok := report.Modules["file"]
	assert.True(t, ok)
	assert.Equal(t, "ERROR", fileStatus.Status)

	// The error text lands in Details["errors"] as a []string, not in Message
	errList, ok := fileStatus.Details["errors"].([]string)
	assert.True(t, ok, "Details[errors] should be a string slice")
	require.NotEmpty(t, errList)
	found := false
	for _, e := range errList {
		if strings.Contains(e, "not supported on this platform") {
			found = true
			break
		}
	}
	assert.True(t, found, fmt.Sprintf("expected error about unsupported permissions, got: %v", errList))
}
