// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package execution_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/execution"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"
)

// testFileConfig returns a file resource config appropriate for the current platform.
// On Unix, includes permissions (0644 = 420 decimal). On Windows, omits permissions
// since NTFS does not support Unix-style permission bits.
// Always includes "state": "present" so the genericConfigState comparator has a
// managed field to compare (path is excluded as an identifier field).
func testFileConfig(path, content string) string {
	dir := filepath.ToSlash(filepath.Dir(path))
	if runtime.GOOS == "windows" {
		return `{
        "state": "present",
        "path": "` + filepath.ToSlash(path) + `",
        "content": "` + content + `",
        "allowed_base_path": "` + dir + `"
      }`
	}
	return `{
        "path": "` + filepath.ToSlash(path) + `",
        "content": "` + content + `",
        "permissions": 420,
        "allowed_base_path": "` + dir + `"
      }`
}

// testDirConfig returns a directory resource config appropriate for the current platform.
// On Unix, includes permissions (0755 = 493 decimal). On Windows, omits permissions.
// Always includes "state": "present" so the genericConfigState comparator has a
// managed field to compare (path is excluded as an identifier field).
// allowed_base_path is set to the parent of path to satisfy the mandatory security boundary.
func testDirConfig(path string) string {
	parent := filepath.ToSlash(filepath.Dir(path))
	if runtime.GOOS == "windows" {
		return `{
        "state": "present",
        "allowed_base_path": "` + parent + `",
        "path": "` + filepath.ToSlash(path) + `"
      }`
	}
	return `{
        "allowed_base_path": "` + parent + `",
        "path": "` + filepath.ToSlash(path) + `",
        "permissions": 493
      }`
}

func TestNewExecutor(t *testing.T) {
	logger := logging.ForModule("executor_test")
	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		TenantID: "test-tenant",
		Logger:   logger,
	})
	require.NoError(t, err)
	assert.NotNil(t, executor)
	// Constructor success proves wiring; ExecuteConfiguration without error confirms
	// factory and comparator are operational end-to-end.
}

func TestNewExecutor_RequiresLogger(t *testing.T) {
	_, err := execution.NewExecutor(&execution.ExecutorConfig{TenantID: "test"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

func TestExecutor_AllSevenModulesAvailable(t *testing.T) {
	logger := logging.ForModule("executor_test")
	executor, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: logger})
	require.NoError(t, err)

	// All 7 built-in modules must be loadable via the factory
	modules := []string{"file", "directory", "script", "firewall", "package", "patch", "acme"}
	for _, name := range modules {
		mod, err := execution.ExecutorFactory(executor).LoadModule(name)
		assert.NoError(t, err, "module %q should be loadable", name)
		assert.NotNil(t, mod, "module %q should not be nil", name)
	}
}

func TestExecutor_ApplyConfiguration_Success(t *testing.T) {
	tempDir := t.TempDir()
	logger := logging.ForModule("executor_test")

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
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

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
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
	// Resource execution failures are reported via report.Status, not returned as error.
	// ApplyConfiguration only returns a non-nil error for config parsing failures.
	report, applyErr := executor.ApplyConfiguration(ctx, []byte(configJSON), "v1.0-fail")
	require.NoError(t, applyErr, "resource execution failures must not surface as error return")

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
	executor, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: logger})
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

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: logger})
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

// TestExecuteResource_ApplyMode_CallsSet asserts that module.Set() is called when
// drift is detected in apply mode, preserving existing behavior bit-for-bit.
func TestExecuteResource_ApplyMode_CallsSet(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not applicable on Windows; no Windows equivalent for this test")
	}
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "apply_test.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("initial content\n"), 0644))

	logger := logging.ForModule("executor_test")
	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:    logger,
		DriftMode: stewardconfig.DriftModeApply,
	})
	require.NoError(t, err)

	var handlerFired int32
	executor.SetDriftEventHandler(func(rn, mn string, diff *stewardtesting.StateDiff) {
		atomic.AddInt32(&handlerFired, 1)
		assert.Equal(t, "drift.detected", diff.EventType, "apply mode must emit drift.detected event type")
	})

	resource := stewardconfig.ResourceConfig{
		Name:   "apply-test-file",
		Module: "file",
		Config: map[string]interface{}{
			"path":              filepath.ToSlash(filePath),
			"content":           "desired content\n",
			"permissions":       420, // 0644 octal
			"allowed_base_path": filepath.ToSlash(tempDir),
		},
	}

	ctx := context.Background()
	result := executor.ExecuteResource(ctx, resource)

	assert.Equal(t, execution.StatusSuccess, result.Status, "apply mode must correct drift and return StatusSuccess")
	assert.True(t, result.DriftDetected, "drift must be detected")
	assert.True(t, result.ChangesApplied, "Set() must be called in apply mode")
	assert.Equal(t, int32(1), atomic.LoadInt32(&handlerFired), "DriftEventHandler must fire once")

	// Verify Set() actually ran — file must contain desired content.
	got, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, "desired content\n", string(got), "file content must be updated by Set()")
}

// TestExecuteResource_MonitorMode_SkipsSet asserts that in monitor mode:
//   - module.Set() and module.Verify() are NOT called
//   - ResourceResult.Status is StatusNonCompliant
//   - DriftEventHandler fires before the early return (ordering preserved)
//   - The emitted event type is "drift.detected.monitor"
func TestExecuteResource_MonitorMode_SkipsSet(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not applicable on Windows; no Windows equivalent for this test")
	}
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "monitor_test.txt")
	initialContent := "initial content\n"
	require.NoError(t, os.WriteFile(filePath, []byte(initialContent), 0644))

	logger := logging.ForModule("executor_test")
	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:    logger,
		DriftMode: stewardconfig.DriftModeMonitor,
	})
	require.NoError(t, err)

	var handlerFired int32
	var capturedEventType string
	executor.SetDriftEventHandler(func(rn, mn string, diff *stewardtesting.StateDiff) {
		atomic.AddInt32(&handlerFired, 1)
		capturedEventType = diff.EventType
	})

	resource := stewardconfig.ResourceConfig{
		Name:   "monitor-test-file",
		Module: "file",
		Config: map[string]interface{}{
			"path":              filepath.ToSlash(filePath),
			"content":           "desired content\n",
			"permissions":       420, // 0644 octal
			"allowed_base_path": filepath.ToSlash(tempDir),
		},
	}

	ctx := context.Background()
	result := executor.ExecuteResource(ctx, resource)

	assert.Equal(t, execution.StatusNonCompliant, result.Status, "monitor mode must return StatusNonCompliant")
	assert.True(t, result.DriftDetected, "drift must be detected")
	assert.False(t, result.ChangesApplied, "Set() must NOT be called in monitor mode")
	assert.Equal(t, int32(1), atomic.LoadInt32(&handlerFired), "DriftEventHandler must fire before the early return")
	assert.Equal(t, "drift.detected.monitor", capturedEventType, "monitor mode must emit drift.detected.monitor event type")

	// Verify Set() was NOT called — file must still contain initial content.
	got, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, initialContent, string(got), "file content must be unchanged in monitor mode (Set() skipped)")
}

// TestApplyConfiguration_MonitorMode verifies that when the executor is configured
// with DriftModeMonitor and a config with drifted resources is applied:
//   - The overall report status is "NON_COMPLIANT"
//   - Drifted resources have StatusNonCompliant
//   - The file on disk is NOT modified (Set() was not called)
//   - ExecutorDriftMode confirms the mode was threaded from ExecutorConfig
func TestApplyConfiguration_MonitorMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not applicable on Windows; no Windows equivalent for this test")
	}
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "monitor_apply_test.txt")
	initialContent := "initial content\n"
	require.NoError(t, os.WriteFile(filePath, []byte(initialContent), 0644))

	logger := logging.ForModule("executor_test")
	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:    logger,
		DriftMode: stewardconfig.DriftModeMonitor,
	})
	require.NoError(t, err)

	// ExecutorDriftMode confirms the mode was threaded from ExecutorConfig.
	assert.Equal(t, stewardconfig.DriftModeMonitor, execution.ExecutorDriftMode(executor),
		"DriftMode must be threaded from ExecutorConfig into Executor")

	configJSON := `{
  "steward": {"id": "test-steward", "mode": "controller"},
  "resources": [
    {
      "name": "monitor-apply-file",
      "module": "file",
      "config": ` + testFileConfig(filePath, "desired content\\n") + `
    }
  ]
}`

	ctx := context.Background()
	report, err := executor.ApplyConfiguration(ctx, []byte(configJSON), "v-monitor-1")
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, "NON_COMPLIANT", report.Status,
		"monitor mode with drifted resources must produce NON_COMPLIANT report status")

	fileStatus, ok := report.Modules["file"]
	assert.True(t, ok, "file module must be present in report")
	assert.Equal(t, "NON_COMPLIANT", fileStatus.Status, "file module status must be NON_COMPLIANT")

	nonCompliantCount, _ := fileStatus.Details["non_compliant_count"].(int)
	assert.Equal(t, 1, nonCompliantCount, "non_compliant_count must be 1")

	// Verify Set() was NOT called — file must still contain initial content.
	got, readErr := os.ReadFile(filePath)
	require.NoError(t, readErr)
	assert.Equal(t, initialContent, string(got), "file must be unchanged in monitor mode")
}

func TestExecutor_ApplyConfiguration_PermissionsRejectedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	tempDir := t.TempDir()
	logger := logging.ForModule("executor_test")

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: logger})
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
        "permissions": 420,
        "allowed_base_path": "` + filepath.ToSlash(tempDir) + `"
      }
    }
  ]
}`

	ctx := context.Background()
	// Resource execution failures are reported via report.Status, not returned as error.
	report, applyErr := executor.ApplyConfiguration(ctx, []byte(configJSON), "v1.0")
	require.NoError(t, applyErr, "resource execution failures must not surface as error return")
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

// TestApplyConfiguration_ApplyMode_CorrectsDriftAndReturnsOK verifies that an executor
// running in DriftModeApply (as set by client_transport.applyDriftModeDefault when the
// controller delivers a config) detects drift and calls Set() to correct it.
// The defaulting itself is tested in features/steward/client/drift_mode_default_test.go.
func TestApplyConfiguration_ApplyMode_CorrectsDriftAndReturnsOK(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not applicable on Windows; no Windows equivalent for this test")
	}
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "managed-file")

	// Inject drift: file exists with wrong content, simulating a post-convergence drift event.
	require.NoError(t, os.WriteFile(filePath, []byte("drift-injected-content\n"), 0644))

	logger := logging.ForModule("executor_test")
	// DriftModeApply is what client_transport.applyDriftModeDefault returns for all
	// controller-delivered configs (proto does not carry drift_mode; default is apply).
	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:    logger,
		DriftMode: stewardconfig.DriftModeApply,
	})
	require.NoError(t, err)

	assert.Equal(t, stewardconfig.DriftModeApply, execution.ExecutorDriftMode(executor),
		"executor must be in DriftModeApply (the fleet default set by client_transport)")

	configJSON := `{
  "steward": {"id": "test-steward", "mode": "controller"},
  "resources": [
    {
      "name": "managed-file",
      "module": "file",
      "config": ` + testFileConfig(filePath, "fleet-managed-content\\n") + `
    }
  ]
}`

	ctx := context.Background()
	report, applyErr := executor.ApplyConfiguration(ctx, []byte(configJSON), "v1")
	require.NoError(t, applyErr)
	require.NotNil(t, report)
	assert.Equal(t, "OK", report.Status,
		"apply mode must correct drift and return OK status")

	// Verify drift was corrected — file must contain the desired content.
	got, readErr := os.ReadFile(filePath)
	require.NoError(t, readErr)
	assert.Equal(t, "fleet-managed-content\n", string(got),
		"drifted managed resource must be re-applied to desired state in apply mode")
}
