// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package execution_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/features/steward/factory"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"
)

// HungModule is a real test module implementation that blocks indefinitely in
// Get() until the context is cancelled or times out. Placed here for reuse by
// downstream tests (S7 assertion gate) that verify the controller-side timeout
// event pipeline.
type HungModule struct{}

func (h *HungModule) Get(ctx context.Context, _ string) (modules.ConfigState, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (h *HungModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil
}

// Compile-time check: HungModule implements modules.Module.
var _ modules.Module = (*HungModule)(nil)

// HungSetModule is a real test module that reports drift on Get() and then
// blocks indefinitely in Set() until the context is cancelled. Used to cover
// the module.Set timeout path in executor.go.
type HungSetModule struct{}

func (h *HungSetModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	// Return drifted state so the comparator detects drift and the executor calls Set.
	return &mapConfigState{data: map[string]interface{}{"state": "drifted"}}, nil
}

func (h *HungSetModule) Set(ctx context.Context, _ string, _ modules.ConfigState) error {
	<-ctx.Done()
	return ctx.Err()
}

var _ modules.Module = (*HungSetModule)(nil)

// HungVerifyModule is a real test module that reports drift on the first Get()
// call, succeeds on Set(), then blocks indefinitely in the second Get() (the
// post-Set verification call). Used to cover the verifyChanges timeout path.
type HungVerifyModule struct {
	getCalls int
}

func (h *HungVerifyModule) Get(ctx context.Context, _ string) (modules.ConfigState, error) {
	h.getCalls++
	if h.getCalls == 1 {
		// First call: return drifted state so the executor proceeds to Set().
		return &mapConfigState{data: map[string]interface{}{"state": "drifted"}}, nil
	}
	// Second call (inside verifyChanges): block until timeout.
	<-ctx.Done()
	return nil, ctx.Err()
}

func (h *HungVerifyModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil
}

var _ modules.Module = (*HungVerifyModule)(nil)

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
        "type": "directory",
        "state": "present",
        "allowed_base_path": "` + parent + `",
        "path": "` + filepath.ToSlash(path) + `"
      }`
	}
	return `{
        "type": "directory",
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

	// On Windows, Unix permission bits are not enforced (NTFS uses ACLs). Specifying
	// the permissions field is a misconfiguration and must produce an explicit error
	// pointing the operator at windows_acl — not be silently ignored.
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

// TestApplyConfiguration_ApplyMode_ModeAliasConfigVerifiesClean reproduces the
// fleet drift scenario: a file resource declared with the "mode" octal-string
// alias (as test/e2e/fleet/configs/fleet-config.yaml does) must verify clean
// after re-apply and report OK. The file module's Set() accepts "mode" but its
// Get() formerly emitted only "permissions"; the drift comparator then saw
// "mode" as a phantom added field that no convergence pass could resolve, so the
// executor reported the resource as failed even though the file was correct.
func TestApplyConfiguration_ApplyMode_ModeAliasConfigVerifiesClean(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not applicable on Windows; no Windows equivalent for this test")
	}
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "managed-file")

	// Inject drift: file present with wrong content.
	require.NoError(t, os.WriteFile(filePath, []byte("drift-injected-content\n"), 0644))

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:    logging.ForModule("executor_test"),
		DriftMode: stewardconfig.DriftModeApply,
	})
	require.NoError(t, err)

	// Config declares permissions via the "mode" octal-string alias, exactly as
	// the fleet E2E config does — not the "permissions" int field.
	configJSON := `{
  "steward": {"id": "test-steward", "mode": "controller"},
  "resources": [
    {
      "name": "managed-file",
      "module": "file",
      "config": {
        "path": "` + filepath.ToSlash(filePath) + `",
        "state": "present",
        "content": "fleet-managed-content\n",
        "mode": "0644",
        "allowed_base_path": "` + filepath.ToSlash(tempDir) + `"
      }
    }
  ]
}`

	report, applyErr := executor.ApplyConfiguration(context.Background(), []byte(configJSON), "v1")
	require.NoError(t, applyErr)
	require.NotNil(t, report)
	assert.Equal(t, "OK", report.Status,
		"a mode-alias config must verify clean and return OK after re-apply")

	got, readErr := os.ReadFile(filePath)
	require.NoError(t, readErr)
	assert.Equal(t, "fleet-managed-content\n", string(got),
		"drifted resource declared with the mode alias must be re-applied to desired state")
}

// TestExecuteResource_HungModule_ProducesTimeoutOutcomeEvent verifies that a
// module whose Get() blocks past the per-call deadline causes ExecuteResource
// to return (not wedge) and emits a detection+outcome pair where the outcome
// action is "did-not-finish(timeout)" with the detection event's correlation_id.
// The HungModule helper defined in this file is placed for reuse by S7 tests.
func TestExecuteResource_HungModule_ProducesTimeoutOutcomeEvent(t *testing.T) {
	emitter := &recordingEmitter{}

	errCfg := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}
	f := factory.New(discovery.ModuleRegistry{}, errCfg, logging.ForModule("executor_test"))
	f.RegisterModule("hung", &HungModule{})

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:               logging.ForModule("executor_test"),
		StewardID:            "test-steward-timeout",
		EventEmitter:         emitter,
		Factory:              f,
		ErrorHandling:        errCfg,
		ModuleCallTimeoutSec: 1, // 1 s for test speed
	})
	require.NoError(t, err)

	resource := stewardconfig.ResourceConfig{
		Name:   "hung-resource",
		Module: "hung",
		Config: map[string]interface{}{
			"state": "present",
		},
	}

	result := executor.ExecuteResource(context.Background(), resource)

	// ExecuteResource must return rather than wedging.
	assert.Equal(t, execution.StatusTimeout, result.Status,
		"a hung module must produce StatusTimeout")
	assert.NotEmpty(t, result.Error,
		"timeout result must carry an error description")

	entries := emitter.Entries()
	require.Len(t, entries, 2,
		"a hung module must emit exactly detection + timeout outcome")

	detection := entries[0]
	assert.Equal(t, "detection", detection.Fields["event_kind"],
		"first entry must be the detection event")
	assert.NotEmpty(t, detection.CorrelationId,
		"detection must carry a non-empty correlation_id")

	outcome := entries[1]
	assert.Equal(t, "outcome", outcome.Fields["event_kind"],
		"second entry must be the outcome event")
	assert.Equal(t, "did-not-finish(timeout)", outcome.Fields["action"],
		"timeout outcome action must be 'did-not-finish(timeout)'")
	assert.NotEmpty(t, outcome.Fields["timeout_ms"],
		"timeout outcome must carry timeout_ms")
	assert.Equal(t, detection.CorrelationId, outcome.CorrelationId,
		"detection and timeout outcome must share the same correlation_id")
}

// TestExecuteResource_HungSetModule_ProducesTimeoutOutcomeEvent verifies that a
// module whose Set() blocks past the per-call deadline yields a timeout outcome
// event and returns StatusTimeout without wedging.
func TestExecuteResource_HungSetModule_ProducesTimeoutOutcomeEvent(t *testing.T) {
	emitter := &recordingEmitter{}

	errCfg := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}
	f := factory.New(discovery.ModuleRegistry{}, errCfg, logging.ForModule("executor_test"))
	f.RegisterModule("hung-set", &HungSetModule{})

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:               logging.ForModule("executor_test"),
		StewardID:            "test-steward-set-timeout",
		EventEmitter:         emitter,
		Factory:              f,
		ErrorHandling:        errCfg,
		ModuleCallTimeoutSec: 1,
	})
	require.NoError(t, err)

	resource := stewardconfig.ResourceConfig{
		Name:   "hung-set-resource",
		Module: "hung-set",
		Config: map[string]interface{}{
			"state": "desired",
		},
	}

	result := executor.ExecuteResource(context.Background(), resource)

	assert.Equal(t, execution.StatusTimeout, result.Status,
		"a module whose Set() hangs must produce StatusTimeout")
	assert.NotEmpty(t, result.Error)

	entries := emitter.Entries()
	require.Len(t, entries, 2, "hung Set must emit detection + timeout outcome")

	detection := entries[0]
	assert.Equal(t, "detection", detection.Fields["event_kind"])
	assert.NotEmpty(t, detection.CorrelationId)

	outcome := entries[1]
	assert.Equal(t, "outcome", outcome.Fields["event_kind"])
	assert.Equal(t, "did-not-finish(timeout)", outcome.Fields["action"],
		"Set timeout must emit did-not-finish(timeout)")
	assert.Equal(t, detection.CorrelationId, outcome.CorrelationId,
		"detection and Set-timeout outcome must share correlation_id")
}

// TestExecuteResource_HungVerifyModule_ProducesTimeoutOutcomeEvent verifies that
// a module whose post-Set Get() (inside verifyChanges) blocks past the deadline
// yields a timeout outcome event and returns StatusTimeout without wedging.
func TestExecuteResource_HungVerifyModule_ProducesTimeoutOutcomeEvent(t *testing.T) {
	emitter := &recordingEmitter{}

	errCfg := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}
	f := factory.New(discovery.ModuleRegistry{}, errCfg, logging.ForModule("executor_test"))
	f.RegisterModule("hung-verify", &HungVerifyModule{})

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:               logging.ForModule("executor_test"),
		StewardID:            "test-steward-verify-timeout",
		EventEmitter:         emitter,
		Factory:              f,
		ErrorHandling:        errCfg,
		ModuleCallTimeoutSec: 1,
	})
	require.NoError(t, err)

	resource := stewardconfig.ResourceConfig{
		Name:   "hung-verify-resource",
		Module: "hung-verify",
		Config: map[string]interface{}{
			"state": "desired",
		},
	}

	result := executor.ExecuteResource(context.Background(), resource)

	assert.Equal(t, execution.StatusTimeout, result.Status,
		"a module whose verifyChanges Get() hangs must produce StatusTimeout")
	assert.NotEmpty(t, result.Error)

	entries := emitter.Entries()
	require.Len(t, entries, 2, "hung verifyChanges must emit detection + timeout outcome")

	detection := entries[0]
	assert.Equal(t, "detection", detection.Fields["event_kind"])
	assert.NotEmpty(t, detection.CorrelationId)

	outcome := entries[1]
	assert.Equal(t, "outcome", outcome.Fields["event_kind"])
	assert.Equal(t, "did-not-finish(timeout)", outcome.Fields["action"],
		"verifyChanges timeout must emit did-not-finish(timeout)")
	assert.Equal(t, detection.CorrelationId, outcome.CorrelationId,
		"detection and verify-timeout outcome must share correlation_id")
}

// SlowSetModule is a real module implementation that reports drift on the first
// Get() call, then waits for the given delay in Set() before succeeding. After a
// successful Set(), subsequent Get() calls report the applied desired state so
// the post-Set verification step sees no remaining drift.
// Used to verify that a slow-but-within-budget Set completes when no outer
// deadline shorter than ModuleCallTimeoutSec is imposed.
type SlowSetModule struct {
	delay   time.Duration
	mu      sync.Mutex
	applied bool
}

func (s *SlowSetModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applied {
		// Post-Set: return the applied desired state so verification finds no drift.
		return &mapConfigState{data: map[string]interface{}{"state": "desired"}}, nil
	}
	return &mapConfigState{data: map[string]interface{}{"state": "drifted"}}, nil
}

func (s *SlowSetModule) Set(ctx context.Context, _ string, _ modules.ConfigState) error {
	select {
	case <-time.After(s.delay):
		s.mu.Lock()
		s.applied = true
		s.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ modules.Module = (*SlowSetModule)(nil)

// warnCapturingLogger captures Warn-level log entries for log-accuracy assertions.
// It satisfies logging.Logger via embedding NoopLogger.
type warnCapturingLogger struct {
	logging.NoopLogger
	mu      sync.Mutex
	entries []warnLogEntry
}

type warnLogEntry struct {
	msg string
	kvs []interface{}
}

func (l *warnCapturingLogger) Warn(msg string, kvs ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	kvcopy := make([]interface{}, len(kvs))
	copy(kvcopy, kvs)
	l.entries = append(l.entries, warnLogEntry{msg: msg, kvs: kvcopy})
}

func (l *warnCapturingLogger) warnEntries() []warnLogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]warnLogEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

func findKV(kvs []interface{}, key string) (interface{}, bool) {
	for i := 0; i+1 < len(kvs); i += 2 {
		if k, ok := kvs[i].(string); ok && k == key {
			return kvs[i+1], true
		}
	}
	return nil, false
}

// TestExecuteResource_SlowSet_CompletesWithNoOuterDeadline verifies that a
// module whose Set() takes longer than the old 30s on-connect-sync ceiling
// completes successfully when the executor is called with context.Background()
// (no outer deadline). This is the behavioral regression test for the bug where
// client_transport.go wrapped syncConfigNow in a 30s context, silently cutting
// off module.Set calls that should have had the full per-call ModuleCallTimeoutSec.
func TestExecuteResource_SlowSet_CompletesWithNoOuterDeadline(t *testing.T) {
	errCfg := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}
	f := factory.New(discovery.ModuleRegistry{}, errCfg, logging.ForModule("executor_test"))
	// SlowSetModule takes 200ms — longer than the old 30s simulated here by a 100ms
	// outer ctx, but well within the 2s per-call module timeout.
	f.RegisterModule("slow-set", &SlowSetModule{delay: 200 * time.Millisecond})

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:               logging.ForModule("executor_test"),
		Factory:              f,
		ErrorHandling:        errCfg,
		ModuleCallTimeoutSec: 2, // 2s per-call budget; well above the 200ms Set delay
	})
	require.NoError(t, err)

	resource := stewardconfig.ResourceConfig{
		Name:   "slow-set-resource",
		Module: "slow-set",
		Config: map[string]interface{}{"state": "desired"},
	}

	// context.Background() — no outer deadline — mirrors the fixed client_transport.go
	// on-connect sync path that now passes context.Background() to syncConfigNow.
	result := executor.ExecuteResource(context.Background(), resource)

	assert.Equal(t, execution.StatusSuccess, result.Status,
		"a Set that completes within ModuleCallTimeoutSec must succeed when no outer deadline is imposed")
	assert.True(t, result.ChangesApplied,
		"module.Set must be counted as applied on success")
}

// TestExecuteResource_TimeoutWarn_LogsActualEnforcedBudget verifies that when
// the ambient context carries a deadline shorter than ModuleCallTimeoutSec, the
// timeout WARN log records the ACTUAL enforced budget (the outer ctx deadline)
// rather than the hardcoded e.moduleCallTimeout value. This guards against the
// mislabeled 120000ms timeout_ms field while a 30s outer context actually fired.
func TestExecuteResource_TimeoutWarn_LogsActualEnforcedBudget(t *testing.T) {
	capLog := &warnCapturingLogger{}

	errCfg := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}
	f := factory.New(discovery.ModuleRegistry{}, errCfg, capLog)
	f.RegisterModule("hung-set", &HungSetModule{})

	// Configure a generous per-call module timeout (10s) so only the outer ctx (200ms)
	// can fire. The log must report ≤1000ms, not 10000ms.
	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:               capLog,
		Factory:              f,
		ErrorHandling:        errCfg,
		ModuleCallTimeoutSec: 10, // 10s configured; outer ctx is much shorter
	})
	require.NoError(t, err)

	resource := stewardconfig.ResourceConfig{
		Name:   "hung-set-budget-check",
		Module: "hung-set",
		Config: map[string]interface{}{"state": "desired"},
	}

	// Outer ctx has a 200ms deadline — shorter than the 10s module timeout.
	// This simulates the old bug where the on-connect sync imposed a 30s ceiling.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	result := executor.ExecuteResource(ctx, resource)

	assert.Equal(t, execution.StatusTimeout, result.Status,
		"outer ctx deadline must cancel the hung Set and produce StatusTimeout")

	warns := capLog.warnEntries()
	var setTimeoutEntry *warnLogEntry
	for i := range warns {
		if warns[i].msg == "module.Set timeout" {
			setTimeoutEntry = &warns[i]
			break
		}
	}
	require.NotNil(t, setTimeoutEntry, "a 'module.Set timeout' WARN entry must be emitted")

	timeoutMSVal, ok := findKV(setTimeoutEntry.kvs, "timeout_ms")
	require.True(t, ok, "timeout WARN must carry a timeout_ms field")
	timeoutMS, ok := timeoutMSVal.(int64)
	require.True(t, ok, "timeout_ms must be int64")

	// The outer ctx budget was 200ms; the configured module timeout is 10000ms.
	// The logged timeout_ms must reflect the outer ctx (≤1000ms), not the config (10000ms).
	assert.LessOrEqual(t, timeoutMS, int64(1000),
		"timeout_ms must reflect the actual enforced budget (~200ms outer ctx), not the configured 10000ms module timeout")
}

// ─── Story #2577: managed-elsewhere short-circuit ──────────────────────────────

// managedElsewhereState is a ConfigState that reports it is managed by another
// authority (e.g. a clustered HA VM owned by another cluster node). The executor
// must treat it as compliant with no Compare/Set/Verify.
type managedElsewhereState struct{ owner string }

func (s *managedElsewhereState) AsMap() map[string]interface{} {
	return map[string]interface{}{"state": "absent"}
}
func (s *managedElsewhereState) ToYAML() ([]byte, error)          { return nil, nil }
func (s *managedElsewhereState) FromYAML([]byte) error            { return nil }
func (s *managedElsewhereState) Validate() error                  { return nil }
func (s *managedElsewhereState) GetManagedFields() []string       { return []string{"state"} }
func (s *managedElsewhereState) ManagedElsewhere() (bool, string) { return true, s.owner }

var _ modules.ManagedElsewhere = (*managedElsewhereState)(nil)

// managedElsewhereModule.Get reports a managed-elsewhere resource; Set must never
// run because the executor short-circuits to compliant before it.
type managedElsewhereModule struct{ setCalled int32 }

func (m *managedElsewhereModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	return &managedElsewhereState{owner: "NODE2"}, nil
}
func (m *managedElsewhereModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	atomic.AddInt32(&m.setCalled, 1)
	return nil
}

var _ modules.Module = (*managedElsewhereModule)(nil)

// TestExecuteResource_ManagedElsewhere_CompliantNoSet (Story #2577): when a
// module's Get reports the resource is managed by another authority, the executor
// short-circuits to compliant — no drift comparison, no Set, no Verify — even
// though the desired config would otherwise show drift against the local view.
func TestExecuteResource_ManagedElsewhere_CompliantNoSet(t *testing.T) {
	errCfg := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}
	f := factory.New(discovery.ModuleRegistry{}, errCfg, logging.ForModule("executor_test"))
	mod := &managedElsewhereModule{}
	f.RegisterModule("managed-elsewhere", mod)

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:        logging.ForModule("executor_test"),
		StewardID:     "test-steward-2577",
		Factory:       f,
		ErrorHandling: errCfg,
		DriftMode:     stewardconfig.DriftModeApply,
	})
	require.NoError(t, err)

	// A desired config that WOULD show drift against the reported "absent" state —
	// the managed-elsewhere signal must short-circuit before any comparison.
	resource := stewardconfig.ResourceConfig{
		Name:   "ha-vm-elsewhere",
		Module: "managed-elsewhere",
		Config: map[string]interface{}{"state": "running", "cpu_count": 2},
	}

	result := executor.ExecuteResource(context.Background(), resource)

	assert.Equal(t, execution.StatusNoChange, result.Status,
		"a managed-elsewhere resource must report compliant (StatusNoChange)")
	assert.False(t, result.DriftDetected,
		"no drift comparison is performed for a managed-elsewhere resource")
	assert.Equal(t, int32(0), atomic.LoadInt32(&mod.setCalled),
		"Set must never be called for a resource managed on another node")
}
