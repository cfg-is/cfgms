// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package execution

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cfgis/cfgms/features/steward/config"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetDriftEventHandler(t *testing.T) {
	errorConfig := config.ErrorHandlingConfig{}
	executor := newTestExecutor(t, errorConfig)

	var called int32
	handler := DriftEventHandler(func(resourceName, moduleName string, diff *stewardtesting.StateDiff) {
		atomic.AddInt32(&called, 1)
	})

	executor.SetDriftEventHandler(handler)

	assert.NotNil(t, executor.driftHandler, "drift handler should be stored")
	assert.Equal(t, int32(0), atomic.LoadInt32(&called), "handler should not have been called yet")
}

func TestSetDriftEventHandler_NilHandler(t *testing.T) {
	errorConfig := config.ErrorHandlingConfig{}
	executor := newTestExecutor(t, errorConfig)

	executor.SetDriftEventHandler(nil)

	assert.Nil(t, executor.driftHandler)
}

func TestExecuteResource_DriftHandlerCalledOnDrift(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "testfile.txt")

	require.NoError(t, os.WriteFile(filePath, []byte("current content"), 0644))

	errorConfig := config.ErrorHandlingConfig{
		ResourceFailure:   config.ActionContinue,
		ModuleLoadFailure: config.ActionContinue,
	}
	executor := newTestExecutor(t, errorConfig)

	var driftCallCount int32
	var mu sync.Mutex
	var capturedResource string
	var capturedModule string
	executor.SetDriftEventHandler(func(resourceName, moduleName string, diff *stewardtesting.StateDiff) {
		atomic.AddInt32(&driftCallCount, 1)
		mu.Lock()
		capturedResource = resourceName
		capturedModule = moduleName
		mu.Unlock()
	})

	resource := config.ResourceConfig{
		Name:   "test-file",
		Module: "file",
		Config: map[string]interface{}{
			"path":              filePath,
			"state":             "present",
			"content":           "desired content",
			"allowed_base_path": dir,
		},
	}

	ctx := context.Background()
	result := executor.ExecuteResource(ctx, resource)

	assert.True(t, result.DriftDetected, "drift should be detected")
	assert.Equal(t, int32(1), atomic.LoadInt32(&driftCallCount), "drift handler should be called once")
	mu.Lock()
	resource_ := capturedResource
	module_ := capturedModule
	mu.Unlock()
	assert.Equal(t, "test-file", resource_)
	assert.Equal(t, "file", module_)
}

func TestExecuteResource_DriftHandlerNotCalledWhenNoDrift(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "testfile.txt")

	require.NoError(t, os.WriteFile(filePath, []byte("desired content"), 0644))

	errorConfig := config.ErrorHandlingConfig{
		ResourceFailure:   config.ActionContinue,
		ModuleLoadFailure: config.ActionContinue,
	}
	executor := newTestExecutor(t, errorConfig)

	var driftCallCount int32
	executor.SetDriftEventHandler(func(resourceName, moduleName string, diff *stewardtesting.StateDiff) {
		atomic.AddInt32(&driftCallCount, 1)
	})

	resource := config.ResourceConfig{
		Name:   "test-file",
		Module: "file",
		Config: map[string]interface{}{
			"path":              filePath,
			"state":             "present",
			"content":           "desired content",
			"allowed_base_path": dir,
		},
	}

	ctx := context.Background()
	result := executor.ExecuteResource(ctx, resource)

	assert.False(t, result.DriftDetected, "no drift should be detected")
	assert.Equal(t, int32(0), atomic.LoadInt32(&driftCallCount), "drift handler should NOT be called when no drift")
}

func TestExecuteResource_DriftHandlerNotCalledWhenModuleNotFound(t *testing.T) {
	errorConfig := config.ErrorHandlingConfig{
		ResourceFailure:   config.ActionContinue,
		ModuleLoadFailure: config.ActionContinue,
	}
	executor := newTestExecutor(t, errorConfig)

	var driftCallCount int32
	executor.SetDriftEventHandler(func(resourceName, moduleName string, diff *stewardtesting.StateDiff) {
		atomic.AddInt32(&driftCallCount, 1)
	})

	resource := config.ResourceConfig{
		Name:   "test-resource",
		Module: "nonexistent-module",
		Config: map[string]interface{}{"key": "value"},
	}

	ctx := context.Background()
	result := executor.ExecuteResource(ctx, resource)

	assert.Equal(t, StatusSkipped, result.Status)
	assert.Equal(t, int32(0), atomic.LoadInt32(&driftCallCount), "drift handler should NOT be called when module not found")
}

func TestExecuteConfiguration_DriftHandlerCalledForDriftingResources(t *testing.T) {
	dir := t.TempDir()
	filePath1 := filepath.Join(dir, "file1.txt")
	filePath2 := filepath.Join(dir, "file2.txt")

	require.NoError(t, os.WriteFile(filePath1, []byte("wrong content"), 0644))
	require.NoError(t, os.WriteFile(filePath2, []byte("correct content"), 0644))

	errorConfig := config.ErrorHandlingConfig{
		ResourceFailure:   config.ActionContinue,
		ModuleLoadFailure: config.ActionContinue,
	}
	executor := newTestExecutor(t, errorConfig)

	var driftCallCount int32
	executor.SetDriftEventHandler(func(resourceName, moduleName string, diff *stewardtesting.StateDiff) {
		atomic.AddInt32(&driftCallCount, 1)
	})

	cfg := config.StewardConfig{
		Resources: []config.ResourceConfig{
			{
				Name:   "file1",
				Module: "file",
				Config: map[string]interface{}{
					"path":              filePath1,
					"state":             "present",
					"content":           "desired content",
					"allowed_base_path": dir,
				},
			},
			{
				Name:   "file2",
				Module: "file",
				Config: map[string]interface{}{
					"path":              filePath2,
					"state":             "present",
					"content":           "correct content",
					"allowed_base_path": dir,
				},
			},
		},
	}

	ctx := context.Background()
	report := executor.ExecuteConfiguration(ctx, cfg)

	assert.Equal(t, int32(1), atomic.LoadInt32(&driftCallCount), "drift handler should be called only for drifted resources")
	assert.Equal(t, 2, report.TotalResources)
}

// TestExecuteResource_Configurable_DirectoryModule_EndToEnd verifies that the directory
// module, which implements modules.Configurable, works correctly through the execution
// engine's Get→Compare→Set→Verify cycle:
//  1. The engine calls Configure(desiredState) to establish the AllowedBasePath boundary
//  2. Get() succeeds and returns "absent" state (directory does not yet exist)
//  3. Compare detects drift (absent vs desired present state)
//  4. Set() creates the directory
//  5. Verify confirms the directory exists
func TestExecuteResource_Configurable_DirectoryModule_EndToEnd(t *testing.T) {
	base := t.TempDir()
	targetPath := filepath.Join(base, "engine-created-dir")

	errorConfig := config.ErrorHandlingConfig{
		ModuleLoadFailure: config.ActionContinue,
		ResourceFailure:   config.ActionWarn,
	}
	executor := newTestExecutor(t, errorConfig)

	cfgMap := map[string]interface{}{
		"allowed_base_path": base,
		"path":              targetPath,
	}
	if runtime.GOOS == "windows" {
		cfgMap["state"] = "present"
	} else {
		cfgMap["permissions"] = 493 // 0755 octal
	}

	resource := config.ResourceConfig{
		Name:   "test-dir",
		Module: "directory",
		Config: cfgMap,
	}

	ctx := context.Background()
	result := executor.ExecuteResource(ctx, resource)

	assert.Equal(t, StatusSuccess, result.Status, "directory module must succeed end-to-end via Configure→Get→Compare→Set→Verify")
	assert.True(t, result.DriftDetected, "drift must be detected when directory does not yet exist")
	assert.True(t, result.ChangesApplied, "Set() must be called when drift is detected")
	assert.Empty(t, result.Error, "no error should be recorded on success")

	info, statErr := os.Stat(targetPath)
	require.NoError(t, statErr, "directory must exist after successful execution")
	assert.True(t, info.IsDir(), "path must be a directory")
}

// TestExecuteResource_MissingAllowedBasePath_FailsConfigure verifies that when a
// Configurable module (file or directory) is given a config without allowed_base_path,
// the engine reports StatusFailed from the Configure step — not from Get or Set.
func TestExecuteResource_MissingAllowedBasePath_FailsConfigure(t *testing.T) {
	errorConfig := config.ErrorHandlingConfig{
		ModuleLoadFailure: config.ActionContinue,
		ResourceFailure:   config.ActionWarn,
	}
	executor := newTestExecutor(t, errorConfig)

	resource := config.ResourceConfig{
		Name:   "no-base-path",
		Module: "file",
		Config: map[string]interface{}{
			"content": "should not reach OS",
		},
	}

	ctx := context.Background()
	result := executor.ExecuteResource(ctx, resource)

	assert.Equal(t, StatusFailed, result.Status, "missing allowed_base_path must fail at Configure step")
	assert.Contains(t, result.Error, "failed to configure module", "error must identify Configure as the source")
	assert.False(t, result.ChangesApplied, "Set() must not be called when Configure fails")
}

func TestNewExecutor_DefaultsWhenNoFactoryProvided(t *testing.T) {
	logger := logging.NewLogger("info")
	executor, err := NewExecutor(&ExecutorConfig{Logger: logger})
	require.NoError(t, err)
	assert.NotNil(t, executor)
	assert.NotNil(t, executor.factory)
	assert.NotNil(t, executor.comparator)
}
