// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package execution

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/factory"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetDriftEventHandler(t *testing.T) {
	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{}
	moduleFactory := factory.New(registry, errorConfig)
	comparator := stewardtesting.NewStateComparator()
	logger := logging.NewLogger("info")

	engine := New(moduleFactory, comparator, errorConfig, logger)

	var called int32
	handler := DriftEventHandler(func(resourceName, moduleName string, diff *stewardtesting.StateDiff) {
		atomic.AddInt32(&called, 1)
	})

	engine.SetDriftEventHandler(handler)

	assert.NotNil(t, engine.driftHandler, "drift handler should be stored")
	assert.Equal(t, int32(0), atomic.LoadInt32(&called), "handler should not have been called yet")
}

func TestSetDriftEventHandler_NilHandler(t *testing.T) {
	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{}
	moduleFactory := factory.New(registry, errorConfig)
	comparator := stewardtesting.NewStateComparator()
	logger := logging.NewLogger("info")

	engine := New(moduleFactory, comparator, errorConfig, logger)
	engine.SetDriftEventHandler(nil)

	// nil handler is valid — no panic
	assert.Nil(t, engine.driftHandler)
}

func TestExecuteResource_DriftHandlerCalledOnDrift(t *testing.T) {
	// Use the real file module — create a temp file with content "current"
	// then configure resource with desired content "desired" to trigger drift.
	dir := t.TempDir()
	filePath := filepath.Join(dir, "testfile.txt")

	// Write current content
	require.NoError(t, os.WriteFile(filePath, []byte("current content"), 0644))

	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{
		ResourceFailure:   config.ActionContinue,
		ModuleLoadFailure: config.ActionContinue,
	}
	moduleFactory := factory.New(registry, errorConfig)
	comparator := stewardtesting.NewStateComparator()
	logger := logging.NewLogger("info")

	engine := New(moduleFactory, comparator, errorConfig, logger)

	// Track drift handler invocations.
	// Use a mutex to protect the captured string values — the handler callback
	// may be called from a goroutine context in future, so we protect all shared
	// state for -race compatibility.
	var driftCallCount int32
	var mu sync.Mutex
	var capturedResource string
	var capturedModule string
	engine.SetDriftEventHandler(func(resourceName, moduleName string, diff *stewardtesting.StateDiff) {
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
	result := engine.ExecuteResource(ctx, resource)

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
	// Create a file with content matching desired — no drift expected.
	dir := t.TempDir()
	filePath := filepath.Join(dir, "testfile.txt")

	require.NoError(t, os.WriteFile(filePath, []byte("desired content"), 0644))

	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{
		ResourceFailure:   config.ActionContinue,
		ModuleLoadFailure: config.ActionContinue,
	}
	moduleFactory := factory.New(registry, errorConfig)
	comparator := stewardtesting.NewStateComparator()
	logger := logging.NewLogger("info")

	engine := New(moduleFactory, comparator, errorConfig, logger)

	var driftCallCount int32
	engine.SetDriftEventHandler(func(resourceName, moduleName string, diff *stewardtesting.StateDiff) {
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
	result := engine.ExecuteResource(ctx, resource)

	assert.False(t, result.DriftDetected, "no drift should be detected")
	assert.Equal(t, int32(0), atomic.LoadInt32(&driftCallCount), "drift handler should NOT be called when no drift")
}

func TestExecuteResource_DriftHandlerNotCalledWhenModuleNotFound(t *testing.T) {
	// Verify handler is not called when module loading fails.
	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{
		ResourceFailure:   config.ActionContinue,
		ModuleLoadFailure: config.ActionContinue,
	}
	moduleFactory := factory.New(registry, errorConfig)
	comparator := stewardtesting.NewStateComparator()
	logger := logging.NewLogger("info")

	engine := New(moduleFactory, comparator, errorConfig, logger)

	var driftCallCount int32
	engine.SetDriftEventHandler(func(resourceName, moduleName string, diff *stewardtesting.StateDiff) {
		atomic.AddInt32(&driftCallCount, 1)
	})

	resource := config.ResourceConfig{
		Name:   "test-resource",
		Module: "nonexistent-module",
		Config: map[string]interface{}{"key": "value"},
	}

	ctx := context.Background()
	result := engine.ExecuteResource(ctx, resource)

	assert.Equal(t, StatusSkipped, result.Status)
	assert.Equal(t, int32(0), atomic.LoadInt32(&driftCallCount), "drift handler should NOT be called when module not found")
}

func TestExecuteConfiguration_DriftHandlerCalledForDriftingResources(t *testing.T) {
	// Test that the drift handler is called for each drifted resource in a configuration.
	dir := t.TempDir()
	filePath1 := filepath.Join(dir, "file1.txt")
	filePath2 := filepath.Join(dir, "file2.txt")

	require.NoError(t, os.WriteFile(filePath1, []byte("wrong content"), 0644))
	require.NoError(t, os.WriteFile(filePath2, []byte("correct content"), 0644))

	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{
		ResourceFailure:   config.ActionContinue,
		ModuleLoadFailure: config.ActionContinue,
	}
	moduleFactory := factory.New(registry, errorConfig)
	comparator := stewardtesting.NewStateComparator()
	logger := logging.NewLogger("info")

	engine := New(moduleFactory, comparator, errorConfig, logger)

	var driftCallCount int32
	engine.SetDriftEventHandler(func(resourceName, moduleName string, diff *stewardtesting.StateDiff) {
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
	report := engine.ExecuteConfiguration(ctx, cfg)

	// file1 drifted (handler called), file2 did not
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

	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{
		ModuleLoadFailure: config.ActionContinue,
		ResourceFailure:   config.ActionWarn,
	}
	moduleFactory := factory.New(registry, errorConfig)
	comparator := stewardtesting.NewStateComparator()
	logger := logging.NewLogger("info")
	engine := New(moduleFactory, comparator, errorConfig, logger)

	resource := config.ResourceConfig{
		Name:   "test-dir",
		Module: "directory",
		Config: map[string]interface{}{
			"allowed_base_path": base,
			"path":              targetPath,
			"permissions":       493, // 0755 octal — absent dir has no permissions, so drift is detected
		},
	}

	ctx := context.Background()
	result := engine.ExecuteResource(ctx, resource)

	assert.Equal(t, StatusSuccess, result.Status, "directory module must succeed end-to-end via Configure→Get→Compare→Set→Verify")
	assert.True(t, result.DriftDetected, "drift must be detected when directory does not yet exist")
	assert.True(t, result.ChangesApplied, "Set() must be called when drift is detected")
	assert.Empty(t, result.Error, "no error should be recorded on success")

	// Verify the directory was actually created on disk
	info, statErr := os.Stat(targetPath)
	require.NoError(t, statErr, "directory must exist after successful execution")
	assert.True(t, info.IsDir(), "path must be a directory")
}

// TestExecuteResource_MissingAllowedBasePath_FailsConfigure verifies that when a
// Configurable module (file or directory) is given a config without allowed_base_path,
// the engine reports StatusFailed from the Configure step — not from Get or Set.
func TestExecuteResource_MissingAllowedBasePath_FailsConfigure(t *testing.T) {
	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{
		ModuleLoadFailure: config.ActionContinue,
		ResourceFailure:   config.ActionWarn,
	}
	moduleFactory := factory.New(registry, errorConfig)
	comparator := stewardtesting.NewStateComparator()
	logger := logging.NewLogger("info")
	engine := New(moduleFactory, comparator, errorConfig, logger)

	// No allowed_base_path → Configure() returns ErrAllowedBasePathRequired.
	resource := config.ResourceConfig{
		Name:   "no-base-path",
		Module: "file",
		Config: map[string]interface{}{
			"content": "should not reach OS",
		},
	}

	ctx := context.Background()
	result := engine.ExecuteResource(ctx, resource)

	assert.Equal(t, StatusFailed, result.Status, "missing allowed_base_path must fail at Configure step")
	assert.Contains(t, result.Error, "failed to configure module", "error must identify Configure as the source")
	assert.False(t, result.ChangesApplied, "Set() must not be called when Configure fails")
}
