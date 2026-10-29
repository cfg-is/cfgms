// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package execution_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/execution"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"
)

// driftFixture holds one drifted resource per module bundle: a file whose
// content differs, and a directory whose permissions differ.
type driftFixture struct {
	file     stewardconfig.ResourceConfig
	dir      stewardconfig.ResourceConfig
	filePath string
	dirPath  string
}

const (
	driftFixtureInitialContent = "initial content\n"
	driftFixtureDesired        = "desired content\n"
)

func newDriftFixture(t *testing.T) driftFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not applicable on Windows")
	}
	root := t.TempDir()
	filePath := filepath.Join(root, "drift.txt")
	require.NoError(t, os.WriteFile(filePath, []byte(driftFixtureInitialContent), 0644))
	dirPath := filepath.Join(root, "driftdir")
	require.NoError(t, os.Mkdir(dirPath, 0700))
	require.NoError(t, os.Chmod(dirPath, 0700))

	return driftFixture{
		filePath: filePath,
		dirPath:  dirPath,
		file: stewardconfig.ResourceConfig{
			Name:   "drift-file",
			Module: "file",
			Config: map[string]interface{}{
				"path":              filepath.ToSlash(filePath),
				"content":           driftFixtureDesired,
				"permissions":       420,
				"allowed_base_path": filepath.ToSlash(root),
			},
		},
		dir: stewardconfig.ResourceConfig{
			Name:   "drift-dir",
			Module: "directory",
			Config: map[string]interface{}{
				"type":              "directory",
				"path":              filepath.ToSlash(dirPath),
				"permissions":       493,
				"allowed_base_path": filepath.ToSlash(root),
			},
		},
	}
}

func (f driftFixture) fileContent(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(f.filePath)
	require.NoError(t, err)
	return string(b)
}

func (f driftFixture) dirPerm(t *testing.T) os.FileMode {
	t.Helper()
	info, err := os.Stat(f.dirPath)
	require.NoError(t, err)
	return info.Mode().Perm()
}

func newDriftExecutor(t *testing.T, global stewardconfig.DriftMode, overrides map[string]stewardconfig.DriftMode) *execution.Executor {
	t.Helper()
	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:    logging.ForModule("executor_drift_test"),
		DriftMode: global,
	})
	require.NoError(t, err)
	executor.SetModuleDriftModes(overrides)
	return executor
}

func TestExecutor_ModuleOverrideMonitor_WhileGlobalApply(t *testing.T) {
	fx := newDriftFixture(t)
	executor := newDriftExecutor(t, stewardconfig.DriftModeApply,
		map[string]stewardconfig.DriftMode{"file": stewardconfig.DriftModeMonitor})

	ctx := context.Background()
	fileResult := executor.ExecuteResource(ctx, fx.file)
	dirResult := executor.ExecuteResource(ctx, fx.dir)

	assert.Equal(t, execution.StatusNonCompliant, fileResult.Status, "overridden module must only report")
	assert.False(t, fileResult.ChangesApplied)
	assert.Equal(t, driftFixtureInitialContent, fx.fileContent(t), "monitor override must leave the file untouched")

	assert.NotEqual(t, execution.StatusNonCompliant, dirResult.Status, "non-overridden module follows the global apply mode")
	assert.True(t, dirResult.ChangesApplied)
	assert.Equal(t, os.FileMode(0755), fx.dirPerm(t), "apply mode must correct the directory")
}

func TestExecutor_ModuleOverrideApply_WhileGlobalMonitor(t *testing.T) {
	fx := newDriftFixture(t)
	executor := newDriftExecutor(t, stewardconfig.DriftModeMonitor,
		map[string]stewardconfig.DriftMode{"file": stewardconfig.DriftModeApply})

	ctx := context.Background()
	fileResult := executor.ExecuteResource(ctx, fx.file)
	dirResult := executor.ExecuteResource(ctx, fx.dir)

	assert.NotEqual(t, execution.StatusNonCompliant, fileResult.Status, "apply override must correct the module")
	assert.True(t, fileResult.ChangesApplied)
	assert.Equal(t, driftFixtureDesired, fx.fileContent(t))

	assert.Equal(t, execution.StatusNonCompliant, dirResult.Status, "non-overridden module follows the global monitor mode")
	assert.False(t, dirResult.ChangesApplied)
	assert.Equal(t, os.FileMode(0700), fx.dirPerm(t), "monitor mode must leave the directory untouched")
}

// TestExecutor_DriftDetectedMonitorEventPerResource asserts the event type is
// chosen per resource: a monitor-mode module emits drift.detected.monitor while
// a sibling resource under apply emits drift.detected.
func TestExecutor_DriftDetectedMonitorEventPerResource(t *testing.T) {
	fx := newDriftFixture(t)
	executor := newDriftExecutor(t, stewardconfig.DriftModeApply,
		map[string]stewardconfig.DriftMode{"file": stewardconfig.DriftModeMonitor})

	var mu sync.Mutex
	eventTypes := map[string]string{}
	executor.SetDriftEventHandler(func(resourceName, _ string, diff *stewardtesting.StateDiff) {
		mu.Lock()
		eventTypes[resourceName] = diff.EventType
		mu.Unlock()
	})

	ctx := context.Background()
	executor.ExecuteResource(ctx, fx.file)
	executor.ExecuteResource(ctx, fx.dir)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "drift.detected.monitor", eventTypes["drift-file"])
	assert.Equal(t, "drift.detected", eventTypes["drift-dir"])
}
