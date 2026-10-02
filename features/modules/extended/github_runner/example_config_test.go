// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package github_runner

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
)

// TestExampleRunnerConfigs_ParseAndValidate verifies that both example runner
// cfg files parse without error and that the github-runner resource's config
// produces a RunnerConfig that passes Validate(). This guards against
// placeholder values (e.g. PLACEHOLDER_SHA256_64HEX) and structural problems
// (e.g. missing owner/repo fields) that would prevent convergence as shipped.
func TestExampleRunnerConfigs_ParseAndValidate(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must succeed")

	// features/modules/extended/github_runner → up 4 levels to repo root
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..")

	tests := []struct {
		name        string
		cfgFile     string
		linuxPath   bool // true when work_dir is a Linux absolute path (/opt/...)
		windowsPath bool // true when work_dir is a Windows absolute path (C:\...)
	}{
		{
			name:      "linux-runner",
			cfgFile:   "linux-runner.cfg",
			linuxPath: true,
		},
		{
			name:        "windows-runner",
			cfgFile:     "windows-runner.cfg",
			windowsPath: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgPath := filepath.Join(repoRoot, "examples", "ci-runners", tt.cfgFile)

			stewardCfg, err := stewardconfig.LoadConfiguration(cfgPath)
			require.NoError(t, err, "%s must parse without error", tt.cfgFile)

			// Locate the github-runner resource.
			var resMap map[string]interface{}
			for _, res := range stewardCfg.Resources {
				if res.Name == "github-runner" {
					resMap = res.Config
					break
				}
			}
			require.NotNil(t, resMap, "resource \"github-runner\" not found in %s", tt.cfgFile)

			var rc RunnerConfig
			require.NoError(t, rc.fromMap(resMap), "fromMap must succeed for %s", tt.cfgFile)

			// filepath.IsAbs("C:\...") returns false on Linux/macOS; substitute a
			// valid temp dir so cross-platform CI can validate the rest of the config.
			if tt.windowsPath && runtime.GOOS != "windows" {
				rc.WorkDir = t.TempDir()
			}
			// filepath.IsAbs("/opt/...") returns false on Windows; substitute a
			// valid temp dir so cross-platform CI can validate the rest of the config.
			if tt.linuxPath && runtime.GOOS == "windows" {
				rc.WorkDir = t.TempDir()
			}

			require.NoError(t, rc.Validate(), "%s github-runner config must pass Validate()", tt.name)
		})
	}
}
