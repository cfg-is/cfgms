// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/config/stewardtypes"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestDriftMode_FullWirePath carries a drift mode and a per-module override from
// a StewardConfig through ToProto, serialised bytes and FromProto into a real
// executor, using the real converters (not YAML), for both converter packages.
func TestDriftMode_FullWirePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not applicable on Windows")
	}

	toProto := map[string]func(*stewardconfig.StewardConfig) (*controller.StewardConfig, error){
		"steward/config": stewardconfig.ToProto,
		"stewardtypes":   stewardtypes.ToProto,
	}
	fromProto := map[string]func(*controller.StewardConfig) (*stewardconfig.StewardConfig, error){
		"steward/config": stewardconfig.FromProto,
		"stewardtypes":   stewardtypes.FromProto,
	}

	for toName, to := range toProto {
		for fromName, from := range fromProto {
			t.Run(toName+"->"+fromName, func(t *testing.T) {
				root := t.TempDir()
				filePath := filepath.Join(root, "wire.txt")
				require.NoError(t, os.WriteFile(filePath, []byte("initial content\n"), 0644))
				dirPath := filepath.Join(root, "wiredir")
				require.NoError(t, os.Mkdir(dirPath, 0700))
				require.NoError(t, os.Chmod(dirPath, 0700))

				cfg := &stewardconfig.StewardConfig{
					Steward: stewardconfig.StewardSettings{
						ID:               "wire-steward",
						Logging:          stewardconfig.LoggingConfig{Level: "info"},
						DriftMode:        stewardconfig.DriftModeApply,
						ModuleDriftModes: map[string]stewardconfig.DriftMode{"file": stewardconfig.DriftModeMonitor},
					},
					Resources: []stewardconfig.ResourceConfig{
						{Name: "wire-file", Module: "file", Config: map[string]interface{}{
							"path":              filepath.ToSlash(filePath),
							"content":           "desired content\n",
							"permissions":       420,
							"allowed_base_path": filepath.ToSlash(root),
						}},
						{Name: "wire-dir", Module: "directory", Config: map[string]interface{}{
							"type":              "directory",
							"path":              filepath.ToSlash(dirPath),
							"permissions":       493,
							"allowed_base_path": filepath.ToSlash(root),
						}},
					},
				}

				pb, err := to(cfg)
				require.NoError(t, err)
				assert.Equal(t, "apply", pb.Steward.DriftMode)
				assert.Equal(t, map[string]string{"file": "monitor"}, pb.Steward.ModuleDriftModes)

				wire, err := proto.Marshal(pb)
				require.NoError(t, err)
				decoded := &controller.StewardConfig{}
				require.NoError(t, proto.Unmarshal(wire, decoded))

				got, err := from(decoded)
				require.NoError(t, err)
				assert.Equal(t, stewardconfig.DriftModeApply, got.Steward.DriftMode)
				assert.Equal(t, cfg.Steward.ModuleDriftModes, got.Steward.ModuleDriftModes)

				executor, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: logging.ForModule("wire_test")})
				require.NoError(t, err)
				executor.SetDriftMode(got.Steward.DriftMode)
				executor.SetModuleDriftModes(got.Steward.ModuleDriftModes)

				report := executor.ExecuteConfiguration(context.Background(), *got)
				byName := map[string]execution.ResourceResult{}
				for _, r := range report.ResourceResults {
					byName[r.ResourceName] = r
				}
				require.Contains(t, byName, "wire-file")
				require.Contains(t, byName, "wire-dir")
				assert.Equal(t, execution.StatusNonCompliant, byName["wire-file"].Status, "file override must reach the executor as monitor")
				assert.NotEqual(t, execution.StatusNonCompliant, byName["wire-dir"].Status)

				content, err := os.ReadFile(filePath)
				require.NoError(t, err)
				assert.Equal(t, "initial content\n", string(content), "monitor module must not be corrected")
				info, err := os.Stat(dirPath)
				require.NoError(t, err)
				assert.Equal(t, os.FileMode(0755), info.Mode().Perm(), "apply module must be corrected")
			})
		}
	}
}
