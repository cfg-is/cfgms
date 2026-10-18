// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"runtime"

	"os"
	"path/filepath"
	"testing"

	"github.com/cfgis/cfgms/pkg/security"

	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadRemoteTerminalCfg(t *testing.T, body string) *StewardConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "steward.cfg")
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
	cfg, err := LoadConfiguration(path)
	require.NoError(t, err)
	return &cfg
}

func TestRemoteTerminalSetting_LoadConfiguration(t *testing.T) {
	t.Run("absent defaults to enabled", func(t *testing.T) {
		cfg := loadRemoteTerminalCfg(t, "steward:\n  id: h1\nresources: []\n")
		assert.True(t, cfg.Steward.RemoteTerminal.IsEnabled())
	})
	t.Run("enabled false disables", func(t *testing.T) {
		cfg := loadRemoteTerminalCfg(t, "steward:\n  id: h1\n  remote_terminal:\n    enabled: false\nresources: []\n")
		assert.False(t, cfg.Steward.RemoteTerminal.IsEnabled())
	})
	t.Run("enabled true stays enabled", func(t *testing.T) {
		cfg := loadRemoteTerminalCfg(t, "steward:\n  id: h1\n  remote_terminal:\n    enabled: true\nresources: []\n")
		assert.True(t, cfg.Steward.RemoteTerminal.IsEnabled())
	})
}

// A controller-delivered config can never carry the setting: FromProto leaves it unset.
func TestRemoteTerminalSetting_FromProtoNeverSets(t *testing.T) {
	cfg, err := FromProto(&controller.StewardConfig{Steward: &controller.StewardSettings{Id: "h1"}})
	require.NoError(t, err)
	assert.Nil(t, cfg.Steward.RemoteTerminal.Enabled)
	assert.True(t, cfg.Steward.RemoteTerminal.IsEnabled())
}

// The documented location (steward.cfg in a standard config dir) must really
// be read by the loader, and the setting must take effect (Issue #5146).
func TestLoadConfiguration_ReadsDocumentedStewardCfg(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cwd := t.TempDir()
	t.Chdir(cwd)

	dir := filepath.Join(home, ".config", "cfgms")
	if runtime.GOOS != "linux" {
		dir = filepath.Join(home, ".cfgms")
	}
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, security.BootConfigFileName),
		[]byte("steward:\n  id: h1\n  remote_terminal:\n    enabled: false\nresources: []\n"), 0o600))

	cfg, err := LoadConfiguration("")
	require.NoError(t, err)
	assert.False(t, cfg.Steward.RemoteTerminal.IsEnabled())
}

func TestWarnShadowedConfigs_ExistingUnreadFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "steward.cfg")
	require.NoError(t, os.WriteFile(p, []byte("steward: {}\n"), 0o600))
	// Must not panic and must tolerate loaded == other path.
	warnShadowedConfigs([]string{p, filepath.Join(dir, "missing.cfg")}, filepath.Join(dir, "other.cfg"))
}
