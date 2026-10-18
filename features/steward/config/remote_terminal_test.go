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
	existing := filepath.Join(dir, "steward.cfg")
	require.NoError(t, os.WriteFile(existing, []byte("steward: {}\n"), 0o600))
	hostCfg := filepath.Join(dir, "host1.cfg")
	require.NoError(t, os.WriteFile(hostCfg, []byte("steward: {}\n"), 0o600))
	missing := filepath.Join(dir, "missing.cfg")

	t.Run("existing unread file warned, missing file not", func(t *testing.T) {
		got := warnShadowedConfigs([]string{existing, missing}, filepath.Join(dir, "other.cfg"))
		assert.Equal(t, []string{existing}, got)
		assert.NotContains(t, got, missing)
	})

	t.Run("loaded path equal to a candidate is not warned", func(t *testing.T) {
		got := warnShadowedConfigs([]string{hostCfg, existing, missing}, hostCfg)
		assert.Equal(t, []string{existing}, got)
		assert.NotContains(t, got, hostCfg)
	})

	t.Run("only loaded file exists yields no warning", func(t *testing.T) {
		got := warnShadowedConfigs([]string{existing, missing}, existing)
		assert.Empty(t, got)
	})
}
