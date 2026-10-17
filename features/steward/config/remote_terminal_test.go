// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"os"
	"path/filepath"
	"testing"

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
