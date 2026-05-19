// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package config

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadWithPath_ParsesCanonicalExample verifies that docs/deployment/controller.cfg
// is valid YAML that the controller config loader accepts and parses to expected values.
func TestLoadWithPath_ParsesCanonicalExample(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must succeed")

	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	configPath := filepath.Join(repoRoot, "docs", "deployment", "controller.cfg")

	cfg, err := LoadWithPath(configPath)
	require.NoError(t, err, "canonical controller.cfg must parse without error")
	require.NotNil(t, cfg)

	// Assert concrete values sourced from controller.cfg to confirm the file was read and parsed.
	assert.Equal(t, "0.0.0.0:9080", cfg.ListenAddr, "listen_addr must match controller.cfg")
	assert.Equal(t, "0.0.0.0:4433", cfg.Transport.ListenAddr, "transport.listen_addr must match controller.cfg")
	assert.Equal(t, "controller.example.com", cfg.Certificate.Server.CommonName, "certificate.server.common_name must match controller.cfg")
	assert.Equal(t, "flatfile", cfg.Storage.Provider, "storage.provider defaults to flatfile when not specified")
	assert.Equal(t, "/var/lib/cfgms/storage", cfg.Storage.FlatfileRoot, "storage.flatfile_root must match controller.cfg")
	assert.Equal(t, "/var/lib/cfgms/cfgms.db", cfg.Storage.SQLitePath, "storage.sqlite_path must match controller.cfg")
}
