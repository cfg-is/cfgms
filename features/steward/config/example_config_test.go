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

// TestLoadConfiguration_ParsesCanonicalExample verifies that docs/deployment/steward.cfg
// is valid YAML that the steward config loader accepts without error.
func TestLoadConfiguration_ParsesCanonicalExample(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must succeed")

	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	configPath := filepath.Join(repoRoot, "docs", "deployment", "steward.cfg")

	cfg, err := LoadConfiguration(configPath)
	require.NoError(t, err, "canonical steward.cfg must parse without error")
	assert.Equal(t, "my-host-01", cfg.Steward.ID)
	assert.Equal(t, ModeStandalone, cfg.Steward.Mode)
	assert.Equal(t, "info", cfg.Steward.Logging.Level)
	assert.Empty(t, cfg.Resources, "boot config should have no inline resources")
}
