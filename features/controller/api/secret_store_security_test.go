// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
)

func TestNewSecretStore_FailsClosedWithoutExternalKey(t *testing.T) {
	t.Setenv("CFGMS_SECRETS_KEY_FILE", "")
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(t.TempDir(), "data"))
	cfg := config.DefaultConfig()

	store, err := NewSecretStore(cfg)

	assert.Nil(t, store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CFGMS_SECRETS_KEY_FILE is required")
}

func TestNewSecretStore_FailsClosedWhenKeyProviderUnavailable(t *testing.T) {
	t.Setenv("CFGMS_SECRETS_KEY_FILE", filepath.Join(t.TempDir(), "missing.key"))
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(t.TempDir(), "data"))
	cfg := config.DefaultConfig()

	store, err := NewSecretStore(cfg)

	assert.Nil(t, store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stat encryption key file")
}

func TestNewSecretStore_DoesNotUseTemporaryFallback(t *testing.T) {
	t.Setenv("CFGMS_SECRETS_KEY_FILE", filepath.Join(t.TempDir(), "missing.key"))
	t.Setenv("CFGMS_SECRETS_REPO_PATH", "")
	cfg := config.DefaultConfig()
	cfg.DataDir = ""

	store, err := NewSecretStore(cfg)

	assert.Nil(t, store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret storage path is required")
	assert.NotContains(t, err.Error(), os.TempDir())
}
