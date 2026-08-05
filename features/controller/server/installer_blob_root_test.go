// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"path/filepath"
	"testing"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/stretchr/testify/assert"
)

func TestResolveInstallerBlobRootUsesLoadedDeploymentPaths(t *testing.T) {
	t.Parallel()

	// A deployment's data directory, spelled the way the host spells paths:
	// resolveInstallerBlobRoot joins with filepath, so the expectation has to be
	// built the same way rather than hard-coded to one platform's separator.
	dataDir := filepath.Join(string(filepath.Separator), "var", "lib", "cfgms")

	cfg := config.DefaultConfig()
	cfg.DataDir = dataDir
	cfg.Storage.FlatfileRoot = filepath.Join(dataDir, "storage")
	cfg.Storage.SQLitePath = filepath.Join(dataDir, "cfgms.db")

	assert.Empty(t, cfg.BlobStorage.Root,
		"default must not freeze a relative root before YAML overrides are loaded")
	assert.Equal(t, filepath.Join(dataDir, "installers"), resolveInstallerBlobRoot(cfg))
}

func TestResolveInstallerBlobRootPrecedence(t *testing.T) {
	t.Parallel()

	explicit := filepath.Join(t.TempDir(), "explicit")
	cfg := &config.Config{
		DataDir:     filepath.Join(t.TempDir(), "data"),
		BlobStorage: config.BlobStorageConfig{Root: explicit},
		Storage: &config.StorageConfig{
			FlatfileRoot: filepath.Join(t.TempDir(), "storage"),
			SQLitePath:   filepath.Join(t.TempDir(), "cfgms.db"),
		},
	}
	assert.Equal(t, explicit, resolveInstallerBlobRoot(cfg))
}
