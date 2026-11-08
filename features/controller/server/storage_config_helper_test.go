// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	teststorage "github.com/cfgis/cfgms/pkg/testing/storage"
)

// createControllerConfigFromFixture creates a complete controller configuration
// using the specified storage provider from the test fixture.
func createControllerConfigFromFixture(f *teststorage.StorageTestFixture, provider string) (*config.Config, error) {
	storageConfig, exists := f.GetProviderConfig(provider)
	if !exists {
		return nil, fmt.Errorf("storage provider not configured in test fixture: %s", provider)
	}

	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		Storage: &config.StorageConfig{
			Provider: storageConfig.Provider,
			Config:   storageConfig.Config,
		},
	}, nil
}

func TestStorageTestFixture_ControllerConfig(t *testing.T) {
	fixture := teststorage.NewStorageTestFixture(t)
	defer fixture.Cleanup()

	t.Run("flatfile_provider_controller_config", func(t *testing.T) {
		cfg, err := createControllerConfigFromFixture(fixture, "flatfile")
		require.NoError(t, err, "Should create flatfile controller config")
		require.NotNil(t, cfg, "Config should not be nil")

		require.NotNil(t, cfg.Storage, "Storage config should be set")
		assert.Equal(t, "flatfile", cfg.Storage.Provider)
		assert.NotNil(t, cfg.Storage.Config, "Storage provider config should be set")
	})

	t.Run("database_provider_controller_config", func(t *testing.T) {
		cfg, err := createControllerConfigFromFixture(fixture, "database")
		require.NoError(t, err, "Should create database controller config")
		require.NotNil(t, cfg, "Config should not be nil")

		require.NotNil(t, cfg.Storage, "Storage config should be set")
		assert.Equal(t, "database", cfg.Storage.Provider)
		assert.NotNil(t, cfg.Storage.Config, "Storage provider config should be set")
	})

	t.Run("invalid_provider_should_fail", func(t *testing.T) {
		_, err := createControllerConfigFromFixture(fixture, "invalid-provider")
		require.Error(t, err, "Should fail for invalid provider")
		assert.Contains(t, err.Error(), "not configured", "Error should mention configuration issue")
	})
}
