// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package storage provides comprehensive testing infrastructure for all storage providers
package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Import storage providers for testing
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

func TestStorageTestFixture_Creation(t *testing.T) {
	fixture := NewStorageTestFixture(t)
	defer fixture.Cleanup()

	// Verify fixture initialization
	require.NotEmpty(t, fixture.TempDir, "TempDir should be set")
	require.NotNil(t, fixture.Configs, "Configs should be initialized")
	require.NotNil(t, fixture.Cleanup, "Cleanup function should be set")

	// Verify git configuration
	gitConfig, exists := fixture.GetProviderConfig("git")
	require.True(t, exists, "Git configuration should exist")
	require.Equal(t, "git", gitConfig.Provider)
	require.NotNil(t, gitConfig.Config, "Git config should not be nil")

	// Verify git config contains required fields
	assert.Contains(t, gitConfig.Config, "repository_path")
	assert.Contains(t, gitConfig.Config, "branch")
	assert.Contains(t, gitConfig.Config, "auto_init")

	// Verify database configuration
	dbConfig, exists := fixture.GetProviderConfig("database")
	require.True(t, exists, "Database configuration should exist")
	require.Equal(t, "database", dbConfig.Provider)
	require.NotNil(t, dbConfig.Config, "Database config should not be nil")

	// Verify database config contains required fields
	assert.Contains(t, dbConfig.Config, "host")
	assert.Contains(t, dbConfig.Config, "port")
	assert.Contains(t, dbConfig.Config, "database")
	assert.Contains(t, dbConfig.Config, "username")
	assert.Contains(t, dbConfig.Config, "password")
}

func TestStorageTestFixture_ControllerConfig(t *testing.T) {
	fixture := NewStorageTestFixture(t)
	defer fixture.Cleanup()

	t.Run("git_provider_controller_config", func(t *testing.T) {
		config, err := fixture.CreateControllerConfig("git")
		require.NoError(t, err, "Should create git controller config")
		require.NotNil(t, config, "Config should not be nil")

		require.NotNil(t, config.Storage, "Storage config should be set")
		assert.Equal(t, "git", config.Storage.Provider)
		assert.NotNil(t, config.Storage.Config, "Storage provider config should be set")
	})

	t.Run("database_provider_controller_config", func(t *testing.T) {
		config, err := fixture.CreateControllerConfig("database")
		require.NoError(t, err, "Should create database controller config")
		require.NotNil(t, config, "Config should not be nil")

		require.NotNil(t, config.Storage, "Storage config should be set")
		assert.Equal(t, "database", config.Storage.Provider)
		assert.NotNil(t, config.Storage.Config, "Storage provider config should be set")
	})

	t.Run("invalid_provider_should_fail", func(t *testing.T) {
		_, err := fixture.CreateControllerConfig("invalid-provider")
		assert.Error(t, err, "Should fail for invalid provider")
		assert.Contains(t, err.Error(), "not configured", "Error should mention configuration issue")
	})
}

func TestStorageTestFixture_ProviderValidation(t *testing.T) {
	fixture := NewStorageTestFixture(t)
	defer fixture.Cleanup()

	// Test individual provider validation
	t.Run("git_provider_validation", func(t *testing.T) {
		fixture.ValidateStorageProvider(t, "git")
	})

	t.Run("database_provider_validation", func(t *testing.T) {
		// Database validation may skip if database not available
		fixture.ValidateStorageProvider(t, "database")
	})
}

func TestStorageTestFixture_AllProviders(t *testing.T) {
	fixture := NewStorageTestFixture(t)
	defer fixture.Cleanup()

	// Test all registered storage providers
	fixture.TestAllStorageProviders(t)
}

func TestSkipHelpers(t *testing.T) {
	t.Run("database_skip_helper", func(t *testing.T) {
		// This test validates the skip helper works
		// In CI environment without database, this would skip
		// In development with CFGMS_TEST_DB_PASSWORD set, this runs
		SkipIfDatabaseNotAvailable(t)

		// If we reach here, database is available for testing
		t.Log("Database testing is available")
	})

	t.Run("git_skip_helper", func(t *testing.T) {
		SkipIfGitNotAvailable(t)

		// Git should always be available
		t.Log("Git testing is available")
	})
}
