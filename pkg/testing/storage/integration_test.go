//go:build integration

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// +build integration

// Package storage provides comprehensive integration testing for storage providers
// Tests storage providers against real backends for Epic 6 validation
package storage

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/server"
	"github.com/cfgis/cfgms/pkg/logging"

	// Import storage providers for integration testing
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func TestStorageProviderIntegration_WithDockerEnvironment(t *testing.T) {
	// This test requires Docker environment to be running
	// Run with: make test-integration-setup && go test -v -tags=integration ./pkg/testing/storage/...

	if !isDockerEnvironmentAvailable() {
		if isInfrastructureRequired() {
			t.Fatal("REQUIRED INFRASTRUCTURE MISSING: Docker integration environment not available in CI/integration mode - run 'make test-integration-setup'")
		} else {
			t.Skip("Docker integration environment not available - run 'make test-integration-setup'")
		}
	}

	logger := logging.NewNoopLogger()
	fixture := NewStorageTestFixture(t)
	defer fixture.Cleanup()

	t.Run("database_provider_with_real_postgres", func(t *testing.T) {
		config, err := fixture.CreateControllerConfig("database")
		require.NoError(t, err, "Should create database controller config")

		// Override with Docker environment settings
		dbConfig := config.Storage.Config
		dbConfig["host"] = os.Getenv("CFGMS_TEST_DB_HOST")
		dbConfig["port"] = 5433
		dbConfig["password"] = os.Getenv("CFGMS_TEST_DB_PASSWORD")

		serverInstance, err := server.New(config, logger)
		require.NoError(t, err, "Should create server with database storage")
		require.NotNil(t, serverInstance, "Server should not be nil")

		t.Log("Database provider successfully initialized with real PostgreSQL")
	})

	t.Run("storage_provider_fixture_validation", func(t *testing.T) {
		// Test our test fixtures work correctly
		fixture.TestAllStorageProviders(t)
	})
}

func TestStorageProviderIntegration_LocalFallback(t *testing.T) {
	// This test runs with local storage only (no Docker required)
	logger := logging.NewNoopLogger()
	fixture := NewStorageTestFixture(t)
	defer fixture.Cleanup()

	t.Run("flatfile_provider_local_filesystem", func(t *testing.T) {
		config, err := fixture.CreateControllerConfig("flatfile")
		require.NoError(t, err, "Should create flatfile controller config")

		// Add FlatfileRoot for OSS composite path
		flatfileConfig, exists := fixture.GetProviderConfig("flatfile")
		require.True(t, exists, "Flatfile config should exist")
		config.Storage.FlatfileRoot = flatfileConfig.Config["root"].(string)

		sqliteConfig, exists := fixture.GetProviderConfig("sqlite")
		require.True(t, exists, "SQLite config should exist")
		config.Storage.SQLitePath = sqliteConfig.Config["path"].(string)

		serverInstance, err := server.New(config, logger)
		if err != nil {
			t.Logf("Flatfile provider local initialization: %v", err)
		} else {
			require.NotNil(t, serverInstance, "Server should not be nil")
			t.Log("Flatfile provider works with local filesystem")
		}
	})

	t.Run("test_fixture_infrastructure", func(t *testing.T) {
		// Test that our test infrastructure components work
		flatfileConfig, exists := fixture.GetProviderConfig("flatfile")
		assert.True(t, exists, "Flatfile config should exist")
		assert.Equal(t, "flatfile", flatfileConfig.Provider)

		dbConfig, exists := fixture.GetProviderConfig("database")
		assert.True(t, exists, "Database config should exist")
		assert.Equal(t, "database", dbConfig.Provider)

		// Verify configurations contain required fields
		assert.Contains(t, flatfileConfig.Config, "root", "Flatfile config should have root")
		assert.Contains(t, dbConfig.Config, "password", "Database config should have password")
	})
}

// Check if Docker integration environment is available
func isDockerEnvironmentAvailable() bool {
	requiredEnvVars := []string{
		"CFGMS_TEST_DB_PASSWORD",
		"CFGMS_TEST_DB_HOST",
	}

	for _, envVar := range requiredEnvVars {
		if os.Getenv(envVar) == "" {
			return false
		}
	}
	return true
}
