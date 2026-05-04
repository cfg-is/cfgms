//go:build integration

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package database provides integration tests for PostgreSQL storage provider
package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

func TestDatabaseProvider_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	// Test provider registration
	providerNames := interfaces.GetRegisteredProviderNames()
	assert.Contains(t, providerNames, "database")

	// Test getting the provider
	provider, err := interfaces.GetStorageProvider("database")
	require.NoError(t, err)
	assert.NotNil(t, provider)

	// Test creating storage manager (database provider uses single-backend mode)
	storageManager, err := interfaces.CreateAllStoresFromConfig("database", getTestConfig()) //nolint:staticcheck // deprecated helper retained for integration coverage; no replacement in scope for this story
	require.NoError(t, err)
	require.NotNil(t, storageManager)

	assert.Equal(t, "database", storageManager.GetProviderName())
	assert.NotNil(t, storageManager.GetClientTenantStore())
	assert.NotNil(t, storageManager.GetConfigStore())
	assert.NotNil(t, storageManager.GetAuditStore())

	capabilities := storageManager.GetCapabilities()
	assert.True(t, capabilities.SupportsTransactions)
}
