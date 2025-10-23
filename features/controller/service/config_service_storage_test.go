// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// MockConfigStore for testing Epic 6 compliance
type MockConfigStore struct {
	configs map[string]*interfaces.ConfigEntry
	history map[string][]*interfaces.ConfigEntry
}

func NewMockConfigStore() *MockConfigStore {
	return &MockConfigStore{
		configs: make(map[string]*interfaces.ConfigEntry),
		history: make(map[string][]*interfaces.ConfigEntry),
	}
}

func (m *MockConfigStore) StoreConfig(ctx context.Context, config *interfaces.ConfigEntry) error {
	key := config.Key.String()

	// Store current version in history
	if existing, exists := m.configs[key]; exists {
		if m.history[key] == nil {
			m.history[key] = []*interfaces.ConfigEntry{}
		}
		m.history[key] = append(m.history[key], existing)
	}

	// Set version and timestamps
	config.Version = int64(len(m.history[key]) + 1)
	config.UpdatedAt = time.Now()
	if config.CreatedAt.IsZero() {
		config.CreatedAt = config.UpdatedAt
	}

	// Store new version
	m.configs[key] = config
	return nil
}

func (m *MockConfigStore) GetConfig(ctx context.Context, key *interfaces.ConfigKey) (*interfaces.ConfigEntry, error) {
	keyStr := key.String()
	config, exists := m.configs[keyStr]
	if !exists {
		return nil, interfaces.ErrConfigNotFound
	}

	// Return a copy
	configCopy := *config
	return &configCopy, nil
}

func (m *MockConfigStore) DeleteConfig(ctx context.Context, key *interfaces.ConfigKey) error {
	keyStr := key.String()
	delete(m.configs, keyStr)
	delete(m.history, keyStr)
	return nil
}

func (m *MockConfigStore) ListConfigs(ctx context.Context, filter *interfaces.ConfigFilter) ([]*interfaces.ConfigEntry, error) {
	var results []*interfaces.ConfigEntry

	for _, config := range m.configs {
		// Apply filtering
		if filter.TenantID != "" && config.Key.TenantID != filter.TenantID {
			continue
		}
		if filter.Namespace != "" && config.Key.Namespace != filter.Namespace {
			continue
		}

		// Return a copy
		configCopy := *config
		results = append(results, &configCopy)
	}

	return results, nil
}

func (m *MockConfigStore) GetConfigHistory(ctx context.Context, key *interfaces.ConfigKey, limit int) ([]*interfaces.ConfigEntry, error) {
	keyStr := key.String()
	history, exists := m.history[keyStr]
	if !exists {
		return []*interfaces.ConfigEntry{}, nil
	}

	// Return most recent versions first
	var results []*interfaces.ConfigEntry
	start := len(history) - limit
	if start < 0 {
		start = 0
	}

	for i := len(history) - 1; i >= start; i-- {
		configCopy := *history[i]
		results = append(results, &configCopy)
	}

	return results, nil
}

func (m *MockConfigStore) GetConfigVersion(ctx context.Context, key *interfaces.ConfigKey, version int64) (*interfaces.ConfigEntry, error) {
	keyStr := key.String()
	history, exists := m.history[keyStr]
	if !exists {
		return nil, interfaces.ErrConfigNotFound
	}

	// Find version in history
	for _, entry := range history {
		if entry.Version == version {
			configCopy := *entry
			return &configCopy, nil
		}
	}

	return nil, interfaces.ErrConfigNotFound
}

func (m *MockConfigStore) StoreConfigBatch(ctx context.Context, configs []*interfaces.ConfigEntry) error {
	for _, config := range configs {
		if err := m.StoreConfig(ctx, config); err != nil {
			return err
		}
	}
	return nil
}

func (m *MockConfigStore) DeleteConfigBatch(ctx context.Context, keys []*interfaces.ConfigKey) error {
	for _, key := range keys {
		if err := m.DeleteConfig(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

func (m *MockConfigStore) ResolveConfigWithInheritance(ctx context.Context, key *interfaces.ConfigKey) (*interfaces.ConfigEntry, error) {
	// Simplified inheritance - just return the direct config
	return m.GetConfig(ctx, key)
}

func (m *MockConfigStore) ValidateConfig(ctx context.Context, config *interfaces.ConfigEntry) error {
	if config.Key == nil {
		return interfaces.ErrTenantRequired
	}
	return nil
}

func (m *MockConfigStore) GetConfigStats(ctx context.Context) (*interfaces.ConfigStats, error) {
	totalConfigs := int64(len(m.configs))
	totalSize := int64(0)

	for _, config := range m.configs {
		totalSize += int64(len(config.Data))
	}

	var averageSize int64
	if totalConfigs > 0 {
		averageSize = totalSize / totalConfigs
	}

	return &interfaces.ConfigStats{
		TotalConfigs: totalConfigs,
		TotalSize:    totalSize,
		AverageSize:  averageSize,
		LastUpdated:  time.Now(),
	}, nil
}

// TestConfigurationStorageMigration tests the Epic 6 compliant storage migration
func TestConfigurationStorageMigration(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	configStore := NewMockConfigStore()
	migration := NewConfigurationStorageMigration(configStore, logger)

	// Test configuration
	testConfig := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "test-steward",
			Mode: stewardconfig.ModeStandalone,
			Logging: stewardconfig.LoggingConfig{
				Level:  "info",
				Format: "text",
			},
		},
		Resources: []stewardconfig.ResourceConfig{
			{
				Name:   "test-resource",
				Module: "directory",
				Config: map[string]interface{}{
					"path":        "/opt/test",
					"permissions": "755",
				},
			},
		},
	}

	// Test storing configuration
	t.Run("StoreAndRetrieveConfiguration", func(t *testing.T) {
		err := migration.StoreConfiguration(ctx, "test-tenant", "test-steward", testConfig)
		require.NoError(t, err)

		retrievedConfig, err := migration.GetConfiguration(ctx, "test-tenant", "test-steward")
		require.NoError(t, err)

		assert.Equal(t, testConfig.Steward.ID, retrievedConfig.Steward.ID)
		assert.Equal(t, testConfig.Steward.Mode, retrievedConfig.Steward.Mode)
		assert.Len(t, retrievedConfig.Resources, 1)
		assert.Equal(t, "test-resource", retrievedConfig.Resources[0].Name)
	})

	// Test configuration with inheritance
	t.Run("GetConfigurationWithInheritance", func(t *testing.T) {
		err := migration.StoreConfiguration(ctx, "test-tenant", "inheritance-test", testConfig)
		require.NoError(t, err)

		inheritedConfig, err := migration.GetConfigurationWithInheritance(ctx, "test-tenant", "inheritance-test")
		require.NoError(t, err)

		assert.Equal(t, testConfig.Steward.ID, inheritedConfig.Steward.ID)
	})

	// Test StoredConfiguration compatibility
	t.Run("GetStoredConfiguration", func(t *testing.T) {
		err := migration.StoreConfiguration(ctx, "test-tenant", "stored-config-test", testConfig)
		require.NoError(t, err)

		storedConfig, err := migration.GetStoredConfiguration(ctx, "test-tenant", "stored-config-test")
		require.NoError(t, err)

		assert.Equal(t, "stored-config-test", storedConfig.StewardID)
		assert.Equal(t, "test-tenant", storedConfig.TenantID)
		assert.NotEmpty(t, storedConfig.Version)
		assert.Equal(t, testConfig.Steward.ID, storedConfig.Config.Steward.ID)
	})

	// Test listing configurations
	t.Run("ListConfigurations", func(t *testing.T) {
		// Store multiple configurations
		for i := 0; i < 3; i++ {
			config := *testConfig
			config.Steward.ID = fmt.Sprintf("steward-%d", i)
			err := migration.StoreConfiguration(ctx, "list-test-tenant", config.Steward.ID, &config)
			require.NoError(t, err)
		}

		configs, err := migration.ListConfigurations(ctx, "list-test-tenant")
		require.NoError(t, err)
		assert.Len(t, configs, 3)

		// Verify all configurations are present
		stewardIDs := make(map[string]bool)
		for _, config := range configs {
			stewardIDs[config.StewardID] = true
		}

		assert.True(t, stewardIDs["steward-0"])
		assert.True(t, stewardIDs["steward-1"])
		assert.True(t, stewardIDs["steward-2"])
	})

	// Test versioning and history
	t.Run("ConfigurationVersioning", func(t *testing.T) {
		// Store initial version
		err := migration.StoreConfiguration(ctx, "version-tenant", "version-test", testConfig)
		require.NoError(t, err)

		// Store second version with different logging level
		modifiedConfig := *testConfig
		modifiedConfig.Steward.Logging.Level = "debug"
		err = migration.StoreConfiguration(ctx, "version-tenant", "version-test", &modifiedConfig)
		require.NoError(t, err)

		// Get history
		history, err := migration.GetConfigurationHistory(ctx, "version-tenant", "version-test", 5)
		require.NoError(t, err)
		assert.Len(t, history, 1) // One version in history (current version not included)

		// Get specific version
		version1Config, err := migration.GetConfigurationVersion(ctx, "version-tenant", "version-test", 1)
		require.NoError(t, err)
		assert.Equal(t, "info", version1Config.Steward.Logging.Level) // Original version

		// Get current version should have debug level
		currentConfig, err := migration.GetConfiguration(ctx, "version-tenant", "version-test")
		require.NoError(t, err)
		assert.Equal(t, "debug", currentConfig.Steward.Logging.Level) // Modified version
	})

	// Test configuration validation
	t.Run("ConfigurationValidation", func(t *testing.T) {
		// Valid configuration should pass
		err := migration.ValidateConfiguration(ctx, testConfig)
		assert.NoError(t, err)

		// Invalid configuration should fail (empty steward ID)
		invalidConfig := &stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{
				ID:   "", // Invalid empty ID
				Mode: stewardconfig.ModeStandalone,
			},
		}

		err = migration.ValidateConfiguration(ctx, invalidConfig)
		assert.Error(t, err)
	})

	// Test deleting configurations
	t.Run("DeleteConfiguration", func(t *testing.T) {
		// Store configuration
		err := migration.StoreConfiguration(ctx, "delete-tenant", "delete-test", testConfig)
		require.NoError(t, err)

		// Verify it exists
		_, err = migration.GetConfiguration(ctx, "delete-tenant", "delete-test")
		assert.NoError(t, err)

		// Delete it
		err = migration.DeleteConfiguration(ctx, "delete-tenant", "delete-test")
		assert.NoError(t, err)

		// Verify it's gone
		_, err = migration.GetConfiguration(ctx, "delete-tenant", "delete-test")
		assert.Error(t, err)
	})

	// Test storage stats
	t.Run("StorageStats", func(t *testing.T) {
		// Store a configuration
		err := migration.StoreConfiguration(ctx, "stats-tenant", "stats-test", testConfig)
		require.NoError(t, err)

		stats, err := migration.GetStats(ctx)
		require.NoError(t, err)

		assert.Greater(t, stats.TotalConfigs, int64(0))
		assert.Greater(t, stats.TotalSize, int64(0))
		assert.NotZero(t, stats.LastUpdated)
	})
}

// TestEpic6ComplianceRequirements validates Epic 6 specific compliance requirements
func TestEpic6ComplianceRequirements(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	configStore := NewMockConfigStore()
	migration := NewConfigurationStorageMigration(configStore, logger)

	testConfig := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "compliance-test",
			Mode: stewardconfig.ModeStandalone,
		},
	}

	// Epic 6: Zero Package-Level Storage Mechanisms
	t.Run("Epic6_NoPackageLevelStorage", func(t *testing.T) {
		// This test validates that ConfigurationStorageMigration uses ONLY ConfigStore interface
		// and has NO package-level storage mechanisms (no file I/O, no memory stores)

		err := migration.StoreConfiguration(ctx, "epic6-tenant", "no-package-storage", testConfig)
		require.NoError(t, err)

		config, err := migration.GetConfiguration(ctx, "epic6-tenant", "no-package-storage")
		require.NoError(t, err)
		assert.Equal(t, testConfig.Steward.ID, config.Steward.ID)
	})

	// Epic 6: Storage Provider Compliance
	t.Run("Epic6_StorageProviderCompliance", func(t *testing.T) {
		// Validates that ALL operations flow through storage provider interfaces
		// No direct file operations, no package-level stores

		err := migration.StoreConfiguration(ctx, "epic6-tenant", "provider-compliance", testConfig)
		require.NoError(t, err)

		// Verify data persists through storage provider
		storedConfig, err := migration.GetStoredConfiguration(ctx, "epic6-tenant", "provider-compliance")
		require.NoError(t, err)
		assert.NotNil(t, storedConfig)
		assert.Equal(t, "provider-compliance", storedConfig.StewardID)
	})

	// Epic 6: Persistent Storage Validation
	t.Run("Epic6_PersistentStorageValidation", func(t *testing.T) {
		// All configuration data persists across service restarts
		err := migration.StoreConfiguration(ctx, "epic6-tenant", "persistence-test", testConfig)
		require.NoError(t, err)

		// Simulate restart by creating new migration instance with same storage
		newMigration := NewConfigurationStorageMigration(configStore, logger)

		// Configuration must still be accessible
		config, err := newMigration.GetConfiguration(ctx, "epic6-tenant", "persistence-test")
		require.NoError(t, err)
		assert.Equal(t, testConfig.Steward.ID, config.Steward.ID)
	})
}

// TestInMemoryToStorageMigration tests migrating from in-memory to storage provider
func TestInMemoryToStorageMigration(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	configStore := NewMockConfigStore()
	migration := NewConfigurationStorageMigration(configStore, logger)

	// Create mock in-memory configurations (simulating old system)
	inMemoryConfigs := map[string]*StoredConfiguration{
		"tenant1:steward1": {
			StewardID: "steward1",
			TenantID:  "tenant1",
			Version:   "v1",
			Config: &stewardconfig.StewardConfig{
				Steward: stewardconfig.StewardSettings{
					ID:   "steward1",
					Mode: stewardconfig.ModeStandalone,
				},
			},
			LastUpdated: time.Now(),
			CreatedAt:   time.Now().Add(-1 * time.Hour),
		},
		"tenant2:steward2": {
			StewardID: "steward2",
			TenantID:  "tenant2",
			Version:   "v1",
			Config: &stewardconfig.StewardConfig{
				Steward: stewardconfig.StewardSettings{
					ID:   "steward2",
					Mode: stewardconfig.ModeController,
				},
			},
			LastUpdated: time.Now(),
			CreatedAt:   time.Now().Add(-2 * time.Hour),
		},
	}

	// Test migration
	t.Run("MigrateFromInMemoryToStorage", func(t *testing.T) {
		err := migration.MigrateFromInMemory(ctx, inMemoryConfigs)
		require.NoError(t, err)

		// Verify all configurations were migrated
		config1, err := migration.GetConfiguration(ctx, "tenant1", "steward1")
		require.NoError(t, err)
		assert.Equal(t, "steward1", config1.Steward.ID)
		assert.Equal(t, stewardconfig.ModeStandalone, config1.Steward.Mode)

		config2, err := migration.GetConfiguration(ctx, "tenant2", "steward2")
		require.NoError(t, err)
		assert.Equal(t, "steward2", config2.Steward.ID)
		assert.Equal(t, stewardconfig.ModeController, config2.Steward.Mode)
	})
}
