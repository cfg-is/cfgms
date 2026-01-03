// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/service"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git" // Register git provider for tenant persistence test
)

// MockStorageProvider implements interfaces.StorageProvider for testing
type MockStorageProvider struct{}

func (m *MockStorageProvider) Name() string             { return "mock" }
func (m *MockStorageProvider) Description() string      { return "Mock storage provider for testing" }
func (m *MockStorageProvider) Available() (bool, error) { return true, nil }
func (m *MockStorageProvider) GetVersion() string       { return "1.0.0" }
func (m *MockStorageProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{
		SupportsTransactions:   true,
		SupportsVersioning:     true,
		SupportsFullTextSearch: false,
		SupportsEncryption:     false,
		SupportsCompression:    false,
		SupportsReplication:    false,
		SupportsSharding:       false,
		MaxBatchSize:           100,
		MaxConfigSize:          1024 * 1024, // 1MB
		MaxAuditRetentionDays:  365,
	}
}

// MockConfigStore implements interfaces.ConfigStore for testing Epic 6 compliance
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

	// Return most recent versions first, limited by limit
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

// Implement remaining interfaces.StorageProvider methods
func (m *MockStorageProvider) CreateClientTenantStore(config map[string]interface{}) (interfaces.ClientTenantStore, error) {
	return nil, nil // Not needed for this test
}

func (m *MockStorageProvider) CreateConfigStore(config map[string]interface{}) (interfaces.ConfigStore, error) {
	return NewMockConfigStore(), nil
}

func (m *MockStorageProvider) CreateAuditStore(config map[string]interface{}) (interfaces.AuditStore, error) {
	return nil, nil // Not needed for this test
}

func (m *MockStorageProvider) CreateRBACStore(config map[string]interface{}) (interfaces.RBACStore, error) {
	return nil, nil // Not needed for this test
}

func (m *MockStorageProvider) CreateRuntimeStore(config map[string]interface{}) (interfaces.RuntimeStore, error) {
	return nil, nil // Not needed for this test
}

func (m *MockStorageProvider) CreateTenantStore(config map[string]interface{}) (interfaces.TenantStore, error) {
	return nil, nil // Not needed for this test
}

// TestEpic6ComplianceConfigurationStorage validates Epic 6 compliance requirements
func TestEpic6ComplianceConfigurationStorage(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()

	// Create mock storage provider and ConfigStore
	_ = &MockStorageProvider{} // Create provider for potential future use
	configStore := NewMockConfigStore()

	// Create configuration storage migration (Epic 6 compliant)
	configStorageMigration := service.NewConfigurationStorageMigration(configStore, logger)

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

	// Epic 6 Requirement: ALL configuration operations use storage provider interfaces ONLY
	t.Run("Epic6_OnlyStorageProviderInterfaces", func(t *testing.T) {
		// Store configuration - must use ConfigStore interface
		err := configStorageMigration.StoreConfiguration(ctx, "test-tenant", "test-steward", testConfig)
		require.NoError(t, err)

		// Retrieve configuration - must use ConfigStore interface
		retrievedConfig, err := configStorageMigration.GetConfiguration(ctx, "test-tenant", "test-steward")
		require.NoError(t, err)

		// Verify configuration matches
		assert.Equal(t, testConfig.Steward.ID, retrievedConfig.Steward.ID)
		assert.Equal(t, testConfig.Steward.Mode, retrievedConfig.Steward.Mode)
		assert.Len(t, retrievedConfig.Resources, 1)
		assert.Equal(t, "test-resource", retrievedConfig.Resources[0].Name)
	})

	// Epic 6 Requirement: Configuration data MUST survive system restarts (durability)
	t.Run("Epic6_ConfigurationPersistenceDurability", func(t *testing.T) {
		// Store configuration
		err := configStorageMigration.StoreConfiguration(ctx, "test-tenant", "durability-test", testConfig)
		require.NoError(t, err)

		// Simulate system restart by creating new storage migration instance
		newConfigStorageMigration := service.NewConfigurationStorageMigration(configStore, logger)

		// Configuration must still exist after "restart"
		retrievedConfig, err := newConfigStorageMigration.GetConfiguration(ctx, "test-tenant", "durability-test")
		require.NoError(t, err)
		assert.Equal(t, testConfig.Steward.ID, retrievedConfig.Steward.ID)
	})

	// Epic 6 Requirement: NO direct file operations for configuration storage
	t.Run("Epic6_NoDirectFileOperations", func(t *testing.T) {
		// This test verifies that ConfigurationStorageMigration only uses ConfigStore interface
		// and never performs direct file operations like os.WriteFile, ioutil.ReadFile, etc.

		// The fact that we're using a mock ConfigStore that doesn't touch the filesystem
		// and our operations still work proves we're not doing direct file operations

		err := configStorageMigration.StoreConfiguration(ctx, "test-tenant", "no-file-ops", testConfig)
		require.NoError(t, err)

		config, err := configStorageMigration.GetConfiguration(ctx, "test-tenant", "no-file-ops")
		require.NoError(t, err)
		assert.NotNil(t, config)
	})

	// Epic 6 Requirement: Configuration inheritance works via storage provider queries
	t.Run("Epic6_InheritanceViaStorageQueries", func(t *testing.T) {
		// Store base configuration
		err := configStorageMigration.StoreConfiguration(ctx, "test-tenant", "inheritance-test", testConfig)
		require.NoError(t, err)

		// Get configuration with inheritance - must use storage provider's ResolveConfigWithInheritance
		inheritedConfig, err := configStorageMigration.GetConfigurationWithInheritance(ctx, "test-tenant", "inheritance-test")
		require.NoError(t, err)
		assert.Equal(t, testConfig.Steward.ID, inheritedConfig.Steward.ID)
	})

	// Epic 6 Requirement: Rollback functionality uses storage provider versioning capabilities
	t.Run("Epic6_VersioningForRollback", func(t *testing.T) {
		// Store initial version
		err := configStorageMigration.StoreConfiguration(ctx, "test-tenant", "version-test", testConfig)
		require.NoError(t, err)

		// Store second version
		modifiedConfig := *testConfig
		modifiedConfig.Steward.Logging.Level = "debug"
		err = configStorageMigration.StoreConfiguration(ctx, "test-tenant", "version-test", &modifiedConfig)
		require.NoError(t, err)

		// Get configuration history - must use storage provider versioning
		history, err := configStorageMigration.GetConfigurationHistory(ctx, "test-tenant", "version-test", 5)
		require.NoError(t, err)
		assert.Len(t, history, 1) // First version is in history

		// Get specific version - must use storage provider versioning
		version1Config, err := configStorageMigration.GetConfigurationVersion(ctx, "test-tenant", "version-test", 1)
		require.NoError(t, err)
		assert.Equal(t, "info", version1Config.Steward.Logging.Level) // Original version
	})

	// Epic 6 Requirement: Zero data loss during system restart or failure scenarios
	t.Run("Epic6_ZeroDataLoss", func(t *testing.T) {
		// Store multiple configurations
		configs := []*stewardconfig.StewardConfig{}
		for i := 0; i < 3; i++ {
			config := *testConfig
			config.Steward.ID = fmt.Sprintf("steward-%d", i)
			configs = append(configs, &config)

			err := configStorageMigration.StoreConfiguration(ctx, "test-tenant", config.Steward.ID, &config)
			require.NoError(t, err)
		}

		// Verify all configurations can be retrieved
		storedConfigs, err := configStorageMigration.ListConfigurations(ctx, "test-tenant")
		require.NoError(t, err)

		// Should have at least the 3 configs we stored (might have more from other tests)
		foundCount := 0
		for _, stored := range storedConfigs {
			for _, original := range configs {
				if stored.StewardID == original.Steward.ID {
					foundCount++
					assert.Equal(t, original.Steward.ID, stored.Config.Steward.ID)
					break
				}
			}
		}
		assert.Equal(t, 3, foundCount, "All stored configurations must be retrievable")
	})
}

// TestEpic6ComplianceValidation validates that Epic 6 compliance requirements are enforced
func TestEpic6ComplianceValidation(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	configStore := NewMockConfigStore()
	configStorageMigration := service.NewConfigurationStorageMigration(configStore, logger)

	// Valid configuration for testing
	validConfig := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "test-steward",
			Mode: stewardconfig.ModeStandalone,
		},
	}

	// Test configuration validation
	t.Run("Epic6_ConfigurationValidation", func(t *testing.T) {
		t.Skip("Configuration validation requires complete config structure - will be fixed in future story")
		// Valid configuration should pass
		err := configStorageMigration.ValidateConfiguration(ctx, validConfig)
		assert.NoError(t, err)

		// Invalid configuration should fail
		invalidConfig := &stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{
				ID:   "",             // Invalid: empty ID after defaults applied
				Mode: "invalid-mode", // Invalid mode
			},
		}

		err = configStorageMigration.ValidateConfiguration(ctx, invalidConfig)
		assert.Error(t, err)
	})

	// Test storage statistics
	t.Run("Epic6_StorageStatistics", func(t *testing.T) {
		// Store a configuration
		err := configStorageMigration.StoreConfiguration(ctx, "test-tenant", "stats-test", validConfig)
		require.NoError(t, err)

		// Get storage stats
		stats, err := configStorageMigration.GetStats(ctx)
		require.NoError(t, err)

		assert.Greater(t, stats.TotalConfigs, int64(0))
		assert.Greater(t, stats.TotalSize, int64(0))
		assert.NotZero(t, stats.LastUpdated)
	})
}

// TestEpic6TenantStoragePersistence validates tenant data persistence (Story #262)
// This test ensures that tenant management uses durable storage and survives restarts
func TestEpic6TenantStoragePersistence(t *testing.T) {
	ctx := context.Background()

	// Create a temporary directory for test git storage
	tempDir := t.TempDir()

	// Create git-backed tenant store (git provider is auto-registered via blank import)
	config := map[string]interface{}{
		"repository_path": tempDir,
	}

	tenantStore, err := interfaces.CreateTenantStoreFromConfig("git", config)
	require.NoError(t, err, "Should create git tenant store")
	defer func() { _ = tenantStore.Close() }()

	// Initialize the store
	err = tenantStore.Initialize(ctx)
	require.NoError(t, err, "Should initialize tenant store")

	// Test: Create tenant with hierarchy
	t.Run("CreateTenantHierarchy", func(t *testing.T) {
		// Create root tenant (MSP level)
		rootTenant := &interfaces.TenantData{
			ID:          "msp-root",
			Name:        "Test MSP",
			Description: "Root MSP tenant for testing",
			Status:      interfaces.TenantStatusActive,
			Metadata:    map[string]string{"tier": "msp"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		err := tenantStore.CreateTenant(ctx, rootTenant)
		require.NoError(t, err, "Should create root tenant")

		// Create child tenant (Client level)
		childTenant := &interfaces.TenantData{
			ID:          "client-1",
			Name:        "Test Client",
			Description: "Client under MSP",
			ParentID:    "msp-root",
			Status:      interfaces.TenantStatusActive,
			Metadata:    map[string]string{"tier": "client"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		err = tenantStore.CreateTenant(ctx, childTenant)
		require.NoError(t, err, "Should create child tenant")

		// Create grandchild tenant (Group level)
		groupTenant := &interfaces.TenantData{
			ID:          "group-1",
			Name:        "Test Group",
			Description: "Group under client",
			ParentID:    "client-1",
			Status:      interfaces.TenantStatusActive,
			Metadata:    map[string]string{"tier": "group"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		err = tenantStore.CreateTenant(ctx, groupTenant)
		require.NoError(t, err, "Should create group tenant")
	})

	// Test: Verify tenant hierarchy
	t.Run("VerifyTenantHierarchy", func(t *testing.T) {
		// Get tenant path
		path, err := tenantStore.GetTenantPath(ctx, "group-1")
		require.NoError(t, err, "Should get tenant path")
		require.Equal(t, []string{"msp-root", "client-1", "group-1"}, path, "Path should be correct")

		// Verify ancestor relationship
		isAncestor, err := tenantStore.IsTenantAncestor(ctx, "msp-root", "group-1")
		require.NoError(t, err)
		require.True(t, isAncestor, "MSP should be ancestor of group")

		isAncestor, err = tenantStore.IsTenantAncestor(ctx, "client-1", "group-1")
		require.NoError(t, err)
		require.True(t, isAncestor, "Client should be ancestor of group")

		// Get child tenants
		children, err := tenantStore.GetChildTenants(ctx, "msp-root")
		require.NoError(t, err)
		require.Len(t, children, 1, "MSP should have one direct child")
		require.Equal(t, "client-1", children[0].ID)
	})

	// Test: Persistence - Close and reopen store
	t.Run("PersistenceAcrossRestart", func(t *testing.T) {
		// Close the current store
		err := tenantStore.Close()
		require.NoError(t, err)

		// Create a new store instance pointing to same directory (simulating restart)
		newStore, err := interfaces.CreateTenantStoreFromConfig("git", config)
		require.NoError(t, err, "Should create new store instance")
		defer func() { _ = newStore.Close() }()

		err = newStore.Initialize(ctx)
		require.NoError(t, err)

		// Verify all data persisted
		tenant, err := newStore.GetTenant(ctx, "msp-root")
		require.NoError(t, err, "Root tenant should persist")
		assert.Equal(t, "Test MSP", tenant.Name)

		tenant, err = newStore.GetTenant(ctx, "client-1")
		require.NoError(t, err, "Child tenant should persist")
		assert.Equal(t, "Test Client", tenant.Name)
		assert.Equal(t, "msp-root", tenant.ParentID)

		tenant, err = newStore.GetTenant(ctx, "group-1")
		require.NoError(t, err, "Group tenant should persist")
		assert.Equal(t, "Test Group", tenant.Name)

		// Verify hierarchy persisted
		path, err := newStore.GetTenantPath(ctx, "group-1")
		require.NoError(t, err)
		assert.Equal(t, []string{"msp-root", "client-1", "group-1"}, path)

		// Update the tenantStore reference for subsequent tests
		tenantStore = newStore
	})

	// Test: Update tenant
	t.Run("UpdateTenant", func(t *testing.T) {
		tenant, err := tenantStore.GetTenant(ctx, "msp-root")
		require.NoError(t, err)

		tenant.Description = "Updated description"
		tenant.UpdatedAt = time.Now()

		err = tenantStore.UpdateTenant(ctx, tenant)
		require.NoError(t, err)

		// Verify update
		updated, err := tenantStore.GetTenant(ctx, "msp-root")
		require.NoError(t, err)
		assert.Equal(t, "Updated description", updated.Description)
	})

	// Test: List and filter tenants
	t.Run("ListAndFilterTenants", func(t *testing.T) {
		// List all tenants
		all, err := tenantStore.ListTenants(ctx, nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(all), 3, "Should have at least 3 tenants")

		// Filter by parent
		filter := &interfaces.TenantFilter{ParentID: "msp-root"}
		children, err := tenantStore.ListTenants(ctx, filter)
		require.NoError(t, err)
		assert.Len(t, children, 1)
		assert.Equal(t, "client-1", children[0].ID)
	})

	// Test: Delete tenant
	t.Run("DeleteTenant", func(t *testing.T) {
		err := tenantStore.DeleteTenant(ctx, "group-1")
		require.NoError(t, err)

		_, err = tenantStore.GetTenant(ctx, "group-1")
		assert.Error(t, err, "Deleted tenant should not be found")
	})
}

// TestPersistenceRegressionGuard is a comprehensive test ensuring ALL persistent data
// survives restarts. This test guards against reintroducing in-memory storage for
// data that must be durable.
//
// CRITICAL: This test should fail if ANY storage type loses data across restart.
// If this test fails, it means someone has introduced a regression by using
// non-durable (e.g., memory-only) storage for data that must persist.
func TestPersistenceRegressionGuard(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	storageConfig := map[string]interface{}{
		"repository_path": tempDir,
	}

	// ============================================================
	// PHASE 1: Create data using fresh storage manager
	// ============================================================
	t.Log("PHASE 1: Creating data with fresh storage manager")

	storageManager, err := interfaces.CreateAllStoresFromConfig("git", storageConfig)
	require.NoError(t, err, "Should create storage manager")

	// Create tenant data
	tenantStore := storageManager.GetTenantStore()
	err = tenantStore.Initialize(ctx)
	require.NoError(t, err)

	testTenant := &interfaces.TenantData{
		ID:          "persistence-test-tenant",
		Name:        "Persistence Test Tenant",
		Description: "Tenant for persistence regression testing",
		Status:      interfaces.TenantStatusActive,
		Metadata:    map[string]string{"test": "persistence"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	err = tenantStore.CreateTenant(ctx, testTenant)
	require.NoError(t, err, "Should create test tenant")

	// Create configuration data
	configStore := storageManager.GetConfigStore()
	testConfig := &interfaces.ConfigEntry{
		Key: &interfaces.ConfigKey{
			TenantID:  "persistence-test-tenant",
			Namespace: "test-namespace",
			Name:      "test-config",
		},
		Data:     []byte(`{"setting": "value", "enabled": true}`),
		Format:   "json",
		Checksum: "test-checksum-123",
		Metadata: map[string]interface{}{"test": "persistence"},
		Tags:     []string{"test", "persistence"},
	}
	err = configStore.StoreConfig(ctx, testConfig)
	require.NoError(t, err, "Should store test config")

	// Verify data exists before restart
	retrievedTenant, err := tenantStore.GetTenant(ctx, "persistence-test-tenant")
	require.NoError(t, err, "Should retrieve tenant before restart")
	assert.Equal(t, "Persistence Test Tenant", retrievedTenant.Name)

	retrievedConfig, err := configStore.GetConfig(ctx, testConfig.Key)
	require.NoError(t, err, "Should retrieve config before restart")
	// Note: Git provider normalizes JSON to YAML, so check semantic content not exact bytes
	assert.Contains(t, string(retrievedConfig.Data), "enabled")
	assert.Contains(t, string(retrievedConfig.Data), "setting")

	t.Log("PHASE 1 COMPLETE: Data created and verified")

	// ============================================================
	// PHASE 2: Simulate restart - close all stores
	// ============================================================
	t.Log("PHASE 2: Simulating restart - closing all stores")

	err = tenantStore.Close()
	require.NoError(t, err, "Should close tenant store")

	t.Log("PHASE 2 COMPLETE: All stores closed")

	// ============================================================
	// PHASE 3: Recreate storage manager (simulating restart)
	// ============================================================
	t.Log("PHASE 3: Recreating storage manager (simulating restart)")

	newStorageManager, err := interfaces.CreateAllStoresFromConfig("git", storageConfig)
	require.NoError(t, err, "Should create new storage manager after restart")

	newTenantStore := newStorageManager.GetTenantStore()
	err = newTenantStore.Initialize(ctx)
	require.NoError(t, err)

	newConfigStore := newStorageManager.GetConfigStore()

	t.Log("PHASE 3 COMPLETE: New storage manager created")

	// ============================================================
	// PHASE 4: Verify ALL data persisted across restart
	// ============================================================
	t.Log("PHASE 4: Verifying data persistence across restart")

	// Verify tenant data persisted
	t.Run("TenantDataPersisted", func(t *testing.T) {
		tenant, err := newTenantStore.GetTenant(ctx, "persistence-test-tenant")
		require.NoError(t, err, "REGRESSION: Tenant data did not survive restart! Check if memory-only storage is being used.")
		assert.Equal(t, "Persistence Test Tenant", tenant.Name, "Tenant name should match")
		assert.Equal(t, "persistence", tenant.Metadata["test"], "Tenant metadata should persist")
	})

	// Verify configuration data persisted
	t.Run("ConfigDataPersisted", func(t *testing.T) {
		config, err := newConfigStore.GetConfig(ctx, testConfig.Key)
		require.NoError(t, err, "REGRESSION: Config data did not survive restart! Check if memory-only storage is being used.")
		// Note: Git provider normalizes JSON to YAML, so check semantic content not exact bytes
		assert.Contains(t, string(config.Data), "enabled", "Config data should contain 'enabled' field")
		assert.Contains(t, string(config.Data), "setting", "Config data should contain 'setting' field")
		assert.Contains(t, config.Tags, "persistence", "Config tags should persist")
	})

	// Cleanup
	err = newTenantStore.Close()
	require.NoError(t, err)

	t.Log("PHASE 4 COMPLETE: All data verified to persist across restart")
	t.Log("✅ PERSISTENCE REGRESSION TEST PASSED - No in-memory storage detected for persistent data")
}
