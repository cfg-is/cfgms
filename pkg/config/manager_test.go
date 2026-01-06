// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package config

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// MockConfigStore implements interfaces.ConfigStore for testing
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
		return nil, &interfaces.ConfigValidationError{
			Field:   "key",
			Message: "configuration not found",
			Code:    "CONFIG_NOT_FOUND",
		}
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
		return nil, &interfaces.ConfigValidationError{
			Field:   "version",
			Message: "configuration history not found",
			Code:    "HISTORY_NOT_FOUND",
		}
	}

	// Find version in history
	for _, entry := range history {
		if entry.Version == version {
			configCopy := *entry
			return &configCopy, nil
		}
	}

	return nil, &interfaces.ConfigValidationError{
		Field:   "version",
		Message: "version not found",
		Code:    "VERSION_NOT_FOUND",
	}
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
		return &interfaces.ConfigValidationError{
			Field:   "key",
			Message: "key is required",
			Code:    "KEY_REQUIRED",
		}
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

// Test Cases

func TestManagerStoreAndGetConfiguration(t *testing.T) {
	mockStore := NewMockConfigStore()
	manager := NewManager(mockStore)
	ctx := context.Background()

	// Create test configuration
	testConfig := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "test-steward",
			Mode: stewardconfig.ModeStandalone,
		},
		Resources: []stewardconfig.ResourceConfig{
			{
				Name:   "test-resource",
				Module: "directory",
				Config: map[string]interface{}{
					"path": "/opt/test",
				},
			},
		},
	}

	// Store configuration
	err := manager.StoreConfiguration(ctx, "test-tenant", "test-steward", testConfig)
	require.NoError(t, err)

	// Retrieve configuration
	retrievedConfig, err := manager.GetConfiguration(ctx, "test-tenant", "test-steward")
	require.NoError(t, err)

	// Verify configuration
	assert.Equal(t, testConfig.Steward.ID, retrievedConfig.Steward.ID)
	assert.Equal(t, testConfig.Steward.Mode, retrievedConfig.Steward.Mode)
	assert.Len(t, retrievedConfig.Resources, 1)
	assert.Equal(t, "test-resource", retrievedConfig.Resources[0].Name)
	assert.Equal(t, "directory", retrievedConfig.Resources[0].Module)
}

func TestManagerGetConfigurationNotFound(t *testing.T) {
	mockStore := NewMockConfigStore()
	manager := NewManager(mockStore)
	ctx := context.Background()

	// Try to get non-existent configuration
	_, err := manager.GetConfiguration(ctx, "test-tenant", "non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration not found")
}

func TestManagerConfigurationHistory(t *testing.T) {
	mockStore := NewMockConfigStore()
	manager := NewManager(mockStore)
	ctx := context.Background()

	// Create and store multiple versions
	for i := 1; i <= 3; i++ {
		testConfig := &stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{
				ID:   "test-steward",
				Mode: stewardconfig.ModeStandalone,
			},
			Resources: []stewardconfig.ResourceConfig{
				{
					Name:   "test-resource",
					Module: "directory",
					Config: map[string]interface{}{
						"path": fmt.Sprintf("/opt/test%d", i),
					},
				},
			},
		}

		err := manager.StoreConfiguration(ctx, "test-tenant", "test-steward", testConfig)
		require.NoError(t, err)
	}

	// Get configuration history
	history, err := manager.GetConfigurationHistory(ctx, "test-tenant", "test-steward", 5)
	require.NoError(t, err)
	assert.Len(t, history, 2) // First version goes to history, current version not in history

	// Verify versions are in descending order
	assert.True(t, history[0].Version > history[1].Version)
}

func TestManagerGetConfigurationVersion(t *testing.T) {
	mockStore := NewMockConfigStore()
	manager := NewManager(mockStore)
	ctx := context.Background()

	// Store initial version
	testConfig1 := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "test-steward",
			Mode: stewardconfig.ModeStandalone,
		},
		Resources: []stewardconfig.ResourceConfig{
			{
				Name:   "test-resource",
				Module: "directory",
				Config: map[string]interface{}{
					"path": "/opt/test1",
				},
			},
		},
	}

	err := manager.StoreConfiguration(ctx, "test-tenant", "test-steward", testConfig1)
	require.NoError(t, err)

	// Store second version
	testConfig2 := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "test-steward",
			Mode: stewardconfig.ModeStandalone,
		},
		Resources: []stewardconfig.ResourceConfig{
			{
				Name:   "test-resource",
				Module: "directory",
				Config: map[string]interface{}{
					"path": "/opt/test2",
				},
			},
		},
	}

	err = manager.StoreConfiguration(ctx, "test-tenant", "test-steward", testConfig2)
	require.NoError(t, err)

	// Get version 1
	versionConfig, err := manager.GetConfigurationVersion(ctx, "test-tenant", "test-steward", 1)
	require.NoError(t, err)

	// Verify it's the first version
	pathValue := versionConfig.Resources[0].Config["path"]
	assert.Equal(t, "/opt/test1", pathValue)
}

func TestManagerListConfigurations(t *testing.T) {
	mockStore := NewMockConfigStore()
	manager := NewManager(mockStore)
	ctx := context.Background()

	// Store configurations for different stewards
	for i := 1; i <= 3; i++ {
		testConfig := &stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{
				ID:   fmt.Sprintf("steward-%d", i),
				Mode: stewardconfig.ModeStandalone,
			},
		}

		err := manager.StoreConfiguration(ctx, "test-tenant", fmt.Sprintf("steward-%d", i), testConfig)
		require.NoError(t, err)
	}

	// List configurations
	summaries, err := manager.ListConfigurations(ctx, "test-tenant")
	require.NoError(t, err)
	assert.Len(t, summaries, 3)

	// Verify summary data
	for _, summary := range summaries {
		assert.Equal(t, "test-tenant", summary.TenantID)
		assert.NotEmpty(t, summary.StewardID)
		assert.NotZero(t, summary.Version)
		assert.NotZero(t, summary.UpdatedAt)
	}
}

func TestManagerBatchStoreConfigurations(t *testing.T) {
	mockStore := NewMockConfigStore()
	manager := NewManager(mockStore)
	ctx := context.Background()

	// Create batch configurations
	var batchConfigs []*BatchConfigurationEntry

	for i := 1; i <= 3; i++ {
		testConfig := &stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{
				ID:   fmt.Sprintf("steward-%d", i),
				Mode: stewardconfig.ModeStandalone,
			},
		}

		batchConfigs = append(batchConfigs, &BatchConfigurationEntry{
			TenantID:  "test-tenant",
			StewardID: fmt.Sprintf("steward-%d", i),
			Config:    testConfig,
		})
	}

	// Store batch
	err := manager.BatchStoreConfigurations(ctx, batchConfigs)
	require.NoError(t, err)

	// Verify all configurations were stored
	for i := 1; i <= 3; i++ {
		config, err := manager.GetConfiguration(ctx, "test-tenant", fmt.Sprintf("steward-%d", i))
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("steward-%d", i), config.Steward.ID)
	}
}

func TestManagerValidateConfiguration(t *testing.T) {
	mockStore := NewMockConfigStore()
	manager := NewManager(mockStore)
	ctx := context.Background()

	// Test valid configuration
	validConfig := &stewardconfig.StewardConfig{
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
					"path": "/opt/test",
				},
			},
		},
	}

	err := manager.ValidateConfiguration(ctx, validConfig)
	assert.NoError(t, err)

	// Test invalid configuration (empty steward ID)
	invalidConfig := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "", // Invalid: empty ID
			Mode: stewardconfig.ModeStandalone,
		},
	}

	err = manager.ValidateConfiguration(ctx, invalidConfig)
	assert.Error(t, err)
}

func TestManagerDeleteConfiguration(t *testing.T) {
	mockStore := NewMockConfigStore()
	manager := NewManager(mockStore)
	ctx := context.Background()

	// Store configuration
	testConfig := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "test-steward",
			Mode: stewardconfig.ModeStandalone,
		},
	}

	err := manager.StoreConfiguration(ctx, "test-tenant", "test-steward", testConfig)
	require.NoError(t, err)

	// Verify it exists
	_, err = manager.GetConfiguration(ctx, "test-tenant", "test-steward")
	assert.NoError(t, err)

	// Delete configuration
	err = manager.DeleteConfiguration(ctx, "test-tenant", "test-steward")
	assert.NoError(t, err)

	// Verify it's deleted
	_, err = manager.GetConfiguration(ctx, "test-tenant", "test-steward")
	assert.Error(t, err)
}

func TestManagerGetConfigurationStats(t *testing.T) {
	mockStore := NewMockConfigStore()
	manager := NewManager(mockStore)
	ctx := context.Background()

	// Store a few configurations
	for i := 1; i <= 2; i++ {
		testConfig := &stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{
				ID:   fmt.Sprintf("steward-%d", i),
				Mode: stewardconfig.ModeStandalone,
			},
		}

		err := manager.StoreConfiguration(ctx, "test-tenant", fmt.Sprintf("steward-%d", i), testConfig)
		require.NoError(t, err)
	}

	// Get stats
	stats, err := manager.GetConfigurationStats(ctx)
	require.NoError(t, err)

	assert.Equal(t, int64(2), stats.TotalConfigs)
	assert.Greater(t, stats.TotalSize, int64(0))
	assert.Greater(t, stats.AverageSize, int64(0))
	assert.NotZero(t, stats.LastUpdated)
}
