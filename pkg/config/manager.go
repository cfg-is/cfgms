// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package config provides unified configuration management using the global storage provider system
package config

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// Manager handles all configuration operations using the ConfigStore interface
// This is the Epic 6 compliant configuration manager that replaces in-memory storage
type Manager struct {
	configStore interfaces.ConfigStore
}

// NewManager creates a new configuration manager with the provided ConfigStore
// This follows the Epic 6 requirement of using only storage provider interfaces
func NewManager(configStore interfaces.ConfigStore) *Manager {
	return &Manager{
		configStore: configStore,
	}
}

// NewManagerWithStorageManager creates a configuration manager from a storage manager
// This is the recommended way to create a configuration manager in production
func NewManagerWithStorageManager(storageManager *interfaces.StorageManager) *Manager {
	return &Manager{
		configStore: storageManager.GetConfigStore(),
	}
}

// StoreConfiguration stores a configuration in the persistent storage
func (m *Manager) StoreConfiguration(ctx context.Context, tenantID, stewardID string, config interface{}) error {
	// Marshal configuration to YAML for human-readable storage
	configData, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration to YAML: %w", err)
	}

	// Calculate checksum for data integrity
	checksum := fmt.Sprintf("%x", sha256.Sum256(configData))

	// Create config entry
	configEntry := &interfaces.ConfigEntry{
		Key: &interfaces.ConfigKey{
			TenantID:  tenantID,
			Namespace: "stewards",
			Name:      stewardID,
		},
		Data:      configData,
		Format:    interfaces.ConfigFormatYAML,
		Checksum:  checksum,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: "config-manager",
		UpdatedBy: "config-manager",
		Source:    "cfgms-controller",
		Tags:      []string{"steward-config"},
	}

	// Store configuration using ConfigStore interface
	return m.configStore.StoreConfig(ctx, configEntry)
}

// GetConfiguration retrieves a configuration from persistent storage
func (m *Manager) GetConfiguration(ctx context.Context, tenantID, stewardID string) (*stewardconfig.StewardConfig, error) {
	// Create config key
	configKey := &interfaces.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	}

	// Retrieve from storage
	configEntry, err := m.configStore.GetConfig(ctx, configKey)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve configuration: %w", err)
	}

	// Verify checksum for data integrity
	expectedChecksum := fmt.Sprintf("%x", sha256.Sum256(configEntry.Data))
	if expectedChecksum != configEntry.Checksum {
		return nil, fmt.Errorf("configuration data integrity check failed")
	}

	// Parse YAML configuration
	var config stewardconfig.StewardConfig
	if err := yaml.Unmarshal(configEntry.Data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration YAML: %w", err)
	}

	return &config, nil
}

// GetConfigurationWithInheritance retrieves configuration with tenant hierarchy inheritance
// This implements the multi-tenant configuration inheritance model
func (m *Manager) GetConfigurationWithInheritance(ctx context.Context, tenantID, stewardID string) (*stewardconfig.StewardConfig, error) {
	// Use storage provider's built-in inheritance resolution
	configKey := &interfaces.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	}

	configEntry, err := m.configStore.ResolveConfigWithInheritance(ctx, configKey)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve configuration with inheritance: %w", err)
	}

	// Parse the resolved configuration
	var config stewardconfig.StewardConfig
	if err := yaml.Unmarshal(configEntry.Data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse inherited configuration: %w", err)
	}

	return &config, nil
}

// DeleteConfiguration removes a steward configuration from persistent storage
func (m *Manager) DeleteConfiguration(ctx context.Context, tenantID, stewardID string) error {
	configKey := &interfaces.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	}

	return m.configStore.DeleteConfig(ctx, configKey)
}

// ListConfigurations lists all configurations for a tenant
func (m *Manager) ListConfigurations(ctx context.Context, tenantID string) ([]*ConfigurationSummary, error) {
	filter := &interfaces.ConfigFilter{
		TenantID:  tenantID,
		Namespace: "stewards",
		SortBy:    "updated_at",
		Order:     "desc",
	}

	configEntries, err := m.configStore.ListConfigs(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list configurations: %w", err)
	}

	var summaries []*ConfigurationSummary
	for _, entry := range configEntries {
		summary := &ConfigurationSummary{
			TenantID:  entry.Key.TenantID,
			StewardID: entry.Key.Name,
			Version:   entry.Version,
			UpdatedAt: entry.UpdatedAt,
			UpdatedBy: entry.UpdatedBy,
			Source:    entry.Source,
			Checksum:  entry.Checksum,
			Tags:      entry.Tags,
		}
		summaries = append(summaries, summary)
	}

	return summaries, nil
}

// GetConfigurationHistory retrieves version history for a configuration
func (m *Manager) GetConfigurationHistory(ctx context.Context, tenantID, stewardID string, limit int) ([]*ConfigurationVersion, error) {
	configKey := &interfaces.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	}

	historyEntries, err := m.configStore.GetConfigHistory(ctx, configKey, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve configuration history: %w", err)
	}

	var versions []*ConfigurationVersion
	for _, entry := range historyEntries {
		version := &ConfigurationVersion{
			Version:   entry.Version,
			CreatedAt: entry.CreatedAt,
			CreatedBy: entry.CreatedBy,
			Checksum:  entry.Checksum,
			Size:      len(entry.Data),
		}
		versions = append(versions, version)
	}

	return versions, nil
}

// GetConfigurationVersion retrieves a specific version of a configuration
func (m *Manager) GetConfigurationVersion(ctx context.Context, tenantID, stewardID string, version int64) (*stewardconfig.StewardConfig, error) {
	configKey := &interfaces.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	}

	configEntry, err := m.configStore.GetConfigVersion(ctx, configKey, version)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve configuration version %d: %w", version, err)
	}

	// Parse YAML configuration
	var config stewardconfig.StewardConfig
	if err := yaml.Unmarshal(configEntry.Data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration version %d: %w", version, err)
	}

	return &config, nil
}

// ValidateConfiguration validates a configuration before storage
func (m *Manager) ValidateConfiguration(ctx context.Context, config *stewardconfig.StewardConfig) error {
	// Use existing steward config validation
	if err := stewardconfig.ValidateConfiguration(*config); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Create a temporary config entry for storage-level validation
	configData, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration for validation: %w", err)
	}

	tempEntry := &interfaces.ConfigEntry{
		Key: &interfaces.ConfigKey{
			TenantID:  "validation",
			Namespace: "stewards",
			Name:      "temp",
		},
		Data:   configData,
		Format: interfaces.ConfigFormatYAML,
	}

	// Use storage provider's validation
	return m.configStore.ValidateConfig(ctx, tempEntry)
}

// BatchStoreConfigurations stores multiple configurations atomically
func (m *Manager) BatchStoreConfigurations(ctx context.Context, configs []*BatchConfigurationEntry) error {
	var configEntries []*interfaces.ConfigEntry

	for _, batchEntry := range configs {
		configData, err := yaml.Marshal(batchEntry.Config)
		if err != nil {
			return fmt.Errorf("failed to marshal configuration for steward %s: %w", batchEntry.StewardID, err)
		}

		checksum := fmt.Sprintf("%x", sha256.Sum256(configData))

		configEntry := &interfaces.ConfigEntry{
			Key: &interfaces.ConfigKey{
				TenantID:  batchEntry.TenantID,
				Namespace: "stewards",
				Name:      batchEntry.StewardID,
			},
			Data:      configData,
			Format:    interfaces.ConfigFormatYAML,
			Checksum:  checksum,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			CreatedBy: "config-manager",
			UpdatedBy: "config-manager",
			Source:    "cfgms-controller",
			Tags:      []string{"steward-config", "batch-operation"},
		}

		configEntries = append(configEntries, configEntry)
	}

	// Use storage provider's batch operation
	return m.configStore.StoreConfigBatch(ctx, configEntries)
}

// GetConfigurationStats returns statistics about stored configurations
func (m *Manager) GetConfigurationStats(ctx context.Context) (*interfaces.ConfigStats, error) {
	return m.configStore.GetConfigStats(ctx)
}

// ConfigurationSummary provides a summary of a stored configuration
type ConfigurationSummary struct {
	TenantID  string    `json:"tenant_id"`
	StewardID string    `json:"steward_id"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
	Source    string    `json:"source"`
	Checksum  string    `json:"checksum"`
	Tags      []string  `json:"tags"`
}

// ConfigurationVersion represents a version in configuration history
type ConfigurationVersion struct {
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	Checksum  string    `json:"checksum"`
	Size      int       `json:"size"`
}

// BatchConfigurationEntry represents a configuration for batch operations
type BatchConfigurationEntry struct {
	TenantID  string                       `json:"tenant_id"`
	StewardID string                       `json:"steward_id"`
	Config    *stewardconfig.StewardConfig `json:"config"`
}
