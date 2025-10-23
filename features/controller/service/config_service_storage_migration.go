// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package service provides configuration service migration from in-memory to ConfigStore
package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// ConfigurationStorageMigration provides Epic 6 compliant storage for ConfigurationService
// This replaces the in-memory map[string]*StoredConfiguration with ConfigStore persistence
type ConfigurationStorageMigration struct {
	configStore interfaces.ConfigStore
	logger      logging.Logger
}

// NewConfigurationStorageMigration creates a storage migration adapter
func NewConfigurationStorageMigration(configStore interfaces.ConfigStore, logger logging.Logger) *ConfigurationStorageMigration {
	return &ConfigurationStorageMigration{
		configStore: configStore,
		logger:      logger,
	}
}

// StoreConfiguration stores a steward configuration using ConfigStore interface
func (csm *ConfigurationStorageMigration) StoreConfiguration(ctx context.Context, tenantID, stewardID string, config *stewardconfig.StewardConfig) error {
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
		CreatedBy: "config-service",
		UpdatedBy: "config-service",
		Source:    "cfgms-controller",
		Tags:      []string{"steward-config", "migration"},
	}

	// Store configuration using ConfigStore interface
	if err := csm.configStore.StoreConfig(ctx, configEntry); err != nil {
		return fmt.Errorf("failed to store configuration in ConfigStore: %w", err)
	}

	csm.logger.Info("Configuration stored successfully",
		"tenant_id", tenantID,
		"steward_id", stewardID,
		"checksum", checksum)

	return nil
}

// GetConfiguration retrieves a steward configuration from ConfigStore
func (csm *ConfigurationStorageMigration) GetConfiguration(ctx context.Context, tenantID, stewardID string) (*stewardconfig.StewardConfig, error) {
	// Create config key
	configKey := &interfaces.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	}

	// Retrieve from storage
	configEntry, err := csm.configStore.GetConfig(ctx, configKey)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve configuration: %w", err)
	}

	// Verify checksum for data integrity
	expectedChecksum := fmt.Sprintf("%x", sha256.Sum256(configEntry.Data))
	if expectedChecksum != configEntry.Checksum {
		csm.logger.Warn("Configuration checksum mismatch",
			"steward_id", stewardID,
			"expected", expectedChecksum,
			"actual", configEntry.Checksum)
		// Don't fail for checksum mismatch, just warn
	}

	// Parse YAML configuration
	var config stewardconfig.StewardConfig
	if err := yaml.Unmarshal(configEntry.Data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration YAML: %w", err)
	}

	return &config, nil
}

// GetConfigurationWithInheritance retrieves configuration with tenant hierarchy inheritance
func (csm *ConfigurationStorageMigration) GetConfigurationWithInheritance(ctx context.Context, tenantID, stewardID string) (*stewardconfig.StewardConfig, error) {
	// Use storage provider's built-in inheritance resolution
	configKey := &interfaces.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	}

	configEntry, err := csm.configStore.ResolveConfigWithInheritance(ctx, configKey)
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

// GetStoredConfiguration retrieves configuration with metadata (compatible with existing interface)
func (csm *ConfigurationStorageMigration) GetStoredConfiguration(ctx context.Context, tenantID, stewardID string) (*StoredConfiguration, error) {
	// Create config key
	configKey := &interfaces.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	}

	// Retrieve from storage
	configEntry, err := csm.configStore.GetConfig(ctx, configKey)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve configuration: %w", err)
	}

	// Parse YAML configuration
	var config stewardconfig.StewardConfig
	if err := yaml.Unmarshal(configEntry.Data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration YAML: %w", err)
	}

	// Create StoredConfiguration compatible structure
	storedConfig := &StoredConfiguration{
		StewardID:   stewardID,
		TenantID:    tenantID,
		Version:     fmt.Sprintf("v%d", configEntry.Version),
		Config:      &config,
		LastUpdated: configEntry.UpdatedAt,
		CreatedAt:   configEntry.CreatedAt,
	}

	return storedConfig, nil
}

// ListConfigurations lists all configurations for a tenant
func (csm *ConfigurationStorageMigration) ListConfigurations(ctx context.Context, tenantID string) ([]*StoredConfiguration, error) {
	filter := &interfaces.ConfigFilter{
		TenantID:  tenantID,
		Namespace: "stewards",
		SortBy:    "updated_at",
		Order:     "desc",
	}

	configEntries, err := csm.configStore.ListConfigs(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list configurations: %w", err)
	}

	var storedConfigs []*StoredConfiguration
	for _, entry := range configEntries {
		// Parse YAML configuration
		var config stewardconfig.StewardConfig
		if err := yaml.Unmarshal(entry.Data, &config); err != nil {
			csm.logger.Warn("Failed to parse configuration during listing",
				"steward_id", entry.Key.Name,
				"error", err)
			continue // Skip malformed configurations
		}

		storedConfig := &StoredConfiguration{
			StewardID:   entry.Key.Name,
			TenantID:    entry.Key.TenantID,
			Version:     fmt.Sprintf("v%d", entry.Version),
			Config:      &config,
			LastUpdated: entry.UpdatedAt,
			CreatedAt:   entry.CreatedAt,
		}
		storedConfigs = append(storedConfigs, storedConfig)
	}

	return storedConfigs, nil
}

// DeleteConfiguration removes a configuration from persistent storage
func (csm *ConfigurationStorageMigration) DeleteConfiguration(ctx context.Context, tenantID, stewardID string) error {
	configKey := &interfaces.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	}

	if err := csm.configStore.DeleteConfig(ctx, configKey); err != nil {
		return fmt.Errorf("failed to delete configuration: %w", err)
	}

	csm.logger.Info("Configuration deleted successfully",
		"tenant_id", tenantID,
		"steward_id", stewardID)

	return nil
}

// GetConfigurationHistory retrieves version history for a configuration
func (csm *ConfigurationStorageMigration) GetConfigurationHistory(ctx context.Context, tenantID, stewardID string, limit int) ([]*ConfigurationVersion, error) {
	configKey := &interfaces.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	}

	historyEntries, err := csm.configStore.GetConfigHistory(ctx, configKey, limit)
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
func (csm *ConfigurationStorageMigration) GetConfigurationVersion(ctx context.Context, tenantID, stewardID string, version int64) (*stewardconfig.StewardConfig, error) {
	configKey := &interfaces.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	}

	configEntry, err := csm.configStore.GetConfigVersion(ctx, configKey, version)
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
func (csm *ConfigurationStorageMigration) ValidateConfiguration(ctx context.Context, config *stewardconfig.StewardConfig) error {
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
	return csm.configStore.ValidateConfig(ctx, tempEntry)
}

// GetStats returns storage statistics
func (csm *ConfigurationStorageMigration) GetStats(ctx context.Context) (*interfaces.ConfigStats, error) {
	return csm.configStore.GetConfigStats(ctx)
}

// ConfigurationVersion represents a version in configuration history
type ConfigurationVersion struct {
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	Checksum  string    `json:"checksum"`
	Size      int       `json:"size"`
}

// MigrateFromInMemory migrates existing in-memory configurations to ConfigStore
func (csm *ConfigurationStorageMigration) MigrateFromInMemory(ctx context.Context, inMemoryConfigs map[string]*StoredConfiguration) error {
	csm.logger.Info("Starting migration from in-memory to ConfigStore", "count", len(inMemoryConfigs))

	successCount := 0
	errorCount := 0

	for key, storedConfig := range inMemoryConfigs {
		if err := csm.StoreConfiguration(ctx, storedConfig.TenantID, storedConfig.StewardID, storedConfig.Config); err != nil {
			csm.logger.Error("Failed to migrate configuration",
				"key", key,
				"tenant_id", storedConfig.TenantID,
				"steward_id", storedConfig.StewardID,
				"error", err)
			errorCount++
		} else {
			successCount++
		}
	}

	csm.logger.Info("Migration completed",
		"total", len(inMemoryConfigs),
		"success", successCount,
		"errors", errorCount)

	if errorCount > 0 {
		return fmt.Errorf("migration completed with %d errors out of %d configurations", errorCount, len(inMemoryConfigs))
	}

	return nil
}
