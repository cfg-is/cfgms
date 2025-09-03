// Package interfaces provides hybrid storage management for mixed backend deployments
package interfaces

import (
	"fmt"
)

// HybridStorageConfig defines configuration for hybrid storage deployments
type HybridStorageConfig struct {
	// Operational data storage (audit, tenant data, sessions, health monitoring)
	Operational StorageBackendConfig `json:"operational" yaml:"operational"`
	
	// Configuration data storage (templates, certificates, configurations)
	Configuration StorageBackendConfig `json:"configuration" yaml:"configuration"`
}

// StorageBackendConfig defines a storage backend configuration
type StorageBackendConfig struct {
	Provider string                 `json:"provider" yaml:"provider"`
	Config   map[string]interface{} `json:"config" yaml:"config"`
}

// HybridStorageManager manages multiple storage backends for different data types
type HybridStorageManager struct {
	operationalProvider   StorageProvider
	configurationProvider StorageProvider
	
	clientTenantStore ClientTenantStore
	auditStore       AuditStore
	configStore      ConfigStore
	
	config HybridStorageConfig
}

// NewHybridStorageManager creates a new hybrid storage manager
func NewHybridStorageManager(config HybridStorageConfig) (*HybridStorageManager, error) {
	manager := &HybridStorageManager{
		config: config,
	}
	
	// Initialize operational provider (database recommended for performance)
	opProvider, err := GetStorageProvider(config.Operational.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get operational storage provider '%s': %w", 
			config.Operational.Provider, err)
	}
	manager.operationalProvider = opProvider
	
	// Initialize configuration provider (git recommended for GitOps)
	cfgProvider, err := GetStorageProvider(config.Configuration.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get configuration storage provider '%s': %w", 
			config.Configuration.Provider, err)
	}
	manager.configurationProvider = cfgProvider
	
	// Create operational stores (high-performance queries)
	clientTenantStore, err := opProvider.CreateClientTenantStore(config.Operational.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create client tenant store: %w", err)
	}
	manager.clientTenantStore = clientTenantStore
	
	auditStore, err := opProvider.CreateAuditStore(config.Operational.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit store: %w", err)
	}
	manager.auditStore = auditStore
	
	// Create configuration store (GitOps workflow)
	configStore, err := cfgProvider.CreateConfigStore(config.Configuration.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create config store: %w", err)
	}
	manager.configStore = configStore
	
	return manager, nil
}

// GetClientTenantStore returns the client tenant storage interface (operational backend)
func (h *HybridStorageManager) GetClientTenantStore() ClientTenantStore {
	return h.clientTenantStore
}

// GetAuditStore returns the audit storage interface (operational backend)
func (h *HybridStorageManager) GetAuditStore() AuditStore {
	return h.auditStore
}

// GetConfigStore returns the configuration storage interface (configuration backend)
func (h *HybridStorageManager) GetConfigStore() ConfigStore {
	return h.configStore
}

// GetOperationalProvider returns the operational storage provider
func (h *HybridStorageManager) GetOperationalProvider() StorageProvider {
	return h.operationalProvider
}

// GetConfigurationProvider returns the configuration storage provider
func (h *HybridStorageManager) GetConfigurationProvider() StorageProvider {
	return h.configurationProvider
}

// GetOperationalCapabilities returns the operational provider's capabilities
func (h *HybridStorageManager) GetOperationalCapabilities() ProviderCapabilities {
	return h.operationalProvider.GetCapabilities()
}

// GetConfigurationCapabilities returns the configuration provider's capabilities
func (h *HybridStorageManager) GetConfigurationCapabilities() ProviderCapabilities {
	return h.configurationProvider.GetCapabilities()
}

// GetBackendInfo returns information about the hybrid storage backends
func (h *HybridStorageManager) GetBackendInfo() HybridBackendInfo {
	return HybridBackendInfo{
		Operational: BackendInfo{
			Provider:     h.operationalProvider.Name(),
			Description:  h.operationalProvider.Description(),
			Version:      h.operationalProvider.GetVersion(),
			Capabilities: h.operationalProvider.GetCapabilities(),
		},
		Configuration: BackendInfo{
			Provider:     h.configurationProvider.Name(),
			Description:  h.configurationProvider.Description(),
			Version:      h.configurationProvider.GetVersion(),
			Capabilities: h.configurationProvider.GetCapabilities(),
		},
	}
}

// HybridBackendInfo provides information about hybrid storage backends
type HybridBackendInfo struct {
	Operational   BackendInfo `json:"operational"`
	Configuration BackendInfo `json:"configuration"`
}

// BackendInfo provides information about a storage backend
type BackendInfo struct {
	Provider     string               `json:"provider"`
	Description  string               `json:"description"`
	Version      string               `json:"version"`
	Capabilities ProviderCapabilities `json:"capabilities"`
}

// ValidateHybridConfig validates hybrid storage configuration
func ValidateHybridConfig(config HybridStorageConfig) error {
	// Validate operational provider
	if config.Operational.Provider == "" {
		return fmt.Errorf("operational storage provider is required")
	}
	
	opProvider, err := GetStorageProvider(config.Operational.Provider)
	if err != nil {
		return fmt.Errorf("operational storage provider '%s' not available: %w", 
			config.Operational.Provider, err)
	}
	
	// Validate configuration provider
	if config.Configuration.Provider == "" {
		return fmt.Errorf("configuration storage provider is required")
	}
	
	cfgProvider, err := GetStorageProvider(config.Configuration.Provider)
	if err != nil {
		return fmt.Errorf("configuration storage provider '%s' not available: %w", 
			config.Configuration.Provider, err)
	}
	
	// Validate operational provider capabilities for high-performance queries
	opCaps := opProvider.GetCapabilities()
	if !opCaps.SupportsTransactions {
		return fmt.Errorf("operational storage provider should support transactions for data consistency")
	}
	
	// Validate configuration provider capabilities for GitOps workflow
	cfgCaps := cfgProvider.GetCapabilities()
	if !cfgCaps.SupportsVersioning {
		return fmt.Errorf("configuration storage provider should support versioning for change tracking")
	}
	
	return nil
}

// CreateHybridStorageFromConfig creates hybrid storage manager from configuration
func CreateHybridStorageFromConfig(config HybridStorageConfig) (*HybridStorageManager, error) {
	// Validate configuration first
	if err := ValidateHybridConfig(config); err != nil {
		return nil, fmt.Errorf("invalid hybrid storage configuration: %w", err)
	}
	
	// Create hybrid storage manager
	return NewHybridStorageManager(config)
}

// GetRecommendedHybridConfig returns recommended hybrid storage configuration
func GetRecommendedHybridConfig() HybridStorageConfig {
	return HybridStorageConfig{
		Operational: StorageBackendConfig{
			Provider: "database",
			Config: map[string]interface{}{
				"host":                              "localhost",
				"port":                              5432,
				"database":                          "cfgms_ops",
				"username":                          "cfgms",
				"password":                          "${POSTGRES_PASSWORD}",
				"sslmode":                          "require",
				"max_open_connections":             50, // Higher for operational queries
				"max_idle_connections":             10,
				"connection_max_lifetime_minutes":  30,
			},
		},
		Configuration: StorageBackendConfig{
			Provider: "git",
			Config: map[string]interface{}{
				"repository_path": "/data/cfgms-configs",
				"remote_url":      "git@github.com:msp-corp/cfgms-configs.git",
				"branch":          "main",
				"auto_sync":       true,
				"sops_enabled":    true,
			},
		},
	}
}

// Migration helpers for existing deployments

// MigrationStrategy defines how to migrate from single to hybrid storage
type MigrationStrategy struct {
	SourceProvider string                 `json:"source_provider"`
	SourceConfig   map[string]interface{} `json:"source_config"`
	TargetConfig   HybridStorageConfig    `json:"target_config"`
	MigrateData    bool                   `json:"migrate_data"`
	BackupFirst    bool                   `json:"backup_first"`
}

// PlanHybridMigration helps plan migration from single-backend to hybrid storage
func PlanHybridMigration(currentProvider string, currentConfig map[string]interface{}) MigrationStrategy {
	strategy := MigrationStrategy{
		SourceProvider: currentProvider,
		SourceConfig:   currentConfig,
		MigrateData:    true,
		BackupFirst:    true,
	}
	
	// Recommend hybrid configuration based on current setup
	if currentProvider == "database" {
		// Already using database - keep for operational, add git for configs
		strategy.TargetConfig = HybridStorageConfig{
			Operational: StorageBackendConfig{
				Provider: "database",
				Config:   currentConfig, // Keep existing DB config
			},
			Configuration: StorageBackendConfig{
				Provider: "git",
				Config: map[string]interface{}{
					"repository_path": "/data/cfgms-configs",
					"remote_url":      "", // Must be configured by user
				},
			},
		}
	} else if currentProvider == "git" {
		// Already using git - keep for configs, add database for operational
		strategy.TargetConfig = HybridStorageConfig{
			Operational: StorageBackendConfig{
				Provider: "database",
				Config: map[string]interface{}{
					"host":     "localhost",
					"database": "cfgms_ops",
					"username": "cfgms",
					"password": "${POSTGRES_PASSWORD}",
				},
			},
			Configuration: StorageBackendConfig{
				Provider: "git",
				Config:   currentConfig, // Keep existing git config
			},
		}
	}
	
	return strategy
}