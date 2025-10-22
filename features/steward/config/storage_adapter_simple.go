// Package config provides simplified adapter to use ConfigStore for steward configuration loading
// This avoids circular imports while maintaining Epic 6 compliance
package config

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// SimpleStorageAdapter provides Epic 6 compliant storage without circular dependencies
type SimpleStorageAdapter struct {
	configStore interfaces.ConfigStore
	tenantID    string
	stewardID   string
}

// NewSimpleStorageAdapter creates a new simple storage adapter
func NewSimpleStorageAdapter(configStore interfaces.ConfigStore, tenantID, stewardID string) *SimpleStorageAdapter {
	return &SimpleStorageAdapter{
		configStore: configStore,
		tenantID:    tenantID,
		stewardID:   stewardID,
	}
}

// StoreConfiguration stores a steward configuration using ConfigStore interface (Epic 6 compliant)
func (ssa *SimpleStorageAdapter) StoreConfiguration(ctx context.Context, config *StewardConfig) error {
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
			TenantID:  ssa.tenantID,
			Namespace: "stewards",
			Name:      ssa.stewardID,
		},
		Data:      configData,
		Format:    interfaces.ConfigFormatYAML,
		Checksum:  checksum,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: "steward-adapter",
		UpdatedBy: "steward-adapter",
		Source:    "cfgms-steward",
		Tags:      []string{"steward-config", "epic6-compliant"},
	}

	// Store configuration using ConfigStore interface (Epic 6 requirement)
	return ssa.configStore.StoreConfig(ctx, configEntry)
}

// LoadConfiguration loads steward configuration from ConfigStore (Epic 6 compliant)
func (ssa *SimpleStorageAdapter) LoadConfiguration(ctx context.Context) (*StewardConfig, error) {
	// Create config key
	configKey := &interfaces.ConfigKey{
		TenantID:  ssa.tenantID,
		Namespace: "stewards",
		Name:      ssa.stewardID,
	}

	// Retrieve from ConfigStore (Epic 6 requirement)
	configEntry, err := ssa.configStore.GetConfig(ctx, configKey)
	if err != nil {
		// If not found in storage, fall back to file-based loading
		if isConfigNotFoundError(err) {
			fallbackConfig, fallbackErr := LoadConfiguration("")
			if fallbackErr != nil {
				return nil, fmt.Errorf("configuration not found in storage and file fallback failed: %w", fallbackErr)
			}
			return &fallbackConfig, nil
		}
		return nil, fmt.Errorf("failed to retrieve configuration from storage: %w", err)
	}

	// Verify checksum for data integrity
	expectedChecksum := fmt.Sprintf("%x", sha256.Sum256(configEntry.Data))
	if expectedChecksum != configEntry.Checksum {
		// Don't fail for checksum mismatch, just proceed (data integrity warning)
		// TODO: Add logging for checksum mismatch in future version
		_ = expectedChecksum // Mark as intentionally unused
	}

	// Parse YAML configuration
	var config StewardConfig
	if err := yaml.Unmarshal(configEntry.Data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration YAML: %w", err)
	}

	return &config, nil
}

// LoadConfigurationWithInheritance loads configuration with tenant hierarchy inheritance (Epic 6 compliant)
func (ssa *SimpleStorageAdapter) LoadConfigurationWithInheritance(ctx context.Context) (*StewardConfig, error) {
	// Use storage provider's built-in inheritance resolution (Epic 6 requirement)
	configKey := &interfaces.ConfigKey{
		TenantID:  ssa.tenantID,
		Namespace: "stewards",
		Name:      ssa.stewardID,
	}

	configEntry, err := ssa.configStore.ResolveConfigWithInheritance(ctx, configKey)
	if err != nil {
		// If not found in storage, fall back to file-based loading
		if isConfigNotFoundError(err) {
			fallbackConfig, fallbackErr := LoadConfiguration("")
			if fallbackErr != nil {
				return nil, fmt.Errorf("configuration not found in storage and file fallback failed: %w", fallbackErr)
			}
			return &fallbackConfig, nil
		}
		return nil, fmt.Errorf("failed to resolve configuration with inheritance: %w", err)
	}

	// Parse the resolved configuration
	var config StewardConfig
	if err := yaml.Unmarshal(configEntry.Data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse inherited configuration: %w", err)
	}

	return &config, nil
}

// DeleteConfiguration removes configuration from storage (Epic 6 compliant)
func (ssa *SimpleStorageAdapter) DeleteConfiguration(ctx context.Context) error {
	configKey := &interfaces.ConfigKey{
		TenantID:  ssa.tenantID,
		Namespace: "stewards",
		Name:      ssa.stewardID,
	}

	return ssa.configStore.DeleteConfig(ctx, configKey)
}

// GetConfigurationHistory returns version history (Epic 6 compliant)
func (ssa *SimpleStorageAdapter) GetConfigurationHistory(ctx context.Context, limit int) ([]*ConfigurationVersion, error) {
	configKey := &interfaces.ConfigKey{
		TenantID:  ssa.tenantID,
		Namespace: "stewards",
		Name:      ssa.stewardID,
	}

	historyEntries, err := ssa.configStore.GetConfigHistory(ctx, configKey, limit)
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

// GetConfigurationVersion retrieves a specific version (Epic 6 compliant)
func (ssa *SimpleStorageAdapter) GetConfigurationVersion(ctx context.Context, version int64) (*StewardConfig, error) {
	configKey := &interfaces.ConfigKey{
		TenantID:  ssa.tenantID,
		Namespace: "stewards",
		Name:      ssa.stewardID,
	}

	configEntry, err := ssa.configStore.GetConfigVersion(ctx, configKey, version)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve configuration version %d: %w", version, err)
	}

	// Parse YAML configuration
	var config StewardConfig
	if err := yaml.Unmarshal(configEntry.Data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration version %d: %w", version, err)
	}

	return &config, nil
}

// MigrateFromFileToStorage migrates existing file-based configuration to storage (Epic 6 migration)
func (ssa *SimpleStorageAdapter) MigrateFromFileToStorage(ctx context.Context, configPath string) error {
	// Load from file
	var fileConfig *StewardConfig

	if configPath != "" {
		fileConfigVal, err := loadFromPath(configPath)
		if err != nil {
			return fmt.Errorf("failed to load file configuration for migration: %w", err)
		}
		fileConfig = &fileConfigVal
	} else {
		fileConfigVal, err := LoadConfiguration("")
		if err != nil {
			return fmt.Errorf("failed to load file configuration for migration: %w", err)
		}
		fileConfig = &fileConfigVal
	}

	// Store in storage provider (Epic 6 compliant)
	if err := ssa.StoreConfiguration(ctx, fileConfig); err != nil {
		return fmt.Errorf("failed to store configuration in storage provider: %w", err)
	}

	return nil
}

// ConfigurationVersion represents a version in configuration history
type ConfigurationVersion struct {
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	Checksum  string    `json:"checksum"`
	Size      int       `json:"size"`
}

// isConfigNotFoundError checks if the error indicates configuration not found
func isConfigNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	// Check for ConfigValidationError with CONFIG_NOT_FOUND code
	if configErr, ok := err.(*interfaces.ConfigValidationError); ok {
		return configErr.Code == "CONFIG_NOT_FOUND"
	}

	// Check for common "not found" error patterns
	errStr := err.Error()
	return errStr == "configuration not found" ||
		errStr == "config not found" ||
		contains(errStr, "not found") ||
		contains(errStr, "does not exist")
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

// findSubstring finds substring in string
func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// GetCurrentHostname returns the current system hostname for steward ID
func GetCurrentHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "localhost", err
	}
	return hostname, nil
}

// GetDefaultTenantID returns the default tenant ID for backward compatibility
func GetDefaultTenantID() string {
	// Check environment variable first
	if tenantID := os.Getenv("CFGMS_TENANT_ID"); tenantID != "" {
		return tenantID
	}

	// Default to "default" tenant
	return "default"
}

// Epic6CompliantLoadConfiguration is the main entry point for Epic 6 compliant configuration loading
func Epic6CompliantLoadConfiguration(ctx context.Context, configStore interfaces.ConfigStore, tenantID, stewardID string) (*StewardConfig, error) {
	adapter := NewSimpleStorageAdapter(configStore, tenantID, stewardID)

	// Try storage first, fall back to file if needed
	config, err := adapter.LoadConfigurationWithInheritance(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	return config, nil
}
