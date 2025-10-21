// Package sops implements SOPS-based secrets provider for CFGMS
// M-AUTH-1: Secure secret storage using Mozilla SOPS with git backend
package sops

import (
	"fmt"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// SOPSProvider implements the SecretProvider interface using SOPS encryption
// This provider uses git ConfigStore as the backend, which automatically handles SOPS encryption
type SOPSProvider struct{}

// Name returns the provider name
func (p *SOPSProvider) Name() string {
	return "sops"
}

// Description returns a human-readable description
func (p *SOPSProvider) Description() string {
	return "SOPS-based secure secret storage with git backend and AES-256-GCM encryption"
}

// GetVersion returns the provider version
func (p *SOPSProvider) GetVersion() string {
	return "1.0.0"
}

// GetCapabilities returns the provider's capabilities
func (p *SOPSProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{
		SupportsVersioning:     true,  // Git provides version history
		SupportsRotation:       true,  // We implement secret rotation
		SupportsEncryption:     true,  // SOPS provides AES-256-GCM encryption
		SupportsAuditTrail:     true,  // Git commits provide full audit trail
		SupportsLeasing:        false, // SOPS doesn't support dynamic leasing
		SupportsRenewal:        false, // No lease renewal support
		SupportsRevocation:     true,  // Can delete secrets immediately
		SupportsMetadata:       true,  // Support custom metadata
		SupportsTags:           true,  // Support tagging secrets
		SupportsAccessPolicies: false, // Access control handled by git/RBAC
		MaxSecretSize:          1 * 1024 * 1024, // 1MB max secret size
		MaxKeyLength:           256,   // 256 character key names
		EncryptionAlgorithm:    "AES-256-GCM", // SOPS uses AES-256-GCM
	}
}

// Available checks if SOPS and git are available
func (p *SOPSProvider) Available() (bool, error) {
	// Check if we can access storage provider (git provider should be registered)
	// The actual availability check happens when creating the store
	return true, nil
}

// CreateSecretStore creates a SOPS-based secret store
// M-AUTH-1: Create secret store that uses git ConfigStore with SOPS encryption
func (p *SOPSProvider) CreateSecretStore(config map[string]interface{}) (interfaces.SecretStore, error) {
	// Parse configuration
	storeConfig, err := parseStoreConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid store configuration: %w", err)
	}

	// Create SOPS secret store
	store, err := NewSOPSSecretStore(storeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOPS secret store: %w", err)
	}

	return store, nil
}

// parseStoreConfig parses store configuration from map
func parseStoreConfig(config map[string]interface{}) (*SOPSSecretStoreConfig, error) {
	storeConfig := &SOPSSecretStoreConfig{
		CacheEnabled: true, // Enable caching by default
		CacheTTL:     300,  // 5 minutes default
		CacheMaxSize: 1000, // 1000 secrets max
	}

	// Parse storage provider configuration
	if storageConfig, ok := config["storage_config"].(map[string]interface{}); ok {
		storeConfig.StorageConfig = storageConfig
	} else {
		// Default storage configuration (git with SOPS)
		storeConfig.StorageConfig = map[string]interface{}{
			"repository_path": "/var/lib/cfgms/secrets",
		}
	}

	// Parse storage provider name
	if providerName, ok := config["storage_provider"].(string); ok {
		storeConfig.StorageProvider = providerName
	} else {
		storeConfig.StorageProvider = "git" // Default to git
	}

	// Parse cache settings
	if cacheEnabled, ok := config["cache_enabled"].(bool); ok {
		storeConfig.CacheEnabled = cacheEnabled
	}

	if cacheTTL, ok := config["cache_ttl"].(int); ok {
		storeConfig.CacheTTL = cacheTTL
	}

	if cacheMaxSize, ok := config["cache_max_size"].(int); ok {
		storeConfig.CacheMaxSize = cacheMaxSize
	}

	// Parse SOPS key ID (optional)
	if kmsKeyID, ok := config["kms_key_id"].(string); ok {
		storeConfig.KMSKeyID = kmsKeyID
	}

	return storeConfig, nil
}

// Auto-register this provider (Salt-style)
func init() {
	interfaces.RegisterSecretProvider(&SOPSProvider{})
}
