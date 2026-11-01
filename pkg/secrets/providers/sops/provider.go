// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sops implements authenticated envelope-encrypted secret storage.
package sops

import (
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// SOPSProvider retains its historical registration name for configuration
// compatibility. Encryption is performed directly with AES-256-GCM and an
// external key file; it does not shell out to Mozilla SOPS.
type SOPSProvider struct{}

// Name returns the provider name
func (p *SOPSProvider) Name() string {
	return "sops"
}

// Description returns a human-readable description.
func (p *SOPSProvider) Description() string {
	return "AES-256-GCM envelope-encrypted secret storage with an external key file"
}

// GetVersion returns the provider version
func (p *SOPSProvider) GetVersion() string {
	return "1.0.0"
}

// GetCapabilities returns the provider's capabilities
func (p *SOPSProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{
		SupportsVersioning:     true,            // Backing ConfigStore provides history
		SupportsRotation:       true,            // We implement secret rotation
		SupportsEncryption:     true,            // SOPS provides AES-256-GCM encryption
		SupportsAuditTrail:     true,            // Backing ConfigStore records versions
		SupportsLeasing:        false,           // SOPS doesn't support dynamic leasing
		SupportsRenewal:        false,           // No lease renewal support
		SupportsRevocation:     true,            // Can delete secrets immediately
		SupportsMetadata:       true,            // Support custom metadata
		SupportsTags:           true,            // Support tagging secrets
		SupportsAccessPolicies: false,           // Access control handled by git/RBAC
		MaxSecretSize:          1 * 1024 * 1024, // 1MB max secret size
		MaxKeyLength:           256,             // 256 character key names
		EncryptionAlgorithm:    "AES-256-GCM",
	}
}

// ClusterCapable returns true if this provider can serve as shared state across
// multiple CFGMS controller nodes in cluster mode.
func (p *SOPSProvider) ClusterCapable() bool { return false }

// Available reports provider registration availability. External key and
// backing-store availability are checked fail-closed during creation.
func (p *SOPSProvider) Available() (bool, error) {
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
		// Default storage configuration (flatfile for SOPS secrets)
		storeConfig.StorageConfig = map[string]interface{}{
			"root": "/var/lib/cfgms/secrets",
		}
	}

	// Parse storage provider name
	if providerName, ok := config["storage_provider"].(string); ok {
		storeConfig.StorageProvider = providerName
	} else {
		storeConfig.StorageProvider = "flatfile" // Default to flatfile
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

	// The key file must be provisioned separately from the data store (for
	// example through a systemd encrypted credential or a container secret).
	if keyFile, ok := config["key_file"].(string); ok {
		storeConfig.KeyFile = strings.TrimSpace(keyFile)
	}
	if storeConfig.KeyFile == "" {
		return nil, fmt.Errorf("key_file is required; plaintext secret storage is prohibited")
	}

	return storeConfig, nil
}

// Auto-register this provider (Salt-style)
func init() {
	interfaces.RegisterSecretProvider(&SOPSProvider{})
}
