// Package interfaces defines the global secrets provider system for CFGMS
// M-AUTH-1: Central secrets management with pluggable backends (SOPS, Vault, Azure KeyVault, AWS Secrets Manager)
package interfaces

import (
	"fmt"
	"sync"
)

// SecretProvider defines the interface that all secrets backends must implement
// Providers can implement SOPS (git-based), Vault, Azure KeyVault, AWS Secrets Manager, etc.
type SecretProvider interface {
	// Identification
	Name() string
	Description() string
	Available() (bool, error) // Check dependencies, connectivity, etc.

	// Secret store creation
	CreateSecretStore(config map[string]interface{}) (SecretStore, error)

	// Provider capabilities and metadata
	GetCapabilities() ProviderCapabilities
	GetVersion() string
}

// Global provider registry (Salt-style auto-registration)
var (
	globalRegistry = &providerRegistry{
		providers: make(map[string]SecretProvider),
	}
)

type providerRegistry struct {
	providers map[string]SecretProvider
	mutex     sync.RWMutex
}

// RegisterSecretProvider registers a secrets provider (called from provider init() functions)
// This function includes validation to ensure providers implement all required interfaces
func RegisterSecretProvider(provider SecretProvider) {
	if err := validateProvider(provider); err != nil {
		// Log the error but don't panic - allows system to start with other providers
		// In production, this would use the configured logger
		fmt.Printf("Warning: Failed to register secrets provider '%s': %v\n", provider.Name(), err)
		return
	}

	globalRegistry.mutex.Lock()
	defer globalRegistry.mutex.Unlock()

	// Check for duplicate registration
	if existing, exists := globalRegistry.providers[provider.Name()]; exists {
		fmt.Printf("Warning: Overwriting existing secrets provider '%s' (version %s) with version %s\n",
			provider.Name(), existing.GetVersion(), provider.GetVersion())
	}

	globalRegistry.providers[provider.Name()] = provider
	fmt.Printf("Registered secrets provider: %s v%s - %s\n",
		provider.Name(), provider.GetVersion(), provider.Description())
}

// validateProvider ensures a provider implements all required interfaces correctly
func validateProvider(provider SecretProvider) error {
	if provider == nil {
		return fmt.Errorf("provider is nil")
	}

	// Validate basic provider interface
	if provider.Name() == "" {
		return fmt.Errorf("provider name cannot be empty")
	}

	if provider.Description() == "" {
		return fmt.Errorf("provider description cannot be empty")
	}

	if provider.GetVersion() == "" {
		return fmt.Errorf("provider version cannot be empty")
	}

	// Test provider availability (non-blocking)
	if available, err := provider.Available(); !available && err != nil {
		// Provider not available is OK (might need setup), but returning error suggests implementation issue
		fmt.Printf("Note: Provider '%s' reports as unavailable: %v\n", provider.Name(), err)
	}

	capabilities := provider.GetCapabilities()
	if capabilities.MaxSecretSize < 0 {
		return fmt.Errorf("provider MaxSecretSize cannot be negative")
	}

	if capabilities.MaxKeyLength < 0 {
		return fmt.Errorf("provider MaxKeyLength cannot be negative")
	}

	return nil
}

// RegisterSecretProviderWithValidation registers a provider with full validation
// This is an enhanced version that tests store creation with a test config
func RegisterSecretProviderWithValidation(provider SecretProvider, testConfig map[string]interface{}) error {
	// Basic validation first
	if err := validateProvider(provider); err != nil {
		return fmt.Errorf("provider validation failed: %w", err)
	}

	// Test store creation with provided config
	if available, _ := provider.Available(); available {
		// Only test store creation if provider is available
		if _, err := provider.CreateSecretStore(testConfig); err != nil {
			return fmt.Errorf("failed to create SecretStore: %w", err)
		}
	}

	// Register after successful validation
	globalRegistry.mutex.Lock()
	defer globalRegistry.mutex.Unlock()

	globalRegistry.providers[provider.Name()] = provider
	fmt.Printf("Successfully registered and validated secrets provider: %s v%s\n",
		provider.Name(), provider.GetVersion())

	return nil
}

// GetRegisteredProviderNames returns a list of all registered provider names
func GetRegisteredProviderNames() []string {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()

	names := make([]string, 0, len(globalRegistry.providers))
	for name := range globalRegistry.providers {
		names = append(names, name)
	}

	return names
}

// UnregisterSecretProvider removes a provider from the registry (primarily for testing)
func UnregisterSecretProvider(name string) bool {
	globalRegistry.mutex.Lock()
	defer globalRegistry.mutex.Unlock()

	if _, exists := globalRegistry.providers[name]; exists {
		delete(globalRegistry.providers, name)
		return true
	}

	return false
}

// GetSecretProvider retrieves a registered provider by name
func GetSecretProvider(name string) (SecretProvider, error) {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()

	provider, exists := globalRegistry.providers[name]
	if !exists {
		return nil, fmt.Errorf("secrets provider '%s' not found", name)
	}

	// Check availability
	if available, err := provider.Available(); !available {
		return nil, fmt.Errorf("secrets provider '%s' not available: %v", name, err)
	}

	return provider, nil
}

// GetAvailableProviders returns all providers that are currently available
func GetAvailableProviders() map[string]SecretProvider {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()

	available := make(map[string]SecretProvider)
	for name, provider := range globalRegistry.providers {
		if ok, err := provider.Available(); ok && err == nil {
			available[name] = provider
		}
	}

	return available
}

// ListProviders returns information about all registered providers
func ListProviders() []ProviderInfo {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()

	var providers []ProviderInfo
	for name, provider := range globalRegistry.providers {
		available, err := provider.Available()

		info := ProviderInfo{
			Name:        name,
			Description: provider.Description(),
			Available:   available,
		}

		if err != nil {
			info.UnavailableReason = err.Error()
		}

		providers = append(providers, info)
	}

	return providers
}

// ProviderInfo provides information about a secrets provider
type ProviderInfo struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	Available         bool   `json:"available"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// ProviderCapabilities describes what features a secrets provider supports
// M-AUTH-1: Define capabilities for different secret backends
type ProviderCapabilities struct {
	SupportsVersioning     bool   `json:"supports_versioning"`      // Secret versioning support
	SupportsRotation       bool   `json:"supports_rotation"`        // Automatic secret rotation
	SupportsEncryption     bool   `json:"supports_encryption"`      // At-rest encryption (all providers should support this)
	SupportsAuditTrail     bool   `json:"supports_audit_trail"`     // Secret access audit trail
	SupportsLeasing        bool   `json:"supports_leasing"`         // Dynamic secret leasing (Vault)
	SupportsRenewal        bool   `json:"supports_renewal"`         // Lease renewal support
	SupportsRevocation     bool   `json:"supports_revocation"`      // Immediate secret revocation
	SupportsMetadata       bool   `json:"supports_metadata"`        // Custom metadata on secrets
	SupportsTags           bool   `json:"supports_tags"`            // Tagging/labeling support
	SupportsAccessPolicies bool   `json:"supports_access_policies"` // Provider-level access policies
	MaxSecretSize          int    `json:"max_secret_size"`          // Maximum secret size in bytes
	MaxKeyLength           int    `json:"max_key_length"`           // Maximum secret key length
	EncryptionAlgorithm    string `json:"encryption_algorithm"`     // Encryption algorithm used (e.g., "AES-256-GCM")
}

// Enhanced ProviderInfo with capabilities
type ProviderInfoV2 struct {
	ProviderInfo
	Capabilities ProviderCapabilities `json:"capabilities"`
	Version      string               `json:"version"`
}

// CreateSecretStoreFromConfig creates a SecretStore from configuration
// This is the main entry point used by the controller
func CreateSecretStoreFromConfig(providerName string, config map[string]interface{}) (SecretStore, error) {
	provider, err := GetSecretProvider(providerName)
	if err != nil {
		// Provide helpful error with available options
		available := GetAvailableProviders()
		var availableNames []string
		for name := range available {
			availableNames = append(availableNames, name)
		}
		return nil, fmt.Errorf("secrets provider '%s' not available. Available providers: %v. Error: %w", providerName, availableNames, err)
	}

	return provider.CreateSecretStore(config)
}

// ListProvidersV2 returns enhanced information about all registered providers
func ListProvidersV2() []ProviderInfoV2 {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()

	var providers []ProviderInfoV2
	for name, provider := range globalRegistry.providers {
		available, err := provider.Available()

		info := ProviderInfoV2{
			ProviderInfo: ProviderInfo{
				Name:        name,
				Description: provider.Description(),
				Available:   available,
			},
			Capabilities: provider.GetCapabilities(),
			Version:      provider.GetVersion(),
		}

		if err != nil {
			info.UnavailableReason = err.Error()
		}

		providers = append(providers, info)
	}

	return providers
}
