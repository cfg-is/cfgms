// Package interfaces defines the global storage provider system for CFGMS
package interfaces

import (
	"fmt"
	"sync"
)

// StorageProvider defines the interface that all storage backends must implement
// Each provider creates all storage interfaces consistently (ClientTenantStore, ConfigStore, etc.)
type StorageProvider interface {
	// Identification
	Name() string
	Description() string
	Available() (bool, error) // Check dependencies, connectivity, etc.
	
	// Storage interface creation
	CreateClientTenantStore(config map[string]interface{}) (ClientTenantStore, error)
	// Future: CreateConfigStore, CreateAuditStore, etc.
}

// Global provider registry (Salt-style auto-registration)
var (
	globalRegistry = &providerRegistry{
		providers: make(map[string]StorageProvider),
	}
)

type providerRegistry struct {
	providers map[string]StorageProvider
	mutex     sync.RWMutex
}

// RegisterStorageProvider registers a storage provider (called from provider init() functions)
func RegisterStorageProvider(provider StorageProvider) {
	globalRegistry.mutex.Lock()
	defer globalRegistry.mutex.Unlock()
	
	globalRegistry.providers[provider.Name()] = provider
}

// GetStorageProvider retrieves a registered provider by name
func GetStorageProvider(name string) (StorageProvider, error) {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()
	
	provider, exists := globalRegistry.providers[name]
	if !exists {
		return nil, fmt.Errorf("storage provider '%s' not found", name)
	}
	
	// Check availability
	if available, err := provider.Available(); !available {
		return nil, fmt.Errorf("storage provider '%s' not available: %v", name, err)
	}
	
	return provider, nil
}

// GetAvailableProviders returns all providers that are currently available
func GetAvailableProviders() map[string]StorageProvider {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()
	
	available := make(map[string]StorageProvider)
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

// ProviderInfo provides information about a storage provider
type ProviderInfo struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	Available         bool   `json:"available"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// CreateClientTenantStoreFromConfig creates a ClientTenantStore from configuration
// This is the main entry point used by the controller
func CreateClientTenantStoreFromConfig(providerName string, config map[string]interface{}) (ClientTenantStore, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		// Provide helpful error with available options
		available := GetAvailableProviders()
		var availableNames []string
		for name := range available {
			availableNames = append(availableNames, name)
		}
		return nil, fmt.Errorf("storage provider '%s' not available. Available providers: %v", providerName, availableNames)
	}
	
	return provider.CreateClientTenantStore(config)
}