// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces defines global storage contracts used by all CFGMS modules
package interfaces

import (
	"fmt"
	"sync"
)

// BlobProvider is the factory interface for BlobStore backends.
// It follows the same auto-registration pattern as StorageProvider but is kept
// separate because blob storage is an independent concern with its own lifecycle.
type BlobProvider interface {
	// Name returns the unique provider identifier (e.g., "filesystem", "s3").
	Name() string
	// Description returns a human-readable description.
	Description() string
	// Available reports whether the provider is usable in the current environment.
	Available() (bool, error)
	// GetVersion returns the provider version string.
	GetVersion() string
	// CreateBlobStore instantiates a BlobStore from the given configuration map.
	CreateBlobStore(config map[string]interface{}) (BlobStore, error)
}

// Global blob provider registry — separate from the StorageProvider registry.
var globalBlobRegistry = &blobProviderRegistry{
	providers: make(map[string]BlobProvider),
}

type blobProviderRegistry struct {
	providers map[string]BlobProvider
	mutex     sync.RWMutex
}

// RegisterBlobProvider registers a BlobProvider. Called from provider init() functions.
func RegisterBlobProvider(provider BlobProvider) {
	if provider == nil {
		fmt.Println("Warning: attempted to register nil blob provider")
		return
	}
	if provider.Name() == "" {
		fmt.Println("Warning: blob provider name cannot be empty")
		return
	}

	globalBlobRegistry.mutex.Lock()
	defer globalBlobRegistry.mutex.Unlock()

	if existing, exists := globalBlobRegistry.providers[provider.Name()]; exists {
		fmt.Printf("Warning: overwriting existing blob provider '%s' (version %s) with version %s\n",
			provider.Name(), existing.GetVersion(), provider.GetVersion())
	}

	globalBlobRegistry.providers[provider.Name()] = provider
	fmt.Printf("Registered blob provider: %s v%s - %s\n",
		provider.Name(), provider.GetVersion(), provider.Description())
}

// GetBlobProvider retrieves a registered BlobProvider by name.
func GetBlobProvider(name string) (BlobProvider, error) {
	globalBlobRegistry.mutex.RLock()
	defer globalBlobRegistry.mutex.RUnlock()

	provider, exists := globalBlobRegistry.providers[name]
	if !exists {
		return nil, fmt.Errorf("blob provider '%s' not found", name)
	}

	if available, err := provider.Available(); !available {
		return nil, fmt.Errorf("blob provider '%s' not available: %v", name, err)
	}

	return provider, nil
}

// CreateBlobStoreFromConfig creates a BlobStore using the named provider.
// This is the main entry point for operator configuration of blob storage.
func CreateBlobStoreFromConfig(providerName string, config map[string]interface{}) (BlobStore, error) {
	provider, err := GetBlobProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("blob provider '%s' not available: %w", providerName, err)
	}
	return provider.CreateBlobStore(config)
}

// GetRegisteredBlobProviderNames returns the names of all registered blob providers.
func GetRegisteredBlobProviderNames() []string {
	globalBlobRegistry.mutex.RLock()
	defer globalBlobRegistry.mutex.RUnlock()

	names := make([]string, 0, len(globalBlobRegistry.providers))
	for name := range globalBlobRegistry.providers {
		names = append(names, name)
	}
	return names
}

// UnregisterBlobProvider removes a blob provider from the registry.
// Intended for use in tests only.
func UnregisterBlobProvider(name string) bool {
	globalBlobRegistry.mutex.Lock()
	defer globalBlobRegistry.mutex.Unlock()

	if _, exists := globalBlobRegistry.providers[name]; exists {
		delete(globalBlobRegistry.providers, name)
		return true
	}
	return false
}
