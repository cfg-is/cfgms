// Package interfaces defines the global storage provider system for CFGMS
package interfaces

import (
	"fmt"
	"sync"
)

// StorageProvider defines the interface that all storage backends must implement
// Each provider creates all storage interfaces consistently (ClientTenantStore, ConfigStore, AuditStore, DNAStore)
type StorageProvider interface {
	// Identification
	Name() string
	Description() string
	Available() (bool, error) // Check dependencies, connectivity, etc.
	
	// Storage interface creation - All providers must implement all interfaces
	CreateClientTenantStore(config map[string]interface{}) (ClientTenantStore, error)
	CreateConfigStore(config map[string]interface{}) (ConfigStore, error)
	CreateAuditStore(config map[string]interface{}) (AuditStore, error)
	
	// Future: CreateDNAStore for DNA storage integration (Epic 6)
	// CreateDNAStore(config map[string]interface{}) (DNAStore, error)
	
	// Provider capabilities and metadata
	GetCapabilities() ProviderCapabilities
	GetVersion() string
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
// This function includes validation to ensure providers implement all required interfaces
func RegisterStorageProvider(provider StorageProvider) {
	if err := validateProvider(provider); err != nil {
		// Log the error but don't panic - allows system to start with other providers
		// In production, this would use the configured logger
		fmt.Printf("Warning: Failed to register storage provider '%s': %v\n", provider.Name(), err)
		return
	}
	
	globalRegistry.mutex.Lock()
	defer globalRegistry.mutex.Unlock()
	
	// Check for duplicate registration
	if existing, exists := globalRegistry.providers[provider.Name()]; exists {
		fmt.Printf("Warning: Overwriting existing storage provider '%s' (version %s) with version %s\n", 
			provider.Name(), existing.GetVersion(), provider.GetVersion())
	}
	
	globalRegistry.providers[provider.Name()] = provider
	fmt.Printf("Registered storage provider: %s v%s - %s\n", 
		provider.Name(), provider.GetVersion(), provider.Description())
}

// validateProvider ensures a provider implements all required interfaces correctly
func validateProvider(provider StorageProvider) error {
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
	
	// Validate provider supports required storage interface creation methods
	// We can't easily test interface creation without config, but we can check method existence
	// This is done by Go's type system at compile time, so we focus on runtime validation
	
	capabilities := provider.GetCapabilities()
	if capabilities.MaxBatchSize < 0 {
		return fmt.Errorf("provider MaxBatchSize cannot be negative")
	}
	
	if capabilities.MaxConfigSize < 0 {
		return fmt.Errorf("provider MaxConfigSize cannot be negative")
	}
	
	if capabilities.MaxAuditRetentionDays < 0 {
		return fmt.Errorf("provider MaxAuditRetentionDays cannot be negative")
	}
	
	return nil
}

// RegisterStorageProviderWithValidation registers a provider with full validation
// This is an enhanced version that tests interface creation with a test config
func RegisterStorageProviderWithValidation(provider StorageProvider, testConfig map[string]interface{}) error {
	// Basic validation first
	if err := validateProvider(provider); err != nil {
		return fmt.Errorf("provider validation failed: %w", err)
	}
	
	// Test interface creation with provided config
	if available, _ := provider.Available(); available {
		// Only test interface creation if provider is available
		if _, err := provider.CreateClientTenantStore(testConfig); err != nil {
			return fmt.Errorf("failed to create ClientTenantStore: %w", err)
		}
		
		if _, err := provider.CreateConfigStore(testConfig); err != nil {
			return fmt.Errorf("failed to create ConfigStore: %w", err)
		}
		
		if _, err := provider.CreateAuditStore(testConfig); err != nil {
			return fmt.Errorf("failed to create AuditStore: %w", err)
		}
	}
	
	// Register after successful validation
	globalRegistry.mutex.Lock()
	defer globalRegistry.mutex.Unlock()
	
	globalRegistry.providers[provider.Name()] = provider
	fmt.Printf("Successfully registered and validated storage provider: %s v%s\n", 
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

// UnregisterStorageProvider removes a provider from the registry (primarily for testing)
func UnregisterStorageProvider(name string) bool {
	globalRegistry.mutex.Lock()
	defer globalRegistry.mutex.Unlock()
	
	if _, exists := globalRegistry.providers[name]; exists {
		delete(globalRegistry.providers, name)
		return true
	}
	
	return false
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

// ProviderCapabilities describes what features a storage provider supports
type ProviderCapabilities struct {
	SupportsTransactions    bool `json:"supports_transactions"`     // ACID transaction support
	SupportsVersioning      bool `json:"supports_versioning"`       // Configuration versioning
	SupportsFullTextSearch  bool `json:"supports_full_text_search"` // Full-text search in audit logs
	SupportsEncryption      bool `json:"supports_encryption"`       // At-rest encryption
	SupportsCompression     bool `json:"supports_compression"`      // Data compression
	SupportsReplication     bool `json:"supports_replication"`      // Data replication/HA
	SupportsSharding        bool `json:"supports_sharding"`         // Horizontal partitioning
	MaxBatchSize           int  `json:"max_batch_size"`            // Maximum batch operation size
	MaxConfigSize          int  `json:"max_config_size"`           // Maximum single config size
	MaxAuditRetentionDays  int  `json:"max_audit_retention_days"`  // Maximum audit retention period
}

// Enhanced ProviderInfo with capabilities
type ProviderInfoV2 struct {
	ProviderInfo
	Capabilities ProviderCapabilities `json:"capabilities"`
	Version      string               `json:"version"`
}

// CreateClientTenantStoreFromConfig creates a ClientTenantStore from configuration
// This is the main entry point used by the controller
func CreateClientTenantStoreFromConfig(providerName string, config map[string]interface{}) (ClientTenantStore, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("storage provider '%s' not available: %w", providerName, err)
	}
	
	return provider.CreateClientTenantStore(config)
}

// CreateConfigStoreFromConfig creates a ConfigStore from configuration
func CreateConfigStoreFromConfig(providerName string, config map[string]interface{}) (ConfigStore, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("storage provider '%s' not available: %w", providerName, err)
	}
	
	return provider.CreateConfigStore(config)
}

// CreateAuditStoreFromConfig creates an AuditStore from configuration
func CreateAuditStoreFromConfig(providerName string, config map[string]interface{}) (AuditStore, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("storage provider '%s' not available: %w", providerName, err)
	}
	
	return provider.CreateAuditStore(config)
}

// CreateAllStoresFromConfig creates all storage interfaces from a single configuration
// This is the main entry point for unified storage configuration
func CreateAllStoresFromConfig(providerName string, config map[string]interface{}) (*StorageManager, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		// Provide helpful error with available options
		available := GetAvailableProviders()
		var availableNames []string
		for name := range available {
			availableNames = append(availableNames, name)
		}
		return nil, fmt.Errorf("storage provider '%s' not available. Available providers: %v. Error: %w", providerName, availableNames, err)
	}
	
	// Create all store interfaces
	clientTenantStore, err := provider.CreateClientTenantStore(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create client tenant store: %w", err)
	}
	
	configStore, err := provider.CreateConfigStore(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create config store: %w", err)
	}
	
	auditStore, err := provider.CreateAuditStore(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit store: %w", err)
	}
	
	return &StorageManager{
		providerName:      providerName,
		provider:          provider,
		clientTenantStore: clientTenantStore,
		configStore:       configStore,
		auditStore:        auditStore,
	}, nil
}

// StorageManager provides unified access to all storage interfaces
type StorageManager struct {
	providerName      string
	provider          StorageProvider
	clientTenantStore ClientTenantStore
	configStore       ConfigStore
	auditStore        AuditStore
}

// GetProviderName returns the name of the storage provider
func (sm *StorageManager) GetProviderName() string {
	return sm.providerName
}

// GetProvider returns the underlying storage provider
func (sm *StorageManager) GetProvider() StorageProvider {
	return sm.provider
}

// GetClientTenantStore returns the client tenant storage interface
func (sm *StorageManager) GetClientTenantStore() ClientTenantStore {
	return sm.clientTenantStore
}

// GetConfigStore returns the configuration storage interface
func (sm *StorageManager) GetConfigStore() ConfigStore {
	return sm.configStore
}

// GetAuditStore returns the audit storage interface
func (sm *StorageManager) GetAuditStore() AuditStore {
	return sm.auditStore
}

// GetCapabilities returns the provider's capabilities
func (sm *StorageManager) GetCapabilities() ProviderCapabilities {
	return sm.provider.GetCapabilities()
}

// GetVersion returns the provider's version
func (sm *StorageManager) GetVersion() string {
	return sm.provider.GetVersion()
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