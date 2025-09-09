// Package interfaces - Provider Factory Implementation
//
// This file implements the provider factory pattern for dynamic directory provider selection.
// It follows CFGMS's pluggable infrastructure design paradigm with auto-discovery and
// configuration-driven provider instantiation.

package interfaces

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// DirectoryProviderFactory creates configured directory providers
type DirectoryProviderFactory interface {
	// CreateProvider creates a new provider instance with the given configuration
	CreateProvider(ctx context.Context, config ProviderConfig) (DirectoryProvider, error)
	
	// GetSupportedProviders returns the names of all supported providers
	GetSupportedProviders() []string
	
	// ValidateConfig validates a provider configuration without creating the provider
	ValidateConfig(config ProviderConfig) error
	
	// GetProviderInfo returns information about a specific provider type
	GetProviderInfo(providerName string) (*ProviderInfo, error)
}

// DefaultDirectoryProviderFactory is the default implementation of the factory
type DefaultDirectoryProviderFactory struct {
	constructors map[string]ProviderConstructor
	mutex        sync.RWMutex
}

// ProviderConstructor is a function that creates a new provider instance
type ProviderConstructor func() DirectoryProvider

// NewDirectoryProviderFactory creates a new directory provider factory
func NewDirectoryProviderFactory() *DefaultDirectoryProviderFactory {
	return &DefaultDirectoryProviderFactory{
		constructors: make(map[string]ProviderConstructor),
	}
}

// RegisterProviderConstructor registers a constructor function for a provider type
// This is called by provider packages in their init() functions
func (f *DefaultDirectoryProviderFactory) RegisterProviderConstructor(providerName string, constructor ProviderConstructor) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	
	f.constructors[providerName] = constructor
}

// CreateProvider creates a new configured provider instance
func (f *DefaultDirectoryProviderFactory) CreateProvider(ctx context.Context, config ProviderConfig) (DirectoryProvider, error) {
	f.mutex.RLock()
	constructor, exists := f.constructors[config.ProviderName]
	f.mutex.RUnlock()
	
	if !exists {
		available := f.GetSupportedProviders()
		return nil, fmt.Errorf("directory provider '%s' not supported. Available providers: %v", config.ProviderName, available)
	}
	
	// Validate configuration first
	if err := f.ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration for provider '%s': %w", config.ProviderName, err)
	}
	
	// Create provider instance
	provider := constructor()
	
	// Connect to the directory service
	connectCtx, cancel := context.WithTimeout(ctx, config.ConnectionTimeout)
	defer cancel()
	
	if err := provider.Connect(connectCtx, config); err != nil {
		return nil, fmt.Errorf("failed to connect to directory provider '%s': %w", config.ProviderName, err)
	}
	
	// Verify connection health
	if health, err := provider.HealthCheck(connectCtx); err != nil || !health.IsHealthy {
		_ = provider.Disconnect(connectCtx) // Ignore error during cleanup
		if err != nil {
			return nil, fmt.Errorf("health check failed for provider '%s': %w", config.ProviderName, err)
		}
		return nil, fmt.Errorf("health check failed for provider '%s': %v", config.ProviderName, health.Errors)
	}
	
	return provider, nil
}

// GetSupportedProviders returns the names of all supported providers
func (f *DefaultDirectoryProviderFactory) GetSupportedProviders() []string {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	
	providers := make([]string, 0, len(f.constructors))
	for name := range f.constructors {
		providers = append(providers, name)
	}
	
	return providers
}

// ValidateConfig validates a provider configuration
func (f *DefaultDirectoryProviderFactory) ValidateConfig(config ProviderConfig) error {
	if config.ProviderName == "" {
		return fmt.Errorf("provider_name is required")
	}
	
	if config.ServerAddress == "" {
		return fmt.Errorf("server_address is required")
	}
	
	if config.ConnectionTimeout <= 0 {
		return fmt.Errorf("connection_timeout must be positive")
	}
	
	if config.MaxConnections <= 0 {
		return fmt.Errorf("max_connections must be positive")
	}
	
	// Validate authentication method
	if config.AuthMethod == "" {
		return fmt.Errorf("auth_method is required")
	}
	
	switch config.AuthMethod {
	case AuthMethodKerberos, AuthMethodLDAP:
		if config.Username == "" {
			return fmt.Errorf("username is required for %s authentication", config.AuthMethod)
		}
		if config.Password == "" {
			return fmt.Errorf("password is required for %s authentication", config.AuthMethod)
		}
	case AuthMethodOAuth2:
		if config.ClientID == "" {
			return fmt.Errorf("client_id is required for OAuth2 authentication")
		}
		if config.TenantID == "" {
			return fmt.Errorf("tenant_id is required for OAuth2 authentication")
		}
	case AuthMethodClientCert:
		// Certificate validation would be done by provider
	case AuthMethodAPIKey:
		// API key validation would be done by provider
	default:
		return fmt.Errorf("unsupported auth_method: %s", config.AuthMethod)
	}
	
	return nil
}

// GetProviderInfo returns information about a specific provider type
func (f *DefaultDirectoryProviderFactory) GetProviderInfo(providerName string) (*ProviderInfo, error) {
	f.mutex.RLock()
	constructor, exists := f.constructors[providerName]
	f.mutex.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("provider '%s' not found", providerName)
	}
	
	// Create temporary instance to get info (without connecting)
	provider := constructor()
	info := provider.GetProviderInfo()
	
	return &info, nil
}

// Global factory instance (singleton pattern following CFGMS conventions)
var (
	globalFactory     *DefaultDirectoryProviderFactory
	globalFactoryOnce sync.Once
)

// GetGlobalDirectoryProviderFactory returns the global factory instance
func GetGlobalDirectoryProviderFactory() *DefaultDirectoryProviderFactory {
	globalFactoryOnce.Do(func() {
		globalFactory = NewDirectoryProviderFactory()
	})
	return globalFactory
}

// Convenience functions for common operations

// RegisterDirectoryProviderConstructor registers a provider constructor globally
// This is called by provider packages in their init() functions
func RegisterDirectoryProviderConstructor(providerName string, constructor ProviderConstructor) {
	factory := GetGlobalDirectoryProviderFactory()
	factory.RegisterProviderConstructor(providerName, constructor)
}

// CreateDirectoryProvider creates a directory provider using the global factory
func CreateDirectoryProvider(ctx context.Context, config ProviderConfig) (DirectoryProvider, error) {
	factory := GetGlobalDirectoryProviderFactory()
	return factory.CreateProvider(ctx, config)
}

// DirectoryProviderManager manages multiple directory providers for hybrid environments
type DirectoryProviderManager struct {
	providers map[string]DirectoryProvider
	factory   DirectoryProviderFactory
	mutex     sync.RWMutex
}

// NewDirectoryProviderManager creates a new provider manager
func NewDirectoryProviderManager(factory DirectoryProviderFactory) *DirectoryProviderManager {
	if factory == nil {
		factory = GetGlobalDirectoryProviderFactory()
	}
	
	return &DirectoryProviderManager{
		providers: make(map[string]DirectoryProvider),
		factory:   factory,
	}
}

// AddProvider adds a configured provider to the manager
func (m *DirectoryProviderManager) AddProvider(name string, config ProviderConfig) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	ctx, cancel := context.WithTimeout(context.Background(), config.ConnectionTimeout)
	defer cancel()
	
	provider, err := m.factory.CreateProvider(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to create provider '%s': %w", name, err)
	}
	
	m.providers[name] = provider
	return nil
}

// GetProvider retrieves a provider by name
func (m *DirectoryProviderManager) GetProvider(name string) (DirectoryProvider, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	provider, exists := m.providers[name]
	if !exists {
		return nil, fmt.Errorf("provider '%s' not found in manager", name)
	}
	
	return provider, nil
}

// RemoveProvider removes a provider from the manager and disconnects it
func (m *DirectoryProviderManager) RemoveProvider(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	provider, exists := m.providers[name]
	if !exists {
		return fmt.Errorf("provider '%s' not found in manager", name)
	}
	
	// Disconnect the provider
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := provider.Disconnect(ctx); err != nil {
		// Log warning but continue with removal - disconnect errors are non-fatal
		// as the provider is being removed from the registry regardless
		// In a real implementation, this would use structured logging
		_ = err // Acknowledge error but continue with removal
	}
	
	delete(m.providers, name)
	return nil
}

// ListProviders returns the names of all managed providers
func (m *DirectoryProviderManager) ListProviders() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	names := make([]string, 0, len(m.providers))
	for name := range m.providers {
		names = append(names, name)
	}
	
	return names
}

// GetProviderStatuses returns health status for all managed providers
func (m *DirectoryProviderManager) GetProviderStatuses(ctx context.Context) map[string]*HealthStatus {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	statuses := make(map[string]*HealthStatus)
	
	for name, provider := range m.providers {
		if health, err := provider.HealthCheck(ctx); err != nil {
			statuses[name] = &HealthStatus{
				IsHealthy: false,
				LastCheck: time.Now(),
				Errors:    []string{err.Error()},
			}
		} else {
			statuses[name] = health
		}
	}
	
	return statuses
}

// Close disconnects all providers and releases resources
func (m *DirectoryProviderManager) Close(ctx context.Context) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	var errors []error
	
	for name, provider := range m.providers {
		if err := provider.Disconnect(ctx); err != nil {
			errors = append(errors, fmt.Errorf("failed to disconnect provider '%s': %w", name, err))
		}
	}
	
	// Clear the providers map
	m.providers = make(map[string]DirectoryProvider)
	
	if len(errors) > 0 {
		// In a real implementation, this would be a multi-error type
		return fmt.Errorf("errors occurred while closing providers: %v", errors)
	}
	
	return nil
}

// Cross-Directory Operations Support

// CrossDirectoryOperation represents an operation that spans multiple directory providers
type CrossDirectoryOperation struct {
	SourceProvider string                 `json:"source_provider"`
	TargetProvider string                 `json:"target_provider"`
	Operation      string                 `json:"operation"`
	Parameters     map[string]interface{} `json:"parameters"`
}

// ExecuteCrossDirectoryOperation executes an operation across multiple directory providers
func (m *DirectoryProviderManager) ExecuteCrossDirectoryOperation(ctx context.Context, operation CrossDirectoryOperation) error {
	sourceProvider, err := m.GetProvider(operation.SourceProvider)
	if err != nil {
		return fmt.Errorf("source provider error: %w", err)
	}
	
	targetProvider, err := m.GetProvider(operation.TargetProvider)
	if err != nil {
		return fmt.Errorf("target provider error: %w", err)
	}
	
	switch operation.Operation {
	case "sync_user":
		userID, ok := operation.Parameters["user_id"].(string)
		if !ok {
			return fmt.Errorf("user_id parameter required for sync_user operation")
		}
		
		return sourceProvider.SyncUser(ctx, userID, targetProvider)
		
	case "sync_group":
		groupID, ok := operation.Parameters["group_id"].(string)
		if !ok {
			return fmt.Errorf("group_id parameter required for sync_group operation")
		}
		
		return sourceProvider.SyncGroup(ctx, groupID, targetProvider)
		
	default:
		return fmt.Errorf("unsupported cross-directory operation: %s", operation.Operation)
	}
}

// Provider Discovery and Capabilities

// DiscoverProviders attempts to discover available directory providers on the network
func (m *DirectoryProviderManager) DiscoverProviders(ctx context.Context, discovery DiscoveryConfig) ([]DiscoveredProvider, error) {
	// This would implement network discovery for directory services
	// For now, return empty slice - real implementation would do LDAP/DNS discovery
	return []DiscoveredProvider{}, nil
}

// DiscoveryConfig configures provider discovery
type DiscoveryConfig struct {
	Networks        []string      `json:"networks"`         // Network ranges to scan
	Protocols       []string      `json:"protocols"`        // Protocols to test (LDAP, LDAPS)
	Timeout         time.Duration `json:"timeout"`          // Discovery timeout
	MaxConcurrency  int           `json:"max_concurrency"`  // Max concurrent discovery operations
}

// DiscoveredProvider represents a discovered directory provider
type DiscoveredProvider struct {
	Address     string                 `json:"address"`      // Server address
	Type        string                 `json:"type"`         // Provider type (AD, LDAP, etc.)
	Port        int                    `json:"port"`         // Port number
	TLS         bool                   `json:"tls"`          // TLS support
	Information map[string]interface{} `json:"information"`  // Additional information
}

// Configuration Validation Helpers

// ValidateProviderConfigurations validates multiple provider configurations
func ValidateProviderConfigurations(configs map[string]ProviderConfig) map[string]error {
	factory := GetGlobalDirectoryProviderFactory()
	errors := make(map[string]error)
	
	for name, config := range configs {
		if err := factory.ValidateConfig(config); err != nil {
			errors[name] = err
		}
	}
	
	return errors
}

// GetProviderConfigurationTemplate returns a configuration template for a provider type
func GetProviderConfigurationTemplate(providerName string) (*ProviderConfig, error) {
	factory := GetGlobalDirectoryProviderFactory()
	
	info, err := factory.GetProviderInfo(providerName)
	if err != nil {
		return nil, err
	}
	
	// Create template with default values
	template := &ProviderConfig{
		ProviderName:      providerName,
		Port:              389, // Default LDAP port
		UseTLS:            true,
		MaxConnections:    10,
		ConnectionTimeout: 30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		PageSize:          100,
	}
	
	// Set provider-specific defaults based on capabilities
	if len(info.Capabilities.SupportedAuthMethods) > 0 {
		template.AuthMethod = info.Capabilities.SupportedAuthMethods[0]
	}
	
	return template, nil
}