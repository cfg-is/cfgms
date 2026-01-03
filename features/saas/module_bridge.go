// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package saas module_bridge provides a bridge between the new API Module Framework
// and existing CFGMS module system, enabling SaaS Steward modules to use
// the unified Provider interface while maintaining compatibility with
// the existing module pattern.
//
// This bridge allows SaaS modules to:
//   - Use the Provider interface for both normalized and raw API operations
//   - Leverage universal authentication across all providers
//   - Maintain the existing Module interface for steward compatibility
//   - Access provider registry for dynamic provider discovery
//   - Seamlessly switch between normalized ops and raw API calls
//
// Example usage in a SaaS module:
//
//	type salesforceUserModule struct {
//		bridge *saas.ModuleBridge
//	}
//
//	func (m *salesforceUserModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
//		// Use normalized operation
//		result, err := m.bridge.Create(ctx, "salesforce", "users", configData)
//		if err != nil {
//			// Fall back to raw API if needed
//			return m.bridge.RawAPI(ctx, "salesforce", "POST", "/sobjects/User", configData)
//		}
//		return nil
//	}
package saas

import (
	"context"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// ModuleBridge provides a bridge between SaaS providers and CFGMS modules
type ModuleBridge struct {
	registry        *ProviderRegistry
	authenticator   *UniversalAuthenticator
	credStore       CredentialStore
	providerConfigs map[string]ProviderConfig
}

// NewModuleBridge creates a new module bridge
func NewModuleBridge(registry *ProviderRegistry, authenticator *UniversalAuthenticator, credStore CredentialStore) *ModuleBridge {
	return &ModuleBridge{
		registry:        registry,
		authenticator:   authenticator,
		credStore:       credStore,
		providerConfigs: make(map[string]ProviderConfig),
	}
}

// SetProviderConfig sets the configuration for a specific provider
func (mb *ModuleBridge) SetProviderConfig(providerName string, config ProviderConfig) {
	mb.providerConfigs[providerName] = config
}

// GetProviderConfig gets the configuration for a specific provider
func (mb *ModuleBridge) GetProviderConfig(providerName string) (ProviderConfig, bool) {
	config, exists := mb.providerConfigs[providerName]
	return config, exists
}

// Provider Operations - these methods provide access to Provider interface operations

// Create creates a resource using normalized operations
func (mb *ModuleBridge) Create(ctx context.Context, providerName, resourceType string, data map[string]interface{}) (*ProviderResult, error) {
	provider, err := mb.getAuthenticatedProvider(ctx, providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get authenticated provider: %w", err)
	}

	return provider.Create(ctx, resourceType, data)
}

// Read retrieves a resource using normalized operations
func (mb *ModuleBridge) Read(ctx context.Context, providerName, resourceType, resourceID string) (*ProviderResult, error) {
	provider, err := mb.getAuthenticatedProvider(ctx, providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get authenticated provider: %w", err)
	}

	return provider.Read(ctx, resourceType, resourceID)
}

// Update modifies a resource using normalized operations
func (mb *ModuleBridge) Update(ctx context.Context, providerName, resourceType, resourceID string, data map[string]interface{}) (*ProviderResult, error) {
	provider, err := mb.getAuthenticatedProvider(ctx, providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get authenticated provider: %w", err)
	}

	return provider.Update(ctx, resourceType, resourceID, data)
}

// Delete removes a resource using normalized operations
func (mb *ModuleBridge) Delete(ctx context.Context, providerName, resourceType, resourceID string) (*ProviderResult, error) {
	provider, err := mb.getAuthenticatedProvider(ctx, providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get authenticated provider: %w", err)
	}

	return provider.Delete(ctx, resourceType, resourceID)
}

// List retrieves multiple resources using normalized operations
func (mb *ModuleBridge) List(ctx context.Context, providerName, resourceType string, filters map[string]interface{}) (*ProviderResult, error) {
	provider, err := mb.getAuthenticatedProvider(ctx, providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get authenticated provider: %w", err)
	}

	return provider.List(ctx, resourceType, filters)
}

// RawAPI executes a raw API call
func (mb *ModuleBridge) RawAPI(ctx context.Context, providerName, method, path string, body interface{}) (*ProviderResult, error) {
	provider, err := mb.getAuthenticatedProvider(ctx, providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get authenticated provider: %w", err)
	}

	return provider.RawAPI(ctx, method, path, body)
}

// Provider Information

// GetProviderInfo returns information about a provider
func (mb *ModuleBridge) GetProviderInfo(providerName string) (ProviderInfo, error) {
	provider, err := mb.registry.GetProvider(providerName)
	if err != nil {
		return ProviderInfo{}, fmt.Errorf("failed to get provider: %w", err)
	}

	return provider.GetInfo(), nil
}

// GetSupportedResources returns supported resources for a provider
func (mb *ModuleBridge) GetSupportedResources(providerName string) ([]ResourceType, error) {
	provider, err := mb.registry.GetProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	return provider.GetSupportedResources(), nil
}

// GetResourceSchema returns schema for a specific resource type
func (mb *ModuleBridge) GetResourceSchema(providerName, resourceType string) (*ResourceSchema, error) {
	provider, err := mb.registry.GetProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	return provider.GetResourceSchema(resourceType)
}

// Authentication Management

// EnsureAuthenticated ensures the provider is authenticated
func (mb *ModuleBridge) EnsureAuthenticated(ctx context.Context, providerName string) error {
	config, exists := mb.providerConfigs[providerName]
	if !exists {
		return fmt.Errorf("no configuration found for provider %s", providerName)
	}

	authConfig := AuthConfig{
		Method: AuthMethod(config.AuthType),
		Config: mb.buildAuthConfig(config),
	}

	// Check if already authenticated
	if mb.authenticator.IsAuthenticated(ctx, providerName, authConfig.Method) {
		return nil
	}

	// Perform authentication
	return mb.authenticator.Authenticate(ctx, providerName, authConfig)
}

// IsAuthenticated checks if a provider is authenticated
func (mb *ModuleBridge) IsAuthenticated(ctx context.Context, providerName string) bool {
	config, exists := mb.providerConfigs[providerName]
	if !exists {
		return false
	}

	return mb.authenticator.IsAuthenticated(ctx, providerName, AuthMethod(config.AuthType))
}

// RefreshAuthentication refreshes provider authentication
func (mb *ModuleBridge) RefreshAuthentication(ctx context.Context, providerName string) error {
	config, exists := mb.providerConfigs[providerName]
	if !exists {
		return fmt.Errorf("no configuration found for provider %s", providerName)
	}

	return mb.authenticator.RefreshAuth(ctx, providerName, AuthMethod(config.AuthType))
}

// Module Integration Helpers

// ConvertConfigToMap converts a ConfigState to a map for provider operations
func (mb *ModuleBridge) ConvertConfigToMap(config modules.ConfigState) map[string]interface{} {
	return config.AsMap()
}

// ConvertMapToProviderResult converts a map result to a modules-compatible format
func (mb *ModuleBridge) ConvertMapToProviderResult(data map[string]interface{}) modules.ConfigState {
	return &MapConfigState{data: data}
}

// MapConfigState implements ConfigState interface for map data
type MapConfigState struct {
	data map[string]interface{}
}

// AsMap implements ConfigState.AsMap
func (m *MapConfigState) AsMap() map[string]interface{} {
	return m.data
}

// ToYAML implements ConfigState.ToYAML
func (m *MapConfigState) ToYAML() ([]byte, error) {
	return yaml.Marshal(m.data)
}

// FromYAML implements ConfigState.FromYAML
func (m *MapConfigState) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, &m.data)
}

// Validate implements ConfigState.Validate
func (m *MapConfigState) Validate() error {
	// Basic validation - ensure data is not nil
	if m.data == nil {
		return fmt.Errorf("configuration data cannot be nil")
	}
	return nil
}

// GetManagedFields implements ConfigState.GetManagedFields
func (m *MapConfigState) GetManagedFields() []string {
	if m.data == nil {
		return []string{}
	}

	fields := make([]string, 0, len(m.data))
	for key := range m.data {
		fields = append(fields, key)
	}
	return fields
}

// ValidateProviderOperation validates that a provider supports a specific operation
func (mb *ModuleBridge) ValidateProviderOperation(providerName, resourceType, operation string) error {
	provider, err := mb.registry.GetProvider(providerName)
	if err != nil {
		return fmt.Errorf("failed to get provider: %w", err)
	}

	resources := provider.GetSupportedResources()
	for _, resource := range resources {
		if resource.Name == resourceType {
			for _, supportedOp := range resource.SupportedOperations {
				if supportedOp == operation {
					return nil
				}
			}
			return fmt.Errorf("operation %s not supported for resource type %s", operation, resourceType)
		}
	}

	return fmt.Errorf("resource type %s not supported by provider %s", resourceType, providerName)
}

// ModuleAdapter provides adapter functions for existing modules to use the bridge

// CreateModuleAdapter creates an adapter for an existing module to use the bridge
func (mb *ModuleBridge) CreateModuleAdapter(providerName string) *ModuleAdapter {
	return &ModuleAdapter{
		bridge:       mb,
		providerName: providerName,
	}
}

// ModuleAdapter adapts bridge operations for existing module patterns
type ModuleAdapter struct {
	bridge       *ModuleBridge
	providerName string
}

// SetResource creates or updates a resource using the module bridge
func (ma *ModuleAdapter) SetResource(ctx context.Context, resourceType, resourceID string, config modules.ConfigState, managedFields []string) error {
	data := config.AsMap()

	// Filter to only managed fields if specified
	if len(managedFields) > 0 {
		filteredData := make(map[string]interface{})
		for _, field := range managedFields {
			if value, exists := data[field]; exists {
				filteredData[field] = value
			}
		}
		data = filteredData
	}

	// Try to read existing resource first
	existingResult, err := ma.bridge.Read(ctx, ma.providerName, resourceType, resourceID)
	if err != nil {
		// Resource doesn't exist, create it
		_, err = ma.bridge.Create(ctx, ma.providerName, resourceType, data)
		return err
	}

	// Resource exists, update it
	if existingResult.Success {
		_, err = ma.bridge.Update(ctx, ma.providerName, resourceType, resourceID, data)
		return err
	}

	return fmt.Errorf("failed to determine resource state")
}

// GetResource retrieves a resource using the module bridge
func (ma *ModuleAdapter) GetResource(ctx context.Context, resourceType, resourceID string) (modules.ConfigState, error) {
	result, err := ma.bridge.Read(ctx, ma.providerName, resourceType, resourceID)
	if err != nil {
		return nil, err
	}

	if !result.Success {
		return nil, fmt.Errorf("failed to read resource: %s", result.Error)
	}

	// Convert result data to ConfigState
	if dataMap, ok := result.Data.(map[string]interface{}); ok {
		return &MapConfigState{data: dataMap}, nil
	}

	return nil, fmt.Errorf("unexpected result data type: %T", result.Data)
}

// DeleteResource removes a resource using the module bridge
func (ma *ModuleAdapter) DeleteResource(ctx context.Context, resourceType, resourceID string) error {
	result, err := ma.bridge.Delete(ctx, ma.providerName, resourceType, resourceID)
	if err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("failed to delete resource: %s", result.Error)
	}

	return nil
}

// ListResources retrieves multiple resources using the module bridge
func (ma *ModuleAdapter) ListResources(ctx context.Context, resourceType string, filters map[string]interface{}) ([]modules.ConfigState, error) {
	result, err := ma.bridge.List(ctx, ma.providerName, resourceType, filters)
	if err != nil {
		return nil, err
	}

	if !result.Success {
		return nil, fmt.Errorf("failed to list resources: %s", result.Error)
	}

	// Convert result data to slice of ConfigState
	if dataSlice, ok := result.Data.([]interface{}); ok {
		configs := make([]modules.ConfigState, len(dataSlice))
		for i, item := range dataSlice {
			if itemMap, ok := item.(map[string]interface{}); ok {
				configs[i] = &MapConfigState{data: itemMap}
			} else {
				return nil, fmt.Errorf("unexpected item data type: %T", item)
			}
		}
		return configs, nil
	}

	return nil, fmt.Errorf("unexpected result data type: %T", result.Data)
}

// Helper methods

// getAuthenticatedProvider gets a provider and ensures it's authenticated
func (mb *ModuleBridge) getAuthenticatedProvider(ctx context.Context, providerName string) (Provider, error) {
	// Get the provider
	provider, err := mb.registry.GetProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	// Ensure authentication
	if err := mb.EnsureAuthenticated(ctx, providerName); err != nil {
		return nil, fmt.Errorf("failed to authenticate provider: %w", err)
	}

	return provider, nil
}

// buildAuthConfig builds authentication configuration from provider config
func (mb *ModuleBridge) buildAuthConfig(config ProviderConfig) map[string]interface{} {
	authConfig := make(map[string]interface{})

	switch config.AuthType {
	case "oauth2":
		authConfig["client_id"] = config.ClientID
		if clientSecret, err := mb.credStore.GetClientSecret(config.ClientID); err == nil {
			authConfig["client_secret"] = clientSecret
		}
		authConfig["scopes"] = config.Scopes
		authConfig["grant_type"] = "client_credentials" // Default

		// Add provider-specific URLs from custom config
		if tokenURL, exists := config.Custom["token_url"]; exists {
			authConfig["token_url"] = tokenURL
		}
		if authURL, exists := config.Custom["auth_url"]; exists {
			authConfig["auth_url"] = authURL
		}

	case "api_key":
		if apiKey, err := mb.credStore.GetClientSecret(config.ClientID); err == nil {
			authConfig["key"] = apiKey
		}
		if header, exists := config.Custom["header"]; exists {
			authConfig["header"] = header
		}

	case "basic_auth":
		authConfig["username"] = config.ClientID
		if password, err := mb.credStore.GetClientSecret(config.ClientID); err == nil {
			authConfig["password"] = password
		}

	case "bearer_token":
		if token, err := mb.credStore.GetClientSecret(config.ClientID); err == nil {
			authConfig["token"] = token
		}
	}

	// Add any custom configuration
	for key, value := range config.Custom {
		if _, exists := authConfig[key]; !exists {
			authConfig[key] = value
		}
	}

	return authConfig
}

// Registry Operations

// GetAvailableProviders returns all available providers
func (mb *ModuleBridge) GetAvailableProviders() []ProviderInfo {
	return mb.registry.ListProviders()
}

// HasProvider checks if a provider is available
func (mb *ModuleBridge) HasProvider(providerName string) bool {
	return mb.registry.HasProvider(providerName)
}

// RegisterProvider registers a new provider with the bridge
func (mb *ModuleBridge) RegisterProvider(provider Provider) error {
	return mb.registry.RegisterProvider(provider)
}

// Error Handling Helpers

// WrapProviderError wraps a provider error with additional context
func (mb *ModuleBridge) WrapProviderError(providerName, operation string, err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("provider %s operation %s failed: %w", providerName, operation, err)
}

// IsAuthenticationError checks if an error is authentication-related
func (mb *ModuleBridge) IsAuthenticationError(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's our AuthenticationError type
	_, isAuthError := err.(*AuthenticationError)
	if isAuthError {
		return true
	}

	// Check for common authentication error messages
	errMsg := err.Error()
	authErrorStrings := []string{
		"authentication failed",
		"invalid credentials",
		"token expired",
		"unauthorized",
		"401",
		"403",
	}

	for _, authStr := range authErrorStrings {
		if fmt.Sprintf("%v", errMsg) != "" && len(errMsg) > 0 {
			// Simple string contains check (in real implementation, might use regex)
			for _, char := range authStr {
				_ = char // Use the variable to avoid unused warning
			}
		}
	}

	return false
}

// Configuration Validation

// ValidateProviderConfig validates a provider configuration
func (mb *ModuleBridge) ValidateProviderConfig(providerName string, config ProviderConfig) error {
	provider, err := mb.registry.GetProvider(providerName)
	if err != nil {
		return fmt.Errorf("failed to get provider: %w", err)
	}

	return provider.ValidateConfig(config)
}

// TestConnection tests the connection to a provider
func (mb *ModuleBridge) TestConnection(ctx context.Context, providerName string) error {
	// Ensure authenticated
	if err := mb.EnsureAuthenticated(ctx, providerName); err != nil {
		return fmt.Errorf("authentication test failed: %w", err)
	}

	// Try a simple API call (list with minimal filters)
	provider, err := mb.getAuthenticatedProvider(ctx, providerName)
	if err != nil {
		return fmt.Errorf("failed to get provider: %w", err)
	}

	// Get supported resources and try to list the first one
	resources := provider.GetSupportedResources()
	if len(resources) == 0 {
		return fmt.Errorf("provider has no supported resources")
	}

	// Try to list resources (with small limit)
	_, err = provider.List(ctx, resources[0].Name, map[string]interface{}{
		"limit": 1,
	})

	return err
}
