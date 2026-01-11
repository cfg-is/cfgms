// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package workflow provides integration framework for external API providers.
//
// This module implements a plugin architecture for SaaS and API integrations,
// allowing easy extension of the workflow engine to support new platforms
// like M365, Google Workspace, Salesforce, ConnectWise, and other MSP tools.
//
// Key features:
//   - Provider registry system for managing API integrations
//   - Plugin architecture for extensible provider support
//   - Standardized interface for all external API providers
//   - Configuration management and validation
//   - Authentication and authorization handling
//   - Error handling and retry logic
//
// Basic usage:
//
//	registry := NewProviderRegistry()
//
//	// Register built-in providers
//	registry.RegisterProvider("microsoft", &MicrosoftProvider{})
//	registry.RegisterProvider("google", &GoogleProvider{})
//
//	// Execute API operation
//	result, err := registry.ExecuteOperation(ctx, "microsoft", "users", "create", params)
package workflow

import (
	"context"
	"fmt"
	"sync"

	"github.com/cfgis/cfgms/pkg/logging"
)

// ProviderRegistry manages external API providers and their operations
type ProviderRegistry struct {
	providers map[string]APIProvider
	mutex     sync.RWMutex
	logger    logging.Logger
}

// APIProvider defines the interface that all external API providers must implement
type APIProvider interface {
	// GetName returns the provider name (e.g., "microsoft", "google", "salesforce")
	GetName() string

	// GetServices returns the list of services supported by this provider
	GetServices() []string

	// GetOperations returns the list of operations supported for a specific service
	GetOperations(service string) []string

	// ValidateConfig validates the provider configuration
	ValidateConfig(config *APIConfig) error

	// ExecuteOperation executes an API operation
	ExecuteOperation(ctx context.Context, config *APIConfig) (*APIResponse, error)

	// GetAuthenticationMethods returns supported authentication methods
	GetAuthenticationMethods() []AuthType

	// RefreshToken refreshes authentication tokens if needed
	RefreshToken(ctx context.Context, config *APIConfig) error
}

// APIResponse represents the response from an API operation
type APIResponse struct {
	// Success indicates if the operation was successful
	Success bool

	// Data contains the response data
	Data interface{}

	// Error contains error information if the operation failed
	Error string

	// StatusCode contains the HTTP status code
	StatusCode int

	// Headers contains response headers
	Headers map[string][]string

	// Duration is how long the operation took
	Duration string

	// Metadata contains provider-specific metadata
	Metadata map[string]interface{}
}

// ProviderInfo contains information about a registered provider
type ProviderInfo struct {
	Name                string
	Services            []string
	SupportedAuth       []AuthType
	ConfigurationSchema map[string]interface{}
	DocumentationURL    string
	Version             string
}

// NewProviderRegistry creates a new provider registry
func NewProviderRegistry(logger logging.Logger) *ProviderRegistry {
	registry := &ProviderRegistry{
		providers: make(map[string]APIProvider),
		logger:    logger,
	}

	// Register built-in providers
	registry.registerBuiltinProviders()

	return registry
}

// RegisterProvider registers an API provider with the registry
func (r *ProviderRegistry) RegisterProvider(name string, provider APIProvider) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.providers[name]; exists {
		return fmt.Errorf("provider %s is already registered", name)
	}

	r.providers[name] = provider
	r.logger.Info("Registered API provider", "provider", name)

	return nil
}

// GetProvider returns a registered provider by name
func (r *ProviderRegistry) GetProvider(name string) (APIProvider, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	provider, exists := r.providers[name]
	if !exists {
		return nil, fmt.Errorf("provider %s is not registered", name)
	}

	return provider, nil
}

// ListProviders returns a list of all registered providers
func (r *ProviderRegistry) ListProviders() []ProviderInfo {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var providers []ProviderInfo
	for name, provider := range r.providers {
		info := ProviderInfo{
			Name:          name,
			Services:      provider.GetServices(),
			SupportedAuth: provider.GetAuthenticationMethods(),
		}
		providers = append(providers, info)
	}

	return providers
}

// ExecuteOperation executes an API operation using the specified provider
func (r *ProviderRegistry) ExecuteOperation(ctx context.Context, config *APIConfig) (*APIResponse, error) {
	// Get the provider
	provider, err := r.GetProvider(config.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	// Validate the configuration
	if err := provider.ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Refresh authentication token if needed
	if err := provider.RefreshToken(ctx, config); err != nil {
		r.logger.Warn("Failed to refresh token", "provider", config.Provider, "error", err)
		// Continue with existing token - some providers may not need refresh
	}

	// Execute the operation
	response, err := provider.ExecuteOperation(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("operation failed: %w", err)
	}

	r.logger.Info("API operation completed",
		"provider", config.Provider,
		"service", config.Service,
		"operation", config.Operation,
		"success", response.Success)

	return response, nil
}

// registerBuiltinProviders registers the built-in API providers
func (r *ProviderRegistry) registerBuiltinProviders() {
	// Register Microsoft provider
	if err := r.RegisterProvider("microsoft", &MicrosoftProvider{}); err != nil {
		r.logger.Error("Failed to register Microsoft provider", "error", err)
	}

	// Register Google provider
	if err := r.RegisterProvider("google", &GoogleProvider{}); err != nil {
		r.logger.Error("Failed to register Google provider", "error", err)
	}

	// Register Salesforce provider
	if err := r.RegisterProvider("salesforce", &SalesforceProvider{}); err != nil {
		r.logger.Error("Failed to register Salesforce provider", "error", err)
	}

	// Register ConnectWise provider
	if err := r.RegisterProvider("connectwise", &ConnectWiseProvider{}); err != nil {
		r.logger.Error("Failed to register ConnectWise provider", "error", err)
	}
}

// MicrosoftProvider implements the APIProvider interface for Microsoft services
type MicrosoftProvider struct{}

func (p *MicrosoftProvider) GetName() string {
	return "microsoft"
}

func (p *MicrosoftProvider) GetServices() []string {
	return []string{"graph", "users", "groups", "teams", "exchange", "sharepoint", "intune"}
}

func (p *MicrosoftProvider) GetOperations(service string) []string {
	switch service {
	case "users":
		return []string{"list", "get", "create", "update", "delete", "assign_license"}
	case "groups":
		return []string{"list", "get", "create", "update", "delete", "add_member", "remove_member"}
	case "teams":
		return []string{"list", "get", "create", "add_member", "remove_member"}
	case "exchange":
		return []string{"get_mailbox", "configure_mailbox", "set_forwarding"}
	default:
		return []string{"list", "get", "create", "update", "delete"}
	}
}

func (p *MicrosoftProvider) GetAuthenticationMethods() []AuthType {
	return []AuthType{AuthTypeOAuth2, AuthTypeBearer}
}

func (p *MicrosoftProvider) ValidateConfig(config *APIConfig) error {
	if config.Service == "" {
		return fmt.Errorf("service is required")
	}

	validServices := p.GetServices()
	for _, service := range validServices {
		if config.Service == service {
			return nil
		}
	}

	return fmt.Errorf("unsupported service: %s", config.Service)
}

func (p *MicrosoftProvider) ExecuteOperation(ctx context.Context, config *APIConfig) (*APIResponse, error) {
	// This is a simplified implementation
	// In a real system, this would make actual Microsoft Graph API calls
	return &APIResponse{
		Success:    true,
		Data:       map[string]interface{}{"message": "Microsoft operation simulated"},
		StatusCode: 200,
		Metadata: map[string]interface{}{
			"provider": "microsoft",
			"service":  config.Service,
		},
	}, nil
}

func (p *MicrosoftProvider) RefreshToken(ctx context.Context, config *APIConfig) error {
	// Implement OAuth2 token refresh logic for Microsoft
	return nil
}

// GoogleProvider implements the APIProvider interface for Google services
type GoogleProvider struct{}

func (p *GoogleProvider) GetName() string {
	return "google"
}

func (p *GoogleProvider) GetServices() []string {
	return []string{"admin", "workspace", "gmail", "drive", "calendar"}
}

func (p *GoogleProvider) GetOperations(service string) []string {
	switch service {
	case "admin":
		return []string{"list_users", "create_user", "update_user", "delete_user"}
	case "workspace":
		return []string{"list_domains", "create_group", "manage_group"}
	default:
		return []string{"list", "get", "create", "update", "delete"}
	}
}

func (p *GoogleProvider) GetAuthenticationMethods() []AuthType {
	return []AuthType{AuthTypeOAuth2, AuthTypeAPIKey}
}

func (p *GoogleProvider) ValidateConfig(config *APIConfig) error {
	if config.Service == "" {
		return fmt.Errorf("service is required")
	}

	validServices := p.GetServices()
	for _, service := range validServices {
		if config.Service == service {
			return nil
		}
	}

	return fmt.Errorf("unsupported service: %s", config.Service)
}

func (p *GoogleProvider) ExecuteOperation(ctx context.Context, config *APIConfig) (*APIResponse, error) {
	return &APIResponse{
		Success:    true,
		Data:       map[string]interface{}{"message": "Google operation simulated"},
		StatusCode: 200,
		Metadata: map[string]interface{}{
			"provider": "google",
			"service":  config.Service,
		},
	}, nil
}

func (p *GoogleProvider) RefreshToken(ctx context.Context, config *APIConfig) error {
	// Implement OAuth2 token refresh logic for Google
	return nil
}

// SalesforceProvider implements the APIProvider interface for Salesforce
type SalesforceProvider struct{}

func (p *SalesforceProvider) GetName() string {
	return "salesforce"
}

func (p *SalesforceProvider) GetServices() []string {
	return []string{"sobjects", "query", "metadata", "analytics"}
}

func (p *SalesforceProvider) GetOperations(service string) []string {
	switch service {
	case "sobjects":
		return []string{"create", "get", "update", "delete", "describe"}
	case "query":
		return []string{"soql", "sosl"}
	default:
		return []string{"create", "get", "update", "delete"}
	}
}

func (p *SalesforceProvider) GetAuthenticationMethods() []AuthType {
	return []AuthType{AuthTypeOAuth2, AuthTypeBearer}
}

func (p *SalesforceProvider) ValidateConfig(config *APIConfig) error {
	if config.Service == "" {
		return fmt.Errorf("service is required")
	}

	validServices := p.GetServices()
	for _, service := range validServices {
		if config.Service == service {
			return nil
		}
	}

	return fmt.Errorf("unsupported service: %s", config.Service)
}

func (p *SalesforceProvider) ExecuteOperation(ctx context.Context, config *APIConfig) (*APIResponse, error) {
	return &APIResponse{
		Success:    true,
		Data:       map[string]interface{}{"message": "Salesforce operation simulated"},
		StatusCode: 200,
		Metadata: map[string]interface{}{
			"provider": "salesforce",
			"service":  config.Service,
		},
	}, nil
}

func (p *SalesforceProvider) RefreshToken(ctx context.Context, config *APIConfig) error {
	// Implement OAuth2 token refresh logic for Salesforce
	return nil
}

// ConnectWiseProvider implements the APIProvider interface for ConnectWise
type ConnectWiseProvider struct{}

func (p *ConnectWiseProvider) GetName() string {
	return "connectwise"
}

func (p *ConnectWiseProvider) GetServices() []string {
	return []string{"manage", "automate", "control", "sell"}
}

func (p *ConnectWiseProvider) GetOperations(service string) []string {
	switch service {
	case "manage":
		return []string{"companies", "contacts", "tickets", "agreements", "time_entries"}
	case "automate":
		return []string{"clients", "locations", "computers", "scripts", "monitors"}
	case "control":
		return []string{"sessions", "machines", "reports"}
	default:
		return []string{"list", "get", "create", "update", "delete"}
	}
}

func (p *ConnectWiseProvider) GetAuthenticationMethods() []AuthType {
	return []AuthType{AuthTypeAPIKey, AuthTypeBasic}
}

func (p *ConnectWiseProvider) ValidateConfig(config *APIConfig) error {
	if config.Service == "" {
		return fmt.Errorf("service is required")
	}

	validServices := p.GetServices()
	for _, service := range validServices {
		if config.Service == service {
			return nil
		}
	}

	return fmt.Errorf("unsupported service: %s", config.Service)
}

func (p *ConnectWiseProvider) ExecuteOperation(ctx context.Context, config *APIConfig) (*APIResponse, error) {
	return &APIResponse{
		Success:    true,
		Data:       map[string]interface{}{"message": "ConnectWise operation simulated"},
		StatusCode: 200,
		Metadata: map[string]interface{}{
			"provider": "connectwise",
			"service":  config.Service,
		},
	}, nil
}

func (p *ConnectWiseProvider) RefreshToken(ctx context.Context, config *APIConfig) error {
	// ConnectWise typically uses API keys, no token refresh needed
	return nil
}
