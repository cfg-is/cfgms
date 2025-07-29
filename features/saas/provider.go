// Package saas provider implements the universal API provider interface
// for SaaS platform integrations in CFGMS.
//
// The Provider interface enables both normalized operations (create, read, update, delete, list)
// and raw API access for any SaaS platform. This dual approach provides:
//   - Simple, standardized operations for common use cases
//   - Full flexibility via raw API access for complex scenarios
//   - Universal authentication handling across all platforms
//   - Seamless integration with both workflow engine and SaaS steward modules
//
// Example usage:
//
//	registry := NewProviderRegistry()
//	provider := registry.GetProvider("microsoft")
//	
//	// Normalized operation
//	result, err := provider.Create(ctx, "users", map[string]interface{}{
//		"displayName": "John Doe",
//		"userPrincipalName": "john@company.com",
//	})
//	
//	// Raw API access
//	result, err := provider.RawAPI(ctx, "GET", "/users/john@company.com", nil)
package saas

import (
	"context"
	"fmt"
	"net/http"
	"sync"
)

// Provider defines the universal interface for SaaS platform integrations.
// All providers must implement both normalized operations and raw API access.
type Provider interface {
	// GetInfo returns basic provider information
	GetInfo() ProviderInfo
	
	// Authenticate performs authentication for this provider
	Authenticate(ctx context.Context, config ProviderConfig, credStore CredentialStore) error
	
	// IsAuthenticated checks if the provider has valid credentials
	IsAuthenticated(ctx context.Context, credStore CredentialStore) bool
	
	// RefreshAuth refreshes authentication credentials if needed
	RefreshAuth(ctx context.Context, credStore CredentialStore) error
	
	// Normalized Operations Interface
	// These provide standardized CRUD operations across all providers
	
	// Create creates a new resource
	Create(ctx context.Context, resourceType string, data map[string]interface{}) (*ProviderResult, error)
	
	// Read retrieves a resource by ID
	Read(ctx context.Context, resourceType string, resourceID string) (*ProviderResult, error)
	
	// Update modifies an existing resource
	Update(ctx context.Context, resourceType string, resourceID string, data map[string]interface{}) (*ProviderResult, error)
	
	// Delete removes a resource
	Delete(ctx context.Context, resourceType string, resourceID string) (*ProviderResult, error)
	
	// List retrieves multiple resources with optional filtering
	List(ctx context.Context, resourceType string, filters map[string]interface{}) (*ProviderResult, error)
	
	// Raw API Interface
	// Provides direct access to the underlying API for complex operations
	
	// RawAPI executes a raw API call
	RawAPI(ctx context.Context, method, path string, body interface{}) (*ProviderResult, error)
	
	// GetAPISchema returns the OpenAPI/Swagger schema if available
	GetAPISchema(ctx context.Context) (*APISchema, error)
	
	// Resource Management
	
	// GetSupportedResources returns list of resources this provider supports
	GetSupportedResources() []ResourceType
	
	// GetResourceSchema returns the schema for a specific resource type
	GetResourceSchema(resourceType string) (*ResourceSchema, error)
	
	// ValidateResource validates resource data against the schema
	ValidateResource(resourceType string, data map[string]interface{}) error
}

// ProviderInfo contains basic information about a provider
type ProviderInfo struct {
	// Name is the provider identifier (e.g., "microsoft", "google", "salesforce")
	Name string `json:"name"`
	
	// DisplayName is the human-readable name
	DisplayName string `json:"display_name"`
	
	// Version is the provider implementation version
	Version string `json:"version"`
	
	// Description provides details about the provider
	Description string `json:"description"`
	
	// SupportedAuthTypes lists supported authentication methods
	SupportedAuthTypes []string `json:"supported_auth_types"`
	
	// BaseURL is the default API base URL
	BaseURL string `json:"base_url"`
	
	// DocumentationURL points to provider documentation
	DocumentationURL string `json:"documentation_url"`
	
	// Capabilities describes what this provider supports
	Capabilities ProviderCapabilities `json:"capabilities"`
}

// ProviderCapabilities describes provider feature support
type ProviderCapabilities struct {
	// NormalizedOperations indicates which CRUD operations are supported
	NormalizedOperations []string `json:"normalized_operations"`
	
	// RawAPISupport indicates if raw API access is available
	RawAPISupport bool `json:"raw_api_support"`
	
	// SchemaSupport indicates if OpenAPI/schema discovery is available
	SchemaSupport bool `json:"schema_support"`
	
	// PaginationSupport indicates if list operations support pagination
	PaginationSupport bool `json:"pagination_support"`
	
	// WebhookSupport indicates if the provider supports webhooks
	WebhookSupport bool `json:"webhook_support"`
	
	// BatchOperations indicates if bulk operations are supported
	BatchOperations bool `json:"batch_operations"`
}

// ProviderResult represents the result of any provider operation
type ProviderResult struct {
	// Success indicates if the operation completed successfully
	Success bool `json:"success"`
	
	// Data contains the operation result data
	Data interface{} `json:"data,omitempty"`
	
	// Error contains error information if the operation failed
	Error string `json:"error,omitempty"`
	
	// StatusCode is the HTTP status code from the API
	StatusCode int `json:"status_code"`
	
	// Headers contains relevant response headers
	Headers map[string]string `json:"headers,omitempty"`
	
	// Metadata contains operation-specific metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	
	// Pagination information for list operations
	Pagination *PaginationInfo `json:"pagination,omitempty"`
	
	// RateLimit information from the API
	RateLimit *RateLimitInfo `json:"rate_limit,omitempty"`
}

// PaginationInfo contains pagination details for list operations
type PaginationInfo struct {
	// HasMore indicates if there are more results available
	HasMore bool `json:"has_more"`
	
	// NextToken for cursor-based pagination
	NextToken string `json:"next_token,omitempty"`
	
	// Page for offset-based pagination
	Page int `json:"page,omitempty"`
	
	// PerPage indicates items per page
	PerPage int `json:"per_page,omitempty"`
	
	// Total count of items (if available)
	Total int `json:"total,omitempty"`
}

// RateLimitInfo contains rate limiting information
type RateLimitInfo struct {
	// Limit is the rate limit ceiling for this period
	Limit int `json:"limit"`
	
	// Remaining is the number of requests remaining in current period
	Remaining int `json:"remaining"`
	
	// ResetAt is when the rate limit resets
	ResetAt int64 `json:"reset_at"`
	
	// RetryAfter is seconds to wait before retrying (for 429 responses)
	RetryAfter int `json:"retry_after,omitempty"`
}

// ResourceType describes a resource type supported by a provider
type ResourceType struct {
	// Name is the resource type identifier (e.g., "users", "groups")
	Name string `json:"name"`
	
	// DisplayName is human-readable name
	DisplayName string `json:"display_name"`
	
	// Description describes the resource type
	Description string `json:"description"`
	
	// SupportedOperations lists which CRUD operations are supported
	SupportedOperations []string `json:"supported_operations"`
	
	// RequiredFields lists fields required for create operations
	RequiredFields []string `json:"required_fields"`
	
	// OptionalFields lists optional fields
	OptionalFields []string `json:"optional_fields"`
	
	// ReadOnlyFields lists fields that cannot be modified
	ReadOnlyFields []string `json:"read_only_fields"`
}

// ResourceSchema defines the structure and validation rules for a resource
type ResourceSchema struct {
	// Type is the resource type name
	Type string `json:"type"`
	
	// Properties defines the resource fields and their schemas
	Properties map[string]PropertySchema `json:"properties"`
	
	// Required lists required fields
	Required []string `json:"required"`
	
	// Examples provides example resource data
	Examples []map[string]interface{} `json:"examples,omitempty"`
}

// PropertySchema defines schema for a single property
type PropertySchema struct {
	// Type is the property data type
	Type string `json:"type"`
	
	// Format provides additional type information
	Format string `json:"format,omitempty"`
	
	// Description explains the property
	Description string `json:"description,omitempty"`
	
	// Enum lists valid values for enumerated properties
	Enum []interface{} `json:"enum,omitempty"`
	
	// ReadOnly indicates if the property cannot be modified
	ReadOnly bool `json:"read_only,omitempty"`
	
	// WriteOnly indicates if the property is write-only
	WriteOnly bool `json:"write_only,omitempty"`
}

// APISchema represents an OpenAPI/Swagger schema
type APISchema struct {
	// OpenAPI version
	OpenAPI string `json:"openapi"`
	
	// Info contains API metadata
	Info APIInfo `json:"info"`
	
	// Servers lists available API servers
	Servers []APIServer `json:"servers"`
	
	// Paths defines available API endpoints
	Paths map[string]map[string]APIOperation `json:"paths"`
	
	// Components contains reusable schema components
	Components map[string]interface{} `json:"components"`
}

// APIInfo contains API metadata
type APIInfo struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

// APIServer describes an API server
type APIServer struct {
	URL         string `json:"url"`
	Description string `json:"description"`
}

// APIOperation describes a single API operation
type APIOperation struct {
	Summary     string                 `json:"summary"`
	Description string                 `json:"description"`
	Parameters  []APIParameter         `json:"parameters"`
	RequestBody map[string]interface{} `json:"requestBody"`
	Responses   map[string]interface{} `json:"responses"`
}

// APIParameter describes an API parameter
type APIParameter struct {
	Name        string `json:"name"`
	In          string `json:"in"` // query, path, header, cookie
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Schema      map[string]interface{} `json:"schema"`
}

// ProviderRegistry manages available providers
type ProviderRegistry struct {
	providers map[string]Provider
	mu        sync.RWMutex
}

// NewProviderRegistry creates a new provider registry
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: make(map[string]Provider),
	}
}

// RegisterProvider registers a new provider
func (r *ProviderRegistry) RegisterProvider(provider Provider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	info := provider.GetInfo()
	if info.Name == "" {
		return fmt.Errorf("provider name cannot be empty")
	}
	
	if _, exists := r.providers[info.Name]; exists {
		return fmt.Errorf("provider %s is already registered", info.Name)
	}
	
	r.providers[info.Name] = provider
	return nil
}

// GetProvider retrieves a provider by name
func (r *ProviderRegistry) GetProvider(name string) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	provider, exists := r.providers[name]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", name)
	}
	
	return provider, nil
}

// ListProviders returns all registered providers
func (r *ProviderRegistry) ListProviders() []ProviderInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	infos := make([]ProviderInfo, 0, len(r.providers))
	for _, provider := range r.providers {
		infos = append(infos, provider.GetInfo())
	}
	
	return infos
}

// HasProvider checks if a provider is registered
func (r *ProviderRegistry) HasProvider(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	_, exists := r.providers[name]
	return exists
}

// UnregisterProvider removes a provider from the registry
func (r *ProviderRegistry) UnregisterProvider(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if _, exists := r.providers[name]; !exists {
		return fmt.Errorf("provider %s not found", name)
	}
	
	delete(r.providers, name)
	return nil
}

// BaseProvider provides common functionality for provider implementations
type BaseProvider struct {
	info       ProviderInfo
	httpClient *http.Client
	credStore  CredentialStore
}

// NewBaseProvider creates a new base provider
func NewBaseProvider(info ProviderInfo, httpClient *http.Client) *BaseProvider {
	return &BaseProvider{
		info:       info,
		httpClient: httpClient,
	}
}

// GetInfo returns provider information
func (bp *BaseProvider) GetInfo() ProviderInfo {
	return bp.info
}

// SetCredentialStore sets the credential store
func (bp *BaseProvider) SetCredentialStore(credStore CredentialStore) {
	bp.credStore = credStore
}

// GetHTTPClient returns the HTTP client
func (bp *BaseProvider) GetHTTPClient() *http.Client {
	return bp.httpClient
}

// Common authentication methods that providers can use

// AuthMethod represents an authentication method
type AuthMethod string

const (
	AuthMethodOAuth2           AuthMethod = "oauth2"
	AuthMethodAPIKey          AuthMethod = "api_key"
	AuthMethodBasicAuth       AuthMethod = "basic_auth"
	AuthMethodBearerToken     AuthMethod = "bearer_token"
	AuthMethodJWT             AuthMethod = "jwt"
	AuthMethodClientCert      AuthMethod = "client_cert"
	AuthMethodAWSSignature    AuthMethod = "aws_signature"
	AuthMethodCustom          AuthMethod = "custom"
)

// AuthConfig contains authentication configuration
type AuthConfig struct {
	Method AuthMethod `json:"method"`
	Config map[string]interface{} `json:"config"`
}

// OAuth2Config contains OAuth2-specific configuration
type OAuth2Config struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
	TokenURL     string   `json:"token_url"`
	AuthURL      string   `json:"auth_url"`
	RedirectURL  string   `json:"redirect_url"`
}

// APIKeyConfig contains API key authentication configuration
type APIKeyConfig struct {
	Key       string `json:"key"`
	Header    string `json:"header"`    // Header name to send key in
	QueryParam string `json:"query_param"` // Query parameter name (alternative to header)
}

// BasicAuthConfig contains basic authentication configuration
type BasicAuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// BearerTokenConfig contains bearer token configuration
type BearerTokenConfig struct {
	Token string `json:"token"`
}

// JWTConfig contains JWT authentication configuration
type JWTConfig struct {
	Token      string            `json:"token"`
	PrivateKey string            `json:"private_key"`
	Algorithm  string            `json:"algorithm"`
	Claims     map[string]interface{} `json:"claims"`
}