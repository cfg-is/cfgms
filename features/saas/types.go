// Package saas provides SaaS platform integration capabilities for CFGMS.
//
// The SaaS package implements a lightweight steward agent that can manage
// SaaS platform configurations using OAuth2 authentication and the existing
// CFGMS workflow engine.
//
// Key features:
//   - OAuth2 with PKCE for secure authentication
//   - Secure credential storage using OS keychain
//   - Pluggable provider architecture for different SaaS platforms
//   - Integration with existing workflow engine
//   - Automatic token refresh and management
//
// Basic usage:
//
//	steward := saas.NewSaaSteward(config, logger)
//	err := steward.Authenticate("microsoft")
//	if err != nil {
//		log.Fatal(err)
//	}
//	
//	result, err := steward.ExecuteOperation("microsoft", "users", "create", params)
package saas

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// SaaSteward is the main SaaS management component
type SaaSteward struct {
	config     *Config
	authMgr    AuthenticationManager
	credStore  CredentialStore
	providers  map[string]SaaSProvider
	httpClient *http.Client
}

// Config holds the SaaS Steward configuration
type Config struct {
	// Providers contains configuration for each SaaS provider
	Providers map[string]ProviderConfig `yaml:"providers" json:"providers"`
	
	// Security contains security-related configuration
	Security SecurityConfig `yaml:"security" json:"security"`
	
	// HTTP contains HTTP client configuration
	HTTP HTTPConfig `yaml:"http" json:"http"`
}

// ProviderConfig contains configuration for a specific SaaS provider
type ProviderConfig struct {
	// AuthType specifies the authentication type (oauth2, api_key, etc.)
	AuthType string `yaml:"auth_type" json:"auth_type"`
	
	// ClientID for OAuth2 authentication
	ClientID string `yaml:"client_id" json:"client_id"`
	
	// TenantID for multi-tenant providers (e.g., Microsoft)
	TenantID string `yaml:"tenant_id,omitempty" json:"tenant_id,omitempty"`
	
	// ProjectID for project-based providers (e.g., Google Cloud)
	ProjectID string `yaml:"project_id,omitempty" json:"project_id,omitempty"`
	
	// Scopes defines the OAuth2 scopes to request
	Scopes []string `yaml:"scopes" json:"scopes"`
	
	// BaseURL is the base URL for API calls
	BaseURL string `yaml:"base_url,omitempty" json:"base_url,omitempty"`
	
	// Region for region-specific providers (e.g., AWS)
	Region string `yaml:"region,omitempty" json:"region,omitempty"`
	
	// Custom contains provider-specific configuration
	Custom map[string]interface{} `yaml:"custom,omitempty" json:"custom,omitempty"`
}

// SecurityConfig contains security-related configuration
type SecurityConfig struct {
	// CredentialStore specifies the credential storage backend
	CredentialStore string `yaml:"credential_store" json:"credential_store"`
	
	// EncryptionKey for encrypting credentials at rest
	EncryptionKey string `yaml:"encryption_key" json:"encryption_key"`
	
	// TokenRefreshThreshold is seconds before expiry to refresh tokens
	TokenRefreshThreshold int `yaml:"token_refresh_threshold" json:"token_refresh_threshold"`
	
	// PKCEEnabled enables PKCE for OAuth2 flows
	PKCEEnabled bool `yaml:"pkce_enabled" json:"pkce_enabled"`
}

// HTTPConfig contains HTTP client configuration
type HTTPConfig struct {
	// Timeout for HTTP requests
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
	
	// RetryAttempts for failed requests
	RetryAttempts int `yaml:"retry_attempts" json:"retry_attempts"`
	
	// UserAgent for HTTP requests
	UserAgent string `yaml:"user_agent" json:"user_agent"`
}

// SaaSProvider defines the interface for SaaS platform providers
type SaaSProvider interface {
	// GetName returns the provider name
	GetName() string
	
	// GetServices returns supported services
	GetServices() []string
	
	// GetOperations returns supported operations for a service
	GetOperations(service string) []string
	
	// Authenticate performs OAuth2 authentication
	Authenticate(ctx context.Context, config ProviderConfig, credStore CredentialStore) error
	
	// IsAuthenticated checks if the provider has valid credentials
	IsAuthenticated(ctx context.Context, credStore CredentialStore) bool
	
	// RefreshToken refreshes the access token if needed
	RefreshToken(ctx context.Context, credStore CredentialStore) error
	
	// ExecuteOperation executes a SaaS operation
	ExecuteOperation(ctx context.Context, service, operation string, params map[string]interface{}) (*OperationResult, error)
	
	// ValidateConfig validates the provider configuration
	ValidateConfig(config ProviderConfig) error
}

// AuthenticationManager handles OAuth2 authentication flows
type AuthenticationManager interface {
	// StartOAuth2Flow initiates an OAuth2 authentication flow
	StartOAuth2Flow(ctx context.Context, provider string, config ProviderConfig) (*OAuth2Flow, error)
	
	// CompleteOAuth2Flow completes an OAuth2 flow with authorization code
	CompleteOAuth2Flow(ctx context.Context, flow *OAuth2Flow, authCode string) (*TokenSet, error)
	
	// RefreshToken refreshes an access token using a refresh token
	RefreshToken(ctx context.Context, provider string, refreshToken string) (*TokenSet, error)
}

// CredentialStore handles secure storage of credentials and tokens
type CredentialStore interface {
	// StoreTokenSet stores a complete token set for a provider
	StoreTokenSet(provider string, tokens *TokenSet) error
	
	// GetTokenSet retrieves a token set for a provider
	GetTokenSet(provider string) (*TokenSet, error)
	
	// DeleteTokenSet removes a token set for a provider
	DeleteTokenSet(provider string) error
	
	// StoreClientSecret stores a client secret for a provider
	StoreClientSecret(provider, clientSecret string) error
	
	// GetClientSecret retrieves a client secret for a provider
	GetClientSecret(provider string) (string, error)
	
	// IsAvailable checks if the credential store is available
	IsAvailable() bool
}

// OAuth2Flow represents an in-progress OAuth2 authentication flow
type OAuth2Flow struct {
	// Provider name
	Provider string `json:"provider"`
	
	// State parameter for CSRF protection
	State string `json:"state"`
	
	// CodeVerifier for PKCE
	CodeVerifier string `json:"code_verifier"`
	
	// CodeChallenge for PKCE
	CodeChallenge string `json:"code_challenge"`
	
	// AuthURL is the authorization URL to redirect user to
	AuthURL string `json:"auth_url"`
	
	// RedirectURI for OAuth2 callback
	RedirectURI string `json:"redirect_uri"`
	
	// Created timestamp
	Created time.Time `json:"created"`
	
	// ExpiresAt when this flow expires
	ExpiresAt time.Time `json:"expires_at"`
}

// TokenSet represents a complete set of OAuth2 tokens
type TokenSet struct {
	// AccessToken for API authentication
	AccessToken string `json:"access_token"`
	
	// RefreshToken for token renewal
	RefreshToken string `json:"refresh_token,omitempty"`
	
	// TokenType (usually "Bearer")
	TokenType string `json:"token_type"`
	
	// ExpiresAt when the access token expires
	ExpiresAt time.Time `json:"expires_at"`
	
	// Scopes granted by the authorization server
	Scopes []string `json:"scopes,omitempty"`
	
	// Extra contains provider-specific token information
	Extra map[string]interface{} `json:"extra,omitempty"`
}

// OperationResult represents the result of a SaaS operation
type OperationResult struct {
	// Success indicates if the operation was successful
	Success bool `json:"success"`
	
	// Data contains the operation result data
	Data interface{} `json:"data,omitempty"`
	
	// Error contains error information if the operation failed
	Error string `json:"error,omitempty"`
	
	// StatusCode is the HTTP status code
	StatusCode int `json:"status_code"`
	
	// Headers contains relevant response headers
	Headers map[string]string `json:"headers,omitempty"`
	
	// Duration is how long the operation took
	Duration time.Duration `json:"duration"`
	
	// Metadata contains operation-specific metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// AuthenticationError represents authentication-related errors
type AuthenticationError struct {
	Provider string
	Code     string
	Message  string
	Cause    error
}

func (e *AuthenticationError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("authentication failed for provider %s [%s]: %s, cause: %v", 
			e.Provider, e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("authentication failed for provider %s [%s]: %s", 
		e.Provider, e.Code, e.Message)
}

// ProviderError represents provider-specific errors
type ProviderError struct {
	Provider  string
	Service   string
	Operation string
	Code      string
	Message   string
	Cause     error
}

func (e *ProviderError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("provider %s/%s/%s failed [%s]: %s, cause: %v", 
			e.Provider, e.Service, e.Operation, e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("provider %s/%s/%s failed [%s]: %s", 
		e.Provider, e.Service, e.Operation, e.Code, e.Message)
}

// IsTokenExpired checks if a token is expired or will expire soon
func (ts *TokenSet) IsTokenExpired(threshold time.Duration) bool {
	if ts.ExpiresAt.IsZero() {
		return false // No expiry information, assume valid
	}
	return time.Now().Add(threshold).After(ts.ExpiresAt)
}

// IsValid checks if a token set is valid and not expired
func (ts *TokenSet) IsValid(threshold time.Duration) bool {
	return ts.AccessToken != "" && !ts.IsTokenExpired(threshold)
}

// GetAuthorizationHeader returns the authorization header value
func (ts *TokenSet) GetAuthorizationHeader() string {
	if ts.TokenType == "" {
		return "Bearer " + ts.AccessToken
	}
	return ts.TokenType + " " + ts.AccessToken
}