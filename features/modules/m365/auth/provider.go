package auth

import (
	"context"
	"fmt"
	"time"
)

// Provider defines the interface for Microsoft Graph authentication
type Provider interface {
	// GetAccessToken retrieves a valid access token for the specified tenant
	GetAccessToken(ctx context.Context, tenantID string) (*AccessToken, error)
	
	// RefreshToken refreshes an existing access token
	RefreshToken(ctx context.Context, refreshToken string) (*AccessToken, error)
	
	// IsTokenValid checks if a token is still valid
	IsTokenValid(token *AccessToken) bool
}

// AccessToken represents a Microsoft Graph access token
type AccessToken struct {
	// Token is the actual access token string
	Token string `json:"access_token"`
	
	// TokenType is usually "Bearer"
	TokenType string `json:"token_type"`
	
	// ExpiresIn is the token lifetime in seconds
	ExpiresIn int `json:"expires_in"`
	
	// ExpiresAt is when the token expires
	ExpiresAt time.Time `json:"expires_at"`
	
	// Scope contains the granted scopes
	Scope string `json:"scope,omitempty"`
	
	// RefreshToken for renewing the access token
	RefreshToken string `json:"refresh_token,omitempty"`
	
	// TenantID this token is valid for
	TenantID string `json:"tenant_id"`
}

// IsExpired checks if the token is expired
func (t *AccessToken) IsExpired() bool {
	// Add 5 minutes buffer for clock skew
	return time.Now().Add(5 * time.Minute).After(t.ExpiresAt)
}

// GetAuthorizationHeader returns the authorization header value
func (t *AccessToken) GetAuthorizationHeader() string {
	if t.TokenType == "" {
		return "Bearer " + t.Token
	}
	return t.TokenType + " " + t.Token
}

// OAuth2Config represents OAuth2 configuration for Microsoft Graph
type OAuth2Config struct {
	// ClientID for the Azure AD application
	ClientID string `yaml:"client_id"`
	
	// ClientSecret for the Azure AD application (for confidential clients)
	ClientSecret string `yaml:"client_secret,omitempty"`
	
	// TenantID for the Azure AD tenant
	TenantID string `yaml:"tenant_id"`
	
	// Scopes to request
	Scopes []string `yaml:"scopes"`
	
	// RedirectURI for authorization code flow (for interactive flows)
	RedirectURI string `yaml:"redirect_uri,omitempty"`
	
	// AuthorityURL is the Azure AD authority URL
	AuthorityURL string `yaml:"authority_url,omitempty"`
	
	// UseClientCredentials determines if we use client credentials flow
	UseClientCredentials bool `yaml:"use_client_credentials"`
}

// GetAuthorityURL returns the authority URL for the tenant
func (c *OAuth2Config) GetAuthorityURL() string {
	if c.AuthorityURL != "" {
		return c.AuthorityURL
	}
	return fmt.Sprintf("https://login.microsoftonline.com/%s", c.TenantID)
}

// GetTokenURL returns the token endpoint URL for the tenant
func (c *OAuth2Config) GetTokenURL() string {
	return fmt.Sprintf("%s/oauth2/v2.0/token", c.GetAuthorityURL())
}

// GetScopeString returns scopes as a space-separated string
func (c *OAuth2Config) GetScopeString() string {
	if len(c.Scopes) == 0 {
		return "https://graph.microsoft.com/.default"
	}
	return fmt.Sprintf("%v", c.Scopes)
}

// CredentialStore defines the interface for secure credential storage
type CredentialStore interface {
	// StoreToken securely stores an access token
	StoreToken(tenantID string, token *AccessToken) error
	
	// GetToken retrieves a stored access token
	GetToken(tenantID string) (*AccessToken, error)
	
	// DeleteToken removes a stored access token
	DeleteToken(tenantID string) error
	
	// StoreConfig securely stores OAuth2 configuration
	StoreConfig(tenantID string, config *OAuth2Config) error
	
	// GetConfig retrieves stored OAuth2 configuration
	GetConfig(tenantID string) (*OAuth2Config, error)
	
	// IsAvailable checks if the credential store is available
	IsAvailable() bool
}

// AuthenticationError represents authentication-related errors
type AuthenticationError struct {
	TenantID string
	Code     string
	Message  string
	Cause    error
}

func (e *AuthenticationError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("authentication failed for tenant %s [%s]: %s, cause: %v", 
			e.TenantID, e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("authentication failed for tenant %s [%s]: %s", 
		e.TenantID, e.Code, e.Message)
}

func (e *AuthenticationError) Unwrap() error {
	return e.Cause
}

// NewAuthenticationError creates a new authentication error
func NewAuthenticationError(tenantID, code, message string, cause error) *AuthenticationError {
	return &AuthenticationError{
		TenantID: tenantID,
		Code:     code,
		Message:  message,
		Cause:    cause,
	}
}