// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Common errors for authentication operations
var (
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenExpired  = errors.New("token expired")
	ErrInvalidToken  = errors.New("invalid token")
)

// Provider defines the interface for Microsoft Graph authentication
type Provider interface {
	// GetAccessToken retrieves a valid access token for the specified tenant
	GetAccessToken(ctx context.Context, tenantID string) (*AccessToken, error)

	// GetDelegatedAccessToken retrieves a valid delegated access token for the specified user
	GetDelegatedAccessToken(ctx context.Context, tenantID string, userContext *UserContext) (*AccessToken, error)

	// RefreshToken refreshes an existing access token
	RefreshToken(ctx context.Context, refreshToken string) (*AccessToken, error)

	// RefreshDelegatedToken refreshes a delegated access token with user context
	RefreshDelegatedToken(ctx context.Context, refreshToken string, userContext *UserContext) (*AccessToken, error)

	// IsTokenValid checks if a token is still valid
	IsTokenValid(token *AccessToken) bool

	// ValidatePermissions checks if the token has the required permissions for an operation
	ValidatePermissions(ctx context.Context, token *AccessToken, requiredScopes []string) error
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

	// IsDelegated indicates if this token was obtained via delegated permissions
	IsDelegated bool `json:"is_delegated,omitempty"`

	// UserContext contains user information for delegated tokens
	UserContext *UserContext `json:"user_context,omitempty"`

	// GrantedScopes contains the actual scopes granted (may differ from requested)
	GrantedScopes []string `json:"granted_scopes,omitempty"`
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

// UserContext represents user information for delegated permissions
type UserContext struct {
	// UserID is the unique identifier for the user
	UserID string `json:"user_id"`

	// UserPrincipalName is the user's UPN
	UserPrincipalName string `json:"user_principal_name"`

	// DisplayName is the user's display name
	DisplayName string `json:"display_name,omitempty"`

	// Roles contains the user's directory roles
	Roles []string `json:"roles,omitempty"`

	// LastAuthenticated is when the user last authenticated
	LastAuthenticated time.Time `json:"last_authenticated,omitempty"`

	// SessionID tracks the user's authentication session
	SessionID string `json:"session_id,omitempty"`
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

	// DelegatedScopes to request for delegated permissions
	DelegatedScopes []string `yaml:"delegated_scopes,omitempty"`

	// RedirectURI for authorization code flow (for interactive flows)
	RedirectURI string `yaml:"redirect_uri,omitempty"`

	// AuthorityURL is the Azure AD authority URL
	AuthorityURL string `yaml:"authority_url,omitempty"`

	// UseClientCredentials determines if we use client credentials flow
	UseClientCredentials bool `yaml:"use_client_credentials"`

	// SupportDelegatedAuth enables delegated authentication support
	SupportDelegatedAuth bool `yaml:"support_delegated_auth,omitempty"`

	// FallbackToAppPermissions allows falling back to application permissions
	FallbackToAppPermissions bool `yaml:"fallback_to_app_permissions,omitempty"`

	// RequiredDelegatedScopes are the minimum scopes needed for delegated operations
	RequiredDelegatedScopes []string `yaml:"required_delegated_scopes,omitempty"`
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
	return strings.Join(c.Scopes, " ")
}

// GetDelegatedScopeString returns delegated scopes as a space-separated string
func (c *OAuth2Config) GetDelegatedScopeString() string {
	if len(c.DelegatedScopes) == 0 {
		// Default delegated scopes for user operations
		return "User.Read User.ReadWrite.All Group.ReadWrite.All Directory.ReadWrite.All Policy.ReadWrite.ConditionalAccess DeviceManagementConfiguration.ReadWrite.All"
	}
	return strings.Join(c.DelegatedScopes, " ")
}

// SupportsDelegatedAuth checks if delegated authentication is configured
func (c *OAuth2Config) SupportsDelegatedAuth() bool {
	return c.SupportDelegatedAuth && c.RedirectURI != ""
}

// GetRequiredDelegatedScopes returns the minimum required scopes for delegated access
func (c *OAuth2Config) GetRequiredDelegatedScopes() []string {
	if len(c.RequiredDelegatedScopes) > 0 {
		return c.RequiredDelegatedScopes
	}
	// Default minimum scopes
	return []string{"User.Read", "Directory.Read.All"}
}

// CredentialStore defines the interface for secure credential storage
type CredentialStore interface {
	// StoreToken securely stores an access token
	StoreToken(tenantID string, token *AccessToken) error

	// GetToken retrieves a stored access token
	GetToken(tenantID string) (*AccessToken, error)

	// DeleteToken removes a stored access token
	DeleteToken(tenantID string) error

	// StoreDelegatedToken securely stores a delegated access token for a specific user
	StoreDelegatedToken(tenantID string, userID string, token *AccessToken) error

	// GetDelegatedToken retrieves a stored delegated access token for a specific user
	GetDelegatedToken(tenantID string, userID string) (*AccessToken, error)

	// DeleteDelegatedToken removes a stored delegated access token for a specific user
	DeleteDelegatedToken(tenantID string, userID string) error

	// StoreUserContext securely stores user context information
	StoreUserContext(tenantID string, userID string, context *UserContext) error

	// GetUserContext retrieves stored user context information
	GetUserContext(tenantID string, userID string) (*UserContext, error)

	// DeleteUserContext removes stored user context information
	DeleteUserContext(tenantID string, userID string) error

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
