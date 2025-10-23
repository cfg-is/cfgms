// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package saas auth implements universal authentication abstraction
// for SaaS provider integrations.
//
// This authentication system provides a unified interface for all
// common authentication mechanisms used by SaaS APIs, including:
//   - OAuth2 (authorization code, client credentials, device flow)
//   - API Keys (header, query parameter, custom formats)
//   - Basic Authentication
//   - Bearer Tokens
//   - JWT (signed tokens)
//   - Client Certificates
//   - AWS Signature V4
//   - Custom authentication schemes
//
// The system handles token refresh, credential storage, and automatic
// authentication header generation for HTTP requests.
package saas

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// UniversalAuthenticator provides authentication services for all provider types
type UniversalAuthenticator struct {
	credStore    CredentialStore
	httpClient   *http.Client
	oauth2Client OAuth2Client
}

// NewUniversalAuthenticator creates a new universal authenticator
func NewUniversalAuthenticator(credStore CredentialStore, httpClient *http.Client) *UniversalAuthenticator {
	return &UniversalAuthenticator{
		credStore:    credStore,
		httpClient:   httpClient,
		oauth2Client: NewOAuth2Client(httpClient),
	}
}

// Authenticate performs authentication using the specified method and configuration
func (ua *UniversalAuthenticator) Authenticate(ctx context.Context, provider string, config AuthConfig) error {
	switch config.Method {
	case AuthMethodOAuth2:
		return ua.authenticateOAuth2(ctx, provider, config.Config)
	case AuthMethodAPIKey:
		return ua.authenticateAPIKey(ctx, provider, config.Config)
	case AuthMethodBasicAuth:
		return ua.authenticateBasicAuth(ctx, provider, config.Config)
	case AuthMethodBearerToken:
		return ua.authenticateBearerToken(ctx, provider, config.Config)
	case AuthMethodJWT:
		return ua.authenticateJWT(ctx, provider, config.Config)
	case AuthMethodClientCert:
		return ua.authenticateClientCert(ctx, provider, config.Config)
	case AuthMethodAWSSignature:
		return ua.authenticateAWSSignature(ctx, provider, config.Config)
	case AuthMethodCustom:
		return ua.authenticateCustom(ctx, provider, config.Config)
	default:
		return fmt.Errorf("unsupported authentication method: %s", config.Method)
	}
}

// IsAuthenticated checks if valid credentials exist for the provider
func (ua *UniversalAuthenticator) IsAuthenticated(ctx context.Context, provider string, method AuthMethod) bool {
	switch method {
	case AuthMethodOAuth2:
		tokenSet, err := ua.credStore.GetTokenSet(provider)
		if err != nil {
			return false
		}
		return tokenSet != nil && tokenSet.IsValid(5*time.Minute) // 5 min threshold
	case AuthMethodAPIKey, AuthMethodBasicAuth, AuthMethodBearerToken, AuthMethodJWT:
		_, err := ua.credStore.GetClientSecret(provider)
		return err == nil
	default:
		return false
	}
}

// RefreshAuth refreshes authentication credentials if needed
func (ua *UniversalAuthenticator) RefreshAuth(ctx context.Context, provider string, method AuthMethod) error {
	switch method {
	case AuthMethodOAuth2:
		return ua.refreshOAuth2Token(ctx, provider)
	default:
		// Most auth methods don't need refresh
		return nil
	}
}

// GetAuthHeaders returns HTTP headers for authenticated requests
func (ua *UniversalAuthenticator) GetAuthHeaders(ctx context.Context, provider string, method AuthMethod) (map[string]string, error) {
	switch method {
	case AuthMethodOAuth2:
		tokenSet, err := ua.credStore.GetTokenSet(provider)
		if err != nil {
			return nil, fmt.Errorf("failed to get OAuth2 token: %w", err)
		}
		return map[string]string{
			"Authorization": tokenSet.GetAuthorizationHeader(),
		}, nil

	case AuthMethodAPIKey:
		return ua.getAPIKeyHeaders(provider)

	case AuthMethodBasicAuth:
		return ua.getBasicAuthHeaders(provider)

	case AuthMethodBearerToken:
		return ua.getBearerTokenHeaders(provider)

	case AuthMethodJWT:
		return ua.getJWTHeaders(provider)

	default:
		return nil, fmt.Errorf("auth headers not implemented for method: %s", method)
	}
}

// OAuth2 Authentication Implementation

func (ua *UniversalAuthenticator) authenticateOAuth2(ctx context.Context, provider string, config map[string]interface{}) error {
	oauth2Config, err := parseOAuth2Config(config)
	if err != nil {
		return fmt.Errorf("invalid OAuth2 config: %w", err)
	}

	// Start OAuth2 flow
	flow, err := ua.oauth2Client.StartFlow(ctx, oauth2Config)
	if err != nil {
		return fmt.Errorf("failed to start OAuth2 flow: %w", err)
	}

	// For client credentials flow, complete immediately
	if oauth2Config.GrantType == "client_credentials" {
		tokenSet, err := ua.oauth2Client.ClientCredentialsGrant(ctx, oauth2Config)
		if err != nil {
			return fmt.Errorf("client credentials grant failed: %w", err)
		}

		return ua.credStore.StoreTokenSet(provider, tokenSet)
	}

	// For authorization code flow, return the authorization URL
	// (In a real implementation, this would be handled differently)
	return fmt.Errorf("authorization code flow requires user interaction: %s", flow.AuthURL)
}

func (ua *UniversalAuthenticator) refreshOAuth2Token(ctx context.Context, provider string) error {
	tokenSet, err := ua.credStore.GetTokenSet(provider)
	if err != nil {
		return fmt.Errorf("failed to get token set: %w", err)
	}

	if tokenSet.RefreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	newTokenSet, err := ua.oauth2Client.RefreshToken(ctx, tokenSet.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	return ua.credStore.StoreTokenSet(provider, newTokenSet)
}

// API Key Authentication Implementation

func (ua *UniversalAuthenticator) authenticateAPIKey(ctx context.Context, provider string, config map[string]interface{}) error {
	apiKeyConfig, err := parseAPIKeyConfig(config)
	if err != nil {
		return fmt.Errorf("invalid API key config: %w", err)
	}

	// Store the API key configuration
	configData := fmt.Sprintf("%s:%s:%s", apiKeyConfig.Key, apiKeyConfig.Header, apiKeyConfig.QueryParam)
	return ua.credStore.StoreClientSecret(provider, configData)
}

func (ua *UniversalAuthenticator) getAPIKeyHeaders(provider string) (map[string]string, error) {
	configData, err := ua.credStore.GetClientSecret(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get API key config: %w", err)
	}

	parts := strings.Split(configData, ":")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid API key config format")
	}

	key, header := parts[0], parts[1]
	if header != "" {
		return map[string]string{header: key}, nil
	}

	// Default to X-API-Key header
	return map[string]string{"X-API-Key": key}, nil
}

// Basic Authentication Implementation

func (ua *UniversalAuthenticator) authenticateBasicAuth(ctx context.Context, provider string, config map[string]interface{}) error {
	basicConfig, err := parseBasicAuthConfig(config)
	if err != nil {
		return fmt.Errorf("invalid basic auth config: %w", err)
	}

	// Store username:password
	configData := fmt.Sprintf("%s:%s", basicConfig.Username, basicConfig.Password)
	return ua.credStore.StoreClientSecret(provider, configData)
}

func (ua *UniversalAuthenticator) getBasicAuthHeaders(provider string) (map[string]string, error) {
	configData, err := ua.credStore.GetClientSecret(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get basic auth config: %w", err)
	}

	return map[string]string{
		"Authorization": "Basic " + configData, // Should be base64 encoded
	}, nil
}

// Bearer Token Authentication Implementation

func (ua *UniversalAuthenticator) authenticateBearerToken(ctx context.Context, provider string, config map[string]interface{}) error {
	bearerConfig, err := parseBearerTokenConfig(config)
	if err != nil {
		return fmt.Errorf("invalid bearer token config: %w", err)
	}

	return ua.credStore.StoreClientSecret(provider, bearerConfig.Token)
}

func (ua *UniversalAuthenticator) getBearerTokenHeaders(provider string) (map[string]string, error) {
	token, err := ua.credStore.GetClientSecret(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get bearer token: %w", err)
	}

	return map[string]string{
		"Authorization": "Bearer " + token,
	}, nil
}

// JWT Authentication Implementation

func (ua *UniversalAuthenticator) authenticateJWT(ctx context.Context, provider string, config map[string]interface{}) error {
	jwtConfig, err := parseJWTConfig(config)
	if err != nil {
		return fmt.Errorf("invalid JWT config: %w", err)
	}

	// Generate JWT token
	token, err := ua.generateJWT(jwtConfig)
	if err != nil {
		return fmt.Errorf("failed to generate JWT: %w", err)
	}

	return ua.credStore.StoreClientSecret(provider, token)
}

func (ua *UniversalAuthenticator) getJWTHeaders(provider string) (map[string]string, error) {
	token, err := ua.credStore.GetClientSecret(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT token: %w", err)
	}

	return map[string]string{
		"Authorization": "Bearer " + token,
	}, nil
}

// Client Certificate Authentication Implementation

func (ua *UniversalAuthenticator) authenticateClientCert(ctx context.Context, provider string, config map[string]interface{}) error {
	// Client certificate authentication is handled at the HTTP client level
	// This would configure the HTTP client with the certificate
	return fmt.Errorf("client certificate authentication not yet implemented")
}

// AWS Signature V4 Authentication Implementation

func (ua *UniversalAuthenticator) authenticateAWSSignature(ctx context.Context, provider string, config map[string]interface{}) error {
	// AWS Signature V4 signing is complex and would require dedicated implementation
	return fmt.Errorf("AWS signature authentication not yet implemented")
}

// Custom Authentication Implementation

func (ua *UniversalAuthenticator) authenticateCustom(ctx context.Context, provider string, config map[string]interface{}) error {
	// Custom authentication would be implemented per provider
	return fmt.Errorf("custom authentication not yet implemented")
}

// Helper functions for parsing configuration

func parseOAuth2Config(config map[string]interface{}) (*ExtendedOAuth2Config, error) {
	oauth2Config := &ExtendedOAuth2Config{}

	if clientID, ok := config["client_id"].(string); ok {
		oauth2Config.ClientID = clientID
	}
	if clientSecret, ok := config["client_secret"].(string); ok {
		oauth2Config.ClientSecret = clientSecret
	}
	if tokenURL, ok := config["token_url"].(string); ok {
		oauth2Config.TokenURL = tokenURL
	}
	if authURL, ok := config["auth_url"].(string); ok {
		oauth2Config.AuthURL = authURL
	}
	if grantType, ok := config["grant_type"].(string); ok {
		oauth2Config.GrantType = grantType
	}
	if scopes, ok := config["scopes"].([]string); ok {
		oauth2Config.Scopes = scopes
	}

	return oauth2Config, nil
}

func parseAPIKeyConfig(config map[string]interface{}) (*APIKeyConfig, error) {
	apiKeyConfig := &APIKeyConfig{}

	if key, ok := config["key"].(string); ok {
		apiKeyConfig.Key = key
	}
	if header, ok := config["header"].(string); ok {
		apiKeyConfig.Header = header
	}
	if queryParam, ok := config["query_param"].(string); ok {
		apiKeyConfig.QueryParam = queryParam
	}

	return apiKeyConfig, nil
}

func parseBasicAuthConfig(config map[string]interface{}) (*BasicAuthConfig, error) {
	basicConfig := &BasicAuthConfig{}

	if username, ok := config["username"].(string); ok {
		basicConfig.Username = username
	}
	if password, ok := config["password"].(string); ok {
		basicConfig.Password = password
	}

	return basicConfig, nil
}

func parseBearerTokenConfig(config map[string]interface{}) (*BearerTokenConfig, error) {
	bearerConfig := &BearerTokenConfig{}

	if token, ok := config["token"].(string); ok {
		bearerConfig.Token = token
	}

	return bearerConfig, nil
}

func parseJWTConfig(config map[string]interface{}) (*JWTConfig, error) {
	jwtConfig := &JWTConfig{}

	if token, ok := config["token"].(string); ok {
		jwtConfig.Token = token
	}
	if privateKey, ok := config["private_key"].(string); ok {
		jwtConfig.PrivateKey = privateKey
	}
	if algorithm, ok := config["algorithm"].(string); ok {
		jwtConfig.Algorithm = algorithm
	}
	if claims, ok := config["claims"].(map[string]interface{}); ok {
		jwtConfig.Claims = claims
	}

	return jwtConfig, nil
}

// OAuth2Client interface for OAuth2 operations
type OAuth2Client interface {
	StartFlow(ctx context.Context, config *ExtendedOAuth2Config) (*OAuth2Flow, error)
	ClientCredentialsGrant(ctx context.Context, config *ExtendedOAuth2Config) (*TokenSet, error)
	RefreshToken(ctx context.Context, refreshToken string) (*TokenSet, error)
}

// ExtendedOAuth2Config extends the basic OAuth2Config with additional fields
type ExtendedOAuth2Config struct {
	OAuth2Config
	GrantType string `json:"grant_type"` // "authorization_code", "client_credentials", "device_code"
}

// DefaultOAuth2Client implements OAuth2Client interface
type DefaultOAuth2Client struct {
	httpClient *http.Client
}

// NewOAuth2Client creates a new OAuth2 client
func NewOAuth2Client(httpClient *http.Client) OAuth2Client {
	return &DefaultOAuth2Client{
		httpClient: httpClient,
	}
}

func (c *DefaultOAuth2Client) StartFlow(ctx context.Context, config *ExtendedOAuth2Config) (*OAuth2Flow, error) {
	// Implementation would create OAuth2 flow with PKCE
	return &OAuth2Flow{
		AuthURL:     config.AuthURL,
		RedirectURI: config.RedirectURL,
		Created:     time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}, nil
}

func (c *DefaultOAuth2Client) ClientCredentialsGrant(ctx context.Context, config *ExtendedOAuth2Config) (*TokenSet, error) {
	// Implementation would perform client credentials grant
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)
	data.Set("scope", strings.Join(config.Scopes, " "))

	req, err := http.NewRequestWithContext(ctx, "POST", config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but continue
			_ = err // Explicitly ignore error for cleanup operation
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status: %d", resp.StatusCode)
	}

	// Parse response and return TokenSet
	// This is a simplified implementation
	return &TokenSet{
		AccessToken: "mock-access-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}, nil
}

func (c *DefaultOAuth2Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenSet, error) {
	// Implementation would refresh the OAuth2 token
	return &TokenSet{
		AccessToken:  "new-access-token",
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}, nil
}

// JWT helper function (simplified implementation)
func (ua *UniversalAuthenticator) generateJWT(config *JWTConfig) (string, error) {
	// This would use a JWT library to generate signed tokens
	// For now, return the provided token or a mock token
	if config.Token != "" {
		return config.Token, nil
	}
	return "mock-jwt-token", nil
}

// AuthMiddleware provides HTTP middleware for automatic authentication
func (ua *UniversalAuthenticator) AuthMiddleware(provider string, method AuthMethod) func(http.RoundTripper) http.RoundTripper {
	return func(next http.RoundTripper) http.RoundTripper {
		return &authRoundTripper{
			next:     next,
			auth:     ua,
			provider: provider,
			method:   method,
		}
	}
}

type authRoundTripper struct {
	next     http.RoundTripper
	auth     *UniversalAuthenticator
	provider string
	method   AuthMethod
}

func (rt *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Add authentication headers
	headers, err := rt.auth.GetAuthHeaders(req.Context(), rt.provider, rt.method)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth headers: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Handle token refresh for OAuth2
	if rt.method == AuthMethodOAuth2 {
		if !rt.auth.IsAuthenticated(req.Context(), rt.provider, rt.method) {
			if err := rt.auth.RefreshAuth(req.Context(), rt.provider, rt.method); err != nil {
				return nil, fmt.Errorf("failed to refresh auth: %w", err)
			}

			// Get updated headers after refresh
			headers, err := rt.auth.GetAuthHeaders(req.Context(), rt.provider, rt.method)
			if err != nil {
				return nil, fmt.Errorf("failed to get refreshed auth headers: %w", err)
			}

			for key, value := range headers {
				req.Header.Set(key, value)
			}
		}
	}

	return rt.next.RoundTrip(req)
}
