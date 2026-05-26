// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/cache"
	"github.com/cfgis/cfgms/pkg/logging"
)

// OAuth2Provider implements the Provider interface using OAuth2 client credentials flow
type OAuth2Provider struct {
	// HTTP client for making requests
	httpClient *http.Client

	// Configuration storage
	credentialStore CredentialStore

	// Token cache to avoid unnecessary requests (for application tokens)
	tokenCache *cache.Cache

	// Delegated token cache for user-specific tokens
	delegatedTokenCache *cache.Cache

	// Default configuration for new tenants
	defaultConfig *OAuth2Config

	logger logging.Logger
}

// NewOAuth2Provider creates a new OAuth2Provider instance
func NewOAuth2Provider(credentialStore CredentialStore, defaultConfig *OAuth2Config, logger logging.Logger) *OAuth2Provider {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	return &OAuth2Provider{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		credentialStore: credentialStore,
		tokenCache: cache.NewCache(cache.CacheConfig{
			Name:            "m365-token",
			DefaultTTL:      55 * time.Minute,
			CleanupInterval: 1 * time.Minute,
		}),
		delegatedTokenCache: cache.NewCache(cache.CacheConfig{
			Name:            "m365-delegated-token",
			DefaultTTL:      55 * time.Minute,
			CleanupInterval: 1 * time.Minute,
		}),
		defaultConfig: defaultConfig,
		logger:        logger,
	}
}

// GetAccessToken retrieves a valid access token for the specified tenant
func (p *OAuth2Provider) GetAccessToken(ctx context.Context, tenantID string) (*AccessToken, error) {
	// Check cache first
	if token := p.getCachedToken(tenantID); token != nil && !token.IsExpired() {
		return token, nil
	}

	// Get OAuth2 configuration for the tenant
	config, err := p.getOAuth2Config(tenantID)
	if err != nil {
		return nil, NewAuthenticationError(tenantID, "CONFIG_ERROR", "Failed to get OAuth2 configuration", err)
	}

	// Try to get stored token first
	storedToken, err := p.credentialStore.GetToken(tenantID)
	if err == nil && storedToken != nil && !storedToken.IsExpired() {
		p.setCachedToken(tenantID, storedToken)
		return storedToken, nil
	}

	// If stored token is expired or doesn't exist, get a new one
	var token *AccessToken
	if config.UseClientCredentials {
		token, err = p.getClientCredentialsToken(ctx, config)
	} else {
		// Design decision: interactive refresh requires a stored refresh token; callers must call RefreshToken explicitly when a refresh token is available.
		if storedToken != nil && storedToken.RefreshToken != "" {
			token, err = p.RefreshToken(ctx, storedToken.RefreshToken)
		} else {
			return nil, NewAuthenticationError(tenantID, "NO_REFRESH_TOKEN",
				"No valid refresh token available for interactive flow", nil)
		}
	}

	if err != nil {
		return nil, err
	}

	// Store the new token
	if err := p.credentialStore.StoreToken(tenantID, token); err != nil {
		// Log warning but don't fail - we can still return the token
		p.logger.Warn("failed to store token", "tenant_id", logging.SanitizeLogValue(tenantID), "error", err)
	}

	// Cache the token
	p.setCachedToken(tenantID, token)

	return token, nil
}

// GetDelegatedAccessToken retrieves a valid delegated access token for the specified user
func (p *OAuth2Provider) GetDelegatedAccessToken(ctx context.Context, tenantID string, userContext *UserContext) (*AccessToken, error) {
	if userContext == nil {
		return nil, NewAuthenticationError(tenantID, "INVALID_USER_CONTEXT", "User context is required for delegated access", nil)
	}

	// Generate cache key for user-specific token
	cacheKey := fmt.Sprintf("%s:%s", tenantID, userContext.UserID)

	// Check delegated cache first
	if token := p.getDelegatedCachedToken(cacheKey); token != nil && !token.IsExpired() {
		return token, nil
	}

	// Get OAuth2 configuration for the tenant
	config, err := p.getOAuth2Config(tenantID)
	if err != nil {
		return nil, NewAuthenticationError(tenantID, "CONFIG_ERROR", "Failed to get OAuth2 configuration", err)
	}

	// Check if delegated auth is supported
	if !config.SupportsDelegatedAuth() {
		if config.FallbackToAppPermissions {
			// Fall back to application permissions
			return p.GetAccessToken(ctx, tenantID)
		}
		return nil, NewAuthenticationError(tenantID, "DELEGATED_NOT_SUPPORTED",
			"Delegated authentication not configured for this tenant", nil)
	}

	// Try to get stored delegated token first
	storedToken, err := p.credentialStore.GetDelegatedToken(tenantID, userContext.UserID)
	if err == nil && storedToken != nil && !storedToken.IsExpired() {
		p.setDelegatedCachedToken(cacheKey, storedToken)
		return storedToken, nil
	}

	// If stored token is expired or doesn't exist, try to refresh it
	if storedToken != nil && storedToken.RefreshToken != "" {
		token, err := p.RefreshDelegatedToken(ctx, storedToken.RefreshToken, userContext)
		if err != nil {
			// If refresh fails and fallback is enabled, use app permissions
			if config.FallbackToAppPermissions {
				return p.GetAccessToken(ctx, tenantID)
			}
			return nil, err
		}
		return token, nil
	}

	// Design decision: delegated token path falls back to app permissions when FallbackToAppPermissions is set; interactive auth requires browser redirect which is architecturally incompatible with a daemon/service context.
	if config.FallbackToAppPermissions {
		return p.GetAccessToken(ctx, tenantID)
	}

	return nil, NewAuthenticationError(tenantID, "NO_DELEGATED_TOKEN",
		"No valid delegated token available; interactive authentication requires browser redirect", nil)
}

// RefreshToken refreshes an existing access token using a refresh token
func (p *OAuth2Provider) RefreshToken(ctx context.Context, refreshToken string) (*AccessToken, error) {
	// Design decision: tenant ID is not encoded in the refresh token; callers must pass it via context.
	// Deferred: tracked in #1443 — propagate tenant ID through refresh token context
	tenantID := "unknown" // Would need to be determined from context

	config, err := p.getOAuth2Config(tenantID)
	if err != nil {
		return nil, NewAuthenticationError(tenantID, "CONFIG_ERROR", "Failed to get OAuth2 configuration", err)
	}

	// Prepare refresh token request
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {config.ClientID},
		"scope":         {config.GetScopeString()},
	}

	// Add client secret if available (for confidential clients)
	if config.ClientSecret != "" {
		data.Set("client_secret", config.ClientSecret)
	}

	// Make the token request
	token, err := p.makeTokenRequest(ctx, config.GetTokenURL(), data)
	if err != nil {
		return nil, NewAuthenticationError(tenantID, "REFRESH_FAILED", "Failed to refresh token", err)
	}

	token.TenantID = tenantID
	return token, nil
}

// RefreshDelegatedToken refreshes a delegated access token with user context
func (p *OAuth2Provider) RefreshDelegatedToken(ctx context.Context, refreshToken string, userContext *UserContext) (*AccessToken, error) {
	if userContext == nil {
		return nil, NewAuthenticationError("unknown", "INVALID_USER_CONTEXT", "User context is required for delegated token refresh", nil)
	}

	// Design decision: tenant ID tracking for refresh token context requires the Provider interface to
	// accept tenantID explicitly in RefreshDelegatedToken. Until then, tenant ID resolution relies on
	// the credential store lookup keyed by UserContext.UserID; callers must ensure UserID maps to a
	// stored tenant configuration.
	tenantID := userContext.UserID

	config, err := p.getOAuth2Config(tenantID)
	if err != nil {
		return nil, NewAuthenticationError(tenantID, "CONFIG_ERROR", "Failed to get OAuth2 configuration", err)
	}

	// Prepare delegated refresh token request
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {config.ClientID},
		"scope":         {config.GetDelegatedScopeString()},
	}

	// Add client secret if available (for confidential clients)
	if config.ClientSecret != "" {
		data.Set("client_secret", config.ClientSecret)
	}

	// Make the token request
	token, err := p.makeTokenRequest(ctx, config.GetTokenURL(), data)
	if err != nil {
		return nil, NewAuthenticationError(tenantID, "DELEGATED_REFRESH_FAILED", "Failed to refresh delegated token", err)
	}

	// Set delegated token properties
	token.TenantID = tenantID
	token.IsDelegated = true
	token.UserContext = userContext

	// Parse granted scopes from response
	if token.Scope != "" {
		token.GrantedScopes = strings.Fields(token.Scope)
	}

	// Update user context with current authentication time
	userContext.LastAuthenticated = time.Now()

	// Store the refreshed token
	if err := p.credentialStore.StoreDelegatedToken(tenantID, userContext.UserID, token); err != nil {
		// Log warning but don't fail
		p.logger.Warn("failed to store delegated token",
			"user_id", logging.SanitizeLogValue(userContext.UserID),
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", err)
	}

	// Store updated user context
	if err := p.credentialStore.StoreUserContext(tenantID, userContext.UserID, userContext); err != nil {
		p.logger.Warn("failed to store user context",
			"user_id", logging.SanitizeLogValue(userContext.UserID),
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", err)
	}

	// Cache the token
	cacheKey := fmt.Sprintf("%s:%s", tenantID, userContext.UserID)
	p.setDelegatedCachedToken(cacheKey, token)

	return token, nil
}

// IsTokenValid checks if a token is still valid
func (p *OAuth2Provider) IsTokenValid(token *AccessToken) bool {
	return token != nil && !token.IsExpired()
}

// ValidatePermissions checks if the token has the required permissions for an operation
func (p *OAuth2Provider) ValidatePermissions(ctx context.Context, token *AccessToken, requiredScopes []string) error {
	if token == nil {
		return fmt.Errorf("token is nil")
	}

	// If no specific scopes are required, any valid token is acceptable
	if len(requiredScopes) == 0 {
		return nil
	}

	// For application permissions, we assume all configured scopes are available
	if !token.IsDelegated {
		return nil
	}

	// For delegated permissions, check granted scopes
	if len(token.GrantedScopes) == 0 {
		// If granted scopes are not tracked, we can't validate
		// Fall back to making a test request to Microsoft Graph
		return p.validatePermissionsByRequest(ctx, token, requiredScopes)
	}

	// Check if all required scopes are in the granted scopes
	grantedScopeSet := make(map[string]bool)
	for _, scope := range token.GrantedScopes {
		grantedScopeSet[scope] = true
	}

	var missingScopes []string
	for _, required := range requiredScopes {
		if !grantedScopeSet[required] {
			missingScopes = append(missingScopes, required)
		}
	}

	if len(missingScopes) > 0 {
		return NewAuthenticationError(token.TenantID, "INSUFFICIENT_PERMISSIONS",
			fmt.Sprintf("Token missing required scopes: %v", missingScopes), nil)
	}

	return nil
}

// validatePermissionsByRequest validates permissions by making a test request
func (p *OAuth2Provider) validatePermissionsByRequest(ctx context.Context, token *AccessToken, requiredScopes []string) error {
	// Make different test requests based on required scopes
	for _, scope := range requiredScopes {
		if err := p.testScopeAccess(ctx, token, scope); err != nil {
			return NewAuthenticationError(token.TenantID, "INSUFFICIENT_PERMISSIONS",
				fmt.Sprintf("Token lacks permission for scope: %s", scope), err)
		}
	}
	return nil
}

// testScopeAccess tests if a token has access to a specific scope
func (p *OAuth2Provider) testScopeAccess(ctx context.Context, token *AccessToken, scope string) error {
	var testURL string

	// Map scopes to test endpoints
	switch scope {
	case "User.Read":
		testURL = "https://graph.microsoft.com/v1.0/me"
	case "User.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All":
		testURL = "https://graph.microsoft.com/v1.0/users?$top=1"
	case "Group.Read.All", "Group.ReadWrite.All":
		testURL = "https://graph.microsoft.com/v1.0/groups?$top=1"
	case "Policy.ReadWrite.ConditionalAccess":
		testURL = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=1"
	case "DeviceManagementConfiguration.ReadWrite.All":
		testURL = "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?$top=1"
	default:
		// For unknown scopes, assume valid
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create test request: %w", err)
	}

	req.Header.Set("Authorization", token.GetAuthorizationHeader())
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make test request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but continue
			_ = err
		}
	}()

	// Check if the request succeeded
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("access denied for scope %s", scope)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("test request failed with status %d", resp.StatusCode)
	}

	return nil
}

// getClientCredentialsToken obtains a new access token using client credentials flow
func (p *OAuth2Provider) getClientCredentialsToken(ctx context.Context, config *OAuth2Config) (*AccessToken, error) {
	// Prepare client credentials request
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {config.ClientID},
		"client_secret": {config.ClientSecret},
		"scope":         {config.GetScopeString()},
	}

	// Make the token request
	token, err := p.makeTokenRequest(ctx, config.GetTokenURL(), data)
	if err != nil {
		return nil, NewAuthenticationError(config.TenantID, "CLIENT_CREDENTIALS_FAILED",
			"Failed to obtain client credentials token", err)
	}

	token.TenantID = config.TenantID
	return token, nil
}

// makeTokenRequest makes an OAuth2 token request to the specified endpoint
func (p *OAuth2Provider) makeTokenRequest(ctx context.Context, tokenURL string, data url.Values) (*AccessToken, error) {
	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "CFGMS-SaaS-Steward/1.0")

	// Make the request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make token request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but continue
			_ = err // Explicitly ignore error for cleanup operation
		}
	}()

	// Parse response
	var tokenResponse struct {
		AccessToken      string `json:"access_token"`
		TokenType        string `json:"token_type"`
		ExpiresIn        int    `json:"expires_in"`
		RefreshToken     string `json:"refresh_token,omitempty"`
		Scope            string `json:"scope,omitempty"`
		Error            string `json:"error,omitempty"`
		ErrorDescription string `json:"error_description,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	// Check for OAuth2 errors
	if tokenResponse.Error != "" {
		return nil, fmt.Errorf("OAuth2 error: %s - %s", tokenResponse.Error, tokenResponse.ErrorDescription)
	}

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d", resp.StatusCode)
	}

	// Create AccessToken
	token := &AccessToken{
		Token:        tokenResponse.AccessToken,
		TokenType:    tokenResponse.TokenType,
		ExpiresIn:    tokenResponse.ExpiresIn,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second),
		RefreshToken: tokenResponse.RefreshToken,
		Scope:        tokenResponse.Scope,
	}

	// Default token type if not specified
	if token.TokenType == "" {
		token.TokenType = "Bearer"
	}

	return token, nil
}

// getOAuth2Config retrieves OAuth2 configuration for a tenant
func (p *OAuth2Provider) getOAuth2Config(tenantID string) (*OAuth2Config, error) {
	// Try to get stored configuration first
	if p.credentialStore != nil {
		if config, err := p.credentialStore.GetConfig(tenantID); err == nil && config != nil {
			return config, nil
		}
	}

	// Fall back to default configuration if available
	if p.defaultConfig != nil {
		// Create a copy with the specific tenant ID
		config := *p.defaultConfig
		config.TenantID = tenantID
		return &config, nil
	}

	return nil, fmt.Errorf("no OAuth2 configuration found for tenant %s", tenantID)
}

// getCachedToken retrieves a token from the cache
func (p *OAuth2Provider) getCachedToken(tenantID string) *AccessToken {
	value, found := p.tokenCache.Get(tenantID)
	if !found {
		return nil
	}
	token, ok := value.(*AccessToken)
	if !ok {
		return nil
	}
	return token
}

// setCachedToken stores a token in the cache with a TTL that fires 5 minutes before the token expires.
// If the token is already within the buffer window (TTL ≤ 0) any existing entry is evicted.
func (p *OAuth2Provider) setCachedToken(tenantID string, token *AccessToken) {
	ttl := time.Until(token.ExpiresAt) - 5*time.Minute
	if ttl <= 0 {
		p.logger.Debug("skipping token cache: TTL too short", "tenant_id", logging.SanitizeLogValue(tenantID))
		p.tokenCache.Delete(tenantID)
		return
	}
	_ = p.tokenCache.Set(tenantID, token, ttl)
}

// getDelegatedCachedToken retrieves a delegated token from the cache
func (p *OAuth2Provider) getDelegatedCachedToken(cacheKey string) *AccessToken {
	value, found := p.delegatedTokenCache.Get(cacheKey)
	if !found {
		return nil
	}
	token, ok := value.(*AccessToken)
	if !ok {
		return nil
	}
	return token
}

// setDelegatedCachedToken stores a delegated token in the cache with a TTL that fires 5 minutes before the token expires.
// If the token is already within the buffer window (TTL ≤ 0) any existing entry is evicted.
func (p *OAuth2Provider) setDelegatedCachedToken(cacheKey string, token *AccessToken) {
	ttl := time.Until(token.ExpiresAt) - 5*time.Minute
	if ttl <= 0 {
		p.logger.Debug("skipping delegated token cache: TTL too short", "cache_key", logging.SanitizeLogValue(cacheKey))
		p.delegatedTokenCache.Delete(cacheKey)
		return
	}
	_ = p.delegatedTokenCache.Set(cacheKey, token, ttl)
}

// ClearCache clears the token cache for all tenants
func (p *OAuth2Provider) ClearCache() {
	p.tokenCache.Clear()
}

// ClearDelegatedCache clears the delegated token cache for all users
func (p *OAuth2Provider) ClearDelegatedCache() {
	p.delegatedTokenCache.Clear()
}

// ClearCacheForTenant clears the token cache for a specific tenant
func (p *OAuth2Provider) ClearCacheForTenant(tenantID string) {
	p.tokenCache.Delete(tenantID)
}

// ClearDelegatedCacheForUser clears the delegated token cache for a specific user
func (p *OAuth2Provider) ClearDelegatedCacheForUser(tenantID, userID string) {
	p.delegatedTokenCache.Delete(fmt.Sprintf("%s:%s", tenantID, userID))
}

// ClearDelegatedCacheForTenant clears all delegated tokens for a specific tenant
func (p *OAuth2Provider) ClearDelegatedCacheForTenant(tenantID string) {
	tenantPrefix := tenantID + ":"
	for _, key := range p.delegatedTokenCache.Keys() {
		if strings.HasPrefix(key, tenantPrefix) {
			p.delegatedTokenCache.Delete(key)
		}
	}
}

// Close stops the background cleanup routines for both token caches
func (p *OAuth2Provider) Close() {
	p.tokenCache.Close()
	p.delegatedTokenCache.Close()
}

// SetHTTPClient allows customization of the HTTP client
func (p *OAuth2Provider) SetHTTPClient(client *http.Client) {
	p.httpClient = client
}

// AuthorizeURL generates an authorization URL for interactive OAuth2 flows
func (p *OAuth2Provider) AuthorizeURL(tenantID string, state string, codeChallenge string) (string, error) {
	config, err := p.getOAuth2Config(tenantID)
	if err != nil {
		return "", fmt.Errorf("failed to get OAuth2 configuration: %w", err)
	}

	authorizeURL := fmt.Sprintf("%s/oauth2/v2.0/authorize", config.GetAuthorityURL())

	params := url.Values{
		"client_id":     {config.ClientID},
		"response_type": {"code"},
		"redirect_uri":  {config.RedirectURI},
		"scope":         {config.GetScopeString()},
		"state":         {state},
	}

	// Add PKCE parameters if using PKCE
	if codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	return fmt.Sprintf("%s?%s", authorizeURL, params.Encode()), nil
}

// ExchangeCodeForToken exchanges an authorization code for an access token
func (p *OAuth2Provider) ExchangeCodeForToken(ctx context.Context, tenantID, code, codeVerifier string) (*AccessToken, error) {
	return p.ExchangeCodeForDelegatedToken(ctx, tenantID, code, codeVerifier, nil)
}

// ExchangeCodeForDelegatedToken exchanges an authorization code for a delegated access token with user context
func (p *OAuth2Provider) ExchangeCodeForDelegatedToken(ctx context.Context, tenantID, code, codeVerifier string, userContext *UserContext) (*AccessToken, error) {
	config, err := p.getOAuth2Config(tenantID)
	if err != nil {
		return nil, NewAuthenticationError(tenantID, "CONFIG_ERROR", "Failed to get OAuth2 configuration", err)
	}

	// Prepare authorization code request
	data := url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {config.ClientID},
		"code":         {code},
		"redirect_uri": {config.RedirectURI},
	}

	// Add client secret if available (for confidential clients)
	if config.ClientSecret != "" {
		data.Set("client_secret", config.ClientSecret)
	}

	// Add PKCE code verifier if provided
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	// Make the token request
	token, err := p.makeTokenRequest(ctx, config.GetTokenURL(), data)
	if err != nil {
		return nil, NewAuthenticationError(tenantID, "CODE_EXCHANGE_FAILED",
			"Failed to exchange authorization code for token", err)
	}

	token.TenantID = tenantID

	// If user context is provided, this is a delegated token
	if userContext != nil {
		token.IsDelegated = true
		token.UserContext = userContext

		// Parse granted scopes from response
		if token.Scope != "" {
			token.GrantedScopes = strings.Fields(token.Scope)
		}

		// Update user context with authentication time
		userContext.LastAuthenticated = time.Now()

		// Store as delegated token
		if err := p.credentialStore.StoreDelegatedToken(tenantID, userContext.UserID, token); err != nil {
			p.logger.Warn("failed to store delegated token",
				"user_id", logging.SanitizeLogValue(userContext.UserID),
				"tenant_id", logging.SanitizeLogValue(tenantID),
				"error", err)
		}

		// Store user context
		if err := p.credentialStore.StoreUserContext(tenantID, userContext.UserID, userContext); err != nil {
			p.logger.Warn("failed to store user context",
				"user_id", logging.SanitizeLogValue(userContext.UserID),
				"tenant_id", logging.SanitizeLogValue(tenantID),
				"error", err)
		}

		// Cache as delegated token
		cacheKey := fmt.Sprintf("%s:%s", tenantID, userContext.UserID)
		p.setDelegatedCachedToken(cacheKey, token)
	} else {
		// Store as application token
		if err := p.credentialStore.StoreToken(tenantID, token); err != nil {
			p.logger.Warn("failed to store token", "tenant_id", logging.SanitizeLogValue(tenantID), "error", err)
		}

		// Cache the token
		p.setCachedToken(tenantID, token)
	}

	return token, nil
}

// ValidateToken validates a token by making a test request to Microsoft Graph
func (p *OAuth2Provider) ValidateToken(ctx context.Context, token *AccessToken) error {
	// Make a simple request to Microsoft Graph to validate the token
	req, err := http.NewRequestWithContext(ctx, "GET", "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return fmt.Errorf("failed to create validation request: %w", err)
	}

	req.Header.Set("Authorization", token.GetAuthorizationHeader())
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to validate token: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but continue
			_ = err // Explicitly ignore error for cleanup operation
		}
	}()

	if resp.StatusCode == http.StatusUnauthorized {
		return NewAuthenticationError(token.TenantID, "INVALID_TOKEN", "Token validation failed", nil)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("token validation failed with status %d", resp.StatusCode)
	}

	return nil
}

// GetTenantInfo retrieves tenant information using the provided token
func (p *OAuth2Provider) GetTenantInfo(ctx context.Context, token *AccessToken) (*TenantInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://graph.microsoft.com/v1.0/organization", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create tenant info request: %w", err)
	}

	req.Header.Set("Authorization", token.GetAuthorizationHeader())
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant info: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but continue
			_ = err // Explicitly ignore error for cleanup operation
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tenant info request failed with status %d", resp.StatusCode)
	}

	var response struct {
		Value []struct {
			ID              string `json:"id"`
			DisplayName     string `json:"displayName"`
			VerifiedDomains []struct {
				Name      string `json:"name"`
				IsDefault bool   `json:"isDefault"`
			} `json:"verifiedDomains"`
			CountryLetterCode string `json:"countryLetterCode"`
			PreferredLanguage string `json:"preferredLanguage"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode tenant info response: %w", err)
	}

	if len(response.Value) == 0 {
		return nil, fmt.Errorf("no tenant information found")
	}

	org := response.Value[0]
	tenantInfo := &TenantInfo{
		TenantID:          org.ID,
		DisplayName:       org.DisplayName,
		CountryLetterCode: org.CountryLetterCode,
		PreferredLanguage: org.PreferredLanguage,
	}

	// Extract verified domains
	for _, domain := range org.VerifiedDomains {
		tenantInfo.VerifiedDomains = append(tenantInfo.VerifiedDomains, domain.Name)
		if domain.IsDefault {
			tenantInfo.DefaultDomain = domain.Name
		}
	}

	return tenantInfo, nil
}

// TenantInfo represents information about a Microsoft 365 tenant
type TenantInfo struct {
	TenantID          string   `json:"tenant_id"`
	DisplayName       string   `json:"display_name"`
	DefaultDomain     string   `json:"default_domain"`
	VerifiedDomains   []string `json:"verified_domains"`
	CountryLetterCode string   `json:"country_letter_code"`
	PreferredLanguage string   `json:"preferred_language"`
}
