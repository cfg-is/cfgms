package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuth2Provider implements the Provider interface using OAuth2 client credentials flow
type OAuth2Provider struct {
	// HTTP client for making requests
	httpClient *http.Client
	
	// Configuration storage
	credentialStore CredentialStore
	
	// Token cache to avoid unnecessary requests
	tokenCache map[string]*cachedToken
	cacheMutex sync.RWMutex
	
	// Default configuration for new tenants
	defaultConfig *OAuth2Config
}

// cachedToken represents a cached access token with expiration tracking
type cachedToken struct {
	token     *AccessToken
	expiresAt time.Time
}

// NewOAuth2Provider creates a new OAuth2Provider instance
func NewOAuth2Provider(credentialStore CredentialStore, defaultConfig *OAuth2Config) *OAuth2Provider {
	return &OAuth2Provider{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		credentialStore: credentialStore,
		tokenCache:      make(map[string]*cachedToken),
		defaultConfig:   defaultConfig,
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
		// For interactive flows, we would need a stored refresh token
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
		fmt.Printf("Warning: Failed to store token for tenant %s: %v\n", tenantID, err)
	}
	
	// Cache the token
	p.setCachedToken(tenantID, token)
	
	return token, nil
}

// RefreshToken refreshes an existing access token using a refresh token
func (p *OAuth2Provider) RefreshToken(ctx context.Context, refreshToken string) (*AccessToken, error) {
	// Parse the refresh token to extract tenant information
	// In a real implementation, you might store tenant info with the refresh token
	// For now, we'll assume the refresh token contains or is associated with tenant info
	
	// This is a simplified implementation - in practice, you'd need to track
	// which tenant this refresh token belongs to
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

// IsTokenValid checks if a token is still valid
func (p *OAuth2Provider) IsTokenValid(token *AccessToken) bool {
	return token != nil && !token.IsExpired()
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
	defer resp.Body.Close()
	
	// Parse response
	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token,omitempty"`
		Scope        string `json:"scope,omitempty"`
		Error        string `json:"error,omitempty"`
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
	p.cacheMutex.RLock()
	defer p.cacheMutex.RUnlock()
	
	cached, exists := p.tokenCache[tenantID]
	if !exists {
		return nil
	}
	
	// Check if cached token is still valid (with 5-minute buffer)
	if time.Now().Add(5 * time.Minute).After(cached.expiresAt) {
		return nil
	}
	
	return cached.token
}

// setCachedToken stores a token in the cache
func (p *OAuth2Provider) setCachedToken(tenantID string, token *AccessToken) {
	p.cacheMutex.Lock()
	defer p.cacheMutex.Unlock()
	
	p.tokenCache[tenantID] = &cachedToken{
		token:     token,
		expiresAt: token.ExpiresAt,
	}
}

// ClearCache clears the token cache for all tenants
func (p *OAuth2Provider) ClearCache() {
	p.cacheMutex.Lock()
	defer p.cacheMutex.Unlock()
	
	p.tokenCache = make(map[string]*cachedToken)
}

// ClearCacheForTenant clears the token cache for a specific tenant
func (p *OAuth2Provider) ClearCacheForTenant(tenantID string) {
	p.cacheMutex.Lock()
	defer p.cacheMutex.Unlock()
	
	delete(p.tokenCache, tenantID)
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
	
	// Store the token
	if err := p.credentialStore.StoreToken(tenantID, token); err != nil {
		fmt.Printf("Warning: Failed to store token for tenant %s: %v\n", tenantID, err)
	}
	
	// Cache the token
	p.setCachedToken(tenantID, token)
	
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
	defer resp.Body.Close()
	
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
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tenant info request failed with status %d", resp.StatusCode)
	}
	
	var response struct {
		Value []struct {
			ID                 string   `json:"id"`
			DisplayName        string   `json:"displayName"`
			VerifiedDomains    []struct {
				Name      string `json:"name"`
				IsDefault bool   `json:"isDefault"`
			} `json:"verifiedDomains"`
			CountryLetterCode  string `json:"countryLetterCode"`
			PreferredLanguage  string `json:"preferredLanguage"`
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