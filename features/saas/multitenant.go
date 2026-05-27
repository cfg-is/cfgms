// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package saas multitenant implements multi-tenant consent flows for enterprise
// SaaS applications, enabling MSPs to manage multiple customer tenants through
// a single application registration.
//
// This system implements Microsoft's multi-tenant consent flow pattern which
// can be extended to other providers that support similar enterprise app models.
//
// Key Features:
//   - Admin consent flow using /common endpoint
//   - Automatic tenant discovery after consent
//   - Per-tenant token isolation and management
//   - Consent status tracking and renewal
//   - Integration with existing authentication system
//
// Usage Example:
//
//	manager := NewMultiTenantManager(credStore, NewInMemoryConsentStore(), httpClient, discoverer)
//
//	// Start admin consent flow
//	consentURL, err := manager.StartAdminConsent(ctx, "microsoft", config)
//	// User visits consentURL and grants admin consent
//
//	// Complete consent and discover tenants
//	err = manager.CompleteAdminConsent(ctx, "microsoft", authCode)
//
//	// Access specific tenant
//	token, err := manager.GetTenantToken(ctx, "microsoft", "tenant-id-123")
package saas

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/pkg/logging"
)

// MultiTenantManager handles multi-tenant OAuth2 consent flows and token management
type MultiTenantManager struct {
	credStore        auth.CredentialStore
	consentStore     ConsentStore
	httpClient       *http.Client
	oauth2Client     OAuth2Client
	tenantDiscoverer TenantDiscoverer
	logger           logging.Logger

	cacheExpiry time.Duration
}

// NewMultiTenantManager creates a new multi-tenant manager.
// consentStore persists admin-consent state; pass NewInMemoryConsentStore() for
// pre-production use until a durable implementation is available.
// discoverer performs the actual tenant discovery API call after consent is
// granted; MicrosoftMultiTenantProvider satisfies this interface in production.
func NewMultiTenantManager(credStore auth.CredentialStore, consentStore ConsentStore, httpClient *http.Client, discoverer TenantDiscoverer, logger logging.Logger) *MultiTenantManager {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	return &MultiTenantManager{
		credStore:        credStore,
		consentStore:     consentStore,
		httpClient:       httpClient,
		oauth2Client:     NewOAuth2Client(httpClient, nil),
		tenantDiscoverer: discoverer,
		logger:           logger,
		cacheExpiry:      15 * time.Minute,
	}
}

// MultiTenantConfig extends OAuth2Config with multi-tenant specific settings
type MultiTenantConfig struct {
	OAuth2Config

	// IsMultiTenant indicates this app supports multi-tenant access
	IsMultiTenant bool `json:"is_multi_tenant"`

	// AdminConsentScopes are scopes that require admin consent
	AdminConsentScopes []string `json:"admin_consent_scopes"`

	// TenantDiscoveryEndpoint for discovering accessible tenants
	TenantDiscoveryEndpoint string `json:"tenant_discovery_endpoint"`

	// ConsentPrompt controls consent behavior ("admin_consent", "consent", etc.)
	ConsentPrompt string `json:"consent_prompt"`
}

// ConsentStatus represents the current consent state for a provider
type ConsentStatus struct {
	// Provider name (e.g., "microsoft")
	Provider string `json:"provider"`

	// HasAdminConsent indicates if admin consent has been granted
	HasAdminConsent bool `json:"has_admin_consent"`

	// ConsentGrantedAt when admin consent was first granted
	ConsentGrantedAt time.Time `json:"consent_granted_at"`

	// LastTenantDiscovery when tenants were last discovered
	LastTenantDiscovery time.Time `json:"last_tenant_discovery"`

	// AccessibleTenants list of tenants this app can access
	AccessibleTenants []TenantInfo `json:"accessible_tenants"`

	// ConsentFlow tracks the current consent flow if in progress
	ConsentFlow *OAuth2Flow `json:"consent_flow,omitempty"`
}

// TenantInfo represents a discoverable tenant
type TenantInfo struct {
	// TenantID is the unique tenant identifier
	TenantID string `json:"tenant_id"`

	// DisplayName is the human-readable tenant name
	DisplayName string `json:"display_name"`

	// Domain is the primary domain for this tenant
	Domain string `json:"domain"`

	// CountryCode indicates tenant's country/region
	CountryCode string `json:"country_code,omitempty"`

	// TenantType indicates tenant type ("AAD", "B2C", etc.)
	TenantType string `json:"tenant_type,omitempty"`

	// HasAccess indicates if the app has been granted access to this tenant
	HasAccess bool `json:"has_access"`

	// LastTokenRefresh when tokens were last refreshed for this tenant
	LastTokenRefresh time.Time `json:"last_token_refresh,omitempty"`
}

// TenantDiscoveryResult contains results from tenant discovery
type TenantDiscoveryResult struct {
	// Tenants discovered during the process
	Tenants []TenantInfo `json:"tenants"`

	// DiscoveredAt when this discovery was performed
	DiscoveredAt time.Time `json:"discovered_at"`

	// Success indicates if discovery completed successfully
	Success bool `json:"success"`

	// Error contains error information if discovery failed
	Error string `json:"error,omitempty"`
}

// tokenSetToAccessToken converts a saas TokenSet to an auth.AccessToken for storage.
func tokenSetToAccessToken(ts *TokenSet, tenantID string) *auth.AccessToken {
	return &auth.AccessToken{
		Token:         ts.AccessToken,
		TokenType:     ts.TokenType,
		RefreshToken:  ts.RefreshToken,
		ExpiresAt:     ts.ExpiresAt,
		TenantID:      tenantID,
		GrantedScopes: ts.Scopes,
	}
}

// accessTokenToTokenSet converts an auth.AccessToken to a saas TokenSet for use in multitenant flows.
func accessTokenToTokenSet(at *auth.AccessToken) *TokenSet {
	return &TokenSet{
		AccessToken:  at.Token,
		TokenType:    at.TokenType,
		RefreshToken: at.RefreshToken,
		ExpiresAt:    at.ExpiresAt,
		Scopes:       at.GrantedScopes,
	}
}

// StartAdminConsent initiates a multi-tenant admin consent flow
func (mtm *MultiTenantManager) StartAdminConsent(ctx context.Context, provider string, config *MultiTenantConfig) (string, error) {
	if !config.IsMultiTenant {
		return "", fmt.Errorf("configuration is not marked as multi-tenant")
	}

	// Create OAuth2 flow for admin consent
	oauth2Config := &ExtendedOAuth2Config{
		OAuth2Config: config.OAuth2Config,
		GrantType:    "authorization_code",
	}

	// Use /common endpoint for multi-tenant
	oauth2Config.AuthURL = strings.Replace(oauth2Config.AuthURL, "{tenant}", "common", 1)
	oauth2Config.TokenURL = strings.Replace(oauth2Config.TokenURL, "{tenant}", "common", 1)

	flow, err := mtm.oauth2Client.StartFlow(ctx, oauth2Config)
	if err != nil {
		return "", fmt.Errorf("failed to start admin consent flow: %w", err)
	}

	// Build admin consent URL with proper parameters
	authURL, err := url.Parse(flow.AuthURL)
	if err != nil {
		return "", fmt.Errorf("invalid auth URL: %w", err)
	}

	query := authURL.Query()

	// Required OAuth2 authorization request parameters.
	query.Set("client_id", flow.ClientID)
	query.Set("response_type", "code")
	if flow.RedirectURI != "" {
		query.Set("redirect_uri", flow.RedirectURI)
	}

	// Add admin consent specific parameters
	if config.ConsentPrompt != "" {
		query.Set("prompt", config.ConsentPrompt)
	} else {
		query.Set("prompt", "admin_consent")
	}

	// Use admin consent scopes if specified
	if len(config.AdminConsentScopes) > 0 {
		query.Set("scope", strings.Join(config.AdminConsentScopes, " "))
	}

	authURL.RawQuery = query.Encode()

	// Store consent status with flow information
	status := &ConsentStatus{
		Provider:        provider,
		HasAdminConsent: false,
		ConsentFlow:     flow,
	}

	if err := mtm.consentStore.StoreConsent(provider, status); err != nil {
		return "", fmt.Errorf("failed to store consent status: %w", err)
	}

	return authURL.String(), nil
}

// CompleteAdminConsent completes the admin consent flow and discovers tenants
func (mtm *MultiTenantManager) CompleteAdminConsent(ctx context.Context, provider, authCode string) error {
	status, err := mtm.consentStore.GetConsent(provider)
	if err != nil {
		return fmt.Errorf("failed to get consent status: %w", err)
	}

	if status == nil || status.ConsentFlow == nil {
		return fmt.Errorf("no active consent flow found for provider %s", provider)
	}

	// Complete the OAuth2 flow to get initial token
	tokenSet, err := mtm.completeOAuth2Flow(ctx, status.ConsentFlow, authCode)
	if err != nil {
		return fmt.Errorf("failed to complete OAuth2 flow: %w", err)
	}

	// Store the initial token set keyed by provider name
	if err := mtm.credStore.StoreToken(provider, tokenSetToAccessToken(tokenSet, provider)); err != nil {
		return fmt.Errorf("failed to store initial token set: %w", err)
	}

	// Discover accessible tenants
	discoveryResult, err := mtm.discoverTenants(ctx, provider, tokenSet)
	if err != nil {
		return fmt.Errorf("tenant discovery failed: %w", err)
	}

	// Update consent status
	status.HasAdminConsent = true
	status.ConsentGrantedAt = time.Now()
	status.LastTenantDiscovery = time.Now()
	status.AccessibleTenants = discoveryResult.Tenants
	status.ConsentFlow = nil // Clear the flow as it's complete

	if err := mtm.consentStore.StoreConsent(provider, status); err != nil {
		return fmt.Errorf("failed to update consent status: %w", err)
	}

	return nil
}

// GetTenantToken retrieves a valid access token for a specific tenant
func (mtm *MultiTenantManager) GetTenantToken(ctx context.Context, provider, tenantID string) (*TokenSet, error) {
	status, err := mtm.consentStore.GetConsent(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get consent status: %w", err)
	}

	if status == nil || !status.HasAdminConsent {
		return nil, fmt.Errorf("admin consent not granted for provider %s", provider)
	}

	// Check if tenant is accessible
	if !mtm.isTenantAccessible(status, tenantID) {
		return nil, fmt.Errorf("tenant %s is not accessible for provider %s", tenantID, provider)
	}

	// Try to get existing tenant-specific token (keyed by tenantID directly)
	authToken, err := mtm.credStore.GetToken(tenantID)
	var tokenSet *TokenSet
	if err == nil && authToken != nil {
		tokenSet = accessTokenToTokenSet(authToken)
	}

	if tokenSet == nil || tokenSet.IsTokenExpired(5*time.Minute) {
		// Need to get a new token for this tenant
		tokenSet, err = mtm.refreshTenantToken(ctx, provider, tenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to refresh tenant token: %w", err)
		}
	}

	// Verify the JWT tid claim matches the requested tenantID.
	// Fail-open for opaque tokens (non-JWT or missing tid) to preserve
	// compatibility with client-credentials flows that return opaque tokens.
	tid, jwtErr := extractJWTTenantID(tokenSet.AccessToken)
	if jwtErr != nil {
		mtm.logger.Warn("GetTenantToken: tid extraction failed, proceeding with opaque token (fail-open)",
			"provider", logging.SanitizeLogValue(provider),
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"reason", logging.SanitizeLogValue(jwtErr.Error()))
	} else if tid != tenantID {
		return nil, fmt.Errorf("token tenant mismatch: got %q, want %q — token rejected", tid, tenantID)
	}

	return tokenSet, nil
}

// ListAccessibleTenants returns all tenants accessible by the provider
func (mtm *MultiTenantManager) ListAccessibleTenants(ctx context.Context, provider string) ([]TenantInfo, error) {
	status, err := mtm.consentStore.GetConsent(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get consent status: %w", err)
	}

	if status == nil || !status.HasAdminConsent {
		return nil, fmt.Errorf("admin consent not granted for provider %s", provider)
	}

	// Check if we need to refresh tenant discovery
	if time.Since(status.LastTenantDiscovery) > mtm.cacheExpiry {
		if err := mtm.RefreshTenantDiscovery(ctx, provider); err != nil {
			// Log error but return cached tenants if available
			if len(status.AccessibleTenants) == 0 {
				return nil, fmt.Errorf("failed to refresh tenant discovery and no cached tenants: %w", err)
			}
		} else {
			// Get updated status after refresh
			refreshed, refreshErr := mtm.consentStore.GetConsent(provider)
			if refreshErr != nil {
				return nil, fmt.Errorf("failed to read updated consent status: %w", refreshErr)
			}
			if refreshed != nil {
				status = refreshed
			}
		}
	}

	return status.AccessibleTenants, nil
}

// RefreshTenantDiscovery re-discovers accessible tenants
func (mtm *MultiTenantManager) RefreshTenantDiscovery(ctx context.Context, provider string) error {
	// Get base token for tenant discovery (keyed by provider name)
	authToken, err := mtm.credStore.GetToken(provider)
	if err != nil {
		return fmt.Errorf("failed to get base token for discovery: %w", err)
	}
	tokenSet := accessTokenToTokenSet(authToken)

	// Perform tenant discovery
	discoveryResult, err := mtm.discoverTenants(ctx, provider, tokenSet)
	if err != nil {
		return fmt.Errorf("tenant discovery failed: %w", err)
	}

	// Update consent status
	status, err := mtm.consentStore.GetConsent(provider)
	if err != nil {
		return fmt.Errorf("failed to get consent status: %w", err)
	}
	if status == nil {
		status = &ConsentStatus{Provider: provider}
	}

	status.LastTenantDiscovery = time.Now()
	status.AccessibleTenants = discoveryResult.Tenants

	if err := mtm.consentStore.StoreConsent(provider, status); err != nil {
		return fmt.Errorf("failed to update consent status: %w", err)
	}

	return nil
}

// RevokeConsent revokes admin consent and cleans up all tenant tokens
func (mtm *MultiTenantManager) RevokeConsent(ctx context.Context, provider string) error {
	status, err := mtm.consentStore.GetConsent(provider)
	if err != nil {
		return fmt.Errorf("failed to get consent status: %w", err)
	}

	// Clean up all tenant-specific tokens (keyed directly by tenantID)
	if status != nil {
		for _, tenant := range status.AccessibleTenants {
			_ = mtm.credStore.DeleteToken(tenant.TenantID) // Ignore errors for cleanup
		}
	}

	// Clean up base provider token (keyed by provider name)
	_ = mtm.credStore.DeleteToken(provider)

	// Delete consent status
	if err := mtm.consentStore.DeleteConsent(provider); err != nil {
		return fmt.Errorf("failed to delete consent status: %w", err)
	}

	return nil
}

// GetConsentStatus returns the current consent status for a provider.
// Returns a default empty ConsentStatus (HasAdminConsent: false) when no
// consent has been stored yet.
func (mtm *MultiTenantManager) GetConsentStatus(ctx context.Context, provider string) (*ConsentStatus, error) {
	status, err := mtm.consentStore.GetConsent(provider)
	if err != nil {
		return nil, err
	}
	if status == nil {
		return &ConsentStatus{Provider: provider, HasAdminConsent: false}, nil
	}
	return status, nil
}

// Private helper methods

func (mtm *MultiTenantManager) isTenantAccessible(status *ConsentStatus, tenantID string) bool {
	for _, tenant := range status.AccessibleTenants {
		if tenant.TenantID == tenantID && tenant.HasAccess {
			return true
		}
	}
	return false
}

func (mtm *MultiTenantManager) completeOAuth2Flow(ctx context.Context, flow *OAuth2Flow, authCode string) (*TokenSet, error) {
	return mtm.oauth2Client.ExchangeCode(ctx, flow, authCode)
}

func (mtm *MultiTenantManager) discoverTenants(ctx context.Context, provider string, tokenSet *TokenSet) (*TenantDiscoveryResult, error) {
	if mtm.tenantDiscoverer == nil {
		return nil, fmt.Errorf("no tenant discoverer configured for provider %s", provider)
	}
	return mtm.tenantDiscoverer.DiscoverTenants(ctx, tokenSet)
}

func (mtm *MultiTenantManager) refreshTenantToken(_ context.Context, provider, tenantID string) (*TokenSet, error) {
	// Per-tenant token refresh requires a real OAuth2 token exchange with the tenant's
	// authorization endpoint. Callers must pre-populate the credential store (e.g. after
	// admin consent completes) or re-run the admin consent flow to obtain a fresh token.
	return nil, fmt.Errorf("tenant token refresh is not supported for provider %q tenantID %q: re-run admin consent to obtain a fresh token", provider, tenantID)
}
