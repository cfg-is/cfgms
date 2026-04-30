// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package saas microsoft_multitenant implements multi-tenant Microsoft Graph
// provider with enterprise app support for MSP scenarios.
//
// This provider extends the base Microsoft provider to support:
//   - Multi-tenant admin consent flows
//   - Per-tenant token management
//   - Automatic tenant discovery
//   - Cross-tenant resource management
//
// It is designed for MSPs who need to manage multiple customer M365 tenants
// through a single enterprise application registration.
package saas

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MicrosoftMultiTenantProvider implements multi-tenant Microsoft Graph operations
type MicrosoftMultiTenantProvider struct {
	*BaseProvider
	multiTenantManager *MultiTenantManager
	baseURL            string
}

// NewMicrosoftMultiTenantProvider creates a new multi-tenant Microsoft provider
func NewMicrosoftMultiTenantProvider(credStore CredentialStore, httpClient *http.Client) *MicrosoftMultiTenantProvider {
	info := ProviderInfo{
		Name:               "microsoft-multitenant",
		DisplayName:        "Microsoft Graph Multi-Tenant",
		Version:            "1.0.0",
		Description:        "Multi-tenant Microsoft Graph API provider for MSP M365 management",
		SupportedAuthTypes: []string{"oauth2-multitenant"},
		BaseURL:            "https://graph.microsoft.com/v1.0",
		DocumentationURL:   "https://docs.microsoft.com/en-us/graph/auth-v2-service",
		Capabilities: ProviderCapabilities{
			NormalizedOperations: []string{"create", "read", "update", "delete", "list"},
			RawAPISupport:        true,
			SchemaSupport:        false,
			PaginationSupport:    true,
			WebhookSupport:       true,
			BatchOperations:      true,
		},
	}

	baseProvider := NewBaseProvider(info, httpClient)
	baseProvider.SetCredentialStore(credStore)

	return &MicrosoftMultiTenantProvider{
		BaseProvider:       baseProvider,
		multiTenantManager: NewMultiTenantManager(credStore, NewInMemoryConsentStore(), httpClient),
		baseURL:            "https://graph.microsoft.com/v1.0",
	}
}

// Multi-Tenant specific configuration
type MicrosoftMultiTenantConfig struct {
	// Base configuration
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`

	// Multi-tenant specific
	TenantID string   `json:"tenant_id,omitempty"` // Leave empty for multi-tenant
	Scopes   []string `json:"scopes"`

	// Admin consent scopes (typically broader than user scopes)
	AdminConsentScopes []string `json:"admin_consent_scopes"`
}

// StartAdminConsent initiates the multi-tenant admin consent flow
func (p *MicrosoftMultiTenantProvider) StartAdminConsent(ctx context.Context, config *MicrosoftMultiTenantConfig) (string, error) {
	mtConfig := &MultiTenantConfig{
		OAuth2Config: OAuth2Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Scopes:       config.Scopes,
			TokenURL:     "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
			AuthURL:      "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
			RedirectURL:  config.RedirectURI,
		},
		IsMultiTenant:           true,
		AdminConsentScopes:      config.AdminConsentScopes,
		TenantDiscoveryEndpoint: "https://graph.microsoft.com/v1.0/organization",
		ConsentPrompt:           "admin_consent",
	}

	return p.multiTenantManager.StartAdminConsent(ctx, p.GetInfo().Name, mtConfig)
}

// CompleteAdminConsent completes the consent flow and discovers tenants
func (p *MicrosoftMultiTenantProvider) CompleteAdminConsent(ctx context.Context, authCode string) error {
	return p.multiTenantManager.CompleteAdminConsent(ctx, p.GetInfo().Name, authCode)
}

// GetTenantToken retrieves a token for a specific tenant
func (p *MicrosoftMultiTenantProvider) GetTenantToken(ctx context.Context, tenantID string) (*TokenSet, error) {
	return p.multiTenantManager.GetTenantToken(ctx, p.GetInfo().Name, tenantID)
}

// ListAccessibleTenants returns all tenants this app can access
func (p *MicrosoftMultiTenantProvider) ListAccessibleTenants(ctx context.Context) ([]TenantInfo, error) {
	return p.multiTenantManager.ListAccessibleTenants(ctx, p.GetInfo().Name)
}

// Tenant-aware CRUD operations

// CreateInTenant creates a resource in a specific tenant
func (p *MicrosoftMultiTenantProvider) CreateInTenant(ctx context.Context, tenantID, resourceType string, data map[string]interface{}) (*ProviderResult, error) {
	token, err := p.GetTenantToken(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant token: %w", err)
	}

	return p.createWithToken(ctx, resourceType, data, token, tenantID)
}

// ReadFromTenant reads a resource from a specific tenant
func (p *MicrosoftMultiTenantProvider) ReadFromTenant(ctx context.Context, tenantID, resourceType, resourceID string) (*ProviderResult, error) {
	token, err := p.GetTenantToken(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant token: %w", err)
	}

	return p.readWithToken(ctx, resourceType, resourceID, token, tenantID)
}

// UpdateInTenant updates a resource in a specific tenant
func (p *MicrosoftMultiTenantProvider) UpdateInTenant(ctx context.Context, tenantID, resourceType, resourceID string, data map[string]interface{}) (*ProviderResult, error) {
	token, err := p.GetTenantToken(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant token: %w", err)
	}

	return p.updateWithToken(ctx, resourceType, resourceID, data, token, tenantID)
}

// DeleteFromTenant deletes a resource from a specific tenant
func (p *MicrosoftMultiTenantProvider) DeleteFromTenant(ctx context.Context, tenantID, resourceType, resourceID string) (*ProviderResult, error) {
	token, err := p.GetTenantToken(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant token: %w", err)
	}

	return p.deleteWithToken(ctx, resourceType, resourceID, token, tenantID)
}

// ListInTenant lists resources in a specific tenant
func (p *MicrosoftMultiTenantProvider) ListInTenant(ctx context.Context, tenantID, resourceType string, filters map[string]interface{}) (*ProviderResult, error) {
	token, err := p.GetTenantToken(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant token: %w", err)
	}

	return p.listWithToken(ctx, resourceType, filters, token, tenantID)
}

// RawAPIInTenant executes a raw API call against a specific tenant
func (p *MicrosoftMultiTenantProvider) RawAPIInTenant(ctx context.Context, tenantID, method, path string, body interface{}) (*ProviderResult, error) {
	token, err := p.GetTenantToken(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant token: %w", err)
	}

	return p.rawAPIWithToken(ctx, method, path, body, token, tenantID)
}

// Cross-tenant operations

// ListUsersAcrossAllTenants retrieves users from all accessible tenants
func (p *MicrosoftMultiTenantProvider) ListUsersAcrossAllTenants(ctx context.Context, filters map[string]interface{}) (*CrossTenantResult, error) {
	tenants, err := p.ListAccessibleTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get accessible tenants: %w", err)
	}

	result := &CrossTenantResult{
		TenantResults: make(map[string]*ProviderResult),
		Summary:       &CrossTenantSummary{},
	}

	for _, tenant := range tenants {
		if !tenant.HasAccess {
			continue
		}

		tenantResult, err := p.ListInTenant(ctx, tenant.TenantID, "users", filters)
		if err != nil {
			result.TenantResults[tenant.TenantID] = &ProviderResult{
				Success: false,
				Error:   err.Error(),
			}
			result.Summary.FailedTenants++
		} else {
			result.TenantResults[tenant.TenantID] = tenantResult
			result.Summary.SuccessfulTenants++

			// Count users in this tenant
			if users, ok := tenantResult.Data.(map[string]interface{}); ok {
				if value, exists := users["value"].([]interface{}); exists {
					result.Summary.TotalResources += len(value)
				}
			}
		}
	}

	return result, nil
}

// Tenant discovery implementation

// DiscoverTenantsFromMicrosoft uses Microsoft Graph to discover accessible tenants
func (p *MicrosoftMultiTenantProvider) DiscoverTenantsFromMicrosoft(ctx context.Context, tokenSet *TokenSet) (*TenantDiscoveryResult, error) {
	// Call Microsoft Graph's organization endpoint to discover tenants
	req, err := http.NewRequestWithContext(ctx, "GET", "https://graph.microsoft.com/v1.0/organization", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", tokenSet.GetAuthorizationHeader())
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.GetHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Log error but continue - this is cleanup
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return &TenantDiscoveryResult{
			Success: false,
			Error:   fmt.Sprintf("API request failed with status: %d", resp.StatusCode),
		}, nil
	}

	var graphResponse struct {
		Value []struct {
			ID              string `json:"id"`
			DisplayName     string `json:"displayName"`
			VerifiedDomains []struct {
				Name      string `json:"name"`
				IsDefault bool   `json:"isDefault"`
			} `json:"verifiedDomains"`
			CountryLetterCode string `json:"countryLetterCode"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&graphResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	tenants := make([]TenantInfo, len(graphResponse.Value))
	for i, org := range graphResponse.Value {
		tenant := TenantInfo{
			TenantID:    org.ID,
			DisplayName: org.DisplayName,
			CountryCode: org.CountryLetterCode,
			TenantType:  "AAD",
			HasAccess:   true,
		}

		// Find the default domain
		for _, domain := range org.VerifiedDomains {
			if domain.IsDefault {
				tenant.Domain = domain.Name
				break
			}
		}

		tenants[i] = tenant
	}

	return &TenantDiscoveryResult{
		Tenants:      tenants,
		DiscoveredAt: time.Now(),
		Success:      true,
	}, nil
}

// Helper methods for token-aware operations

func (p *MicrosoftMultiTenantProvider) createWithToken(ctx context.Context, resourceType string, data map[string]interface{}, token *TokenSet, tenantID string) (*ProviderResult, error) {
	path := "/" + resourceType
	return p.rawAPIWithToken(ctx, "POST", path, data, token, tenantID)
}

func (p *MicrosoftMultiTenantProvider) readWithToken(ctx context.Context, resourceType, resourceID string, token *TokenSet, tenantID string) (*ProviderResult, error) {
	path := fmt.Sprintf("/%s/%s", resourceType, url.PathEscape(resourceID))
	return p.rawAPIWithToken(ctx, "GET", path, nil, token, tenantID)
}

func (p *MicrosoftMultiTenantProvider) updateWithToken(ctx context.Context, resourceType, resourceID string, data map[string]interface{}, token *TokenSet, tenantID string) (*ProviderResult, error) {
	path := fmt.Sprintf("/%s/%s", resourceType, url.PathEscape(resourceID))
	return p.rawAPIWithToken(ctx, "PATCH", path, data, token, tenantID)
}

func (p *MicrosoftMultiTenantProvider) deleteWithToken(ctx context.Context, resourceType, resourceID string, token *TokenSet, tenantID string) (*ProviderResult, error) {
	path := fmt.Sprintf("/%s/%s", resourceType, url.PathEscape(resourceID))
	return p.rawAPIWithToken(ctx, "DELETE", path, nil, token, tenantID)
}

func (p *MicrosoftMultiTenantProvider) listWithToken(ctx context.Context, resourceType string, filters map[string]interface{}, token *TokenSet, tenantID string) (*ProviderResult, error) {
	path := "/" + resourceType

	// Add OData query parameters
	queryParams := make([]string, 0)
	if filter, exists := filters["filter"]; exists {
		queryParams = append(queryParams, fmt.Sprintf("$filter=%v", filter))
	}
	if limit, exists := filters["limit"]; exists {
		queryParams = append(queryParams, fmt.Sprintf("$top=%v", limit))
	}
	if select_, exists := filters["select"]; exists {
		queryParams = append(queryParams, fmt.Sprintf("$select=%v", select_))
	}

	if len(queryParams) > 0 {
		path += "?" + strings.Join(queryParams, "&")
	}

	return p.rawAPIWithToken(ctx, "GET", path, nil, token, tenantID)
}

func (p *MicrosoftMultiTenantProvider) rawAPIWithToken(ctx context.Context, method, path string, body interface{}, token *TokenSet, tenantID string) (*ProviderResult, error) {
	// Build the full URL
	fullURL := p.baseURL + path

	var reqBody []byte
	var err error

	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication headers
	req.Header.Set("Authorization", token.GetAuthorizationHeader())
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	resp, err := p.GetHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Log error but continue - this is cleanup
			_ = closeErr
		}
	}()

	// Parse response
	var responseData interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil && resp.StatusCode < 400 {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	result := &ProviderResult{
		Success:    success,
		Data:       responseData,
		StatusCode: resp.StatusCode,
		Headers:    make(map[string]string),
		Metadata: map[string]interface{}{
			"provider": p.GetInfo().Name,
			"tenant":   tenantID,
			"method":   method,
			"path":     path,
		},
	}

	if !success {
		if data, ok := responseData.(map[string]interface{}); ok {
			if errMsg, exists := data["error"]; exists {
				result.Error = fmt.Sprintf("%v", errMsg)
			}
		}
	}

	// Copy relevant headers
	for _, header := range []string{"Content-Type", "X-RateLimit-Limit", "X-RateLimit-Remaining"} {
		if value := resp.Header.Get(header); value != "" {
			result.Headers[header] = value
		}
	}

	return result, nil
}

// Standard Provider interface implementation (delegates to first tenant or requires tenant specification)

// Authenticate performs multi-tenant authentication
func (p *MicrosoftMultiTenantProvider) Authenticate(ctx context.Context, config ProviderConfig, credStore CredentialStore) error {
	// For multi-tenant, authentication is handled via admin consent flow
	// This method could initiate that flow or return an error directing to use StartAdminConsent
	return fmt.Errorf("multi-tenant provider requires admin consent flow - use StartAdminConsent() method")
}

// IsAuthenticated checks if multi-tenant consent has been granted
func (p *MicrosoftMultiTenantProvider) IsAuthenticated(ctx context.Context, credStore CredentialStore) bool {
	status, err := p.multiTenantManager.GetConsentStatus(ctx, p.GetInfo().Name)
	return err == nil && status.HasAdminConsent
}

// RefreshAuth refreshes authentication (for multi-tenant, this refreshes tenant discovery)
func (p *MicrosoftMultiTenantProvider) RefreshAuth(ctx context.Context, credStore CredentialStore) error {
	return p.multiTenantManager.RefreshTenantDiscovery(ctx, p.GetInfo().Name)
}

// Standard CRUD operations (these require tenant context - could default to first tenant or return error)

// Create (delegates to first accessible tenant)
func (p *MicrosoftMultiTenantProvider) Create(ctx context.Context, resourceType string, data map[string]interface{}) (*ProviderResult, error) {
	tenants, err := p.ListAccessibleTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenants: %w", err)
	}
	if len(tenants) == 0 {
		return nil, fmt.Errorf("no accessible tenants found")
	}

	return p.CreateInTenant(ctx, tenants[0].TenantID, resourceType, data)
}

// Read (delegates to first accessible tenant)
func (p *MicrosoftMultiTenantProvider) Read(ctx context.Context, resourceType string, resourceID string) (*ProviderResult, error) {
	tenants, err := p.ListAccessibleTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenants: %w", err)
	}
	if len(tenants) == 0 {
		return nil, fmt.Errorf("no accessible tenants found")
	}

	return p.ReadFromTenant(ctx, tenants[0].TenantID, resourceType, resourceID)
}

// Update (delegates to first accessible tenant)
func (p *MicrosoftMultiTenantProvider) Update(ctx context.Context, resourceType string, resourceID string, data map[string]interface{}) (*ProviderResult, error) {
	tenants, err := p.ListAccessibleTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenants: %w", err)
	}
	if len(tenants) == 0 {
		return nil, fmt.Errorf("no accessible tenants found")
	}

	return p.UpdateInTenant(ctx, tenants[0].TenantID, resourceType, resourceID, data)
}

// Delete (delegates to first accessible tenant)
func (p *MicrosoftMultiTenantProvider) Delete(ctx context.Context, resourceType string, resourceID string) (*ProviderResult, error) {
	tenants, err := p.ListAccessibleTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenants: %w", err)
	}
	if len(tenants) == 0 {
		return nil, fmt.Errorf("no accessible tenants found")
	}

	return p.DeleteFromTenant(ctx, tenants[0].TenantID, resourceType, resourceID)
}

// List (aggregates across all tenants)
func (p *MicrosoftMultiTenantProvider) List(ctx context.Context, resourceType string, filters map[string]interface{}) (*ProviderResult, error) {
	crossTenantResult, err := p.ListUsersAcrossAllTenants(ctx, filters)
	if err != nil {
		return nil, err
	}

	// Aggregate results from all tenants
	allResources := make([]interface{}, 0)
	for _, result := range crossTenantResult.TenantResults {
		if result.Success {
			if data, ok := result.Data.(map[string]interface{}); ok {
				if value, exists := data["value"].([]interface{}); exists {
					allResources = append(allResources, value...)
				}
			}
		}
	}

	return &ProviderResult{
		Success: true,
		Data: map[string]interface{}{
			"value": allResources,
		},
		StatusCode: 200,
		Metadata: map[string]interface{}{
			"provider":        p.GetInfo().Name,
			"cross_tenant":    true,
			"tenant_count":    len(crossTenantResult.TenantResults),
			"total_resources": len(allResources),
		},
	}, nil
}

// RawAPI (delegates to first accessible tenant)
func (p *MicrosoftMultiTenantProvider) RawAPI(ctx context.Context, method, path string, body interface{}) (*ProviderResult, error) {
	tenants, err := p.ListAccessibleTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenants: %w", err)
	}
	if len(tenants) == 0 {
		return nil, fmt.Errorf("no accessible tenants found")
	}

	return p.RawAPIInTenant(ctx, tenants[0].TenantID, method, path, body)
}

// GetAPISchema returns the Microsoft Graph schema
func (p *MicrosoftMultiTenantProvider) GetAPISchema(ctx context.Context) (*APISchema, error) {
	return nil, fmt.Errorf("API schema not implemented for multi-tenant provider")
}

// GetSupportedResources returns supported resource types
func (p *MicrosoftMultiTenantProvider) GetSupportedResources() []ResourceType {
	return []ResourceType{
		{
			Name:                "users",
			DisplayName:         "Users",
			Description:         "Azure AD users across all accessible tenants",
			SupportedOperations: []string{"create", "read", "update", "delete", "list"},
			RequiredFields:      []string{"displayName", "userPrincipalName"},
			OptionalFields:      []string{"givenName", "surname", "jobTitle", "department"},
			ReadOnlyFields:      []string{"id", "createdDateTime"},
		},
		{
			Name:                "groups",
			DisplayName:         "Groups",
			Description:         "Azure AD groups across all accessible tenants",
			SupportedOperations: []string{"create", "read", "update", "delete", "list"},
			RequiredFields:      []string{"displayName"},
			OptionalFields:      []string{"description", "mailEnabled", "securityEnabled"},
			ReadOnlyFields:      []string{"id", "createdDateTime"},
		},
	}
}

// GetResourceSchema returns schema for a specific resource
func (p *MicrosoftMultiTenantProvider) GetResourceSchema(resourceType string) (*ResourceSchema, error) {
	// Delegate to base provider implementation (same as single-tenant)
	switch resourceType {
	case "users":
		return &ResourceSchema{
			Type: "users",
			Properties: map[string]PropertySchema{
				"id": {
					Type:        "string",
					Description: "Unique identifier",
					ReadOnly:    true,
				},
				"displayName": {
					Type:        "string",
					Description: "Display name",
				},
				"userPrincipalName": {
					Type:        "string",
					Format:      "email",
					Description: "User principal name (email)",
				},
			},
			Required: []string{"displayName", "userPrincipalName"},
		}, nil
	default:
		return nil, fmt.Errorf("schema not available for resource type: %s", resourceType)
	}
}

// ValidateResource validates resource data
func (p *MicrosoftMultiTenantProvider) ValidateResource(resourceType string, data map[string]interface{}) error {
	schema, err := p.GetResourceSchema(resourceType)
	if err != nil {
		return err
	}

	// Check required fields
	for _, field := range schema.Required {
		if _, exists := data[field]; !exists {
			return fmt.Errorf("required field %s is missing", field)
		}
	}

	return nil
}

// ValidateConfig validates provider configuration
func (p *MicrosoftMultiTenantProvider) ValidateConfig(config ProviderConfig) error {
	if config.ClientID == "" {
		return fmt.Errorf("client_id is required for multi-tenant provider")
	}

	// For multi-tenant, tenant_id should be empty or "common"
	if config.TenantID != "" && config.TenantID != "common" {
		return fmt.Errorf("multi-tenant provider should not specify tenant_id or use 'common'")
	}

	return nil
}

// CrossTenantResult aggregates results from multiple tenants
type CrossTenantResult struct {
	// TenantResults maps tenant ID to the result from that tenant
	TenantResults map[string]*ProviderResult `json:"tenant_results"`

	// Summary provides aggregate statistics
	Summary *CrossTenantSummary `json:"summary"`
}

// CrossTenantSummary provides aggregate statistics across tenants
type CrossTenantSummary struct {
	// SuccessfulTenants count of tenants that returned successful results
	SuccessfulTenants int `json:"successful_tenants"`

	// FailedTenants count of tenants that returned errors
	FailedTenants int `json:"failed_tenants"`

	// TotalResources aggregate count of resources across all tenants
	TotalResources int `json:"total_resources"`
}
