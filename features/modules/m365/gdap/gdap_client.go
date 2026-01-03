// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package gdap gdap_client implements Microsoft Partner Center API client
// for GDAP (Granular Delegated Admin Privileges) operations.
//
// This client provides methods to:
//   - Retrieve GDAP relationships from Partner Center API
//   - Validate partner permissions and roles
//   - Manage GDAP relationship lifecycle
//   - Query customer tenant information via GDAP
//
// It integrates with the Microsoft Partner Center REST API to discover
// and manage customer tenant relationships for MSP scenarios.
package gdap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
)

// GDAPClient provides methods for interacting with Microsoft Partner Center API
type GDAPClient struct {
	httpClient      *http.Client
	partnerTenantID string
	credStore       auth.CredentialStore
	baseURL         string
}

// NewGDAPClient creates a new GDAP client
func NewGDAPClient(httpClient *http.Client, partnerTenantID string) *GDAPClient {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	return &GDAPClient{
		httpClient:      httpClient,
		partnerTenantID: partnerTenantID,
		baseURL:         "https://api.partnercenter.microsoft.com/v1",
	}
}

// SetCredentialStore sets the credential store for Partner Center authentication
func (c *GDAPClient) SetCredentialStore(credStore auth.CredentialStore) {
	c.credStore = credStore
}

// GetGDAPRelationships retrieves all GDAP relationships from Partner Center API
func (c *GDAPClient) GetGDAPRelationships(ctx context.Context) ([]GDAPRelationship, error) {
	// Get Partner Center access token
	token, err := c.getPartnerCenterToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Partner Center token: %w", err)
	}

	// Build request URL
	reqURL := fmt.Sprintf("%s/customers/relationships/delegatedAdminRelationships", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", token.GetAuthorizationHeader())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("MS-RequestId", c.generateRequestID())
	req.Header.Set("MS-PartnerCenter-Application", "CFGMS-GDAP-Client/1.0")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("partner center API request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Log error but continue
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("partner center API returned status %d", resp.StatusCode)
	}

	// Parse response
	var apiResponse struct {
		TotalCount int `json:"totalCount"`
		Items      []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			Customer    struct {
				TenantID    string `json:"tenantId"`
				DisplayName string `json:"displayName"`
			} `json:"customer"`
			Details struct {
				UnifiedRoles []struct {
					RoleDefinitionID string `json:"roleDefinitionId"`
					RoleName         string `json:"roleName"`
					Description      string `json:"description"`
				} `json:"unifiedRoles"`
			} `json:"details"`
			Status               string    `json:"status"`
			CreatedDateTime      time.Time `json:"createdDateTime"`
			LastModifiedDateTime time.Time `json:"lastModifiedDateTime"`
			EndDateTime          time.Time `json:"endDateTime"`
		} `json:"items"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("failed to parse Partner Center response: %w", err)
	}

	// Convert to our format
	relationships := make([]GDAPRelationship, 0, len(apiResponse.Items))
	for _, item := range apiResponse.Items {
		roles := make([]GDAPRole, 0, len(item.Details.UnifiedRoles))
		for _, role := range item.Details.UnifiedRoles {
			roles = append(roles, GDAPRole{
				RoleDefinitionID: role.RoleDefinitionID,
				RoleName:         role.RoleName,
				RoleDescription:  role.Description,
			})
		}

		relationship := GDAPRelationship{
			RelationshipID:   item.ID,
			CustomerTenantID: item.Customer.TenantID,
			CustomerName:     item.Customer.DisplayName,
			Status:           GDAPRelationshipStatus(strings.ToLower(item.Status)),
			Roles:            roles,
			ExpiresAt:        item.EndDateTime,
			CreatedAt:        item.CreatedDateTime,
			LastModified:     item.LastModifiedDateTime,
		}

		relationships = append(relationships, relationship)
	}

	return relationships, nil
}

// GetGDAPRelationship retrieves a specific GDAP relationship by ID
func (c *GDAPClient) GetGDAPRelationship(ctx context.Context, relationshipID string) (*GDAPRelationship, error) {
	// Get Partner Center access token
	token, err := c.getPartnerCenterToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Partner Center token: %w", err)
	}

	// Build request URL
	reqURL := fmt.Sprintf("%s/customers/relationships/delegatedAdminRelationships/%s",
		c.baseURL, url.PathEscape(relationshipID))

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", token.GetAuthorizationHeader())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("MS-RequestId", c.generateRequestID())

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("partner center API request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("GDAP relationship not found: %s", relationshipID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("partner center API returned status %d", resp.StatusCode)
	}

	// Parse single relationship response
	var apiItem struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		Customer    struct {
			TenantID    string `json:"tenantId"`
			DisplayName string `json:"displayName"`
		} `json:"customer"`
		Details struct {
			UnifiedRoles []struct {
				RoleDefinitionID string `json:"roleDefinitionId"`
				RoleName         string `json:"roleName"`
				Description      string `json:"description"`
			} `json:"unifiedRoles"`
		} `json:"details"`
		Status               string    `json:"status"`
		CreatedDateTime      time.Time `json:"createdDateTime"`
		LastModifiedDateTime time.Time `json:"lastModifiedDateTime"`
		EndDateTime          time.Time `json:"endDateTime"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiItem); err != nil {
		return nil, fmt.Errorf("failed to parse Partner Center response: %w", err)
	}

	// Convert to our format
	roles := make([]GDAPRole, 0, len(apiItem.Details.UnifiedRoles))
	for _, role := range apiItem.Details.UnifiedRoles {
		roles = append(roles, GDAPRole{
			RoleDefinitionID: role.RoleDefinitionID,
			RoleName:         role.RoleName,
			RoleDescription:  role.Description,
		})
	}

	relationship := &GDAPRelationship{
		RelationshipID:   apiItem.ID,
		CustomerTenantID: apiItem.Customer.TenantID,
		CustomerName:     apiItem.Customer.DisplayName,
		Status:           GDAPRelationshipStatus(strings.ToLower(apiItem.Status)),
		Roles:            roles,
		ExpiresAt:        apiItem.EndDateTime,
		CreatedAt:        apiItem.CreatedDateTime,
		LastModified:     apiItem.LastModifiedDateTime,
	}

	return relationship, nil
}

// ValidatePartnerAccess validates that the partner has access to perform operations in a customer tenant
func (c *GDAPClient) ValidatePartnerAccess(ctx context.Context, customerTenantID string) (*PartnerAccessValidation, error) {
	relationships, err := c.GetGDAPRelationships(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get GDAP relationships: %w", err)
	}

	validation := &PartnerAccessValidation{
		CustomerTenantID:    customerTenantID,
		PartnerTenantID:     c.partnerTenantID,
		HasAccess:           false,
		ValidatedAt:         time.Now(),
		ActiveRelationships: make([]string, 0),
		AvailableRoles:      make([]string, 0),
	}

	// Find active relationships for this customer
	for _, rel := range relationships {
		if rel.CustomerTenantID == customerTenantID {
			if rel.Status == GDAPStatusActive && time.Now().Before(rel.ExpiresAt) {
				validation.HasAccess = true
				validation.ActiveRelationships = append(validation.ActiveRelationships, rel.RelationshipID)

				// Collect all available roles
				for _, role := range rel.Roles {
					validation.AvailableRoles = append(validation.AvailableRoles, role.RoleName)
				}
			}
		}
	}

	if !validation.HasAccess {
		validation.Error = fmt.Sprintf("No active GDAP relationship found for customer tenant %s", customerTenantID)
	}

	return validation, nil
}

// GetCustomerInformation retrieves customer tenant information via GDAP
func (c *GDAPClient) GetCustomerInformation(ctx context.Context, customerTenantID string) (*CustomerInfo, error) {
	// First validate access
	validation, err := c.ValidatePartnerAccess(ctx, customerTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to validate partner access: %w", err)
	}

	if !validation.HasAccess {
		return nil, fmt.Errorf("no GDAP access to customer tenant: %s", customerTenantID)
	}

	// Get Partner Center token
	token, err := c.getPartnerCenterToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Partner Center token: %w", err)
	}

	// Get customer profile information
	reqURL := fmt.Sprintf("%s/customers/%s", c.baseURL, url.PathEscape(customerTenantID))

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", token.GetAuthorizationHeader())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("MS-RequestId", c.generateRequestID())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("partner center API request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get customer information, status: %d", resp.StatusCode)
	}

	var customerProfile struct {
		ID             string `json:"id"`
		CompanyName    string `json:"companyName"`
		Domain         string `json:"domain"`
		TenantID       string `json:"tenantId"`
		BillingProfile struct {
			CompanyName string `json:"companyName"`
			Address     struct {
				Country string `json:"country"`
				Region  string `json:"region"`
				City    string `json:"city"`
			} `json:"address"`
		} `json:"billingProfile"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&customerProfile); err != nil {
		return nil, fmt.Errorf("failed to parse customer information: %w", err)
	}

	customerInfo := &CustomerInfo{
		TenantID:     customerProfile.TenantID,
		CompanyName:  customerProfile.CompanyName,
		Domain:       customerProfile.Domain,
		Country:      customerProfile.BillingProfile.Address.Country,
		Region:       customerProfile.BillingProfile.Address.Region,
		City:         customerProfile.BillingProfile.Address.City,
		AccessMethod: "gdap",
		Validation:   validation,
	}

	return customerInfo, nil
}

// getPartnerCenterToken gets an access token for Partner Center API
func (c *GDAPClient) getPartnerCenterToken(ctx context.Context) (*auth.AccessToken, error) {
	if c.credStore == nil {
		return nil, fmt.Errorf("credential store not configured for GDAP client")
	}

	// Try to get cached Partner Center token
	token, err := c.credStore.GetToken(c.partnerTenantID)
	if err == nil && token != nil && time.Now().Before(token.ExpiresAt.Add(-5*time.Minute)) {
		return token, nil
	}

	// Need to get new Partner Center token - this would require partner credentials
	// In a real implementation, this would use the Partner Center OAuth2 flow
	return nil, fmt.Errorf("partner Center token acquisition not implemented - requires partner credentials")
}

// generateRequestID generates a unique request ID for Partner Center API calls
func (c *GDAPClient) generateRequestID() string {
	return fmt.Sprintf("cfgms-gdap-%d", time.Now().UnixNano())
}

// PartnerAccessValidation represents the result of partner access validation
type PartnerAccessValidation struct {
	CustomerTenantID    string    `json:"customer_tenant_id"`
	PartnerTenantID     string    `json:"partner_tenant_id"`
	HasAccess           bool      `json:"has_access"`
	ActiveRelationships []string  `json:"active_relationships"`
	AvailableRoles      []string  `json:"available_roles"`
	Error               string    `json:"error,omitempty"`
	ValidatedAt         time.Time `json:"validated_at"`
}

// CustomerInfo represents customer tenant information retrieved via GDAP
type CustomerInfo struct {
	TenantID     string                   `json:"tenant_id"`
	CompanyName  string                   `json:"company_name"`
	Domain       string                   `json:"domain"`
	Country      string                   `json:"country"`
	Region       string                   `json:"region"`
	City         string                   `json:"city"`
	AccessMethod string                   `json:"access_method"`
	Validation   *PartnerAccessValidation `json:"validation"`
}

// GDAPClientConfig represents configuration for the GDAP client
type GDAPClientConfig struct {
	PartnerTenantID     string   `json:"partner_tenant_id"`
	PartnerClientID     string   `json:"partner_client_id"`
	PartnerClientSecret string   `json:"partner_client_secret"`
	PartnerCenterScopes []string `json:"partner_center_scopes"`
	BaseURL             string   `json:"base_url,omitempty"`
}

// ValidateGDAPClientConfig validates GDAP client configuration
func ValidateGDAPClientConfig(config *GDAPClientConfig) error {
	if config.PartnerTenantID == "" {
		return fmt.Errorf("partner_tenant_id is required")
	}

	if config.PartnerClientID == "" {
		return fmt.Errorf("partner_client_id is required")
	}

	if config.PartnerClientSecret == "" {
		return fmt.Errorf("partner_client_secret is required")
	}

	// Validate Partner Center scopes
	requiredScopes := []string{
		"https://api.partnercenter.microsoft.com/user_impersonation",
	}

	for _, requiredScope := range requiredScopes {
		found := false
		for _, scope := range config.PartnerCenterScopes {
			if scope == requiredScope {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("required Partner Center scope missing: %s", requiredScope)
		}
	}

	return nil
}
