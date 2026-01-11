// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package gdap implements Microsoft GDAP (Granular Delegated Admin Privileges)
// integration for MSP scenarios with partner tenant relationships.
//
// This provider extends the multi-tenant SaaS provider to support:
//   - GDAP relationship discovery via Partner Center API
//   - Role-based access through GDAP assignments
//   - Conditional access based on partner relationships
//   - Time-bound access controls via GDAP
//
// It enables MSPs to manage multiple customer M365 tenants through their
// partner relationship without requiring individual enterprise app registrations
// in each customer tenant.
package gdap

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/saas"
)

// credentialStoreAdapter adapts auth.CredentialStore to saas.CredentialStore
type credentialStoreAdapter struct {
	auth.CredentialStore
}

// Implement missing methods for saas.CredentialStore compatibility
func (a *credentialStoreAdapter) StoreTokenSet(provider string, tokens *saas.TokenSet) error {
	// Convert saas.TokenSet to auth.AccessToken
	authToken := &auth.AccessToken{
		Token:        tokens.AccessToken,
		TokenType:    tokens.TokenType,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt,
		TenantID:     provider, // Use provider as tenant ID
	}
	return a.StoreToken(provider, authToken)
}

func (a *credentialStoreAdapter) GetTokenSet(provider string) (*saas.TokenSet, error) {
	token, err := a.GetToken(provider)
	if err != nil {
		return nil, err
	}

	// Convert auth.AccessToken to saas.TokenSet
	tokenSet := &saas.TokenSet{
		AccessToken:  token.Token,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.ExpiresAt,
	}
	return tokenSet, nil
}

func (a *credentialStoreAdapter) DeleteTokenSet(provider string) error {
	return a.DeleteToken(provider)
}

func (a *credentialStoreAdapter) StoreClientSecret(provider, clientSecret string) error {
	// Not implemented in base auth store - would need extension
	return fmt.Errorf("client secret storage not implemented in auth credential store")
}

func (a *credentialStoreAdapter) GetClientSecret(provider string) (string, error) {
	// Not implemented in base auth store - would need extension
	return "", fmt.Errorf("client secret retrieval not implemented in auth credential store")
}

func (a *credentialStoreAdapter) IsAvailable() bool {
	return true // File-based store is always available
}

// GDAPProvider implements GDAP-aware M365 operations for MSP scenarios
type GDAPProvider struct {
	*saas.MicrosoftMultiTenantProvider
	partnerTenantID string
	gdapClient      *GDAPClient
}

// NewGDAPProvider creates a new GDAP-enabled M365 provider
func NewGDAPProvider(credStore auth.CredentialStore, httpClient *http.Client, partnerTenantID string) *GDAPProvider {
	// Adapt auth.CredentialStore to saas.CredentialStore
	adaptedCredStore := &credentialStoreAdapter{credStore}
	multiTenant := saas.NewMicrosoftMultiTenantProvider(adaptedCredStore, httpClient)

	return &GDAPProvider{
		MicrosoftMultiTenantProvider: multiTenant,
		partnerTenantID:              partnerTenantID,
		gdapClient:                   NewGDAPClient(httpClient, partnerTenantID),
	}
}

// GDAPConfig extends the multi-tenant config with GDAP-specific settings
type GDAPConfig struct {
	// Base multi-tenant configuration
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`

	// Partner-specific configuration
	PartnerTenantID string `json:"partner_tenant_id"`

	// GDAP-specific scopes (Partner Center + Microsoft Graph)
	PartnerCenterScopes []string `json:"partner_center_scopes"`
	GraphScopes         []string `json:"graph_scopes"`

	// GDAP behavior configuration
	ValidateGDAPRelationships bool `json:"validate_gdap_relationships"`
	EnforceRoleBasedAccess    bool `json:"enforce_role_based_access"`
	RequireActiveRelationship bool `json:"require_active_relationship"`
}

// GDAPRelationship represents a GDAP relationship with a customer tenant
type GDAPRelationship struct {
	RelationshipID   string                 `json:"relationship_id"`
	CustomerTenantID string                 `json:"customer_tenant_id"`
	CustomerName     string                 `json:"customer_name"`
	Status           GDAPRelationshipStatus `json:"status"`
	Roles            []GDAPRole             `json:"roles"`
	ExpiresAt        time.Time              `json:"expires_at"`
	CreatedAt        time.Time              `json:"created_at"`
	LastModified     time.Time              `json:"last_modified"`
}

// GDAPRelationshipStatus represents the status of a GDAP relationship
type GDAPRelationshipStatus string

const (
	GDAPStatusPending    GDAPRelationshipStatus = "pending"
	GDAPStatusActive     GDAPRelationshipStatus = "active"
	GDAPStatusExpired    GDAPRelationshipStatus = "expired"
	GDAPStatusTerminated GDAPRelationshipStatus = "terminated"
)

// GDAPRole represents a role assignment within a GDAP relationship
type GDAPRole struct {
	RoleDefinitionID string `json:"role_definition_id"`
	RoleName         string `json:"role_name"`
	RoleDescription  string `json:"role_description"`
}

// DiscoverGDAPCustomers discovers customer tenants accessible via GDAP
func (p *GDAPProvider) DiscoverGDAPCustomers(ctx context.Context) ([]GDAPRelationship, error) {
	// Get GDAP relationships from Partner Center API
	relationships, err := p.gdapClient.GetGDAPRelationships(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get GDAP relationships: %w", err)
	}

	// Filter to active relationships only
	activeRelationships := make([]GDAPRelationship, 0)
	for _, rel := range relationships {
		if rel.Status == GDAPStatusActive && time.Now().Before(rel.ExpiresAt) {
			activeRelationships = append(activeRelationships, rel)
		}
	}

	return activeRelationships, nil
}

// ValidateGDAPAccess validates that the MSP has GDAP access to perform an operation
func (p *GDAPProvider) ValidateGDAPAccess(ctx context.Context, customerTenantID string, requiredRoles []string) (*GDAPRelationship, error) {
	relationships, err := p.DiscoverGDAPCustomers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to discover GDAP customers: %w", err)
	}

	// Find the relationship for this customer tenant
	var relationship *GDAPRelationship
	for _, rel := range relationships {
		if rel.CustomerTenantID == customerTenantID {
			relationship = &rel
			break
		}
	}

	if relationship == nil {
		return nil, fmt.Errorf("no GDAP relationship found for tenant %s", customerTenantID)
	}

	// Check if relationship is active
	if relationship.Status != GDAPStatusActive {
		return nil, fmt.Errorf("GDAP relationship for tenant %s is %s", customerTenantID, relationship.Status)
	}

	// Check if relationship is expired
	if time.Now().After(relationship.ExpiresAt) {
		return nil, fmt.Errorf("GDAP relationship for tenant %s expired at %s", customerTenantID, relationship.ExpiresAt)
	}

	// Check required roles if specified
	if len(requiredRoles) > 0 {
		availableRoles := make(map[string]bool)
		for _, role := range relationship.Roles {
			availableRoles[role.RoleName] = true
		}

		for _, requiredRole := range requiredRoles {
			if !availableRoles[requiredRole] {
				return nil, fmt.Errorf("GDAP relationship for tenant %s lacks required role: %s", customerTenantID, requiredRole)
			}
		}
	}

	return relationship, nil
}

// CreateInCustomerTenant creates a resource in a customer tenant via GDAP
func (p *GDAPProvider) CreateInCustomerTenant(ctx context.Context, customerTenantID, resourceType string, data map[string]interface{}, requiredRoles []string) (*saas.ProviderResult, error) {
	// Validate GDAP access
	relationship, err := p.ValidateGDAPAccess(ctx, customerTenantID, requiredRoles)
	if err != nil {
		return nil, fmt.Errorf("GDAP validation failed: %w", err)
	}

	// Use the multi-tenant provider to perform the operation
	result, err := p.CreateInTenant(ctx, customerTenantID, resourceType, data)
	if err != nil {
		return nil, err
	}

	// Add GDAP metadata to the result
	if result.Metadata == nil {
		result.Metadata = make(map[string]interface{})
	}
	result.Metadata["gdap_relationship_id"] = relationship.RelationshipID
	result.Metadata["gdap_customer_name"] = relationship.CustomerName
	result.Metadata["access_method"] = "gdap"

	return result, nil
}

// ReadFromCustomerTenant reads a resource from a customer tenant via GDAP
func (p *GDAPProvider) ReadFromCustomerTenant(ctx context.Context, customerTenantID, resourceType, resourceID string, requiredRoles []string) (*saas.ProviderResult, error) {
	// Validate GDAP access
	relationship, err := p.ValidateGDAPAccess(ctx, customerTenantID, requiredRoles)
	if err != nil {
		return nil, fmt.Errorf("GDAP validation failed: %w", err)
	}

	// Use the multi-tenant provider to perform the operation
	result, err := p.ReadFromTenant(ctx, customerTenantID, resourceType, resourceID)
	if err != nil {
		return nil, err
	}

	// Add GDAP metadata to the result
	if result.Metadata == nil {
		result.Metadata = make(map[string]interface{})
	}
	result.Metadata["gdap_relationship_id"] = relationship.RelationshipID
	result.Metadata["gdap_customer_name"] = relationship.CustomerName
	result.Metadata["access_method"] = "gdap"

	return result, nil
}

// UpdateInCustomerTenant updates a resource in a customer tenant via GDAP
func (p *GDAPProvider) UpdateInCustomerTenant(ctx context.Context, customerTenantID, resourceType, resourceID string, data map[string]interface{}, requiredRoles []string) (*saas.ProviderResult, error) {
	// Validate GDAP access
	relationship, err := p.ValidateGDAPAccess(ctx, customerTenantID, requiredRoles)
	if err != nil {
		return nil, fmt.Errorf("GDAP validation failed: %w", err)
	}

	// Use the multi-tenant provider to perform the operation
	result, err := p.UpdateInTenant(ctx, customerTenantID, resourceType, resourceID, data)
	if err != nil {
		return nil, err
	}

	// Add GDAP metadata to the result
	if result.Metadata == nil {
		result.Metadata = make(map[string]interface{})
	}
	result.Metadata["gdap_relationship_id"] = relationship.RelationshipID
	result.Metadata["gdap_customer_name"] = relationship.CustomerName
	result.Metadata["access_method"] = "gdap"

	return result, nil
}

// DeleteFromCustomerTenant deletes a resource from a customer tenant via GDAP
func (p *GDAPProvider) DeleteFromCustomerTenant(ctx context.Context, customerTenantID, resourceType, resourceID string, requiredRoles []string) (*saas.ProviderResult, error) {
	// Validate GDAP access
	relationship, err := p.ValidateGDAPAccess(ctx, customerTenantID, requiredRoles)
	if err != nil {
		return nil, fmt.Errorf("GDAP validation failed: %w", err)
	}

	// Use the multi-tenant provider to perform the operation
	result, err := p.DeleteFromTenant(ctx, customerTenantID, resourceType, resourceID)
	if err != nil {
		return nil, err
	}

	// Add GDAP metadata to the result
	if result.Metadata == nil {
		result.Metadata = make(map[string]interface{})
	}
	result.Metadata["gdap_relationship_id"] = relationship.RelationshipID
	result.Metadata["gdap_customer_name"] = relationship.CustomerName
	result.Metadata["access_method"] = "gdap"

	return result, nil
}

// ListAcrossGDAPCustomers lists resources across all GDAP customer tenants
func (p *GDAPProvider) ListAcrossGDAPCustomers(ctx context.Context, resourceType string, filters map[string]interface{}, requiredRoles []string) (*saas.CrossTenantResult, error) {
	customers, err := p.DiscoverGDAPCustomers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to discover GDAP customers: %w", err)
	}

	result := &saas.CrossTenantResult{
		TenantResults: make(map[string]*saas.ProviderResult),
		Summary:       &saas.CrossTenantSummary{},
	}

	for _, customer := range customers {
		// Check if this customer has the required roles
		if len(requiredRoles) > 0 {
			hasRequiredRoles := true
			availableRoles := make(map[string]bool)
			for _, role := range customer.Roles {
				availableRoles[role.RoleName] = true
			}

			for _, requiredRole := range requiredRoles {
				if !availableRoles[requiredRole] {
					hasRequiredRoles = false
					break
				}
			}

			if !hasRequiredRoles {
				result.TenantResults[customer.CustomerTenantID] = &saas.ProviderResult{
					Success: false,
					Error:   fmt.Sprintf("Insufficient GDAP roles for tenant %s", customer.CustomerTenantID),
				}
				result.Summary.FailedTenants++
				continue
			}
		}

		// Perform the operation on this customer tenant
		tenantResult, err := p.ListInTenant(ctx, customer.CustomerTenantID, resourceType, filters)
		if err != nil {
			result.TenantResults[customer.CustomerTenantID] = &saas.ProviderResult{
				Success: false,
				Error:   err.Error(),
			}
			result.Summary.FailedTenants++
		} else {
			// Add GDAP metadata
			if tenantResult.Metadata == nil {
				tenantResult.Metadata = make(map[string]interface{})
			}
			tenantResult.Metadata["gdap_relationship_id"] = customer.RelationshipID
			tenantResult.Metadata["gdap_customer_name"] = customer.CustomerName
			tenantResult.Metadata["access_method"] = "gdap"

			result.TenantResults[customer.CustomerTenantID] = tenantResult
			result.Summary.SuccessfulTenants++

			// Count resources in this tenant
			if data, ok := tenantResult.Data.(map[string]interface{}); ok {
				if value, exists := data["value"].([]interface{}); exists {
					result.Summary.TotalResources += len(value)
				}
			}
		}
	}

	return result, nil
}

// GetGDAPRoleRequirements returns the required GDAP roles for different operations
func (p *GDAPProvider) GetGDAPRoleRequirements(operation, resourceType string) []string {
	roleMap := map[string]map[string][]string{
		"users": {
			"create": {"User Administrator", "Global Administrator"},
			"read":   {"User Administrator", "Global Reader", "Directory Readers"},
			"update": {"User Administrator", "Global Administrator"},
			"delete": {"User Administrator", "Global Administrator"},
			"list":   {"User Administrator", "Global Reader", "Directory Readers"},
		},
		"groups": {
			"create": {"Groups Administrator", "Global Administrator"},
			"read":   {"Groups Administrator", "Global Reader", "Directory Readers"},
			"update": {"Groups Administrator", "Global Administrator"},
			"delete": {"Groups Administrator", "Global Administrator"},
			"list":   {"Groups Administrator", "Global Reader", "Directory Readers"},
		},
		"conditional_access": {
			"create": {"Conditional Access Administrator", "Security Administrator", "Global Administrator"},
			"read":   {"Conditional Access Administrator", "Security Administrator", "Security Reader", "Global Reader"},
			"update": {"Conditional Access Administrator", "Security Administrator", "Global Administrator"},
			"delete": {"Conditional Access Administrator", "Security Administrator", "Global Administrator"},
			"list":   {"Conditional Access Administrator", "Security Administrator", "Security Reader", "Global Reader"},
		},
		"intune_policies": {
			"create": {"Intune Administrator", "Global Administrator"},
			"read":   {"Intune Administrator", "Global Reader"},
			"update": {"Intune Administrator", "Global Administrator"},
			"delete": {"Intune Administrator", "Global Administrator"},
			"list":   {"Intune Administrator", "Global Reader"},
		},
	}

	if resourceRoles, exists := roleMap[resourceType]; exists {
		if operationRoles, exists := resourceRoles[operation]; exists {
			return operationRoles
		}
	}

	// Default to Global Administrator if no specific mapping exists
	return []string{"Global Administrator"}
}

// ValidateGDAPConfig validates GDAP-specific configuration
func (p *GDAPProvider) ValidateGDAPConfig(config *GDAPConfig) error {
	if config.ClientID == "" {
		return fmt.Errorf("client_id is required for GDAP provider")
	}

	if config.ClientSecret == "" {
		return fmt.Errorf("client_secret is required for GDAP provider")
	}

	if config.PartnerTenantID == "" {
		return fmt.Errorf("partner_tenant_id is required for GDAP provider")
	}

	// Validate that required Partner Center scopes are present
	requiredPartnerScopes := []string{
		"https://api.partnercenter.microsoft.com/user_impersonation",
	}

	for _, requiredScope := range requiredPartnerScopes {
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

// GetGDAPMetrics returns metrics about GDAP relationships and usage
func (p *GDAPProvider) GetGDAPMetrics(ctx context.Context) (*GDAPMetrics, error) {
	relationships, err := p.DiscoverGDAPCustomers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get GDAP relationships: %w", err)
	}

	metrics := &GDAPMetrics{
		TotalRelationships: len(relationships),
		StatusCounts:       make(map[GDAPRelationshipStatus]int),
		RoleCounts:         make(map[string]int),
		ExpiringWithin30:   0,
		CollectedAt:        time.Now(),
	}

	thirtyDaysFromNow := time.Now().AddDate(0, 0, 30)

	for _, rel := range relationships {
		// Count by status
		metrics.StatusCounts[rel.Status]++

		// Count roles
		for _, role := range rel.Roles {
			metrics.RoleCounts[role.RoleName]++
		}

		// Count expiring relationships
		if rel.ExpiresAt.Before(thirtyDaysFromNow) {
			metrics.ExpiringWithin30++
		}
	}

	return metrics, nil
}

// GDAPMetrics provides insights into GDAP relationship health
type GDAPMetrics struct {
	TotalRelationships int                            `json:"total_relationships"`
	StatusCounts       map[GDAPRelationshipStatus]int `json:"status_counts"`
	RoleCounts         map[string]int                 `json:"role_counts"`
	ExpiringWithin30   int                            `json:"expiring_within_30_days"`
	CollectedAt        time.Time                      `json:"collected_at"`
}
