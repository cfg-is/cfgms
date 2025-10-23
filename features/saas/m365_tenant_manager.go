// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package saas m365_tenant_manager integrates Microsoft 365 multi-tenant
// management with CFGMS tenant system, providing discovery, sync, and
// health monitoring for MSP M365 tenant management.
package saas

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/tenant"
)

// GDAPProvider defines the interface for GDAP operations (avoids import cycle)
type GDAPProvider interface {
	DiscoverGDAPCustomers(ctx context.Context) ([]GDAPRelationship, error)
	ValidateGDAPAccess(ctx context.Context, customerTenantID string, requiredRoles []string) (*GDAPRelationship, error)
}

// GDAPRelationship represents a GDAP relationship (copied to avoid import cycle)
type GDAPRelationship struct {
	RelationshipID   string
	CustomerTenantID string
	CustomerName     string
	Status           string // "active", "pending", "expired", "terminated"
	ExpiresAt        time.Time
}

// M365TenantManager integrates M365 multi-tenant capabilities with CFGMS tenant management
type M365TenantManager struct {
	cfgmsTenantManager *tenant.Manager
	m365Provider       *MicrosoftMultiTenantProvider
	adminConsentFlow   *auth.AdminConsentFlow
	gdapProvider       GDAPProvider
	httpClient         *http.Client
}

// NewM365TenantManager creates a new M365 tenant manager
func NewM365TenantManager(
	cfgmsTenantManager *tenant.Manager,
	m365Provider *MicrosoftMultiTenantProvider,
	adminConsentFlow *auth.AdminConsentFlow,
	gdapProvider GDAPProvider,
) *M365TenantManager {
	return &M365TenantManager{
		cfgmsTenantManager: cfgmsTenantManager,
		m365Provider:       m365Provider,
		adminConsentFlow:   adminConsentFlow,
		gdapProvider:       gdapProvider,
		httpClient:         &http.Client{Timeout: 30 * time.Second},
	}
}

// DiscoverAndSyncTenants discovers M365 tenants and syncs them to CFGMS
func (m *M365TenantManager) DiscoverAndSyncTenants(ctx context.Context, discoveryMethod string) (*M365DiscoveryResult, error) {
	var tenants []TenantInfo
	var err error

	// Discover tenants based on method
	switch discoveryMethod {
	case "admin_consent":
		tenants, err = m.m365Provider.ListAccessibleTenants(ctx)
	case "gdap":
		gdapRelationships, gdapErr := m.gdapProvider.DiscoverGDAPCustomers(ctx)
		if gdapErr != nil {
			return nil, fmt.Errorf("GDAP discovery failed: %w", gdapErr)
		}
		// Convert GDAP relationships to TenantInfo
		tenants = make([]TenantInfo, 0, len(gdapRelationships))
		for _, rel := range gdapRelationships {
			tenants = append(tenants, TenantInfo{
				TenantID:    rel.CustomerTenantID,
				DisplayName: rel.CustomerName,
				HasAccess:   rel.Status == "active",
			})
		}
	default:
		return nil, fmt.Errorf("invalid discovery method: %s", discoveryMethod)
	}

	if err != nil {
		return nil, fmt.Errorf("tenant discovery failed: %w", err)
	}

	// Sync discovered tenants to CFGMS
	syncedCount := 0
	failedCount := 0
	discoveredAt := time.Now()

	for _, m365Tenant := range tenants {
		// Check if tenant already exists
		existing, err := m.getTenantByM365ID(ctx, m365Tenant.TenantID)
		if err == nil && existing != nil {
			// Tenant exists, update metadata
			if updateErr := m.updateTenantMetadata(ctx, existing, &m365Tenant, discoveryMethod, discoveredAt); updateErr != nil {
				failedCount++
				continue
			}
			syncedCount++
			continue
		}

		// Create new CFGMS tenant
		if createErr := m.createCFGMSTenant(ctx, &m365Tenant, discoveryMethod, discoveredAt); createErr != nil {
			failedCount++
			continue
		}
		syncedCount++
	}

	return &M365DiscoveryResult{
		TenantDiscoveryResult: &TenantDiscoveryResult{
			Tenants:      tenants,
			DiscoveredAt: discoveredAt,
			Success:      true,
		},
		Metadata: map[string]interface{}{
			"synced_count": syncedCount,
			"failed_count": failedCount,
			"total_count":  len(tenants),
			"method":       discoveryMethod,
		},
	}, nil
}

// PerformHealthCheck performs health check on an M365 tenant
func (m *M365TenantManager) PerformHealthCheck(ctx context.Context, cfgmsTenantID string) (*TenantHealthResult, error) {
	// Get CFGMS tenant
	cfgmsTenant, err := m.cfgmsTenantManager.GetTenant(ctx, cfgmsTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	// Extract M365 metadata
	m365Metadata, err := m.getM365Metadata(cfgmsTenant)
	if err != nil {
		return nil, fmt.Errorf("failed to get M365 metadata: %w", err)
	}

	healthResult := &TenantHealthResult{
		TenantID:     cfgmsTenantID,
		M365TenantID: m365Metadata.M365TenantID,
		CheckedAt:    time.Now(),
		Checks:       make(map[string]HealthCheckResult),
	}

	// Check 1: Token validity
	tokenCheck := m.checkTokenValidity(ctx, m365Metadata)
	healthResult.Checks["token_validity"] = tokenCheck

	// Check 2: Microsoft Graph API connectivity
	apiCheck := m.checkGraphAPIConnectivity(ctx, m365Metadata.M365TenantID)
	healthResult.Checks["graph_api_connectivity"] = apiCheck

	// Check 3: GDAP relationship status (if applicable)
	if m365Metadata.GDAPRelationshipID != "" {
		gdapCheck := m.checkGDAPRelationship(ctx, m365Metadata.M365TenantID)
		healthResult.Checks["gdap_relationship"] = gdapCheck
	}

	// Determine overall health status
	healthResult.OverallStatus = m.calculateOverallHealth(healthResult.Checks)

	// Update tenant metadata with health status
	m365Metadata.LastHealthCheck = healthResult.CheckedAt
	m365Metadata.HealthStatus = healthResult.OverallStatus
	if healthResult.OverallStatus != tenant.HealthStatusHealthy {
		healthResult.HealthDetails = m.generateHealthDetails(healthResult.Checks)
		m365Metadata.HealthDetails = healthResult.HealthDetails
	}

	// Save updated metadata
	if err := m.saveM365Metadata(ctx, cfgmsTenant, m365Metadata); err != nil {
		return nil, fmt.Errorf("failed to save health status: %w", err)
	}

	return healthResult, nil
}

// BulkHealthCheck performs health checks on all M365 tenants
func (m *M365TenantManager) BulkHealthCheck(ctx context.Context) (*BulkHealthCheckResult, error) {
	// Get all M365 tenants
	m365Tenants, err := m.listM365Tenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list M365 tenants: %w", err)
	}

	result := &BulkHealthCheckResult{
		TotalTenants:   len(m365Tenants),
		CheckedAt:      time.Now(),
		TenantResults:  make(map[string]*TenantHealthResult),
		HealthySummary: &HealthSummary{},
	}

	for _, cfgmsTenant := range m365Tenants {
		healthResult, err := m.PerformHealthCheck(ctx, cfgmsTenant.ID)
		if err != nil {
			result.TenantResults[cfgmsTenant.ID] = &TenantHealthResult{
				TenantID:      cfgmsTenant.ID,
				CheckedAt:     time.Now(),
				OverallStatus: tenant.HealthStatusUnknown,
				HealthDetails: fmt.Sprintf("Health check failed: %v", err),
			}
			result.HealthySummary.UnknownCount++
			continue
		}

		result.TenantResults[cfgmsTenant.ID] = healthResult

		// Update summary
		switch healthResult.OverallStatus {
		case tenant.HealthStatusHealthy:
			result.HealthySummary.HealthyCount++
		case tenant.HealthStatusDegraded:
			result.HealthySummary.DegradedCount++
		case tenant.HealthStatusUnhealthy:
			result.HealthySummary.UnhealthyCount++
		default:
			result.HealthySummary.UnknownCount++
		}
	}

	return result, nil
}

// BulkMetadataUpdate updates metadata for all M365 tenants from Microsoft Graph
func (m *M365TenantManager) BulkMetadataUpdate(ctx context.Context) (*BulkMetadataUpdateResult, error) {
	m365Tenants, err := m.listM365Tenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list M365 tenants: %w", err)
	}

	result := &BulkMetadataUpdateResult{
		TotalTenants: len(m365Tenants),
		UpdatedAt:    time.Now(),
		SuccessCount: 0,
		FailedCount:  0,
	}

	for _, cfgmsTenant := range m365Tenants {
		m365Metadata, err := m.getM365Metadata(cfgmsTenant)
		if err != nil {
			result.FailedCount++
			continue
		}

		// Fetch fresh organization info from Microsoft Graph
		orgInfo, err := m.fetchOrganizationInfo(ctx, m365Metadata.M365TenantID)
		if err != nil {
			result.FailedCount++
			continue
		}

		// Update metadata
		m365Metadata.PrimaryDomain = orgInfo.DefaultDomain
		m365Metadata.CountryCode = orgInfo.CountryCode
		m365Metadata.TenantType = orgInfo.TenantType

		// Save updated metadata
		if err := m.saveM365Metadata(ctx, cfgmsTenant, m365Metadata); err != nil {
			result.FailedCount++
			continue
		}

		result.SuccessCount++
	}

	return result, nil
}

// GetM365TenantStatus retrieves comprehensive M365 tenant status
func (m *M365TenantManager) GetM365TenantStatus(ctx context.Context, cfgmsTenantID string) (*M365TenantStatus, error) {
	cfgmsTenant, err := m.cfgmsTenantManager.GetTenant(ctx, cfgmsTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	m365Metadata, err := m.getM365Metadata(cfgmsTenant)
	if err != nil {
		return nil, fmt.Errorf("failed to get M365 metadata: %w", err)
	}

	status := &M365TenantStatus{
		CFGMSTenantID: cfgmsTenantID,
		M365TenantID:  m365Metadata.M365TenantID,
		TenantName:    cfgmsTenant.Name,
		PrimaryDomain: m365Metadata.PrimaryDomain,
		Status:        cfgmsTenant.Status,
		HealthStatus:  m365Metadata.HealthStatus,
		M365Metadata:  m365Metadata,
		RetrievedAt:   time.Now(),
	}

	return status, nil
}

// Helper methods

func (m *M365TenantManager) getTenantByM365ID(ctx context.Context, m365TenantID string) (*tenant.Tenant, error) {
	// List all tenants and search for M365 tenant ID in metadata
	allTenants, err := m.cfgmsTenantManager.ListTenants(ctx, nil)
	if err != nil {
		return nil, err
	}

	for _, t := range allTenants {
		if m365Metadata, err := m.getM365Metadata(t); err == nil {
			if m365Metadata.M365TenantID == m365TenantID {
				return t, nil
			}
		}
	}

	return nil, fmt.Errorf("tenant not found")
}

func (m *M365TenantManager) createCFGMSTenant(ctx context.Context, m365Tenant *TenantInfo, discoveryMethod string, discoveredAt time.Time) error {
	m365Metadata := &tenant.M365TenantMetadata{
		M365TenantID:    m365Tenant.TenantID,
		PrimaryDomain:   m365Tenant.Domain,
		CountryCode:     m365Tenant.CountryCode,
		TenantType:      m365Tenant.TenantType,
		DiscoveredAt:    discoveredAt,
		DiscoveryMethod: discoveryMethod,
		HealthStatus:    tenant.HealthStatusUnknown,
	}

	metadataJSON, err := json.Marshal(m365Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	req := &tenant.TenantRequest{
		Name:        m365Tenant.DisplayName,
		Description: fmt.Sprintf("M365 Tenant (%s)", m365Tenant.Domain),
		Metadata: map[string]string{
			"m365_metadata": string(metadataJSON),
			"tenant_type":   "m365",
		},
	}

	_, err = m.cfgmsTenantManager.CreateTenant(ctx, req)
	return err
}

func (m *M365TenantManager) updateTenantMetadata(ctx context.Context, cfgmsTenant *tenant.Tenant, m365Tenant *TenantInfo, discoveryMethod string, discoveredAt time.Time) error {
	m365Metadata, err := m.getM365Metadata(cfgmsTenant)
	if err != nil {
		return err
	}

	// Update discovery metadata
	m365Metadata.DiscoveredAt = discoveredAt
	m365Metadata.DiscoveryMethod = discoveryMethod

	// Update organization info if available
	if m365Tenant.Domain != "" {
		m365Metadata.PrimaryDomain = m365Tenant.Domain
	}
	if m365Tenant.CountryCode != "" {
		m365Metadata.CountryCode = m365Tenant.CountryCode
	}

	return m.saveM365Metadata(ctx, cfgmsTenant, m365Metadata)
}

func (m *M365TenantManager) getM365Metadata(cfgmsTenant *tenant.Tenant) (*tenant.M365TenantMetadata, error) {
	metadataJSON, exists := cfgmsTenant.Metadata["m365_metadata"]
	if !exists {
		return nil, fmt.Errorf("M365 metadata not found")
	}

	var metadata tenant.M365TenantMetadata
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal M365 metadata: %w", err)
	}

	return &metadata, nil
}

func (m *M365TenantManager) saveM365Metadata(ctx context.Context, cfgmsTenant *tenant.Tenant, m365Metadata *tenant.M365TenantMetadata) error {
	metadataJSON, err := json.Marshal(m365Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if cfgmsTenant.Metadata == nil {
		cfgmsTenant.Metadata = make(map[string]string)
	}
	cfgmsTenant.Metadata["m365_metadata"] = string(metadataJSON)

	req := &tenant.TenantRequest{
		Name:        cfgmsTenant.Name,
		Description: cfgmsTenant.Description,
		Metadata:    cfgmsTenant.Metadata,
	}

	_, err = m.cfgmsTenantManager.UpdateTenant(ctx, cfgmsTenant.ID, req)
	return err
}

func (m *M365TenantManager) listM365Tenants(ctx context.Context) ([]*tenant.Tenant, error) {
	allTenants, err := m.cfgmsTenantManager.ListTenants(ctx, nil)
	if err != nil {
		return nil, err
	}

	m365Tenants := make([]*tenant.Tenant, 0)
	for _, t := range allTenants {
		if tenantType, exists := t.Metadata["tenant_type"]; exists && tenantType == "m365" {
			m365Tenants = append(m365Tenants, t)
		}
	}

	return m365Tenants, nil
}

func (m *M365TenantManager) checkTokenValidity(ctx context.Context, m365Metadata *tenant.M365TenantMetadata) HealthCheckResult {
	now := time.Now()

	if m365Metadata.TokenExpiresAt.IsZero() {
		return HealthCheckResult{
			Name:    "token_validity",
			Status:  tenant.HealthStatusUnknown,
			Message: "Token expiration time not set",
		}
	}

	if now.After(m365Metadata.TokenExpiresAt) {
		return HealthCheckResult{
			Name:    "token_validity",
			Status:  tenant.HealthStatusUnhealthy,
			Message: fmt.Sprintf("Token expired at %s", m365Metadata.TokenExpiresAt.Format(time.RFC3339)),
		}
	}

	// Warn if token expires within 7 days
	sevenDaysFromNow := now.AddDate(0, 0, 7)
	if m365Metadata.TokenExpiresAt.Before(sevenDaysFromNow) {
		return HealthCheckResult{
			Name:    "token_validity",
			Status:  tenant.HealthStatusDegraded,
			Message: fmt.Sprintf("Token expires soon at %s", m365Metadata.TokenExpiresAt.Format(time.RFC3339)),
		}
	}

	return HealthCheckResult{
		Name:    "token_validity",
		Status:  tenant.HealthStatusHealthy,
		Message: fmt.Sprintf("Token valid until %s", m365Metadata.TokenExpiresAt.Format(time.RFC3339)),
	}
}

func (m *M365TenantManager) checkGraphAPIConnectivity(ctx context.Context, m365TenantID string) HealthCheckResult {
	// Attempt to read tenant information from Graph API
	result, err := m.m365Provider.ReadFromTenant(ctx, m365TenantID, "organization", m365TenantID)
	if err != nil {
		return HealthCheckResult{
			Name:    "graph_api_connectivity",
			Status:  tenant.HealthStatusUnhealthy,
			Message: fmt.Sprintf("Graph API connection failed: %v", err),
		}
	}

	if !result.Success {
		return HealthCheckResult{
			Name:    "graph_api_connectivity",
			Status:  tenant.HealthStatusUnhealthy,
			Message: fmt.Sprintf("Graph API returned error: %s", result.Error),
		}
	}

	return HealthCheckResult{
		Name:    "graph_api_connectivity",
		Status:  tenant.HealthStatusHealthy,
		Message: "Graph API connectivity verified",
	}
}

func (m *M365TenantManager) checkGDAPRelationship(ctx context.Context, m365TenantID string) HealthCheckResult {
	// Validate GDAP access
	relationship, err := m.gdapProvider.ValidateGDAPAccess(ctx, m365TenantID, nil)
	if err != nil {
		return HealthCheckResult{
			Name:    "gdap_relationship",
			Status:  tenant.HealthStatusUnhealthy,
			Message: fmt.Sprintf("GDAP validation failed: %v", err),
		}
	}

	if relationship.Status != "active" {
		return HealthCheckResult{
			Name:    "gdap_relationship",
			Status:  tenant.HealthStatusDegraded,
			Message: fmt.Sprintf("GDAP relationship status: %s", relationship.Status),
		}
	}

	// Check if relationship is expiring soon
	thirtyDaysFromNow := time.Now().AddDate(0, 0, 30)
	if relationship.ExpiresAt.Before(thirtyDaysFromNow) {
		return HealthCheckResult{
			Name:    "gdap_relationship",
			Status:  tenant.HealthStatusDegraded,
			Message: fmt.Sprintf("GDAP relationship expires soon at %s", relationship.ExpiresAt.Format(time.RFC3339)),
		}
	}

	return HealthCheckResult{
		Name:    "gdap_relationship",
		Status:  tenant.HealthStatusHealthy,
		Message: fmt.Sprintf("GDAP relationship active until %s", relationship.ExpiresAt.Format(time.RFC3339)),
	}
}

func (m *M365TenantManager) calculateOverallHealth(checks map[string]HealthCheckResult) tenant.HealthStatus {
	hasUnhealthy := false
	hasDegraded := false

	for _, check := range checks {
		switch check.Status {
		case tenant.HealthStatusUnhealthy:
			hasUnhealthy = true
		case tenant.HealthStatusDegraded:
			hasDegraded = true
		}
	}

	if hasUnhealthy {
		return tenant.HealthStatusUnhealthy
	}
	if hasDegraded {
		return tenant.HealthStatusDegraded
	}
	return tenant.HealthStatusHealthy
}

func (m *M365TenantManager) generateHealthDetails(checks map[string]HealthCheckResult) string {
	details := ""
	for _, check := range checks {
		if check.Status != tenant.HealthStatusHealthy {
			if details != "" {
				details += "; "
			}
			details += fmt.Sprintf("%s: %s", check.Name, check.Message)
		}
	}
	return details
}

func (m *M365TenantManager) fetchOrganizationInfo(ctx context.Context, m365TenantID string) (*OrganizationInfo, error) {
	result, err := m.m365Provider.ReadFromTenant(ctx, m365TenantID, "organization", m365TenantID)
	if err != nil {
		return nil, err
	}

	if !result.Success {
		return nil, fmt.Errorf("failed to fetch organization info: %s", result.Error)
	}

	// Parse organization data
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid organization data format")
	}

	orgInfo := &OrganizationInfo{
		TenantID: m365TenantID,
	}

	// Extract relevant fields
	if verifiedDomains, ok := data["verifiedDomains"].([]interface{}); ok {
		for _, domain := range verifiedDomains {
			if domainMap, ok := domain.(map[string]interface{}); ok {
				if isDefault, ok := domainMap["isDefault"].(bool); ok && isDefault {
					if name, ok := domainMap["name"].(string); ok {
						orgInfo.DefaultDomain = name
						break
					}
				}
			}
		}
	}

	if countryCode, ok := data["countryLetterCode"].(string); ok {
		orgInfo.CountryCode = countryCode
	}

	orgInfo.TenantType = "AAD" // Default to Azure AD

	return orgInfo, nil
}

// Result types

// M365DiscoveryResult extends TenantDiscoveryResult with M365-specific sync metadata
type M365DiscoveryResult struct {
	*TenantDiscoveryResult
	Metadata map[string]interface{}
}

// TenantHealthResult represents health check results for a tenant
type TenantHealthResult struct {
	TenantID      string
	M365TenantID  string
	CheckedAt     time.Time
	OverallStatus tenant.HealthStatus
	HealthDetails string
	Checks        map[string]HealthCheckResult
}

// HealthCheckResult represents a single health check result
type HealthCheckResult struct {
	Name    string
	Status  tenant.HealthStatus
	Message string
}

// BulkHealthCheckResult aggregates health check results for multiple tenants
type BulkHealthCheckResult struct {
	TotalTenants   int
	CheckedAt      time.Time
	TenantResults  map[string]*TenantHealthResult
	HealthySummary *HealthSummary
}

// HealthSummary provides health statistics summary
type HealthSummary struct {
	HealthyCount   int
	DegradedCount  int
	UnhealthyCount int
	UnknownCount   int
}

// BulkMetadataUpdateResult represents bulk metadata update results
type BulkMetadataUpdateResult struct {
	TotalTenants int
	UpdatedAt    time.Time
	SuccessCount int
	FailedCount  int
}

// M365TenantStatus represents comprehensive M365 tenant status
type M365TenantStatus struct {
	CFGMSTenantID string
	M365TenantID  string
	TenantName    string
	PrimaryDomain string
	Status        tenant.TenantStatus
	HealthStatus  tenant.HealthStatus
	M365Metadata  *tenant.M365TenantMetadata
	RetrievedAt   time.Time
}

// OrganizationInfo represents Microsoft Graph organization information
type OrganizationInfo struct {
	TenantID      string
	DefaultDomain string
	CountryCode   string
	TenantType    string
}
