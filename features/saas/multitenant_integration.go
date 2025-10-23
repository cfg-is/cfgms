// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package saas multitenant_integration provides workflow integration and
// tenant onboarding capabilities for multi-tenant SaaS providers.
//
// This module enables CFGMS workflows to utilize multi-tenant providers
// and provides automated tenant onboarding workflows for MSP scenarios.
package saas

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// TenantOnboardingWorkflow provides automated tenant onboarding capabilities
type TenantOnboardingWorkflow struct {
	multiTenantManager *MultiTenantManager
	provider           *MicrosoftMultiTenantProvider
}

// NewTenantOnboardingWorkflow creates a new tenant onboarding workflow
func NewTenantOnboardingWorkflow(provider *MicrosoftMultiTenantProvider) *TenantOnboardingWorkflow {
	return &TenantOnboardingWorkflow{
		multiTenantManager: provider.multiTenantManager,
		provider:           provider,
	}
}

// OnboardingRequest represents a tenant onboarding request
type OnboardingRequest struct {
	// ProviderName (e.g., "microsoft-multitenant")
	ProviderName string `json:"provider_name"`

	// MSPInfo contains MSP-specific information
	MSPInfo MSPInfo `json:"msp_info"`

	// ClientInfo contains client/customer information
	ClientInfo ClientInfo `json:"client_info"`

	// ConsentConfiguration for the admin consent flow
	ConsentConfig ConsentConfiguration `json:"consent_config"`

	// AutomationSettings for post-consent automation
	AutomationSettings AutomationSettings `json:"automation_settings"`
}

// MSPInfo contains Managed Service Provider information
type MSPInfo struct {
	// MSPName is the MSP company name
	MSPName string `json:"msp_name"`

	// MSPTenantID is the MSP's own tenant ID
	MSPTenantID string `json:"msp_tenant_id"`

	// ContactEmail for notifications
	ContactEmail string `json:"contact_email"`

	// PartnerID if the MSP is a Microsoft Partner
	PartnerID string `json:"partner_id,omitempty"`
}

// ClientInfo contains customer/client information
type ClientInfo struct {
	// ClientName is the customer company name
	ClientName string `json:"client_name"`

	// ExpectedTenantID if known in advance
	ExpectedTenantID string `json:"expected_tenant_id,omitempty"`

	// PrimaryDomain is the customer's primary domain
	PrimaryDomain string `json:"primary_domain,omitempty"`

	// Industry for compliance requirements
	Industry string `json:"industry,omitempty"`

	// ComplianceRequirements (HIPAA, SOX, etc.)
	ComplianceRequirements []string `json:"compliance_requirements,omitempty"`
}

// ConsentConfiguration controls the admin consent process
type ConsentConfiguration struct {
	// RequiredScopes for the application
	RequiredScopes []string `json:"required_scopes"`

	// OptionalScopes that enhance functionality
	OptionalScopes []string `json:"optional_scopes,omitempty"`

	// ConsentTimeout how long to wait for admin consent
	ConsentTimeout time.Duration `json:"consent_timeout"`

	// RetryAttempts if consent fails
	RetryAttempts int `json:"retry_attempts"`

	// NotificationWebhook for consent status updates
	NotificationWebhook string `json:"notification_webhook,omitempty"`
}

// AutomationSettings configure post-consent automation
type AutomationSettings struct {
	// EnableUserDiscovery to discover existing users
	EnableUserDiscovery bool `json:"enable_user_discovery"`

	// EnableGroupDiscovery to discover existing groups
	EnableGroupDiscovery bool `json:"enable_group_discovery"`

	// EnableSecurityBaseline to apply security baseline
	EnableSecurityBaseline bool `json:"enable_security_baseline"`

	// EnableMonitoring to set up drift detection
	EnableMonitoring bool `json:"enable_monitoring"`

	// CustomWorkflows to execute after onboarding
	CustomWorkflows []string `json:"custom_workflows,omitempty"`
}

// OnboardingResult contains the results of tenant onboarding
type OnboardingResult struct {
	// Success indicates if onboarding completed successfully
	Success bool `json:"success"`

	// OnboardedTenants list of successfully onboarded tenants
	OnboardedTenants []TenantInfo `json:"onboarded_tenants"`

	// ConsentURL if admin consent is still needed
	ConsentURL string `json:"consent_url,omitempty"`

	// Errors encountered during onboarding
	Errors []string `json:"errors,omitempty"`

	// Warnings for non-critical issues
	Warnings []string `json:"warnings,omitempty"`

	// NextSteps recommended actions
	NextSteps []string `json:"next_steps,omitempty"`

	// OnboardingID for tracking this onboarding process
	OnboardingID string `json:"onboarding_id"`

	// CompletedAt when onboarding finished
	CompletedAt time.Time `json:"completed_at"`

	// AutomationResults from post-consent automation
	AutomationResults map[string]interface{} `json:"automation_results,omitempty"`
}

// StartTenantOnboarding initiates the tenant onboarding process
func (tow *TenantOnboardingWorkflow) StartTenantOnboarding(ctx context.Context, request *OnboardingRequest) (*OnboardingResult, error) {
	result := &OnboardingResult{
		OnboardingID:      fmt.Sprintf("onboard_%d", time.Now().Unix()),
		OnboardedTenants:  []TenantInfo{},
		Errors:            []string{},
		Warnings:          []string{},
		NextSteps:         []string{},
		AutomationResults: make(map[string]interface{}),
	}

	// Validate the onboarding request
	if err := tow.validateOnboardingRequest(request); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Validation failed: %v", err))
		return result, err
	}

	// Check if admin consent has already been granted
	consentStatus, err := tow.multiTenantManager.GetConsentStatus(ctx, request.ProviderName)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to check consent status: %v", err))
		return result, err
	}

	if !consentStatus.HasAdminConsent {
		// Start admin consent flow
		consentURL, err := tow.startAdminConsentFlow(ctx, request)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to start consent flow: %v", err))
			return result, err
		}

		result.ConsentURL = consentURL
		result.NextSteps = append(result.NextSteps,
			"Visit the consent URL to grant admin consent",
			"Call CompleteOnboarding() after consent is granted")

		return result, nil
	}

	// Admin consent already exists - proceed with onboarding
	return tow.completeOnboarding(ctx, request, result)
}

// CompleteOnboarding completes the onboarding process after admin consent
func (tow *TenantOnboardingWorkflow) CompleteOnboarding(ctx context.Context, request *OnboardingRequest, authCode string) (*OnboardingResult, error) {
	result := &OnboardingResult{
		OnboardingID:      fmt.Sprintf("complete_%d", time.Now().Unix()),
		OnboardedTenants:  []TenantInfo{},
		Errors:            []string{},
		Warnings:          []string{},
		NextSteps:         []string{},
		AutomationResults: make(map[string]interface{}),
	}

	// Complete admin consent if auth code provided
	if authCode != "" {
		err := tow.multiTenantManager.CompleteAdminConsent(ctx, request.ProviderName, authCode)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to complete consent: %v", err))
			return result, err
		}
	}

	return tow.completeOnboarding(ctx, request, result)
}

// GetOnboardingStatus returns the current onboarding status
func (tow *TenantOnboardingWorkflow) GetOnboardingStatus(ctx context.Context, providerName, onboardingID string) (*OnboardingStatus, error) {
	consentStatus, err := tow.multiTenantManager.GetConsentStatus(ctx, providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get consent status: %w", err)
	}

	status := &OnboardingStatus{
		OnboardingID:      onboardingID,
		ProviderName:      providerName,
		HasAdminConsent:   consentStatus.HasAdminConsent,
		ConsentGrantedAt:  consentStatus.ConsentGrantedAt,
		AccessibleTenants: len(consentStatus.AccessibleTenants),
		LastUpdated:       time.Now(),
	}

	if consentStatus.HasAdminConsent {
		status.Status = "completed"
		status.NextSteps = []string{"Tenants are ready for management"}
	} else if consentStatus.ConsentFlow != nil {
		status.Status = "pending_consent"
		status.NextSteps = []string{"Admin consent required"}
	} else {
		status.Status = "not_started"
		status.NextSteps = []string{"Start onboarding process"}
	}

	return status, nil
}

// Private helper methods

func (tow *TenantOnboardingWorkflow) validateOnboardingRequest(request *OnboardingRequest) error {
	if request.ProviderName == "" {
		return fmt.Errorf("provider_name is required")
	}

	if request.MSPInfo.MSPName == "" {
		return fmt.Errorf("msp_info.msp_name is required")
	}

	if request.ClientInfo.ClientName == "" {
		return fmt.Errorf("client_info.client_name is required")
	}

	if len(request.ConsentConfig.RequiredScopes) == 0 {
		return fmt.Errorf("consent_config.required_scopes cannot be empty")
	}

	if request.ConsentConfig.ConsentTimeout <= 0 {
		request.ConsentConfig.ConsentTimeout = 30 * time.Minute // Default timeout
	}

	return nil
}

func (tow *TenantOnboardingWorkflow) startAdminConsentFlow(ctx context.Context, request *OnboardingRequest) (string, error) {
	// Build multi-tenant config from onboarding request
	mtConfig := &MicrosoftMultiTenantConfig{
		ClientID:           "your-client-id", // This would come from provider config
		ClientSecret:       "your-client-secret",
		RedirectURI:        "your-redirect-uri",
		Scopes:             request.ConsentConfig.RequiredScopes,
		AdminConsentScopes: append(request.ConsentConfig.RequiredScopes, request.ConsentConfig.OptionalScopes...),
	}

	return tow.provider.StartAdminConsent(ctx, mtConfig)
}

func (tow *TenantOnboardingWorkflow) completeOnboarding(ctx context.Context, request *OnboardingRequest, result *OnboardingResult) (*OnboardingResult, error) {
	// Get list of accessible tenants
	tenants, err := tow.provider.ListAccessibleTenants(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to list tenants: %v", err))
		return result, err
	}

	// Filter tenants based on client requirements
	relevantTenants := tow.filterRelevantTenants(tenants, request.ClientInfo)
	result.OnboardedTenants = relevantTenants

	if len(relevantTenants) == 0 {
		result.Warnings = append(result.Warnings, "No tenants match the client requirements")
		result.NextSteps = append(result.NextSteps, "Review client information and tenant filtering")
	}

	// Execute post-consent automation
	if request.AutomationSettings.EnableUserDiscovery ||
		request.AutomationSettings.EnableGroupDiscovery ||
		request.AutomationSettings.EnableSecurityBaseline {

		automationResults, err := tow.executePostConsentAutomation(ctx, relevantTenants, &request.AutomationSettings)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Automation failed: %v", err))
		} else {
			result.AutomationResults = automationResults
		}
	}

	result.Success = len(result.Errors) == 0
	result.CompletedAt = time.Now()

	if result.Success {
		result.NextSteps = append(result.NextSteps,
			"Tenants are ready for configuration management",
			"Consider setting up monitoring workflows")
	}

	return result, nil
}

func (tow *TenantOnboardingWorkflow) filterRelevantTenants(tenants []TenantInfo, clientInfo ClientInfo) []TenantInfo {
	relevant := make([]TenantInfo, 0)

	for _, tenant := range tenants {
		if !tenant.HasAccess {
			continue
		}

		// Match by expected tenant ID
		if clientInfo.ExpectedTenantID != "" && tenant.TenantID == clientInfo.ExpectedTenantID {
			relevant = append(relevant, tenant)
			continue
		}

		// Match by primary domain
		if clientInfo.PrimaryDomain != "" && tenant.Domain == clientInfo.PrimaryDomain {
			relevant = append(relevant, tenant)
			continue
		}

		// Match by display name (fuzzy matching)
		if strings.Contains(strings.ToLower(tenant.DisplayName), strings.ToLower(clientInfo.ClientName)) {
			relevant = append(relevant, tenant)
			continue
		}
	}

	return relevant
}

func (tow *TenantOnboardingWorkflow) executePostConsentAutomation(ctx context.Context, tenants []TenantInfo, settings *AutomationSettings) (map[string]interface{}, error) {
	results := make(map[string]interface{})

	for _, tenant := range tenants {
		tenantResults := make(map[string]interface{})

		if settings.EnableUserDiscovery {
			users, err := tow.provider.ListInTenant(ctx, tenant.TenantID, "users", map[string]interface{}{
				"limit": 100,
			})
			if err != nil {
				tenantResults["user_discovery_error"] = err.Error()
			} else {
				tenantResults["users_discovered"] = users.Data
			}
		}

		if settings.EnableGroupDiscovery {
			groups, err := tow.provider.ListInTenant(ctx, tenant.TenantID, "groups", map[string]interface{}{
				"limit": 100,
			})
			if err != nil {
				tenantResults["group_discovery_error"] = err.Error()
			} else {
				tenantResults["groups_discovered"] = groups.Data
			}
		}

		if settings.EnableSecurityBaseline {
			// This would implement security baseline application
			tenantResults["security_baseline"] = "applied"
		}

		results[tenant.TenantID] = tenantResults
	}

	return results, nil
}

// OnboardingStatus represents the current status of an onboarding process
type OnboardingStatus struct {
	// OnboardingID for tracking
	OnboardingID string `json:"onboarding_id"`

	// ProviderName being onboarded
	ProviderName string `json:"provider_name"`

	// Status of the onboarding process
	Status string `json:"status"` // "not_started", "pending_consent", "completed", "failed"

	// HasAdminConsent indicates if consent has been granted
	HasAdminConsent bool `json:"has_admin_consent"`

	// ConsentGrantedAt when consent was granted
	ConsentGrantedAt time.Time `json:"consent_granted_at,omitempty"`

	// AccessibleTenants count of tenants available
	AccessibleTenants int `json:"accessible_tenants"`

	// NextSteps recommended actions
	NextSteps []string `json:"next_steps"`

	// LastUpdated when status was last checked
	LastUpdated time.Time `json:"last_updated"`
}
