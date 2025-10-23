// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// AdminConsentFlow manages multi-tenant admin consent for MSP client onboarding
type AdminConsentFlow struct {
	config      *MultiTenantConfig
	httpClient  *http.Client
	clientStore ClientTenantStore
}

// MultiTenantConfig represents configuration for multi-tenant MSP application
type MultiTenantConfig struct {
	// CFGMS app registration details (registered in cfgis.onmicrosoft.com)
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret,omitempty"`
	TenantID     string `yaml:"tenant_id"` // cfgis tenant ID

	// Multi-tenant settings
	SupportedAccountTypes string `yaml:"supported_account_types"` // "AzureADMultipleOrgs"
	RequireAdminConsent   bool   `yaml:"require_admin_consent"`   // true for MSP

	// Production URLs
	AdminCallbackURI string `yaml:"admin_callback_uri"` // https://auth.cfgms.com/admin/callback

	// Application permissions (no delegated permissions for MSP)
	ApplicationPermissions []string `yaml:"application_permissions"`
}

// ClientTenant represents a client organization that has consented to CFGMS
type ClientTenant struct {
	ID               string                 `json:"id"`
	TenantID         string                 `json:"tenant_id"`   // Client's Azure AD tenant ID
	TenantName       string                 `json:"tenant_name"` // Client organization name
	DomainName       string                 `json:"domain_name"` // Primary domain (e.g., client.com)
	AdminEmail       string                 `json:"admin_email"` // Admin who consented
	ConsentedAt      time.Time              `json:"consented_at"`
	Status           ClientTenantStatus     `json:"status"`
	ClientIdentifier string                 `json:"client_identifier"` // CFGMS internal client ID
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
}

// ClientTenantStatus represents the consent status of a client tenant
type ClientTenantStatus string

const (
	ClientTenantStatusPending   ClientTenantStatus = "pending"   // Admin consent URL generated, awaiting consent
	ClientTenantStatusConsented ClientTenantStatus = "consented" // Admin has consented
	ClientTenantStatusActive    ClientTenantStatus = "active"    // Fully configured and operational
	ClientTenantStatusSuspended ClientTenantStatus = "suspended" // Temporarily disabled
	ClientTenantStatusRevoked   ClientTenantStatus = "revoked"   // Admin revoked consent
)

// AdminConsentRequest represents a request for admin consent from a client
type AdminConsentRequest struct {
	ClientIdentifier string                 `json:"client_identifier"` // CFGMS internal client ID
	ClientName       string                 `json:"client_name"`       // Display name for client
	RequestedBy      string                 `json:"requested_by"`      // MSP employee who initiated
	State            string                 `json:"state"`             // OAuth2 state parameter
	ExpiresAt        time.Time              `json:"expires_at"`        // Request expiration
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
}

// AdminConsentResult represents the result of an admin consent flow
type AdminConsentResult struct {
	Success          bool              `json:"success"`
	ClientTenant     *ClientTenant     `json:"client_tenant,omitempty"`
	Error            string            `json:"error,omitempty"`
	ErrorDetails     string            `json:"error_details,omitempty"`
	AdminConsentInfo *AdminConsentInfo `json:"admin_consent_info,omitempty"`
}

// AdminConsentInfo contains information from the admin consent callback
type AdminConsentInfo struct {
	TenantID       string    `json:"tenant_id"`       // Client tenant ID from Microsoft
	AdminConsented bool      `json:"admin_consented"` // Whether admin granted consent
	State          string    `json:"state"`           // OAuth2 state parameter
	AdminObjectID  string    `json:"admin_object_id"` // Admin user object ID
	ConsentedAt    time.Time `json:"consented_at"`
}

// ClientTenantStore defines the interface for storing client tenant information
type ClientTenantStore interface {
	// Client tenant management
	StoreClientTenant(client *ClientTenant) error
	GetClientTenant(tenantID string) (*ClientTenant, error)
	GetClientTenantByIdentifier(clientIdentifier string) (*ClientTenant, error)
	ListClientTenants(status ClientTenantStatus) ([]*ClientTenant, error)
	UpdateClientTenantStatus(tenantID string, status ClientTenantStatus) error
	DeleteClientTenant(tenantID string) error

	// Admin consent request management
	StoreAdminConsentRequest(request *AdminConsentRequest) error
	GetAdminConsentRequest(state string) (*AdminConsentRequest, error)
	DeleteAdminConsentRequest(state string) error
}

// NewAdminConsentFlow creates a new admin consent flow manager
func NewAdminConsentFlow(config *MultiTenantConfig, clientStore ClientTenantStore) *AdminConsentFlow {
	return &AdminConsentFlow{
		config:      config,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		clientStore: clientStore,
	}
}

// StartAdminConsentFlow initiates admin consent for a new client tenant
func (f *AdminConsentFlow) StartAdminConsentFlow(ctx context.Context, clientIdentifier, clientName, requestedBy string) (*AdminConsentRequest, string, error) {
	// Generate secure state parameter
	state, err := f.generateState()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate state: %w", err)
	}

	// Create admin consent request
	request := &AdminConsentRequest{
		ClientIdentifier: clientIdentifier,
		ClientName:       clientName,
		RequestedBy:      requestedBy,
		State:            state,
		ExpiresAt:        time.Now().Add(24 * time.Hour), // 24 hour expiry for admin consent
		CreatedAt:        time.Now(),
		Metadata: map[string]interface{}{
			"user_agent":   "CFGMS-AdminConsent/1.0",
			"initiated_at": time.Now().Format(time.RFC3339),
		},
	}

	// Store the request
	if err := f.clientStore.StoreAdminConsentRequest(request); err != nil {
		return nil, "", fmt.Errorf("failed to store admin consent request: %w", err)
	}

	// Generate admin consent URL
	adminConsentURL, err := f.buildAdminConsentURL(state)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build admin consent URL: %w", err)
	}

	return request, adminConsentURL, nil
}

// HandleAdminConsentCallback processes the admin consent callback from Microsoft
func (f *AdminConsentFlow) HandleAdminConsentCallback(ctx context.Context, callbackURL string) (*AdminConsentResult, error) {
	// Parse callback URL
	parsedURL, err := url.Parse(callbackURL)
	if err != nil {
		return &AdminConsentResult{
			Success:      false,
			Error:        "INVALID_CALLBACK_URL",
			ErrorDetails: fmt.Sprintf("Failed to parse callback URL: %v", err),
		}, nil
	}

	query := parsedURL.Query()

	// Check for error in callback
	if errorCode := query.Get("error"); errorCode != "" {
		return &AdminConsentResult{
			Success:      false,
			Error:        errorCode,
			ErrorDetails: query.Get("error_description"),
		}, nil
	}

	// Extract admin consent information
	tenantID := query.Get("tenant")
	adminConsented := query.Get("admin_consent") == "True"
	state := query.Get("state")

	if !adminConsented || tenantID == "" || state == "" {
		return &AdminConsentResult{
			Success:      false,
			Error:        "INVALID_ADMIN_CONSENT",
			ErrorDetails: "Missing required parameters or admin consent not granted",
		}, nil
	}

	// Retrieve admin consent request
	request, err := f.clientStore.GetAdminConsentRequest(state)
	if err != nil {
		return &AdminConsentResult{
			Success:      false,
			Error:        "INVALID_STATE",
			ErrorDetails: fmt.Sprintf("Failed to retrieve admin consent request: %v", err),
		}, nil
	}

	// Validate request hasn't expired
	if time.Now().After(request.ExpiresAt) {
		return &AdminConsentResult{
			Success:      false,
			Error:        "REQUEST_EXPIRED",
			ErrorDetails: "Admin consent request has expired",
		}, nil
	}

	// Create client tenant record
	clientTenant := &ClientTenant{
		ID:               f.generateClientID(),
		TenantID:         tenantID,
		TenantName:       request.ClientName,
		ClientIdentifier: request.ClientIdentifier,
		ConsentedAt:      time.Now(),
		Status:           ClientTenantStatusActive,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		Metadata: map[string]interface{}{
			"consent_requested_by": request.RequestedBy,
			"consent_flow_state":   state,
			"admin_consent_url":    f.config.AdminCallbackURI,
		},
	}

	// Store client tenant
	if err := f.clientStore.StoreClientTenant(clientTenant); err != nil {
		return &AdminConsentResult{
			Success:      false,
			Error:        "STORAGE_FAILED",
			ErrorDetails: fmt.Sprintf("Failed to store client tenant: %v", err),
		}, nil
	}

	// Clean up admin consent request
	if err := f.clientStore.DeleteAdminConsentRequest(state); err != nil {
		// Log warning - we could add a logger field to AdminConsentFlow in the future
		_ = err // Acknowledge error but continue
	}

	// Create admin consent info
	adminConsentInfo := &AdminConsentInfo{
		TenantID:       tenantID,
		AdminConsented: adminConsented,
		State:          state,
		ConsentedAt:    time.Now(),
	}

	return &AdminConsentResult{
		Success:          true,
		ClientTenant:     clientTenant,
		AdminConsentInfo: adminConsentInfo,
	}, nil
}

// GetClientTenantStatus checks the status of a client tenant
func (f *AdminConsentFlow) GetClientTenantStatus(ctx context.Context, clientIdentifier string) (*ClientTenant, error) {
	client, err := f.clientStore.GetClientTenantByIdentifier(clientIdentifier)
	if err != nil {
		return nil, fmt.Errorf("failed to get client tenant: %w", err)
	}

	return client, nil
}

// ActivateClientTenant activates a consented client tenant for production use
func (f *AdminConsentFlow) ActivateClientTenant(ctx context.Context, tenantID string) error {
	return f.clientStore.UpdateClientTenantStatus(tenantID, ClientTenantStatusActive)
}

// SuspendClientTenant temporarily suspends a client tenant
func (f *AdminConsentFlow) SuspendClientTenant(ctx context.Context, tenantID string) error {
	return f.clientStore.UpdateClientTenantStatus(tenantID, ClientTenantStatusSuspended)
}

// RevokeClientTenant marks a client tenant as having revoked consent
func (f *AdminConsentFlow) RevokeClientTenant(ctx context.Context, tenantID string) error {
	return f.clientStore.UpdateClientTenantStatus(tenantID, ClientTenantStatusRevoked)
}

// ListClientTenants returns all client tenants with optional status filter
func (f *AdminConsentFlow) ListClientTenants(ctx context.Context, status ClientTenantStatus) ([]*ClientTenant, error) {
	return f.clientStore.ListClientTenants(status)
}

// Helper methods

// buildAdminConsentURL generates the Microsoft admin consent URL
func (f *AdminConsentFlow) buildAdminConsentURL(state string) (string, error) {
	baseURL := "https://login.microsoftonline.com/common/adminconsent"

	params := url.Values{
		"client_id":    {f.config.ClientID},
		"redirect_uri": {f.config.AdminCallbackURI},
		"state":        {state},
	}

	// Add specific scopes if configured (otherwise Microsoft will use app registration permissions)
	if len(f.config.ApplicationPermissions) > 0 {
		// Note: For admin consent, scopes are usually determined by app registration
		// but can be specified for clarity
		params.Set("scope", "https://graph.microsoft.com/.default")
	}

	adminConsentURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())
	return adminConsentURL, nil
}

// generateState generates a cryptographically secure state parameter
func (f *AdminConsentFlow) generateState() (string, error) {
	randomBytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	state := base64.RawURLEncoding.EncodeToString(randomBytes)
	return state, nil
}

// generateClientID generates a unique client ID for CFGMS internal use
func (f *AdminConsentFlow) generateClientID() string {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to timestamp-based ID if crypto/rand fails
		return fmt.Sprintf("cfgms-client-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("client-%s", base64.RawURLEncoding.EncodeToString(randomBytes))
}

// GetMultiTenantConfig returns the configuration for multi-tenant setup
func (f *AdminConsentFlow) GetMultiTenantConfig() *MultiTenantConfig {
	return f.config
}

// ValidateClientTenant validates that a client tenant is active and usable
func (f *AdminConsentFlow) ValidateClientTenant(ctx context.Context, tenantID string) error {
	client, err := f.clientStore.GetClientTenant(tenantID)
	if err != nil {
		return fmt.Errorf("client tenant not found: %w", err)
	}

	switch client.Status {
	case ClientTenantStatusActive:
		return nil
	case ClientTenantStatusConsented:
		return fmt.Errorf("client tenant not yet activated")
	case ClientTenantStatusSuspended:
		return fmt.Errorf("client tenant is suspended")
	case ClientTenantStatusRevoked:
		return fmt.Errorf("client tenant consent has been revoked")
	case ClientTenantStatusPending:
		return fmt.Errorf("client tenant consent is still pending")
	default:
		return fmt.Errorf("client tenant has unknown status: %s", client.Status)
	}
}
