// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package entra_application

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
)

// entraApplicationModule implements the Module interface for Entra ID application management
type entraApplicationModule struct {
	authProvider auth.Provider
	graphClient  graph.Client
}

// New creates a new instance of the Entra Application module
func New(authProvider auth.Provider, graphClient graph.Client) modules.Module {
	return &entraApplicationModule{
		authProvider: authProvider,
		graphClient:  graphClient,
	}
}

// EntraApplicationConfig represents the configuration for an Entra ID application registration
type EntraApplicationConfig struct {
	// Core application properties
	DisplayName    string `yaml:"display_name"`
	Description    string `yaml:"description,omitempty"`
	SignInAudience string `yaml:"sign_in_audience"` // AzureADMyOrg, AzureADMultipleOrgs, AzureADandPersonalMicrosoftAccount, PersonalMicrosoftAccount

	// Application URLs
	IdentifierUris []string      `yaml:"identifier_uris,omitempty"`
	RedirectUris   *RedirectUris `yaml:"redirect_uris,omitempty"`
	LogoutUrl      string        `yaml:"logout_url,omitempty"`

	// API permissions and scopes
	RequiredResourceAccess []ResourceAccess `yaml:"required_resource_access,omitempty"`
	OAuth2Permissions      []OAuth2Scope    `yaml:"oauth2_permissions,omitempty"`
	AppRoles               []AppRole        `yaml:"app_roles,omitempty"`

	// Authentication settings
	PasswordCredentials []PasswordCredential `yaml:"password_credentials,omitempty"`
	KeyCredentials      []KeyCredential      `yaml:"key_credentials,omitempty"`

	// API settings
	AcceptMappedClaims          bool     `yaml:"accept_mapped_claims,omitempty"`
	KnownClientApplications     []string `yaml:"known_client_applications,omitempty"`
	PreAuthorizedApplications   []string `yaml:"pre_authorized_applications,omitempty"`
	RequestedAccessTokenVersion int      `yaml:"requested_access_token_version,omitempty"`

	// Optional claims
	OptionalClaims *OptionalClaims `yaml:"optional_claims,omitempty"`

	// Branding
	PublisherDomain string   `yaml:"publisher_domain,omitempty"`
	Tags            []string `yaml:"tags,omitempty"`

	// Service Principal settings
	CreateServicePrincipal   bool                    `yaml:"create_service_principal,omitempty"`
	ServicePrincipalSettings *ServicePrincipalConfig `yaml:"service_principal_settings,omitempty"`

	// Tenant configuration
	TenantID string `yaml:"tenant_id"`

	// Managed fields - controls which fields Set() will modify
	ManagedFieldsList []string `yaml:"managed_fields,omitempty"`
}

// RedirectUris represents redirect URIs for different platforms
type RedirectUris struct {
	Web     []string `yaml:"web,omitempty"`
	Spa     []string `yaml:"spa,omitempty"`
	Mobile  []string `yaml:"mobile,omitempty"`
	Desktop []string `yaml:"desktop,omitempty"`
}

// ResourceAccess represents required permissions to a resource (API)
type ResourceAccess struct {
	ResourceAppId  string            `yaml:"resource_app_id"`
	ResourceAccess []PermissionScope `yaml:"resource_access"`
}

// PermissionScope represents a specific permission
type PermissionScope struct {
	ID   string `yaml:"id"`   // Permission ID (UUID)
	Type string `yaml:"type"` // "Role" or "Scope"
}

// OAuth2Scope represents an OAuth2 permission scope exposed by the application
type OAuth2Scope struct {
	ID                      string `yaml:"id"`
	AdminConsentDisplayName string `yaml:"admin_consent_display_name"`
	AdminConsentDescription string `yaml:"admin_consent_description"`
	UserConsentDisplayName  string `yaml:"user_consent_display_name,omitempty"`
	UserConsentDescription  string `yaml:"user_consent_description,omitempty"`
	Value                   string `yaml:"value"`
	Type                    string `yaml:"type"` // "Admin", "User"
	IsEnabled               bool   `yaml:"is_enabled"`
}

// AppRole represents an application role that can be assigned to users, groups, or service principals
type AppRole struct {
	ID                 string   `yaml:"id"`
	DisplayName        string   `yaml:"display_name"`
	Description        string   `yaml:"description"`
	Value              string   `yaml:"value"`
	AllowedMemberTypes []string `yaml:"allowed_member_types"` // "User", "Application"
	IsEnabled          bool     `yaml:"is_enabled"`
}

// PasswordCredential represents a password (client secret) credential
type PasswordCredential struct {
	DisplayName string `yaml:"display_name"`
	EndDateTime string `yaml:"end_date_time,omitempty"` // ISO 8601 format
	SecretText  string `yaml:"secret_text,omitempty"`   // Only used during creation
}

// KeyCredential represents a certificate credential
type KeyCredential struct {
	DisplayName string `yaml:"display_name"`
	EndDateTime string `yaml:"end_date_time,omitempty"`
	Type        string `yaml:"type"`          // "AsymmetricX509Cert", "X509CertAndPassword"
	Usage       string `yaml:"usage"`         // "Sign", "Verify"
	Key         string `yaml:"key,omitempty"` // Base64-encoded certificate
	KeyId       string `yaml:"key_id,omitempty"`
}

// OptionalClaims represents optional claims configuration
type OptionalClaims struct {
	IdToken     []OptionalClaim `yaml:"id_token,omitempty"`
	AccessToken []OptionalClaim `yaml:"access_token,omitempty"`
	Saml2Token  []OptionalClaim `yaml:"saml2_token,omitempty"`
}

// OptionalClaim represents a single optional claim
type OptionalClaim struct {
	Name                 string                  `yaml:"name"`
	Source               string                  `yaml:"source,omitempty"`
	Essential            bool                    `yaml:"essential,omitempty"`
	AdditionalProperties []OptionalClaimProperty `yaml:"additional_properties,omitempty"`
}

// OptionalClaimProperty represents additional properties for optional claims
type OptionalClaimProperty struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// ServicePrincipalConfig represents configuration for the associated service principal
type ServicePrincipalConfig struct {
	AccountEnabled             bool     `yaml:"account_enabled"`
	AppRoleAssignmentRequired  bool     `yaml:"app_role_assignment_required,omitempty"`
	ServicePrincipalType       string   `yaml:"service_principal_type,omitempty"` // "Application", "Legacy", "SocialIdp"
	Tags                       []string `yaml:"tags,omitempty"`
	PreferredSingleSignOnMode  string   `yaml:"preferred_single_sign_on_mode,omitempty"`
	ReplyUrls                  []string `yaml:"reply_urls,omitempty"`
	NotificationEmailAddresses []string `yaml:"notification_email_addresses,omitempty"`
}

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *EntraApplicationConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"display_name":     c.DisplayName,
		"sign_in_audience": c.SignInAudience,
		"tenant_id":        c.TenantID,
	}

	if c.Description != "" {
		result["description"] = c.Description
	}
	if len(c.IdentifierUris) > 0 {
		result["identifier_uris"] = c.IdentifierUris
	}
	if c.RedirectUris != nil {
		result["redirect_uris"] = c.RedirectUris
	}
	if c.LogoutUrl != "" {
		result["logout_url"] = c.LogoutUrl
	}
	if len(c.RequiredResourceAccess) > 0 {
		result["required_resource_access"] = c.RequiredResourceAccess
	}
	if len(c.OAuth2Permissions) > 0 {
		result["oauth2_permissions"] = c.OAuth2Permissions
	}
	if len(c.AppRoles) > 0 {
		result["app_roles"] = c.AppRoles
	}
	if len(c.PasswordCredentials) > 0 {
		// Remove secret text from comparison for security
		sanitizedCreds := make([]PasswordCredential, len(c.PasswordCredentials))
		for i, cred := range c.PasswordCredentials {
			sanitizedCreds[i] = PasswordCredential{
				DisplayName: cred.DisplayName,
				EndDateTime: cred.EndDateTime,
			}
		}
		result["password_credentials"] = sanitizedCreds
	}
	if len(c.KeyCredentials) > 0 {
		result["key_credentials"] = c.KeyCredentials
	}
	if c.OptionalClaims != nil {
		result["optional_claims"] = c.OptionalClaims
	}
	if c.CreateServicePrincipal {
		result["create_service_principal"] = c.CreateServicePrincipal
		if c.ServicePrincipalSettings != nil {
			result["service_principal_settings"] = c.ServicePrincipalSettings
		}
	}

	return result
}

// ToYAML serializes the configuration to YAML for export/storage
func (c *EntraApplicationConfig) ToYAML() ([]byte, error) {
	// Create a copy without sensitive data for export
	exportConfig := *c
	if len(exportConfig.PasswordCredentials) > 0 {
		sanitizedCreds := make([]PasswordCredential, len(c.PasswordCredentials))
		for i, cred := range c.PasswordCredentials {
			sanitizedCreds[i] = PasswordCredential{
				DisplayName: cred.DisplayName,
				EndDateTime: cred.EndDateTime,
				// SecretText is omitted
			}
		}
		exportConfig.PasswordCredentials = sanitizedCreds
	}
	return yaml.Marshal(&exportConfig)
}

// FromYAML deserializes YAML data into the configuration
func (c *EntraApplicationConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate ensures the configuration is valid
func (c *EntraApplicationConfig) Validate() error {
	if c.DisplayName == "" {
		return fmt.Errorf("display_name is required")
	}

	if c.SignInAudience == "" {
		return fmt.Errorf("sign_in_audience is required")
	}

	if c.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}

	// Validate sign-in audience
	validAudiences := map[string]bool{
		"AzureADMyOrg":                       true,
		"AzureADMultipleOrgs":                true,
		"AzureADandPersonalMicrosoftAccount": true,
		"PersonalMicrosoftAccount":           true,
	}
	if !validAudiences[c.SignInAudience] {
		return fmt.Errorf("invalid sign_in_audience: %s", c.SignInAudience)
	}

	// Validate app roles
	for i, role := range c.AppRoles {
		if role.DisplayName == "" {
			return fmt.Errorf("app_role %d: display_name is required", i)
		}
		if role.Value == "" {
			return fmt.Errorf("app_role %d: value is required", i)
		}
		if len(role.AllowedMemberTypes) == 0 {
			return fmt.Errorf("app_role %d: at least one allowed_member_type is required", i)
		}
	}

	// Validate OAuth2 permissions
	for i, permission := range c.OAuth2Permissions {
		if permission.AdminConsentDisplayName == "" {
			return fmt.Errorf("oauth2_permission %d: admin_consent_display_name is required", i)
		}
		if permission.Value == "" {
			return fmt.Errorf("oauth2_permission %d: value is required", i)
		}
	}

	return nil
}

// GetManagedFields returns the list of fields this configuration manages
func (c *EntraApplicationConfig) GetManagedFields() []string {
	// If explicitly specified, use those fields
	if len(c.ManagedFieldsList) > 0 {
		return c.ManagedFieldsList
	}

	// Default managed fields based on what's configured
	fields := []string{"display_name", "sign_in_audience"}

	if c.Description != "" {
		fields = append(fields, "description")
	}
	if len(c.IdentifierUris) > 0 {
		fields = append(fields, "identifier_uris")
	}
	if c.RedirectUris != nil {
		fields = append(fields, "redirect_uris")
	}
	if len(c.RequiredResourceAccess) > 0 {
		fields = append(fields, "required_resource_access")
	}
	if len(c.OAuth2Permissions) > 0 {
		fields = append(fields, "oauth2_permissions")
	}
	if len(c.AppRoles) > 0 {
		fields = append(fields, "app_roles")
	}
	if len(c.PasswordCredentials) > 0 {
		fields = append(fields, "password_credentials")
	}
	if len(c.KeyCredentials) > 0 {
		fields = append(fields, "key_credentials")
	}
	if c.CreateServicePrincipal {
		fields = append(fields, "create_service_principal")
	}

	return fields
}

// Set creates or updates an Entra ID application according to the configuration
func (m *entraApplicationModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	// Convert ConfigState to EntraApplicationConfig
	configMap := config.AsMap()
	appConfig := &EntraApplicationConfig{}

	// Map basic fields
	if displayName, ok := configMap["display_name"].(string); ok {
		appConfig.DisplayName = displayName
	}
	if description, ok := configMap["description"].(string); ok {
		appConfig.Description = description
	}
	if signInAudience, ok := configMap["sign_in_audience"].(string); ok {
		appConfig.SignInAudience = signInAudience
	}
	if tenantID, ok := configMap["tenant_id"].(string); ok {
		appConfig.TenantID = tenantID
	}

	// Map complex fields (simplified mapping - would need proper type conversion)
	if identifierUris, ok := configMap["identifier_uris"].([]string); ok {
		appConfig.IdentifierUris = identifierUris
	}
	if createServicePrincipal, ok := configMap["create_service_principal"].(bool); ok {
		appConfig.CreateServicePrincipal = createServicePrincipal
	}

	// Validate configuration
	if err := appConfig.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Authenticate with Microsoft Graph
	token, err := m.authProvider.GetAccessToken(ctx, appConfig.TenantID)
	if err != nil {
		return fmt.Errorf("failed to authenticate with Microsoft Graph: %w", err)
	}

	// Check if application exists
	appID := extractApplicationID(resourceID)
	existingApp, err := m.getApplicationByID(ctx, token, appID)
	if err != nil {
		// Application doesn't exist, create it
		return m.createApplication(ctx, token, appConfig)
	}

	// Application exists, update it with only managed fields
	return m.updateApplication(ctx, token, appConfig, existingApp)
}

// Get retrieves the current configuration of an Entra ID application
func (m *entraApplicationModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	// Parse resource ID to extract tenant ID and app ID
	// Format: tenantID:applicationID
	tenantID, appID, err := parseEntraApplicationResourceID(resourceID)
	if err != nil {
		return nil, fmt.Errorf("invalid resource ID format: %w", err)
	}

	// Authenticate with Microsoft Graph
	token, err := m.authProvider.GetAccessToken(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with Microsoft Graph: %w", err)
	}

	// Get application from Graph API
	app, err := m.getApplicationByID(ctx, token, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get application from Graph API: %w", err)
	}

	// Convert to our config format
	config := &EntraApplicationConfig{
		DisplayName:    app.DisplayName,
		Description:    app.Description,
		SignInAudience: app.SignInAudience,
		IdentifierUris: app.IdentifierUris,
		TenantID:       tenantID,
	}

	return config, nil
}

// Helper methods for Graph API operations

func (m *entraApplicationModule) getApplicationByID(ctx context.Context, token *auth.AccessToken, appID string) (*ApplicationInfo, error) {
	// Get application from Graph API
	app, err := m.graphClient.GetApplication(ctx, token, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get application from Graph API: %w", err)
	}

	// Convert Graph API response to our internal format
	return &ApplicationInfo{
		ID:             app.ID,
		DisplayName:    app.DisplayName,
		Description:    app.Description,
		SignInAudience: app.SignInAudience,
		IdentifierUris: app.IdentifierUris,
	}, nil
}

func (m *entraApplicationModule) createApplication(ctx context.Context, token *auth.AccessToken, config *EntraApplicationConfig) error {
	// Build the create request
	request := &graph.CreateApplicationRequest{
		DisplayName:    config.DisplayName,
		SignInAudience: config.SignInAudience,
	}

	if config.Description != "" {
		request.Description = config.Description
	}
	if len(config.IdentifierUris) > 0 {
		request.IdentifierUris = config.IdentifierUris
	}

	// Create application via Graph API
	app, err := m.graphClient.CreateApplication(ctx, token, request)
	if err != nil {
		return fmt.Errorf("failed to create application via Graph API: %w", err)
	}

	// Wait for application creation to propagate
	time.Sleep(2 * time.Second)

	// Create service principal if requested
	if config.CreateServicePrincipal {
		if err := m.createServicePrincipal(ctx, token, app.AppID, config.ServicePrincipalSettings); err != nil {
			return fmt.Errorf("failed to create service principal: %w", err)
		}
	}

	// Add password credentials (client secrets) if specified
	if len(config.PasswordCredentials) > 0 {
		for _, cred := range config.PasswordCredentials {
			if err := m.addPasswordCredential(ctx, token, app.ID, &cred); err != nil {
				return fmt.Errorf("failed to add password credential: %w", err)
			}
		}
	}

	// Add certificate credentials if specified
	if len(config.KeyCredentials) > 0 {
		for _, cred := range config.KeyCredentials {
			if err := m.addKeyCredential(ctx, token, app.ID, &cred); err != nil {
				return fmt.Errorf("failed to add key credential: %w", err)
			}
		}
	}

	return nil
}

func (m *entraApplicationModule) updateApplication(ctx context.Context, token *auth.AccessToken, config *EntraApplicationConfig, existingApp *ApplicationInfo) error {
	managedFields := config.GetManagedFields()
	updates := make(map[string]interface{})

	// Only update managed fields
	for _, field := range managedFields {
		switch field {
		case "display_name":
			if config.DisplayName != existingApp.DisplayName {
				updates["displayName"] = config.DisplayName
			}
		case "description":
			if config.Description != existingApp.Description {
				updates["description"] = config.Description
			}
		case "sign_in_audience":
			if config.SignInAudience != existingApp.SignInAudience {
				updates["signInAudience"] = config.SignInAudience
			}
		}
	}

	// Update the application if there are changes
	if len(updates) > 0 {
		// Build the update request
		updateRequest := &graph.UpdateApplicationRequest{}

		if displayName, ok := updates["displayName"].(string); ok {
			updateRequest.DisplayName = &displayName
		}
		if description, ok := updates["description"].(string); ok {
			updateRequest.Description = &description
		}
		if signInAudience, ok := updates["signInAudience"].(string); ok {
			updateRequest.SignInAudience = &signInAudience
		}

		// Update application via Graph API
		if err := m.graphClient.UpdateApplication(ctx, token, existingApp.ID, updateRequest); err != nil {
			return fmt.Errorf("failed to update application via Graph API: %w", err)
		}
	}

	// Handle credentials if managed
	if contains(managedFields, "password_credentials") {
		if err := m.syncPasswordCredentials(ctx, token, existingApp.ID, config.PasswordCredentials); err != nil {
			return fmt.Errorf("failed to sync password credentials: %w", err)
		}
	}

	if contains(managedFields, "key_credentials") {
		if err := m.syncKeyCredentials(ctx, token, existingApp.ID, config.KeyCredentials); err != nil {
			return fmt.Errorf("failed to sync key credentials: %w", err)
		}
	}

	return nil
}

// Additional helper methods (placeholders)

func (m *entraApplicationModule) createServicePrincipal(ctx context.Context, token *auth.AccessToken, appID string, settings *ServicePrincipalConfig) error {
	// Placeholder - would use Graph API POST /servicePrincipals
	return nil
}

func (m *entraApplicationModule) addPasswordCredential(ctx context.Context, token *auth.AccessToken, appID string, credential *PasswordCredential) error {
	// Placeholder - would use Graph API POST /applications/{id}/addPassword
	return nil
}

func (m *entraApplicationModule) addKeyCredential(ctx context.Context, token *auth.AccessToken, appID string, credential *KeyCredential) error {
	// Placeholder - would use Graph API POST /applications/{id}/addKey
	return nil
}

func (m *entraApplicationModule) syncPasswordCredentials(ctx context.Context, token *auth.AccessToken, appID string, credentials []PasswordCredential) error {
	// Would implement credential synchronization logic
	return nil
}

func (m *entraApplicationModule) syncKeyCredentials(ctx context.Context, token *auth.AccessToken, appID string, credentials []KeyCredential) error {
	// Would implement credential synchronization logic
	return nil
}

// Utility types and functions

type ApplicationInfo struct {
	ID             string
	DisplayName    string
	Description    string
	SignInAudience string
	IdentifierUris []string
}

func parseEntraApplicationResourceID(resourceID string) (tenantID, appID string, err error) {
	parts := strings.SplitN(resourceID, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("resource ID must be in format 'tenantID:applicationID'")
	}
	return parts[0], parts[1], nil
}

func extractApplicationID(resourceID string) string {
	_, appID, _ := parseEntraApplicationResourceID(resourceID)
	return appID
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
