// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package entra_application

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
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
	LogoutURL      string        `yaml:"logout_url,omitempty"`

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
	ResourceAppID  string            `yaml:"resource_app_id"`
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
	KeyID       string `yaml:"key_id,omitempty"`
}

// OptionalClaims represents optional claims configuration
type OptionalClaims struct {
	IDToken     []OptionalClaim `yaml:"id_token,omitempty"`
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
	if c.LogoutURL != "" {
		result["logout_url"] = c.LogoutURL
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
	}
	if c.ServicePrincipalSettings != nil {
		result["service_principal_settings"] = c.ServicePrincipalSettings
	}
	if len(c.Tags) > 0 {
		result["tags"] = c.Tags
	}
	if len(c.ManagedFieldsList) > 0 {
		result["managed_fields"] = c.ManagedFieldsList
	}
	if c.AcceptMappedClaims {
		result["accept_mapped_claims"] = c.AcceptMappedClaims
	}
	if len(c.KnownClientApplications) > 0 {
		result["known_client_applications"] = c.KnownClientApplications
	}
	if len(c.PreAuthorizedApplications) > 0 {
		result["pre_authorized_applications"] = c.PreAuthorizedApplications
	}
	if c.RequestedAccessTokenVersion != 0 {
		result["requested_access_token_version"] = c.RequestedAccessTokenVersion
	}
	if c.PublisherDomain != "" {
		result["publisher_domain"] = c.PublisherDomain
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
	if c.LogoutURL != "" {
		fields = append(fields, "logout_url")
	}
	if len(c.Tags) > 0 {
		fields = append(fields, "tags")
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
	appConfig, err := configFromMap(config.AsMap())
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Validate configuration
	if err := appConfig.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Refuse every declared field this module cannot apply, before any
	// authentication or Graph call, so a step never reports success while the
	// tenant differs from what was declared.
	if err := appConfig.checkApplicable(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// The CFGMS tenant this workflow execution is authenticated as is the sole
	// authority for which M365 credentials get used — never the tenant_id a
	// workflow step's own configuration claims (Issue #4325, same fix as
	// entra_user). Config-supplied tenant_id is still required (Validate
	// above) and is checked against the authenticated tenant's actual M365
	// tenant below, but it never selects which credentials are looked up.
	cfgmsTenantID, err := requireExecutionTenant(ctx)
	if err != nil {
		return err
	}

	// Authenticate with Microsoft Graph using the credentials on file for this
	// CFGMS tenant.
	token, err := m.authProvider.GetAccessToken(ctx, cfgmsTenantID)
	if err != nil {
		return fmt.Errorf("failed to authenticate with Microsoft Graph: %w", err)
	}

	// Refuse when the workflow step's declared tenant_id does not match the
	// M365 tenant actually configured for this CFGMS tenant — a mismatch means
	// the step is either misconfigured or attempting to act on a different
	// customer's M365 tenant.
	if appConfig.TenantID != token.TenantID {
		return fmt.Errorf("configured tenant_id %q does not match the M365 tenant configured for this workflow execution",
			appConfig.TenantID)
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

	// The CFGMS tenant this workflow execution is authenticated as is the
	// sole authority for which M365 credentials get used. The resource ID's
	// own tenant segment is never used to select credentials (Issue #4325) —
	// it is only checked for agreement below.
	cfgmsTenantID, err := requireExecutionTenant(ctx)
	if err != nil {
		return nil, err
	}

	// Authenticate with Microsoft Graph using the credentials on file for this
	// CFGMS tenant.
	token, err := m.authProvider.GetAccessToken(ctx, cfgmsTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with Microsoft Graph: %w", err)
	}

	// Refuse when the resource ID's declared tenant does not match the M365
	// tenant actually configured for this CFGMS tenant.
	if tenantID != token.TenantID {
		return nil, fmt.Errorf("resource tenant %q does not match the M365 tenant configured for this workflow execution",
			tenantID)
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
	info := &ApplicationInfo{
		ID:             app.ID,
		AppID:          app.AppID,
		DisplayName:    app.DisplayName,
		Description:    app.Description,
		SignInAudience: app.SignInAudience,
		IdentifierUris: app.IdentifierUris,
		Tags:           app.Tags,
	}
	if app.Web != nil {
		info.WebRedirectUris = app.Web.RedirectUris
		info.LogoutURL = app.Web.LogoutURL
	}
	if app.Spa != nil {
		info.SpaRedirectUris = app.Spa.RedirectUris
	}
	return info, nil
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
	if len(config.Tags) > 0 {
		request.Tags = config.Tags
	}
	if (config.RedirectUris != nil && len(config.RedirectUris.Web) > 0) || config.LogoutURL != "" {
		request.Web = &graph.ApplicationWeb{LogoutURL: config.LogoutURL}
		if config.RedirectUris != nil {
			request.Web.RedirectUris = config.RedirectUris.Web
		}
	}
	if config.RedirectUris != nil && len(config.RedirectUris.Spa) > 0 {
		request.Spa = &graph.ApplicationSpa{RedirectUris: config.RedirectUris.Spa}
	}

	// Create application via Graph API.
	app, err := m.graphClient.CreateApplication(ctx, token, request)
	if err != nil {
		return fmt.Errorf("failed to create application via Graph API: %w", err)
	}

	if len(config.PasswordCredentials) > 0 || len(config.KeyCredentials) > 0 {
		if app == nil || app.ID == "" {
			return fmt.Errorf("failed to add credentials: Graph returned no id for the created application")
		}
		for i := range config.PasswordCredentials {
			if err := m.addPasswordCredential(ctx, token, app.ID, &config.PasswordCredentials[i]); err != nil {
				return err
			}
		}
		for i := range config.KeyCredentials {
			if err := m.addKeyCredential(ctx, token, app.ID, &config.KeyCredentials[i]); err != nil {
				return err
			}
		}
	}

	if config.CreateServicePrincipal {
		if app == nil || app.AppID == "" {
			return fmt.Errorf("failed to create service principal: Graph returned no appId for the created application")
		}
		return m.createServicePrincipal(ctx, token, app.AppID, config.ServicePrincipalSettings)
	}

	return nil
}

func (m *entraApplicationModule) updateApplication(ctx context.Context, token *auth.AccessToken, config *EntraApplicationConfig, existingApp *ApplicationInfo) error {
	managedFields := config.GetManagedFields()
	updateRequest := &graph.UpdateApplicationRequest{}
	changed := false

	var declaredWeb, declaredSpa []string
	if config.RedirectUris != nil {
		declaredWeb = config.RedirectUris.Web
		declaredSpa = config.RedirectUris.Spa
	}
	webManaged := contains(managedFields, "redirect_uris")
	webChanged := webManaged && !stringSlicesEqual(declaredWeb, existingApp.WebRedirectUris)
	logoutChanged := contains(managedFields, "logout_url") && config.LogoutURL != existingApp.LogoutURL

	// Only update managed fields
	for _, field := range managedFields {
		switch field {
		case "display_name":
			if config.DisplayName != existingApp.DisplayName {
				displayName := config.DisplayName
				updateRequest.DisplayName = &displayName
				changed = true
			}
		case "description":
			if config.Description != existingApp.Description {
				description := config.Description
				updateRequest.Description = &description
				changed = true
			}
		case "sign_in_audience":
			if config.SignInAudience != existingApp.SignInAudience {
				signInAudience := config.SignInAudience
				updateRequest.SignInAudience = &signInAudience
				changed = true
			}
		case "identifier_uris":
			if !stringSlicesEqual(config.IdentifierUris, existingApp.IdentifierUris) {
				updateRequest.IdentifierUris = config.IdentifierUris
				changed = true
			}
		case "tags":
			if !stringSlicesEqual(config.Tags, existingApp.Tags) {
				updateRequest.Tags = config.Tags
				changed = true
			}
		case "redirect_uris":
			if !stringSlicesEqual(declaredSpa, existingApp.SpaRedirectUris) {
				updateRequest.Spa = &graph.ApplicationSpa{RedirectUris: nonNil(declaredSpa)}
				changed = true
			}
		}
	}

	// Graph replaces the web object as a unit, so send the unmanaged half
	// (redirect URIs or logout URL) at its existing value.
	if webChanged || logoutChanged {
		web := &graph.ApplicationWeb{
			RedirectUris: nonNil(existingApp.WebRedirectUris),
			LogoutURL:    existingApp.LogoutURL,
		}
		if webChanged {
			web.RedirectUris = nonNil(declaredWeb)
		}
		if logoutChanged {
			web.LogoutURL = config.LogoutURL
		}
		updateRequest.Web = web
		changed = true
	}

	// Update the application if there are changes.
	if changed {
		if err := m.graphClient.UpdateApplication(ctx, token, existingApp.ID, updateRequest); err != nil {
			return fmt.Errorf("failed to update application via Graph API: %w", err)
		}
	}

	if contains(managedFields, "password_credentials") {
		if err := m.syncPasswordCredentials(ctx, token, existingApp.ID, config.PasswordCredentials); err != nil {
			return err
		}
	}
	if contains(managedFields, "key_credentials") {
		if err := m.syncKeyCredentials(ctx, token, existingApp.ID, config.KeyCredentials); err != nil {
			return err
		}
	}

	if contains(managedFields, "create_service_principal") && config.CreateServicePrincipal {
		if existingApp.AppID == "" {
			return fmt.Errorf("failed to create service principal: Graph returned no appId for the application")
		}
		return m.createServicePrincipal(ctx, token, existingApp.AppID, config.ServicePrincipalSettings)
	}

	return nil
}

// createServicePrincipal ensures a service principal exists for the application
// identified by appID (the application's appId, not its object id). It creates
// one only when none exists, so repeated calls are idempotent. Settings are
// applied at creation; an existing service principal is left as it is. Without
// declared settings the service principal is created enabled.
func (m *entraApplicationModule) createServicePrincipal(ctx context.Context, token *auth.AccessToken, appID string, settings *ServicePrincipalConfig) error {
	if appID == "" {
		return fmt.Errorf("failed to create service principal: application appId is empty")
	}
	filter := fmt.Sprintf("appId eq '%s'", strings.ReplaceAll(appID, "'", "''"))
	existing, err := m.graphClient.ListServicePrincipals(ctx, token, filter)
	if err != nil {
		return fmt.Errorf("failed to list service principals via Graph API: %w", err)
	}
	for _, sp := range existing {
		if sp.AppID == appID {
			return nil
		}
	}

	request := &graph.CreateServicePrincipalRequest{AppID: appID, AccountEnabled: true}
	if settings != nil {
		request.AccountEnabled = settings.AccountEnabled
		request.AppRoleAssignmentRequired = settings.AppRoleAssignmentRequired
		request.ServicePrincipalType = settings.ServicePrincipalType
		request.Tags = settings.Tags
		request.PreferredSingleSignOnMode = settings.PreferredSingleSignOnMode
		request.ReplyUrls = settings.ReplyUrls
		request.NotificationEmailAddresses = settings.NotificationEmailAddresses
	}
	if _, err := m.graphClient.CreateServicePrincipal(ctx, token, request); err != nil {
		return fmt.Errorf("failed to create service principal via Graph API: %w", err)
	}
	return nil
}

// parseCredentialEnd parses a declared end date. An empty value is "not declared".
func parseCredentialEnd(field, value string) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, fmt.Errorf("%s end_date_time must be an RFC 3339 timestamp", field)
	}
	return &t, nil
}

// endDateDiffers reports whether a declared end date disagrees with the current one.
// An undeclared end date never differs.
func endDateDiffers(declared *time.Time, current time.Time) bool {
	return declared != nil && !declared.Equal(current)
}

// addPasswordCredential asks Graph to generate a new password credential. The
// generated secret is discarded: it is never logged, returned or placed in an error.
func (m *entraApplicationModule) addPasswordCredential(ctx context.Context, token *auth.AccessToken, appID string, credential *PasswordCredential) error {
	if credential.SecretText != "" {
		return fmt.Errorf("password credential %q declares secret_text, which is not supported: Graph generates the secret", credential.DisplayName)
	}
	end, err := parseCredentialEnd("password credential", credential.EndDateTime)
	if err != nil {
		return err
	}
	request := &graph.AddApplicationPasswordRequest{
		PasswordCredential: graph.ApplicationPasswordCredentialInput{DisplayName: credential.DisplayName, EndDate: end},
	}
	if _, err := m.graphClient.AddApplicationPassword(ctx, token, appID, request); err != nil {
		return fmt.Errorf("failed to add password credential %q via Graph API: %w", credential.DisplayName, err)
	}
	return nil
}

// addKeyCredential adds a certificate credential. Graph refuses addKey without a
// proof of possession this module cannot supply; that refusal is returned.
func (m *entraApplicationModule) addKeyCredential(ctx context.Context, token *auth.AccessToken, appID string, credential *KeyCredential) error {
	end, err := parseCredentialEnd("key credential", credential.EndDateTime)
	if err != nil {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(credential.Key)
	if err != nil || len(key) == 0 {
		return fmt.Errorf("key credential %q key must be non-empty base64", credential.DisplayName)
	}
	request := &graph.AddApplicationKeyRequest{
		KeyCredential: graph.ApplicationKeyCredentialInput{
			DisplayName: credential.DisplayName,
			Type:        credential.Type,
			Usage:       credential.Usage,
			Key:         key,
			EndDate:     end,
		},
	}
	if _, err := m.graphClient.AddApplicationKey(ctx, token, appID, request); err != nil {
		return fmt.Errorf("failed to add key credential %q via Graph API: %w", credential.DisplayName, err)
	}
	return nil
}

// syncPasswordCredentials converges the application's password credentials to the
// declared list, matching by display name. Any Graph error stops the sync.
func (m *entraApplicationModule) syncPasswordCredentials(ctx context.Context, token *auth.AccessToken, appID string, credentials []PasswordCredential) error {
	ends := make([]*time.Time, len(credentials))
	for i := range credentials {
		if credentials[i].SecretText != "" {
			return fmt.Errorf("password credential %q declares secret_text, which is not supported: Graph generates the secret", credentials[i].DisplayName)
		}
		end, err := parseCredentialEnd("password credential", credentials[i].EndDateTime)
		if err != nil {
			return err
		}
		ends[i] = end
	}
	app, err := m.graphClient.GetApplication(ctx, token, appID)
	if err != nil {
		return fmt.Errorf("failed to get application from Graph API: %w", err)
	}

	matched := make(map[string]bool)
	var toRemove []string
	var toAdd []int
	for i, declared := range credentials {
		found := false
		for _, current := range app.PasswordCredentials {
			if matched[current.KeyID] || current.DisplayName != declared.DisplayName {
				continue
			}
			matched[current.KeyID] = true
			found = true
			if endDateDiffers(ends[i], current.EndDate) {
				toRemove = append(toRemove, current.KeyID)
				toAdd = append(toAdd, i)
			}
			break
		}
		if !found {
			toAdd = append(toAdd, i)
		}
	}
	for _, current := range app.PasswordCredentials {
		if !matched[current.KeyID] {
			toRemove = append(toRemove, current.KeyID)
		}
	}

	// Add before removing so a failed add never leaves the application without a credential.
	for _, i := range toAdd {
		if err := m.addPasswordCredential(ctx, token, appID, &credentials[i]); err != nil {
			return err
		}
	}
	for _, keyID := range toRemove {
		if err := m.graphClient.RemoveApplicationPassword(ctx, token, appID, keyID); err != nil {
			return fmt.Errorf("failed to remove password credential via Graph API: %w", err)
		}
	}
	return nil
}

// syncKeyCredentials converges the application's key credentials to the declared
// list, matching by key_id or, when none is declared, by display name.
func (m *entraApplicationModule) syncKeyCredentials(ctx context.Context, token *auth.AccessToken, appID string, credentials []KeyCredential) error {
	ends := make([]*time.Time, len(credentials))
	for i := range credentials {
		end, err := parseCredentialEnd("key credential", credentials[i].EndDateTime)
		if err != nil {
			return err
		}
		ends[i] = end
	}
	app, err := m.graphClient.GetApplication(ctx, token, appID)
	if err != nil {
		return fmt.Errorf("failed to get application from Graph API: %w", err)
	}

	matched := make(map[string]bool)
	var toRemove []string
	var toAdd []int
	for i, declared := range credentials {
		found := false
		for _, current := range app.KeyCredentials {
			if matched[current.KeyID] {
				continue
			}
			if declared.KeyID != "" {
				if current.KeyID != declared.KeyID {
					continue
				}
			} else if current.DisplayName != declared.DisplayName {
				continue
			}
			matched[current.KeyID] = true
			found = true
			if endDateDiffers(ends[i], current.EndDate) {
				toRemove = append(toRemove, current.KeyID)
				toAdd = append(toAdd, i)
			}
			break
		}
		if !found {
			toAdd = append(toAdd, i)
		}
	}
	for _, current := range app.KeyCredentials {
		if !matched[current.KeyID] {
			toRemove = append(toRemove, current.KeyID)
		}
	}

	for _, i := range toAdd {
		if err := m.addKeyCredential(ctx, token, appID, &credentials[i]); err != nil {
			return err
		}
	}
	for _, keyID := range toRemove {
		if err := m.graphClient.RemoveApplicationKey(ctx, token, appID, keyID); err != nil {
			return fmt.Errorf("failed to remove key credential via Graph API: %w", err)
		}
	}
	return nil
}

// Utility types and functions

type ApplicationInfo struct {
	ID              string
	AppID           string
	DisplayName     string
	Description     string
	SignInAudience  string
	IdentifierUris  []string
	WebRedirectUris []string
	SpaRedirectUris []string
	LogoutURL       string
	Tags            []string
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

// requireExecutionTenant reads the CFGMS tenant the current workflow
// execution is authenticated as. It fails closed: a missing tenant context
// (wrong context key, a dropped context.Background() call, a forgotten
// propagation) must never be treated as an unrestricted or default tenant
// (Issue #4325, matching the fail-closed convention in pkg/ctxkeys).
func requireExecutionTenant(ctx context.Context) (string, error) {
	tenantID, _ := ctx.Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		return "", fmt.Errorf("entra_application: tenant context required")
	}
	return tenantID, nil
}

// stringSlicesEqual compares two string slices, treating nil and empty alike.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// nonNil returns an empty, non-nil slice for nil input so it serializes as [].
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// unsupportedManagedFields are managed_fields entries this module cannot apply.
var unsupportedManagedFields = map[string]bool{
	"redirect_uris.mobile": true, "redirect_uris.desktop": true,
	"required_resource_access": true, "oauth2_permissions": true, "app_roles": true,
	"optional_claims": true, "accept_mapped_claims": true, "known_client_applications": true,
	"pre_authorized_applications": true, "requested_access_token_version": true,
	"publisher_domain": true,
}

// checkApplicable returns an error naming the first declared field this module
// cannot apply to Graph. It fails closed so that a step never succeeds while
// silently dropping part of what it declared.
func (c *EntraApplicationConfig) checkApplicable() error {
	reject := func(field string) error {
		return fmt.Errorf("%s is declared but cannot be applied by this module", field)
	}
	if c.RedirectUris != nil {
		if len(c.RedirectUris.Mobile) > 0 {
			return reject("redirect_uris.mobile")
		}
		if len(c.RedirectUris.Desktop) > 0 {
			return reject("redirect_uris.desktop")
		}
	}
	declared := []struct {
		name string
		set  bool
	}{
		{"required_resource_access", len(c.RequiredResourceAccess) > 0},
		{"oauth2_permissions", len(c.OAuth2Permissions) > 0},
		{"app_roles", len(c.AppRoles) > 0},
		{"optional_claims", c.OptionalClaims != nil},
		{"accept_mapped_claims", c.AcceptMappedClaims},
		{"known_client_applications", len(c.KnownClientApplications) > 0},
		{"pre_authorized_applications", len(c.PreAuthorizedApplications) > 0},
		{"requested_access_token_version", c.RequestedAccessTokenVersion != 0},
		{"publisher_domain", c.PublisherDomain != ""},
	}
	for _, d := range declared {
		if d.set {
			return reject(d.name)
		}
	}
	// Graph generates password secrets; a client-supplied value is never sent.
	// The error names the field only, never the value.
	for _, cred := range c.PasswordCredentials {
		if cred.SecretText != "" {
			return fmt.Errorf("password_credentials secret_text is declared but cannot be applied: Graph generates the secret")
		}
	}

	// A managed field is declared even when its value is empty. Fields this
	// module cannot apply are rejected outright; fields it can apply but whose
	// empty value cannot be sent as a clear (omitted by omitempty) likewise.
	for _, field := range c.ManagedFieldsList {
		if unsupportedManagedFields[field] {
			return reject(field)
		}
		switch field {
		case "identifier_uris":
			if len(c.IdentifierUris) == 0 {
				return fmt.Errorf("managed field identifier_uris is empty and cannot be cleared by this module")
			}
		case "tags":
			if len(c.Tags) == 0 {
				return fmt.Errorf("managed field tags is empty and cannot be cleared by this module")
			}
		case "create_service_principal":
			if !c.CreateServicePrincipal {
				return fmt.Errorf("managed field create_service_principal is false and an existing service principal cannot be removed by this module")
			}
		case "logout_url":
			if c.LogoutURL == "" {
				return fmt.Errorf("managed field logout_url is empty and cannot be cleared by this module")
			}
		}
	}
	return nil
}

// configFromMap maps every key of a step configuration onto an
// EntraApplicationConfig. A key that is present with an unexpected type is an
// error naming the key; unknown keys are ignored.
func configFromMap(m map[string]interface{}) (*EntraApplicationConfig, error) {
	c := &EntraApplicationConfig{}
	var err error
	strField := func(key string, dst *string) {
		if err != nil {
			return
		}
		if v, ok := m[key]; ok && v != nil {
			s, isStr := v.(string)
			if !isStr {
				err = fmt.Errorf("%s must be a string", key)
				return
			}
			*dst = s
		}
	}
	listField := func(key string, dst *[]string) {
		if err != nil {
			return
		}
		if v, ok := m[key]; ok && v != nil {
			*dst, err = toStringSlice(key, v)
		}
	}
	// yamlField decodes structured values (typed or generic maps) via YAML so
	// the struct tags define the accepted keys.
	yamlField := func(key string, dst interface{}) {
		if err != nil {
			return
		}
		v, ok := m[key]
		if !ok || v == nil {
			return
		}
		raw, mErr := yaml.Marshal(v)
		if mErr == nil {
			mErr = yaml.Unmarshal(raw, dst)
		}
		if mErr != nil {
			err = fmt.Errorf("%s has an unexpected type", key)
		}
	}

	strField("display_name", &c.DisplayName)
	strField("description", &c.Description)
	strField("sign_in_audience", &c.SignInAudience)
	strField("tenant_id", &c.TenantID)
	strField("logout_url", &c.LogoutURL)
	strField("publisher_domain", &c.PublisherDomain)
	listField("identifier_uris", &c.IdentifierUris)
	listField("tags", &c.Tags)
	listField("managed_fields", &c.ManagedFieldsList)
	listField("known_client_applications", &c.KnownClientApplications)
	listField("pre_authorized_applications", &c.PreAuthorizedApplications)
	yamlField("redirect_uris", &c.RedirectUris)
	yamlField("required_resource_access", &c.RequiredResourceAccess)
	yamlField("oauth2_permissions", &c.OAuth2Permissions)
	yamlField("app_roles", &c.AppRoles)
	yamlField("password_credentials", &c.PasswordCredentials)
	yamlField("key_credentials", &c.KeyCredentials)
	yamlField("optional_claims", &c.OptionalClaims)
	yamlField("service_principal_settings", &c.ServicePrincipalSettings)
	for _, b := range []struct {
		key string
		dst *bool
	}{{"accept_mapped_claims", &c.AcceptMappedClaims}, {"create_service_principal", &c.CreateServicePrincipal}} {
		if v, ok := m[b.key]; ok && v != nil && err == nil {
			bv, isBool := v.(bool)
			if !isBool {
				err = fmt.Errorf("%s must be a boolean", b.key)
			}
			*b.dst = bv
		}
	}
	if v, ok := m["requested_access_token_version"]; ok && v != nil && err == nil {
		switch n := v.(type) {
		case int:
			c.RequestedAccessTokenVersion = n
		case int64:
			c.RequestedAccessTokenVersion = int(n)
		case float64:
			c.RequestedAccessTokenVersion = int(n)
		default:
			err = fmt.Errorf("requested_access_token_version must be an integer")
		}
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// toStringSlice accepts []string and []interface{} of strings.
func toStringSlice(key string, v interface{}) ([]string, error) {
	switch t := v.(type) {
	case []string:
		return t, nil
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("%s must be a list of strings", key)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s must be a list of strings", key)
	}
}
