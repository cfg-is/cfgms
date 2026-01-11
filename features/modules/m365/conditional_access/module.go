// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package conditional_access

import (
	"context"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
)

// conditionalAccessModule implements the Module interface for Conditional Access policy management
type conditionalAccessModule struct {
	authProvider auth.Provider
	graphClient  graph.Client
}

// New creates a new instance of the Conditional Access module
func New(authProvider auth.Provider, graphClient graph.Client) modules.Module {
	return &conditionalAccessModule{
		authProvider: authProvider,
		graphClient:  graphClient,
	}
}

// ConditionalAccessConfig represents the configuration for a Conditional Access policy
type ConditionalAccessConfig struct {
	// Basic policy properties
	DisplayName string `yaml:"display_name"`
	State       string `yaml:"state"` // enabled, disabled, enabledForReportingButNotEnforced

	// Conditions
	Conditions ConditionalAccessConditions `yaml:"conditions"`

	// Grant controls
	GrantControls ConditionalAccessGrantControls `yaml:"grant_controls"`

	// Session controls (optional)
	SessionControls *ConditionalAccessSessionControls `yaml:"session_controls,omitempty"`

	// Tenant configuration
	TenantID string `yaml:"tenant_id"`

	// Managed fields - controls which fields Set() will modify
	ManagedFieldsList []string `yaml:"managed_fields,omitempty"`
}

// ConditionalAccessConditions represents the conditions for a CA policy
type ConditionalAccessConditions struct {
	Users            ConditionalAccessUsers         `yaml:"users"`
	Applications     ConditionalAccessApplications  `yaml:"applications"`
	Locations        *ConditionalAccessLocations    `yaml:"locations,omitempty"`
	Platforms        *ConditionalAccessPlatforms    `yaml:"platforms,omitempty"`
	DeviceStates     *ConditionalAccessDeviceStates `yaml:"device_states,omitempty"`
	ClientAppTypes   []string                       `yaml:"client_app_types,omitempty"`
	SignInRiskLevels []string                       `yaml:"sign_in_risk_levels,omitempty"`
	UserRiskLevels   []string                       `yaml:"user_risk_levels,omitempty"`
}

// ConditionalAccessUsers represents user conditions
type ConditionalAccessUsers struct {
	IncludeUsers  []string `yaml:"include_users,omitempty"`
	ExcludeUsers  []string `yaml:"exclude_users,omitempty"`
	IncludeGroups []string `yaml:"include_groups,omitempty"`
	ExcludeGroups []string `yaml:"exclude_groups,omitempty"`
	IncludeRoles  []string `yaml:"include_roles,omitempty"`
	ExcludeRoles  []string `yaml:"exclude_roles,omitempty"`
}

// ConditionalAccessApplications represents application conditions
type ConditionalAccessApplications struct {
	IncludeApplications []string `yaml:"include_applications,omitempty"`
	ExcludeApplications []string `yaml:"exclude_applications,omitempty"`
	IncludeUserActions  []string `yaml:"include_user_actions,omitempty"`
}

// ConditionalAccessLocations represents location conditions
type ConditionalAccessLocations struct {
	IncludeLocations []string `yaml:"include_locations,omitempty"`
	ExcludeLocations []string `yaml:"exclude_locations,omitempty"`
}

// ConditionalAccessPlatforms represents platform conditions
type ConditionalAccessPlatforms struct {
	IncludePlatforms []string `yaml:"include_platforms,omitempty"`
	ExcludePlatforms []string `yaml:"exclude_platforms,omitempty"`
}

// ConditionalAccessDeviceStates represents device state conditions
type ConditionalAccessDeviceStates struct {
	IncludeStates []string `yaml:"include_states,omitempty"`
	ExcludeStates []string `yaml:"exclude_states,omitempty"`
}

// ConditionalAccessGrantControls represents grant controls
type ConditionalAccessGrantControls struct {
	Operator                    string   `yaml:"operator"` // AND, OR
	BuiltInControls             []string `yaml:"built_in_controls,omitempty"`
	CustomAuthenticationFactors []string `yaml:"custom_authentication_factors,omitempty"`
	TermsOfUse                  []string `yaml:"terms_of_use,omitempty"`
}

// ConditionalAccessSessionControls represents session controls
type ConditionalAccessSessionControls struct {
	ApplicationEnforcedRestrictions *ApplicationEnforcedRestrictions `yaml:"application_enforced_restrictions,omitempty"`
	CloudAppSecurity                *CloudAppSecurity                `yaml:"cloud_app_security,omitempty"`
	PersistentBrowser               *PersistentBrowser               `yaml:"persistent_browser,omitempty"`
	SignInFrequency                 *SignInFrequency                 `yaml:"sign_in_frequency,omitempty"`
}

// ApplicationEnforcedRestrictions represents application enforced restrictions
type ApplicationEnforcedRestrictions struct {
	IsEnabled bool `yaml:"is_enabled"`
}

// CloudAppSecurity represents cloud app security settings
type CloudAppSecurity struct {
	IsEnabled            bool   `yaml:"is_enabled"`
	CloudAppSecurityType string `yaml:"cloud_app_security_type,omitempty"`
}

// PersistentBrowser represents persistent browser settings
type PersistentBrowser struct {
	IsEnabled bool   `yaml:"is_enabled"`
	Mode      string `yaml:"mode,omitempty"` // always, never
}

// SignInFrequency represents sign-in frequency settings
type SignInFrequency struct {
	IsEnabled         bool   `yaml:"is_enabled"`
	Type              string `yaml:"type,omitempty"` // hours, days
	Value             int    `yaml:"value,omitempty"`
	FrequencyInterval string `yaml:"frequency_interval,omitempty"` // timeBased, everyTime
}

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *ConditionalAccessConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"display_name":   c.DisplayName,
		"state":          c.State,
		"conditions":     c.Conditions,
		"grant_controls": c.GrantControls,
		"tenant_id":      c.TenantID,
	}

	if c.SessionControls != nil {
		result["session_controls"] = c.SessionControls
	}

	return result
}

// ToYAML serializes the configuration to YAML for export/storage
func (c *ConditionalAccessConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration
func (c *ConditionalAccessConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate ensures the configuration is valid
func (c *ConditionalAccessConfig) Validate() error {
	if c.DisplayName == "" {
		return fmt.Errorf("display_name is required")
	}

	if c.State == "" {
		c.State = "enabled" // Default to enabled
	}

	// Validate state
	validStates := []string{"enabled", "disabled", "enabledForReportingButNotEnforced"}
	if !contains(validStates, c.State) {
		return fmt.Errorf("invalid state: %s, must be one of: %v", c.State, validStates)
	}

	if c.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}

	// Validate conditions
	if err := c.validateConditions(); err != nil {
		return fmt.Errorf("invalid conditions: %w", err)
	}

	// Validate grant controls
	if err := c.validateGrantControls(); err != nil {
		return fmt.Errorf("invalid grant_controls: %w", err)
	}

	return nil
}

// validateConditions validates the conditions section
func (c *ConditionalAccessConfig) validateConditions() error {
	// Users must be specified
	if len(c.Conditions.Users.IncludeUsers) == 0 &&
		len(c.Conditions.Users.IncludeGroups) == 0 &&
		len(c.Conditions.Users.IncludeRoles) == 0 {
		return fmt.Errorf("at least one user, group, or role must be included")
	}

	// Applications must be specified
	if len(c.Conditions.Applications.IncludeApplications) == 0 &&
		len(c.Conditions.Applications.IncludeUserActions) == 0 {
		return fmt.Errorf("at least one application or user action must be included")
	}

	return nil
}

// validateGrantControls validates the grant controls section
func (c *ConditionalAccessConfig) validateGrantControls() error {
	if c.GrantControls.Operator == "" {
		c.GrantControls.Operator = "OR" // Default to OR
	}

	// Validate operator
	validOperators := []string{"AND", "OR"}
	if !contains(validOperators, c.GrantControls.Operator) {
		return fmt.Errorf("invalid grant controls operator: %s, must be one of: %v", c.GrantControls.Operator, validOperators)
	}

	// At least one control must be specified
	if len(c.GrantControls.BuiltInControls) == 0 &&
		len(c.GrantControls.CustomAuthenticationFactors) == 0 &&
		len(c.GrantControls.TermsOfUse) == 0 {
		return fmt.Errorf("at least one grant control must be specified")
	}

	return nil
}

// GetManagedFields returns the list of fields this configuration manages
func (c *ConditionalAccessConfig) GetManagedFields() []string {
	// If explicitly specified, use those fields
	if len(c.ManagedFieldsList) > 0 {
		return c.ManagedFieldsList
	}

	// Default managed fields
	fields := []string{"display_name", "state", "conditions", "grant_controls"}

	if c.SessionControls != nil {
		fields = append(fields, "session_controls")
	}

	return fields
}

// Set creates or updates a Conditional Access policy according to the configuration
func (m *conditionalAccessModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	// Convert ConfigState to ConditionalAccessConfig
	configMap := config.AsMap()
	caConfig := &ConditionalAccessConfig{}

	// Map basic fields
	if displayName, ok := configMap["display_name"].(string); ok {
		caConfig.DisplayName = displayName
	}
	if state, ok := configMap["state"].(string); ok {
		caConfig.State = state
	}
	if tenantID, ok := configMap["tenant_id"].(string); ok {
		caConfig.TenantID = tenantID
	}

	// Map conditions
	if conditions, ok := configMap["conditions"].(ConditionalAccessConditions); ok {
		caConfig.Conditions = conditions
	}

	// Map grant controls
	if grantControls, ok := configMap["grant_controls"].(ConditionalAccessGrantControls); ok {
		caConfig.GrantControls = grantControls
	}

	// Map session controls
	if sessionControls, ok := configMap["session_controls"].(*ConditionalAccessSessionControls); ok {
		caConfig.SessionControls = sessionControls
	}

	// Validate configuration
	if err := caConfig.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Authenticate with Microsoft Graph
	token, err := m.authProvider.GetAccessToken(ctx, caConfig.TenantID)
	if err != nil {
		return fmt.Errorf("failed to authenticate with Microsoft Graph: %w", err)
	}

	// Parse policy ID from resource ID if provided
	policyID := extractPolicyID(resourceID)

	// Check if policy exists
	var existingPolicy *graph.ConditionalAccessPolicy
	if policyID != "" {
		existingPolicy, err = m.graphClient.GetConditionalAccessPolicy(ctx, token, policyID)
		if err != nil {
			if !graph.IsNotFoundError(err) {
				return fmt.Errorf("failed to check if policy exists: %w", err)
			}
			// Policy doesn't exist, we'll create it
		}
	}

	if existingPolicy == nil {
		// Create new policy
		return m.createPolicy(ctx, token, caConfig)
	}

	// Update existing policy with only managed fields
	return m.updatePolicy(ctx, token, caConfig, existingPolicy)
}

// Get retrieves the current configuration of a Conditional Access policy
func (m *conditionalAccessModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	// Parse resource ID to extract tenant ID and policy ID
	// Format: tenantID:policyID
	tenantID, policyID, err := parseCAResourceID(resourceID)
	if err != nil {
		return nil, fmt.Errorf("invalid resource ID format: %w", err)
	}

	// Authenticate with Microsoft Graph
	token, err := m.authProvider.GetAccessToken(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with Microsoft Graph: %w", err)
	}

	// Get policy from Graph API
	policy, err := m.graphClient.GetConditionalAccessPolicy(ctx, token, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy from Graph API: %w", err)
	}

	// Convert Graph policy to our config format
	config := &ConditionalAccessConfig{
		DisplayName:   policy.DisplayName,
		State:         policy.State,
		TenantID:      tenantID,
		Conditions:    convertGraphConditions(policy.Conditions),
		GrantControls: convertGraphGrantControls(policy.GrantControls),
	}

	// Convert session controls if present
	if policy.SessionControls != (graph.ConditionalAccessSessionControls{}) {
		config.SessionControls = convertGraphSessionControls(policy.SessionControls)
	}

	return config, nil
}

// createPolicy creates a new Conditional Access policy
func (m *conditionalAccessModule) createPolicy(ctx context.Context, token *auth.AccessToken, config *ConditionalAccessConfig) error {
	request := &graph.CreateConditionalAccessPolicyRequest{
		DisplayName:   config.DisplayName,
		State:         config.State,
		Conditions:    convertToGraphConditions(config.Conditions),
		GrantControls: convertToGraphGrantControls(config.GrantControls),
	}

	// Add session controls if specified
	if config.SessionControls != nil {
		request.SessionControls = convertToGraphSessionControls(*config.SessionControls)
	}

	// Create the policy
	_, err := m.graphClient.CreateConditionalAccessPolicy(ctx, token, request)
	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	return nil
}

// updatePolicy updates an existing Conditional Access policy with only the managed fields
func (m *conditionalAccessModule) updatePolicy(ctx context.Context, token *auth.AccessToken, config *ConditionalAccessConfig, existingPolicy *graph.ConditionalAccessPolicy) error {
	managedFields := config.GetManagedFields()
	updateRequest := &graph.UpdateConditionalAccessPolicyRequest{}

	// Only update managed fields
	for _, field := range managedFields {
		switch field {
		case "display_name":
			if config.DisplayName != existingPolicy.DisplayName {
				updateRequest.DisplayName = &config.DisplayName
			}
		case "state":
			if config.State != existingPolicy.State {
				updateRequest.State = &config.State
			}
		case "conditions":
			// Always update conditions if managed (complex comparison would be needed for partial updates)
			graphConditions := convertToGraphConditions(config.Conditions)
			updateRequest.Conditions = &graphConditions
		case "grant_controls":
			// Always update grant controls if managed
			graphGrantControls := convertToGraphGrantControls(config.GrantControls)
			updateRequest.GrantControls = &graphGrantControls
		case "session_controls":
			if config.SessionControls != nil {
				graphSessionControls := convertToGraphSessionControls(*config.SessionControls)
				updateRequest.SessionControls = &graphSessionControls
			}
		}
	}

	// Update the policy if there are changes
	return m.graphClient.UpdateConditionalAccessPolicy(ctx, token, existingPolicy.ID, updateRequest)
}

// parseCAResourceID parses a resource ID into tenant ID and policy ID
// Format: tenantID:policyID
func parseCAResourceID(resourceID string) (tenantID, policyID string, err error) {
	parts := strings.SplitN(resourceID, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("resource ID must be in format 'tenantID:policyID'")
	}
	return parts[0], parts[1], nil
}

// extractPolicyID extracts policy ID from resource ID (may be empty for new policies)
func extractPolicyID(resourceID string) string {
	parts := strings.SplitN(resourceID, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// convertGraphConditions converts Graph API conditions to our format
func convertGraphConditions(graphConditions graph.ConditionalAccessConditions) ConditionalAccessConditions {
	return ConditionalAccessConditions{
		Users: ConditionalAccessUsers{
			IncludeUsers:  graphConditions.Users.IncludeUsers,
			ExcludeUsers:  graphConditions.Users.ExcludeUsers,
			IncludeGroups: graphConditions.Users.IncludeGroups,
			ExcludeGroups: graphConditions.Users.ExcludeGroups,
			IncludeRoles:  graphConditions.Users.IncludeRoles,
			ExcludeRoles:  graphConditions.Users.ExcludeRoles,
		},
		Applications: ConditionalAccessApplications{
			IncludeApplications: graphConditions.Applications.IncludeApplications,
			ExcludeApplications: graphConditions.Applications.ExcludeApplications,
			IncludeUserActions:  graphConditions.Applications.IncludeUserActions,
		},
		ClientAppTypes:   graphConditions.ClientAppTypes,
		SignInRiskLevels: graphConditions.SignInRiskLevels,
		UserRiskLevels:   graphConditions.UserRiskLevels,
	}
}

// convertToGraphConditions converts our format to Graph API conditions
func convertToGraphConditions(conditions ConditionalAccessConditions) graph.ConditionalAccessConditions {
	return graph.ConditionalAccessConditions{
		Users: graph.ConditionalAccessUsers{
			IncludeUsers:  conditions.Users.IncludeUsers,
			ExcludeUsers:  conditions.Users.ExcludeUsers,
			IncludeGroups: conditions.Users.IncludeGroups,
			ExcludeGroups: conditions.Users.ExcludeGroups,
			IncludeRoles:  conditions.Users.IncludeRoles,
			ExcludeRoles:  conditions.Users.ExcludeRoles,
		},
		Applications: graph.ConditionalAccessApplications{
			IncludeApplications: conditions.Applications.IncludeApplications,
			ExcludeApplications: conditions.Applications.ExcludeApplications,
			IncludeUserActions:  conditions.Applications.IncludeUserActions,
		},
		ClientAppTypes:   conditions.ClientAppTypes,
		SignInRiskLevels: conditions.SignInRiskLevels,
		UserRiskLevels:   conditions.UserRiskLevels,
	}
}

// convertGraphGrantControls converts Graph API grant controls to our format
func convertGraphGrantControls(graphGrantControls graph.ConditionalAccessGrantControls) ConditionalAccessGrantControls {
	return ConditionalAccessGrantControls{
		Operator:                    graphGrantControls.Operator,
		BuiltInControls:             graphGrantControls.BuiltInControls,
		CustomAuthenticationFactors: graphGrantControls.CustomAuthenticationFactors,
		TermsOfUse:                  graphGrantControls.TermsOfUse,
	}
}

// convertToGraphGrantControls converts our format to Graph API grant controls
func convertToGraphGrantControls(grantControls ConditionalAccessGrantControls) graph.ConditionalAccessGrantControls {
	return graph.ConditionalAccessGrantControls{
		Operator:                    grantControls.Operator,
		BuiltInControls:             grantControls.BuiltInControls,
		CustomAuthenticationFactors: grantControls.CustomAuthenticationFactors,
		TermsOfUse:                  grantControls.TermsOfUse,
	}
}

// convertGraphSessionControls converts Graph API session controls to our format
func convertGraphSessionControls(graphSessionControls graph.ConditionalAccessSessionControls) *ConditionalAccessSessionControls {
	sessionControls := &ConditionalAccessSessionControls{}

	if graphSessionControls.ApplicationEnforcedRestrictions.IsEnabled {
		sessionControls.ApplicationEnforcedRestrictions = &ApplicationEnforcedRestrictions{
			IsEnabled: graphSessionControls.ApplicationEnforcedRestrictions.IsEnabled,
		}
	}

	if graphSessionControls.CloudAppSecurity.IsEnabled {
		sessionControls.CloudAppSecurity = &CloudAppSecurity{
			IsEnabled:            graphSessionControls.CloudAppSecurity.IsEnabled,
			CloudAppSecurityType: graphSessionControls.CloudAppSecurity.CloudAppSecurityType,
		}
	}

	if graphSessionControls.PersistentBrowser.IsEnabled {
		sessionControls.PersistentBrowser = &PersistentBrowser{
			IsEnabled: graphSessionControls.PersistentBrowser.IsEnabled,
			Mode:      graphSessionControls.PersistentBrowser.Mode,
		}
	}

	if graphSessionControls.SignInFrequency.IsEnabled {
		sessionControls.SignInFrequency = &SignInFrequency{
			IsEnabled:         graphSessionControls.SignInFrequency.IsEnabled,
			Type:              graphSessionControls.SignInFrequency.Type,
			Value:             graphSessionControls.SignInFrequency.Value,
			FrequencyInterval: graphSessionControls.SignInFrequency.FrequencyInterval,
		}
	}

	return sessionControls
}

// convertToGraphSessionControls converts our format to Graph API session controls
func convertToGraphSessionControls(sessionControls ConditionalAccessSessionControls) graph.ConditionalAccessSessionControls {
	graphSessionControls := graph.ConditionalAccessSessionControls{}

	if sessionControls.ApplicationEnforcedRestrictions != nil {
		graphSessionControls.ApplicationEnforcedRestrictions = graph.ApplicationEnforcedRestrictions{
			IsEnabled: sessionControls.ApplicationEnforcedRestrictions.IsEnabled,
		}
	}

	if sessionControls.CloudAppSecurity != nil {
		graphSessionControls.CloudAppSecurity = graph.CloudAppSecurity{
			IsEnabled:            sessionControls.CloudAppSecurity.IsEnabled,
			CloudAppSecurityType: sessionControls.CloudAppSecurity.CloudAppSecurityType,
		}
	}

	if sessionControls.PersistentBrowser != nil {
		graphSessionControls.PersistentBrowser = graph.PersistentBrowser{
			IsEnabled: sessionControls.PersistentBrowser.IsEnabled,
			Mode:      sessionControls.PersistentBrowser.Mode,
		}
	}

	if sessionControls.SignInFrequency != nil {
		graphSessionControls.SignInFrequency = graph.SignInFrequency{
			IsEnabled:         sessionControls.SignInFrequency.IsEnabled,
			Type:              sessionControls.SignInFrequency.Type,
			Value:             sessionControls.SignInFrequency.Value,
			FrequencyInterval: sessionControls.SignInFrequency.FrequencyInterval,
		}
	}

	return graphSessionControls
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
