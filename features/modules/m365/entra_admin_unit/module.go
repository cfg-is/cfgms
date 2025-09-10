package entra_admin_unit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
	"gopkg.in/yaml.v3"
)

// entraAdminUnitModule implements the Module interface for Entra ID Administrative Unit management
type entraAdminUnitModule struct {
	authProvider auth.Provider
	graphClient  graph.Client
}

// New creates a new instance of the Entra Administrative Unit module
func New(authProvider auth.Provider, graphClient graph.Client) modules.Module {
	return &entraAdminUnitModule{
		authProvider: authProvider,
		graphClient:  graphClient,
	}
}

// EntraAdminUnitConfig represents the configuration for an Entra ID Administrative Unit
type EntraAdminUnitConfig struct {
	// Core administrative unit properties
	DisplayName string `yaml:"display_name"`
	Description string `yaml:"description,omitempty"`
	Visibility  string `yaml:"visibility"` // "Public", "HiddenMembership"

	// Membership settings
	MembershipType string `yaml:"membership_type,omitempty"` // "Dynamic", "Assigned"
	MembershipRule string `yaml:"membership_rule,omitempty"` // For dynamic groups

	// Members - users and groups that belong to this administrative unit
	UserMembers  []string `yaml:"user_members,omitempty"`
	GroupMembers []string `yaml:"group_members,omitempty"`

	// Scoped role assignments - administrators with specific roles for this AU
	ScopedRoleMembers []ScopedRoleMember `yaml:"scoped_role_members,omitempty"`

	// Extensions and custom attributes
	ExtensionAttributes map[string]interface{} `yaml:"extension_attributes,omitempty"`

	// Restricted management settings
	IsMemberManagementRestricted bool     `yaml:"is_member_management_restricted,omitempty"`
	RestrictedManagementUnits    []string `yaml:"restricted_management_units,omitempty"`

	// Tenant configuration
	TenantID string `yaml:"tenant_id"`

	// Managed fields - controls which fields Set() will modify
	ManagedFieldsList []string `yaml:"managed_fields,omitempty"`
}

// ScopedRoleMember represents a role assignment scoped to this administrative unit
type ScopedRoleMember struct {
	// Principal (user or service principal) being assigned the role
	PrincipalID   string `yaml:"principal_id"`
	PrincipalType string `yaml:"principal_type"` // "User", "ServicePrincipal"
	
	// Role being assigned
	RoleDefinitionID string `yaml:"role_definition_id"`
	RoleName         string `yaml:"role_name,omitempty"` // For convenience/documentation
	
	// Assignment details
	AssignmentType string `yaml:"assignment_type,omitempty"` // "Eligible", "Active"
	StartDateTime  string `yaml:"start_date_time,omitempty"`
	EndDateTime    string `yaml:"end_date_time,omitempty"`
	
	// Justification for the assignment
	Justification string `yaml:"justification,omitempty"`
}

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *EntraAdminUnitConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"display_name": c.DisplayName,
		"visibility":   c.Visibility,
		"tenant_id":    c.TenantID,
	}

	if c.Description != "" {
		result["description"] = c.Description
	}
	if c.MembershipType != "" {
		result["membership_type"] = c.MembershipType
	}
	if c.MembershipRule != "" {
		result["membership_rule"] = c.MembershipRule
	}
	if len(c.UserMembers) > 0 {
		result["user_members"] = c.UserMembers
	}
	if len(c.GroupMembers) > 0 {
		result["group_members"] = c.GroupMembers
	}
	if len(c.ScopedRoleMembers) > 0 {
		result["scoped_role_members"] = c.ScopedRoleMembers
	}
	if len(c.ExtensionAttributes) > 0 {
		result["extension_attributes"] = c.ExtensionAttributes
	}
	if c.IsMemberManagementRestricted {
		result["is_member_management_restricted"] = c.IsMemberManagementRestricted
		if len(c.RestrictedManagementUnits) > 0 {
			result["restricted_management_units"] = c.RestrictedManagementUnits
		}
	}

	return result
}

// ToYAML serializes the configuration to YAML for export/storage
func (c *EntraAdminUnitConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration
func (c *EntraAdminUnitConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate ensures the configuration is valid
func (c *EntraAdminUnitConfig) Validate() error {
	if c.DisplayName == "" {
		return fmt.Errorf("display_name is required")
	}

	if c.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}

	// Validate visibility
	if c.Visibility != "" {
		validVisibilities := map[string]bool{
			"Public":           true,
			"HiddenMembership": true,
		}
		if !validVisibilities[c.Visibility] {
			return fmt.Errorf("invalid visibility: %s (must be Public or HiddenMembership)", c.Visibility)
		}
	}

	// Validate membership type
	if c.MembershipType != "" {
		validMembershipTypes := map[string]bool{
			"Dynamic":  true,
			"Assigned": true,
		}
		if !validMembershipTypes[c.MembershipType] {
			return fmt.Errorf("invalid membership_type: %s", c.MembershipType)
		}
	}

	// If membership type is dynamic, a rule is required
	if c.MembershipType == "Dynamic" && c.MembershipRule == "" {
		return fmt.Errorf("membership_rule is required when membership_type is Dynamic")
	}

	// Validate scoped role members
	for i, roleMember := range c.ScopedRoleMembers {
		if roleMember.PrincipalID == "" {
			return fmt.Errorf("scoped_role_member %d: principal_id is required", i)
		}
		if roleMember.RoleDefinitionID == "" {
			return fmt.Errorf("scoped_role_member %d: role_definition_id is required", i)
		}
		if roleMember.PrincipalType != "" {
			validPrincipalTypes := map[string]bool{
				"User":             true,
				"ServicePrincipal": true,
			}
			if !validPrincipalTypes[roleMember.PrincipalType] {
				return fmt.Errorf("scoped_role_member %d: invalid principal_type: %s", i, roleMember.PrincipalType)
			}
		}
	}

	return nil
}

// GetManagedFields returns the list of fields this configuration manages
func (c *EntraAdminUnitConfig) GetManagedFields() []string {
	// If explicitly specified, use those fields
	if len(c.ManagedFieldsList) > 0 {
		return c.ManagedFieldsList
	}

	// Default managed fields based on what's configured
	fields := []string{"display_name", "visibility"}

	if c.Description != "" {
		fields = append(fields, "description")
	}
	if c.MembershipType != "" {
		fields = append(fields, "membership_type")
	}
	if c.MembershipRule != "" {
		fields = append(fields, "membership_rule")
	}
	if len(c.UserMembers) > 0 {
		fields = append(fields, "user_members")
	}
	if len(c.GroupMembers) > 0 {
		fields = append(fields, "group_members")
	}
	if len(c.ScopedRoleMembers) > 0 {
		fields = append(fields, "scoped_role_members")
	}
	if len(c.ExtensionAttributes) > 0 {
		fields = append(fields, "extension_attributes")
	}
	if c.IsMemberManagementRestricted {
		fields = append(fields, "is_member_management_restricted")
	}

	return fields
}

// Set creates or updates an Entra ID Administrative Unit according to the configuration
func (m *entraAdminUnitModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	// Convert ConfigState to EntraAdminUnitConfig
	configMap := config.AsMap()
	auConfig := &EntraAdminUnitConfig{}

	// Map basic fields
	if displayName, ok := configMap["display_name"].(string); ok {
		auConfig.DisplayName = displayName
	}
	if description, ok := configMap["description"].(string); ok {
		auConfig.Description = description
	}
	if visibility, ok := configMap["visibility"].(string); ok {
		auConfig.Visibility = visibility
	}
	if tenantID, ok := configMap["tenant_id"].(string); ok {
		auConfig.TenantID = tenantID
	}

	// Map membership settings
	if membershipType, ok := configMap["membership_type"].(string); ok {
		auConfig.MembershipType = membershipType
	}
	if membershipRule, ok := configMap["membership_rule"].(string); ok {
		auConfig.MembershipRule = membershipRule
	}

	// Map members
	if userMembers, ok := configMap["user_members"].([]string); ok {
		auConfig.UserMembers = userMembers
	}
	if groupMembers, ok := configMap["group_members"].([]string); ok {
		auConfig.GroupMembers = groupMembers
	}

	// Map scoped role members (simplified - would need proper type conversion)
	if scopedRoleMembers, ok := configMap["scoped_role_members"].([]ScopedRoleMember); ok {
		auConfig.ScopedRoleMembers = scopedRoleMembers
	}

	// Validate configuration
	if err := auConfig.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Authenticate with Microsoft Graph
	token, err := m.authProvider.GetAccessToken(ctx, auConfig.TenantID)
	if err != nil {
		return fmt.Errorf("failed to authenticate with Microsoft Graph: %w", err)
	}

	// Check if administrative unit exists
	auID := extractAdminUnitID(resourceID)
	existingAU, err := m.getAdminUnitByID(ctx, token, auID)
	if err != nil {
		// Administrative unit doesn't exist, create it
		return m.createAdminUnit(ctx, token, auConfig)
	}

	// Administrative unit exists, update it with only managed fields
	return m.updateAdminUnit(ctx, token, auConfig, existingAU)
}

// Get retrieves the current configuration of an Entra ID Administrative Unit
func (m *entraAdminUnitModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	// Parse resource ID to extract tenant ID and AU ID
	// Format: tenantID:adminUnitID
	tenantID, auID, err := parseEntraAdminUnitResourceID(resourceID)
	if err != nil {
		return nil, fmt.Errorf("invalid resource ID format: %w", err)
	}

	// Authenticate with Microsoft Graph
	token, err := m.authProvider.GetAccessToken(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with Microsoft Graph: %w", err)
	}

	// Get administrative unit from Graph API
	au, err := m.getAdminUnitByID(ctx, token, auID)
	if err != nil {
		return nil, fmt.Errorf("failed to get administrative unit from Graph API: %w", err)
	}

	// Get members
	userMembers, err := m.getAdminUnitUserMembers(ctx, token, auID)
	if err != nil {
		return nil, fmt.Errorf("failed to get administrative unit user members: %w", err)
	}

	groupMembers, err := m.getAdminUnitGroupMembers(ctx, token, auID)
	if err != nil {
		return nil, fmt.Errorf("failed to get administrative unit group members: %w", err)
	}

	// Get scoped role members
	scopedRoleMembers, err := m.getAdminUnitScopedRoleMembers(ctx, token, auID)
	if err != nil {
		return nil, fmt.Errorf("failed to get scoped role members: %w", err)
	}

	// Convert to our config format
	config := &EntraAdminUnitConfig{
		DisplayName:       au.DisplayName,
		Description:       au.Description,
		Visibility:        au.Visibility,
		MembershipType:    au.MembershipType,
		MembershipRule:    au.MembershipRule,
		TenantID:          tenantID,
		UserMembers:       userMembers,
		GroupMembers:      groupMembers,
		ScopedRoleMembers: scopedRoleMembers,
	}

	return config, nil
}

// Helper methods for Graph API operations

func (m *entraAdminUnitModule) getAdminUnitByID(ctx context.Context, token *auth.AccessToken, auID string) (*AdminUnitInfo, error) {
	// Get administrative unit from Graph API
	au, err := m.graphClient.GetAdministrativeUnit(ctx, token, auID)
	if err != nil {
		return nil, fmt.Errorf("failed to get administrative unit from Graph API: %w", err)
	}

	// Convert Graph API response to our internal format
	return &AdminUnitInfo{
		ID:                            au.ID,
		DisplayName:                   au.DisplayName,
		Description:                   au.Description,
		Visibility:                    au.Visibility,
		MembershipType:                au.MembershipType,
		MembershipRule:                au.MembershipRule,
		MembershipRuleProcessingState: au.MembershipRuleProcessingState,
	}, nil
}

func (m *entraAdminUnitModule) createAdminUnit(ctx context.Context, token *auth.AccessToken, config *EntraAdminUnitConfig) error {
	// Build the create request
	request := &graph.CreateAdministrativeUnitRequest{
		DisplayName: config.DisplayName,
		Visibility:  config.Visibility,
	}

	if config.Description != "" {
		request.Description = config.Description
	}

	if config.MembershipType == "Dynamic" {
		request.MembershipType = "Dynamic"
		request.MembershipRule = config.MembershipRule
		request.MembershipRuleProcessingState = "On"
	}

	// Create administrative unit via Graph API
	au, err := m.graphClient.CreateAdministrativeUnit(ctx, token, request)
	if err != nil {
		return fmt.Errorf("failed to create administrative unit via Graph API: %w", err)
	}
	
	// Wait for creation to propagate
	time.Sleep(2 * time.Second)

	// Add user members if specified and not dynamic
	if len(config.UserMembers) > 0 && config.MembershipType != "Dynamic" {
		for _, userID := range config.UserMembers {
			if err := m.addUserMember(ctx, token, au.ID, userID); err != nil {
				return fmt.Errorf("failed to add user member %s: %w", userID, err)
			}
		}
	}

	// Add group members if specified and not dynamic
	if len(config.GroupMembers) > 0 && config.MembershipType != "Dynamic" {
		for _, groupID := range config.GroupMembers {
			if err := m.addGroupMember(ctx, token, au.ID, groupID); err != nil {
				return fmt.Errorf("failed to add group member %s: %w", groupID, err)
			}
		}
	}

	// Add scoped role members if specified
	if len(config.ScopedRoleMembers) > 0 {
		for _, roleMember := range config.ScopedRoleMembers {
			if err := m.addScopedRoleMember(ctx, token, au.ID, &roleMember); err != nil {
				return fmt.Errorf("failed to add scoped role member %s: %w", roleMember.PrincipalID, err)
			}
		}
	}

	return nil
}

func (m *entraAdminUnitModule) updateAdminUnit(ctx context.Context, token *auth.AccessToken, config *EntraAdminUnitConfig, existingAU *AdminUnitInfo) error {
	managedFields := config.GetManagedFields()
	updates := make(map[string]interface{})

	// Only update managed fields
	for _, field := range managedFields {
		switch field {
		case "display_name":
			if config.DisplayName != existingAU.DisplayName {
				updates["displayName"] = config.DisplayName
			}
		case "description":
			if config.Description != existingAU.Description {
				updates["description"] = config.Description
			}
		case "visibility":
			if config.Visibility != existingAU.Visibility {
				updates["visibility"] = config.Visibility
			}
		case "membership_rule":
			if config.MembershipRule != existingAU.MembershipRule {
				updates["membershipRule"] = config.MembershipRule
			}
		}
	}

	// Update the administrative unit if there are changes
	if len(updates) > 0 {
		// Build the update request
		updateRequest := &graph.UpdateAdministrativeUnitRequest{}
		
		if displayName, ok := updates["displayName"].(string); ok {
			updateRequest.DisplayName = &displayName
		}
		if description, ok := updates["description"].(string); ok {
			updateRequest.Description = &description
		}
		if visibility, ok := updates["visibility"].(string); ok {
			updateRequest.Visibility = &visibility
		}
		if membershipRule, ok := updates["membershipRule"].(string); ok {
			updateRequest.MembershipRule = &membershipRule
		}
		
		// Update administrative unit via Graph API
		if err := m.graphClient.UpdateAdministrativeUnit(ctx, token, existingAU.ID, updateRequest); err != nil {
			return fmt.Errorf("failed to update administrative unit via Graph API: %w", err)
		}
	}

	// Handle membership if managed and not dynamic
	if config.MembershipType != "Dynamic" {
		if contains(managedFields, "user_members") {
			if err := m.syncUserMembers(ctx, token, existingAU.ID, config.UserMembers); err != nil {
				return fmt.Errorf("failed to sync user members: %w", err)
			}
		}

		if contains(managedFields, "group_members") {
			if err := m.syncGroupMembers(ctx, token, existingAU.ID, config.GroupMembers); err != nil {
				return fmt.Errorf("failed to sync group members: %w", err)
			}
		}
	}

	// Handle scoped role members if managed
	if contains(managedFields, "scoped_role_members") {
		if err := m.syncScopedRoleMembers(ctx, token, existingAU.ID, config.ScopedRoleMembers); err != nil {
			return fmt.Errorf("failed to sync scoped role members: %w", err)
		}
	}

	return nil
}

// Additional helper methods (placeholders)

func (m *entraAdminUnitModule) getAdminUnitUserMembers(ctx context.Context, token *auth.AccessToken, auID string) ([]string, error) {
	// Placeholder - would use Graph API /administrativeUnits/{id}/members/microsoft.graph.user
	return []string{}, nil
}

func (m *entraAdminUnitModule) getAdminUnitGroupMembers(ctx context.Context, token *auth.AccessToken, auID string) ([]string, error) {
	// Placeholder - would use Graph API /administrativeUnits/{id}/members/microsoft.graph.group
	return []string{}, nil
}

func (m *entraAdminUnitModule) getAdminUnitScopedRoleMembers(ctx context.Context, token *auth.AccessToken, auID string) ([]ScopedRoleMember, error) {
	// Placeholder - would use Graph API /administrativeUnits/{id}/scopedRoleMembers
	return []ScopedRoleMember{}, nil
}

func (m *entraAdminUnitModule) addUserMember(ctx context.Context, token *auth.AccessToken, auID, userID string) error {
	// Placeholder - would use Graph API POST /administrativeUnits/{id}/members/$ref
	return nil
}

func (m *entraAdminUnitModule) addGroupMember(ctx context.Context, token *auth.AccessToken, auID, groupID string) error {
	// Placeholder - would use Graph API POST /administrativeUnits/{id}/members/$ref
	return nil
}

func (m *entraAdminUnitModule) addScopedRoleMember(ctx context.Context, token *auth.AccessToken, auID string, roleMember *ScopedRoleMember) error {
	// Placeholder - would use Graph API POST /administrativeUnits/{id}/scopedRoleMembers
	return nil
}

func (m *entraAdminUnitModule) syncUserMembers(ctx context.Context, token *auth.AccessToken, auID string, desiredMembers []string) error {
	// Similar logic to user license/group sync
	return nil
}

func (m *entraAdminUnitModule) syncGroupMembers(ctx context.Context, token *auth.AccessToken, auID string, desiredMembers []string) error {
	// Similar logic to user license/group sync
	return nil
}

func (m *entraAdminUnitModule) syncScopedRoleMembers(ctx context.Context, token *auth.AccessToken, auID string, desiredMembers []ScopedRoleMember) error {
	// Would implement scoped role member synchronization
	return nil
}

// Utility types and functions

type AdminUnitInfo struct {
	ID                            string
	DisplayName                   string
	Description                   string
	Visibility                    string
	MembershipType                string
	MembershipRule                string
	MembershipRuleProcessingState string
}

func parseEntraAdminUnitResourceID(resourceID string) (tenantID, auID string, err error) {
	parts := strings.SplitN(resourceID, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("resource ID must be in format 'tenantID:adminUnitID'")
	}
	return parts[0], parts[1], nil
}

func extractAdminUnitID(resourceID string) string {
	_, auID, _ := parseEntraAdminUnitResourceID(resourceID)
	return auID
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}