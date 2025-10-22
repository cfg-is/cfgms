package entra_group

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

// entraGroupModule implements the Module interface for Entra ID group management
type entraGroupModule struct {
	authProvider auth.Provider
	graphClient  graph.Client
}

// New creates a new instance of the Entra Group module
func New(authProvider auth.Provider, graphClient graph.Client) modules.Module {
	return &entraGroupModule{
		authProvider: authProvider,
		graphClient:  graphClient,
	}
}

// EntraGroupConfig represents the configuration for an Entra ID group
type EntraGroupConfig struct {
	// Core group properties
	DisplayName  string `yaml:"display_name"`
	Description  string `yaml:"description,omitempty"`
	MailNickname string `yaml:"mail_nickname"`
	MailEnabled  bool   `yaml:"mail_enabled"`

	// Group type and security
	SecurityEnabled bool   `yaml:"security_enabled"`
	GroupType       string `yaml:"group_type,omitempty"` // "Unified", "Security", "Distribution"
	Visibility      string `yaml:"visibility,omitempty"` // "Private", "Public"

	// Membership settings
	MembershipRule          string `yaml:"membership_rule,omitempty"`
	MembershipRuleEnabled   bool   `yaml:"membership_rule_enabled,omitempty"`
	AllowExternalSenders    bool   `yaml:"allow_external_senders,omitempty"`
	AutoSubscribeNewMembers bool   `yaml:"auto_subscribe_new_members,omitempty"`

	// Members and owners
	Members []string `yaml:"members,omitempty"`
	Owners  []string `yaml:"owners,omitempty"`

	// Team settings (for Microsoft Teams integration)
	IsTeamEnabled bool          `yaml:"is_team_enabled,omitempty"`
	TeamSettings  *TeamSettings `yaml:"team_settings,omitempty"`
	TeamChannels  []TeamChannel `yaml:"team_channels,omitempty"`

	// Tenant configuration
	TenantID string `yaml:"tenant_id"`

	// Managed fields - controls which fields Set() will modify
	ManagedFieldsList []string `yaml:"managed_fields,omitempty"`
}

// TeamSettings represents Microsoft Teams specific settings
type TeamSettings struct {
	AllowAddRemoveApps         bool   `yaml:"allow_add_remove_apps,omitempty"`
	AllowCreatePrivateChannels bool   `yaml:"allow_create_private_channels,omitempty"`
	AllowCreateUpdateChannels  bool   `yaml:"allow_create_update_channels,omitempty"`
	AllowDeleteChannels        bool   `yaml:"allow_delete_channels,omitempty"`
	AllowUserEditMessages      bool   `yaml:"allow_user_edit_messages,omitempty"`
	AllowGuestCreateChannels   bool   `yaml:"allow_guest_create_channels,omitempty"`
	AllowGuestDeleteChannels   bool   `yaml:"allow_guest_delete_channels,omitempty"`
	Fun                        string `yaml:"fun_settings,omitempty"` // "strict", "moderate", "enabled"
}

// TeamChannel represents a Microsoft Teams channel
type TeamChannel struct {
	DisplayName string `yaml:"display_name"`
	Description string `yaml:"description,omitempty"`
	ChannelType string `yaml:"channel_type,omitempty"` // "standard", "private", "shared"
	IsFavorite  bool   `yaml:"is_favorite,omitempty"`
	WebURL      string `yaml:"web_url,omitempty"`
}

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *EntraGroupConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"display_name":     c.DisplayName,
		"mail_nickname":    c.MailNickname,
		"mail_enabled":     c.MailEnabled,
		"security_enabled": c.SecurityEnabled,
		"tenant_id":        c.TenantID,
	}

	if c.Description != "" {
		result["description"] = c.Description
	}
	if c.GroupType != "" {
		result["group_type"] = c.GroupType
	}
	if c.Visibility != "" {
		result["visibility"] = c.Visibility
	}
	if c.MembershipRule != "" {
		result["membership_rule"] = c.MembershipRule
		result["membership_rule_enabled"] = c.MembershipRuleEnabled
	}
	if c.AllowExternalSenders {
		result["allow_external_senders"] = c.AllowExternalSenders
	}
	if c.AutoSubscribeNewMembers {
		result["auto_subscribe_new_members"] = c.AutoSubscribeNewMembers
	}
	if len(c.Members) > 0 {
		result["members"] = c.Members
	}
	if len(c.Owners) > 0 {
		result["owners"] = c.Owners
	}
	if c.IsTeamEnabled {
		result["is_team_enabled"] = c.IsTeamEnabled
		if c.TeamSettings != nil {
			result["team_settings"] = c.TeamSettings
		}
		if len(c.TeamChannels) > 0 {
			result["team_channels"] = c.TeamChannels
		}
	}

	return result
}

// ToYAML serializes the configuration to YAML for export/storage
func (c *EntraGroupConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration
func (c *EntraGroupConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate ensures the configuration is valid
func (c *EntraGroupConfig) Validate() error {
	if c.DisplayName == "" {
		return fmt.Errorf("display_name is required")
	}

	if c.MailNickname == "" {
		return fmt.Errorf("mail_nickname is required")
	}

	if c.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}

	// Validate group type
	if c.GroupType != "" {
		validTypes := map[string]bool{
			"Unified":      true,
			"Security":     true,
			"Distribution": true,
		}
		if !validTypes[c.GroupType] {
			return fmt.Errorf("invalid group_type: %s (must be Unified, Security, or Distribution)", c.GroupType)
		}
	}

	// Validate visibility
	if c.Visibility != "" {
		validVisibilities := map[string]bool{
			"Private":          true,
			"Public":           true,
			"Hiddenmembership": true,
		}
		if !validVisibilities[c.Visibility] {
			return fmt.Errorf("invalid visibility: %s", c.Visibility)
		}
	}

	// Validate team channels if team is enabled
	if c.IsTeamEnabled && len(c.TeamChannels) > 0 {
		for i, channel := range c.TeamChannels {
			if channel.DisplayName == "" {
				return fmt.Errorf("team channel %d: display_name is required", i)
			}
		}
	}

	return nil
}

// GetManagedFields returns the list of fields this configuration manages
func (c *EntraGroupConfig) GetManagedFields() []string {
	// If explicitly specified, use those fields
	if len(c.ManagedFieldsList) > 0 {
		return c.ManagedFieldsList
	}

	// Default managed fields based on what's configured
	fields := []string{"display_name", "mail_enabled", "security_enabled"}

	if c.Description != "" {
		fields = append(fields, "description")
	}
	if c.GroupType != "" {
		fields = append(fields, "group_type")
	}
	if c.Visibility != "" {
		fields = append(fields, "visibility")
	}
	if c.MembershipRule != "" {
		fields = append(fields, "membership_rule", "membership_rule_enabled")
	}
	if len(c.Members) > 0 {
		fields = append(fields, "members")
	}
	if len(c.Owners) > 0 {
		fields = append(fields, "owners")
	}
	if c.IsTeamEnabled {
		fields = append(fields, "is_team_enabled")
		if c.TeamSettings != nil {
			fields = append(fields, "team_settings")
		}
		if len(c.TeamChannels) > 0 {
			fields = append(fields, "team_channels")
		}
	}

	return fields
}

// Set creates or updates an Entra ID group according to the configuration
func (m *entraGroupModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	// Convert ConfigState to EntraGroupConfig
	configMap := config.AsMap()
	groupConfig := &EntraGroupConfig{}

	// Map basic fields
	if displayName, ok := configMap["display_name"].(string); ok {
		groupConfig.DisplayName = displayName
	}
	if description, ok := configMap["description"].(string); ok {
		groupConfig.Description = description
	}
	if mailNickname, ok := configMap["mail_nickname"].(string); ok {
		groupConfig.MailNickname = mailNickname
	}
	if mailEnabled, ok := configMap["mail_enabled"].(bool); ok {
		groupConfig.MailEnabled = mailEnabled
	}
	if securityEnabled, ok := configMap["security_enabled"].(bool); ok {
		groupConfig.SecurityEnabled = securityEnabled
	}
	if tenantID, ok := configMap["tenant_id"].(string); ok {
		groupConfig.TenantID = tenantID
	}

	// Map optional fields
	if groupType, ok := configMap["group_type"].(string); ok {
		groupConfig.GroupType = groupType
	}
	if visibility, ok := configMap["visibility"].(string); ok {
		groupConfig.Visibility = visibility
	}
	if membershipRule, ok := configMap["membership_rule"].(string); ok {
		groupConfig.MembershipRule = membershipRule
	}
	if membershipRuleEnabled, ok := configMap["membership_rule_enabled"].(bool); ok {
		groupConfig.MembershipRuleEnabled = membershipRuleEnabled
	}

	// Map members and owners
	if members, ok := configMap["members"].([]string); ok {
		groupConfig.Members = members
	}
	if owners, ok := configMap["owners"].([]string); ok {
		groupConfig.Owners = owners
	}

	// Map team settings
	if isTeamEnabled, ok := configMap["is_team_enabled"].(bool); ok {
		groupConfig.IsTeamEnabled = isTeamEnabled
	}

	// Validate configuration
	if err := groupConfig.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Authenticate with Microsoft Graph
	token, err := m.authProvider.GetAccessToken(ctx, groupConfig.TenantID)
	if err != nil {
		return fmt.Errorf("failed to authenticate with Microsoft Graph: %w", err)
	}

	// Check if group exists by searching for it
	// Note: The graph client would need to be extended with group search capabilities
	// For now, we'll implement a placeholder

	// Try to get group by display name or ID
	groupID := extractGroupID(resourceID)
	existingGroup, err := m.getGroupByID(ctx, token, groupID)
	if err != nil {
		// Group doesn't exist, create it
		return m.createGroup(ctx, token, groupConfig)
	}

	// Group exists, update it with only managed fields
	return m.updateGroup(ctx, token, groupConfig, existingGroup)
}

// Get retrieves the current configuration of an Entra ID group
func (m *entraGroupModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	// Parse resource ID to extract tenant ID and group ID
	// Format: tenantID:groupID
	tenantID, groupID, err := parseEntraGroupResourceID(resourceID)
	if err != nil {
		return nil, fmt.Errorf("invalid resource ID format: %w", err)
	}

	// Authenticate with Microsoft Graph
	token, err := m.authProvider.GetAccessToken(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with Microsoft Graph: %w", err)
	}

	// Get group from Graph API
	group, err := m.getGroupByID(ctx, token, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group from Graph API: %w", err)
	}

	// Get group members and owners
	members, err := m.getGroupMembers(ctx, token, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}

	owners, err := m.getGroupOwners(ctx, token, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group owners: %w", err)
	}

	// Convert to our config format
	config := &EntraGroupConfig{
		DisplayName:     group.DisplayName,
		Description:     group.Description,
		MailNickname:    group.MailNickname,
		MailEnabled:     group.MailEnabled,
		SecurityEnabled: group.SecurityEnabled,
		TenantID:        tenantID,
		Members:         members,
		Owners:          owners,
	}

	// Check if this is a Microsoft Teams-enabled group
	if m.isTeamGroup(ctx, token, groupID) {
		config.IsTeamEnabled = true
		// Get team settings and channels would be implemented here
	}

	return config, nil
}

// Helper methods for Graph API operations

func (m *entraGroupModule) getGroupByID(ctx context.Context, token *auth.AccessToken, groupID string) (*GroupInfo, error) {
	// Get group from Graph API
	group, err := m.graphClient.GetGroup(ctx, token, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group from Graph API: %w", err)
	}

	// Convert Graph API response to our internal format
	return &GroupInfo{
		ID:              group.ID,
		DisplayName:     group.DisplayName,
		Description:     group.Description,
		MailNickname:    group.MailNickname,
		MailEnabled:     group.MailEnabled,
		SecurityEnabled: group.SecurityEnabled,
	}, nil
}

func (m *entraGroupModule) createGroup(ctx context.Context, token *auth.AccessToken, config *EntraGroupConfig) error {
	// Build the create request
	request := &graph.CreateGroupRequest{
		DisplayName:     config.DisplayName,
		MailNickname:    config.MailNickname,
		MailEnabled:     config.MailEnabled,
		SecurityEnabled: config.SecurityEnabled,
	}

	if config.Description != "" {
		request.Description = config.Description
	}

	if config.GroupType == "Unified" {
		request.GroupTypes = []string{"Unified"}
	}

	// Create group via Graph API
	group, err := m.graphClient.CreateGroup(ctx, token, request)
	if err != nil {
		return fmt.Errorf("failed to create group via Graph API: %w", err)
	}

	// Wait for group creation to propagate
	time.Sleep(2 * time.Second)

	// Add members and owners if specified
	if len(config.Members) > 0 {
		for _, member := range config.Members {
			if err := m.addGroupMember(ctx, token, group.ID, member); err != nil {
				return fmt.Errorf("failed to add member %s: %w", member, err)
			}
		}
	}

	if len(config.Owners) > 0 {
		for _, owner := range config.Owners {
			if err := m.addGroupOwner(ctx, token, group.ID, owner); err != nil {
				return fmt.Errorf("failed to add owner %s: %w", owner, err)
			}
		}
	}

	// Create Microsoft Team if enabled
	if config.IsTeamEnabled {
		if err := m.createTeam(ctx, token, group.ID, config.TeamSettings); err != nil {
			return fmt.Errorf("failed to create team: %w", err)
		}
	}

	return nil
}

func (m *entraGroupModule) updateGroup(ctx context.Context, token *auth.AccessToken, config *EntraGroupConfig, existingGroup *GroupInfo) error {
	managedFields := config.GetManagedFields()
	updates := make(map[string]interface{})

	// Only update managed fields
	for _, field := range managedFields {
		switch field {
		case "display_name":
			if config.DisplayName != existingGroup.DisplayName {
				updates["displayName"] = config.DisplayName
			}
		case "description":
			if config.Description != existingGroup.Description {
				updates["description"] = config.Description
			}
		case "mail_enabled":
			if config.MailEnabled != existingGroup.MailEnabled {
				updates["mailEnabled"] = config.MailEnabled
			}
		case "security_enabled":
			if config.SecurityEnabled != existingGroup.SecurityEnabled {
				updates["securityEnabled"] = config.SecurityEnabled
			}
		}
	}

	// Update the group if there are changes
	if len(updates) > 0 {
		// Build the update request
		updateRequest := &graph.UpdateGroupRequest{}

		// Map updates to the request structure (using pointers as required)
		if displayName, ok := updates["displayName"].(string); ok {
			updateRequest.DisplayName = &displayName
		}
		if description, ok := updates["description"].(string); ok {
			updateRequest.Description = &description
		}
		if mailEnabled, ok := updates["mailEnabled"].(bool); ok {
			updateRequest.MailEnabled = &mailEnabled
		}
		if securityEnabled, ok := updates["securityEnabled"].(bool); ok {
			updateRequest.SecurityEnabled = &securityEnabled
		}

		// Make the Graph API PATCH call
		if err := m.graphClient.UpdateGroup(ctx, token, existingGroup.ID, updateRequest); err != nil {
			return fmt.Errorf("failed to update group via Graph API: %w", err)
		}
	}

	// Handle membership if managed
	if contains(managedFields, "members") {
		if err := m.syncGroupMembers(ctx, token, existingGroup.ID, config.Members); err != nil {
			return fmt.Errorf("failed to sync group members: %w", err)
		}
	}

	if contains(managedFields, "owners") {
		if err := m.syncGroupOwners(ctx, token, existingGroup.ID, config.Owners); err != nil {
			return fmt.Errorf("failed to sync group owners: %w", err)
		}
	}

	// Handle team settings if managed
	if contains(managedFields, "is_team_enabled") && config.IsTeamEnabled {
		if !m.isTeamGroup(ctx, token, existingGroup.ID) {
			if err := m.createTeam(ctx, token, existingGroup.ID, config.TeamSettings); err != nil {
				return fmt.Errorf("failed to create team: %w", err)
			}
		} else if contains(managedFields, "team_settings") {
			if err := m.updateTeamSettings(ctx, token, existingGroup.ID, config.TeamSettings); err != nil {
				return fmt.Errorf("failed to update team settings: %w", err)
			}
		}
	}

	return nil
}

// Additional helper methods (placeholders)

func (m *entraGroupModule) getGroupMembers(ctx context.Context, token *auth.AccessToken, groupID string) ([]string, error) {
	// Placeholder - would use Graph API /groups/{id}/members
	return []string{}, nil
}

func (m *entraGroupModule) getGroupOwners(ctx context.Context, token *auth.AccessToken, groupID string) ([]string, error) {
	// Placeholder - would use Graph API /groups/{id}/owners
	return []string{}, nil
}

func (m *entraGroupModule) addGroupMember(ctx context.Context, token *auth.AccessToken, groupID, userID string) error {
	// Placeholder - would use Graph API POST /groups/{id}/members/$ref
	return nil
}

func (m *entraGroupModule) addGroupOwner(ctx context.Context, token *auth.AccessToken, groupID, userID string) error {
	// Placeholder - would use Graph API POST /groups/{id}/owners/$ref
	return nil
}

func (m *entraGroupModule) syncGroupMembers(ctx context.Context, token *auth.AccessToken, groupID string, desiredMembers []string) error {
	// Similar to user license sync logic
	return nil
}

func (m *entraGroupModule) syncGroupOwners(ctx context.Context, token *auth.AccessToken, groupID string, desiredOwners []string) error {
	// Similar to user license sync logic
	return nil
}

func (m *entraGroupModule) isTeamGroup(ctx context.Context, token *auth.AccessToken, groupID string) bool {
	// Placeholder - would check if group has an associated team
	return false
}

func (m *entraGroupModule) createTeam(ctx context.Context, token *auth.AccessToken, groupID string, settings *TeamSettings) error {
	// Placeholder - would use Graph API PUT /groups/{id}/team
	return nil
}

func (m *entraGroupModule) updateTeamSettings(ctx context.Context, token *auth.AccessToken, groupID string, settings *TeamSettings) error {
	// Placeholder - would use Graph API PATCH /teams/{id}
	return nil
}

// Utility types and functions

type GroupInfo struct {
	ID              string
	DisplayName     string
	Description     string
	MailNickname    string
	MailEnabled     bool
	SecurityEnabled bool
}

func parseEntraGroupResourceID(resourceID string) (tenantID, groupID string, err error) {
	parts := strings.SplitN(resourceID, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("resource ID must be in format 'tenantID:groupID'")
	}
	return parts[0], parts[1], nil
}

func extractGroupID(resourceID string) string {
	_, groupID, _ := parseEntraGroupResourceID(resourceID)
	return groupID
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
