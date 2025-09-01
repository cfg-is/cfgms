package network_activedirectory

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
)

// Advanced Search Operations

// Search performs an advanced search query in Active Directory
func (p *ActiveDirectoryProvider) Search(ctx context.Context, query *interfaces.DirectoryQuery) (*interfaces.SearchResults, error) {
	p.logger.Debug("Performing AD search", "filter", query.Filter, "search_base", query.SearchBase)
	
	// For initial implementation, convert advanced query to simple operations
	// In a full implementation, this would pass the LDAP filter directly to the module
	
	results := &interfaces.SearchResults{
		TotalCount: 0,
		HasMore:    false,
	}
	
	// If no specific attributes requested, search all object types
	objectTypes := []string{"user", "group", "organizational_unit"}
	
	// Search each object type
	for _, objType := range objectTypes {
		switch objType {
		case "user":
			userList, err := p.ListUsers(ctx, &interfaces.SearchFilters{
				Query: "", // Would need to convert LDAP filter to simple query
				Limit: 1000,
			})
			if err != nil {
				p.logger.Warn("Failed to search users", "error", err)
				continue
			}
			results.Users = userList.Users
			results.TotalCount += userList.TotalCount
			
		case "group":
			groupList, err := p.ListGroups(ctx, &interfaces.SearchFilters{
				Query: "",
				Limit: 1000,
			})
			if err != nil {
				p.logger.Warn("Failed to search groups", "error", err)
				continue
			}
			results.Groups = groupList.Groups
			results.TotalCount += groupList.TotalCount
			
		case "organizational_unit":
			ouList, err := p.ListOUs(ctx, &interfaces.SearchFilters{
				Query: "",
				Limit: 1000,
			})
			if err != nil {
				p.logger.Warn("Failed to search OUs", "error", err)
				continue
			}
			results.OUs = ouList.OUs
			results.TotalCount += ouList.TotalCount
		}
	}
	
	return results, nil
}

// Bulk Operations

// BulkCreateUsers creates multiple users in Active Directory
func (p *ActiveDirectoryProvider) BulkCreateUsers(ctx context.Context, users []*interfaces.DirectoryUser, options *interfaces.BulkOptions) (*interfaces.BulkResult, error) {
	return nil, fmt.Errorf("bulk user creation not yet implemented - AD module in read-only mode")
}

// BulkUpdateUsers updates multiple users in Active Directory
func (p *ActiveDirectoryProvider) BulkUpdateUsers(ctx context.Context, updates []*interfaces.UserUpdate, options *interfaces.BulkOptions) (*interfaces.BulkResult, error) {
	return nil, fmt.Errorf("bulk user updates not yet implemented - AD module in read-only mode")
}

// BulkDeleteUsers deletes multiple users from Active Directory
func (p *ActiveDirectoryProvider) BulkDeleteUsers(ctx context.Context, userIDs []string, options *interfaces.BulkOptions) (*interfaces.BulkResult, error) {
	return nil, fmt.Errorf("bulk user deletion not yet implemented - AD module in read-only mode")
}

// Cross-Directory Operations

// SyncUser synchronizes a user between directory providers
func (p *ActiveDirectoryProvider) SyncUser(ctx context.Context, sourceUserID string, targetProvider interfaces.DirectoryProvider) error {
	p.logger.Debug("Syncing user to target provider", "user_id", sourceUserID)
	
	// Get user from AD
	sourceUser, err := p.GetUser(ctx, sourceUserID)
	if err != nil {
		return fmt.Errorf("failed to get source user: %w", err)
	}
	
	// Check if user exists in target
	targetUser, err := targetProvider.GetUser(ctx, sourceUser.UserPrincipalName)
	if err != nil {
		// User doesn't exist, create it
		_, err = targetProvider.CreateUser(ctx, sourceUser)
		if err != nil {
			return fmt.Errorf("failed to create user in target provider: %w", err)
		}
		
		p.logger.Info("User synchronized (created)", 
			"user_id", sourceUserID,
			"target_provider", targetProvider.GetProviderInfo().Name)
	} else {
		// User exists, update it
		_, err = targetProvider.UpdateUser(ctx, targetUser.ID, sourceUser)
		if err != nil {
			return fmt.Errorf("failed to update user in target provider: %w", err)
		}
		
		p.logger.Info("User synchronized (updated)", 
			"user_id", sourceUserID,
			"target_provider", targetProvider.GetProviderInfo().Name)
	}
	
	return nil
}

// SyncGroup synchronizes a group between directory providers
func (p *ActiveDirectoryProvider) SyncGroup(ctx context.Context, sourceGroupID string, targetProvider interfaces.DirectoryProvider) error {
	p.logger.Debug("Syncing group to target provider", "group_id", sourceGroupID)
	
	// Get group from AD
	sourceGroup, err := p.GetGroup(ctx, sourceGroupID)
	if err != nil {
		return fmt.Errorf("failed to get source group: %w", err)
	}
	
	// Check if group exists in target
	targetGroup, err := targetProvider.GetGroup(ctx, sourceGroup.Name)
	if err != nil {
		// Group doesn't exist, create it
		_, err = targetProvider.CreateGroup(ctx, sourceGroup)
		if err != nil {
			return fmt.Errorf("failed to create group in target provider: %w", err)
		}
		
		p.logger.Info("Group synchronized (created)", 
			"group_id", sourceGroupID,
			"target_provider", targetProvider.GetProviderInfo().Name)
	} else {
		// Group exists, update it
		_, err = targetProvider.UpdateGroup(ctx, targetGroup.ID, sourceGroup)
		if err != nil {
			return fmt.Errorf("failed to update group in target provider: %w", err)
		}
		
		p.logger.Info("Group synchronized (updated)", 
			"group_id", sourceGroupID,
			"target_provider", targetProvider.GetProviderInfo().Name)
	}
	
	return nil
}

// Schema and Capabilities

// GetSchema returns the schema supported by Active Directory
func (p *ActiveDirectoryProvider) GetSchema(ctx context.Context) (*interfaces.DirectorySchema, error) {
	return &interfaces.DirectorySchema{
		UserSchema: interfaces.ObjectSchema{
			ObjectType: interfaces.DirectoryObjectTypeUser,
			RequiredFields: []interfaces.SchemaField{
				{Name: "sAMAccountName", Type: "string", Description: "Windows logon name", MaxLength: 20},
				{Name: "userPrincipalName", Type: "string", Description: "User principal name (UPN)", MaxLength: 1024},
				{Name: "displayName", Type: "string", Description: "Display name", MaxLength: 256},
			},
			OptionalFields: []interfaces.SchemaField{
				{Name: "mail", Type: "string", Description: "Email address", MaxLength: 256, Format: "email"},
				{Name: "telephoneNumber", Type: "string", Description: "Phone number", MaxLength: 64},
				{Name: "mobile", Type: "string", Description: "Mobile phone", MaxLength: 64},
				{Name: "department", Type: "string", Description: "Department", MaxLength: 64},
				{Name: "title", Type: "string", Description: "Job title", MaxLength: 128},
				{Name: "manager", Type: "string", Description: "Manager DN", MaxLength: 1024},
				{Name: "company", Type: "string", Description: "Company name", MaxLength: 64},
				{Name: "physicalDeliveryOfficeName", Type: "string", Description: "Office location", MaxLength: 128},
			},
			ReadOnlyFields: []interfaces.SchemaField{
				{Name: "objectGUID", Type: "string", Description: "Unique object identifier"},
				{Name: "distinguishedName", Type: "string", Description: "Distinguished name"},
				{Name: "whenCreated", Type: "datetime", Description: "Creation timestamp"},
				{Name: "whenChanged", Type: "datetime", Description: "Last modification timestamp"},
				{Name: "lastLogon", Type: "datetime", Description: "Last logon timestamp"},
			},
			SearchableFields: []interfaces.SchemaField{
				{Name: "sAMAccountName", Type: "string", Description: "Search by account name"},
				{Name: "userPrincipalName", Type: "string", Description: "Search by UPN"},
				{Name: "displayName", Type: "string", Description: "Search by display name"},
				{Name: "mail", Type: "string", Description: "Search by email"},
				{Name: "department", Type: "string", Description: "Search by department"},
			},
		},
		GroupSchema: interfaces.ObjectSchema{
			ObjectType: interfaces.DirectoryObjectTypeGroup,
			RequiredFields: []interfaces.SchemaField{
				{Name: "sAMAccountName", Type: "string", Description: "Group name", MaxLength: 20},
				{Name: "displayName", Type: "string", Description: "Display name", MaxLength: 256},
			},
			OptionalFields: []interfaces.SchemaField{
				{Name: "description", Type: "string", Description: "Group description", MaxLength: 1024},
				{Name: "groupType", Type: "int", Description: "Group type flags"},
				{Name: "managedBy", Type: "string", Description: "Managed by DN", MaxLength: 1024},
			},
			ReadOnlyFields: []interfaces.SchemaField{
				{Name: "objectGUID", Type: "string", Description: "Unique object identifier"},
				{Name: "distinguishedName", Type: "string", Description: "Distinguished name"},
				{Name: "member", Type: "array", Description: "Group members"},
				{Name: "whenCreated", Type: "datetime", Description: "Creation timestamp"},
				{Name: "whenChanged", Type: "datetime", Description: "Last modification timestamp"},
			},
			SearchableFields: []interfaces.SchemaField{
				{Name: "sAMAccountName", Type: "string", Description: "Search by group name"},
				{Name: "displayName", Type: "string", Description: "Search by display name"},
				{Name: "description", Type: "string", Description: "Search by description"},
			},
		},
		OUSchema: interfaces.ObjectSchema{
			ObjectType: interfaces.DirectoryObjectTypeOU,
			RequiredFields: []interfaces.SchemaField{
				{Name: "name", Type: "string", Description: "OU name", MaxLength: 64},
			},
			OptionalFields: []interfaces.SchemaField{
				{Name: "displayName", Type: "string", Description: "Display name", MaxLength: 256},
				{Name: "description", Type: "string", Description: "OU description", MaxLength: 1024},
				{Name: "managedBy", Type: "string", Description: "Managed by DN", MaxLength: 1024},
			},
			ReadOnlyFields: []interfaces.SchemaField{
				{Name: "objectGUID", Type: "string", Description: "Unique object identifier"},
				{Name: "distinguishedName", Type: "string", Description: "Distinguished name"},
				{Name: "whenCreated", Type: "datetime", Description: "Creation timestamp"},
				{Name: "whenChanged", Type: "datetime", Description: "Last modification timestamp"},
			},
			SearchableFields: []interfaces.SchemaField{
				{Name: "name", Type: "string", Description: "Search by OU name"},
				{Name: "displayName", Type: "string", Description: "Search by display name"},
				{Name: "description", Type: "string", Description: "Search by description"},
			},
		},
	}, nil
}

// GetCapabilities returns the capabilities of this provider
func (p *ActiveDirectoryProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return p.GetProviderInfo().Capabilities
}

// ValidateUser validates a user object against AD schema
func (p *ActiveDirectoryProvider) ValidateUser(user *interfaces.DirectoryUser) error {
	if user == nil {
		return fmt.Errorf("user object is nil")
	}
	
	// Validate required fields
	if user.SAMAccountName == "" && user.UserPrincipalName == "" {
		return fmt.Errorf("either sAMAccountName or userPrincipalName is required")
	}
	
	if user.DisplayName == "" {
		return fmt.Errorf("displayName is required")
	}
	
	// Validate field lengths
	if len(user.SAMAccountName) > 20 {
		return fmt.Errorf("sAMAccountName exceeds maximum length of 20 characters")
	}
	
	if len(user.UserPrincipalName) > 1024 {
		return fmt.Errorf("userPrincipalName exceeds maximum length of 1024 characters")
	}
	
	if len(user.DisplayName) > 256 {
		return fmt.Errorf("displayName exceeds maximum length of 256 characters")
	}
	
	// Validate UPN format if specified
	if user.UserPrincipalName != "" && !strings.Contains(user.UserPrincipalName, "@") {
		return fmt.Errorf("userPrincipalName must be in user@domain format")
	}
	
	return nil
}

// ValidateGroup validates a group object against AD schema
func (p *ActiveDirectoryProvider) ValidateGroup(group *interfaces.DirectoryGroup) error {
	if group == nil {
		return fmt.Errorf("group object is nil")
	}
	
	// Validate required fields
	if group.Name == "" {
		return fmt.Errorf("group name is required")
	}
	
	if group.DisplayName == "" {
		return fmt.Errorf("displayName is required")
	}
	
	// Validate field lengths
	if len(group.Name) > 20 {
		return fmt.Errorf("group name exceeds maximum length of 20 characters")
	}
	
	if len(group.DisplayName) > 256 {
		return fmt.Errorf("displayName exceeds maximum length of 256 characters")
	}
	
	if len(group.Description) > 1024 {
		return fmt.Errorf("description exceeds maximum length of 1024 characters")
	}
	
	// Validate group type
	if group.GroupType != "" {
		if group.GroupType != interfaces.GroupTypeSecurity && group.GroupType != interfaces.GroupTypeDistribution {
			return fmt.Errorf("invalid group type: %s", group.GroupType)
		}
	}
	
	// Validate group scope
	if group.GroupScope != "" {
		switch group.GroupScope {
		case interfaces.GroupScopeDomainLocal, interfaces.GroupScopeGlobal, interfaces.GroupScopeUniversal:
			// Valid scopes
		default:
			return fmt.Errorf("invalid group scope: %s", group.GroupScope)
		}
	}
	
	return nil
}

// Additional helper methods for provider operations

// GetAverageLatency returns the average latency for AD operations
func (p *ActiveDirectoryProvider) GetAverageLatency() time.Duration {
	p.stats.RLock()
	defer p.stats.RUnlock()
	
	if p.stats.requestCount == 0 {
		return 0
	}
	
	return time.Duration(int64(p.stats.totalLatency) / p.stats.requestCount)
}

// GetRequestCount returns the total number of requests made
func (p *ActiveDirectoryProvider) GetRequestCount() int64 {
	p.stats.RLock()
	defer p.stats.RUnlock()
	return p.stats.requestCount
}

// GetErrorCount returns the total number of errors encountered
func (p *ActiveDirectoryProvider) GetErrorCount() int64 {
	p.stats.RLock()
	defer p.stats.RUnlock()
	return p.stats.errorCount
}

// GetConnectionInfo returns information about the current connection
func (p *ActiveDirectoryProvider) GetConnectionInfo() (*interfaces.ConnectionInfo, error) {
	p.connMux.RLock()
	defer p.connMux.RUnlock()
	
	if !p.connected {
		return nil, fmt.Errorf("not connected")
	}
	
	p.stats.RLock()
	connectedSince := p.stats.connectedAt
	p.stats.RUnlock()
	
	info := &interfaces.ConnectionInfo{
		ProviderName:   "network_activedirectory",
		ServerAddress:  p.config.ServerAddress,
		ConnectedSince: connectedSince,
		AuthMethod:     p.config.AuthMethod,
		UserContext:    p.config.Username,
		Properties: map[string]string{
			"domain":         p.config.ServerAddress,
			"port":           fmt.Sprintf("%d", p.config.Port),
			"use_tls":        fmt.Sprintf("%t", p.config.UseTLS),
			"page_size":      fmt.Sprintf("%d", p.config.PageSize),
			"max_connections": fmt.Sprintf("%d", p.config.MaxConnections),
		},
	}
	
	return info, nil
}

// AD-Specific Advanced Operations

// GetComputer retrieves a computer object from Active Directory
func (p *ActiveDirectoryProvider) GetComputer(ctx context.Context, computerID string) (*interfaces.DirectoryUser, error) {
	if !p.IsConnected(ctx) {
		return nil, fmt.Errorf("not connected to Active Directory")
	}
	
	p.logger.Debug("Getting computer object", "computer_id", computerID)
	
	// Find suitable AD steward
	stewardID, err := p.findADSteward(ctx, p.config.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to find AD steward: %w", err)
	}
	
	// Query computer object via steward
	resourceID := fmt.Sprintf("query:computer:%s", computerID)
	state, err := p.stewardClient.GetModuleState(ctx, stewardID, "activedirectory", resourceID)
	if err != nil {
		p.updateStats(false, time.Since(time.Now()))
		return nil, fmt.Errorf("failed to query computer from steward: %w", err)
	}
	
	// Check for query success
	success, ok := state["success"].(bool)
	if !ok || !success {
		errMsg, _ := state["error"].(string)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return nil, fmt.Errorf("computer query failed: %s", errMsg)
	}
	
	// Extract computer object (represented as DirectoryUser with computer attributes)
	userObj, ok := state["user"]
	if !ok {
		return nil, fmt.Errorf("computer object not found in response")
	}
	
	// Convert to DirectoryUser
	computer, err := p.convertToDirectoryUser(userObj)
	if err != nil {
		return nil, fmt.Errorf("failed to convert computer object: %w", err)
	}
	
	p.updateStats(true, time.Since(time.Now()))
	return computer, nil
}

// ListComputers lists computer objects from Active Directory
func (p *ActiveDirectoryProvider) ListComputers(ctx context.Context, filters *interfaces.SearchFilters) (*interfaces.UserList, error) {
	if !p.IsConnected(ctx) {
		return nil, fmt.Errorf("not connected to Active Directory")
	}
	
	p.logger.Debug("Listing computer objects")
	
	// Find suitable AD steward
	stewardID, err := p.findADSteward(ctx, p.config.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to find AD steward: %w", err)
	}
	
	// List computer objects via steward
	resourceID := "list:computer"
	state, err := p.stewardClient.GetModuleState(ctx, stewardID, "activedirectory", resourceID)
	if err != nil {
		p.updateStats(false, time.Since(time.Now()))
		return nil, fmt.Errorf("failed to list computers from steward: %w", err)
	}
	
	// Check for query success
	success, ok := state["success"].(bool)
	if !ok || !success {
		errMsg, _ := state["error"].(string)
		return nil, fmt.Errorf("computer list failed: %s", errMsg)
	}
	
	// Extract computer objects
	userList := &interfaces.UserList{
		Users:      []interfaces.DirectoryUser{},
		TotalCount: 0,
		HasMore:    false,
	}
	
	if usersData, ok := state["users"].([]interface{}); ok {
		for _, userData := range usersData {
			if computer, err := p.convertToDirectoryUser(userData); err == nil {
				userList.Users = append(userList.Users, *computer)
			}
		}
		userList.TotalCount = len(userList.Users)
	}
	
	// Apply client-side filtering if needed
	if filters != nil {
		filtered := p.filterUsers(userList.Users, filters)
		userList.Users = filtered
		userList.TotalCount = len(filtered)
	}
	
	p.updateStats(true, time.Since(time.Now()))
	return userList, nil
}

// GetGroupPolicy retrieves a Group Policy Object from Active Directory
func (p *ActiveDirectoryProvider) GetGroupPolicy(ctx context.Context, gpoID string) (map[string]interface{}, error) {
	if !p.IsConnected(ctx) {
		return nil, fmt.Errorf("not connected to Active Directory")
	}
	
	p.logger.Debug("Getting Group Policy Object", "gpo_id", gpoID)
	
	// Find suitable AD steward
	stewardID, err := p.findADSteward(ctx, p.config.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to find AD steward: %w", err)
	}
	
	// Query GPO via steward
	resourceID := fmt.Sprintf("query:gpo:%s", gpoID)
	state, err := p.stewardClient.GetModuleState(ctx, stewardID, "activedirectory", resourceID)
	if err != nil {
		p.updateStats(false, time.Since(time.Now()))
		return nil, fmt.Errorf("failed to query GPO from steward: %w", err)
	}
	
	// Check for query success
	success, ok := state["success"].(bool)
	if !ok || !success {
		errMsg, _ := state["error"].(string)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return nil, fmt.Errorf("GPO query failed: %s", errMsg)
	}
	
	// Extract GPO object
	gpoObj, ok := state["generic_object"]
	if !ok {
		return nil, fmt.Errorf("GPO object not found in response")
	}
	
	// Convert to map
	gpoMap, ok := gpoObj.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid GPO object format")
	}
	
	p.updateStats(true, time.Since(time.Now()))
	return gpoMap, nil
}

// ListGroupPolicies lists Group Policy Objects from Active Directory
func (p *ActiveDirectoryProvider) ListGroupPolicies(ctx context.Context) ([]map[string]interface{}, error) {
	if !p.IsConnected(ctx) {
		return nil, fmt.Errorf("not connected to Active Directory")
	}
	
	p.logger.Debug("Listing Group Policy Objects")
	
	// Find suitable AD steward
	stewardID, err := p.findADSteward(ctx, p.config.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to find AD steward: %w", err)
	}
	
	// List GPOs via steward
	resourceID := "list:gpo"
	state, err := p.stewardClient.GetModuleState(ctx, stewardID, "activedirectory", resourceID)
	if err != nil {
		p.updateStats(false, time.Since(time.Now()))
		return nil, fmt.Errorf("failed to list GPOs from steward: %w", err)
	}
	
	// Check for query success
	success, ok := state["success"].(bool)
	if !ok || !success {
		errMsg, _ := state["error"].(string)
		return nil, fmt.Errorf("GPO list failed: %s", errMsg)
	}
	
	// Extract GPO objects
	var gpos []map[string]interface{}
	
	if gpoData, ok := state["generic_objects"].([]interface{}); ok {
		for _, obj := range gpoData {
			if gpoMap, ok := obj.(map[string]interface{}); ok {
				gpos = append(gpos, gpoMap)
			}
		}
	}
	
	p.updateStats(true, time.Since(time.Now()))
	return gpos, nil
}

// GetDomainTrust retrieves domain trust information from Active Directory
func (p *ActiveDirectoryProvider) GetDomainTrust(ctx context.Context, trustName string) (map[string]interface{}, error) {
	if !p.IsConnected(ctx) {
		return nil, fmt.Errorf("not connected to Active Directory")
	}
	
	p.logger.Debug("Getting domain trust", "trust_name", trustName)
	
	// Find suitable AD steward
	stewardID, err := p.findADSteward(ctx, p.config.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to find AD steward: %w", err)
	}
	
	// Query trust via steward
	resourceID := fmt.Sprintf("query:trust:%s", trustName)
	state, err := p.stewardClient.GetModuleState(ctx, stewardID, "activedirectory", resourceID)
	if err != nil {
		p.updateStats(false, time.Since(time.Now()))
		return nil, fmt.Errorf("failed to query trust from steward: %w", err)
	}
	
	// Check for query success
	success, ok := state["success"].(bool)
	if !ok || !success {
		errMsg, _ := state["error"].(string)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return nil, fmt.Errorf("trust query failed: %s", errMsg)
	}
	
	// Extract trust object
	trustObj, ok := state["generic_object"]
	if !ok {
		return nil, fmt.Errorf("trust object not found in response")
	}
	
	// Convert to map
	trustMap, ok := trustObj.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid trust object format")
	}
	
	p.updateStats(true, time.Since(time.Now()))
	return trustMap, nil
}

// ListDomainTrusts lists domain trusts from Active Directory
func (p *ActiveDirectoryProvider) ListDomainTrusts(ctx context.Context) ([]map[string]interface{}, error) {
	if !p.IsConnected(ctx) {
		return nil, fmt.Errorf("not connected to Active Directory")
	}
	
	p.logger.Debug("Listing domain trusts")
	
	// Find suitable AD steward
	stewardID, err := p.findADSteward(ctx, p.config.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to find AD steward: %w", err)
	}
	
	// List trusts via steward
	resourceID := "list:trust"
	state, err := p.stewardClient.GetModuleState(ctx, stewardID, "activedirectory", resourceID)
	if err != nil {
		p.updateStats(false, time.Since(time.Now()))
		return nil, fmt.Errorf("failed to list trusts from steward: %w", err)
	}
	
	// Check for query success
	success, ok := state["success"].(bool)
	if !ok || !success {
		errMsg, _ := state["error"].(string)
		return nil, fmt.Errorf("trust list failed: %s", errMsg)
	}
	
	// Extract trust objects
	var trusts []map[string]interface{}
	
	if trustData, ok := state["generic_objects"].([]interface{}); ok {
		for _, obj := range trustData {
			if trustMap, ok := obj.(map[string]interface{}); ok {
				trusts = append(trusts, trustMap)
			}
		}
	}
	
	p.updateStats(true, time.Since(time.Now()))
	return trusts, nil
}

// GetDomainController retrieves domain controller information
func (p *ActiveDirectoryProvider) GetDomainController(ctx context.Context) (map[string]interface{}, error) {
	if !p.IsConnected(ctx) {
		return nil, fmt.Errorf("not connected to Active Directory")
	}
	
	p.logger.Debug("Getting domain controller information")
	
	// Find suitable AD steward
	stewardID, err := p.findADSteward(ctx, p.config.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to find AD steward: %w", err)
	}
	
	// Get connection status which includes DC info
	resourceID := "status"
	state, err := p.stewardClient.GetModuleState(ctx, stewardID, "activedirectory", resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get status from steward: %w", err)
	}
	
	// Extract domain controller information from status
	dcInfo := map[string]interface{}{
		"domain_controller": state["domain_controller"],
		"domain":           state["domain"],
		"connected":        state["connected"],
		"health_status":    state["health_status"],
		"response_time":    state["response_time"],
	}
	
	return dcInfo, nil
}

// ValidateDomainTrust validates domain trust configuration
func (p *ActiveDirectoryProvider) ValidateDomainTrust(trust map[string]interface{}) error {
	// Validate required trust fields
	if trust["trust_partner"] == "" {
		return fmt.Errorf("trust_partner is required")
	}
	
	if trust["trust_direction"] == "" {
		return fmt.Errorf("trust_direction is required")
	}
	
	// Validate trust direction
	direction, ok := trust["trust_direction"].(string)
	if !ok {
		return fmt.Errorf("trust_direction must be a string")
	}
	
	validDirections := map[string]bool{
		"TRUST_DIRECTION_INBOUND":      true,
		"TRUST_DIRECTION_OUTBOUND":     true,
		"TRUST_DIRECTION_BIDIRECTIONAL": true,
	}
	
	if !validDirections[direction] {
		return fmt.Errorf("invalid trust_direction: %s", direction)
	}
	
	// Validate trust type if specified
	if trustType, exists := trust["trust_type"]; exists {
		typeStr, ok := trustType.(string)
		if !ok {
			return fmt.Errorf("trust_type must be a string")
		}
		
		validTypes := map[string]bool{
			"TRUST_TYPE_DOWNLEVEL": true,
			"TRUST_TYPE_UPLEVEL":   true,
			"TRUST_TYPE_MIT":       true,
			"TRUST_TYPE_DCE":       true,
		}
		
		if !validTypes[typeStr] {
			return fmt.Errorf("invalid trust_type: %s", typeStr)
		}
	}
	
	return nil
}

// Multi-Domain and Multi-Forest Provider Operations

// QueryTrustedDomain performs a query in a trusted domain via AD steward
func (p *ActiveDirectoryProvider) QueryTrustedDomain(ctx context.Context, targetDomain, objectType, objectID string) (map[string]interface{}, error) {
	if !p.IsConnected(ctx) {
		return nil, fmt.Errorf("not connected to Active Directory")
	}
	
	p.logger.Debug("Querying trusted domain", "target_domain", targetDomain, "object_type", objectType, "object_id", objectID)
	
	// Find suitable AD steward
	stewardID, err := p.findADSteward(ctx, p.config.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to find AD steward: %w", err)
	}
	
	// Query trusted domain via steward
	resourceID := fmt.Sprintf("query:%s:%s:%s", objectType, objectID, targetDomain)
	state, err := p.stewardClient.GetModuleState(ctx, stewardID, "activedirectory", resourceID)
	if err != nil {
		p.updateStats(false, time.Since(time.Now()))
		return nil, fmt.Errorf("failed to query trusted domain from steward: %w", err)
	}
	
	// Check for query success
	success, ok := state["success"].(bool)
	if !ok || !success {
		errMsg, _ := state["error"].(string)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return nil, fmt.Errorf("trusted domain query failed: %s", errMsg)
	}
	
	p.updateStats(true, time.Since(time.Now()))
	return state, nil
}

// QueryForest performs a forest-wide search via AD steward Global Catalog
func (p *ActiveDirectoryProvider) QueryForest(ctx context.Context, objectType, objectID string) (map[string]interface{}, error) {
	if !p.IsConnected(ctx) {
		return nil, fmt.Errorf("not connected to Active Directory")
	}
	
	p.logger.Debug("Performing forest search", "object_type", objectType, "object_id", objectID)
	
	// Find suitable AD steward
	stewardID, err := p.findADSteward(ctx, p.config.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to find AD steward: %w", err)
	}
	
	// Query forest via steward Global Catalog
	resourceID := fmt.Sprintf("forest:%s:%s", objectType, objectID)
	state, err := p.stewardClient.GetModuleState(ctx, stewardID, "activedirectory", resourceID)
	if err != nil {
		p.updateStats(false, time.Since(time.Now()))
		return nil, fmt.Errorf("failed to query forest from steward: %w", err)
	}
	
	// Check for query success
	success, ok := state["success"].(bool)
	if !ok || !success {
		errMsg, _ := state["error"].(string)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return nil, fmt.Errorf("forest query failed: %s", errMsg)
	}
	
	p.updateStats(true, time.Since(time.Now()))
	return state, nil
}

// ValidateCrossDomainTrust validates cross-domain trust relationships via AD steward
func (p *ActiveDirectoryProvider) ValidateCrossDomainTrust(ctx context.Context, targetDomain string) error {
	if !p.IsConnected(ctx) {
		return fmt.Errorf("not connected to Active Directory")
	}
	
	p.logger.Debug("Validating cross-domain trust", "target_domain", targetDomain)
	
	// Find suitable AD steward
	stewardID, err := p.findADSteward(ctx, p.config.ServerAddress)
	if err != nil {
		return fmt.Errorf("failed to find AD steward: %w", err)
	}
	
	// Validate trust via steward
	resourceID := fmt.Sprintf("validate_trust:%s", targetDomain)
	state, err := p.stewardClient.GetModuleState(ctx, stewardID, "activedirectory", resourceID)
	if err != nil {
		p.updateStats(false, time.Since(time.Now()))
		return fmt.Errorf("failed to validate trust via steward: %w", err)
	}
	
	// Check validation result
	success, ok := state["success"].(bool)
	if !ok || !success {
		errMsg, _ := state["error"].(string)
		if errMsg == "" {
			errMsg = "trust validation failed"
		}
		return fmt.Errorf("%s", errMsg)
	}
	
	p.updateStats(true, time.Since(time.Now()))
	p.logger.Info("Cross-domain trust validated successfully", "target_domain", targetDomain)
	return nil
}