package network_activedirectory

import (
	"context"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
)

// User Management Operations

// GetUser retrieves a user from Active Directory
func (p *ActiveDirectoryProvider) GetUser(ctx context.Context, userID string) (*interfaces.DirectoryUser, error) {
	p.logger.Debug("Getting AD user", "user_id", userID)

	result, err := p.executeADQuery(ctx, fmt.Sprintf("query:user:%s", userID))
	if err != nil {
		return nil, fmt.Errorf("failed to query user %s: %w", userID, err)
	}

	queryResult, err := p.parseADQueryResult(result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user query result: %w", err)
	}

	if !queryResult.Success {
		return nil, fmt.Errorf("user query failed: %s", queryResult.Error)
	}

	if queryResult.User == nil {
		return nil, fmt.Errorf("user %s not found", userID)
	}

	return queryResult.User, nil
}

// CreateUser creates a new user in Active Directory
func (p *ActiveDirectoryProvider) CreateUser(ctx context.Context, user *interfaces.DirectoryUser) (*interfaces.DirectoryUser, error) {
	// Note: Create operations would require write permissions and additional implementation
	return nil, fmt.Errorf("user creation not yet implemented - AD module in read-only mode")
}

// UpdateUser updates an existing user in Active Directory
func (p *ActiveDirectoryProvider) UpdateUser(ctx context.Context, userID string, updates *interfaces.DirectoryUser) (*interfaces.DirectoryUser, error) {
	return nil, fmt.Errorf("user updates not yet implemented - AD module in read-only mode")
}

// DeleteUser deletes a user from Active Directory
func (p *ActiveDirectoryProvider) DeleteUser(ctx context.Context, userID string) error {
	return fmt.Errorf("user deletion not yet implemented - AD module in read-only mode")
}

// ListUsers lists users from Active Directory
func (p *ActiveDirectoryProvider) ListUsers(ctx context.Context, filters *interfaces.SearchFilters) (*interfaces.UserList, error) {
	p.logger.Debug("Listing AD users", "filters", filters)

	result, err := p.executeADQuery(ctx, "list:user")
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	queryResult, err := p.parseADQueryResult(result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user list result: %w", err)
	}

	if !queryResult.Success {
		return nil, fmt.Errorf("user list failed: %s", queryResult.Error)
	}

	users := queryResult.Users
	if users == nil {
		users = []interfaces.DirectoryUser{}
	}

	// Apply client-side filtering if needed
	if filters != nil {
		users = p.filterUsers(users, filters)
	}

	return &interfaces.UserList{
		Users:      users,
		TotalCount: queryResult.TotalCount,
		HasMore:    queryResult.HasMore,
		NextToken:  queryResult.NextToken,
	}, nil
}

// Group Management Operations

// GetGroup retrieves a group from Active Directory
func (p *ActiveDirectoryProvider) GetGroup(ctx context.Context, groupID string) (*interfaces.DirectoryGroup, error) {
	p.logger.Debug("Getting AD group", "group_id", groupID)

	result, err := p.executeADQuery(ctx, fmt.Sprintf("query:group:%s", groupID))
	if err != nil {
		return nil, fmt.Errorf("failed to query group %s: %w", groupID, err)
	}

	queryResult, err := p.parseADQueryResult(result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse group query result: %w", err)
	}

	if !queryResult.Success {
		return nil, fmt.Errorf("group query failed: %s", queryResult.Error)
	}

	if queryResult.Group == nil {
		return nil, fmt.Errorf("group %s not found", groupID)
	}

	return queryResult.Group, nil
}

// CreateGroup creates a new group in Active Directory
func (p *ActiveDirectoryProvider) CreateGroup(ctx context.Context, group *interfaces.DirectoryGroup) (*interfaces.DirectoryGroup, error) {
	return nil, fmt.Errorf("group creation not yet implemented - AD module in read-only mode")
}

// UpdateGroup updates an existing group in Active Directory
func (p *ActiveDirectoryProvider) UpdateGroup(ctx context.Context, groupID string, updates *interfaces.DirectoryGroup) (*interfaces.DirectoryGroup, error) {
	return nil, fmt.Errorf("group updates not yet implemented - AD module in read-only mode")
}

// DeleteGroup deletes a group from Active Directory
func (p *ActiveDirectoryProvider) DeleteGroup(ctx context.Context, groupID string) error {
	return fmt.Errorf("group deletion not yet implemented - AD module in read-only mode")
}

// ListGroups lists groups from Active Directory
func (p *ActiveDirectoryProvider) ListGroups(ctx context.Context, filters *interfaces.SearchFilters) (*interfaces.GroupList, error) {
	p.logger.Debug("Listing AD groups", "filters", filters)

	result, err := p.executeADQuery(ctx, "list:group")
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}

	queryResult, err := p.parseADQueryResult(result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse group list result: %w", err)
	}

	if !queryResult.Success {
		return nil, fmt.Errorf("group list failed: %s", queryResult.Error)
	}

	groups := queryResult.Groups
	if groups == nil {
		groups = []interfaces.DirectoryGroup{}
	}

	// Apply client-side filtering if needed
	if filters != nil {
		groups = p.filterGroups(groups, filters)
	}

	return &interfaces.GroupList{
		Groups:     groups,
		TotalCount: queryResult.TotalCount,
		HasMore:    queryResult.HasMore,
		NextToken:  queryResult.NextToken,
	}, nil
}

// Membership Management Operations

// AddUserToGroup adds a user to a group in Active Directory
func (p *ActiveDirectoryProvider) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	return fmt.Errorf("group membership management not yet implemented - AD module in read-only mode")
}

// RemoveUserFromGroup removes a user from a group in Active Directory
func (p *ActiveDirectoryProvider) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	return fmt.Errorf("group membership management not yet implemented - AD module in read-only mode")
}

// GetUserGroups gets all groups that a user is a member of
func (p *ActiveDirectoryProvider) GetUserGroups(ctx context.Context, userID string) ([]interfaces.DirectoryGroup, error) {
	// Get the user first to get their group DNs
	user, err := p.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user for group lookup: %w", err)
	}

	if len(user.Groups) == 0 {
		return []interfaces.DirectoryGroup{}, nil
	}

	var userGroups []interfaces.DirectoryGroup

	// Query each group by DN
	for _, groupDN := range user.Groups {
		// Extract group name from DN for query
		groupName := p.extractNameFromDN(groupDN)
		if groupName == "" {
			continue
		}

		group, err := p.GetGroup(ctx, groupName)
		if err != nil {
			p.logger.Warn("Failed to get group details", "group_dn", groupDN, "error", err)
			continue
		}

		userGroups = append(userGroups, *group)
	}

	return userGroups, nil
}

// GetGroupMembers gets all members of a group
func (p *ActiveDirectoryProvider) GetGroupMembers(ctx context.Context, groupID string) ([]interfaces.DirectoryUser, error) {
	// Get the group first to get member DNs
	group, err := p.GetGroup(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group for member lookup: %w", err)
	}

	if len(group.Members) == 0 {
		return []interfaces.DirectoryUser{}, nil
	}

	var groupMembers []interfaces.DirectoryUser

	// Query each member by DN
	for _, memberDN := range group.Members {
		// Extract user name from DN for query
		userName := p.extractNameFromDN(memberDN)
		if userName == "" {
			continue
		}

		user, err := p.GetUser(ctx, userName)
		if err != nil {
			p.logger.Warn("Failed to get member details", "member_dn", memberDN, "error", err)
			continue
		}

		groupMembers = append(groupMembers, *user)
	}

	return groupMembers, nil
}

// Organizational Unit Management Operations

// GetOU retrieves an organizational unit from Active Directory
func (p *ActiveDirectoryProvider) GetOU(ctx context.Context, ouID string) (*interfaces.OrganizationalUnit, error) {
	p.logger.Debug("Getting AD OU", "ou_id", ouID)

	result, err := p.executeADQuery(ctx, fmt.Sprintf("query:ou:%s", ouID))
	if err != nil {
		return nil, fmt.Errorf("failed to query OU %s: %w", ouID, err)
	}

	queryResult, err := p.parseADQueryResult(result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OU query result: %w", err)
	}

	if !queryResult.Success {
		return nil, fmt.Errorf("OU query failed: %s", queryResult.Error)
	}

	if queryResult.OU == nil {
		return nil, fmt.Errorf("OU %s not found", ouID)
	}

	return queryResult.OU, nil
}

// CreateOU creates a new organizational unit in Active Directory
func (p *ActiveDirectoryProvider) CreateOU(ctx context.Context, ou *interfaces.OrganizationalUnit) (*interfaces.OrganizationalUnit, error) {
	return nil, fmt.Errorf("OU creation not yet implemented - AD module in read-only mode")
}

// UpdateOU updates an existing organizational unit in Active Directory
func (p *ActiveDirectoryProvider) UpdateOU(ctx context.Context, ouID string, updates *interfaces.OrganizationalUnit) (*interfaces.OrganizationalUnit, error) {
	return nil, fmt.Errorf("OU updates not yet implemented - AD module in read-only mode")
}

// DeleteOU deletes an organizational unit from Active Directory
func (p *ActiveDirectoryProvider) DeleteOU(ctx context.Context, ouID string) error {
	return fmt.Errorf("OU deletion not yet implemented - AD module in read-only mode")
}

// ListOUs lists organizational units from Active Directory
func (p *ActiveDirectoryProvider) ListOUs(ctx context.Context, filters *interfaces.SearchFilters) (*interfaces.OUList, error) {
	p.logger.Debug("Listing AD OUs", "filters", filters)

	result, err := p.executeADQuery(ctx, "list:ou")
	if err != nil {
		return nil, fmt.Errorf("failed to list OUs: %w", err)
	}

	queryResult, err := p.parseADQueryResult(result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OU list result: %w", err)
	}

	if !queryResult.Success {
		return nil, fmt.Errorf("OU list failed: %s", queryResult.Error)
	}

	ous := queryResult.OUs
	if ous == nil {
		ous = []interfaces.OrganizationalUnit{}
	}

	// Apply client-side filtering if needed
	if filters != nil {
		ous = p.filterOUs(ous, filters)
	}

	return &interfaces.OUList{
		OUs:        ous,
		TotalCount: queryResult.TotalCount,
		HasMore:    queryResult.HasMore,
		NextToken:  queryResult.NextToken,
	}, nil
}

// Helper methods for filtering

// filterUsers applies client-side filtering to user results
func (p *ActiveDirectoryProvider) filterUsers(users []interfaces.DirectoryUser, filters *interfaces.SearchFilters) []interfaces.DirectoryUser {
	if filters == nil {
		return users
	}

	var filtered []interfaces.DirectoryUser

	for _, user := range users {
		// Apply filters
		if filters.Department != "" && user.Department != filters.Department {
			continue
		}
		if filters.JobTitle != "" && user.JobTitle != filters.JobTitle {
			continue
		}
		if filters.Enabled != nil && user.AccountEnabled != *filters.Enabled {
			continue
		}
		if filters.OU != "" && user.OU != filters.OU {
			continue
		}
		if filters.Query != "" {
			// Simple text search in name and email
			query := strings.ToLower(filters.Query)
			if !strings.Contains(strings.ToLower(user.DisplayName), query) &&
				!strings.Contains(strings.ToLower(user.EmailAddress), query) &&
				!strings.Contains(strings.ToLower(user.UserPrincipalName), query) {
				continue
			}
		}

		filtered = append(filtered, user)

		// Apply limit
		if filters.Limit > 0 && len(filtered) >= filters.Limit {
			break
		}
	}

	// Apply offset
	if filters.Offset > 0 && filters.Offset < len(filtered) {
		filtered = filtered[filters.Offset:]
	}

	return filtered
}

// filterGroups applies client-side filtering to group results
func (p *ActiveDirectoryProvider) filterGroups(groups []interfaces.DirectoryGroup, filters *interfaces.SearchFilters) []interfaces.DirectoryGroup {
	if filters == nil {
		return groups
	}

	var filtered []interfaces.DirectoryGroup

	for _, group := range groups {
		// Apply filters
		if filters.OU != "" && group.OU != filters.OU {
			continue
		}
		if filters.Query != "" {
			// Simple text search in name and description
			query := strings.ToLower(filters.Query)
			if !strings.Contains(strings.ToLower(group.DisplayName), query) &&
				!strings.Contains(strings.ToLower(group.Description), query) &&
				!strings.Contains(strings.ToLower(group.Name), query) {
				continue
			}
		}

		filtered = append(filtered, group)

		// Apply limit
		if filters.Limit > 0 && len(filtered) >= filters.Limit {
			break
		}
	}

	// Apply offset
	if filters.Offset > 0 && filters.Offset < len(filtered) {
		filtered = filtered[filters.Offset:]
	}

	return filtered
}

// filterOUs applies client-side filtering to OU results
func (p *ActiveDirectoryProvider) filterOUs(ous []interfaces.OrganizationalUnit, filters *interfaces.SearchFilters) []interfaces.OrganizationalUnit {
	if filters == nil {
		return ous
	}

	var filtered []interfaces.OrganizationalUnit

	for _, ou := range ous {
		// Apply filters
		if filters.Query != "" {
			// Simple text search in name and description
			query := strings.ToLower(filters.Query)
			if !strings.Contains(strings.ToLower(ou.DisplayName), query) &&
				!strings.Contains(strings.ToLower(ou.Description), query) &&
				!strings.Contains(strings.ToLower(ou.Name), query) {
				continue
			}
		}

		filtered = append(filtered, ou)

		// Apply limit
		if filters.Limit > 0 && len(filtered) >= filters.Limit {
			break
		}
	}

	// Apply offset
	if filters.Offset > 0 && filters.Offset < len(filtered) {
		filtered = filtered[filters.Offset:]
	}

	return filtered
}

// extractNameFromDN extracts the name component from a distinguished name
func (p *ActiveDirectoryProvider) extractNameFromDN(dn string) string {
	if dn == "" {
		return ""
	}

	// Split DN and get the first component
	parts := strings.Split(dn, ",")
	if len(parts) == 0 {
		return ""
	}

	firstPart := strings.TrimSpace(parts[0])

	// Handle different DN component types
	if strings.HasPrefix(strings.ToUpper(firstPart), "CN=") {
		return strings.TrimPrefix(firstPart, "CN=")
	}
	if strings.HasPrefix(strings.ToUpper(firstPart), "OU=") {
		return strings.TrimPrefix(firstPart, "OU=")
	}

	return firstPart
}
