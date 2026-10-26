// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package m365 provides the Microsoft Entra ID directory provider.
//
// EntraIDDirectoryProvider implements pkg/directory/interfaces.DirectoryProvider,
// the sole directory contract. It holds no tenant of its own: every Graph call
// obtains its token for the CFGMS execution tenant carried in the context
// (ctxkeys.TenantID), so one provider instance serves every tenant and no
// credential travels through ProviderConfig.
package m365

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/directory/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

const (
	entraProviderName     = "entraid"
	defaultGraphURL       = "https://graph.microsoft.com/v1.0"
	maxSearchResults      = 999
	defaultListPageSize   = 100
	errNotConnected       = "not connected to Entra ID"
	errOUsNotSupportedMsg = "organizational units not supported by Entra ID"
)

var _ interfaces.DirectoryProvider = (*EntraIDDirectoryProvider)(nil)

// EntraIDDirectoryProvider implements interfaces.DirectoryProvider for
// Microsoft Entra ID (formerly Azure AD).
type EntraIDDirectoryProvider struct {
	logger       logging.Logger
	authProvider auth.Provider
	graphClient  graph.Client

	mu        sync.RWMutex
	connected bool
	config    *ProviderConfig
}

// ProviderConfig contains Entra ID specific configuration. It carries no
// tenant or credential: tokens are resolved per execution tenant by the
// auth.Provider from the credential store.
type ProviderConfig struct {
	GraphURL string `json:"graph_url,omitempty"`
}

// NewEntraIDDirectoryProvider creates a new Entra ID directory provider
func NewEntraIDDirectoryProvider(logger logging.Logger, authProvider auth.Provider, graphClient graph.Client) *EntraIDDirectoryProvider {
	return &EntraIDDirectoryProvider{
		logger:       logger,
		authProvider: authProvider,
		graphClient:  graphClient,
	}
}

// GetProviderInfo returns provider identity, capabilities and configuration schema
func (p *EntraIDDirectoryProvider) GetProviderInfo() interfaces.ProviderInfo {
	return interfaces.ProviderInfo{
		Name:        entraProviderName,
		DisplayName: "Microsoft Entra ID",
		Version:     "1.0.0",
		Description: "Microsoft Entra ID (formerly Azure Active Directory) directory provider",
		SupportedTypes: []interfaces.DirectoryObjectType{
			interfaces.DirectoryObjectTypeUser,
			interfaces.DirectoryObjectTypeGroup,
		},
		Capabilities: p.GetCapabilities(),
		Configuration: interfaces.ConfigurationSchema{
			Optional: []interfaces.ConfigField{
				{Name: "graph_url", Type: "string", Description: "Microsoft Graph base URL", DefaultValue: defaultGraphURL},
			},
		},
	}
}

// GetCapabilities returns what this provider supports. Entra ID has no
// organizational units, and administrative units are managed by the
// entra_admin_unit module rather than through this contract.
func (p *EntraIDDirectoryProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{
		SupportsUserManagement:     true,
		SupportsGroupManagement:    true,
		SupportsOUManagement:       false,
		SupportsBulkOperations:     true,
		SupportsAdvancedSearch:     true,
		SupportsCrossDirectorySync: true,
		SupportsRealTimeSync:       false,
		SupportedAuthMethods:       []interfaces.AuthMethod{interfaces.AuthMethodOAuth2},
		MaxSearchResults:           maxSearchResults,
		SupportedSearchTypes:       []string{"user", "group"},
		RateLimitInfo: &interfaces.RateLimitInfo{
			RequestsPerSecond: 10,
			RequestsPerMinute: 600,
			BurstSize:         20,
			BackoffStrategy:   "exponential",
		},
	}
}

// Connection Management

// Connect validates configuration and marks the provider connected. It makes
// no Graph call: there is no tenant until an operation carries one.
func (p *EntraIDDirectoryProvider) Connect(ctx context.Context, config interfaces.ProviderConfig) error {
	providerConfig, err := p.parseConfig(config)
	if err != nil {
		return fmt.Errorf("invalid Entra ID configuration: %w", err)
	}

	p.mu.Lock()
	p.config = providerConfig
	p.connected = true
	p.mu.Unlock()

	p.logger.Info("Entra ID directory provider connected")
	return nil
}

// Disconnect marks the provider disconnected
func (p *EntraIDDirectoryProvider) Disconnect(ctx context.Context) error {
	p.mu.Lock()
	p.connected = false
	p.mu.Unlock()
	p.logger.Info("Entra ID directory provider disconnected")
	return nil
}

// IsConnected returns true if connected to Entra ID
func (p *EntraIDDirectoryProvider) IsConnected(ctx context.Context) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.connected
}

// HealthCheck verifies a token can be obtained for the execution tenant in
// ctx. Without an execution tenant the provider reports unhealthy by design.
func (p *EntraIDDirectoryProvider) HealthCheck(ctx context.Context) (*interfaces.HealthStatus, error) {
	status := &interfaces.HealthStatus{
		IsHealthy: false,
		LastCheck: time.Now(),
		Details:   map[string]interface{}{},
	}

	if !p.IsConnected(ctx) {
		status.Errors = []string{errNotConnected}
		return status, nil
	}

	tenantID, err := requireExecutionTenant(ctx)
	if err != nil {
		status.Errors = []string{logging.SanitizeLogValue(err.Error())}
		return status, nil
	}

	start := time.Now()
	_, err = p.authProvider.GetAccessToken(ctx, tenantID)
	status.ResponseTime = time.Since(start)
	if err != nil {
		status.Errors = []string{"token retrieval failed: " + logging.SanitizeLogValue(err.Error())}
		return status, nil
	}

	status.IsHealthy = true
	return status, nil
}

// token returns a Graph token for the execution tenant in ctx. It fails
// closed, before any Graph call, when disconnected or without a tenant.
func (p *EntraIDDirectoryProvider) token(ctx context.Context) (*auth.AccessToken, error) {
	if !p.IsConnected(ctx) {
		return nil, fmt.Errorf("%s", errNotConnected)
	}
	tenantID, err := requireExecutionTenant(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := p.authProvider.GetAccessToken(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with Microsoft Graph: %w", err)
	}
	return tok, nil
}

// User Operations

// ValidateUser checks a user against what Entra ID requires to create one
func (p *EntraIDDirectoryProvider) ValidateUser(user *interfaces.DirectoryUser) error {
	if user == nil {
		return fmt.Errorf("user object is nil")
	}
	return user.Validate()
}

// ValidateGroup checks a group against what Entra ID requires to create one
func (p *EntraIDDirectoryProvider) ValidateGroup(group *interfaces.DirectoryGroup) error {
	if group == nil {
		return fmt.Errorf("group object is nil")
	}
	return group.Validate()
}

// GetUser retrieves a user from Entra ID
func (p *EntraIDDirectoryProvider) GetUser(ctx context.Context, userID string) (*interfaces.DirectoryUser, error) {
	tok, err := p.token(ctx)
	if err != nil {
		return nil, err
	}

	graphUser, err := p.graphClient.GetUser(ctx, tok, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user from Entra ID: %w", err)
	}
	return p.userFromGraph(graphUser), nil
}

// CreateUser validates and creates a user in Entra ID
func (p *EntraIDDirectoryProvider) CreateUser(ctx context.Context, user *interfaces.DirectoryUser) (*interfaces.DirectoryUser, error) {
	if err := p.ValidateUser(user); err != nil {
		return nil, fmt.Errorf("invalid user: %w", err)
	}
	tok, err := p.token(ctx)
	if err != nil {
		return nil, err
	}

	graphUser := user.ToGraphUser()
	created, err := p.graphClient.CreateUser(ctx, tok, &graph.CreateUserRequest{
		UserPrincipalName: graphUser.UserPrincipalName,
		DisplayName:       graphUser.DisplayName,
		MailNickname:      graphUser.MailNickname,
		AccountEnabled:    graphUser.AccountEnabled,
		Mail:              graphUser.Mail,
		MobilePhone:       graphUser.MobilePhone,
		OfficeLocation:    graphUser.OfficeLocation,
		JobTitle:          graphUser.JobTitle,
		Department:        graphUser.Department,
		CompanyName:       graphUser.CompanyName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user in Entra ID: %w", err)
	}
	return p.userFromGraph(created), nil
}

// UpdateUser updates a user in Entra ID and returns the stored result
func (p *EntraIDDirectoryProvider) UpdateUser(ctx context.Context, userID string, updates *interfaces.DirectoryUser) (*interfaces.DirectoryUser, error) {
	if updates == nil {
		return nil, fmt.Errorf("user updates are nil")
	}
	tok, err := p.token(ctx)
	if err != nil {
		return nil, err
	}

	graphUser := updates.ToGraphUser()
	err = p.graphClient.UpdateUser(ctx, tok, userID, &graph.UpdateUserRequest{
		DisplayName:    &graphUser.DisplayName,
		AccountEnabled: &graphUser.AccountEnabled,
		Mail:           &graphUser.Mail,
		MobilePhone:    &graphUser.MobilePhone,
		OfficeLocation: &graphUser.OfficeLocation,
		JobTitle:       &graphUser.JobTitle,
		Department:     &graphUser.Department,
		CompanyName:    &graphUser.CompanyName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update user in Entra ID: %w", err)
	}
	return p.GetUser(ctx, userID)
}

// DeleteUser deletes a user from Entra ID
func (p *EntraIDDirectoryProvider) DeleteUser(ctx context.Context, userID string) error {
	tok, err := p.token(ctx)
	if err != nil {
		return err
	}
	if err := p.graphClient.DeleteUser(ctx, tok, userID); err != nil {
		return fmt.Errorf("failed to delete user from Entra ID: %w", err)
	}
	return nil
}

// ListUsers lists users matching filters. Graph results are paged here with
// Offset/Limit; TotalCount is the full match count and HasMore signals a
// further page (NextToken is the next offset).
func (p *EntraIDDirectoryProvider) ListUsers(ctx context.Context, filters *interfaces.SearchFilters) (*interfaces.UserList, error) {
	tok, err := p.token(ctx)
	if err != nil {
		return nil, err
	}

	users, err := p.graphClient.ListUsers(ctx, tok, userFilter(filters))
	if err != nil {
		return nil, fmt.Errorf("failed to list users in Entra ID: %w", err)
	}

	start, end, hasMore := pageBounds(len(users), filters)
	list := &interfaces.UserList{
		Users:      make([]interfaces.DirectoryUser, 0, end-start),
		TotalCount: len(users),
		HasMore:    hasMore,
	}
	for i := start; i < end; i++ {
		list.Users = append(list.Users, *p.userFromGraph(&users[i]))
	}
	if hasMore {
		list.NextToken = strconv.Itoa(end)
	}
	return list, nil
}

// Group Operations

// GetGroup retrieves a group from Entra ID
func (p *EntraIDDirectoryProvider) GetGroup(ctx context.Context, groupID string) (*interfaces.DirectoryGroup, error) {
	tok, err := p.token(ctx)
	if err != nil {
		return nil, err
	}
	group, err := p.graphClient.GetGroup(ctx, tok, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group from Entra ID: %w", err)
	}
	return p.groupFromGraph(group), nil
}

// CreateGroup validates and creates a group in Entra ID
func (p *EntraIDDirectoryProvider) CreateGroup(ctx context.Context, group *interfaces.DirectoryGroup) (*interfaces.DirectoryGroup, error) {
	if err := p.ValidateGroup(group); err != nil {
		return nil, fmt.Errorf("invalid group: %w", err)
	}
	tok, err := p.token(ctx)
	if err != nil {
		return nil, err
	}

	graphGroup := group.ToGraphGroup()
	created, err := p.graphClient.CreateGroup(ctx, tok, &graph.CreateGroupRequest{
		DisplayName:     graphGroup.DisplayName,
		Description:     graphGroup.Description,
		MailEnabled:     graphGroup.MailEnabled,
		SecurityEnabled: graphGroup.SecurityEnabled,
		MailNickname:    graphGroup.MailNickname,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create group in Entra ID: %w", err)
	}
	return p.groupFromGraph(created), nil
}

// UpdateGroup updates a group in Entra ID and returns the stored result
func (p *EntraIDDirectoryProvider) UpdateGroup(ctx context.Context, groupID string, updates *interfaces.DirectoryGroup) (*interfaces.DirectoryGroup, error) {
	if updates == nil {
		return nil, fmt.Errorf("group updates are nil")
	}
	tok, err := p.token(ctx)
	if err != nil {
		return nil, err
	}

	graphGroup := updates.ToGraphGroup()
	err = p.graphClient.UpdateGroup(ctx, tok, groupID, &graph.UpdateGroupRequest{
		DisplayName:     &graphGroup.DisplayName,
		Description:     &graphGroup.Description,
		MailEnabled:     &graphGroup.MailEnabled,
		SecurityEnabled: &graphGroup.SecurityEnabled,
		MailNickname:    &graphGroup.MailNickname,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update group in Entra ID: %w", err)
	}
	return p.GetGroup(ctx, groupID)
}

// DeleteGroup deletes a group from Entra ID
func (p *EntraIDDirectoryProvider) DeleteGroup(ctx context.Context, groupID string) error {
	tok, err := p.token(ctx)
	if err != nil {
		return err
	}
	if err := p.graphClient.DeleteGroup(ctx, tok, groupID); err != nil {
		return fmt.Errorf("failed to delete group from Entra ID: %w", err)
	}
	return nil
}

// ListGroups lists groups matching filters, paged like ListUsers
func (p *EntraIDDirectoryProvider) ListGroups(ctx context.Context, filters *interfaces.SearchFilters) (*interfaces.GroupList, error) {
	tok, err := p.token(ctx)
	if err != nil {
		return nil, err
	}

	groups, err := p.graphClient.ListGroups(ctx, tok, groupFilter(filters))
	if err != nil {
		return nil, fmt.Errorf("failed to list groups in Entra ID: %w", err)
	}

	start, end, hasMore := pageBounds(len(groups), filters)
	list := &interfaces.GroupList{
		Groups:     make([]interfaces.DirectoryGroup, 0, end-start),
		TotalCount: len(groups),
		HasMore:    hasMore,
	}
	for i := start; i < end; i++ {
		list.Groups = append(list.Groups, *p.groupFromGraph(&groups[i]))
	}
	if hasMore {
		list.NextToken = strconv.Itoa(end)
	}
	return list, nil
}

// Membership Operations

// AddUserToGroup adds a user to a group in Entra ID
func (p *EntraIDDirectoryProvider) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	tok, err := p.token(ctx)
	if err != nil {
		return err
	}
	if err := p.graphClient.AddUserToGroup(ctx, tok, userID, groupID); err != nil {
		return fmt.Errorf("failed to add user to group in Entra ID: %w", err)
	}
	return nil
}

// RemoveUserFromGroup removes a user from a group in Entra ID
func (p *EntraIDDirectoryProvider) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	tok, err := p.token(ctx)
	if err != nil {
		return err
	}
	if err := p.graphClient.RemoveUserFromGroup(ctx, tok, userID, groupID); err != nil {
		return fmt.Errorf("failed to remove user from group in Entra ID: %w", err)
	}
	return nil
}

// GetUserGroups gets all groups for a user in Entra ID
func (p *EntraIDDirectoryProvider) GetUserGroups(ctx context.Context, userID string) ([]interfaces.DirectoryGroup, error) {
	tok, err := p.token(ctx)
	if err != nil {
		return nil, err
	}

	groupIDs, err := p.graphClient.GetUserGroups(ctx, tok, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups from Entra ID: %w", err)
	}

	result := make([]interfaces.DirectoryGroup, 0, len(groupIDs))
	for _, gid := range groupIDs {
		group, err := p.graphClient.GetGroup(ctx, tok, gid)
		if err != nil {
			p.logger.Warn("failed to get group details", "group_id", logging.SanitizeLogValue(gid), "error", logging.SanitizeLogValue(err.Error()))
			continue
		}
		result = append(result, *p.groupFromGraph(group))
	}
	return result, nil
}

// GetGroupMembers gets all members of a group in Entra ID
func (p *EntraIDDirectoryProvider) GetGroupMembers(ctx context.Context, groupID string) ([]interfaces.DirectoryUser, error) {
	tok, err := p.token(ctx)
	if err != nil {
		return nil, err
	}

	upns, err := p.graphClient.ListGroupMembers(ctx, tok, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members from Entra ID: %w", err)
	}

	result := make([]interfaces.DirectoryUser, 0, len(upns))
	for _, upn := range upns {
		user, err := p.graphClient.GetUser(ctx, tok, upn)
		if err != nil {
			p.logger.Warn("failed to get member details", "upn", logging.SanitizeLogValue(upn), "error", logging.SanitizeLogValue(err.Error()))
			continue
		}
		result = append(result, *p.userFromGraph(user))
	}
	return result, nil
}

// Organizational Units (Entra ID has none)

// GetOU returns not supported error
func (p *EntraIDDirectoryProvider) GetOU(ctx context.Context, ouID string) (*interfaces.OrganizationalUnit, error) {
	return nil, fmt.Errorf("%s", errOUsNotSupportedMsg)
}

// CreateOU returns not supported error
func (p *EntraIDDirectoryProvider) CreateOU(ctx context.Context, ou *interfaces.OrganizationalUnit) (*interfaces.OrganizationalUnit, error) {
	return nil, fmt.Errorf("%s", errOUsNotSupportedMsg)
}

// UpdateOU returns not supported error
func (p *EntraIDDirectoryProvider) UpdateOU(ctx context.Context, ouID string, updates *interfaces.OrganizationalUnit) (*interfaces.OrganizationalUnit, error) {
	return nil, fmt.Errorf("%s", errOUsNotSupportedMsg)
}

// DeleteOU returns not supported error
func (p *EntraIDDirectoryProvider) DeleteOU(ctx context.Context, ouID string) error {
	return fmt.Errorf("%s", errOUsNotSupportedMsg)
}

// ListOUs returns an empty list: Entra ID has no organizational units
func (p *EntraIDDirectoryProvider) ListOUs(ctx context.Context, filters *interfaces.SearchFilters) (*interfaces.OUList, error) {
	return &interfaces.OUList{OUs: []interfaces.OrganizationalUnit{}}, nil
}

// Advanced Search

// Search finds users and groups whose display name (or, for users, user
// principal name) starts with query.Filter. An empty filter is rejected to
// prevent accidentally fetching the whole directory.
func (p *EntraIDDirectoryProvider) Search(ctx context.Context, query *interfaces.DirectoryQuery) (*interfaces.SearchResults, error) {
	if query == nil || strings.TrimSpace(query.Filter) == "" {
		return nil, fmt.Errorf("search filter must not be empty")
	}
	tok, err := p.token(ctx)
	if err != nil {
		return nil, err
	}

	text := odataQuote(query.Filter)
	users, err := p.graphClient.ListUsers(ctx, tok,
		fmt.Sprintf("startswith(displayName,'%s') or startswith(userPrincipalName,'%s')", text, text))
	if err != nil {
		return nil, fmt.Errorf("failed to search users in Entra ID: %w", err)
	}
	groups, err := p.graphClient.ListGroups(ctx, tok, fmt.Sprintf("startswith(displayName,'%s')", text))
	if err != nil {
		return nil, fmt.Errorf("failed to search groups in Entra ID: %w", err)
	}

	results := &interfaces.SearchResults{
		Users:  make([]interfaces.DirectoryUser, 0, len(users)),
		Groups: make([]interfaces.DirectoryGroup, 0, len(groups)),
	}
	for i := range users {
		results.Users = append(results.Users, *p.userFromGraph(&users[i]))
	}
	for i := range groups {
		results.Groups = append(results.Groups, *p.groupFromGraph(&groups[i]))
	}
	results.TotalCount = len(results.Users) + len(results.Groups)
	return results, nil
}

// Bulk Operations

// BulkCreateUsers creates each user in turn and reports per-item results.
// With non-nil options and ContinueOnError false it stops at the first failure.
func (p *EntraIDDirectoryProvider) BulkCreateUsers(ctx context.Context, users []*interfaces.DirectoryUser, options *interfaces.BulkOptions) (*interfaces.BulkResult, error) {
	return runBulk(ctx, len(users), options, func(i int) (string, interface{}, error) {
		created, err := p.CreateUser(ctx, users[i])
		if err != nil {
			id := ""
			if users[i] != nil {
				id = users[i].UserPrincipalName
			}
			return id, nil, err
		}
		return created.ID, created, nil
	})
}

// BulkUpdateUsers updates each user in turn and reports per-item results
func (p *EntraIDDirectoryProvider) BulkUpdateUsers(ctx context.Context, updates []*interfaces.UserUpdate, options *interfaces.BulkOptions) (*interfaces.BulkResult, error) {
	return runBulk(ctx, len(updates), options, func(i int) (string, interface{}, error) {
		if updates[i] == nil {
			return "", nil, fmt.Errorf("user update is nil")
		}
		updated, err := p.UpdateUser(ctx, updates[i].UserID, updates[i].Updates)
		if err != nil {
			return updates[i].UserID, nil, err
		}
		return updated.ID, updated, nil
	})
}

// BulkDeleteUsers deletes each user in turn and reports per-item results
func (p *EntraIDDirectoryProvider) BulkDeleteUsers(ctx context.Context, userIDs []string, options *interfaces.BulkOptions) (*interfaces.BulkResult, error) {
	return runBulk(ctx, len(userIDs), options, func(i int) (string, interface{}, error) {
		return userIDs[i], nil, p.DeleteUser(ctx, userIDs[i])
	})
}

// runBulk drives a per-item operation and assembles the BulkResult.
func runBulk(ctx context.Context, total int, options *interfaces.BulkOptions, op func(i int) (string, interface{}, error)) (*interfaces.BulkResult, error) {
	start := time.Now()
	result := &interfaces.BulkResult{TotalItems: total}
	stopOnError := options != nil && !options.ContinueOnError

	for i := 0; i < total; i++ {
		if err := ctx.Err(); err != nil {
			result.Duration = time.Since(start)
			return result, err
		}
		id, data, err := op(i)
		item := interfaces.BulkItemResult{ItemIndex: i, ItemID: id, Success: err == nil, Data: data}
		if err != nil {
			msg := logging.SanitizeLogValue(err.Error())
			item.Error = msg
			result.ErrorCount++
			result.Errors = append(result.Errors, interfaces.BulkItemError{ItemIndex: i, ItemID: id, Error: msg})
		} else {
			result.SuccessCount++
		}
		result.ItemResults = append(result.ItemResults, item)
		if err != nil && stopOnError {
			break
		}
	}
	result.Duration = time.Since(start)
	return result, nil
}

// Cross-Directory Operations

// SyncUser copies a user from Entra ID into targetProvider, updating it when
// it already exists there.
func (p *EntraIDDirectoryProvider) SyncUser(ctx context.Context, sourceUserID string, targetProvider interfaces.DirectoryProvider) error {
	if targetProvider == nil {
		return fmt.Errorf("target provider is nil")
	}
	sourceUser, err := p.GetUser(ctx, sourceUserID)
	if err != nil {
		return fmt.Errorf("failed to get source user: %w", err)
	}

	targetUser, err := targetProvider.GetUser(ctx, sourceUser.UserPrincipalName)
	if err != nil {
		if _, err := targetProvider.CreateUser(ctx, sourceUser); err != nil {
			return fmt.Errorf("failed to create user in target provider: %w", err)
		}
		return nil
	}
	if _, err := targetProvider.UpdateUser(ctx, targetUser.ID, sourceUser); err != nil {
		return fmt.Errorf("failed to update user in target provider: %w", err)
	}
	return nil
}

// SyncGroup copies a group from Entra ID into targetProvider, updating it when
// it already exists there.
func (p *EntraIDDirectoryProvider) SyncGroup(ctx context.Context, sourceGroupID string, targetProvider interfaces.DirectoryProvider) error {
	if targetProvider == nil {
		return fmt.Errorf("target provider is nil")
	}
	sourceGroup, err := p.GetGroup(ctx, sourceGroupID)
	if err != nil {
		return fmt.Errorf("failed to get source group: %w", err)
	}

	targetGroup, err := targetProvider.GetGroup(ctx, sourceGroup.Name)
	if err != nil {
		if _, err := targetProvider.CreateGroup(ctx, sourceGroup); err != nil {
			return fmt.Errorf("failed to create group in target provider: %w", err)
		}
		return nil
	}
	if _, err := targetProvider.UpdateGroup(ctx, targetGroup.ID, sourceGroup); err != nil {
		return fmt.Errorf("failed to update group in target provider: %w", err)
	}
	return nil
}

// GetSchema describes the user and group objects Entra ID exposes
func (p *EntraIDDirectoryProvider) GetSchema(ctx context.Context) (*interfaces.DirectorySchema, error) {
	return &interfaces.DirectorySchema{
		UserSchema: interfaces.ObjectSchema{
			ObjectType: interfaces.DirectoryObjectTypeUser,
			RequiredFields: []interfaces.SchemaField{
				{Name: "userPrincipalName", Type: "string", Description: "User principal name (UPN)", MaxLength: 113},
				{Name: "displayName", Type: "string", Description: "Display name", MaxLength: 256},
				{Name: "mailNickname", Type: "string", Description: "Mail alias", MaxLength: 64},
			},
			OptionalFields: []interfaces.SchemaField{
				{Name: "mail", Type: "string", Description: "Email address", MaxLength: 256, Format: "email"},
				{Name: "mobilePhone", Type: "string", Description: "Mobile phone", MaxLength: 64},
				{Name: "department", Type: "string", Description: "Department", MaxLength: 64},
				{Name: "jobTitle", Type: "string", Description: "Job title", MaxLength: 128},
				{Name: "companyName", Type: "string", Description: "Company name", MaxLength: 64},
				{Name: "officeLocation", Type: "string", Description: "Office location", MaxLength: 128},
				{Name: "accountEnabled", Type: "bool", Description: "Whether the account is enabled"},
			},
			ReadOnlyFields: []interfaces.SchemaField{
				{Name: "id", Type: "string", Description: "Object ID"},
				{Name: "createdDateTime", Type: "datetime", Description: "Creation timestamp"},
			},
			SearchableFields: []interfaces.SchemaField{
				{Name: "displayName", Type: "string", Description: "Search by display name"},
				{Name: "userPrincipalName", Type: "string", Description: "Search by UPN"},
			},
		},
		GroupSchema: interfaces.ObjectSchema{
			ObjectType: interfaces.DirectoryObjectTypeGroup,
			RequiredFields: []interfaces.SchemaField{
				{Name: "displayName", Type: "string", Description: "Display name", MaxLength: 256},
				{Name: "mailNickname", Type: "string", Description: "Mail alias", MaxLength: 64},
			},
			OptionalFields: []interfaces.SchemaField{
				{Name: "description", Type: "string", Description: "Group description", MaxLength: 1024},
				{Name: "mailEnabled", Type: "bool", Description: "Whether the group is mail-enabled"},
				{Name: "securityEnabled", Type: "bool", Description: "Whether the group is a security group"},
			},
			ReadOnlyFields: []interfaces.SchemaField{
				{Name: "id", Type: "string", Description: "Object ID"},
				{Name: "mail", Type: "string", Description: "Primary SMTP address"},
			},
			SearchableFields: []interfaces.SchemaField{
				{Name: "displayName", Type: "string", Description: "Search by display name"},
			},
		},
	}, nil
}

// Helper Methods

// parseConfig reads the only setting Entra ID accepts, an optional graph_url.
func (p *EntraIDDirectoryProvider) parseConfig(config interfaces.ProviderConfig) (*ProviderConfig, error) {
	graphURL := defaultGraphURL
	if raw, ok := config.ProviderConfig["graph_url"]; ok {
		url, isString := raw.(string)
		if !isString {
			return nil, fmt.Errorf("graph_url must be a string")
		}
		if url != "" {
			if !strings.HasPrefix(url, "https://") {
				return nil, fmt.Errorf("graph_url must be an https URL")
			}
			graphURL = url
		}
	}
	return &ProviderConfig{GraphURL: graphURL}, nil
}

// userFromGraph converts a graph.User, stamping Source with the provider name
func (p *EntraIDDirectoryProvider) userFromGraph(u *graph.User) *interfaces.DirectoryUser {
	user := types.FromGraphUser(&types.GraphUser{
		ID:                u.ID,
		UserPrincipalName: u.UserPrincipalName,
		DisplayName:       u.DisplayName,
		MailNickname:      u.MailNickname,
		AccountEnabled:    u.AccountEnabled,
		Mail:              u.Mail,
		MobilePhone:       u.MobilePhone,
		OfficeLocation:    u.OfficeLocation,
		JobTitle:          u.JobTitle,
		Department:        u.Department,
		CompanyName:       u.CompanyName,
		CreatedDateTime:   u.CreatedDateTime,
	}, entraProviderName)
	user.Source = entraProviderName
	return user
}

// groupFromGraph converts a graph.Group, stamping Source with the provider name
func (p *EntraIDDirectoryProvider) groupFromGraph(g *graph.Group) *interfaces.DirectoryGroup {
	group := types.FromGraphGroup(&types.GraphGroup{
		ID:              g.ID,
		DisplayName:     g.DisplayName,
		Description:     g.Description,
		MailEnabled:     g.MailEnabled,
		SecurityEnabled: g.SecurityEnabled,
		MailNickname:    g.MailNickname,
		Mail:            g.Mail,
	}, entraProviderName)
	group.Source = entraProviderName
	return group
}

// odataQuote escapes single quotes so a value cannot break out of an OData string literal
func odataQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// userFilter builds the OData $filter for ListUsers
func userFilter(f *interfaces.SearchFilters) string {
	if f == nil {
		return ""
	}
	var clauses []string
	if q := strings.TrimSpace(f.Query); q != "" {
		q = odataQuote(q)
		clauses = append(clauses, fmt.Sprintf("(startswith(displayName,'%s') or startswith(userPrincipalName,'%s'))", q, q))
	}
	if f.Department != "" {
		clauses = append(clauses, fmt.Sprintf("department eq '%s'", odataQuote(f.Department)))
	}
	if f.JobTitle != "" {
		clauses = append(clauses, fmt.Sprintf("jobTitle eq '%s'", odataQuote(f.JobTitle)))
	}
	if f.Enabled != nil {
		clauses = append(clauses, fmt.Sprintf("accountEnabled eq %t", *f.Enabled))
	}
	return strings.Join(clauses, " and ")
}

// groupFilter builds the OData $filter for ListGroups
func groupFilter(f *interfaces.SearchFilters) string {
	if f == nil || strings.TrimSpace(f.Query) == "" {
		return ""
	}
	return fmt.Sprintf("startswith(displayName,'%s')", odataQuote(strings.TrimSpace(f.Query)))
}

// pageBounds resolves Offset/Limit against n results, returning the slice
// window and whether more results follow it.
func pageBounds(n int, f *interfaces.SearchFilters) (start, end int, hasMore bool) {
	limit := defaultListPageSize
	if f != nil {
		start = f.Offset
		if f.Limit > 0 {
			limit = f.Limit
		}
	}
	if limit > maxSearchResults {
		limit = maxSearchResults
	}
	if start < 0 {
		start = 0
	}
	if start > n {
		start = n
	}
	end = start + limit
	if end > n {
		end = n
	}
	return start, end, end < n
}
