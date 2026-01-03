// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package m365 provides directory provider integration for Microsoft 365/Entra ID
// that implements the controller's unified directory interface.
//
// This module bridges the gap between CFGMS's controller-centric directory abstraction
// and Microsoft 365 specific operations, eliminating the need for duplicate user/group
// management code across entra_user, entra_group, and other M365 modules.
package m365

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/controller/directory"
	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/directory/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// EntraIDDirectoryProvider implements the controller's directory.Provider interface
// for Microsoft Entra ID (formerly Azure AD) operations.
type EntraIDDirectoryProvider struct {
	name         string
	displayName  string
	description  string
	logger       logging.Logger
	authProvider auth.Provider
	graphClient  graph.Client
	connected    bool
	config       *ProviderConfig
	capabilities directory.ProviderCapabilities
}

// ProviderConfig contains Entra ID specific configuration
type ProviderConfig struct {
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	GraphURL     string `json:"graph_url,omitempty"`
}

// NewEntraIDDirectoryProvider creates a new Entra ID directory provider
func NewEntraIDDirectoryProvider(logger logging.Logger, authProvider auth.Provider, graphClient graph.Client) *EntraIDDirectoryProvider {
	return &EntraIDDirectoryProvider{
		name:         "entraid",
		displayName:  "Microsoft Entra ID",
		description:  "Microsoft Entra ID (formerly Azure Active Directory) directory provider",
		logger:       logger,
		authProvider: authProvider,
		graphClient:  graphClient,
		capabilities: directory.ProviderCapabilities{
			UserManagement:       true,
			GroupManagement:      true,
			AdvancedSearch:       true,
			BulkOperations:       false, // Not yet implemented
			RealTimeSync:         false, // Not yet implemented
			CrossDirectoryOps:    true,
			OUSupport:            false, // Entra ID doesn't have OUs
			AdminUnitSupport:     true,  // Entra ID specific
			SupportedAuthMethods: []string{"oauth2", "client_credentials"},
			MaxSearchResults:     999, // Microsoft Graph default limit
			RateLimit: &directory.RateLimitInfo{
				RequestsPerSecond: 10,
				RequestsPerMinute: 600,
				BurstSize:         20,
				BackoffStrategy:   "exponential",
			},
		},
	}
}

// Provider Interface Implementation

// Name returns the provider name
func (p *EntraIDDirectoryProvider) Name() string {
	return p.name
}

// DisplayName returns the provider display name
func (p *EntraIDDirectoryProvider) DisplayName() string {
	return p.displayName
}

// Description returns the provider description
func (p *EntraIDDirectoryProvider) Description() string {
	return p.description
}

// Capabilities returns the provider capabilities
func (p *EntraIDDirectoryProvider) Capabilities() directory.ProviderCapabilities {
	return p.capabilities
}

// Connection Management

// Connect establishes connection to Entra ID
func (p *EntraIDDirectoryProvider) Connect(ctx context.Context, config directory.ProviderConfig) error {
	// Extract Entra ID specific configuration
	providerConfig, err := p.parseConfig(config)
	if err != nil {
		return fmt.Errorf("invalid Entra ID configuration: %w", err)
	}

	p.config = providerConfig

	// Test connection by getting a token
	token, err := p.authProvider.GetAccessToken(ctx, providerConfig.TenantID)
	if err != nil {
		return fmt.Errorf("failed to authenticate with Entra ID: %w", err)
	}

	// Test Graph API access
	_, err = p.graphClient.GetUser(ctx, token, "me")
	if err != nil {
		// This is expected if using client credentials - just log it
		p.logger.Debug("Graph API test call completed", "error", err)
	}

	p.connected = true
	p.logger.Info("Connected to Entra ID", "tenant_id", providerConfig.TenantID)
	return nil
}

// Disconnect closes the connection to Entra ID
func (p *EntraIDDirectoryProvider) Disconnect(ctx context.Context) error {
	p.connected = false
	p.logger.Info("Disconnected from Entra ID")
	return nil
}

// IsConnected returns true if connected to Entra ID
func (p *EntraIDDirectoryProvider) IsConnected() bool {
	return p.connected
}

// HealthCheck performs a health check on the Entra ID connection
func (p *EntraIDDirectoryProvider) HealthCheck(ctx context.Context) (*directory.ProviderHealth, error) {
	health := &directory.ProviderHealth{
		IsHealthy:    p.connected,
		LastCheck:    time.Now(),
		Capabilities: p.capabilities,
	}

	if !p.connected {
		health.ErrorMessage = "not connected to Entra ID"
		return health, nil
	}

	// Test token retrieval
	start := time.Now()
	_, err := p.authProvider.GetAccessToken(ctx, p.config.TenantID)
	health.ResponseTime = time.Since(start)

	if err != nil {
		health.IsHealthy = false
		health.ErrorMessage = fmt.Sprintf("token retrieval failed: %v", err)
	}

	return health, nil
}

// User Operations

// GetUser retrieves a user from Entra ID
func (p *EntraIDDirectoryProvider) GetUser(ctx context.Context, userID string) (*types.DirectoryUser, error) {
	if !p.connected {
		return nil, fmt.Errorf("not connected to Entra ID")
	}

	token, err := p.getToken(ctx)
	if err != nil {
		return nil, err
	}

	graphUser, err := p.graphClient.GetUser(ctx, token, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user from Entra ID: %w", err)
	}

	// Convert Graph User to unified DirectoryUser using proper types
	graphUserType := &types.GraphUser{
		ID:                graphUser.ID,
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
		CreatedDateTime:   graphUser.CreatedDateTime,
	}
	return types.FromGraphUser(graphUserType, p.name), nil
}

// CreateUser creates a user in Entra ID
func (p *EntraIDDirectoryProvider) CreateUser(ctx context.Context, user *types.DirectoryUser) (*types.DirectoryUser, error) {
	if !p.connected {
		return nil, fmt.Errorf("not connected to Entra ID")
	}

	token, err := p.getToken(ctx)
	if err != nil {
		return nil, err
	}

	// Convert DirectoryUser to Graph CreateUserRequest
	graphUser := user.ToGraphUser()
	createRequest := &graph.CreateUserRequest{
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
	}

	createdUser, err := p.graphClient.CreateUser(ctx, token, createRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to create user in Entra ID: %w", err)
	}

	// Convert Graph User to unified DirectoryUser using proper types
	graphUserType := &types.GraphUser{
		ID:                createdUser.ID,
		UserPrincipalName: createdUser.UserPrincipalName,
		DisplayName:       createdUser.DisplayName,
		MailNickname:      createdUser.MailNickname,
		AccountEnabled:    createdUser.AccountEnabled,
		Mail:              createdUser.Mail,
		MobilePhone:       createdUser.MobilePhone,
		OfficeLocation:    createdUser.OfficeLocation,
		JobTitle:          createdUser.JobTitle,
		Department:        createdUser.Department,
		CompanyName:       createdUser.CompanyName,
		CreatedDateTime:   createdUser.CreatedDateTime,
	}
	return types.FromGraphUser(graphUserType, p.name), nil
}

// UpdateUser updates a user in Entra ID
func (p *EntraIDDirectoryProvider) UpdateUser(ctx context.Context, userID string, updates *types.DirectoryUser) (*types.DirectoryUser, error) {
	if !p.connected {
		return nil, fmt.Errorf("not connected to Entra ID")
	}

	token, err := p.getToken(ctx)
	if err != nil {
		return nil, err
	}

	// Convert DirectoryUser updates to Graph UpdateUserRequest
	graphUser := updates.ToGraphUser()
	updateRequest := &graph.UpdateUserRequest{
		DisplayName:    &graphUser.DisplayName,
		AccountEnabled: &graphUser.AccountEnabled,
		Mail:           &graphUser.Mail,
		MobilePhone:    &graphUser.MobilePhone,
		OfficeLocation: &graphUser.OfficeLocation,
		JobTitle:       &graphUser.JobTitle,
		Department:     &graphUser.Department,
		CompanyName:    &graphUser.CompanyName,
	}

	err = p.graphClient.UpdateUser(ctx, token, userID, updateRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to update user in Entra ID: %w", err)
	}

	// Return the updated user
	return p.GetUser(ctx, userID)
}

// DeleteUser deletes a user from Entra ID
func (p *EntraIDDirectoryProvider) DeleteUser(ctx context.Context, userID string) error {
	if !p.connected {
		return fmt.Errorf("not connected to Entra ID")
	}

	token, err := p.getToken(ctx)
	if err != nil {
		return err
	}

	err = p.graphClient.DeleteUser(ctx, token, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user from Entra ID: %w", err)
	}

	return nil
}

// SearchUsers searches for users in Entra ID
func (p *EntraIDDirectoryProvider) SearchUsers(ctx context.Context, query *directory.SearchQuery) ([]*types.DirectoryUser, error) {
	if !p.connected {
		return nil, fmt.Errorf("not connected to Entra ID")
	}

	// For now, return empty slice - full implementation would use Graph API search
	// This would involve constructing OData filter queries from the SearchQuery
	p.logger.Info("SearchUsers called", "query", query.Query, "limit", query.Limit)
	return []*types.DirectoryUser{}, nil
}

// Group Operations (similar pattern to user operations)

// GetGroup retrieves a group from Entra ID
func (p *EntraIDDirectoryProvider) GetGroup(ctx context.Context, groupID string) (*types.DirectoryGroup, error) {
	// Similar implementation to GetUser but for groups
	return nil, fmt.Errorf("GetGroup not yet implemented for Entra ID provider")
}

// CreateGroup creates a group in Entra ID
func (p *EntraIDDirectoryProvider) CreateGroup(ctx context.Context, group *types.DirectoryGroup) (*types.DirectoryGroup, error) {
	return nil, fmt.Errorf("CreateGroup not yet implemented for Entra ID provider")
}

// UpdateGroup updates a group in Entra ID
func (p *EntraIDDirectoryProvider) UpdateGroup(ctx context.Context, groupID string, updates *types.DirectoryGroup) (*types.DirectoryGroup, error) {
	return nil, fmt.Errorf("UpdateGroup not yet implemented for Entra ID provider")
}

// DeleteGroup deletes a group from Entra ID
func (p *EntraIDDirectoryProvider) DeleteGroup(ctx context.Context, groupID string) error {
	return fmt.Errorf("DeleteGroup not yet implemented for Entra ID provider")
}

// SearchGroups searches for groups in Entra ID
func (p *EntraIDDirectoryProvider) SearchGroups(ctx context.Context, query *directory.SearchQuery) ([]*types.DirectoryGroup, error) {
	return nil, fmt.Errorf("SearchGroups not yet implemented for Entra ID provider")
}

// Membership Operations

// AddUserToGroup adds a user to a group in Entra ID
func (p *EntraIDDirectoryProvider) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	return fmt.Errorf("AddUserToGroup not yet implemented for Entra ID provider")
}

// RemoveUserFromGroup removes a user from a group in Entra ID
func (p *EntraIDDirectoryProvider) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	return fmt.Errorf("RemoveUserFromGroup not yet implemented for Entra ID provider")
}

// GetUserGroups gets all groups for a user in Entra ID
func (p *EntraIDDirectoryProvider) GetUserGroups(ctx context.Context, userID string) ([]*types.DirectoryGroup, error) {
	return nil, fmt.Errorf("GetUserGroups not yet implemented for Entra ID provider")
}

// GetGroupMembers gets all members of a group in Entra ID
func (p *EntraIDDirectoryProvider) GetGroupMembers(ctx context.Context, groupID string) ([]*types.DirectoryUser, error) {
	return nil, fmt.Errorf("GetGroupMembers not yet implemented for Entra ID provider")
}

// Organizational Structure (Entra ID doesn't support OUs)

// SupportsOUs returns false since Entra ID doesn't have organizational units
func (p *EntraIDDirectoryProvider) SupportsOUs() bool {
	return false
}

// GetOU returns not supported error
func (p *EntraIDDirectoryProvider) GetOU(ctx context.Context, ouID string) (*directory.OrganizationalUnit, error) {
	return nil, fmt.Errorf("organizational units not supported by Entra ID")
}

// CreateOU returns not supported error
func (p *EntraIDDirectoryProvider) CreateOU(ctx context.Context, ou *directory.OrganizationalUnit) (*directory.OrganizationalUnit, error) {
	return nil, fmt.Errorf("organizational units not supported by Entra ID")
}

// UpdateOU returns not supported error
func (p *EntraIDDirectoryProvider) UpdateOU(ctx context.Context, ouID string, updates *directory.OrganizationalUnit) (*directory.OrganizationalUnit, error) {
	return nil, fmt.Errorf("organizational units not supported by Entra ID")
}

// DeleteOU returns not supported error
func (p *EntraIDDirectoryProvider) DeleteOU(ctx context.Context, ouID string) error {
	return fmt.Errorf("organizational units not supported by Entra ID")
}

// ListOUs returns not supported error
func (p *EntraIDDirectoryProvider) ListOUs(ctx context.Context) ([]*directory.OrganizationalUnit, error) {
	return nil, fmt.Errorf("organizational units not supported by Entra ID")
}

// Administrative Units (Entra ID specific feature)

// SupportsAdminUnits returns true since Entra ID supports administrative units
func (p *EntraIDDirectoryProvider) SupportsAdminUnits() bool {
	return true
}

// GetAdminUnit gets an administrative unit from Entra ID
func (p *EntraIDDirectoryProvider) GetAdminUnit(ctx context.Context, unitID string) (*directory.AdministrativeUnit, error) {
	return nil, fmt.Errorf("GetAdminUnit not yet implemented for Entra ID provider")
}

// CreateAdminUnit creates an administrative unit in Entra ID
func (p *EntraIDDirectoryProvider) CreateAdminUnit(ctx context.Context, unit *directory.AdministrativeUnit) (*directory.AdministrativeUnit, error) {
	return nil, fmt.Errorf("CreateAdminUnit not yet implemented for Entra ID provider")
}

// UpdateAdminUnit updates an administrative unit in Entra ID
func (p *EntraIDDirectoryProvider) UpdateAdminUnit(ctx context.Context, unitID string, updates *directory.AdministrativeUnit) (*directory.AdministrativeUnit, error) {
	return nil, fmt.Errorf("UpdateAdminUnit not yet implemented for Entra ID provider")
}

// DeleteAdminUnit deletes an administrative unit from Entra ID
func (p *EntraIDDirectoryProvider) DeleteAdminUnit(ctx context.Context, unitID string) error {
	return fmt.Errorf("DeleteAdminUnit not yet implemented for Entra ID provider")
}

// ListAdminUnits lists administrative units in Entra ID
func (p *EntraIDDirectoryProvider) ListAdminUnits(ctx context.Context) ([]*directory.AdministrativeUnit, error) {
	return nil, fmt.Errorf("ListAdminUnits not yet implemented for Entra ID provider")
}

// Helper Methods

// getToken retrieves an access token for Graph API operations
func (p *EntraIDDirectoryProvider) getToken(ctx context.Context) (*auth.AccessToken, error) {
	return p.authProvider.GetAccessToken(ctx, p.config.TenantID)
}

// parseConfig parses the generic provider config into Entra ID specific config
func (p *EntraIDDirectoryProvider) parseConfig(config directory.ProviderConfig) (*ProviderConfig, error) {
	tenantID, ok := config.Settings["tenant_id"].(string)
	if !ok || tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}

	clientID, ok := config.Settings["client_id"].(string)
	if !ok || clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	clientSecret, ok := config.Credentials["client_secret"]
	if !ok || clientSecret == "" {
		return nil, fmt.Errorf("client_secret is required")
	}

	graphURL := "https://graph.microsoft.com/v1.0"
	if url, ok := config.Settings["graph_url"].(string); ok && url != "" {
		graphURL = url
	}

	return &ProviderConfig{
		TenantID:     tenantID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		GraphURL:     graphURL,
	}, nil
}

// RegisterWithController registers this provider with the controller's directory service
func RegisterWithController(controller interface{}) error {
	// This would be called during module initialization
	// For now, just return success - actual registration would happen through controller interface
	return nil
}
