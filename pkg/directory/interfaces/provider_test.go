// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDirectoryProvider provides a mock implementation for testing
type TestDirectoryProvider struct {
	info         ProviderInfo
	connected    bool
	users        map[string]*DirectoryUser
	groups       map[string]*DirectoryGroup
	ous          map[string]*OrganizationalUnit
	lastError    error
	capabilities ProviderCapabilities
}

// NewTestDirectoryProvider creates a new test directory provider
func NewTestDirectoryProvider(name string) *TestDirectoryProvider {
	return &TestDirectoryProvider{
		info: ProviderInfo{
			Name:        name,
			DisplayName: "Test " + name,
			Version:     "1.0.0",
			Description: "Test directory provider for unit testing",
			SupportedTypes: []DirectoryObjectType{
				DirectoryObjectTypeUser,
				DirectoryObjectTypeGroup,
				DirectoryObjectTypeOU,
			},
		},
		users:  make(map[string]*DirectoryUser),
		groups: make(map[string]*DirectoryGroup),
		ous:    make(map[string]*OrganizationalUnit),
		capabilities: ProviderCapabilities{
			SupportsUserManagement:     true,
			SupportsGroupManagement:    true,
			SupportsOUManagement:       true,
			SupportsBulkOperations:     true,
			SupportsAdvancedSearch:     true,
			SupportsCrossDirectorySync: true,
			SupportedAuthMethods: []AuthMethod{
				AuthMethodLDAP,
				AuthMethodOAuth2,
			},
			MaxSearchResults: 1000,
		},
	}
}

// Implement DirectoryProvider interface
func (t *TestDirectoryProvider) GetProviderInfo() ProviderInfo {
	return t.info
}

func (t *TestDirectoryProvider) Connect(ctx context.Context, config ProviderConfig) error {
	if t.lastError != nil {
		return t.lastError
	}
	t.connected = true
	return nil
}

func (t *TestDirectoryProvider) Disconnect(ctx context.Context) error {
	if t.lastError != nil {
		return t.lastError
	}
	t.connected = false
	return nil
}

func (t *TestDirectoryProvider) IsConnected(ctx context.Context) bool {
	return t.connected
}

func (t *TestDirectoryProvider) HealthCheck(ctx context.Context) (*HealthStatus, error) {
	if t.lastError != nil {
		return &HealthStatus{
			IsHealthy: false,
			LastCheck: time.Now(),
			Errors:    []string{t.lastError.Error()},
		}, nil
	}

	return &HealthStatus{
		IsHealthy:    t.connected,
		LastCheck:    time.Now(),
		ResponseTime: 50 * time.Millisecond,
	}, nil
}

func (t *TestDirectoryProvider) GetUser(ctx context.Context, userID string) (*DirectoryUser, error) {
	if t.lastError != nil {
		return nil, t.lastError
	}

	user, exists := t.users[userID]
	if !exists {
		return nil, &DirectoryError{
			Type:    ErrorTypeNotFound,
			Message: "user not found",
		}
	}

	return user, nil
}

func (t *TestDirectoryProvider) CreateUser(ctx context.Context, user *DirectoryUser) (*DirectoryUser, error) {
	if t.lastError != nil {
		return nil, t.lastError
	}

	// Generate ID if not provided
	if user.ID == "" {
		user.ID = user.UserPrincipalName
	}

	// Set metadata
	now := time.Now()
	user.Created = &now
	user.Modified = &now
	user.Source = t.info.Name

	t.users[user.ID] = user
	return user, nil
}

func (t *TestDirectoryProvider) UpdateUser(ctx context.Context, userID string, updates *DirectoryUser) (*DirectoryUser, error) {
	if t.lastError != nil {
		return nil, t.lastError
	}

	user, exists := t.users[userID]
	if !exists {
		return nil, &DirectoryError{
			Type:    ErrorTypeNotFound,
			Message: "user not found",
		}
	}

	// Apply updates
	if updates.DisplayName != "" {
		user.DisplayName = updates.DisplayName
	}
	if updates.EmailAddress != "" {
		user.EmailAddress = updates.EmailAddress
	}
	if updates.Department != "" {
		user.Department = updates.Department
	}
	if updates.JobTitle != "" {
		user.JobTitle = updates.JobTitle
	}

	// Update metadata
	now := time.Now()
	user.Modified = &now

	return user, nil
}

func (t *TestDirectoryProvider) DeleteUser(ctx context.Context, userID string) error {
	if t.lastError != nil {
		return t.lastError
	}

	if _, exists := t.users[userID]; !exists {
		return &DirectoryError{
			Type:    ErrorTypeNotFound,
			Message: "user not found",
		}
	}

	delete(t.users, userID)
	return nil
}

func (t *TestDirectoryProvider) ListUsers(ctx context.Context, filters *SearchFilters) (*UserList, error) {
	if t.lastError != nil {
		return nil, t.lastError
	}

	var users []DirectoryUser
	for _, user := range t.users {
		// Apply filters
		if filters.Department != "" && user.Department != filters.Department {
			continue
		}
		if filters.Enabled != nil && user.AccountEnabled != *filters.Enabled {
			continue
		}

		users = append(users, *user)
	}

	// Apply pagination
	start := filters.Offset
	if start >= len(users) {
		return &UserList{
			Users:      []DirectoryUser{},
			TotalCount: len(users),
			HasMore:    false,
		}, nil
	}

	end := start + filters.Limit
	if end > len(users) {
		end = len(users)
	}

	return &UserList{
		Users:      users[start:end],
		TotalCount: len(users),
		HasMore:    end < len(users),
	}, nil
}

func (t *TestDirectoryProvider) GetGroup(ctx context.Context, groupID string) (*DirectoryGroup, error) {
	if t.lastError != nil {
		return nil, t.lastError
	}

	group, exists := t.groups[groupID]
	if !exists {
		return nil, &DirectoryError{
			Type:    ErrorTypeNotFound,
			Message: "group not found",
		}
	}

	return group, nil
}

func (t *TestDirectoryProvider) CreateGroup(ctx context.Context, group *DirectoryGroup) (*DirectoryGroup, error) {
	if t.lastError != nil {
		return nil, t.lastError
	}

	if group.ID == "" {
		group.ID = group.Name
	}

	now := time.Now()
	group.Created = &now
	group.Modified = &now
	group.Source = t.info.Name

	t.groups[group.ID] = group
	return group, nil
}

func (t *TestDirectoryProvider) UpdateGroup(ctx context.Context, groupID string, updates *DirectoryGroup) (*DirectoryGroup, error) {
	if t.lastError != nil {
		return nil, t.lastError
	}

	group, exists := t.groups[groupID]
	if !exists {
		return nil, &DirectoryError{
			Type:    ErrorTypeNotFound,
			Message: "group not found",
		}
	}

	if updates.DisplayName != "" {
		group.DisplayName = updates.DisplayName
	}
	if updates.Description != "" {
		group.Description = updates.Description
	}

	now := time.Now()
	group.Modified = &now

	return group, nil
}

func (t *TestDirectoryProvider) DeleteGroup(ctx context.Context, groupID string) error {
	if t.lastError != nil {
		return t.lastError
	}

	if _, exists := t.groups[groupID]; !exists {
		return &DirectoryError{
			Type:    ErrorTypeNotFound,
			Message: "group not found",
		}
	}

	delete(t.groups, groupID)
	return nil
}

func (t *TestDirectoryProvider) ListGroups(ctx context.Context, filters *SearchFilters) (*GroupList, error) {
	if t.lastError != nil {
		return nil, t.lastError
	}

	var groups []DirectoryGroup
	for _, group := range t.groups {
		groups = append(groups, *group)
	}

	return &GroupList{
		Groups:     groups,
		TotalCount: len(groups),
		HasMore:    false,
	}, nil
}

func (t *TestDirectoryProvider) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	if t.lastError != nil {
		return t.lastError
	}

	user, userExists := t.users[userID]
	group, groupExists := t.groups[groupID]

	if !userExists {
		return &DirectoryError{Type: ErrorTypeNotFound, Message: "user not found"}
	}
	if !groupExists {
		return &DirectoryError{Type: ErrorTypeNotFound, Message: "group not found"}
	}

	// Add group to user's groups
	for _, g := range user.Groups {
		if g == groupID {
			return nil // Already member
		}
	}
	user.Groups = append(user.Groups, groupID)

	// Add user to group's members
	for _, m := range group.Members {
		if m == userID {
			return nil // Already member
		}
	}
	group.Members = append(group.Members, userID)

	return nil
}

func (t *TestDirectoryProvider) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	if t.lastError != nil {
		return t.lastError
	}

	user, userExists := t.users[userID]
	group, groupExists := t.groups[groupID]

	if !userExists {
		return &DirectoryError{Type: ErrorTypeNotFound, Message: "user not found"}
	}
	if !groupExists {
		return &DirectoryError{Type: ErrorTypeNotFound, Message: "group not found"}
	}

	// Remove group from user's groups
	for i, g := range user.Groups {
		if g == groupID {
			user.Groups = append(user.Groups[:i], user.Groups[i+1:]...)
			break
		}
	}

	// Remove user from group's members
	for i, m := range group.Members {
		if m == userID {
			group.Members = append(group.Members[:i], group.Members[i+1:]...)
			break
		}
	}

	return nil
}

func (t *TestDirectoryProvider) GetUserGroups(ctx context.Context, userID string) ([]DirectoryGroup, error) {
	if t.lastError != nil {
		return nil, t.lastError
	}

	user, exists := t.users[userID]
	if !exists {
		return nil, &DirectoryError{Type: ErrorTypeNotFound, Message: "user not found"}
	}

	var groups []DirectoryGroup
	for _, groupID := range user.Groups {
		if group, exists := t.groups[groupID]; exists {
			groups = append(groups, *group)
		}
	}

	return groups, nil
}

func (t *TestDirectoryProvider) GetGroupMembers(ctx context.Context, groupID string) ([]DirectoryUser, error) {
	if t.lastError != nil {
		return nil, t.lastError
	}

	group, exists := t.groups[groupID]
	if !exists {
		return nil, &DirectoryError{Type: ErrorTypeNotFound, Message: "group not found"}
	}

	var users []DirectoryUser
	for _, userID := range group.Members {
		if user, exists := t.users[userID]; exists {
			users = append(users, *user)
		}
	}

	return users, nil
}

// Stub implementations for remaining methods
func (t *TestDirectoryProvider) GetOU(ctx context.Context, ouID string) (*OrganizationalUnit, error) {
	return nil, &DirectoryError{Type: ErrorTypeNotImplemented, Message: "OU operations not implemented in test provider"}
}

func (t *TestDirectoryProvider) CreateOU(ctx context.Context, ou *OrganizationalUnit) (*OrganizationalUnit, error) {
	return nil, &DirectoryError{Type: ErrorTypeNotImplemented, Message: "OU operations not implemented in test provider"}
}

func (t *TestDirectoryProvider) UpdateOU(ctx context.Context, ouID string, updates *OrganizationalUnit) (*OrganizationalUnit, error) {
	return nil, &DirectoryError{Type: ErrorTypeNotImplemented, Message: "OU operations not implemented in test provider"}
}

func (t *TestDirectoryProvider) DeleteOU(ctx context.Context, ouID string) error {
	return &DirectoryError{Type: ErrorTypeNotImplemented, Message: "OU operations not implemented in test provider"}
}

func (t *TestDirectoryProvider) ListOUs(ctx context.Context, filters *SearchFilters) (*OUList, error) {
	return nil, &DirectoryError{Type: ErrorTypeNotImplemented, Message: "OU operations not implemented in test provider"}
}

func (t *TestDirectoryProvider) Search(ctx context.Context, query *DirectoryQuery) (*SearchResults, error) {
	return nil, &DirectoryError{Type: ErrorTypeNotImplemented, Message: "Advanced search not implemented in test provider"}
}

func (t *TestDirectoryProvider) BulkCreateUsers(ctx context.Context, users []*DirectoryUser, options *BulkOptions) (*BulkResult, error) {
	return nil, &DirectoryError{Type: ErrorTypeNotImplemented, Message: "Bulk operations not implemented in test provider"}
}

func (t *TestDirectoryProvider) BulkUpdateUsers(ctx context.Context, updates []*UserUpdate, options *BulkOptions) (*BulkResult, error) {
	return nil, &DirectoryError{Type: ErrorTypeNotImplemented, Message: "Bulk operations not implemented in test provider"}
}

func (t *TestDirectoryProvider) BulkDeleteUsers(ctx context.Context, userIDs []string, options *BulkOptions) (*BulkResult, error) {
	return nil, &DirectoryError{Type: ErrorTypeNotImplemented, Message: "Bulk operations not implemented in test provider"}
}

func (t *TestDirectoryProvider) SyncUser(ctx context.Context, sourceUserID string, targetProvider DirectoryProvider) error {
	return &DirectoryError{Type: ErrorTypeNotImplemented, Message: "Cross-directory sync not implemented in test provider"}
}

func (t *TestDirectoryProvider) SyncGroup(ctx context.Context, sourceGroupID string, targetProvider DirectoryProvider) error {
	return &DirectoryError{Type: ErrorTypeNotImplemented, Message: "Cross-directory sync not implemented in test provider"}
}

func (t *TestDirectoryProvider) GetSchema(ctx context.Context) (*DirectorySchema, error) {
	return &DirectorySchema{
		UserSchema: ObjectSchema{
			ObjectType: DirectoryObjectTypeUser,
			RequiredFields: []SchemaField{
				{Name: "user_principal_name", Type: "string", Description: "User principal name"},
				{Name: "display_name", Type: "string", Description: "Display name"},
			},
		},
		GroupSchema: ObjectSchema{
			ObjectType: DirectoryObjectTypeGroup,
			RequiredFields: []SchemaField{
				{Name: "name", Type: "string", Description: "Group name"},
			},
		},
	}, nil
}

func (t *TestDirectoryProvider) GetCapabilities() ProviderCapabilities {
	return t.capabilities
}

func (t *TestDirectoryProvider) ValidateUser(user *DirectoryUser) error {
	if user.UserPrincipalName == "" {
		return &DirectoryError{Type: ErrorTypeValidation, Message: "user_principal_name is required"}
	}
	if user.DisplayName == "" {
		return &DirectoryError{Type: ErrorTypeValidation, Message: "display_name is required"}
	}
	return nil
}

func (t *TestDirectoryProvider) ValidateGroup(group *DirectoryGroup) error {
	if group.Name == "" {
		return &DirectoryError{Type: ErrorTypeValidation, Message: "group name is required"}
	}
	return nil
}

// Helper methods for testing
func (t *TestDirectoryProvider) SetError(err error) {
	t.lastError = err
}

func (t *TestDirectoryProvider) ClearError() {
	t.lastError = nil
}

// DirectoryError represents directory-specific errors
type DirectoryError struct {
	Type    ErrorType
	Message string
	Cause   error
}

func (e *DirectoryError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("directory error [%s]: %s, cause: %v", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("directory error [%s]: %s", e.Type, e.Message)
}

// ErrorType represents the type of directory error
type ErrorType string

const (
	ErrorTypeNotFound       ErrorType = "not_found"
	ErrorTypeAlreadyExists  ErrorType = "already_exists"
	ErrorTypeValidation     ErrorType = "validation"
	ErrorTypeAuthentication ErrorType = "authentication"
	ErrorTypeAuthorization  ErrorType = "authorization"
	ErrorTypeConnection     ErrorType = "connection"
	ErrorTypeRateLimit      ErrorType = "rate_limit"
	ErrorTypeNotImplemented ErrorType = "not_implemented"
	ErrorTypeInternalError  ErrorType = "internal_error"
)

// Test Cases

func TestProviderRegistry(t *testing.T) {
	// Clear registry for testing
	globalRegistry = &providerRegistry{
		providers: make(map[string]DirectoryProvider),
	}

	t.Run("RegisterProvider", func(t *testing.T) {
		provider := NewTestDirectoryProvider("test-ad")
		RegisterDirectoryProvider(provider)

		retrieved, err := GetDirectoryProvider("test-ad")
		require.NoError(t, err)
		assert.Equal(t, provider.GetProviderInfo().Name, retrieved.GetProviderInfo().Name)
	})

	t.Run("GetNonExistentProvider", func(t *testing.T) {
		_, err := GetDirectoryProvider("non-existent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("ListProviders", func(t *testing.T) {
		provider1 := NewTestDirectoryProvider("test-ad-1")
		provider2 := NewTestDirectoryProvider("test-entraid-1")

		RegisterDirectoryProvider(provider1)
		RegisterDirectoryProvider(provider2)

		providers := ListDirectoryProviders()
		assert.Len(t, providers, 3) // Including the one from earlier test

		names := make([]string, len(providers))
		for i, p := range providers {
			names[i] = p.Name
		}
		assert.Contains(t, names, "test-ad-1")
		assert.Contains(t, names, "test-entraid-1")
	})
}

func TestDirectoryProviderBasicOperations(t *testing.T) {
	provider := NewTestDirectoryProvider("test-provider")
	ctx := context.Background()

	t.Run("Connection Management", func(t *testing.T) {
		// Initially disconnected
		assert.False(t, provider.IsConnected(ctx))

		// Connect
		config := ProviderConfig{
			ProviderName:      "test-provider",
			ServerAddress:     "ldap://test.example.com",
			AuthMethod:        AuthMethodLDAP,
			ConnectionTimeout: 30 * time.Second,
		}

		err := provider.Connect(ctx, config)
		require.NoError(t, err)
		assert.True(t, provider.IsConnected(ctx))

		// Health check
		health, err := provider.HealthCheck(ctx)
		require.NoError(t, err)
		assert.True(t, health.IsHealthy)
		assert.Empty(t, health.Errors)

		// Disconnect
		err = provider.Disconnect(ctx)
		require.NoError(t, err)
		assert.False(t, provider.IsConnected(ctx))
	})

	t.Run("User Management", func(t *testing.T) {
		// Connect first
		config := ProviderConfig{ProviderName: "test-provider"}
		require.NoError(t, provider.Connect(ctx, config))

		// Create user
		user := &DirectoryUser{
			UserPrincipalName: "john.doe@example.com",
			DisplayName:       "John Doe",
			EmailAddress:      "john.doe@example.com",
			Department:        "IT",
			JobTitle:          "Software Engineer",
			AccountEnabled:    true,
		}

		createdUser, err := provider.CreateUser(ctx, user)
		require.NoError(t, err)
		assert.Equal(t, user.UserPrincipalName, createdUser.UserPrincipalName)
		assert.Equal(t, user.DisplayName, createdUser.DisplayName)
		assert.NotEmpty(t, createdUser.ID)
		assert.NotNil(t, createdUser.Created)
		assert.Equal(t, "test-provider", createdUser.Source)

		// Get user
		retrievedUser, err := provider.GetUser(ctx, createdUser.ID)
		require.NoError(t, err)
		assert.Equal(t, createdUser.ID, retrievedUser.ID)
		assert.Equal(t, createdUser.DisplayName, retrievedUser.DisplayName)

		// Update user
		updates := &DirectoryUser{
			DisplayName: "John Smith",
			Department:  "Engineering",
		}

		updatedUser, err := provider.UpdateUser(ctx, createdUser.ID, updates)
		require.NoError(t, err)
		assert.Equal(t, "John Smith", updatedUser.DisplayName)
		assert.Equal(t, "Engineering", updatedUser.Department)
		assert.Equal(t, user.JobTitle, updatedUser.JobTitle) // Unchanged

		// List users
		filters := &SearchFilters{
			Department: "Engineering",
			Limit:      10,
		}

		userList, err := provider.ListUsers(ctx, filters)
		require.NoError(t, err)
		assert.Len(t, userList.Users, 1)
		assert.Equal(t, updatedUser.ID, userList.Users[0].ID)

		// Delete user
		err = provider.DeleteUser(ctx, createdUser.ID)
		require.NoError(t, err)

		// Verify deletion
		_, err = provider.GetUser(ctx, createdUser.ID)
		assert.Error(t, err)

		var dirErr *DirectoryError
		assert.ErrorAs(t, err, &dirErr)
		assert.Equal(t, ErrorTypeNotFound, dirErr.Type)
	})

	t.Run("Group Management", func(t *testing.T) {
		// Create group
		group := &DirectoryGroup{
			Name:        "Engineering",
			DisplayName: "Engineering Team",
			Description: "Software engineering team",
			GroupType:   GroupTypeSecurity,
		}

		createdGroup, err := provider.CreateGroup(ctx, group)
		require.NoError(t, err)
		assert.Equal(t, group.Name, createdGroup.Name)
		assert.Equal(t, group.DisplayName, createdGroup.DisplayName)
		assert.NotEmpty(t, createdGroup.ID)

		// Get group
		retrievedGroup, err := provider.GetGroup(ctx, createdGroup.ID)
		require.NoError(t, err)
		assert.Equal(t, createdGroup.ID, retrievedGroup.ID)

		// Update group
		updates := &DirectoryGroup{
			DisplayName: "Engineering Department",
			Description: "Software engineering department",
		}

		updatedGroup, err := provider.UpdateGroup(ctx, createdGroup.ID, updates)
		require.NoError(t, err)
		assert.Equal(t, "Engineering Department", updatedGroup.DisplayName)
		assert.Equal(t, "Software engineering department", updatedGroup.Description)

		// List groups
		groupList, err := provider.ListGroups(ctx, &SearchFilters{Limit: 10})
		require.NoError(t, err)
		assert.Len(t, groupList.Groups, 1)

		// Delete group
		err = provider.DeleteGroup(ctx, createdGroup.ID)
		require.NoError(t, err)

		// Verify deletion
		_, err = provider.GetGroup(ctx, createdGroup.ID)
		assert.Error(t, err)
	})

	t.Run("Group Membership", func(t *testing.T) {
		// Create user and group
		user := &DirectoryUser{
			UserPrincipalName: "jane.doe@example.com",
			DisplayName:       "Jane Doe",
			AccountEnabled:    true,
		}
		createdUser, err := provider.CreateUser(ctx, user)
		require.NoError(t, err)

		group := &DirectoryGroup{
			Name:        "Developers",
			DisplayName: "Developers",
			GroupType:   GroupTypeSecurity,
		}
		createdGroup, err := provider.CreateGroup(ctx, group)
		require.NoError(t, err)

		// Add user to group
		err = provider.AddUserToGroup(ctx, createdUser.ID, createdGroup.ID)
		require.NoError(t, err)

		// Verify membership
		userGroups, err := provider.GetUserGroups(ctx, createdUser.ID)
		require.NoError(t, err)
		assert.Len(t, userGroups, 1)
		assert.Equal(t, createdGroup.ID, userGroups[0].ID)

		groupMembers, err := provider.GetGroupMembers(ctx, createdGroup.ID)
		require.NoError(t, err)
		assert.Len(t, groupMembers, 1)
		assert.Equal(t, createdUser.ID, groupMembers[0].ID)

		// Remove user from group
		err = provider.RemoveUserFromGroup(ctx, createdUser.ID, createdGroup.ID)
		require.NoError(t, err)

		// Verify removal
		userGroups, err = provider.GetUserGroups(ctx, createdUser.ID)
		require.NoError(t, err)
		assert.Empty(t, userGroups)

		groupMembers, err = provider.GetGroupMembers(ctx, createdGroup.ID)
		require.NoError(t, err)
		assert.Empty(t, groupMembers)
	})
}

func TestDirectoryProviderErrorHandling(t *testing.T) {
	provider := NewTestDirectoryProvider("test-error-provider")
	ctx := context.Background()

	t.Run("Connection Errors", func(t *testing.T) {
		// Set error condition
		testError := &DirectoryError{
			Type:    ErrorTypeConnection,
			Message: "connection refused",
		}
		provider.SetError(testError)

		config := ProviderConfig{ProviderName: "test-error-provider"}
		err := provider.Connect(ctx, config)
		assert.Error(t, err)
		assert.Equal(t, testError, err)

		// Clear error and retry
		provider.ClearError()
		err = provider.Connect(ctx, config)
		require.NoError(t, err)
	})

	t.Run("Not Found Errors", func(t *testing.T) {
		config := ProviderConfig{ProviderName: "test-error-provider"}
		require.NoError(t, provider.Connect(ctx, config))

		// Try to get non-existent user
		_, err := provider.GetUser(ctx, "non-existent-user")
		assert.Error(t, err)

		var dirErr *DirectoryError
		assert.ErrorAs(t, err, &dirErr)
		assert.Equal(t, ErrorTypeNotFound, dirErr.Type)
	})

	t.Run("Validation Errors", func(t *testing.T) {
		// Test user validation
		invalidUser := &DirectoryUser{
			// Missing required fields
			EmailAddress: "test@example.com",
		}

		err := provider.ValidateUser(invalidUser)
		assert.Error(t, err)

		var dirErr *DirectoryError
		assert.ErrorAs(t, err, &dirErr)
		assert.Equal(t, ErrorTypeValidation, dirErr.Type)
		assert.Contains(t, err.Error(), "user_principal_name is required")

		// Test group validation
		invalidGroup := &DirectoryGroup{
			// Missing required fields
			Description: "Test group",
		}

		err = provider.ValidateGroup(invalidGroup)
		assert.Error(t, err)
		assert.ErrorAs(t, err, &dirErr)
		assert.Equal(t, ErrorTypeValidation, dirErr.Type)
		assert.Contains(t, err.Error(), "group name is required")
	})
}

func TestDirectoryProviderCapabilities(t *testing.T) {
	provider := NewTestDirectoryProvider("capabilities-test")

	t.Run("Provider Info", func(t *testing.T) {
		info := provider.GetProviderInfo()
		assert.Equal(t, "capabilities-test", info.Name)
		assert.Equal(t, "Test capabilities-test", info.DisplayName)
		assert.Equal(t, "1.0.0", info.Version)
		assert.Contains(t, info.SupportedTypes, DirectoryObjectTypeUser)
		assert.Contains(t, info.SupportedTypes, DirectoryObjectTypeGroup)
		assert.Contains(t, info.SupportedTypes, DirectoryObjectTypeOU)
	})

	t.Run("Capabilities", func(t *testing.T) {
		caps := provider.GetCapabilities()
		assert.True(t, caps.SupportsUserManagement)
		assert.True(t, caps.SupportsGroupManagement)
		assert.True(t, caps.SupportsOUManagement)
		assert.True(t, caps.SupportsBulkOperations)
		assert.True(t, caps.SupportsAdvancedSearch)
		assert.Contains(t, caps.SupportedAuthMethods, AuthMethodLDAP)
		assert.Contains(t, caps.SupportedAuthMethods, AuthMethodOAuth2)
		assert.Equal(t, 1000, caps.MaxSearchResults)
	})

	t.Run("Schema", func(t *testing.T) {
		ctx := context.Background()
		schema, err := provider.GetSchema(ctx)
		require.NoError(t, err)

		assert.Equal(t, DirectoryObjectTypeUser, schema.UserSchema.ObjectType)
		assert.Len(t, schema.UserSchema.RequiredFields, 2)
		assert.Equal(t, "user_principal_name", schema.UserSchema.RequiredFields[0].Name)
		assert.Equal(t, "display_name", schema.UserSchema.RequiredFields[1].Name)

		assert.Equal(t, DirectoryObjectTypeGroup, schema.GroupSchema.ObjectType)
		assert.Len(t, schema.GroupSchema.RequiredFields, 1)
		assert.Equal(t, "name", schema.GroupSchema.RequiredFields[0].Name)
	})
}

func TestCreateDirectoryProviderFromConfig(t *testing.T) {
	// Clear and setup registry
	globalRegistry = &providerRegistry{
		providers: make(map[string]DirectoryProvider),
	}

	testProvider := NewTestDirectoryProvider("config-test")
	RegisterDirectoryProvider(testProvider)

	t.Run("ValidProvider", func(t *testing.T) {
		config := ProviderConfig{
			ProviderName:      "config-test",
			ServerAddress:     "ldap://test.example.com",
			AuthMethod:        AuthMethodLDAP,
			ConnectionTimeout: 30 * time.Second,
		}

		provider, err := CreateDirectoryProviderFromConfig("config-test", config)
		require.NoError(t, err)
		assert.Equal(t, "config-test", provider.GetProviderInfo().Name)
		assert.True(t, provider.IsConnected(context.Background()))
	})

	t.Run("InvalidProvider", func(t *testing.T) {
		config := ProviderConfig{
			ProviderName: "non-existent",
		}

		_, err := CreateDirectoryProviderFromConfig("non-existent", config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not available")
		assert.Contains(t, err.Error(), "Available providers:")
	})
}

// Benchmark tests for performance validation
func BenchmarkUserOperations(b *testing.B) {
	provider := NewTestDirectoryProvider("benchmark-test")
	ctx := context.Background()

	config := ProviderConfig{ProviderName: "benchmark-test"}
	require.NoError(b, provider.Connect(ctx, config))

	b.Run("CreateUser", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			user := &DirectoryUser{
				UserPrincipalName: fmt.Sprintf("user%d@example.com", i),
				DisplayName:       fmt.Sprintf("User %d", i),
				AccountEnabled:    true,
			}

			_, err := provider.CreateUser(ctx, user)
			require.NoError(b, err)
		}
	})

	b.Run("GetUser", func(b *testing.B) {
		// Pre-create some users
		for i := 0; i < 100; i++ {
			user := &DirectoryUser{
				UserPrincipalName: fmt.Sprintf("getuser%d@example.com", i),
				DisplayName:       fmt.Sprintf("Get User %d", i),
				AccountEnabled:    true,
			}
			_, err := provider.CreateUser(ctx, user)
			require.NoError(b, err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			userID := fmt.Sprintf("getuser%d@example.com", i%100)
			_, err := provider.GetUser(ctx, userID)
			require.NoError(b, err)
		}
	})
}
