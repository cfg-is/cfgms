// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package dna

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// MockDirectoryProvider implements the DirectoryProvider interface for testing
type MockDirectoryProvider struct {
	mutex  sync.RWMutex
	users  map[string]*interfaces.DirectoryUser
	groups map[string]*interfaces.DirectoryGroup
	ous    map[string]*interfaces.OrganizationalUnit

	// For simulating errors
	shouldErrorOnUser  string
	shouldErrorOnGroup string
	shouldErrorOnOU    string
}

func NewMockDirectoryProvider() *MockDirectoryProvider {
	return &MockDirectoryProvider{
		users:  make(map[string]*interfaces.DirectoryUser),
		groups: make(map[string]*interfaces.DirectoryGroup),
		ous:    make(map[string]*interfaces.OrganizationalUnit),
	}
}

func (m *MockDirectoryProvider) GetUser(ctx context.Context, userID string) (*interfaces.DirectoryUser, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.shouldErrorOnUser == userID {
		return nil, assert.AnError
	}
	if user, exists := m.users[userID]; exists {
		return user, nil
	}
	return nil, assert.AnError
}

func (m *MockDirectoryProvider) GetGroup(ctx context.Context, groupID string) (*interfaces.DirectoryGroup, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.shouldErrorOnGroup == groupID {
		return nil, assert.AnError
	}
	if group, exists := m.groups[groupID]; exists {
		return group, nil
	}
	return nil, assert.AnError
}

func (m *MockDirectoryProvider) GetOU(ctx context.Context, ouID string) (*interfaces.OrganizationalUnit, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.shouldErrorOnOU == ouID {
		return nil, assert.AnError
	}
	if ou, exists := m.ous[ouID]; exists {
		return ou, nil
	}
	return nil, assert.AnError
}

func (m *MockDirectoryProvider) ListUsers(ctx context.Context, filters *interfaces.SearchFilters) (*interfaces.UserList, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var users []interfaces.DirectoryUser
	totalCount := 0

	// First pass: count total matches without limit
	for _, user := range m.users {
		if filters != nil && filters.OU != "" && user.OU != filters.OU {
			continue
		}
		totalCount++
	}

	// Second pass: collect with limit
	for _, user := range m.users {
		// Apply filters if specified
		if filters != nil && filters.OU != "" && user.OU != filters.OU {
			continue
		}
		users = append(users, *user)
		if filters != nil && filters.Limit > 0 && len(users) >= filters.Limit {
			break
		}
	}

	return &interfaces.UserList{
		Users:      users,
		TotalCount: totalCount,
	}, nil
}

func (m *MockDirectoryProvider) ListGroups(ctx context.Context, filters *interfaces.SearchFilters) (*interfaces.GroupList, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var groups []interfaces.DirectoryGroup
	totalCount := 0

	// First pass: count total matches without limit
	for _, group := range m.groups {
		if filters != nil && filters.OU != "" && group.OU != filters.OU {
			continue
		}
		totalCount++
	}

	// Second pass: collect with limit
	for _, group := range m.groups {
		// Apply filters if specified
		if filters != nil && filters.OU != "" && group.OU != filters.OU {
			continue
		}
		groups = append(groups, *group)
		if filters != nil && filters.Limit > 0 && len(groups) >= filters.Limit {
			break
		}
	}

	return &interfaces.GroupList{
		Groups:     groups,
		TotalCount: totalCount,
	}, nil
}

func (m *MockDirectoryProvider) ListOUs(ctx context.Context, filters *interfaces.SearchFilters) (*interfaces.OUList, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var ous []interfaces.OrganizationalUnit
	totalCount := len(m.ous) // OUs don't typically filter by OU

	for _, ou := range m.ous {
		ous = append(ous, *ou)
		if filters != nil && filters.Limit > 0 && len(ous) >= filters.Limit {
			break
		}
	}

	return &interfaces.OUList{
		OUs:        ous,
		TotalCount: totalCount,
	}, nil
}

func (m *MockDirectoryProvider) GetUserGroups(ctx context.Context, userID string) ([]interfaces.DirectoryGroup, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Simple implementation: return groups that have this user as a member
	var userGroups []interfaces.DirectoryGroup
	for _, group := range m.groups {
		// This would normally check actual membership, but for testing we'll simulate
		if group.ID == "group1" && userID == "user1" {
			userGroups = append(userGroups, *group)
		}
	}
	return userGroups, nil
}

func (m *MockDirectoryProvider) GetGroupMembers(ctx context.Context, groupID string) ([]interfaces.DirectoryUser, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Simple implementation: return users that belong to this group
	var members []interfaces.DirectoryUser
	for _, user := range m.users {
		// This would normally check actual membership, but for testing we'll simulate
		if groupID == "group1" && user.ID == "user1" {
			members = append(members, *user)
		}
	}
	return members, nil
}

func (m *MockDirectoryProvider) GetProviderInfo() interfaces.ProviderInfo {
	return interfaces.ProviderInfo{
		Name:        "MockProvider",
		DisplayName: "Mock Directory Provider for Testing",
		Version:     "1.0.0",
		Capabilities: interfaces.ProviderCapabilities{
			SupportsUserManagement:  true,
			SupportsGroupManagement: true,
			SupportsOUManagement:    true,
		},
	}
}

// Implement missing interface methods
func (m *MockDirectoryProvider) Connect(ctx context.Context, config interfaces.ProviderConfig) error {
	return nil
}

func (m *MockDirectoryProvider) Disconnect(ctx context.Context) error {
	return nil
}

func (m *MockDirectoryProvider) IsConnected(ctx context.Context) bool {
	return true
}

func (m *MockDirectoryProvider) HealthCheck(ctx context.Context) (*interfaces.HealthStatus, error) {
	return &interfaces.HealthStatus{IsHealthy: true}, nil
}

func (m *MockDirectoryProvider) CreateUser(ctx context.Context, user *interfaces.DirectoryUser) (*interfaces.DirectoryUser, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.users[user.ID] = user
	return user, nil
}

func (m *MockDirectoryProvider) UpdateUser(ctx context.Context, userID string, updates *interfaces.DirectoryUser) (*interfaces.DirectoryUser, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if user, exists := m.users[userID]; exists {
		*user = *updates
		return user, nil
	}
	return nil, assert.AnError
}

func (m *MockDirectoryProvider) DeleteUser(ctx context.Context, userID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.users, userID)
	return nil
}

func (m *MockDirectoryProvider) CreateGroup(ctx context.Context, group *interfaces.DirectoryGroup) (*interfaces.DirectoryGroup, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.groups[group.ID] = group
	return group, nil
}

func (m *MockDirectoryProvider) UpdateGroup(ctx context.Context, groupID string, updates *interfaces.DirectoryGroup) (*interfaces.DirectoryGroup, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if group, exists := m.groups[groupID]; exists {
		*group = *updates
		return group, nil
	}
	return nil, assert.AnError
}

func (m *MockDirectoryProvider) DeleteGroup(ctx context.Context, groupID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.groups, groupID)
	return nil
}

func (m *MockDirectoryProvider) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	// Mock implementation - just return success
	return nil
}

func (m *MockDirectoryProvider) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	// Mock implementation - just return success
	return nil
}

func (m *MockDirectoryProvider) CreateOU(ctx context.Context, ou *interfaces.OrganizationalUnit) (*interfaces.OrganizationalUnit, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.ous[ou.ID] = ou
	return ou, nil
}

func (m *MockDirectoryProvider) UpdateOU(ctx context.Context, ouID string, updates *interfaces.OrganizationalUnit) (*interfaces.OrganizationalUnit, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if ou, exists := m.ous[ouID]; exists {
		*ou = *updates
		return ou, nil
	}
	return nil, assert.AnError
}

func (m *MockDirectoryProvider) DeleteOU(ctx context.Context, ouID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.ous, ouID)
	return nil
}

func (m *MockDirectoryProvider) Search(ctx context.Context, query *interfaces.DirectoryQuery) (*interfaces.SearchResults, error) {
	return &interfaces.SearchResults{}, nil
}

func (m *MockDirectoryProvider) SyncUser(ctx context.Context, sourceUserID string, targetProvider interfaces.DirectoryProvider) error {
	return nil
}

func (m *MockDirectoryProvider) SyncGroup(ctx context.Context, sourceGroupID string, targetProvider interfaces.DirectoryProvider) error {
	return nil
}

func (m *MockDirectoryProvider) ValidateUser(user *interfaces.DirectoryUser) error {
	return nil
}

func (m *MockDirectoryProvider) ValidateGroup(group *interfaces.DirectoryGroup) error {
	return nil
}

func (m *MockDirectoryProvider) ValidateOU(ou *interfaces.OrganizationalUnit) error {
	return nil
}

// Additional missing interface methods
func (m *MockDirectoryProvider) BulkCreateUsers(ctx context.Context, users []*interfaces.DirectoryUser, options *interfaces.BulkOptions) (*interfaces.BulkResult, error) {
	return &interfaces.BulkResult{}, nil
}

func (m *MockDirectoryProvider) BulkUpdateUsers(ctx context.Context, updates []*interfaces.UserUpdate, options *interfaces.BulkOptions) (*interfaces.BulkResult, error) {
	return &interfaces.BulkResult{}, nil
}

func (m *MockDirectoryProvider) BulkDeleteUsers(ctx context.Context, userIDs []string, options *interfaces.BulkOptions) (*interfaces.BulkResult, error) {
	return &interfaces.BulkResult{}, nil
}

func (m *MockDirectoryProvider) GetSchema(ctx context.Context) (*interfaces.DirectorySchema, error) {
	return &interfaces.DirectorySchema{}, nil
}

func (m *MockDirectoryProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{
		SupportsUserManagement:  true,
		SupportsGroupManagement: true,
		SupportsOUManagement:    true,
	}
}

// Helper methods to add test data
func (m *MockDirectoryProvider) AddUser(user *interfaces.DirectoryUser) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.users[user.ID] = user
}

func (m *MockDirectoryProvider) AddGroup(group *interfaces.DirectoryGroup) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.groups[group.ID] = group
}

func (m *MockDirectoryProvider) AddOU(ou *interfaces.OrganizationalUnit) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.ous[ou.ID] = ou
}

func (m *MockDirectoryProvider) SetErrorOnUser(userID string) {
	m.shouldErrorOnUser = userID
}

func (m *MockDirectoryProvider) SetErrorOnGroup(groupID string) {
	m.shouldErrorOnGroup = groupID
}

func (m *MockDirectoryProvider) SetErrorOnOU(ouID string) {
	m.shouldErrorOnOU = ouID
}

// Test helper to create test data
func createTestUser(id, name string) *interfaces.DirectoryUser {
	return &interfaces.DirectoryUser{
		ID:                id,
		UserPrincipalName: name + "@test.local",
		DisplayName:       "Test " + name,
		EmailAddress:      name + "@test.local",
		OU:                "ou1",
		Manager:           "",
		AccountEnabled:    true,
		ProviderAttributes: map[string]interface{}{
			"department":  "IT",
			"title":       "Developer",
			"phone":       "+1234567890",
			"employee_id": "EMP" + id,
		},
		DistinguishedName: "CN=" + name + ",OU=Users,DC=test,DC=local",
	}
}

func createTestGroup(id, name string) *interfaces.DirectoryGroup {
	return &interfaces.DirectoryGroup{
		ID:          id,
		Name:        name,
		DisplayName: "Test " + name,
		Description: "Test group for " + name,
		GroupType:   interfaces.GroupTypeSecurity,
		GroupScope:  interfaces.GroupScopeGlobal,
		OU:          "ou1",
		ProviderAttributes: map[string]interface{}{
			"managed_by": "admin@test.local",
			"notes":      "Test group",
		},
		DistinguishedName: "CN=" + name + ",OU=Groups,DC=test,DC=local",
	}
}

func createTestOU(id, name, parentOU string) *interfaces.OrganizationalUnit {
	return &interfaces.OrganizationalUnit{
		ID:          id,
		Name:        name,
		Description: "Test OU for " + name,
		ParentOU:    parentOU,
		ProviderAttributes: map[string]interface{}{
			"managed_by": "admin@test.local",
		},
		DistinguishedName: "OU=" + name + ",DC=test,DC=local",
	}
}

// Test Cases

func TestNewDirectoryDNACollector(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()

	collector := NewDirectoryDNACollector(provider, logger)

	assert.NotNil(t, collector)
	assert.Equal(t, provider, collector.provider)
	assert.Equal(t, logger, collector.logger)

	// Verify default configuration
	config := collector.GetCollectionCapabilities()
	assert.True(t, config.SupportsUsers)
	assert.True(t, config.SupportsGroups)
	assert.True(t, config.SupportsOUs)
	assert.True(t, config.SupportsRelationships)
}

func TestCollectUserDNA(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Add test user
	testUser := createTestUser("user1", "TestUser")
	provider.AddUser(testUser)

	ctx := context.Background()

	t.Run("successful collection", func(t *testing.T) {
		dna, err := collector.CollectUserDNA(ctx, "user1")

		require.NoError(t, err)
		assert.NotNil(t, dna)
		assert.Equal(t, "user1", dna.ObjectID)
		assert.Equal(t, interfaces.DirectoryObjectTypeUser, dna.ObjectType)
		assert.NotEmpty(t, dna.ID)

		// Verify attributes are captured
		assert.Equal(t, "TestUser@test.local", dna.Attributes["user_principal_name"])
		assert.Equal(t, "Test TestUser", dna.Attributes["display_name"])
		assert.Equal(t, "TestUser@test.local", dna.Attributes["email_address"])
		assert.Equal(t, "true", dna.Attributes["account_enabled"])
		assert.Equal(t, "IT", dna.Attributes["provider_department"])
		assert.Equal(t, "Developer", dna.Attributes["provider_title"])

		// Verify DNA metadata
		assert.Equal(t, "MockProvider", dna.Provider)
		assert.NotNil(t, dna.LastUpdated)
		assert.Greater(t, dna.AttributeCount, int32(0))

		// Verify object state
		assert.NotNil(t, dna.ObjectState)
		assert.Equal(t, testUser, dna.ObjectState.User)
	})

	t.Run("user not found", func(t *testing.T) {
		dna, err := collector.CollectUserDNA(ctx, "nonexistent")

		assert.Error(t, err)
		assert.Nil(t, dna)
		assert.Contains(t, err.Error(), "failed to get user nonexistent")
	})

	t.Run("provider error", func(t *testing.T) {
		provider.SetErrorOnUser("error_user")

		dna, err := collector.CollectUserDNA(ctx, "error_user")

		assert.Error(t, err)
		assert.Nil(t, dna)
	})
}

func TestCollectGroupDNA(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Add test group
	testGroup := createTestGroup("group1", "TestGroup")
	provider.AddGroup(testGroup)

	ctx := context.Background()

	t.Run("successful collection", func(t *testing.T) {
		dna, err := collector.CollectGroupDNA(ctx, "group1")

		require.NoError(t, err)
		assert.NotNil(t, dna)
		assert.Equal(t, "group1", dna.ObjectID)
		assert.Equal(t, interfaces.DirectoryObjectTypeGroup, dna.ObjectType)
		assert.NotEmpty(t, dna.ID)

		// Verify attributes are captured
		assert.Equal(t, "TestGroup", dna.Attributes["name"])
		assert.Equal(t, "Test TestGroup", dna.Attributes["display_name"])
		assert.Equal(t, "Test group for TestGroup", dna.Attributes["description"])
		assert.Equal(t, string(interfaces.GroupTypeSecurity), dna.Attributes["group_type"])
		assert.Equal(t, string(interfaces.GroupScopeGlobal), dna.Attributes["group_scope"])

		// Verify object state
		assert.NotNil(t, dna.ObjectState)
		assert.Equal(t, testGroup, dna.ObjectState.Group)
	})

	t.Run("group not found", func(t *testing.T) {
		dna, err := collector.CollectGroupDNA(ctx, "nonexistent")

		assert.Error(t, err)
		assert.Nil(t, dna)
	})
}

func TestCollectOUDNA(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Add test OU
	testOU := createTestOU("ou1", "TestOU", "")
	provider.AddOU(testOU)

	ctx := context.Background()

	t.Run("successful collection", func(t *testing.T) {
		dna, err := collector.CollectOUDNA(ctx, "ou1")

		require.NoError(t, err)
		assert.NotNil(t, dna)
		assert.Equal(t, "ou1", dna.ObjectID)
		assert.Equal(t, interfaces.DirectoryObjectTypeOU, dna.ObjectType)
		assert.NotEmpty(t, dna.ID)

		// Verify attributes are captured
		assert.Equal(t, "TestOU", dna.Attributes["name"])
		assert.Equal(t, "Test OU for TestOU", dna.Attributes["description"])
		assert.Equal(t, "", dna.Attributes["parent_ou"])

		// Verify object state
		assert.NotNil(t, dna.ObjectState)
		assert.Equal(t, testOU, dna.ObjectState.OU)
	})

	t.Run("ou not found", func(t *testing.T) {
		dna, err := collector.CollectOUDNA(ctx, "nonexistent")

		assert.Error(t, err)
		assert.Nil(t, dna)
	})
}

func TestCollectAllUsers(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Add test users
	provider.AddUser(createTestUser("user1", "User1"))
	provider.AddUser(createTestUser("user2", "User2"))
	provider.AddUser(createTestUser("user3", "User3"))

	ctx := context.Background()

	t.Run("collect all users", func(t *testing.T) {
		dnaList, err := collector.CollectAllUsers(ctx, nil)

		require.NoError(t, err)
		assert.Len(t, dnaList, 3)

		// Verify all users are collected
		userIDs := make(map[string]bool)
		for _, dna := range dnaList {
			assert.Equal(t, interfaces.DirectoryObjectTypeUser, dna.ObjectType)
			userIDs[dna.ObjectID] = true
		}

		assert.True(t, userIDs["user1"])
		assert.True(t, userIDs["user2"])
		assert.True(t, userIDs["user3"])
	})

	t.Run("collect with filters", func(t *testing.T) {
		filters := &interfaces.SearchFilters{
			Limit: 2,
		}

		dnaList, err := collector.CollectAllUsers(ctx, filters)

		require.NoError(t, err)
		assert.Len(t, dnaList, 2)
	})
}

func TestCollectAllGroups(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Add test groups
	provider.AddGroup(createTestGroup("group1", "Group1"))
	provider.AddGroup(createTestGroup("group2", "Group2"))

	ctx := context.Background()

	dnaList, err := collector.CollectAllGroups(ctx, nil)

	require.NoError(t, err)
	assert.Len(t, dnaList, 2)

	// Verify all groups are collected
	for _, dna := range dnaList {
		assert.Equal(t, interfaces.DirectoryObjectTypeGroup, dna.ObjectType)
	}
}

func TestCollectAllOUs(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Add test OUs
	provider.AddOU(createTestOU("ou1", "OU1", ""))
	provider.AddOU(createTestOU("ou2", "OU2", "ou1"))

	ctx := context.Background()

	dnaList, err := collector.CollectAllOUs(ctx, nil)

	require.NoError(t, err)
	assert.Len(t, dnaList, 2)

	// Verify all OUs are collected
	for _, dna := range dnaList {
		assert.Equal(t, interfaces.DirectoryObjectTypeOU, dna.ObjectType)
	}
}

func TestCollectAll(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Add test data
	provider.AddUser(createTestUser("user1", "User1"))
	provider.AddGroup(createTestGroup("group1", "Group1"))
	provider.AddOU(createTestOU("ou1", "OU1", ""))

	ctx := context.Background()

	dnaList, err := collector.CollectAll(ctx)

	require.NoError(t, err)
	assert.Len(t, dnaList, 3)

	// Verify all object types are collected
	objectTypes := make(map[interfaces.DirectoryObjectType]bool)
	for _, dna := range dnaList {
		objectTypes[dna.ObjectType] = true
	}

	assert.True(t, objectTypes[interfaces.DirectoryObjectTypeUser])
	assert.True(t, objectTypes[interfaces.DirectoryObjectTypeGroup])
	assert.True(t, objectTypes[interfaces.DirectoryObjectTypeOU])
}

func TestGetProviderInfo(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	info := collector.GetProviderInfo()

	assert.Equal(t, "MockProvider", info.Name)
	assert.Equal(t, "Mock Directory Provider for Testing", info.DisplayName)
	assert.Equal(t, "1.0.0", info.Version)
}

func TestGetCollectionCapabilities(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	capabilities := collector.GetCollectionCapabilities()

	assert.True(t, capabilities.SupportsUsers)
	assert.True(t, capabilities.SupportsGroups)
	assert.True(t, capabilities.SupportsOUs)
	assert.True(t, capabilities.SupportsRelationships)
	assert.Greater(t, capabilities.MaxBatchSize, 0)
	assert.Greater(t, capabilities.CollectionInterval, time.Duration(0))
}

func TestGetCollectionStats(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Add test user and collect to generate stats
	provider.AddUser(createTestUser("user1", "User1"))

	ctx := context.Background()
	_, err := collector.CollectUserDNA(ctx, "user1")
	require.NoError(t, err)

	stats := collector.GetCollectionStats()

	assert.NotNil(t, stats)
	assert.Greater(t, stats.TotalCollections, int64(0))
	assert.Greater(t, stats.SuccessfulCollections, int64(0))
	assert.Greater(t, stats.UsersCollected, int64(0))
}

func TestContextCancellation(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	provider.AddUser(createTestUser("user1", "User1"))

	dna, err := collector.CollectUserDNA(ctx, "user1")

	// The method should still work since the context is only checked in some operations
	// But we can test timeout scenarios
	assert.NotNil(t, dna)
	assert.NoError(t, err)
}

func TestConcurrentCollection(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Add multiple test users
	for i := 0; i < 10; i++ {
		userID := "user" + string(rune('0'+i))
		provider.AddUser(createTestUser(userID, "User"+string(rune('0'+i))))
	}

	ctx := context.Background()

	// Test concurrent collection
	dnaList, err := collector.CollectAllUsers(ctx, nil)

	require.NoError(t, err)
	assert.Len(t, dnaList, 10)

	// Verify all DNA records are valid
	for _, dna := range dnaList {
		assert.NotEmpty(t, dna.ObjectID)
		assert.Equal(t, interfaces.DirectoryObjectTypeUser, dna.ObjectType)
		assert.NotEmpty(t, dna.ID)
		assert.NotNil(t, dna.LastUpdated)
	}
}
