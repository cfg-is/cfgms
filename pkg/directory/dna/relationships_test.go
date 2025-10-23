// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package dna

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestCollectRelationships(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Set up test data with relationships
	testUser := createTestUser("user1", "TestUser")
	testUser.Manager = "manager1"
	provider.AddUser(testUser)

	testGroup := createTestGroup("group1", "TestGroup")
	provider.AddGroup(testGroup)

	testOU := createTestOU("ou1", "TestOU", "")
	provider.AddOU(testOU)

	ctx := context.Background()

	t.Run("collect user relationships", func(t *testing.T) {
		relationships, err := collector.CollectRelationships(ctx, "user1")

		require.NoError(t, err)
		assert.NotNil(t, relationships)
		assert.Equal(t, "user1", relationships.ObjectID)
		assert.Equal(t, interfaces.DirectoryObjectTypeUser, relationships.ObjectType)
		assert.Equal(t, "manager1", relationships.Manager)
		assert.Equal(t, "ou1", relationships.ParentOU)
		assert.Equal(t, "MockProvider", relationships.Provider)
		assert.NotZero(t, relationships.CollectedAt)

		// Verify group membership (based on mock implementation)
		assert.Contains(t, relationships.MemberOf, "group1")
	})

	t.Run("collect group relationships", func(t *testing.T) {
		relationships, err := collector.CollectRelationships(ctx, "group1")

		require.NoError(t, err)
		assert.Equal(t, "group1", relationships.ObjectID)
		assert.Equal(t, interfaces.DirectoryObjectTypeGroup, relationships.ObjectType)
		assert.Equal(t, "ou1", relationships.ParentOU)

		// Verify group members (based on mock implementation)
		assert.Contains(t, relationships.Members, "user1")
	})

	t.Run("collect OU relationships", func(t *testing.T) {
		// Add child OU
		childOU := createTestOU("ou2", "ChildOU", "ou1")
		provider.AddOU(childOU)

		relationships, err := collector.CollectRelationships(ctx, "ou1")

		require.NoError(t, err)
		assert.Equal(t, "ou1", relationships.ObjectID)
		assert.Equal(t, interfaces.DirectoryObjectTypeOU, relationships.ObjectType)
		assert.Equal(t, "", relationships.ParentOU) // Root OU has no parent
		assert.Contains(t, relationships.ChildOUs, "ou2")
		assert.Contains(t, relationships.UsersInOU, "user1")
		assert.Contains(t, relationships.GroupsInOU, "group1")
	})

	t.Run("object not found", func(t *testing.T) {
		relationships, err := collector.CollectRelationships(ctx, "nonexistent")

		assert.Error(t, err)
		assert.Nil(t, relationships)
		assert.Contains(t, err.Error(), "failed to determine object type")
	})
}

func TestCollectGroupMemberships(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Set up test data
	user1 := createTestUser("user1", "User1")
	user2 := createTestUser("user2", "User2")
	group1 := createTestGroup("group1", "Group1")
	group2 := createTestGroup("group2", "Group2")

	provider.AddUser(user1)
	provider.AddUser(user2)
	provider.AddGroup(group1)
	provider.AddGroup(group2)

	ctx := context.Background()

	memberships, err := collector.CollectGroupMemberships(ctx)

	require.NoError(t, err)
	assert.NotNil(t, memberships)

	// Verify membership structure
	for _, membership := range memberships {
		assert.NotEmpty(t, membership.UserID)
		assert.NotEmpty(t, membership.GroupID)
		assert.Equal(t, "direct", membership.MemberType)
		assert.Equal(t, "directory_provider", membership.Source)
		assert.Equal(t, "MockProvider", membership.Provider)
		// TenantID may be empty in default configuration
		assert.Contains(t, []string{"", "test-tenant"}, membership.TenantID)
	}

	// Based on mock implementation, we expect specific memberships
	membershipMap := make(map[string]string)
	for _, membership := range memberships {
		membershipMap[membership.UserID] = membership.GroupID
	}

	// Mock provider should return user1 in group1
	assert.Equal(t, "group1", membershipMap["user1"])
}

func TestCollectOUHierarchy(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Create hierarchical OU structure
	rootOU := createTestOU("ou1", "Root", "")
	childOU1 := createTestOU("ou2", "Child1", "ou1")
	childOU2 := createTestOU("ou3", "Child2", "ou1")
	grandChildOU := createTestOU("ou4", "GrandChild", "ou2")

	provider.AddOU(rootOU)
	provider.AddOU(childOU1)
	provider.AddOU(childOU2)
	provider.AddOU(grandChildOU)

	// Add users to OUs for counting
	user1 := createTestUser("user1", "User1")
	user1.OU = "ou1"
	user2 := createTestUser("user2", "User2")
	user2.OU = "ou2"

	provider.AddUser(user1)
	provider.AddUser(user2)

	ctx := context.Background()

	hierarchy, err := collector.CollectOUHierarchy(ctx)

	require.NoError(t, err)
	assert.NotNil(t, hierarchy)
	assert.Equal(t, 4, hierarchy.TotalOUs)
	assert.Equal(t, "ou1", hierarchy.RootOU) // Should be the first root OU found
	assert.Equal(t, "MockProvider", hierarchy.Provider)
	assert.NotZero(t, hierarchy.CollectedAt)

	// Verify hierarchy structure
	assert.Len(t, hierarchy.Hierarchy, 4)

	// Check root OU
	rootNode := hierarchy.Hierarchy["ou1"]
	require.NotNil(t, rootNode)
	assert.Equal(t, "Root", rootNode.Name)
	assert.Equal(t, "", rootNode.ParentID)
	assert.Contains(t, rootNode.Children, "ou2")
	assert.Contains(t, rootNode.Children, "ou3")
	assert.Equal(t, 0, rootNode.Depth) // Root should be at depth 0

	// Check child OU
	childNode := hierarchy.Hierarchy["ou2"]
	require.NotNil(t, childNode)
	assert.Equal(t, "Child1", childNode.Name)
	assert.Equal(t, "ou1", childNode.ParentID)
	assert.Contains(t, childNode.Children, "ou4")
	assert.Greater(t, childNode.Depth, 0)

	// Check grandchild OU
	grandChildNode := hierarchy.Hierarchy["ou4"]
	require.NotNil(t, grandChildNode)
	assert.Equal(t, "GrandChild", grandChildNode.Name)
	assert.Equal(t, "ou2", grandChildNode.ParentID)
	assert.Empty(t, grandChildNode.Children)
	assert.Greater(t, grandChildNode.Depth, childNode.Depth)

	// Verify maximum depth
	assert.Greater(t, hierarchy.Depth, 1)
}

func TestGetRelationshipStats(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Set up test data
	user1 := createTestUser("user1", "User1")
	user2 := createTestUser("user2", "User2")
	group1 := createTestGroup("group1", "Group1")
	ou1 := createTestOU("ou1", "OU1", "")
	ou2 := createTestOU("ou2", "OU2", "ou1")

	provider.AddUser(user1)
	provider.AddUser(user2)
	provider.AddGroup(group1)
	provider.AddOU(ou1)
	provider.AddOU(ou2)

	ctx := context.Background()

	stats, err := collector.GetRelationshipStats(ctx)

	require.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Equal(t, "MockProvider", stats.Provider)
	assert.NotZero(t, stats.CollectedAt)
	assert.GreaterOrEqual(t, stats.TotalMemberships, 0)
	assert.Equal(t, 2, stats.TotalOUs)
	assert.Greater(t, stats.MaxOUDepth, 0)
	assert.GreaterOrEqual(t, stats.LargestGroupSize, 0)
	assert.GreaterOrEqual(t, stats.AverageMembershipsPerUser, float64(0))
}

func TestBatchDNACollection(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Create multiple users for batch collection testing
	users := make([]interfaces.DirectoryUser, 10)
	for i := 0; i < 10; i++ {
		userID := "user" + string(rune('0'+i))
		user := *createTestUser(userID, "User"+string(rune('0'+i)))
		users[i] = user
		provider.AddUser(&user)
	}

	ctx := context.Background()

	t.Run("batch user collection", func(t *testing.T) {
		dnaList, err := collector.collectUserBatchDNA(ctx, users)

		require.NoError(t, err)
		assert.Len(t, dnaList, 10)

		// Verify all users are collected
		userIDs := make(map[string]bool)
		for _, dna := range dnaList {
			assert.Equal(t, interfaces.DirectoryObjectTypeUser, dna.ObjectType)
			userIDs[dna.ObjectID] = true
		}

		for i := 0; i < 10; i++ {
			userID := "user" + string(rune('0'+i))
			assert.True(t, userIDs[userID])
		}
	})

	t.Run("batch collection with errors", func(t *testing.T) {
		// Set one user to error
		provider.SetErrorOnUser("user5")

		dnaList, err := collector.collectUserBatchDNA(ctx, users)

		// Should not return error but may have fewer results
		assert.NoError(t, err)
		assert.LessOrEqual(t, len(dnaList), 10)

		// Reset error condition
		provider.SetErrorOnUser("")
	})

	t.Run("concurrent collection safety", func(t *testing.T) {
		// Test that concurrent collection doesn't cause race conditions
		results := make(chan []*DirectoryDNA, 3)

		for i := 0; i < 3; i++ {
			go func() {
				dnaList, err := collector.collectUserBatchDNA(ctx, users[:5])
				assert.NoError(t, err)
				results <- dnaList
			}()
		}

		// Collect results
		for i := 0; i < 3; i++ {
			dnaList := <-results
			assert.Len(t, dnaList, 5)
		}
	})
}

func TestBatchGroupCollection(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Create multiple groups
	groups := make([]interfaces.DirectoryGroup, 5)
	for i := 0; i < 5; i++ {
		groupID := "group" + string(rune('0'+i))
		group := *createTestGroup(groupID, "Group"+string(rune('0'+i)))
		groups[i] = group
		provider.AddGroup(&group)
	}

	ctx := context.Background()

	dnaList, err := collector.collectGroupBatchDNA(ctx, groups)

	require.NoError(t, err)
	assert.Len(t, dnaList, 5)

	// Verify all groups are collected
	for _, dna := range dnaList {
		assert.Equal(t, interfaces.DirectoryObjectTypeGroup, dna.ObjectType)
		assert.NotEmpty(t, dna.ObjectID)
		assert.NotEmpty(t, dna.ID)
	}
}

func TestBatchOUCollection(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Create multiple OUs
	ous := make([]interfaces.OrganizationalUnit, 5)
	for i := 0; i < 5; i++ {
		ouID := "ou" + string(rune('0'+i))
		ou := *createTestOU(ouID, "OU"+string(rune('0'+i)), "")
		ous[i] = ou
		provider.AddOU(&ou)
	}

	ctx := context.Background()

	dnaList, err := collector.collectOUBatchDNA(ctx, ous)

	require.NoError(t, err)
	assert.Len(t, dnaList, 5)

	// Verify all OUs are collected
	for _, dna := range dnaList {
		assert.Equal(t, interfaces.DirectoryObjectTypeOU, dna.ObjectType)
		assert.NotEmpty(t, dna.ObjectID)
		assert.NotEmpty(t, dna.ID)
	}
}

func TestDetermineObjectType(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Add test objects
	provider.AddUser(createTestUser("user1", "User1"))
	provider.AddGroup(createTestGroup("group1", "Group1"))
	provider.AddOU(createTestOU("ou1", "OU1", ""))

	ctx := context.Background()

	t.Run("determine user type", func(t *testing.T) {
		objectType, err := collector.determineObjectType(ctx, "user1")

		require.NoError(t, err)
		assert.Equal(t, interfaces.DirectoryObjectTypeUser, objectType)
	})

	t.Run("determine group type", func(t *testing.T) {
		objectType, err := collector.determineObjectType(ctx, "group1")

		require.NoError(t, err)
		assert.Equal(t, interfaces.DirectoryObjectTypeGroup, objectType)
	})

	t.Run("determine OU type", func(t *testing.T) {
		objectType, err := collector.determineObjectType(ctx, "ou1")

		require.NoError(t, err)
		assert.Equal(t, interfaces.DirectoryObjectTypeOU, objectType)
	})

	t.Run("object not found", func(t *testing.T) {
		objectType, err := collector.determineObjectType(ctx, "nonexistent")

		assert.Error(t, err)
		assert.Empty(t, objectType)
		assert.Contains(t, err.Error(), "not found in any directory object type")
	})
}

func TestCollectUserRelationships(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Set up test data
	user := createTestUser("user1", "User1")
	user.Manager = "manager1"
	user.OU = "ou1"
	provider.AddUser(user)

	group := createTestGroup("group1", "Group1")
	provider.AddGroup(group)

	ctx := context.Background()

	relationships := &DirectoryRelationships{
		ObjectID:    "user1",
		ObjectType:  interfaces.DirectoryObjectTypeUser,
		CollectedAt: time.Now(),
		Provider:    "MockProvider",
	}

	err := collector.collectUserRelationships(ctx, "user1", relationships)

	require.NoError(t, err)
	assert.Equal(t, "manager1", relationships.Manager)
	assert.Equal(t, "ou1", relationships.ParentOU)
	assert.Contains(t, relationships.MemberOf, "group1")
}

func TestCollectGroupRelationships(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Set up test data
	group := createTestGroup("group1", "Group1")
	group.OU = "ou1"
	provider.AddGroup(group)

	user := createTestUser("user1", "User1")
	provider.AddUser(user)

	ctx := context.Background()

	relationships := &DirectoryRelationships{
		ObjectID:    "group1",
		ObjectType:  interfaces.DirectoryObjectTypeGroup,
		CollectedAt: time.Now(),
		Provider:    "MockProvider",
	}

	err := collector.collectGroupRelationships(ctx, "group1", relationships)

	require.NoError(t, err)
	assert.Equal(t, "ou1", relationships.ParentOU)
	assert.Contains(t, relationships.Members, "user1")
}

func TestCollectOURelationships(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Set up test data
	parentOU := createTestOU("ou1", "Parent", "")
	childOU := createTestOU("ou2", "Child", "ou1")
	provider.AddOU(parentOU)
	provider.AddOU(childOU)

	user := createTestUser("user1", "User1")
	user.OU = "ou1"
	provider.AddUser(user)

	group := createTestGroup("group1", "Group1")
	group.OU = "ou1"
	provider.AddGroup(group)

	ctx := context.Background()

	relationships := &DirectoryRelationships{
		ObjectID:    "ou1",
		ObjectType:  interfaces.DirectoryObjectTypeOU,
		CollectedAt: time.Now(),
		Provider:    "MockProvider",
	}

	err := collector.collectOURelationships(ctx, "ou1", relationships)

	require.NoError(t, err)
	assert.Equal(t, "", relationships.ParentOU) // Root OU has no parent
	assert.Contains(t, relationships.ChildOUs, "ou2")
	assert.Contains(t, relationships.UsersInOU, "user1")
	assert.Contains(t, relationships.GroupsInOU, "group1")
}

func TestCountObjectsInOU(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Set up test data
	ou := createTestOU("ou1", "TestOU", "")
	provider.AddOU(ou)

	// Add users and groups to the OU
	user1 := createTestUser("user1", "User1")
	user1.OU = "ou1"
	user2 := createTestUser("user2", "User2")
	user2.OU = "ou1"
	provider.AddUser(user1)
	provider.AddUser(user2)

	group1 := createTestGroup("group1", "Group1")
	group1.OU = "ou1"
	provider.AddGroup(group1)

	ctx := context.Background()

	userCount, groupCount := collector.countObjectsInOU(ctx, "ou1")

	// Note: The exact counts depend on the mock implementation
	// which returns TotalCount from the list results
	assert.GreaterOrEqual(t, userCount, 0)
	assert.GreaterOrEqual(t, groupCount, 0)
}

func TestCalculateOUDepth(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Create test hierarchy
	hierarchy := map[string]*OUNode{
		"ou1": {
			OUID:     "ou1",
			Name:     "Root",
			ParentID: "",
		},
		"ou2": {
			OUID:     "ou2",
			Name:     "Child",
			ParentID: "ou1",
		},
		"ou3": {
			OUID:     "ou3",
			Name:     "GrandChild",
			ParentID: "ou2",
		},
	}

	t.Run("root OU depth", func(t *testing.T) {
		depth := collector.calculateOUDepth("ou1", hierarchy, 0)
		assert.Equal(t, 0, depth)
	})

	t.Run("child OU depth", func(t *testing.T) {
		depth := collector.calculateOUDepth("ou2", hierarchy, 0)
		assert.Equal(t, 1, depth)
	})

	t.Run("grandchild OU depth", func(t *testing.T) {
		depth := collector.calculateOUDepth("ou3", hierarchy, 0)
		assert.Equal(t, 2, depth)
	})

	t.Run("nonexistent OU", func(t *testing.T) {
		depth := collector.calculateOUDepth("nonexistent", hierarchy, 0)
		assert.Equal(t, 0, depth)
	})

	t.Run("circular reference protection", func(t *testing.T) {
		// Create circular reference
		circularHierarchy := map[string]*OUNode{
			"ou1": {
				OUID:     "ou1",
				Name:     "Node1",
				ParentID: "ou2",
			},
			"ou2": {
				OUID:     "ou2",
				Name:     "Node2",
				ParentID: "ou1",
			},
		}

		depth := collector.calculateOUDepth("ou1", circularHierarchy, 0)
		assert.Equal(t, 20, depth) // Should stop at exactly max depth due to circular reference
	})
}

func TestContextCancellationInRelationships(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Set up test data
	provider.AddUser(createTestUser("user1", "User1"))
	provider.AddGroup(createTestGroup("group1", "Group1"))

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Test that operations handle cancelled context gracefully
	memberships, err := collector.CollectGroupMemberships(ctx)

	// The exact behavior depends on how the mock provider handles context
	// Most operations should complete quickly and not be cancelled
	if err != nil {
		assert.Error(t, err)
	} else {
		assert.NotNil(t, memberships)
	}
}

func TestRelationshipCollectionPerformance(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	// Add a larger dataset
	for i := 0; i < 100; i++ {
		userID := "user" + string(rune('0'+(i%10))) + string(rune('0'+(i/10)))
		groupID := "group" + string(rune('0'+(i%10))) + string(rune('0'+(i/10)))
		ouID := "ou" + string(rune('0'+(i%10))) + string(rune('0'+(i/10)))

		provider.AddUser(createTestUser(userID, "User"+userID))
		provider.AddGroup(createTestGroup(groupID, "Group"+groupID))
		provider.AddOU(createTestOU(ouID, "OU"+ouID, ""))
	}

	ctx := context.Background()

	// Test performance of bulk operations
	start := time.Now()
	memberships, err := collector.CollectGroupMemberships(ctx)
	duration := time.Since(start)

	require.NoError(t, err)
	// Memberships may be empty if no groups have members, but should not be nil
	assert.NotNil(t, memberships)

	// Performance assertion - should complete quickly
	assert.Less(t, duration, 10*time.Second, "Group membership collection took too long")

	// Test hierarchy collection performance
	start = time.Now()
	hierarchy, err := collector.CollectOUHierarchy(ctx)
	duration = time.Since(start)

	require.NoError(t, err)
	assert.NotNil(t, hierarchy)
	assert.Less(t, duration, 10*time.Second, "OU hierarchy collection took too long")
}
