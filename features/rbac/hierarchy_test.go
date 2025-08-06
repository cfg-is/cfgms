package rbac

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHierarchyEngine_ComputeEffectivePermissions(t *testing.T) {
	store := memory.NewStore()
	engine := NewHierarchyEngine(store, store)
	ctx := context.Background()

	// Setup test data
	setupHierarchyTestData(t, store)

	tests := []struct {
		name                     string
		roleID                   string
		expectedDirectCount      int
		expectedInheritedRoles   []string
		expectedConflicts        int
		expectError              bool
	}{
		{
			name:                   "Role with no parent",
			roleID:                 "standalone.role",
			expectedDirectCount:    2,
			expectedInheritedRoles: []string{},
			expectedConflicts:      0,
			expectError:            false,
		},
		{
			name:                   "Role with additive inheritance",
			roleID:                 "child.additive",
			expectedDirectCount:    1,
			expectedInheritedRoles: []string{"parent.role"},
			expectedConflicts:      0,
			expectError:            false,
		},
		{
			name:                   "Role with override inheritance",
			roleID:                 "child.override",
			expectedDirectCount:    2,
			expectedInheritedRoles: []string{"parent.role"},
			expectedConflicts:      1, // Conflict on shared permission
			expectError:            false,
		},
		{
			name:                   "Role with restrictive inheritance",
			roleID:                 "child.restrictive",
			expectedDirectCount:    2,
			expectedInheritedRoles: []string{"parent.role"},
			expectedConflicts:      0,
			expectError:            false,
		},
		{
			name:        "Non-existent role",
			roleID:      "non.existent",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			effective, err := engine.ComputeEffectivePermissions(ctx, tt.roleID)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, effective)

			assert.Equal(t, tt.roleID, effective.RoleID)
			assert.Len(t, effective.DirectPermissions, tt.expectedDirectCount)
			assert.Len(t, effective.InheritedPermissions, len(tt.expectedInheritedRoles))

			for _, expectedRole := range tt.expectedInheritedRoles {
				assert.Contains(t, effective.InheritedPermissions, expectedRole)
			}

			assert.Len(t, effective.ConflictResolution, tt.expectedConflicts)
			assert.True(t, effective.ComputedAt.After(time.Time{}))
		})
	}
}

func TestHierarchyEngine_ValidateHierarchy(t *testing.T) {
	store := memory.NewStore()
	engine := NewHierarchyEngine(store, store)
	ctx := context.Background()

	// Setup test data with circular dependency
	setupCircularHierarchyTestData(t, store)

	tests := []struct {
		name        string
		roleID      string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid hierarchy",
			roleID:      "valid.child",
			expectError: false,
		},
		{
			name:        "Circular dependency",
			roleID:      "circular.a",
			expectError: true,
			errorMsg:    "circular dependency",
		},
		{
			name:        "Non-existent role",
			roleID:      "non.existent",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.ValidateHierarchy(ctx, tt.roleID)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHierarchyEngine_PermissionInheritanceTypes(t *testing.T) {
	store := memory.NewStore()
	engine := NewHierarchyEngine(store, store)
	ctx := context.Background()

	// Setup roles with different inheritance types
	setupInheritanceTypeTestData(t, store)

	// Test Additive inheritance
	t.Run("Additive inheritance", func(t *testing.T) {
		effective, err := engine.ComputeEffectivePermissions(ctx, "child.additive")
		require.NoError(t, err)

		// Should have both direct and inherited permissions
		directPermIDs := getPermissionIDs(effective.DirectPermissions)
		inheritedPermIDs := getPermissionIDs(effective.InheritedPermissions["parent.role"])

		assert.Contains(t, directPermIDs, "child.permission")
		assert.Contains(t, inheritedPermIDs, "parent.permission1")
		assert.Contains(t, inheritedPermIDs, "parent.permission2")
	})

	// Test Override inheritance
	t.Run("Override inheritance", func(t *testing.T) {
		effective, err := engine.ComputeEffectivePermissions(ctx, "child.override")
		require.NoError(t, err)

		// Conflicts should be resolved in favor of direct permissions
		assert.Contains(t, effective.ConflictResolution, "shared.permission")
		conflict := effective.ConflictResolution["shared.permission"]
		assert.Equal(t, "override", conflict.Resolution)
		assert.Equal(t, "child.override", conflict.SourceRoleID)
	})

	// Test Restrictive inheritance
	t.Run("Restrictive inheritance", func(t *testing.T) {
		effective, err := engine.ComputeEffectivePermissions(ctx, "child.restrictive")
		require.NoError(t, err)

		// Should only have permissions that exist in both parent and child
		directPermIDs := getPermissionIDs(effective.DirectPermissions)
		inheritedPermIDs := getPermissionIDs(effective.InheritedPermissions["parent.role"])

		// Only shared permissions should remain
		assert.Contains(t, directPermIDs, "shared.permission")
		assert.Contains(t, inheritedPermIDs, "shared.permission")
		assert.NotContains(t, directPermIDs, "child.only.permission")
		assert.NotContains(t, inheritedPermIDs, "parent.only.permission")
	})
}

func TestHierarchyEngine_ConflictResolution(t *testing.T) {
	store := memory.NewStore()
	engine := NewHierarchyEngine(store, store)

	// Test merge permissions
	directPerm := &common.Permission{
		Id:       "test.permission",
		Actions:  []string{"read", "write"},
	}
	inheritedPerms := []*common.Permission{
		{
			Id:      "test.permission",
			Actions: []string{"write", "delete"},
		},
	}

	merged := engine.mergePermissions(directPerm, inheritedPerms)
	actions := merged.Actions
	
	assert.Contains(t, actions, "read")
	assert.Contains(t, actions, "write")
	assert.Contains(t, actions, "delete")
	assert.Len(t, actions, 3)

	// Test restrict permissions
	restricted := engine.restrictPermissions(directPerm, inheritedPerms)
	restrictedActions := restricted.Actions
	
	assert.Contains(t, restrictedActions, "write") // Common action
	assert.NotContains(t, restrictedActions, "read") // Only in direct
	assert.NotContains(t, restrictedActions, "delete") // Only in inherited
	assert.Len(t, restrictedActions, 1)
}

// Helper functions

func setupHierarchyTestData(t *testing.T, store *memory.Store) {
	ctx := context.Background()

	// Create permissions
	permissions := []*common.Permission{
		{Id: "read.permission", Name: "Read Permission", Actions: []string{"read"}},
		{Id: "write.permission", Name: "Write Permission", Actions: []string{"write"}},
		{Id: "delete.permission", Name: "Delete Permission", Actions: []string{"delete"}},
		{Id: "shared.permission", Name: "Shared Permission", Actions: []string{"shared"}},
		{Id: "parent.only", Name: "Parent Only Permission", Actions: []string{"parent"}},
	}
	store.LoadPermissions(permissions)

	// Create roles with hierarchy
	roles := []*common.Role{
		{
			Id:              "standalone.role",
			Name:            "Standalone Role",
			PermissionIds:   []string{"read.permission", "write.permission"},
			InheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_NONE,
		},
		{
			Id:              "parent.role",
			Name:            "Parent Role",
			PermissionIds:   []string{"shared.permission", "parent.only"},
			InheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_NONE,
		},
		{
			Id:              "child.additive",
			Name:            "Child Additive Role",
			PermissionIds:   []string{"delete.permission"},
			ParentRoleId:    "parent.role",
			InheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE,
		},
		{
			Id:              "child.override",
			Name:            "Child Override Role",
			PermissionIds:   []string{"shared.permission", "write.permission"},
			ParentRoleId:    "parent.role",
			InheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_OVERRIDE,
		},
		{
			Id:              "child.restrictive",
			Name:            "Child Restrictive Role",
			PermissionIds:   []string{"shared.permission", "read.permission"},
			ParentRoleId:    "parent.role",
			InheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_RESTRICTIVE,
		},
	}
	store.LoadRoles(roles)

	// Set up parent-child relationships
	require.NoError(t, store.SetRoleParent(ctx, "child.additive", "parent.role", common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE))
	require.NoError(t, store.SetRoleParent(ctx, "child.override", "parent.role", common.RoleInheritanceType_ROLE_INHERITANCE_OVERRIDE))
	require.NoError(t, store.SetRoleParent(ctx, "child.restrictive", "parent.role", common.RoleInheritanceType_ROLE_INHERITANCE_RESTRICTIVE))
}

func setupCircularHierarchyTestData(t *testing.T, store *memory.Store) {
	ctx := context.Background()

	roles := []*common.Role{
		{
			Id:              "valid.parent",
			Name:            "Valid Parent",
			PermissionIds:   []string{},
			InheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_NONE,
		},
		{
			Id:              "valid.child",
			Name:            "Valid Child",
			PermissionIds:   []string{},
			ParentRoleId:    "valid.parent",
			InheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE,
		},
		{
			Id:              "circular.a",
			Name:            "Circular A",
			PermissionIds:   []string{},
			ParentRoleId:    "circular.b",
			InheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE,
		},
		{
			Id:              "circular.b",
			Name:            "Circular B",
			PermissionIds:   []string{},
			ParentRoleId:    "circular.a",
			InheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE,
		},
	}
	store.LoadRoles(roles)

	// Set up relationships (this will create the circular dependency)
	require.NoError(t, store.SetRoleParent(ctx, "valid.child", "valid.parent", common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE))
	require.NoError(t, store.SetRoleParent(ctx, "circular.a", "circular.b", common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE))
	require.NoError(t, store.SetRoleParent(ctx, "circular.b", "circular.a", common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE))
}

func setupInheritanceTypeTestData(t *testing.T, store *memory.Store) {
	ctx := context.Background()

	// Create permissions with overlaps for testing
	permissions := []*common.Permission{
		{Id: "parent.permission1", Name: "Parent Perm 1", Actions: []string{"action1"}},
		{Id: "parent.permission2", Name: "Parent Perm 2", Actions: []string{"action2"}},
		{Id: "parent.only.permission", Name: "Parent Only", Actions: []string{"parent_action"}},
		{Id: "child.permission", Name: "Child Perm", Actions: []string{"child_action"}},
		{Id: "child.only.permission", Name: "Child Only", Actions: []string{"child_only"}},
		{Id: "shared.permission", Name: "Shared Perm", Actions: []string{"shared"}},
	}
	store.LoadPermissions(permissions)

	roles := []*common.Role{
		{
			Id:              "parent.role",
			Name:            "Parent Role",
			PermissionIds:   []string{"parent.permission1", "parent.permission2", "shared.permission", "parent.only.permission"},
			InheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_NONE,
		},
		{
			Id:              "child.additive",
			Name:            "Child Additive",
			PermissionIds:   []string{"child.permission"},
			ParentRoleId:    "parent.role",
			InheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE,
		},
		{
			Id:              "child.override",
			Name:            "Child Override", 
			PermissionIds:   []string{"child.permission", "shared.permission"}, // Shared permission conflicts
			ParentRoleId:    "parent.role",
			InheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_OVERRIDE,
		},
		{
			Id:              "child.restrictive",
			Name:            "Child Restrictive",
			PermissionIds:   []string{"shared.permission", "child.only.permission"}, // Only shared.permission overlaps
			ParentRoleId:    "parent.role",
			InheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_RESTRICTIVE,
		},
	}
	store.LoadRoles(roles)

	// Set up relationships
	require.NoError(t, store.SetRoleParent(ctx, "child.additive", "parent.role", common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE))
	require.NoError(t, store.SetRoleParent(ctx, "child.override", "parent.role", common.RoleInheritanceType_ROLE_INHERITANCE_OVERRIDE))
	require.NoError(t, store.SetRoleParent(ctx, "child.restrictive", "parent.role", common.RoleInheritanceType_ROLE_INHERITANCE_RESTRICTIVE))
}

func getPermissionIDs(permissions []*common.Permission) []string {
	var ids []string
	for _, perm := range permissions {
		ids = append(ids, perm.Id)
	}
	return ids
}