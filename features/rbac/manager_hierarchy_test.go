package rbac

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	
	// Import storage providers for testing
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

func TestManager_CreateRoleWithParent(t *testing.T) {
	// Use git storage for durable testing - minimum storage requirement
	config := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":         "main",
		"auto_init":      true,
	}
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
	require.NoError(t, err)
	
	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	ctx := context.Background()
	
	// Initialize manager
	err = manager.Initialize(ctx)
	require.NoError(t, err)

	// Create parent role first
	parentRole := &common.Role{
		Id:              "parent.test",
		Name:            "Parent Test Role",
		Description:     "Test parent role",
		PermissionIds:   []string{"read.permission"},
		IsSystemRole:    false,
		TenantId:        "tenant-1",
		InheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_NONE,
	}
	require.NoError(t, manager.CreateRole(ctx, parentRole))

	tests := []struct {
		name            string
		role            *common.Role
		parentRoleID    string
		inheritanceType common.RoleInheritanceType
		expectError     bool
		errorMsg        string
	}{
		{
			name: "Valid role with parent",
			role: &common.Role{
				Id:              "child.test",
				Name:            "Child Test Role",
				Description:     "Test child role",
				PermissionIds:   []string{"write.permission"},
				IsSystemRole:    false,
				TenantId:        "tenant-1",
			},
			parentRoleID:    "parent.test",
			inheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE,
			expectError:     false,
		},
		{
			name: "Role without parent",
			role: &common.Role{
				Id:              "standalone.test",
				Name:            "Standalone Test Role",
				Description:     "Test standalone role",
				PermissionIds:   []string{"delete.permission"},
				IsSystemRole:    false,
				TenantId:        "tenant-1",
			},
			parentRoleID:    "",
			inheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_NONE,
			expectError:     false,
		},
		{
			name: "Role with non-existent parent",
			role: &common.Role{
				Id:              "orphan.test",
				Name:            "Orphan Test Role",
				Description:     "Test orphan role",
				PermissionIds:   []string{},
				IsSystemRole:    false,
				TenantId:        "tenant-1",
			},
			parentRoleID:    "non.existent.parent",
			inheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE,
			expectError:     true,
			errorMsg:        "not found",
		},
		{
			name: "Self-referencing role",
			role: &common.Role{
				Id:              "self.ref.test",
				Name:            "Self Reference Test Role",
				Description:     "Test self-referencing role",
				PermissionIds:   []string{},
				IsSystemRole:    false,
				TenantId:        "tenant-1",
			},
			parentRoleID:    "self.ref.test",
			inheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE,
			expectError:     true,
			errorMsg:        "cannot be its own parent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.CreateRoleWithParent(ctx, tt.role, tt.parentRoleID, tt.inheritanceType)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				return
			}

			require.NoError(t, err)

			// Verify the role was created with correct parent relationship
			createdRole, err := manager.GetRole(ctx, tt.role.Id)
			require.NoError(t, err)

			assert.Equal(t, tt.parentRoleID, createdRole.ParentRoleId)
			assert.Equal(t, tt.inheritanceType, createdRole.InheritanceType)

			// If there's a parent, verify the relationship exists
			if tt.parentRoleID != "" {
				children, err := manager.GetChildRoles(ctx, tt.parentRoleID)
				require.NoError(t, err)
				
				found := false
				for _, child := range children {
					if child.Id == tt.role.Id {
						found = true
						break
					}
				}
				assert.True(t, found, "Child role should be in parent's children list")
			}
		})
	}
}

func TestManager_GetRoleHierarchy(t *testing.T) {
	// Use git storage for durable testing - minimum storage requirement
	config := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":         "main",
		"auto_init":      true,
	}
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
	require.NoError(t, err)
	
	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	ctx := context.Background()
	
	// Initialize and set up test hierarchy
	err = manager.Initialize(ctx)
	require.NoError(t, err)
	setupManagerHierarchyTestData(t, manager)

	tests := []struct {
		name           string
		roleID         string
		expectParent   bool
		parentRoleID   string
		expectChildren bool
		childrenCount  int
		expectError    bool
	}{
		{
			name:           "Root role with children",
			roleID:         "root.role",
			expectParent:   false,
			expectChildren: true,
			childrenCount:  2,
			expectError:    false,
		},
		{
			name:           "Middle role with parent and children",
			roleID:         "middle.role",
			expectParent:   true,
			parentRoleID:   "root.role",
			expectChildren: true,
			childrenCount:  1,
			expectError:    false,
		},
		{
			name:           "Leaf role with parent only",
			roleID:         "leaf.role",
			expectParent:   true,
			parentRoleID:   "middle.role",
			expectChildren: false,
			childrenCount:  0,
			expectError:    false,
		},
		{
			name:        "Non-existent role",
			roleID:      "non.existent",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hierarchy, err := manager.GetRoleHierarchy(ctx, tt.roleID)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, hierarchy)
			assert.Equal(t, tt.roleID, hierarchy.Role.Id)

			if tt.expectParent {
				require.NotNil(t, hierarchy.Parent)
				assert.Equal(t, tt.parentRoleID, hierarchy.Parent.Role.Id)
			} else {
				assert.Nil(t, hierarchy.Parent)
			}

			if tt.expectChildren {
				assert.Len(t, hierarchy.Children, tt.childrenCount)
			} else {
				assert.Empty(t, hierarchy.Children)
			}
		})
	}
}

func TestManager_SetAndRemoveRoleParent(t *testing.T) {
	// Use git storage for durable testing - minimum storage requirement
	config := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":         "main",
		"auto_init":      true,
	}
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
	require.NoError(t, err)
	
	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	ctx := context.Background()
	
	err = manager.Initialize(ctx)
	require.NoError(t, err)

	// Create test roles
	parentRole := &common.Role{
		Id:           "parent.role",
		Name:         "Parent Role",
		PermissionIds: []string{},
		TenantId:     "tenant-1",
	}
	require.NoError(t, manager.CreateRole(ctx, parentRole))

	childRole := &common.Role{
		Id:           "child.role", 
		Name:         "Child Role",
		PermissionIds: []string{},
		TenantId:     "tenant-1",
	}
	require.NoError(t, manager.CreateRole(ctx, childRole))

	// Test SetRoleParent
	t.Run("Set role parent", func(t *testing.T) {
		err := manager.SetRoleParent(ctx, "child.role", "parent.role", common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE)
		require.NoError(t, err)

		// Verify relationship
		updatedChild, err := manager.GetRole(ctx, "child.role")
		require.NoError(t, err)
		assert.Equal(t, "parent.role", updatedChild.ParentRoleId)
		assert.Equal(t, common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE, updatedChild.InheritanceType)

		// Verify parent's children list
		children, err := manager.GetChildRoles(ctx, "parent.role")
		require.NoError(t, err)
		assert.Len(t, children, 1)
		assert.Equal(t, "child.role", children[0].Id)
	})

	// Test RemoveRoleParent
	t.Run("Remove role parent", func(t *testing.T) {
		err := manager.RemoveRoleParent(ctx, "child.role")
		require.NoError(t, err)

		// Verify relationship is removed
		updatedChild, err := manager.GetRole(ctx, "child.role")
		require.NoError(t, err)
		assert.Empty(t, updatedChild.ParentRoleId)
		assert.Equal(t, common.RoleInheritanceType_ROLE_INHERITANCE_NONE, updatedChild.InheritanceType)

		// Verify parent's children list is empty
		children, err := manager.GetChildRoles(ctx, "parent.role")
		require.NoError(t, err)
		assert.Empty(t, children)
	})
}

func TestManager_ComputeRolePermissions(t *testing.T) {
	// Use git storage for durable testing - minimum storage requirement
	config := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":         "main",
		"auto_init":      true,
	}
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
	require.NoError(t, err)
	
	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	ctx := context.Background()
	
	err = manager.Initialize(ctx)
	require.NoError(t, err)
	setupManagerPermissionTestData(t, manager)

	tests := []struct {
		name                    string
		roleID                  string
		expectedDirectCount     int
		expectedInheritedRoles  int
		expectedConflicts       int
		expectError             bool
	}{
		{
			name:                   "Role with additive inheritance",
			roleID:                 "child.additive",
			expectedDirectCount:    1,
			expectedInheritedRoles: 1,
			expectedConflicts:      0,
			expectError:            false,
		},
		{
			name:                   "Role with override inheritance and conflicts",
			roleID:                 "child.override",
			expectedDirectCount:    2,
			expectedInheritedRoles: 1,
			expectedConflicts:      1,
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
			effective, err := manager.ComputeRolePermissions(ctx, tt.roleID)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, effective)

			assert.Equal(t, tt.roleID, effective.RoleID)
			assert.Len(t, effective.DirectPermissions, tt.expectedDirectCount)
			assert.Len(t, effective.InheritedPermissions, tt.expectedInheritedRoles)
			assert.Len(t, effective.ConflictResolution, tt.expectedConflicts)
		})
	}
}

func TestManager_ValidateHierarchyOperation(t *testing.T) {
	// Use git storage for durable testing - minimum storage requirement
	config := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":         "main",
		"auto_init":      true,
	}
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
	require.NoError(t, err)
	
	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	ctx := context.Background()
	
	err = manager.Initialize(ctx)
	require.NoError(t, err)

	// Create roles for testing
	role1 := &common.Role{Id: "role1", Name: "Role 1", TenantId: "tenant-1"}
	role2 := &common.Role{Id: "role2", Name: "Role 2", TenantId: "tenant-1"}
	require.NoError(t, manager.CreateRole(ctx, role1))
	require.NoError(t, manager.CreateRole(ctx, role2))

	tests := []struct {
		name         string
		childRoleID  string
		parentRoleID string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "Valid hierarchy operation",
			childRoleID:  "role1",
			parentRoleID: "role2",
			expectError:  false,
		},
		{
			name:         "Self-referencing hierarchy",
			childRoleID:  "role1",
			parentRoleID: "role1",
			expectError:  true,
			errorMsg:     "cannot be its own parent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.ValidateHierarchyOperation(ctx, tt.childRoleID, tt.parentRoleID)

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

// Helper functions

func setupManagerHierarchyTestData(t *testing.T, manager *Manager) {
	ctx := context.Background()

	// Create a 3-level hierarchy: root -> middle -> leaf
	roles := []*common.Role{
		{
			Id:           "root.role",
			Name:         "Root Role",
			PermissionIds: []string{},
			TenantId:     "tenant-1",
		},
		{
			Id:           "middle.role",
			Name:         "Middle Role", 
			PermissionIds: []string{},
			TenantId:     "tenant-1",
		},
		{
			Id:           "leaf.role",
			Name:         "Leaf Role",
			PermissionIds: []string{},
			TenantId:     "tenant-1",
		},
		{
			Id:           "another.child",
			Name:         "Another Child",
			PermissionIds: []string{},
			TenantId:     "tenant-1",
		},
	}

	for _, role := range roles {
		require.NoError(t, manager.CreateRole(ctx, role))
	}

	// Set up hierarchy: root -> [middle, another.child], middle -> leaf
	require.NoError(t, manager.SetRoleParent(ctx, "middle.role", "root.role", common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE))
	require.NoError(t, manager.SetRoleParent(ctx, "another.child", "root.role", common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE))
	require.NoError(t, manager.SetRoleParent(ctx, "leaf.role", "middle.role", common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE))
}

func setupManagerPermissionTestData(t *testing.T, manager *Manager) {
	ctx := context.Background()

	// Create permissions
	permissions := []*common.Permission{
		{Id: "parent.perm", Name: "Parent Permission", Actions: []string{"parent_action"}},
		{Id: "child.perm", Name: "Child Permission", Actions: []string{"child_action"}},
		{Id: "shared.perm", Name: "Shared Permission", Actions: []string{"shared"}},
	}
	
	for _, perm := range permissions {
		require.NoError(t, manager.CreatePermission(ctx, perm))
	}

	// Create roles with permissions
	parentRole := &common.Role{
		Id:           "parent.role",
		Name:         "Parent Role",
		PermissionIds: []string{"parent.perm", "shared.perm"},
		TenantId:     "tenant-1",
	}
	require.NoError(t, manager.CreateRole(ctx, parentRole))

	childAdditiveRole := &common.Role{
		Id:           "child.additive",
		Name:         "Child Additive Role",
		PermissionIds: []string{"child.perm"},
		TenantId:     "tenant-1",
	}
	require.NoError(t, manager.CreateRoleWithParent(ctx, childAdditiveRole, "parent.role", common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE))

	childOverrideRole := &common.Role{
		Id:           "child.override",
		Name:         "Child Override Role",
		PermissionIds: []string{"child.perm", "shared.perm"}, // shared.perm conflicts with parent
		TenantId:     "tenant-1",
	}
	require.NoError(t, manager.CreateRoleWithParent(ctx, childOverrideRole, "parent.role", common.RoleInheritanceType_ROLE_INHERITANCE_OVERRIDE))
}