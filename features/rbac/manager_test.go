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

func TestManager_Initialize(t *testing.T) {
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

	// Verify default permissions were loaded
	var permissions []*common.Permission
	permissions, err = manager.ListPermissions(ctx, "")
	require.NoError(t, err)
	assert.NotEmpty(t, permissions)

	// Check for specific default permissions
	stewardRegisterPerm, err := manager.GetPermission(ctx, "steward.register")
	require.NoError(t, err)
	assert.Equal(t, "Register Steward", stewardRegisterPerm.Name)

	// Verify default system roles were loaded
	systemAdminRole, err := manager.GetRole(ctx, "system.admin")
	require.NoError(t, err)
	assert.Equal(t, "System Administrator", systemAdminRole.Name)
	assert.True(t, systemAdminRole.IsSystemRole)

	stewardServiceRole, err := manager.GetRole(ctx, "steward.service")
	require.NoError(t, err)
	assert.Equal(t, "Steward Service Account", stewardServiceRole.Name)
	assert.True(t, stewardServiceRole.IsSystemRole)
}

func TestManager_CreateTenantDefaultRoles(t *testing.T) {
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

	tenantID := "test-tenant"
	err = manager.CreateTenantDefaultRoles(ctx, tenantID)
	require.NoError(t, err)

	// Verify tenant-specific roles were created
	tenantAdminRole, err := manager.GetRole(ctx, tenantID+".tenant.admin")
	require.NoError(t, err)
	assert.Equal(t, "Tenant Administrator", tenantAdminRole.Name)
	assert.Equal(t, tenantID, tenantAdminRole.TenantId)
	assert.False(t, tenantAdminRole.IsSystemRole)

	tenantOperatorRole, err := manager.GetRole(ctx, tenantID+".tenant.operator")
	require.NoError(t, err)
	assert.Equal(t, "Tenant Operator", tenantOperatorRole.Name)
	assert.Equal(t, tenantID, tenantOperatorRole.TenantId)

	tenantViewerRole, err := manager.GetRole(ctx, tenantID+".tenant.viewer")
	require.NoError(t, err)
	assert.Equal(t, "Tenant Viewer", tenantViewerRole.Name)
	assert.Equal(t, tenantID, tenantViewerRole.TenantId)
}

func TestManager_SubjectManagement(t *testing.T) {
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

	// Create a test subject
	subject := &common.Subject{
		Id:          "test-user-1",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Test User One",
		TenantId:    "test-tenant",
		IsActive:    true,
		Attributes: map[string]string{
			"department": "engineering",
		},
	}

	err = manager.CreateSubject(ctx, subject)
	require.NoError(t, err)

	// Retrieve the subject
	retrievedSubject, err := manager.GetSubject(ctx, "test-user-1")
	require.NoError(t, err)
	assert.Equal(t, subject.DisplayName, retrievedSubject.DisplayName)
	assert.Equal(t, subject.Type, retrievedSubject.Type)
	assert.Equal(t, subject.TenantId, retrievedSubject.TenantId)
	assert.True(t, retrievedSubject.IsActive)

	// List subjects
	subjects, err := manager.ListSubjects(ctx, "test-tenant", common.SubjectType_SUBJECT_TYPE_USER)
	require.NoError(t, err)
	assert.Len(t, subjects, 1)
	assert.Equal(t, "test-user-1", subjects[0].Id)

	// Update subject
	retrievedSubject.DisplayName = "Updated Test User"
	err = manager.UpdateSubject(ctx, retrievedSubject)
	require.NoError(t, err)

	updatedSubject, err := manager.GetSubject(ctx, "test-user-1")
	require.NoError(t, err)
	assert.Equal(t, "Updated Test User", updatedSubject.DisplayName)

	// Delete subject
	err = manager.DeleteSubject(ctx, "test-user-1")
	require.NoError(t, err)

	_, err = manager.GetSubject(ctx, "test-user-1")
	assert.Error(t, err)
}

func TestManager_RoleAssignment(t *testing.T) {
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

	tenantID := "test-tenant"
	err = manager.CreateTenantDefaultRoles(ctx, tenantID)
	require.NoError(t, err)

	// Create a test subject
	subject := &common.Subject{
		Id:          "test-user-1",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Test User One",
		TenantId:    tenantID,
		IsActive:    true,
	}

	err = manager.CreateSubject(ctx, subject)
	require.NoError(t, err)

	// Assign a role
	assignment := &common.RoleAssignment{
		SubjectId: "test-user-1",
		RoleId:    tenantID + ".tenant.admin",
		TenantId:  tenantID,
	}

	err = manager.AssignRole(ctx, assignment)
	require.NoError(t, err)

	// Verify role assignment
	roles, err := manager.GetSubjectRoles(ctx, "test-user-1", tenantID)
	require.NoError(t, err)
	assert.Len(t, roles, 1)
	assert.Equal(t, tenantID+".tenant.admin", roles[0].Id)

	// List assignments
	assignments, err := manager.ListAssignments(ctx, "test-user-1", "", tenantID)
	require.NoError(t, err)
	assert.Len(t, assignments, 1)

	// Revoke role
	err = manager.RevokeRole(ctx, "test-user-1", tenantID+".tenant.admin", tenantID)
	require.NoError(t, err)

	// Verify role was revoked
	roles, err = manager.GetSubjectRoles(ctx, "test-user-1", tenantID)
	require.NoError(t, err)
	assert.Len(t, roles, 0)
}

func TestManager_PermissionChecking(t *testing.T) {
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

	tenantID := "test-tenant"
	err = manager.CreateTenantDefaultRoles(ctx, tenantID)
	require.NoError(t, err)

	// Create a test subject
	subject := &common.Subject{
		Id:          "test-user-1",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Test User One",
		TenantId:    tenantID,
		IsActive:    true,
	}

	err = manager.CreateSubject(ctx, subject)
	require.NoError(t, err)

	// Assign tenant admin role
	assignment := &common.RoleAssignment{
		SubjectId: "test-user-1",
		RoleId:    tenantID + ".tenant.admin",
		TenantId:  tenantID,
	}

	err = manager.AssignRole(ctx, assignment)
	require.NoError(t, err)

	// Test permission checking
	tests := []struct {
		name       string
		permission string
		expectGranted bool
	}{
		{
			name:       "should_grant_steward_read_permission",
			permission: "steward.read",
			expectGranted: true,
		},
		{
			name:       "should_grant_config_read_permission",
			permission: "config.read",
			expectGranted: true,
		},
		{
			name:       "should_not_grant_system_admin_permission",
			permission: "system.admin",
			expectGranted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &common.AccessRequest{
				SubjectId:    "test-user-1",
				PermissionId: tt.permission,
				TenantId:     tenantID,
			}

			response, err := manager.CheckPermission(ctx, request)
			require.NoError(t, err)
			assert.Equal(t, tt.expectGranted, response.Granted)
			
			if tt.expectGranted {
				assert.NotEmpty(t, response.Reason)
				assert.NotEmpty(t, response.AppliedRoles)
			}
		})
	}
}

func TestManager_SystemAdminPermissions(t *testing.T) {
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

	// Create a system admin subject
	subject := &common.Subject{
		Id:          "system-admin",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "System Administrator",
		TenantId:    "root",
		IsActive:    true,
	}

	err = manager.CreateSubject(ctx, subject)
	require.NoError(t, err)

	// Assign system admin role
	assignment := &common.RoleAssignment{
		SubjectId: "system-admin",
		RoleId:    "system.admin",
		TenantId:  "root",
	}

	err = manager.AssignRole(ctx, assignment)
	require.NoError(t, err)

	// System admin should have access to everything
	testPermissions := []string{
		"steward.register",
		"steward.manage",
		"config.create",
		"config.delete",
		"tenant.manage",
		"rbac.role.manage",
		"any.custom.permission", // Should work due to system.admin wildcard
	}

	for _, permission := range testPermissions {
		t.Run("system_admin_should_have_"+permission, func(t *testing.T) {
			request := &common.AccessRequest{
				SubjectId:    "system-admin",
				PermissionId: permission,
				TenantId:     "root",
			}

			response, err := manager.CheckPermission(ctx, request)
			require.NoError(t, err)
			assert.True(t, response.Granted, "System admin should have permission %s", permission)
		})
	}
}

func TestManager_CreateStewardSubject(t *testing.T) {
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

	stewardID := "steward-001"
	tenantID := "test-tenant"

	err = manager.CreateStewardSubject(ctx, stewardID, tenantID)
	require.NoError(t, err)

	// Verify steward subject was created
	subject, err := manager.GetSubject(ctx, stewardID)
	require.NoError(t, err)
	assert.Equal(t, common.SubjectType_SUBJECT_TYPE_STEWARD, subject.Type)
	assert.Equal(t, tenantID, subject.TenantId)
	assert.True(t, subject.IsActive)
	assert.Equal(t, stewardID, subject.Attributes["steward_id"])

	// Verify steward service role was assigned
	roles, err := manager.GetSubjectRoles(ctx, stewardID, tenantID)
	require.NoError(t, err)
	assert.Len(t, roles, 1)
	assert.Equal(t, "steward.service", roles[0].Id)

	// Verify steward has required permissions
	permissions := []string{
		"steward.register",
		"steward.heartbeat",
		"config.read",
		"config.status.report",
	}

	for _, permission := range permissions {
		request := &common.AccessRequest{
			SubjectId:    stewardID,
			PermissionId: permission,
			TenantId:     tenantID,
		}

		response, err := manager.CheckPermission(ctx, request)
		require.NoError(t, err)
		assert.True(t, response.Granted, "Steward should have permission %s", permission)
	}
}

func TestManager_InactiveSubjectPermissions(t *testing.T) {
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

	tenantID := "test-tenant"
	err = manager.CreateTenantDefaultRoles(ctx, tenantID)
	require.NoError(t, err)

	// Create an inactive subject
	subject := &common.Subject{
		Id:          "inactive-user",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Inactive User",
		TenantId:    tenantID,
		IsActive:    false, // Inactive
	}

	err = manager.CreateSubject(ctx, subject)
	require.NoError(t, err)

	// Assign a role
	assignment := &common.RoleAssignment{
		SubjectId: "inactive-user",
		RoleId:    tenantID + ".tenant.admin",
		TenantId:  tenantID,
	}

	err = manager.AssignRole(ctx, assignment)
	require.NoError(t, err)

	// Inactive subject should not have permissions
	request := &common.AccessRequest{
		SubjectId:    "inactive-user",
		PermissionId: "config.read",
		TenantId:     tenantID,
	}

	response, err := manager.CheckPermission(ctx, request)
	require.NoError(t, err)
	assert.False(t, response.Granted)
	assert.Contains(t, response.Reason, "inactive")
}