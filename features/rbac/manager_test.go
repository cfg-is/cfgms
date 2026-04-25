// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rbac

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"

	// Import storage providers for testing
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func TestManager_Initialize(t *testing.T) {
	// Use git storage for durable testing - minimum storage requirement
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})
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
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})
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
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})
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
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})
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
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})
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
		name          string
		permission    string
		expectGranted bool
	}{
		{
			name:          "should_grant_steward_read_permission",
			permission:    "steward.read",
			expectGranted: true,
		},
		{
			name:          "should_grant_config_read_permission",
			permission:    "config.read",
			expectGranted: true,
		},
		{
			name:          "should_not_grant_system_admin_permission",
			permission:    "system.admin",
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
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})
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
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})
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
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})
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

func TestManager_ListAllSubjects(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})
	ctx := context.Background()

	require.NoError(t, manager.Initialize(ctx))

	tenantID := "list-all-subjects-tenant"

	subjects := []*common.Subject{
		{Id: "user-1", Type: common.SubjectType_SUBJECT_TYPE_USER, TenantId: tenantID, IsActive: true},
		{Id: "svc-1", Type: common.SubjectType_SUBJECT_TYPE_SERVICE, TenantId: tenantID, IsActive: true},
		{Id: "steward-1", Type: common.SubjectType_SUBJECT_TYPE_STEWARD, TenantId: tenantID, IsActive: true},
		{Id: "other-tenant-user", Type: common.SubjectType_SUBJECT_TYPE_USER, TenantId: "other-tenant", IsActive: true},
	}
	for _, s := range subjects {
		require.NoError(t, manager.CreateSubject(ctx, s))
	}

	all, err := manager.ListAllSubjects(ctx, tenantID)
	require.NoError(t, err)
	assert.Len(t, all, 3, "expected only subjects scoped to the tenant")

	ids := make([]string, len(all))
	for i, s := range all {
		ids[i] = s.Id
	}
	assert.ElementsMatch(t, []string{"user-1", "svc-1", "steward-1"}, ids)
}

func TestManager_DeleteSubjectsByTenant(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})
	ctx := context.Background()

	require.NoError(t, manager.Initialize(ctx))

	tenantID := "delete-subjects-tenant"
	otherTenantID := "other-tenant"

	for _, s := range []*common.Subject{
		{Id: "subj-a", Type: common.SubjectType_SUBJECT_TYPE_USER, TenantId: tenantID, IsActive: true},
		{Id: "subj-b", Type: common.SubjectType_SUBJECT_TYPE_SERVICE, TenantId: tenantID, IsActive: true},
		{Id: "subj-other", Type: common.SubjectType_SUBJECT_TYPE_USER, TenantId: otherTenantID, IsActive: true},
	} {
		require.NoError(t, manager.CreateSubject(ctx, s))
	}

	err = manager.DeleteSubjectsByTenant(ctx, tenantID)
	require.NoError(t, err)

	remaining, err := manager.ListAllSubjects(ctx, tenantID)
	require.NoError(t, err)
	assert.Empty(t, remaining, "expected no subjects for deleted tenant")

	// Other tenant's subjects must be untouched
	others, err := manager.ListAllSubjects(ctx, otherTenantID)
	require.NoError(t, err)
	assert.Len(t, others, 1)
}

func TestManager_DeleteRolesByTenant(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})
	ctx := context.Background()

	require.NoError(t, manager.Initialize(ctx))

	tenantID := "delete-roles-tenant"
	otherTenantID := "other-roles-tenant"

	for _, r := range []*common.Role{
		{Id: tenantID + ".role-a", Name: "Role A", TenantId: tenantID},
		{Id: tenantID + ".role-b", Name: "Role B", TenantId: tenantID},
		{Id: otherTenantID + ".role-x", Name: "Role X", TenantId: otherTenantID},
	} {
		require.NoError(t, manager.CreateRole(ctx, r))
	}

	err = manager.DeleteRolesByTenant(ctx, tenantID)
	require.NoError(t, err)

	// ListRoles includes system roles; verify only tenant-scoped roles are gone
	all, err := manager.ListRoles(ctx, tenantID)
	require.NoError(t, err)
	for _, r := range all {
		assert.NotEqual(t, tenantID, r.TenantId, "tenant-scoped role should have been deleted: %s", r.Id)
	}

	// Verify individual roles are gone
	_, err = manager.GetRole(ctx, tenantID+".role-a")
	assert.Error(t, err, "role-a should not exist after DeleteRolesByTenant")
	_, err = manager.GetRole(ctx, tenantID+".role-b")
	assert.Error(t, err, "role-b should not exist after DeleteRolesByTenant")

	// Other tenant's role must be untouched
	otherRole, err := manager.GetRole(ctx, otherTenantID+".role-x")
	require.NoError(t, err)
	assert.Equal(t, otherTenantID, otherRole.TenantId)
}
