// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package rbac

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/continuous"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
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

	// M-AUTH-2: sensitive operations require justification in context
	ctxJ := WithSensitiveOperationJustification(ctx, "test: role assignment management for rbac validation")

	// Assign a role
	assignment := &common.RoleAssignment{
		SubjectId: "test-user-1",
		RoleId:    tenantID + ".tenant.admin",
		TenantId:  tenantID,
	}

	err = manager.AssignRole(ctxJ, assignment)
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
	err = manager.RevokeRole(ctxJ, "test-user-1", tenantID+".tenant.admin", tenantID)
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

	// M-AUTH-2: sensitive operations require justification in context
	ctxJ := WithSensitiveOperationJustification(ctx, "test: assign role for permission checking validation")

	// Assign tenant admin role
	assignment := &common.RoleAssignment{
		SubjectId: "test-user-1",
		RoleId:    tenantID + ".tenant.admin",
		TenantId:  tenantID,
	}

	err = manager.AssignRole(ctxJ, assignment)
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

	// M-AUTH-2: sensitive operations require justification in context
	ctxJ := WithSensitiveOperationJustification(ctx, "test: assign system admin role for permission validation")

	// Assign system admin role
	assignment := &common.RoleAssignment{
		SubjectId: "system-admin",
		RoleId:    "system.admin",
		TenantId:  "root",
	}

	err = manager.AssignRole(ctxJ, assignment)
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

	// M-AUTH-2: sensitive operations require justification in context
	ctxJ := WithSensitiveOperationJustification(ctx, "test: assign role to inactive subject for permission gate validation")

	// Assign a role
	assignment := &common.RoleAssignment{
		SubjectId: "inactive-user",
		RoleId:    tenantID + ".tenant.admin",
		TenantId:  tenantID,
	}

	err = manager.AssignRole(ctxJ, assignment)
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

	// M-AUTH-2: sensitive operations require justification in context
	ctxJ := WithSensitiveOperationJustification(ctx, "test: create roles for DeleteRolesByTenant validation")

	for _, r := range []*common.Role{
		{Id: tenantID + ".role-a", Name: "Role A", TenantId: tenantID},
		{Id: tenantID + ".role-b", Name: "Role B", TenantId: tenantID},
		{Id: otherTenantID + ".role-x", Name: "Role X", TenantId: otherTenantID},
	} {
		require.NoError(t, manager.CreateRole(ctxJ, r))
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

// newTestManagerWithCache creates a Manager wired with a CacheManager for cache
// invalidation tests. Returns both the manager and the raw CacheManager so tests
// can prime cache entries and observe invalidation.
func newTestManagerWithCache(t *testing.T) (*Manager, *continuous.CacheManager) {
	t.Helper()
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

	cm := continuous.NewCacheManager(5*time.Minute, 100)
	manager.SetCacheManager(cm)

	ctx := context.Background()
	require.NoError(t, manager.Initialize(ctx))
	return manager, cm
}

// primeSubjectCache inserts a granted auth decision into the CacheManager for the
// given subject so tests can verify the entry is removed after role revocation.
func primeSubjectCache(t *testing.T, cm *continuous.CacheManager, subjectID, tenantID string) *continuous.ContinuousAuthRequest {
	t.Helper()
	req := &continuous.ContinuousAuthRequest{
		AccessRequest: &common.AccessRequest{
			SubjectId:    subjectID,
			TenantId:     tenantID,
			PermissionId: "test.permission",
			ResourceId:   "test-resource",
		},
		SessionID: "session-" + subjectID,
	}
	resp := &continuous.ContinuousAuthResponse{
		AccessResponse: &common.AccessResponse{Granted: true, Reason: "test grant"},
		DecisionID:     "decision-" + subjectID,
		DecisionTime:   time.Now(),
		ValidUntil:     time.Now().Add(5 * time.Minute),
		SessionValid:   true,
	}
	require.NoError(t, cm.CacheAuth(req, resp))
	require.NotNil(t, cm.GetCachedAuth(req), "primed cache entry must be retrievable")
	return req
}

// TestManager_RevokeRole_InvalidatesSubjectCache verifies that after RevokeRole the
// CacheManager no longer returns a cached auth decision for the revoked subject.
func TestManager_RevokeRole_InvalidatesSubjectCache(t *testing.T) {
	ctx := context.Background()
	manager, cm := newTestManagerWithCache(t)

	tenantID := "cache-revoke-tenant"
	subjectID := "cache-revoke-user"
	roleID := tenantID + ".tenant.admin"

	require.NoError(t, manager.CreateTenantDefaultRoles(ctx, tenantID))
	require.NoError(t, manager.CreateSubject(ctx, &common.Subject{
		Id:       subjectID,
		Type:     common.SubjectType_SUBJECT_TYPE_USER,
		TenantId: tenantID,
		IsActive: true,
	}))
	// M-AUTH-2: sensitive operations require justification in context
	ctxJ := WithSensitiveOperationJustification(ctx, "test: assign and revoke role for cache invalidation validation")

	require.NoError(t, manager.AssignRole(ctxJ, &common.RoleAssignment{
		SubjectId: subjectID,
		RoleId:    roleID,
		TenantId:  tenantID,
	}))

	req := primeSubjectCache(t, cm, subjectID, tenantID)

	require.NoError(t, manager.RevokeRole(ctxJ, subjectID, roleID, tenantID))

	assert.Nil(t, cm.GetCachedAuth(req),
		"GetCachedAuth must return nil after RevokeRole invalidates the subject cache")
}

// TestManager_CreateTenantDefaultRoles_PersistsAcrossRestart verifies that roles
// created by CreateTenantDefaultRoles survive a manager restart (i.e., are written
// to durable storage via StoreBulkRoles and re-loaded on Initialize).
func TestManager_CreateTenantDefaultRoles_PersistsAcrossRestart(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	ctx := context.Background()
	tenantID := "persist-tenant"

	// First manager instance: create default roles for the tenant.
	m1 := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m1.Close(stopCtx)
	})
	require.NoError(t, m1.Initialize(ctx))
	require.NoError(t, m1.CreateTenantDefaultRoles(ctx, tenantID))

	// Verify roles exist in the first manager instance.
	_, err = m1.GetRole(ctx, tenantID+".tenant.admin")
	require.NoError(t, err, "tenant admin role must exist in first manager instance")

	// Second manager instance using the same storage — simulates a restart.
	m2 := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m2.Close(stopCtx)
	})
	require.NoError(t, m2.Initialize(ctx))

	// Tenant roles must survive the restart.
	tenantAdminRole, err := m2.GetRole(ctx, tenantID+".tenant.admin")
	require.NoError(t, err, "tenant admin role must be reloaded from durable storage after restart")
	assert.Equal(t, tenantID, tenantAdminRole.TenantId)

	_, err = m2.GetRole(ctx, tenantID+".tenant.operator")
	require.NoError(t, err, "tenant operator role must survive restart")

	_, err = m2.GetRole(ctx, tenantID+".tenant.viewer")
	require.NoError(t, err, "tenant viewer role must survive restart")
}

// TestManager_CheckPermission_DbError_RecordsAuditEvent verifies that when
// CheckPermission encounters a non-not-found DB error from the auth engine, the
// Manager records a RBAC_PERMISSION_CHECK_DB_ERROR audit event before propagating
// the error to the caller.
func TestManager_CheckPermission_DbError_RecordsAuditEvent(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	ctx := context.Background()
	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(stopCtx)
	})
	require.NoError(t, manager.Initialize(ctx))

	tenantID := "db-error-tenant"
	subjectID := "db-error-user"
	roleID := "db-error-role"

	// Create a role and subject in the ephemeral store.
	role := &common.Role{Id: roleID, Name: "DB Error Role", TenantId: tenantID}
	manager.store.LoadRoles([]*common.Role{role})

	subject := &common.Subject{
		Id:       subjectID,
		TenantId: tenantID,
		IsActive: true,
	}
	require.NoError(t, manager.store.CreateSubject(ctx, subject))

	// Formally assign the role so it appears in the valid-assignment map used by CheckPermission.
	require.NoError(t, manager.store.AssignRole(ctx, &common.RoleAssignment{
		SubjectId: subjectID,
		RoleId:    roleID,
		TenantId:  tenantID,
	}))

	// Inject a non-not-found DB error into the base engine's role store.
	dbErr := fmt.Errorf("simulated postgres connection failure")
	errorStore := &errorInjectingRoleStore{
		Store:       manager.store,
		errorRoleID: roleID,
		err:         dbErr,
	}

	// Replace the base engine inside the advanced engine with one that uses the
	// error-injecting store. manager.advancedEngine.baseEngine is the actual
	// path used by Manager.CheckPermission.
	errorEngine := NewAuthEngine(manager.store, errorStore, manager.store, manager.store)
	errorEngine.SetHierarchyEngine(manager.hierarchyEngine)
	manager.advancedEngine.baseEngine = errorEngine

	request := &common.AccessRequest{
		SubjectId:    subjectID,
		PermissionId: "config.read",
		TenantId:     tenantID,
	}

	_, checkErr := manager.CheckPermission(ctx, request)
	require.Error(t, checkErr, "Manager.CheckPermission must propagate non-not-found DB errors")

	// Flush pending async audit writes before querying the audit store.
	require.NoError(t, manager.FlushAudit(ctx))

	// Verify RBAC_PERMISSION_CHECK_DB_ERROR audit event was recorded.
	entries, err := manager.QueryAuditEntries(ctx, nil)
	require.NoError(t, err)

	var dbErrorEventFound bool
	for _, entry := range entries {
		if entry.ErrorCode == "RBAC_PERMISSION_CHECK_DB_ERROR" {
			dbErrorEventFound = true
			assert.Equal(t, subjectID, entry.UserID)
			assert.Equal(t, tenantID, entry.TenantID)
			break
		}
	}
	assert.True(t, dbErrorEventFound, "RBAC_PERMISSION_CHECK_DB_ERROR audit event must be recorded when CheckPermission returns a DB error")
}

// TestManager_DeleteRolesByTenant_InvalidatesTenantCache verifies that after
// DeleteRolesByTenant the CacheManager no longer returns cached auth decisions
// for any subject belonging to that tenant.
func TestManager_DeleteRolesByTenant_InvalidatesTenantCache(t *testing.T) {
	ctx := context.Background()
	manager, cm := newTestManagerWithCache(t)

	tenantID := "cache-delete-roles-tenant"
	otherTenantID := "cache-other-tenant"

	// M-AUTH-2: sensitive operations require justification in context
	ctxJ := WithSensitiveOperationJustification(ctx, "test: create role for tenant cache invalidation validation")

	for _, r := range []*common.Role{
		{Id: tenantID + ".role-a", Name: "Role A", TenantId: tenantID},
	} {
		require.NoError(t, manager.CreateRole(ctxJ, r))
	}

	// Prime cache for two different subjects in the target tenant.
	req1 := primeSubjectCache(t, cm, "user1", tenantID)
	req2 := primeSubjectCache(t, cm, "user2", tenantID)

	// Also prime for a subject in a different tenant that must not be affected.
	otherReq := primeSubjectCache(t, cm, "other-user", otherTenantID)

	require.NoError(t, manager.DeleteRolesByTenant(ctx, tenantID))

	assert.Nil(t, cm.GetCachedAuth(req1),
		"user1 cache entry should be nil after DeleteRolesByTenant")
	assert.Nil(t, cm.GetCachedAuth(req2),
		"user2 cache entry should be nil after DeleteRolesByTenant")
	assert.NotNil(t, cm.GetCachedAuth(otherReq),
		"other tenant's cache entry must survive DeleteRolesByTenant")
}

// newInheritanceTestManager builds an initialized Manager backed by real OSS
// storage for the role-inheritance tenant boundary tests (M-TENANT-2).
func newInheritanceTestManager(t *testing.T) *Manager {
	t.Helper()
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
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(stopCtx)
	})
	require.NotNil(t, manager.auditManager, "audit manager must be wired for inheritance audit assertions")
	require.NoError(t, manager.Initialize(context.Background()))
	return manager
}

// TestManager_CreateRole_BlocksCrossTenantInheritance verifies the M-TENANT-2
// security gate in CreateRole: a role whose ParentRoleId resolves to a role in a
// different tenant must be rejected, must not be persisted, and must produce a
// critical RBAC_CROSS_TENANT_INHERITANCE_BLOCKED audit event. This gate prevents
// privilege escalation across tenant boundaries via role inheritance.
func TestManager_CreateRole_BlocksCrossTenantInheritance(t *testing.T) {
	manager := newInheritanceTestManager(t)
	ctx := context.Background()
	// M-AUTH-2: sensitive operations require justification in context
	ctxJ := WithSensitiveOperationJustification(ctx, "test: validate cross-tenant role inheritance is blocked")

	const (
		parentTenant = "tenant-victim"
		childTenant  = "tenant-attacker"
		parentRoleID = "tenant-victim.privileged-role"
		childRoleID  = "tenant-attacker.escalation-role"
	)

	// Privileged role living in the victim tenant.
	require.NoError(t, manager.CreateRole(ctxJ, &common.Role{
		Id:            parentRoleID,
		Name:          "Victim Privileged Role",
		TenantId:      parentTenant,
		PermissionIds: []string{"system.admin"},
	}))

	// Attempt to inherit it from a role owned by a different tenant.
	childRole := &common.Role{
		Id:           childRoleID,
		Name:         "Attacker Escalation Role",
		TenantId:     childTenant,
		ParentRoleId: parentRoleID,
	}
	err := manager.CreateRole(ctxJ, childRole)
	require.Error(t, err, "cross-tenant role inheritance must be rejected")
	assert.Contains(t, err.Error(), "cross-tenant role inheritance not allowed")
	assert.Contains(t, err.Error(), "M-TENANT-2")

	// The child role must not exist in either the ephemeral or durable store.
	_, getErr := manager.GetRole(ctx, childRoleID)
	require.Error(t, getErr, "blocked role must not be persisted")

	childTenantRoles, listErr := manager.ListRoles(ctx, childTenant)
	require.NoError(t, listErr)
	for _, r := range childTenantRoles {
		assert.NotEqual(t, childRoleID, r.Id, "blocked role must not appear in the child tenant's role list")
	}

	// Flush pending async audit writes before querying the audit store.
	require.NoError(t, manager.FlushAudit(ctx))

	entries, queryErr := manager.QueryAuditEntries(ctx, &business.AuditFilter{
		TenantID:      childTenant,
		EventTypes:    []business.AuditEventType{business.AuditEventUserManagement},
		Actions:       []string{"create_role"},
		ResourceTypes: []string{"role"},
		ResourceIDs:   []string{childRoleID},
		Limit:         10,
	})
	require.NoError(t, queryErr)
	require.Len(t, entries, 1, "exactly one audit entry must exist for the blocked role creation")

	entry := entries[0]
	assert.Equal(t, "RBAC_CROSS_TENANT_INHERITANCE_BLOCKED", entry.ErrorCode)
	assert.Equal(t, business.AuditSeverityCritical, entry.Severity,
		"cross-tenant inheritance attempts are security-critical")
	assert.Equal(t, business.AuditResultError, entry.Result)
	assert.Equal(t, childTenant, entry.TenantID)
	assert.Equal(t, childRoleID, entry.ResourceID)
	require.NotNil(t, entry.Details)
	assert.Equal(t, childTenant, entry.Details["child_tenant"])
	assert.Equal(t, parentTenant, entry.Details["parent_tenant"])
	assert.Equal(t, parentRoleID, entry.Details["parent_role_id"])
	assert.Equal(t, "M-TENANT-2", entry.Details["security_finding"])
	assert.True(t, manager.auditManager.VerifyIntegrity(entry),
		"blocked-inheritance audit entry must have a valid integrity checksum")
}

// TestManager_CreateRole_AllowsSameTenantInheritance is the positive control for
// the M-TENANT-2 gate: inheritance within a single tenant must still succeed, so
// the boundary check rejects only genuine cross-tenant escalation attempts.
func TestManager_CreateRole_AllowsSameTenantInheritance(t *testing.T) {
	manager := newInheritanceTestManager(t)
	ctx := context.Background()
	// M-AUTH-2: sensitive operations require justification in context
	ctxJ := WithSensitiveOperationJustification(ctx, "test: validate same-tenant role inheritance is permitted")

	const (
		tenantID     = "tenant-single"
		parentRoleID = "tenant-single.parent-role"
		childRoleID  = "tenant-single.child-role"
	)

	require.NoError(t, manager.CreateRole(ctxJ, &common.Role{
		Id:            parentRoleID,
		Name:          "Parent Role",
		TenantId:      tenantID,
		PermissionIds: []string{"config.read"},
	}))

	require.NoError(t, manager.CreateRole(ctxJ, &common.Role{
		Id:           childRoleID,
		Name:         "Child Role",
		TenantId:     tenantID,
		ParentRoleId: parentRoleID,
	}))

	stored, err := manager.GetRole(ctx, childRoleID)
	require.NoError(t, err, "same-tenant inheritance must be permitted")
	assert.Equal(t, parentRoleID, stored.ParentRoleId)
	assert.Equal(t, tenantID, stored.TenantId)
}

// TestManager_CreateRole_BlocksInheritanceFromMissingParent verifies the sibling
// branch of the M-TENANT-2 gate: an unresolvable ParentRoleId is rejected before
// the role is stored and records a high-severity RBAC_PARENT_ROLE_NOT_FOUND event.
func TestManager_CreateRole_BlocksInheritanceFromMissingParent(t *testing.T) {
	manager := newInheritanceTestManager(t)
	ctx := context.Background()
	// M-AUTH-2: sensitive operations require justification in context
	ctxJ := WithSensitiveOperationJustification(ctx, "test: validate unresolvable parent role is rejected")

	const (
		tenantID    = "tenant-missing-parent"
		childRoleID = "tenant-missing-parent.child-role"
	)

	err := manager.CreateRole(ctxJ, &common.Role{
		Id:           childRoleID,
		Name:         "Orphan Child Role",
		TenantId:     tenantID,
		ParentRoleId: "does-not-exist",
	})
	require.Error(t, err, "inheritance from a non-existent parent must be rejected")
	assert.Contains(t, err.Error(), "parent role does-not-exist not found")

	_, getErr := manager.GetRole(ctx, childRoleID)
	require.Error(t, getErr, "rejected role must not be persisted")

	require.NoError(t, manager.FlushAudit(ctx))

	entries, queryErr := manager.QueryAuditEntries(ctx, &business.AuditFilter{
		TenantID:      tenantID,
		EventTypes:    []business.AuditEventType{business.AuditEventUserManagement},
		Actions:       []string{"create_role"},
		ResourceTypes: []string{"role"},
		ResourceIDs:   []string{childRoleID},
		Limit:         10,
	})
	require.NoError(t, queryErr)
	require.Len(t, entries, 1, "exactly one audit entry must exist for the rejected role creation")

	entry := entries[0]
	assert.Equal(t, "RBAC_PARENT_ROLE_NOT_FOUND", entry.ErrorCode)
	assert.Equal(t, business.AuditSeverityHigh, entry.Severity)
	assert.Equal(t, business.AuditResultError, entry.Result)
	assert.Equal(t, "does-not-exist", entry.Details["parent_role_id"])
}
