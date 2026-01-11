// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"

	// Import storage providers for testing
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

func TestRBACService_Integration(t *testing.T) {
	// Setup RBAC manager and service with git storage
	config := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":          "main",
		"auto_init":       true,
	}
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
	require.NoError(t, err)

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	ctx := context.Background()

	err = rbacManager.Initialize(ctx)
	require.NoError(t, err)

	tenantID := "test-tenant"
	err = rbacManager.CreateTenantDefaultRoles(ctx, tenantID)
	require.NoError(t, err)

	service := NewRBACService(rbacManager)

	t.Run("permission_management", func(t *testing.T) {
		// List permissions
		listResp, err := service.ListPermissions(ctx, &controller.ListPermissionsRequest{
			ResourceType: "steward",
		})
		require.NoError(t, err)
		assert.NotEmpty(t, listResp.Permissions)

		// Get specific permission
		getResp, err := service.GetPermission(ctx, &controller.GetPermissionRequest{
			PermissionId: "steward.register",
		})
		require.NoError(t, err)
		assert.Equal(t, "steward.register", getResp.Permission.Id)
		assert.Equal(t, "Register Steward", getResp.Permission.Name)
	})

	t.Run("role_management", func(t *testing.T) {
		// Create a custom role
		customRole := &common.Role{
			Id:            tenantID + ".custom.role",
			Name:          "Custom Role",
			Description:   "A test custom role",
			PermissionIds: []string{"steward.read", "config.read"},
			TenantId:      tenantID,
		}

		createResp, err := service.CreateRole(ctx, &controller.CreateRoleRequest{
			Role: customRole,
		})
		require.NoError(t, err)
		assert.Equal(t, customRole.Id, createResp.Role.Id)

		// Get the role
		getResp, err := service.GetRole(ctx, &controller.GetRoleRequest{
			RoleId: customRole.Id,
		})
		require.NoError(t, err)
		assert.Equal(t, customRole.Name, getResp.Role.Name)

		// List roles for tenant
		listResp, err := service.ListRoles(ctx, &controller.ListRolesRequest{
			TenantId: tenantID,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, listResp.Roles)

		// Find our custom role in the list
		found := false
		for _, role := range listResp.Roles {
			if role.Id == customRole.Id {
				found = true
				break
			}
		}
		assert.True(t, found, "Custom role should be in the list")

		// Update the role
		customRole.Description = "Updated description"
		updateResp, err := service.UpdateRole(ctx, &controller.UpdateRoleRequest{
			Role: customRole,
		})
		require.NoError(t, err)
		assert.Equal(t, "Updated description", updateResp.Role.Description)

		// Delete the role
		// M-AUTH-2: Provide justification for sensitive delete operation
		deleteResp, err := service.DeleteRole(ctx, &controller.DeleteRoleRequest{
			RoleId:        customRole.Id,
			Justification: "Test role deletion for integration testing",
		})
		require.NoError(t, err)
		assert.True(t, deleteResp.Success)

		// Verify role is deleted
		_, err = service.GetRole(ctx, &controller.GetRoleRequest{
			RoleId: customRole.Id,
		})
		assert.Error(t, err)
	})

	t.Run("subject_management", func(t *testing.T) {
		// Create a subject
		subject := &common.Subject{
			Id:          "test-user-1",
			Type:        common.SubjectType_SUBJECT_TYPE_USER,
			DisplayName: "Test User One",
			TenantId:    tenantID,
			IsActive:    true,
			Attributes: map[string]string{
				"department": "engineering",
			},
		}

		createResp, err := service.CreateSubject(ctx, &controller.CreateSubjectRequest{
			Subject: subject,
		})
		require.NoError(t, err)
		assert.Equal(t, subject.Id, createResp.Subject.Id)

		// Get the subject
		getResp, err := service.GetSubject(ctx, &controller.GetSubjectRequest{
			SubjectId: subject.Id,
		})
		require.NoError(t, err)
		assert.Equal(t, subject.DisplayName, getResp.Subject.DisplayName)

		// List subjects
		listResp, err := service.ListSubjects(ctx, &controller.ListSubjectsRequest{
			TenantId: tenantID,
			Type:     common.SubjectType_SUBJECT_TYPE_USER,
		})
		require.NoError(t, err)
		assert.Len(t, listResp.Subjects, 1)
		assert.Equal(t, subject.Id, listResp.Subjects[0].Id)

		// Update subject
		subject.DisplayName = "Updated Test User"
		updateResp, err := service.UpdateSubject(ctx, &controller.UpdateSubjectRequest{
			Subject: subject,
		})
		require.NoError(t, err)
		assert.Equal(t, "Updated Test User", updateResp.Subject.DisplayName)

		// Delete subject
		deleteResp, err := service.DeleteSubject(ctx, &controller.DeleteSubjectRequest{
			SubjectId: subject.Id,
		})
		require.NoError(t, err)
		assert.True(t, deleteResp.Success)
	})

	t.Run("role_assignment_and_permission_checking", func(t *testing.T) {
		// Create a test subject
		subject := &common.Subject{
			Id:          "test-user-2",
			Type:        common.SubjectType_SUBJECT_TYPE_USER,
			DisplayName: "Test User Two",
			TenantId:    tenantID,
			IsActive:    true,
		}

		_, err := service.CreateSubject(ctx, &controller.CreateSubjectRequest{
			Subject: subject,
		})
		require.NoError(t, err)

		// Assign tenant admin role
		assignment := &common.RoleAssignment{
			SubjectId: subject.Id,
			RoleId:    tenantID + ".tenant.admin",
			TenantId:  tenantID,
		}

		assignResp, err := service.AssignRole(ctx, &controller.AssignRoleRequest{
			Assignment: assignment,
		})
		require.NoError(t, err)
		assert.Equal(t, assignment.SubjectId, assignResp.Assignment.SubjectId)

		// Get subject roles
		rolesResp, err := service.GetSubjectRoles(ctx, &controller.GetSubjectRolesRequest{
			SubjectId: subject.Id,
			TenantId:  tenantID,
		})
		require.NoError(t, err)
		assert.Len(t, rolesResp.Roles, 1)
		assert.Equal(t, tenantID+".tenant.admin", rolesResp.Roles[0].Id)

		// Check permission
		checkResp, err := service.CheckPermission(ctx, &controller.CheckPermissionRequest{
			Request: &common.AccessRequest{
				SubjectId:    subject.Id,
				PermissionId: "config.read",
				TenantId:     tenantID,
			},
		})
		require.NoError(t, err)
		assert.True(t, checkResp.Response.Granted)
		assert.NotEmpty(t, checkResp.Response.Reason)

		// Get subject permissions
		permsResp, err := service.GetSubjectPermissions(ctx, &controller.GetSubjectPermissionsRequest{
			SubjectId: subject.Id,
			TenantId:  tenantID,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, permsResp.Permissions)

		// Verify specific permissions exist
		permissionIDs := make(map[string]bool)
		for _, perm := range permsResp.Permissions {
			permissionIDs[perm.Id] = true
		}
		assert.True(t, permissionIDs["config.read"], "Should have config.read permission")
		assert.True(t, permissionIDs["steward.read"], "Should have steward.read permission")

		// Revoke role
		revokeResp, err := service.RevokeRole(ctx, &controller.RevokeRoleRequest{
			SubjectId: subject.Id,
			RoleId:    tenantID + ".tenant.admin",
			TenantId:  tenantID,
		})
		require.NoError(t, err)
		assert.True(t, revokeResp.Success)

		// Verify role was revoked
		rolesResp, err = service.GetSubjectRoles(ctx, &controller.GetSubjectRolesRequest{
			SubjectId: subject.Id,
			TenantId:  tenantID,
		})
		require.NoError(t, err)
		assert.Len(t, rolesResp.Roles, 0)

		// Verify permission is now denied
		checkResp, err = service.CheckPermission(ctx, &controller.CheckPermissionRequest{
			Request: &common.AccessRequest{
				SubjectId:    subject.Id,
				PermissionId: "config.read",
				TenantId:     tenantID,
			},
		})
		require.NoError(t, err)
		assert.False(t, checkResp.Response.Granted)
	})

	t.Run("validation_errors", func(t *testing.T) {
		// Test missing permission ID
		_, err := service.GetPermission(ctx, &controller.GetPermissionRequest{})
		assert.Error(t, err)

		// Test missing role ID
		_, err = service.GetRole(ctx, &controller.GetRoleRequest{})
		assert.Error(t, err)

		// Test missing subject ID
		_, err = service.GetSubject(ctx, &controller.GetSubjectRequest{})
		assert.Error(t, err)

		// Test missing assignment data
		_, err = service.AssignRole(ctx, &controller.AssignRoleRequest{})
		assert.Error(t, err)

		// Test missing access request data
		_, err = service.CheckPermission(ctx, &controller.CheckPermissionRequest{})
		assert.Error(t, err)
	})
}
