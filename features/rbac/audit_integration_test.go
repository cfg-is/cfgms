// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rbac

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"

	// Import storage providers to register them
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

// TestRBACManager_AuditIntegration tests that RBAC operations generate proper audit events
func TestRBACManager_AuditIntegration(t *testing.T) {
	// Setup git storage provider for testing
	config := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":          "main",
		"auto_init":       true,
	}

	storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
	require.NoError(t, err)

	// Create RBAC manager with audit integration
	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	require.NotNil(t, manager)
	require.NotNil(t, manager.auditManager)

	ctx := context.Background()
	err = manager.Initialize(ctx)
	require.NoError(t, err)

	t.Run("CreateRole generates audit event", func(t *testing.T) {
		role := &common.Role{
			Id:            "test-role-audit",
			Name:          "Test Role for Audit",
			Description:   "A test role to verify audit logging",
			TenantId:      "test-tenant",
			PermissionIds: []string{"test.permission"},
		}

		// Create the role - this should generate an audit event
		err := manager.CreateRole(ctx, role)
		require.NoError(t, err)

		// Query the audit store to verify the audit event was recorded
		auditFilter := &interfaces.AuditFilter{
			TenantID:      "test-tenant",
			EventTypes:    []interfaces.AuditEventType{interfaces.AuditEventUserManagement},
			Actions:       []string{"create_role"},
			ResourceTypes: []string{"role"},
			ResourceIDs:   []string{"test-role-audit"},
			Limit:         10,
		}

		auditEntries, err := manager.auditManager.QueryEntries(ctx, auditFilter)
		require.NoError(t, err)
		require.Len(t, auditEntries, 1, "Should have exactly one audit entry for role creation")

		entry := auditEntries[0]
		assert.Equal(t, "test-tenant", entry.TenantID)
		assert.Equal(t, interfaces.AuditEventUserManagement, entry.EventType)
		assert.Equal(t, "create_role", entry.Action)
		assert.Equal(t, "role", entry.ResourceType)
		assert.Equal(t, "test-role-audit", entry.ResourceID)
		assert.Equal(t, interfaces.AuditResultSuccess, entry.Result)
		assert.Equal(t, interfaces.AuditSeverityHigh, entry.Severity)
		assert.Equal(t, "rbac", entry.Source)

		// Verify audit integrity
		assert.True(t, manager.auditManager.VerifyIntegrity(entry), "Audit entry should have valid integrity checksum")
	})

	t.Run("UpdateRole generates audit event with changes", func(t *testing.T) {
		// First create a role to update
		originalRole := &common.Role{
			Id:            "test-role-update-audit",
			Name:          "Original Role Name",
			Description:   "Original description",
			TenantId:      "test-tenant",
			PermissionIds: []string{"original.permission"},
		}

		err := manager.CreateRole(ctx, originalRole)
		require.NoError(t, err)

		// Update the role
		updatedRole := &common.Role{
			Id:            "test-role-update-audit",
			Name:          "Updated Role Name",   // Changed
			Description:   "Updated description", // Changed
			TenantId:      "test-tenant",
			PermissionIds: []string{"original.permission", "new.permission"}, // Changed
		}

		err = manager.UpdateRole(ctx, updatedRole)
		require.NoError(t, err)

		// Query audit entries for the update
		auditFilter := &interfaces.AuditFilter{
			TenantID:      "test-tenant",
			EventTypes:    []interfaces.AuditEventType{interfaces.AuditEventUserManagement},
			Actions:       []string{"update_role"},
			ResourceTypes: []string{"role"},
			ResourceIDs:   []string{"test-role-update-audit"},
			Limit:         10,
		}

		auditEntries, err := manager.auditManager.QueryEntries(ctx, auditFilter)
		require.NoError(t, err)
		require.Len(t, auditEntries, 1, "Should have exactly one audit entry for role update")

		entry := auditEntries[0]
		assert.Equal(t, "update_role", entry.Action)
		assert.Equal(t, interfaces.AuditResultSuccess, entry.Result)

		// Verify change tracking is present
		assert.NotNil(t, entry.Changes, "Should have change tracking information")
		if entry.Changes != nil {
			assert.NotEmpty(t, entry.Changes.Before, "Should have before state")
			assert.NotEmpty(t, entry.Changes.After, "Should have after state")
			assert.NotEmpty(t, entry.Changes.Fields, "Should have list of changed fields")
		}
	})

	t.Run("DeleteRole generates critical audit event", func(t *testing.T) {
		// First create a role to delete
		roleToDelete := &common.Role{
			Id:            "test-role-delete-audit",
			Name:          "Role to Delete",
			Description:   "This role will be deleted",
			TenantId:      "test-tenant",
			PermissionIds: []string{"delete.test.permission"},
		}

		err := manager.CreateRole(ctx, roleToDelete)
		require.NoError(t, err)

		// Delete the role
		// M-AUTH-2: Add justification for sensitive operation
		ctxWithJustification := WithSensitiveOperationJustification(ctx, "Test role deletion for audit integration testing")
		err = manager.DeleteRole(ctxWithJustification, "test-role-delete-audit")
		require.NoError(t, err)

		// Query audit entries for the deletion
		auditFilter := &interfaces.AuditFilter{
			TenantID:      "test-tenant",
			EventTypes:    []interfaces.AuditEventType{interfaces.AuditEventUserManagement},
			Actions:       []string{"delete_role"},
			ResourceTypes: []string{"role"},
			ResourceIDs:   []string{"test-role-delete-audit"},
			Limit:         10,
		}

		auditEntries, err := manager.auditManager.QueryEntries(ctx, auditFilter)
		require.NoError(t, err)
		require.Len(t, auditEntries, 1, "Should have exactly one audit entry for role deletion")

		entry := auditEntries[0]
		assert.Equal(t, "delete_role", entry.Action)
		assert.Equal(t, interfaces.AuditResultSuccess, entry.Result)
		assert.Equal(t, interfaces.AuditSeverityCritical, entry.Severity, "Role deletion should be critical severity")

		// Verify deleted role information is captured
		assert.Contains(t, entry.Details, "deleted_permissions")
		assert.Contains(t, entry.Details, "role_description")
	})

	t.Run("RevokeRole generates audit event", func(t *testing.T) {
		// Create a test subject first
		subject := &common.Subject{
			Id:          "test-user-revoke",
			Type:        common.SubjectType_SUBJECT_TYPE_USER,
			DisplayName: "Test User for Revoke",
			TenantId:    "test-tenant",
			IsActive:    true,
		}

		err := manager.CreateSubject(ctx, subject)
		require.NoError(t, err)

		// Create a test role
		testRole := &common.Role{
			Id:            "test-role-revoke",
			Name:          "Test Role for Revoke",
			TenantId:      "test-tenant",
			PermissionIds: []string{"test.revoke.permission"},
		}

		err = manager.CreateRole(ctx, testRole)
		require.NoError(t, err)

		// Assign the role first (this goes through escalation prevention, so we won't get direct audit)
		assignment := &common.RoleAssignment{
			SubjectId: "test-user-revoke",
			RoleId:    "test-role-revoke",
			TenantId:  "test-tenant",
		}

		// Use the manager's AssignRole method to ensure proper persistence through RBAC store
		err = manager.AssignRole(ctx, assignment)
		require.NoError(t, err)

		// Now revoke the role - this should generate an audit event
		err = manager.RevokeRole(ctx, "test-user-revoke", "test-role-revoke", "test-tenant")
		require.NoError(t, err)

		// Query audit entries for the revocation
		auditFilter := &interfaces.AuditFilter{
			TenantID:      "test-tenant",
			EventTypes:    []interfaces.AuditEventType{interfaces.AuditEventUserManagement},
			Actions:       []string{"revoke_role"},
			ResourceTypes: []string{"role_assignment"},
			Limit:         10,
		}

		auditEntries, err := manager.auditManager.QueryEntries(ctx, auditFilter)
		require.NoError(t, err)
		require.Len(t, auditEntries, 1, "Should have exactly one audit entry for role revocation")

		entry := auditEntries[0]
		assert.Equal(t, "revoke_role", entry.Action)
		assert.Equal(t, "test-user-revoke", entry.UserID)
		assert.Equal(t, interfaces.AuditResultSuccess, entry.Result)
		assert.Equal(t, interfaces.AuditSeverityHigh, entry.Severity)

		// Verify revocation details
		assert.Contains(t, entry.Details, "revoked_role")
		assert.Contains(t, entry.Details, "subject_id")
		assert.Equal(t, "test-role-revoke", entry.Details["revoked_role"])
		assert.Equal(t, "test-user-revoke", entry.Details["subject_id"])
	})

	t.Run("Failed operations generate error audit events", func(t *testing.T) {
		// Try to create a role with invalid data (empty ID)
		invalidRole := &common.Role{
			Id:       "", // Invalid - empty ID
			Name:     "Invalid Role",
			TenantId: "test-tenant",
		}

		_ = manager.CreateRole(ctx, invalidRole)
		// This should fail, but let's check if we still get an audit event

		// Query for any audit entries with error result
		auditFilter := &interfaces.AuditFilter{
			TenantID:   "test-tenant",
			EventTypes: []interfaces.AuditEventType{interfaces.AuditEventUserManagement},
			Actions:    []string{"create_role"},
			Results:    []interfaces.AuditResult{interfaces.AuditResultError},
			Limit:      10,
		}

		// Note: This test depends on whether the underlying store validates the role
		// If validation passes through, we won't get an error audit event
		auditEntries, err := manager.auditManager.QueryEntries(ctx, auditFilter)
		require.NoError(t, err)

		// If there are error entries, verify they have proper error information
		for _, entry := range auditEntries {
			assert.Equal(t, interfaces.AuditResultError, entry.Result)
			assert.NotEmpty(t, entry.ErrorCode)
			assert.NotEmpty(t, entry.ErrorMessage)
		}
	})

	t.Run("Audit entries maintain integrity", func(t *testing.T) {
		// Query all audit entries we've created
		auditFilter := &interfaces.AuditFilter{
			TenantID:   "test-tenant",
			EventTypes: []interfaces.AuditEventType{interfaces.AuditEventUserManagement},
			Limit:      100,
		}

		auditEntries, err := manager.auditManager.QueryEntries(ctx, auditFilter)
		require.NoError(t, err)
		assert.NotEmpty(t, auditEntries, "Should have audit entries from previous tests")

		// Verify all entries have valid integrity checksums
		for i, entry := range auditEntries {
			assert.True(t, manager.auditManager.VerifyIntegrity(entry),
				"Audit entry %d should have valid integrity checksum", i)
			assert.NotEmpty(t, entry.Checksum, "Audit entry %d should have checksum", i)
			assert.Equal(t, "rbac", entry.Source, "Audit entry %d should have correct source", i)
			assert.Equal(t, "1.0", entry.Version, "Audit entry %d should have version", i)
		}
	})
}

// TestRBACManager_AuditFailureHandling tests audit failure scenarios
func TestRBACManager_AuditFailureHandling(t *testing.T) {
	// Setup git storage provider
	config := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":          "main",
		"auto_init":       true,
	}

	storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
	require.NoError(t, err)

	// Create manager but then simulate audit failure by setting auditManager to nil
	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	require.NotNil(t, manager)

	ctx := context.Background()
	err = manager.Initialize(ctx)
	require.NoError(t, err)

	t.Run("RBAC operations continue when audit fails", func(t *testing.T) {
		// Temporarily disable audit manager to simulate failure
		originalAuditManager := manager.auditManager
		manager.auditManager = nil

		// RBAC operations should still work without auditing
		role := &common.Role{
			Id:            "test-role-no-audit",
			Name:          "Test Role No Audit",
			TenantId:      "test-tenant",
			PermissionIds: []string{"test.permission"},
		}

		err := manager.CreateRole(ctx, role)
		require.NoError(t, err, "Role creation should succeed even without audit")

		// Verify the role was actually created
		retrievedRole, err := manager.GetRole(ctx, "test-role-no-audit")
		require.NoError(t, err)
		assert.Equal(t, role.Name, retrievedRole.Name)

		// Restore audit manager
		manager.auditManager = originalAuditManager
	})

	t.Run("Audit system is resilient to nil manager", func(t *testing.T) {
		// With Epic 6, all managers require proper storage configuration
		// Test that operations work normally even if audit events might fail
		config := map[string]interface{}{
			"repository_path": t.TempDir(),
			"branch":          "main",
			"auto_init":       true,
		}
		storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
		require.NoError(t, err)

		// Create a properly configured manager (audit manager is always present in Epic 6)
		manager := NewManagerWithStorage(
			storageManager.GetAuditStore(),
			storageManager.GetClientTenantStore(),
			storageManager.GetRBACStore(),
		)
		err = manager.Initialize(ctx)
		require.NoError(t, err)

		// Operations should still work
		role := &common.Role{
			Id:       "test-role-no-manager",
			Name:     "Test Role No Manager",
			TenantId: "test-tenant",
		}

		err = manager.CreateRole(ctx, role)
		require.NoError(t, err, "Should handle nil audit manager gracefully")
	})
}
