// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rbac

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"

	// Import storage providers to register them
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// TestRBACManager_AuditIntegration tests that RBAC operations generate proper audit events
func TestRBACManager_AuditIntegration(t *testing.T) {
	// Setup git storage provider for testing
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	// Create RBAC manager with audit integration
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
	require.NotNil(t, manager)
	require.NotNil(t, manager.auditManager)

	ctx := context.Background()
	err = manager.Initialize(ctx)
	require.NoError(t, err)

	// Issue #764: audit writes are now asynchronous. Tests that query the audit
	// store must Flush first to guarantee pending entries have landed. Drain
	// shutdown is handled by manager.Close cleanup registered above (Issue #848).
	flushAudit := func(t *testing.T) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, manager.auditManager.Flush(ctx))
	}

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
		auditFilter := &business.AuditFilter{
			TenantID:      "test-tenant",
			EventTypes:    []business.AuditEventType{business.AuditEventUserManagement},
			Actions:       []string{"create_role"},
			ResourceTypes: []string{"role"},
			ResourceIDs:   []string{"test-role-audit"},
			Limit:         10,
		}

		flushAudit(t)
		auditEntries, err := manager.auditManager.QueryEntries(ctx, auditFilter)
		require.NoError(t, err)
		require.Len(t, auditEntries, 1, "Should have exactly one audit entry for role creation")

		entry := auditEntries[0]
		assert.Equal(t, "test-tenant", entry.TenantID)
		assert.Equal(t, business.AuditEventUserManagement, entry.EventType)
		assert.Equal(t, "create_role", entry.Action)
		assert.Equal(t, "role", entry.ResourceType)
		assert.Equal(t, "test-role-audit", entry.ResourceID)
		assert.Equal(t, business.AuditResultSuccess, entry.Result)
		assert.Equal(t, business.AuditSeverityHigh, entry.Severity)
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
		auditFilter := &business.AuditFilter{
			TenantID:      "test-tenant",
			EventTypes:    []business.AuditEventType{business.AuditEventUserManagement},
			Actions:       []string{"update_role"},
			ResourceTypes: []string{"role"},
			ResourceIDs:   []string{"test-role-update-audit"},
			Limit:         10,
		}

		flushAudit(t)
		auditEntries, err := manager.auditManager.QueryEntries(ctx, auditFilter)
		require.NoError(t, err)
		require.Len(t, auditEntries, 1, "Should have exactly one audit entry for role update")

		entry := auditEntries[0]
		assert.Equal(t, "update_role", entry.Action)
		assert.Equal(t, business.AuditResultSuccess, entry.Result)

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
		auditFilter := &business.AuditFilter{
			TenantID:      "test-tenant",
			EventTypes:    []business.AuditEventType{business.AuditEventUserManagement},
			Actions:       []string{"delete_role"},
			ResourceTypes: []string{"role"},
			ResourceIDs:   []string{"test-role-delete-audit"},
			Limit:         10,
		}

		flushAudit(t)
		auditEntries, err := manager.auditManager.QueryEntries(ctx, auditFilter)
		require.NoError(t, err)
		require.Len(t, auditEntries, 1, "Should have exactly one audit entry for role deletion")

		entry := auditEntries[0]
		assert.Equal(t, "delete_role", entry.Action)
		assert.Equal(t, business.AuditResultSuccess, entry.Result)
		assert.Equal(t, business.AuditSeverityCritical, entry.Severity, "Role deletion should be critical severity")

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
		auditFilter := &business.AuditFilter{
			TenantID:      "test-tenant",
			EventTypes:    []business.AuditEventType{business.AuditEventUserManagement},
			Actions:       []string{"revoke_role"},
			ResourceTypes: []string{"role_assignment"},
			Limit:         10,
		}

		flushAudit(t)
		auditEntries, err := manager.auditManager.QueryEntries(ctx, auditFilter)
		require.NoError(t, err)
		require.Len(t, auditEntries, 1, "Should have exactly one audit entry for role revocation")

		entry := auditEntries[0]
		assert.Equal(t, "revoke_role", entry.Action)
		assert.Equal(t, "test-user-revoke", entry.UserID)
		assert.Equal(t, business.AuditResultSuccess, entry.Result)
		assert.Equal(t, business.AuditSeverityHigh, entry.Severity)

		// Verify revocation details
		assert.Contains(t, entry.Details, "revoked_role")
		assert.Contains(t, entry.Details, "subject_id")
		assert.Equal(t, "test-role-revoke", entry.Details["revoked_role"])
		assert.Equal(t, "test-user-revoke", entry.Details["subject_id"])
	})

	t.Run("Failed operations generate error audit events", func(t *testing.T) {
		// Use a case that deterministically fails at the manager level:
		// a role claiming a non-existent parent triggers the explicit error
		// path in Manager.CreateRole (RBAC_PARENT_ROLE_NOT_FOUND), which
		// synchronously emits an error audit event.
		invalidRole := &common.Role{
			Id:           "test-role-parent-missing",
			Name:         "Role with missing parent",
			TenantId:     "test-tenant",
			ParentRoleId: "does-not-exist",
		}

		err := manager.CreateRole(ctx, invalidRole)
		require.Error(t, err, "CreateRole must return an error when parent role does not exist")
		require.Contains(t, err.Error(), "not found")

		auditFilter := &business.AuditFilter{
			TenantID:    "test-tenant",
			EventTypes:  []business.AuditEventType{business.AuditEventUserManagement},
			Actions:     []string{"create_role"},
			Results:     []business.AuditResult{business.AuditResultError},
			ResourceIDs: []string{"test-role-parent-missing"},
			Limit:       10,
		}

		flushAudit(t)
		auditEntries, err := manager.auditManager.QueryEntries(ctx, auditFilter)
		require.NoError(t, err)
		require.Len(t, auditEntries, 1, "failed CreateRole must produce exactly one error audit entry")

		entry := auditEntries[0]
		assert.Equal(t, business.AuditResultError, entry.Result)
		assert.Equal(t, "RBAC_PARENT_ROLE_NOT_FOUND", entry.ErrorCode)
		assert.NotEmpty(t, entry.ErrorMessage)
	})

	t.Run("Audit entries maintain integrity", func(t *testing.T) {
		// Query all audit entries we've created
		auditFilter := &business.AuditFilter{
			TenantID:   "test-tenant",
			EventTypes: []business.AuditEventType{business.AuditEventUserManagement},
			Limit:      100,
		}

		flushAudit(t)
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
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	// Create manager but then simulate audit failure by setting auditManager to nil
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
		tmpDir := t.TempDir()
		storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
		require.NoError(t, err)
		t.Cleanup(func() { _ = storageManager.Close() })

		// Create a properly configured manager (audit manager is always present in Epic 6)
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
