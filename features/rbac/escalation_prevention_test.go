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

// TestEscalationOperationType_Constants verifies that EscalationOperationType constants
// have the expected string values after the rename from OperationType.
func TestEscalationOperationType_Constants(t *testing.T) {
	assert.Equal(t, EscalationOperationType("role_assignment"), EscalationOpTypeRoleAssignment)
	assert.Equal(t, EscalationOperationType("role_revocation"), EscalationOpTypeRoleRevocation)
	assert.Equal(t, EscalationOperationType("role_parent_set"), EscalationOpTypeRoleParentSet)
	assert.Equal(t, EscalationOperationType("role_parent_remove"), EscalationOpTypeRoleParentRemove)
	assert.Equal(t, EscalationOperationType("permission_check"), EscalationOpTypePermissionCheck)
}

// TestEscalationOperationType_DistinctType verifies EscalationOperationType is its own type.
func TestEscalationOperationType_DistinctType(t *testing.T) {
	et := EscalationOpTypeRoleAssignment
	assert.Equal(t, "role_assignment", string(et))
}

// TestNewEscalationPreventionManager_AcceptsStoreAccessor verifies that
// NewEscalationPreventionManager accepts a separate RBACStoreAccessor argument
// and that *Manager satisfies both RBACManager and RBACStoreAccessor.
func TestNewEscalationPreventionManager_AcceptsStoreAccessor(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	t.Cleanup(func() {
		_ = manager.Close(ctx)
	})

	// *Manager satisfies both RBACManager and RBACStoreAccessor; construction must not panic.
	epm := NewEscalationPreventionManager(manager, manager)
	require.NotNil(t, epm)

	// Verify the manager's GetStore accessor satisfies the interface.
	var _ RBACStoreAccessor = manager
}

// TestValidateAndSetRoleParent_NoTypeAssertion verifies that ValidateAndSetRoleParent
// works correctly when called through the Manager (which routes through
// escalationPreventionMgr). This confirms the storeAccessor path works end-to-end
// without a type assertion to *Manager.
func TestValidateAndSetRoleParent_NoTypeAssertion(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t.Cleanup(func() {
		_ = manager.Close(ctx)
	})

	require.NoError(t, manager.Initialize(ctx))

	// Create two roles so we can establish a parent-child relationship.
	parentRole := &common.Role{
		Id:          "test-parent-role",
		Name:        "Test Parent Role",
		TenantId:    "tenant-1",
		Description: "Parent role for hierarchy test",
	}
	childRole := &common.Role{
		Id:          "test-child-role",
		Name:        "Test Child Role",
		TenantId:    "tenant-1",
		Description: "Child role for hierarchy test",
	}

	ctxWithJustification := WithSensitiveOperationJustification(ctx, "test: creating roles for hierarchy test")
	require.NoError(t, manager.CreateRole(ctxWithJustification, parentRole))
	require.NoError(t, manager.CreateRole(ctxWithJustification, childRole))

	// SetRoleParent routes through Manager.SetRoleParent → escalationPreventionMgr.ValidateAndSetRoleParent
	// → storeAccessor.GetStore().SetRoleParent (no type assertion to *Manager).
	err = manager.SetRoleParent(ctx, childRole.Id, parentRole.Id, common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE)
	require.NoError(t, err)

	// Verify the parent was set.
	parent, err := manager.GetParentRole(ctx, childRole.Id)
	require.NoError(t, err)
	assert.Equal(t, parentRole.Id, parent.Id)
}

// TestOperationLog_UsesEscalationOperationType verifies that the operation log
// records operations using EscalationOperationType values.
func TestOperationLog_UsesEscalationOperationType(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t.Cleanup(func() {
		_ = manager.Close(ctx)
	})

	require.NoError(t, manager.Initialize(ctx))

	// Create a simple role and a subject, then assign the role to generate a log entry.
	ctxWithJustification := WithSensitiveOperationJustification(ctx, "test: creating roles and assigning for log verification")
	testRole := &common.Role{
		Id:       "test-role-log",
		Name:     "Test Role Log",
		TenantId: "tenant-log",
	}
	require.NoError(t, manager.CreateRole(ctxWithJustification, testRole))

	subjectID := "test-subject-log"
	subject := &common.Subject{
		Id:       subjectID,
		Type:     common.SubjectType_SUBJECT_TYPE_USER,
		TenantId: "tenant-log",
		IsActive: true,
	}
	require.NoError(t, manager.CreateSubject(ctx, subject))

	assignment := &common.RoleAssignment{
		SubjectId: subjectID,
		RoleId:    testRole.Id,
		TenantId:  "tenant-log",
	}
	require.NoError(t, manager.AssignRole(ctxWithJustification, assignment))

	// The operation log must contain at least one entry with EscalationOpTypeRoleAssignment.
	log := manager.GetOperationLog()
	require.NotEmpty(t, log, "operation log must not be empty after role assignment")

	var found bool
	for _, entry := range log {
		if entry.Type == EscalationOpTypeRoleAssignment {
			found = true
			break
		}
	}
	assert.True(t, found, "operation log must contain an EscalationOpTypeRoleAssignment entry")
}
