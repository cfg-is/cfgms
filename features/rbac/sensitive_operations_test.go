// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package rbac - Tests for sensitive operation controls
package rbac

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestValidateSensitiveOperation tests validation of sensitive operations
func TestValidateSensitiveOperation(t *testing.T) {
	tests := []struct {
		name    string
		opCtx   *SensitiveOperationContext
		wantErr bool
		errType error
	}{
		{
			name: "valid operation with justification",
			opCtx: &SensitiveOperationContext{
				OperationType: SensitiveOpDeleteRole,
				SubjectID:     "user-123",
				TenantID:      "tenant-123",
				ResourceID:    "role-456",
				Justification: "Removing deprecated role per security policy v2.1",
			},
			wantErr: false,
		},
		{
			name: "missing justification",
			opCtx: &SensitiveOperationContext{
				OperationType: SensitiveOpDeleteRole,
				SubjectID:     "user-123",
				TenantID:      "tenant-123",
				ResourceID:    "role-456",
				Justification: "",
			},
			wantErr: true,
			errType: ErrJustificationRequired,
		},
		{
			name: "justification too short",
			opCtx: &SensitiveOperationContext{
				OperationType: SensitiveOpDeleteRole,
				SubjectID:     "user-123",
				TenantID:      "tenant-123",
				ResourceID:    "role-456",
				Justification: "short",
			},
			wantErr: true,
		},
		{
			name: "justification too long",
			opCtx: &SensitiveOperationContext{
				OperationType: SensitiveOpDeleteRole,
				SubjectID:     "user-123",
				TenantID:      "tenant-123",
				ResourceID:    "role-456",
				Justification: string(make([]byte, 1001)), // 1001 characters
			},
			wantErr: true,
		},
		{
			name:    "nil operation context",
			opCtx:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSensitiveOperation(tt.opCtx)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestIsSensitiveOperation tests sensitive operation detection
func TestIsSensitiveOperation(t *testing.T) {
	tests := []struct {
		name     string
		opType   SensitiveOperationType
		expected bool
	}{
		{
			name:     "create role is sensitive",
			opType:   SensitiveOpCreateRole,
			expected: true,
		},
		{
			name:     "delete role is sensitive",
			opType:   SensitiveOpDeleteRole,
			expected: true,
		},
		{
			name:     "bulk delete is sensitive",
			opType:   SensitiveOpBulkDelete,
			expected: true,
		},
		{
			name:     "unknown operation",
			opType:   SensitiveOperationType("unknown_operation"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSensitiveOperation(tt.opType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSensitiveOperationContext tests context helpers
func TestSensitiveOperationContext(t *testing.T) {
	t.Run("add and retrieve justification from context", func(t *testing.T) {
		ctx := context.Background()
		justification := "Removing obsolete role as part of security audit cleanup"

		// Add justification to context
		ctx = WithSensitiveOperationJustification(ctx, justification)

		// Retrieve justification
		retrieved := GetSensitiveOperationJustification(ctx)
		assert.Equal(t, justification, retrieved)
	})

	t.Run("retrieve from empty context returns empty string", func(t *testing.T) {
		ctx := context.Background()

		retrieved := GetSensitiveOperationJustification(ctx)
		assert.Equal(t, "", retrieved)
	})
}

// TestAuditSensitiveOperation tests audit logging for sensitive operations
func TestAuditSensitiveOperation(t *testing.T) {
	// Create manager without audit (nil audit manager)
	manager := &Manager{}

	opCtx := &SensitiveOperationContext{
		OperationType: SensitiveOpDeleteRole,
		SubjectID:     "user-123",
		TenantID:      "tenant-123",
		ResourceID:    "role-456",
		Justification: "Test operation for unit testing",
		Metadata: map[string]interface{}{
			"test_metadata": "value",
		},
	}

	// Should not panic with nil audit manager
	require.NotPanics(t, func() {
		manager.AuditSensitiveOperation(context.Background(), opCtx, business.AuditResultSuccess, nil)
	})
}

// TestManagerSensitiveGates verifies that each newly-gated Manager operation returns
// ErrJustificationRequired when called without a justification in context and succeeds
// when WithSensitiveOperationJustification is used.
func TestManagerSensitiveGates(t *testing.T) {
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

	ctx := context.Background()
	require.NoError(t, manager.Initialize(ctx))
	require.NoError(t, manager.CreateTenantDefaultRoles(ctx, "gate-test-tenant"))

	justCtx := WithSensitiveOperationJustification(ctx, "test: validating sensitive operation gate for rbac story #742")

	// -- CreatePermission --
	t.Run("CreatePermission/missing_justification", func(t *testing.T) {
		perm := &common.Permission{
			Id:           "gate.test.perm1",
			Name:         "Gate Test Permission 1",
			ResourceType: "gate",
			Actions:      []string{"read"},
		}
		err := manager.CreatePermission(ctx, perm)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrJustificationRequired)
	})
	t.Run("CreatePermission/with_justification", func(t *testing.T) {
		perm := &common.Permission{
			Id:           "gate.test.perm2",
			Name:         "Gate Test Permission 2",
			ResourceType: "gate",
			Actions:      []string{"read"},
		}
		err := manager.CreatePermission(justCtx, perm)
		require.NoError(t, err)
	})

	// -- DeletePermission --
	t.Run("DeletePermission/missing_justification", func(t *testing.T) {
		err := manager.DeletePermission(ctx, "gate.test.perm2")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrJustificationRequired)
	})
	t.Run("DeletePermission/with_justification", func(t *testing.T) {
		err := manager.DeletePermission(justCtx, "gate.test.perm2")
		require.NoError(t, err)
	})

	// -- CreateRole --
	t.Run("CreateRole/missing_justification", func(t *testing.T) {
		role := &common.Role{
			Id:       "gate-test-tenant.gate.role1",
			Name:     "Gate Test Role 1",
			TenantId: "gate-test-tenant",
		}
		err := manager.CreateRole(ctx, role)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrJustificationRequired)
	})
	t.Run("CreateRole/with_justification", func(t *testing.T) {
		role := &common.Role{
			Id:       "gate-test-tenant.gate.role2",
			Name:     "Gate Test Role 2",
			TenantId: "gate-test-tenant",
		}
		err := manager.CreateRole(justCtx, role)
		require.NoError(t, err)
	})

	// -- UpdateRole --
	t.Run("UpdateRole/missing_justification", func(t *testing.T) {
		role := &common.Role{
			Id:          "gate-test-tenant.gate.role2",
			Name:        "Gate Test Role 2 Updated",
			TenantId:    "gate-test-tenant",
			Description: "Updated description",
		}
		err := manager.UpdateRole(ctx, role)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrJustificationRequired)
	})
	t.Run("UpdateRole/with_justification", func(t *testing.T) {
		role := &common.Role{
			Id:          "gate-test-tenant.gate.role2",
			Name:        "Gate Test Role 2 Updated",
			TenantId:    "gate-test-tenant",
			Description: "Updated description",
		}
		err := manager.UpdateRole(justCtx, role)
		require.NoError(t, err)
	})

	// -- AssignRole --
	subject := &common.Subject{
		Id:       "gate-test-subject",
		Type:     common.SubjectType_SUBJECT_TYPE_USER,
		TenantId: "gate-test-tenant",
		IsActive: true,
	}
	require.NoError(t, manager.CreateSubject(ctx, subject))

	t.Run("AssignRole/missing_justification", func(t *testing.T) {
		assignment := &common.RoleAssignment{
			SubjectId: "gate-test-subject",
			RoleId:    "gate-test-tenant.gate.role2",
			TenantId:  "gate-test-tenant",
		}
		err := manager.AssignRole(ctx, assignment)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrJustificationRequired)
	})
	t.Run("AssignRole/with_justification", func(t *testing.T) {
		assignment := &common.RoleAssignment{
			SubjectId: "gate-test-subject",
			RoleId:    "gate-test-tenant.gate.role2",
			TenantId:  "gate-test-tenant",
		}
		err := manager.AssignRole(justCtx, assignment)
		require.NoError(t, err)
	})

	// -- RevokeRole --
	t.Run("RevokeRole/missing_justification", func(t *testing.T) {
		err := manager.RevokeRole(ctx, "gate-test-subject", "gate-test-tenant.gate.role2", "gate-test-tenant")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrJustificationRequired)
	})
	t.Run("RevokeRole/with_justification", func(t *testing.T) {
		err := manager.RevokeRole(justCtx, "gate-test-subject", "gate-test-tenant.gate.role2", "gate-test-tenant")
		require.NoError(t, err)
	})
}

// TestSensitiveOperationTypes tests all defined operation types
func TestSensitiveOperationTypes(t *testing.T) {
	operations := []SensitiveOperationType{
		SensitiveOpCreateRole,
		SensitiveOpDeleteRole,
		SensitiveOpModifyRole,
		SensitiveOpAssignRole,
		SensitiveOpRevokeRole,
		SensitiveOpCreatePermission,
		SensitiveOpDeletePermission,
		SensitiveOpCreateUser,
		SensitiveOpDeleteUser,
		SensitiveOpModifyUser,
		SensitiveOpModifyConfig,
		SensitiveOpDisableSecurity,
		SensitiveOpViewAuditLogs,
		SensitiveOpModifyAuditLogs,
		SensitiveOpBulkDelete,
		SensitiveOpDataExport,
	}

	for _, op := range operations {
		t.Run(string(op), func(t *testing.T) {
			// All defined operations should be sensitive
			assert.True(t, IsSensitiveOperation(op), "operation %s should be sensitive", op)

			// Should be able to create valid context
			opCtx := &SensitiveOperationContext{
				OperationType: op,
				SubjectID:     "user-123",
				TenantID:      "tenant-123",
				ResourceID:    "resource-456",
				Justification: "Valid justification for testing purposes",
			}

			// Should validate successfully
			err := ValidateSensitiveOperation(opCtx)
			assert.NoError(t, err)
		})
	}
}
