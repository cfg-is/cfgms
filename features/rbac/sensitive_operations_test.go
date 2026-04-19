// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package rbac - Tests for sensitive operation controls
package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
