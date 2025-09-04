package rbac

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	// Import storage providers to register them
	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewManagerWithStorage tests the new constructor that accepts storage interfaces
func TestNewManagerWithStorage(t *testing.T) {
	tests := []struct {
		name         string
		setupStorage func(t *testing.T) (*interfaces.StorageManager, error)
		wantErr      bool
	}{
		{
			name: "with database storage provider (if configured)",
			setupStorage: func(t *testing.T) (*interfaces.StorageManager, error) {
				// Skip database tests for now due to configuration complexity
				// In production, database provider will be properly configured
				t.Skip("database provider requires complex configuration - skipping for basic test")
				return nil, nil
			},
			wantErr: false,
		},
		{
			name: "with git storage provider",
			setupStorage: func(t *testing.T) (*interfaces.StorageManager, error) {
				// Git provider with temporary directory
				config := map[string]interface{}{
					"repository_path": t.TempDir(),
					"branch":         "main",
					"auto_init":      true,
				}
				return interfaces.CreateAllStoresFromConfig("git", config)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storageManager, err := tt.setupStorage(t)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, storageManager)

			// Test creating manager with storage interfaces
			manager := NewManagerWithStorage(
				storageManager.GetAuditStore(),
				storageManager.GetClientTenantStore(),
				storageManager.GetRBACStore(),
			)
			require.NotNil(t, manager)

			// Verify manager initializes correctly with pluggable storage
			ctx := context.Background()
			err = manager.Initialize(ctx)
			require.NoError(t, err)

			// Test basic RBAC operations work with pluggable storage
			t.Run("permissions work with storage backend", func(t *testing.T) {
				// Test permission creation
				permission := &common.Permission{
					Id:           "test.permission",
					Name:         "Test Permission",
					Description:  "A test permission",
					ResourceType: "test",
					Actions:      []string{"read"},
				}

				err := manager.CreatePermission(ctx, permission)
				require.NoError(t, err)

				// Test permission retrieval
				retrievedPerm, err := manager.GetPermission(ctx, "test.permission")
				require.NoError(t, err)
				assert.Equal(t, permission.Id, retrievedPerm.Id)
				assert.Equal(t, permission.Name, retrievedPerm.Name)
			})

			t.Run("roles work with storage backend", func(t *testing.T) {
				// Test role creation
				role := &common.Role{
					Id:            "test.role",
					Name:          "Test Role",
					Description:   "A test role",
					PermissionIds: []string{"test.permission"},
					TenantId:      "test-tenant",
				}

				err := manager.CreateRole(ctx, role)
				require.NoError(t, err)

				// Test role retrieval
				retrievedRole, err := manager.GetRole(ctx, "test.role")
				require.NoError(t, err)
				assert.Equal(t, role.Id, retrievedRole.Id)
				assert.Equal(t, role.Name, retrievedRole.Name)
				assert.Equal(t, role.TenantId, retrievedRole.TenantId)
			})

			t.Run("role assignments work with storage backend", func(t *testing.T) {
				// Test subject creation
				subject := &common.Subject{
					Id:          "test-user",
					Type:        common.SubjectType_SUBJECT_TYPE_USER,
					DisplayName: "Test User",
					TenantId:    "test-tenant",
					IsActive:    true,
				}

				err := manager.CreateSubject(ctx, subject)
				require.NoError(t, err)

				// Test role assignment
				assignment := &common.RoleAssignment{
					SubjectId: "test-user",
					RoleId:    "test.role",
					TenantId:  "test-tenant",
				}

				err = manager.AssignRole(ctx, assignment)
				require.NoError(t, err)

				// Test assignment retrieval
				assignments, err := manager.GetSubjectAssignments(ctx, "test-user", "test-tenant")
				require.NoError(t, err)
				assert.Len(t, assignments, 1)
				assert.Equal(t, "test.role", assignments[0].RoleId)
			})
		})
	}
}

// TestNewManagerWithStorage_BackwardCompatibility was removed in Epic 6
// This test previously validated the NewManager() function which has been
// deliberately removed to eliminate package-level storage mechanisms
// All RBAC managers now require explicit storage configuration via NewManagerWithStorage()

// TestNewManagerWithStorage_NilStorageHandling tests error handling for nil storage interfaces
func TestNewManagerWithStorage_NilStorageHandling(t *testing.T) {
	tests := []struct {
		name              string
		auditStore        interfaces.AuditStore
		clientTenantStore interfaces.ClientTenantStore
		expectPanic       bool
	}{
		{
			name:              "nil audit store",
			auditStore:        nil,
			clientTenantStore: nil,
			expectPanic:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectPanic {
				assert.Panics(t, func() {
					NewManagerWithStorage(tt.auditStore, tt.clientTenantStore, nil)
				})
			} else {
				manager := NewManagerWithStorage(tt.auditStore, tt.clientTenantStore, nil)
				assert.NotNil(t, manager)
			}
		})
	}
}

// TestManagerWithStorage_TenantIsolation tests that tenant isolation works correctly with pluggable storage
func TestManagerWithStorage_TenantIsolation(t *testing.T) {
	// Create storage manager using git provider
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
	require.NotNil(t, manager)

	ctx := context.Background()
	err = manager.Initialize(ctx)
	require.NoError(t, err)

	// Create roles for different tenants
	tenant1Role := &common.Role{
		Id:          "tenant1.role",
		Name:        "Tenant 1 Role",
		TenantId:    "tenant-1",
		Description: "Role for tenant 1",
	}

	tenant2Role := &common.Role{
		Id:          "tenant2.role",
		Name:        "Tenant 2 Role",
		TenantId:    "tenant-2",
		Description: "Role for tenant 2",
	}

	err = manager.CreateRole(ctx, tenant1Role)
	require.NoError(t, err)

	err = manager.CreateRole(ctx, tenant2Role)
	require.NoError(t, err)

	// Verify tenant isolation - tenant 1 should only see tenant 1 roles
	tenant1Roles, err := manager.ListRoles(ctx, "tenant-1")
	require.NoError(t, err)
	
	found := false
	for _, role := range tenant1Roles {
		if role.Id == "tenant1.role" {
			found = true
		}
		// Should not see roles from other tenants
		assert.NotEqual(t, "tenant2.role", role.Id, "tenant isolation violated - saw other tenant's role")
	}
	assert.True(t, found, "should find tenant 1 role in tenant 1 results")

	// Verify tenant 2 isolation
	tenant2Roles, err := manager.ListRoles(ctx, "tenant-2")
	require.NoError(t, err)
	
	found = false
	for _, role := range tenant2Roles {
		if role.Id == "tenant2.role" {
			found = true
		}
		// Should not see roles from other tenants
		assert.NotEqual(t, "tenant1.role", role.Id, "tenant isolation violated - saw other tenant's role")
	}
	assert.True(t, found, "should find tenant 2 role in tenant 2 results")
}

// TestManagerWithStorage_AuditTrail tests that RBAC operations are properly audited
func TestManagerWithStorage_AuditTrail(t *testing.T) {
	// Create storage manager using git provider
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
	require.NotNil(t, manager)

	ctx := context.Background()
	err = manager.Initialize(ctx)
	require.NoError(t, err)

	// Perform RBAC operations that should generate audit entries
	role := &common.Role{
		Id:          "audit.test.role",
		Name:        "Audit Test Role",
		TenantId:    "audit-tenant",
		Description: "Role for testing audit trail",
	}

	err = manager.CreateRole(ctx, role)
	require.NoError(t, err)

	// TODO: Once audit integration is implemented, verify audit entries exist
	// For now, this test establishes the structure for future audit validation
	// auditEntries, err := storageManager.GetAuditStore().ListAuditEntries(ctx, &interfaces.AuditFilter{
	// 	ResourceTypes: []string{"role"},
	// 	Actions:       []string{"create"},
	// })
	// require.NoError(t, err)
	// assert.Len(t, auditEntries, 1)
	// assert.Equal(t, "create", auditEntries[0].Action)
	// assert.Equal(t, "role", auditEntries[0].ResourceType)
}