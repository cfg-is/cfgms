// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	cfgmstesting "github.com/cfgis/cfgms/pkg/testing"
)

// newTestTenantManager creates a Manager backed by real SQLite+flatfile storage.
func newTestTenantManager(t *testing.T) *Manager {
	t.Helper()
	storageManager := cfgmstesting.SetupTestStorage(t)
	tenantStore := NewStorageAdapter(storageManager.GetTenantStore())
	rbacManager := cfgmstesting.SetupTestRBACManager(t)
	return NewManager(tenantStore, rbacManager)
}

func TestManager_CreateTenant(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Test creating a new tenant
	req := &TenantRequest{
		Name:        "Test-Tenant",
		Description: "A test tenant",
		Metadata: map[string]string{
			"owner": "test@example.com",
		},
	}

	tenant, err := manager.CreateTenant(ctx, req)
	require.NoError(t, err)
	assert.NotEmpty(t, tenant.ID)
	assert.Equal(t, "Test-Tenant", tenant.Name)
	assert.Equal(t, "A test tenant", tenant.Description)
	assert.Equal(t, TenantStatusActive, tenant.Status)
	assert.Equal(t, "test@example.com", tenant.Metadata["owner"])
	assert.NotZero(t, tenant.CreatedAt)
	assert.NotZero(t, tenant.UpdatedAt)

	// Verify tenant can be retrieved
	retrieved, err := manager.GetTenant(ctx, tenant.ID)
	require.NoError(t, err)
	assert.Equal(t, tenant.ID, retrieved.ID)
	assert.Equal(t, tenant.Name, retrieved.Name)
}

func TestManager_CreateTenant_WithParent(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Create parent tenant
	parentReq := &TenantRequest{
		Name: "Parent-Tenant",
	}
	parent, err := manager.CreateTenant(ctx, parentReq)
	require.NoError(t, err)

	// Create child tenant
	childReq := &TenantRequest{
		Name:     "Child-Tenant",
		ParentID: parent.ID,
	}
	child, err := manager.CreateTenant(ctx, childReq)
	require.NoError(t, err)
	assert.Equal(t, parent.ID, child.ParentID)

	// Verify hierarchy
	hierarchy, err := manager.GetTenantHierarchy(ctx, child.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, hierarchy.Depth)
	assert.Contains(t, hierarchy.Path, parent.ID)
	assert.Contains(t, hierarchy.Path, child.ID)

	// Verify parent has child
	children, err := manager.GetChildTenants(ctx, parent.ID)
	require.NoError(t, err)
	assert.Len(t, children, 1)
	assert.Equal(t, child.ID, children[0].ID)
}

func TestManager_CreateTenant_Validation(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Test validation errors
	tests := []struct {
		name string
		req  *TenantRequest
	}{
		{
			name: "empty name",
			req:  &TenantRequest{Name: ""},
		},
		{
			name: "invalid characters",
			req:  &TenantRequest{Name: "test@tenant!"},
		},
		{
			name: "name too long",
			req:  &TenantRequest{Name: string(make([]byte, 65))},
		},
		{
			name: "description too long",
			req:  &TenantRequest{Name: "test", Description: string(make([]byte, 256))},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := manager.CreateTenant(ctx, tt.req)
			assert.Error(t, err)
		})
	}
}

func TestManager_ListTenants(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Create test tenants
	tenant1, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Tenant1"})
	require.NoError(t, err)

	tenant2, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Tenant2", ParentID: tenant1.ID})
	require.NoError(t, err)

	// List all tenants (real storage starts empty — only tenant1 and tenant2 present)
	tenants, err := manager.ListTenants(ctx, nil)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(tenants), 2)

	// List tenants with filter
	filter := &TenantFilter{ParentID: tenant1.ID}
	filteredTenants, err := manager.ListTenants(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, filteredTenants, 1)
	assert.Equal(t, tenant2.ID, filteredTenants[0].ID)
}

func TestManager_UpdateTenant(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Create tenant
	originalReq := &TenantRequest{
		Name:        "Original-Name",
		Description: "Original Description",
	}
	tenant, err := manager.CreateTenant(ctx, originalReq)
	require.NoError(t, err)

	// Update tenant
	updateReq := &TenantRequest{
		Name:        "Updated-Name",
		Description: "Updated Description",
		Metadata: map[string]string{
			"updated": "true",
		},
	}

	updated, err := manager.UpdateTenant(ctx, tenant.ID, updateReq)
	require.NoError(t, err)
	assert.Equal(t, "Updated-Name", updated.Name)
	assert.Equal(t, "Updated Description", updated.Description)
	assert.Equal(t, "true", updated.Metadata["updated"])
	assert.True(t, tenant.CreatedAt.Equal(updated.CreatedAt), "CreatedAt should not change after update")
	// UpdatedAt should be at or after the original (may be equal on fast systems)
	assert.False(t, updated.UpdatedAt.Before(tenant.UpdatedAt))
}

func TestManager_DeleteTenant(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Create tenant
	tenant, err := manager.CreateTenant(ctx, &TenantRequest{Name: "ToDelete"})
	require.NoError(t, err)

	// Delete tenant
	err = manager.DeleteTenant(ctx, tenant.ID)
	require.NoError(t, err)

	// Verify tenant was removed (real storage hard-deletes)
	_, err = manager.GetTenant(ctx, tenant.ID)
	require.Error(t, err)
}

func TestManager_DeleteTenant_WithChildren(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Create parent and child tenants
	parent, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Parent"})
	require.NoError(t, err)

	_, err = manager.CreateTenant(ctx, &TenantRequest{Name: "Child", ParentID: parent.ID})
	require.NoError(t, err)

	// Try to delete parent - should fail
	err = manager.DeleteTenant(ctx, parent.ID)
	assert.Error(t, err)
	assert.Equal(t, ErrTenantHasChildren, err)
}

func TestManager_IsTenantAncestor(t *testing.T) {
	manager := newTestTenantManager(t)
	ctx := context.Background()

	// Create hierarchy: grandparent -> parent -> child
	grandparent, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Grandparent"})
	require.NoError(t, err)

	parent, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Parent", ParentID: grandparent.ID})
	require.NoError(t, err)

	child, err := manager.CreateTenant(ctx, &TenantRequest{Name: "Child", ParentID: parent.ID})
	require.NoError(t, err)

	// Test ancestor relationships
	isAncestor, err := manager.IsTenantAncestor(ctx, grandparent.ID, child.ID)
	require.NoError(t, err)
	assert.True(t, isAncestor)

	isAncestor, err = manager.IsTenantAncestor(ctx, parent.ID, child.ID)
	require.NoError(t, err)
	assert.True(t, isAncestor)

	isAncestor, err = manager.IsTenantAncestor(ctx, child.ID, grandparent.ID)
	require.NoError(t, err)
	assert.False(t, isAncestor)

	isAncestor, err = manager.IsTenantAncestor(ctx, child.ID, parent.ID)
	require.NoError(t, err)
	assert.False(t, isAncestor)
}

// setupRealTenantManager creates a Manager backed by real SQLite storage for cascade tests.
func setupRealTenantManager(t *testing.T, rbacManager *rbac.Manager) *Manager {
	t.Helper()
	storageManager := cfgmstesting.SetupTestStorage(t)
	tenantStore := NewStorageAdapter(storageManager.GetTenantStore())
	return NewManager(tenantStore, rbacManager)
}

func TestDeleteTenant_CascadesRBACCleanup(t *testing.T) {
	rbacManager := cfgmstesting.SetupTestRBACManager(t)
	manager := setupRealTenantManager(t, rbacManager)
	ctx := context.Background()
	// M-AUTH-2: CreateRole requires justification in context
	ctx = rbac.WithSensitiveOperationJustification(ctx, "test: tenant RBAC cleanup cascade")

	// Create a tenant — this also calls CreateTenantDefaultRoles (in-memory only)
	tenant, err := manager.CreateTenant(ctx, &TenantRequest{Name: "RBACCleanupTenant"})
	require.NoError(t, err)
	tenantID := tenant.ID

	// Explicitly create a persisted role and two subjects for this tenant
	role := &common.Role{
		Id:       tenantID + ".custom-role",
		Name:     "Custom Role",
		TenantId: tenantID,
	}
	require.NoError(t, rbacManager.CreateRole(ctx, role))

	for _, s := range []*common.Subject{
		{Id: "user-" + tenantID, Type: common.SubjectType_SUBJECT_TYPE_USER, TenantId: tenantID, IsActive: true},
		{Id: "svc-" + tenantID, Type: common.SubjectType_SUBJECT_TYPE_SERVICE, TenantId: tenantID, IsActive: true},
	} {
		require.NoError(t, rbacManager.CreateSubject(ctx, s))
	}

	// Verify the persisted role and subjects exist before deletion
	_, err = rbacManager.GetRole(ctx, role.Id)
	require.NoError(t, err, "custom role must exist before deletion")

	subjectsBefore, err := rbacManager.ListAllSubjects(ctx, tenantID)
	require.NoError(t, err)
	assert.NotEmpty(t, subjectsBefore, "expected subjects before tenant deletion")

	// Delete the tenant — must cascade RBAC cleanup
	require.NoError(t, manager.DeleteTenant(ctx, tenantID))

	// Persisted role must be gone
	_, err = rbacManager.GetRole(ctx, role.Id)
	assert.Error(t, err, "custom role should not exist after tenant deletion")

	// No subjects must remain for this tenant
	subjectsAfter, err := rbacManager.ListAllSubjects(ctx, tenantID)
	require.NoError(t, err)
	assert.Empty(t, subjectsAfter, "expected no subjects after tenant deletion")

	// No tenant-scoped roles must remain (ListRoles also returns system roles; skip those)
	rolesAfter, err := rbacManager.ListRoles(ctx, tenantID)
	require.NoError(t, err)
	for _, r := range rolesAfter {
		assert.NotEqual(t, tenantID, r.TenantId, "tenant-scoped role should have been deleted: %s", r.Id)
	}
}

func TestDeleteTenant_CascadesRBACCleanup_NilRBACManager(t *testing.T) {
	// Manager with nil rbacManager — must not panic, must succeed
	manager := setupRealTenantManager(t, nil)
	ctx := context.Background()

	tenant, err := manager.CreateTenant(ctx, &TenantRequest{Name: "NoRBACTenant"})
	require.NoError(t, err)

	require.NoError(t, manager.DeleteTenant(ctx, tenant.ID))
}

// TestDeleteTenant_CascadesRBACCleanup_PartialFailureContinues verifies that
// DeleteTenant returns nil even when individual RBAC cascade deletions encounter
// errors. CreateTenant loads default tenant roles into the in-memory RBAC store
// without persisting them to durable storage. The cascade deletes them from
// in-memory but the durable delete fails; the warning is logged and the tenant
// deletion proceeds successfully.
func TestDeleteTenant_CascadesRBACCleanup_PartialFailureContinues(t *testing.T) {
	rbacManager := cfgmstesting.SetupTestRBACManager(t)
	manager := setupRealTenantManager(t, rbacManager)
	ctx := context.Background()

	// CreateTenant triggers CreateTenantDefaultRoles which loads roles into the
	// in-memory store only (not the durable RBAC store). The cascade will
	// encounter "role not found" errors from the durable layer — those must be
	// logged as warnings, not returned as failures.
	tenant, err := manager.CreateTenant(ctx, &TenantRequest{Name: "PartialFailureTenant"})
	require.NoError(t, err)

	// DeleteTenant must return nil despite individual cascade errors
	require.NoError(t, manager.DeleteTenant(ctx, tenant.ID))
}
