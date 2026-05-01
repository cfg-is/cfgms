// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rbac

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/memory"
)

// errorInjectingRoleStore wraps a real memory.Store but returns a controlled error
// from GetRolePermissions for a specific role ID. Used to test error handling paths
// in AuthEngine without mocking unrelated store operations.
type errorInjectingRoleStore struct {
	*memory.Store
	errorRoleID string
	err         error
}

func (s *errorInjectingRoleStore) GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error) {
	if roleID == s.errorRoleID {
		return nil, s.err
	}
	return s.Store.GetRolePermissions(ctx, roleID)
}

func setupEngineTestStore(t *testing.T) (*memory.Store, context.Context) {
	t.Helper()
	store := memory.NewStore()
	ctx := context.Background()
	require.NoError(t, store.Initialize(ctx))
	return store, ctx
}

// TestAuthEngine_GetEffectivePermissions_WithInheritedPermissions verifies that
// GetEffectivePermissions calls HierarchyEngine.ComputeEffectivePermissions for
// each role and returns permissions inherited via ParentRoleId.
func TestAuthEngine_GetEffectivePermissions_WithInheritedPermissions(t *testing.T) {
	store, ctx := setupEngineTestStore(t)

	// Create the inherited permission
	inheritedPerm := &common.Permission{
		Id:           "config.deploy",
		Name:         "Deploy Config",
		ResourceType: "config",
		Actions:      []string{"deploy"},
	}
	store.LoadPermissions([]*common.Permission{inheritedPerm})

	// Create parent role with the inherited permission
	parentRole := &common.Role{
		Id:            "parent-role",
		Name:          "Parent Role",
		TenantId:      "test-tenant",
		PermissionIds: []string{"config.deploy"},
	}
	store.LoadRoles([]*common.Role{parentRole})

	// Create child role that inherits from parent (no direct permissions)
	childRole := &common.Role{
		Id:              "child-role",
		Name:            "Child Role",
		TenantId:        "test-tenant",
		ParentRoleId:    "parent-role",
		InheritanceType: common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE,
	}
	store.LoadRoles([]*common.Role{childRole})

	// Create subject assigned to child role
	subject := &common.Subject{
		Id:       "test-subject",
		TenantId: "test-tenant",
		IsActive: true,
		RoleIds:  []string{"child-role"},
	}
	require.NoError(t, store.CreateSubject(ctx, subject))

	// Create engine with hierarchy engine wired
	engine := NewAuthEngine(store, store, store, store)
	hierarchyEngine := NewHierarchyEngine(store, store)
	engine.SetHierarchyEngine(hierarchyEngine)

	perms, err := engine.GetEffectivePermissions(ctx, "test-subject", "test-tenant")
	require.NoError(t, err)

	permIDs := make(map[string]bool, len(perms))
	for _, p := range perms {
		permIDs[p.Id] = true
	}
	assert.True(t, permIDs["config.deploy"], "GetEffectivePermissions must return permission inherited from parent role")
}

// TestAuthEngine_GetEffectivePermissions_NoHierarchyEngine verifies that when no
// hierarchy engine is wired, GetEffectivePermissions falls back to GetSubjectPermissions.
func TestAuthEngine_GetEffectivePermissions_NoHierarchyEngine(t *testing.T) {
	store, ctx := setupEngineTestStore(t)

	directPerm := &common.Permission{Id: "steward.read", Name: "Steward Read"}
	store.LoadPermissions([]*common.Permission{directPerm})

	role := &common.Role{
		Id:            "reader-role",
		Name:          "Reader",
		TenantId:      "t1",
		PermissionIds: []string{"steward.read"},
	}
	store.LoadRoles([]*common.Role{role})

	subject := &common.Subject{Id: "subj1", TenantId: "t1", IsActive: true, RoleIds: []string{"reader-role"}}
	require.NoError(t, store.CreateSubject(ctx, subject))

	engine := NewAuthEngine(store, store, store, store)
	// no SetHierarchyEngine call — fallback path

	perms, err := engine.GetEffectivePermissions(ctx, "subj1", "t1")
	require.NoError(t, err)
	require.Len(t, perms, 1)
	assert.Equal(t, "steward.read", perms[0].Id)
}

// TestAuthEngine_CheckPermission_DBError_Propagates verifies that a non-not-found
// error from GetRolePermissions is propagated by CheckPermission rather than
// silently treated as a permission denial.
func TestAuthEngine_CheckPermission_DBError_Propagates(t *testing.T) {
	store, ctx := setupEngineTestStore(t)

	role := &common.Role{Id: "db-error-role", Name: "DB Error Role", TenantId: "tenant1"}
	store.LoadRoles([]*common.Role{role})

	subject := &common.Subject{
		Id:       "test-subject",
		TenantId: "tenant1",
		IsActive: true,
		RoleIds:  []string{"db-error-role"},
	}
	require.NoError(t, store.CreateSubject(ctx, subject))

	// Inject a non-not-found DB error (e.g., connection failure)
	dbErr := fmt.Errorf("connection refused: postgres is unavailable")
	errorStore := &errorInjectingRoleStore{Store: store, errorRoleID: "db-error-role", err: dbErr}
	engine := NewAuthEngine(store, errorStore, store, store)

	request := &common.AccessRequest{
		SubjectId:    "test-subject",
		PermissionId: "config.read",
		TenantId:     "tenant1",
	}

	resp, err := engine.CheckPermission(ctx, request)
	require.Error(t, err, "non-not-found DB error must be propagated, not swallowed as a silent deny")
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "db-error-role")
}

// TestAuthEngine_CheckPermission_NotFoundError_Skips verifies that a not-found
// error from GetRolePermissions causes that role to be skipped and evaluation
// continues with remaining roles — it must not propagate as an error.
func TestAuthEngine_CheckPermission_NotFoundError_Skips(t *testing.T) {
	store, ctx := setupEngineTestStore(t)

	// Role whose GetRolePermissions will return a not-found error (simulates
	// a role that existed when the subject was loaded but was deleted from the
	// permissions table between calls).
	ghostRole := &common.Role{Id: "ghost-role", Name: "Ghost Role", TenantId: "tenant1"}
	store.LoadRoles([]*common.Role{ghostRole})

	// Valid role that does grant the permission
	validPerm := &common.Permission{Id: "steward.read", Name: "Steward Read"}
	store.LoadPermissions([]*common.Permission{validPerm})
	validRole := &common.Role{
		Id:            "valid-role",
		Name:          "Valid Role",
		TenantId:      "tenant1",
		PermissionIds: []string{"steward.read"},
	}
	store.LoadRoles([]*common.Role{validRole})

	subject := &common.Subject{
		Id:       "test-subject",
		TenantId: "tenant1",
		IsActive: true,
		RoleIds:  []string{"ghost-role", "valid-role"},
	}
	require.NoError(t, store.CreateSubject(ctx, subject))

	// ghost-role returns a not-found error from GetRolePermissions
	notFoundErr := fmt.Errorf("role ghost-role not found")
	errorStore := &errorInjectingRoleStore{Store: store, errorRoleID: "ghost-role", err: notFoundErr}
	engine := NewAuthEngine(store, errorStore, store, store)

	request := &common.AccessRequest{
		SubjectId:    "test-subject",
		PermissionId: "steward.read",
		TenantId:     "tenant1",
	}

	resp, err := engine.CheckPermission(ctx, request)
	require.NoError(t, err, "not-found role error must be skipped, not propagated")
	require.NotNil(t, resp)
	assert.True(t, resp.Granted, "permission must be granted via the valid role after skipping the ghost role")
}
