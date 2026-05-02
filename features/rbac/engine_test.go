// SPDX-License-Identifier: Apache-2.0
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
	}
	require.NoError(t, store.CreateSubject(ctx, subject))

	// Formally assign the role so it appears in the valid-assignment map used by CheckPermission.
	require.NoError(t, store.AssignRole(ctx, &common.RoleAssignment{
		SubjectId: "test-subject",
		RoleId:    "db-error-role",
		TenantId:  "tenant1",
	}))

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
	}
	require.NoError(t, store.CreateSubject(ctx, subject))

	// Formally assign both roles so they appear in the valid-assignment map.
	require.NoError(t, store.AssignRole(ctx, &common.RoleAssignment{
		SubjectId: "test-subject",
		RoleId:    "ghost-role",
		TenantId:  "tenant1",
	}))
	require.NoError(t, store.AssignRole(ctx, &common.RoleAssignment{
		SubjectId: "test-subject",
		RoleId:    "valid-role",
		TenantId:  "tenant1",
	}))

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

// TestPermissionMatches_LiteralStar_ReturnsFalse verifies that a Permission with
// Id "*" does not match any requested permission string. The literal "*" is not a
// valid wildcard; only the "prefix.*" form is supported.
func TestPermissionMatches_LiteralStar_ReturnsFalse(t *testing.T) {
	store, _ := setupEngineTestStore(t)
	engine := NewAuthEngine(store, store, store, store)

	starPerm := &common.Permission{Id: "*", Name: "Wildcard (invalid)"}

	assert.False(t, engine.permissionMatches(starPerm, "system.admin"),
		"Permission{Id:\"*\"} must not match \"system.admin\"")
	assert.False(t, engine.permissionMatches(starPerm, "steward.read"),
		"Permission{Id:\"*\"} must not match \"steward.read\"")
	assert.False(t, engine.permissionMatches(starPerm, "*"),
		"Permission{Id:\"*\"} must not match literal \"*\" request")
	assert.False(t, engine.permissionMatches(starPerm, "anything.at.all"),
		"Permission{Id:\"*\"} must not match any permission string")
}

// TestAuthEngine_CheckPermission_ExpiredAssignment_Denied verifies that a role
// assignment with ExpiresAt in the past does not grant permissions. The permission
// must be denied even though the role still exists and has the required permission.
func TestAuthEngine_CheckPermission_ExpiredAssignment_Denied(t *testing.T) {
	store, ctx := setupEngineTestStore(t)

	perm := &common.Permission{Id: "steward.read", Name: "Steward Read", ResourceType: "steward", Actions: []string{"read"}}
	store.LoadPermissions([]*common.Permission{perm})

	role := &common.Role{
		Id:            "temp-role",
		Name:          "Temporary Role",
		TenantId:      "tenant1",
		PermissionIds: []string{"steward.read"},
	}
	store.LoadRoles([]*common.Role{role})

	subject := &common.Subject{
		Id:       "temp-subject",
		TenantId: "tenant1",
		IsActive: true,
	}
	require.NoError(t, store.CreateSubject(ctx, subject))

	// Assign the role with an ExpiresAt set 1 hour in the past.
	expiredAssignment := &common.RoleAssignment{
		SubjectId: "temp-subject",
		RoleId:    "temp-role",
		TenantId:  "tenant1",
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
	}
	require.NoError(t, store.AssignRole(ctx, expiredAssignment))

	engine := NewAuthEngine(store, store, store, store)

	resp, err := engine.CheckPermission(ctx, &common.AccessRequest{
		SubjectId:    "temp-subject",
		PermissionId: "steward.read",
		TenantId:     "tenant1",
	})
	require.NoError(t, err)
	assert.False(t, resp.Granted, "expired role assignment must not grant permission")
}
