// SPDX-License-Identifier: AGPL-3.0-only
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

// errPermissionStore is a minimal PermissionStore test double that returns a configurable
// error from GetPermission. Used to exercise the non-not-found error branch of getPermissionByID.
type errPermissionStore struct{ getErr error }

func (s *errPermissionStore) GetPermission(_ context.Context, _ string) (*common.Permission, error) {
	return nil, s.getErr
}
func (s *errPermissionStore) CreatePermission(_ context.Context, _ *common.Permission) error {
	return nil
}
func (s *errPermissionStore) ListPermissions(_ context.Context, _ string) ([]*common.Permission, error) {
	return nil, nil
}
func (s *errPermissionStore) UpdatePermission(_ context.Context, _ *common.Permission) error {
	return nil
}
func (s *errPermissionStore) DeletePermission(_ context.Context, _ string) error { return nil }

func setupAdvancedEngineStore(t *testing.T) (*memory.Store, context.Context) {
	t.Helper()
	store := memory.NewStore()
	ctx := context.Background()
	require.NoError(t, store.Initialize(ctx))
	return store, ctx
}

func TestAdvancedAuthEngine_CheckPermission(t *testing.T) {
	store, ctx := setupAdvancedEngineStore(t)

	store.LoadPermissions([]*common.Permission{
		{Id: "steward.register", Name: "Register Steward", Description: "Allow steward registration"},
	})
	store.LoadRoles([]*common.Role{
		{Id: "admin", Name: "Administrator", Description: "Full admin access", TenantId: "tenant456",
			PermissionIds: []string{"steward.register"}},
	})
	require.NoError(t, store.CreateSubject(ctx, &common.Subject{
		Id:          "user123",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Test User",
		TenantId:    "tenant456",
		IsActive:    true,
	}))
	require.NoError(t, store.AssignRole(ctx, &common.RoleAssignment{
		SubjectId: "user123",
		RoleId:    "admin",
		TenantId:  "tenant456",
	}))

	engine := NewAdvancedAuthEngine(store, store, store, store)

	t.Run("RBAC granted", func(t *testing.T) {
		request := &common.AccessRequest{
			SubjectId:    "user123",
			PermissionId: "steward.register",
			TenantId:     "tenant456",
			Context: map[string]string{
				"source_ip":  "192.168.1.100",
				"user_agent": "test-agent",
			},
		}

		response, err := engine.CheckPermission(ctx, request)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.True(t, response.Granted)
		assert.Contains(t, response.Reason, "Access granted via role 'Administrator' with permission 'Register Steward'")
	})

	t.Run("RBAC denied", func(t *testing.T) {
		request := &common.AccessRequest{
			SubjectId:    "user123",
			PermissionId: "steward.delete",
			TenantId:     "tenant456",
			Context: map[string]string{
				"source_ip":  "192.168.1.100",
				"user_agent": "test-agent",
			},
		}

		response, err := engine.CheckPermission(ctx, request)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.False(t, response.Granted)
	})
}

// TestAdvancedAuthEngine_GetDelegatedPermissions_UsesPermissionStore verifies that
// getPermissionByID calls permissionStore.GetPermission and falls back gracefully.
func TestAdvancedAuthEngine_GetDelegatedPermissions_UsesPermissionStore(t *testing.T) {
	store, ctx := setupAdvancedEngineStore(t)

	// Register the permission that will be delegated
	store.LoadPermissions([]*common.Permission{
		{Id: "files.read", Name: "Read Files", Description: "Allows reading files"},
	})

	// Set up delegator and delegatee subjects
	require.NoError(t, store.CreateSubject(ctx, &common.Subject{
		Id: "delegator1", Type: common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Delegator", TenantId: "t1", IsActive: true,
	}))
	require.NoError(t, store.CreateSubject(ctx, &common.Subject{
		Id: "delegatee1", Type: common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Delegatee", TenantId: "t1", IsActive: true,
	}))

	engine := NewAdvancedAuthEngine(store, store, store, store)

	// Inject a delegation directly (same package access to unexported map)
	dm := NewDelegationManager(nil)
	dm.mu.Lock()
	dm.delegations["del-1"] = &common.PermissionDelegation{
		Id:            "del-1",
		DelegatorId:   "delegator1",
		DelegateeId:   "delegatee1",
		PermissionIds: []string{"files.read"},
		TenantId:      "t1",
		Revoked:       false,
	}
	dm.mu.Unlock()
	engine.SetDelegationManager(dm)

	t.Run("uses permission store for known permission", func(t *testing.T) {
		perms, err := engine.GetSubjectPermissions(ctx, "delegatee1", "t1")
		require.NoError(t, err)

		var found *common.Permission
		for _, p := range perms {
			if p.Id == "files.read" {
				found = p
				break
			}
		}
		require.NotNil(t, found, "delegated permission should appear in subject permissions")
		assert.Equal(t, "Read Files", found.Name, "name should come from permission store, not synthetic fallback")
	})

	t.Run("falls back gracefully for unknown delegated permission", func(t *testing.T) {
		dm2 := NewDelegationManager(nil)
		dm2.mu.Lock()
		dm2.delegations["del-2"] = &common.PermissionDelegation{
			Id:            "del-2",
			DelegatorId:   "delegator1",
			DelegateeId:   "delegatee1",
			PermissionIds: []string{"nonexistent.permission"},
			TenantId:      "t1",
			Revoked:       false,
		}
		dm2.mu.Unlock()
		engine.SetDelegationManager(dm2)

		perms, err := engine.GetSubjectPermissions(ctx, "delegatee1", "t1")
		require.NoError(t, err)

		var found *common.Permission
		for _, p := range perms {
			if p.Id == "nonexistent.permission" {
				found = p
				break
			}
		}
		require.NotNil(t, found, "synthetic fallback permission should be returned for unknown IDs")
		assert.Equal(t, "Delegated: nonexistent.permission", found.Name)
	})

	t.Run("falls back and does not propagate non-not-found store error", func(t *testing.T) {
		// Directly test getPermissionByID with a store that returns a non-not-found error
		// (e.g. connection failure). The helper must return the synthetic fallback, not the error.
		storeErr := fmt.Errorf("connection timeout to permission store")
		errorEngine := &AdvancedAuthEngine{
			baseEngine: &AuthEngine{permissionStore: &errPermissionStore{getErr: storeErr}},
		}

		perm := errorEngine.getPermissionByID(ctx, "some.permission", "some-delegator")
		require.NotNil(t, perm, "should return synthetic fallback when store returns non-not-found error")
		assert.Equal(t, "some.permission", perm.Id)
		assert.Equal(t, "Delegated: some.permission", perm.Name)
		assert.Contains(t, perm.Description, "some-delegator")
	})
}
