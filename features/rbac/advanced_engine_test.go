// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/memory"
)

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
