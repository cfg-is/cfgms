// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package memory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
)

// TestStore_UpdateRole_TenantScopeIsImmutable verifies that UpdateRole — a whole-record
// replacement — cannot re-tenant a role or flip its system-role status. Re-tenanting
// would move a role out of its owner's ListRoles view (which filters on tenant_id) and
// leave it editable only through a fleet-wide read; promoting a tenant role to a system
// role would expose it to every tenant.
func TestStore_UpdateRole_TenantScopeIsImmutable(t *testing.T) {
	ctx := context.Background()
	store := NewStore()

	require.NoError(t, store.CreateRole(ctx, &common.Role{
		Id:       "tenant-a.viewer",
		Name:     "Tenant A Viewer",
		TenantId: "tenant-a",
	}))

	t.Run("tenant change rejected", func(t *testing.T) {
		err := store.UpdateRole(ctx, &common.Role{
			Id:       "tenant-a.viewer",
			Name:     "Tenant A Viewer",
			TenantId: "tenant-b",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tenant cannot be changed")

		stored, getErr := store.GetRole(ctx, "tenant-a.viewer")
		require.NoError(t, getErr)
		assert.Equal(t, "tenant-a", stored.TenantId)
	})

	t.Run("system-role promotion rejected", func(t *testing.T) {
		err := store.UpdateRole(ctx, &common.Role{
			Id:           "tenant-a.viewer",
			Name:         "Tenant A Viewer",
			TenantId:     "tenant-a",
			IsSystemRole: true,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "system-role status cannot be changed")

		stored, getErr := store.GetRole(ctx, "tenant-a.viewer")
		require.NoError(t, getErr)
		assert.False(t, stored.IsSystemRole)
	})

	t.Run("in-tenant edit applies and preserves creation time", func(t *testing.T) {
		before, err := store.GetRole(ctx, "tenant-a.viewer")
		require.NoError(t, err)
		createdAt := before.CreatedAt
		require.NotZero(t, createdAt)

		require.NoError(t, store.UpdateRole(ctx, &common.Role{
			Id:          "tenant-a.viewer",
			Name:        "Tenant A Viewer Updated",
			Description: "narrowed",
			TenantId:    "tenant-a",
		}))

		stored, err := store.GetRole(ctx, "tenant-a.viewer")
		require.NoError(t, err)
		assert.Equal(t, "Tenant A Viewer Updated", stored.Name)
		assert.Equal(t, "tenant-a", stored.TenantId)
		assert.Equal(t, createdAt, stored.CreatedAt,
			"a partial update record must not blank the creation timestamp")
	})
}
