// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Tests for DatabaseRBACStore.StoreBulkRoles parent_role_id handling. The
// column has a self-referential foreign key, so an empty ParentRoleId must be
// stored as NULL (as StoreRole does) or every parentless bulk insert, including
// a new tenant's default roles, is rejected. These run against the real
// PostgreSQL test database and skip when it is unavailable.
package database

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

func TestStoreBulkRoles_EmptyParentStoredAsNull(t *testing.T) {
	store := newDeleteRoleTestStore(t)
	ctx := ctxkeys.WithSystem(context.Background())

	roles := []*common.Role{
		{Id: "bulk-t1.tenant.admin", Name: "Admin", TenantId: "bulk-t1"},
		{Id: "bulk-t1.tenant.viewer", Name: "Viewer", TenantId: "bulk-t1"},
	}
	require.NoError(t, store.StoreBulkRoles(ctx, roles))

	for _, r := range roles {
		got, err := store.GetRole(ctx, r.Id)
		require.NoError(t, err)
		assert.Empty(t, got.ParentRoleId)

		var parent sql.NullString
		require.NoError(t, store.db.QueryRowContext(ctx,
			`SELECT parent_role_id FROM rbac_roles WHERE id = $1`, r.Id).Scan(&parent))
		assert.False(t, parent.Valid, "empty ParentRoleId must be persisted as SQL NULL, not ''")
	}
}

func TestStoreBulkRoles_ParentReferenceEnforced(t *testing.T) {
	store := newDeleteRoleTestStore(t)
	ctx := ctxkeys.WithSystem(context.Background())

	t.Run("existing parent in same batch is stored", func(t *testing.T) {
		require.NoError(t, store.StoreBulkRoles(ctx, []*common.Role{
			{Id: "bulk-parent", Name: "Parent", TenantId: "bulk-t2"},
			{Id: "bulk-child", Name: "Child", TenantId: "bulk-t2", ParentRoleId: "bulk-parent"},
		}))

		got, err := store.GetRole(ctx, "bulk-child")
		require.NoError(t, err)
		assert.Equal(t, "bulk-parent", got.ParentRoleId)
	})

	t.Run("nonexistent parent is rejected by the foreign key", func(t *testing.T) {
		err := store.StoreBulkRoles(ctx, []*common.Role{
			{Id: "bulk-orphan", Name: "Orphan", TenantId: "bulk-t2", ParentRoleId: "no-such-role"},
		})
		require.Error(t, err)

		_, getErr := store.GetRole(ctx, "bulk-orphan")
		assert.Error(t, getErr, "a rejected batch must not leave the role behind")
	})
}
