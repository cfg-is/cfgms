// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func newRBACStore(t *testing.T) business.RBACStore {
	t.Helper()
	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	store, err := p.CreateRBACStore(map[string]interface{}{"path": filepath.Join(dir, "rbac.db")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestRBACStore_Permission_CRUD(t *testing.T) {
	store := newRBACStore(t)
	ctx := context.Background()

	perm := &common.Permission{
		Id:           "perm-1",
		Name:         "steward.read",
		Description:  "Read steward data",
		ResourceType: "steward",
		Actions:      []string{"read", "list"},
	}
	require.NoError(t, store.StorePermission(ctx, perm))

	got, err := store.GetPermission(ctx, "perm-1")
	require.NoError(t, err)
	assert.Equal(t, perm.Id, got.Id)
	assert.Equal(t, perm.Name, got.Name)
	assert.Equal(t, perm.Actions, got.Actions)

	// Update
	perm.Actions = []string{"read"}
	require.NoError(t, store.UpdatePermission(ctx, perm))
	updated, err := store.GetPermission(ctx, "perm-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"read"}, updated.Actions)

	// Delete
	require.NoError(t, store.DeletePermission(ctx, "perm-1"))
	_, err = store.GetPermission(ctx, "perm-1")
	assert.Error(t, err)
}

func TestRBACStore_Permission_NotFound(t *testing.T) {
	store := newRBACStore(t)
	ctx := context.Background()
	_, err := store.GetPermission(ctx, "nonexistent")
	assert.Error(t, err)
}

func TestRBACStore_ListPermissions(t *testing.T) {
	store := newRBACStore(t)
	ctx := context.Background()

	for _, p := range []*common.Permission{
		{Id: "p-1", ResourceType: "steward", Name: "p1", Actions: []string{"read"}},
		{Id: "p-2", ResourceType: "tenant", Name: "p2", Actions: []string{"write"}},
		{Id: "p-3", ResourceType: "steward", Name: "p3", Actions: []string{"delete"}},
	} {
		require.NoError(t, store.StorePermission(ctx, p))
	}

	all, err := store.ListPermissions(ctx, "")
	require.NoError(t, err)
	assert.Len(t, all, 3)

	steward, err := store.ListPermissions(ctx, "steward")
	require.NoError(t, err)
	assert.Len(t, steward, 2)
}

func TestRBACStore_Role_CRUD(t *testing.T) {
	store := newRBACStore(t)
	ctx := context.Background()

	role := &common.Role{
		Id:            "role-1",
		Name:          "admin",
		Description:   "Administrator",
		PermissionIds: []string{"p-1", "p-2"},
		IsSystemRole:  false,
		TenantId:      "tenant-a",
	}
	require.NoError(t, store.StoreRole(ctx, role))

	got, err := store.GetRole(ctx, "role-1")
	require.NoError(t, err)
	assert.Equal(t, role.Id, got.Id)
	assert.Equal(t, role.Name, got.Name)
	assert.Equal(t, role.PermissionIds, got.PermissionIds)
	assert.False(t, got.IsSystemRole)

	// Delete
	require.NoError(t, store.DeleteRole(ctx, "role-1"))
	_, err = store.GetRole(ctx, "role-1")
	assert.Error(t, err)
}

func TestRBACStore_ListRoles_TenantScoped(t *testing.T) {
	store := newRBACStore(t)
	ctx := context.Background()

	require.NoError(t, store.StoreRole(ctx, &common.Role{Id: "sys-role", Name: "system", IsSystemRole: true}))
	require.NoError(t, store.StoreRole(ctx, &common.Role{Id: "ta-role", Name: "ta-admin", TenantId: "tenant-a"}))
	require.NoError(t, store.StoreRole(ctx, &common.Role{Id: "tb-role", Name: "tb-admin", TenantId: "tenant-b"}))

	roles, err := store.ListRoles(ctx, "tenant-a")
	require.NoError(t, err)
	// Should include the system role and tenant-a role
	ids := make(map[string]bool)
	for _, r := range roles {
		ids[r.Id] = true
	}
	assert.True(t, ids["sys-role"])
	assert.True(t, ids["ta-role"])
	assert.False(t, ids["tb-role"])
}

func TestRBACStore_Subject_CRUD(t *testing.T) {
	store := newRBACStore(t)
	ctx := context.Background()

	subj := &common.Subject{
		Id:          "subj-1",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Alice",
		TenantId:    "tenant-a",
		RoleIds:     []string{"role-1"},
		IsActive:    true,
	}
	require.NoError(t, store.StoreSubject(ctx, subj))

	got, err := store.GetSubject(ctx, "subj-1")
	require.NoError(t, err)
	assert.Equal(t, subj.Id, got.Id)
	assert.Equal(t, subj.DisplayName, got.DisplayName)
	assert.Equal(t, common.SubjectType_SUBJECT_TYPE_USER, got.Type)
	assert.True(t, got.IsActive)
	assert.Equal(t, []string{"role-1"}, got.RoleIds)

	require.NoError(t, store.DeleteSubject(ctx, "subj-1"))
	_, err = store.GetSubject(ctx, "subj-1")
	assert.Error(t, err)
}

func TestRBACStore_RoleAssignment_CRUD(t *testing.T) {
	store := newRBACStore(t)
	ctx := context.Background()

	a := &common.RoleAssignment{
		Id:         "assign-1",
		SubjectId:  "user-1",
		RoleId:     "role-1",
		TenantId:   "tenant-a",
		AssignedBy: "admin",
	}
	require.NoError(t, store.StoreRoleAssignment(ctx, a))

	got, err := store.GetRoleAssignment(ctx, "assign-1")
	require.NoError(t, err)
	assert.Equal(t, a.Id, got.Id)
	assert.Equal(t, a.SubjectId, got.SubjectId)

	require.NoError(t, store.DeleteRoleAssignment(ctx, "user-1", "role-1", "tenant-a"))
	_, err = store.GetRoleAssignment(ctx, "assign-1")
	assert.Error(t, err)
}

func TestRBACStore_BulkOperations(t *testing.T) {
	store := newRBACStore(t)
	ctx := context.Background()

	// A nil element must be skipped rather than aborting the batch, and every
	// non-nil element must be persisted and readable.
	perms := []*common.Permission{
		{Id: "bp-1", Name: "bp1", ResourceType: "r", Actions: []string{"read"}},
		nil,
		{Id: "bp-2", Name: "bp2", ResourceType: "r", Actions: []string{"write"}},
	}
	require.NoError(t, store.StoreBulkPermissions(ctx, perms))

	list, err := store.ListPermissions(ctx, "r")
	require.NoError(t, err)
	assert.Len(t, list, 2)

	roles := []*common.Role{
		{Id: "br-1", Name: "br1"},
		nil,
		{Id: "br-2", Name: "br2", PermissionIds: []string{"bp-1"}},
	}
	require.NoError(t, store.StoreBulkRoles(ctx, roles))

	gotRole, err := store.GetRole(ctx, "br-2")
	require.NoError(t, err)
	assert.Equal(t, "br2", gotRole.Name)
	assert.Equal(t, []string{"bp-1"}, gotRole.PermissionIds)

	subjects := []*common.Subject{
		{Id: "bs-1", Type: common.SubjectType_SUBJECT_TYPE_USER, DisplayName: "Bob", TenantId: "t", IsActive: true},
		nil,
	}
	require.NoError(t, store.StoreBulkSubjects(ctx, subjects))

	gotSubject, err := store.GetSubject(ctx, "bs-1")
	require.NoError(t, err)
	assert.Equal(t, "Bob", gotSubject.DisplayName)
}

// TestRBACStore_BulkOperations_Upsert covers the ON CONFLICT arm of each bulk
// writer: re-running a batch with the same IDs must update the existing rows in
// place rather than inserting duplicates or failing on the primary key. Default
// permissions and roles are re-seeded on every controller start, so this is the
// path exercised by every boot after the first.
func TestRBACStore_BulkOperations_Upsert(t *testing.T) {
	store := newRBACStore(t)
	ctx := context.Background()

	require.NoError(t, store.StoreBulkPermissions(ctx, []*common.Permission{
		{Id: "up-1", Name: "before", ResourceType: "res", Actions: []string{"read"}},
	}))
	require.NoError(t, store.StoreBulkPermissions(ctx, []*common.Permission{
		{Id: "up-1", Name: "after", ResourceType: "res", Actions: []string{"read", "write"}},
	}))

	perms, err := store.ListPermissions(ctx, "res")
	require.NoError(t, err)
	require.Len(t, perms, 1, "re-storing the same permission ID must update, not duplicate")
	assert.Equal(t, "after", perms[0].Name)
	assert.Equal(t, []string{"read", "write"}, perms[0].Actions)

	require.NoError(t, store.StoreBulkRoles(ctx, []*common.Role{
		{Id: "ur-1", Name: "before", TenantId: "t-1"},
	}))
	require.NoError(t, store.StoreBulkRoles(ctx, []*common.Role{
		{Id: "ur-1", Name: "after", TenantId: "t-1", PermissionIds: []string{"up-1"}},
	}))

	roles, err := store.ListRoles(ctx, "t-1")
	require.NoError(t, err)
	require.Len(t, roles, 1, "re-storing the same role ID must update, not duplicate")
	assert.Equal(t, "after", roles[0].Name)
	assert.Equal(t, []string{"up-1"}, roles[0].PermissionIds)

	require.NoError(t, store.StoreBulkSubjects(ctx, []*common.Subject{
		{Id: "us-1", Type: common.SubjectType_SUBJECT_TYPE_USER, DisplayName: "before", TenantId: "t-1", IsActive: true},
	}))
	require.NoError(t, store.StoreBulkSubjects(ctx, []*common.Subject{
		{Id: "us-1", Type: common.SubjectType_SUBJECT_TYPE_USER, DisplayName: "after", TenantId: "t-1", IsActive: false},
	}))

	subjects, err := store.ListSubjects(ctx, "t-1", common.SubjectType_SUBJECT_TYPE_USER)
	require.NoError(t, err)
	require.Len(t, subjects, 1, "re-storing the same subject ID must update, not duplicate")
	assert.Equal(t, "after", subjects[0].DisplayName)
	assert.False(t, subjects[0].IsActive)
}

func TestRBACStore_GetSubjectRoles(t *testing.T) {
	store := newRBACStore(t)
	ctx := context.Background()

	require.NoError(t, store.StoreRole(ctx, &common.Role{Id: "r-1", Name: "admin"}))
	require.NoError(t, store.StoreRoleAssignment(ctx, &common.RoleAssignment{
		Id: "a-1", SubjectId: "u-1", RoleId: "r-1", TenantId: "t-1", AssignedBy: "admin",
	}))

	roles, err := store.GetSubjectRoles(ctx, "u-1", "t-1")
	require.NoError(t, err)
	require.Len(t, roles, 1)
	assert.Equal(t, "r-1", roles[0].Id)
}
