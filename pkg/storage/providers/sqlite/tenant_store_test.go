// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func newTenantStore(t *testing.T) business.TenantStore {
	t.Helper()
	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	store, err := p.CreateTenantStore(map[string]interface{}{"path": filepath.Join(dir, "tenants.db")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestTenantStore_CreateAndGet(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()

	tenant := &business.TenantData{
		ID:          "tenant-1",
		Name:        "Acme Corp",
		Description: "Test tenant",
		Status:      business.TenantStatusActive,
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		UpdatedAt:   time.Now().UTC().Truncate(time.Second),
		Metadata:    map[string]string{"key": "value"},
	}

	require.NoError(t, store.CreateTenant(ctx, tenant))

	got, err := store.GetTenant(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, tenant.ID, got.ID)
	assert.Equal(t, tenant.Name, got.Name)
	assert.Equal(t, tenant.Description, got.Description)
	assert.Equal(t, tenant.Status, got.Status)
	assert.Equal(t, "value", got.Metadata["key"])
}

func TestTenantStore_GetNotFound(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()

	_, err := store.GetTenant(ctx, "nonexistent")
	assert.Error(t, err)
}

func TestTenantStore_Update(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()

	tenant := &business.TenantData{
		ID:     "tenant-2",
		Name:   "Original",
		Status: business.TenantStatusActive,
	}
	require.NoError(t, store.CreateTenant(ctx, tenant))

	tenant.Name = "Updated"
	tenant.Status = business.TenantStatusSuspended
	require.NoError(t, store.UpdateTenant(ctx, tenant))

	got, err := store.GetTenant(ctx, "tenant-2")
	require.NoError(t, err)
	assert.Equal(t, "Updated", got.Name)
	assert.Equal(t, business.TenantStatusSuspended, got.Status)
}

func TestTenantStore_UpdateNotFound(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()

	err := store.UpdateTenant(ctx, &business.TenantData{ID: "nonexistent", Name: "X"})
	assert.Error(t, err)
}

func TestTenantStore_Delete(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()

	tenant := &business.TenantData{
		ID:     "tenant-del",
		Name:   "ToDelete",
		Status: business.TenantStatusActive,
	}
	require.NoError(t, store.CreateTenant(ctx, tenant))
	require.NoError(t, store.DeleteTenant(ctx, "tenant-del"))

	_, err := store.GetTenant(ctx, "tenant-del")
	assert.Error(t, err)
}

func TestTenantStore_DeleteNotFound(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()

	assert.Error(t, store.DeleteTenant(ctx, "nonexistent"))
}

func TestTenantStore_List(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()

	for _, td := range []business.TenantData{
		{ID: "t-1", Name: "Alpha", Status: business.TenantStatusActive},
		{ID: "t-2", Name: "Beta", Status: business.TenantStatusSuspended},
		{ID: "t-3", Name: "Gamma", Status: business.TenantStatusActive},
	} {
		td := td
		require.NoError(t, store.CreateTenant(ctx, &td))
	}

	all, err := store.ListTenants(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, all, 3)

	active, err := store.ListTenants(ctx, &business.TenantFilter{Status: business.TenantStatusActive})
	require.NoError(t, err)
	assert.Len(t, active, 2)
}

func TestTenantStore_Hierarchy(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()

	root := &business.TenantData{ID: "root", Name: "Root", Status: business.TenantStatusActive}
	child := &business.TenantData{ID: "child", Name: "Child", ParentID: "root", Status: business.TenantStatusActive}
	grand := &business.TenantData{ID: "grand", Name: "Grandchild", ParentID: "child", Status: business.TenantStatusActive}

	require.NoError(t, store.CreateTenant(ctx, root))
	require.NoError(t, store.CreateTenant(ctx, child))
	require.NoError(t, store.CreateTenant(ctx, grand))

	// Path
	path, err := store.GetTenantPath(ctx, "grand")
	require.NoError(t, err)
	assert.Equal(t, []string{"root", "child", "grand"}, path)

	// IsAncestor
	isAncestor, err := store.IsTenantAncestor(ctx, "root", "grand")
	require.NoError(t, err)
	assert.True(t, isAncestor)

	notAncestor, err := store.IsTenantAncestor(ctx, "grand", "root")
	require.NoError(t, err)
	assert.False(t, notAncestor)

	// Children
	children, err := store.GetChildTenants(ctx, "root")
	require.NoError(t, err)
	require.Len(t, children, 1)
	assert.Equal(t, "child", children[0].ID)

	// Hierarchy struct
	hier, err := store.GetTenantHierarchy(ctx, "child")
	require.NoError(t, err)
	assert.Equal(t, 1, hier.Depth) // child is depth 1
	assert.Equal(t, []string{"grand"}, hier.Children)
}

func TestTenantStore_MultiTenantIsolation(t *testing.T) {
	store := newTenantStore(t)
	ctx := context.Background()

	t1 := &business.TenantData{ID: "msp-a", Name: "MSP A", Status: business.TenantStatusActive}
	t2 := &business.TenantData{ID: "msp-b", Name: "MSP B", Status: business.TenantStatusActive}

	require.NoError(t, store.CreateTenant(ctx, t1))
	require.NoError(t, store.CreateTenant(ctx, t2))

	got1, err := store.GetTenant(ctx, "msp-a")
	require.NoError(t, err)
	assert.Equal(t, "MSP A", got1.Name)

	got2, err := store.GetTenant(ctx, "msp-b")
	require.NoError(t, err)
	assert.Equal(t, "MSP B", got2.Name)

	// Verify they don't cross-contaminate
	assert.NotEqual(t, got1.ID, got2.ID)
}
