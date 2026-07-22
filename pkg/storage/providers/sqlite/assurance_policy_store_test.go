// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestAssurancePolicyStore opens an in-memory SQLite store for testing.
func newTestAssurancePolicyStore(t *testing.T) *SQLiteAssurancePolicyStore {
	t.Helper()
	db, err := openAndInit(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return &SQLiteAssurancePolicyStore{db: db}
}

// TestAssurancePolicyStore_DefaultEmpty verifies that GetPolicy returns an empty
// override set when no record exists for the tenant (ADR-021, Issue #2845 AC).
func TestAssurancePolicyStore_DefaultEmpty(t *testing.T) {
	store := newTestAssurancePolicyStore(t)
	ctx := context.Background()

	got, err := store.GetPolicy(ctx, "tenant-ap-absent")
	require.NoError(t, err, "absent record must not be an error")
	require.NotNil(t, got)
	assert.Equal(t, "tenant-ap-absent", got.TenantID)
	assert.Nil(t, got.Overrides, "Overrides must default to nil when no record exists")
}

func TestAssurancePolicyStore_SetAndGet(t *testing.T) {
	store := newTestAssurancePolicyStore(t)
	ctx := context.Background()

	minVal := 2 // Strong
	policy := &business.AssurancePolicy{
		TenantID: "tenant-ap-1",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "perm:write", MinOverride: &minVal, RequireUserPresence: true},
			{PermissionID: "perm:read"},
		},
	}
	require.NoError(t, store.SetPolicy(ctx, policy))

	got, err := store.GetPolicy(ctx, "tenant-ap-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "tenant-ap-1", got.TenantID)
	require.Len(t, got.Overrides, 2)

	// Find and verify each override (order is not guaranteed by SQLite).
	byPerm := make(map[string]business.AssurancePolicyOverride, len(got.Overrides))
	for _, o := range got.Overrides {
		byPerm[o.PermissionID] = o
	}

	write, ok := byPerm["perm:write"]
	require.True(t, ok, "perm:write must be present")
	require.NotNil(t, write.MinOverride)
	assert.Equal(t, 2, *write.MinOverride)
	assert.True(t, write.RequireUserPresence)

	read, ok := byPerm["perm:read"]
	require.True(t, ok, "perm:read must be present")
	assert.Nil(t, read.MinOverride)
	assert.False(t, read.RequireUserPresence)
}

func TestAssurancePolicyStore_SetReplaces(t *testing.T) {
	store := newTestAssurancePolicyStore(t)
	ctx := context.Background()

	min1 := 1
	require.NoError(t, store.SetPolicy(ctx, &business.AssurancePolicy{
		TenantID: "tenant-ap-replace",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "perm:admin", MinOverride: &min1},
			{PermissionID: "perm:read"},
		},
	}))

	// Second call fully replaces; perm:admin and perm:read are dropped.
	min2 := 2
	require.NoError(t, store.SetPolicy(ctx, &business.AssurancePolicy{
		TenantID: "tenant-ap-replace",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "perm:write", MinOverride: &min2},
		},
	}))

	got, err := store.GetPolicy(ctx, "tenant-ap-replace")
	require.NoError(t, err)
	require.Len(t, got.Overrides, 1, "second SetPolicy must fully replace first")
	assert.Equal(t, "perm:write", got.Overrides[0].PermissionID)
	require.NotNil(t, got.Overrides[0].MinOverride)
	assert.Equal(t, 2, *got.Overrides[0].MinOverride)
}

func TestAssurancePolicyStore_SetNilPolicy(t *testing.T) {
	store := newTestAssurancePolicyStore(t)
	err := store.SetPolicy(context.Background(), nil)
	require.Error(t, err)
}

func TestAssurancePolicyStore_SetEmptyTenantID(t *testing.T) {
	store := newTestAssurancePolicyStore(t)
	err := store.SetPolicy(context.Background(), &business.AssurancePolicy{
		Overrides: []business.AssurancePolicyOverride{{PermissionID: "perm:read"}},
	})
	require.Error(t, err)
}
