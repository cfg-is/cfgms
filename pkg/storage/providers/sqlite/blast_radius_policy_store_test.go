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

// newTestBlastRadiusPolicyStore opens an in-memory SQLite store for testing.
func newTestBlastRadiusPolicyStore(t *testing.T) *SQLiteBlastRadiusPolicyStore {
	t.Helper()
	db, err := openAndInit(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return &SQLiteBlastRadiusPolicyStore{db: db}
}

// TestBlastRadiusPolicyStore_DefaultEmpty verifies that GetPolicy returns
// MaxTargets: nil when no record exists for the tenant (Issue #3698 AC).
func TestBlastRadiusPolicyStore_DefaultEmpty(t *testing.T) {
	store := newTestBlastRadiusPolicyStore(t)
	ctx := context.Background()

	got, err := store.GetPolicy(ctx, "tenant-brp-absent")
	require.NoError(t, err, "absent record must not be an error")
	require.NotNil(t, got)
	assert.Equal(t, "tenant-brp-absent", got.TenantID)
	assert.Nil(t, got.MaxTargets, "MaxTargets must default to nil when no record exists")
}

func TestBlastRadiusPolicyStore_SetAndGet(t *testing.T) {
	store := newTestBlastRadiusPolicyStore(t)
	ctx := context.Background()

	maxTargets := 250
	require.NoError(t, store.SetPolicy(ctx, &business.BlastRadiusPolicy{
		TenantID:   "tenant-brp-1",
		MaxTargets: &maxTargets,
	}))

	got, err := store.GetPolicy(ctx, "tenant-brp-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "tenant-brp-1", got.TenantID)
	require.NotNil(t, got.MaxTargets)
	assert.Equal(t, 250, *got.MaxTargets)
}

func TestBlastRadiusPolicyStore_SetReplaces(t *testing.T) {
	store := newTestBlastRadiusPolicyStore(t)
	ctx := context.Background()

	first := 100
	require.NoError(t, store.SetPolicy(ctx, &business.BlastRadiusPolicy{
		TenantID:   "tenant-brp-replace",
		MaxTargets: &first,
	}))

	second := 50
	require.NoError(t, store.SetPolicy(ctx, &business.BlastRadiusPolicy{
		TenantID:   "tenant-brp-replace",
		MaxTargets: &second,
	}))

	got, err := store.GetPolicy(ctx, "tenant-brp-replace")
	require.NoError(t, err)
	require.NotNil(t, got.MaxTargets)
	assert.Equal(t, 50, *got.MaxTargets, "second SetPolicy must replace the first value")
}

func TestBlastRadiusPolicyStore_SetClearsOverride(t *testing.T) {
	store := newTestBlastRadiusPolicyStore(t)
	ctx := context.Background()

	val := 500
	require.NoError(t, store.SetPolicy(ctx, &business.BlastRadiusPolicy{
		TenantID:   "tenant-brp-clear",
		MaxTargets: &val,
	}))
	require.NoError(t, store.SetPolicy(ctx, &business.BlastRadiusPolicy{
		TenantID:   "tenant-brp-clear",
		MaxTargets: nil,
	}))

	got, err := store.GetPolicy(ctx, "tenant-brp-clear")
	require.NoError(t, err)
	assert.Nil(t, got.MaxTargets)
}

func TestBlastRadiusPolicyStore_SetNilPolicy(t *testing.T) {
	store := newTestBlastRadiusPolicyStore(t)
	err := store.SetPolicy(context.Background(), nil)
	require.Error(t, err)
}

func TestBlastRadiusPolicyStore_SetEmptyTenantID(t *testing.T) {
	store := newTestBlastRadiusPolicyStore(t)
	maxTargets := 10
	err := store.SetPolicy(context.Background(), &business.BlastRadiusPolicy{MaxTargets: &maxTargets})
	require.Error(t, err)
}
