// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides unit tests for the PostgreSQL BlastRadiusPolicyStore (Issue #3698).
package database

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestBlastRadiusPolicyStore creates a BlastRadiusPolicyStore backed by the test
// Postgres database. The schema is initialised fresh via the store constructor;
// the test is skipped when Postgres is unavailable.
func newTestBlastRadiusPolicyStore(t *testing.T) *DatabaseBlastRadiusPolicyStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreateBlastRadiusPolicyOverridesTable(ctx, db))

	store, err := NewDatabaseBlastRadiusPolicyStore(db, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestDatabaseBlastRadiusPolicyStore_GetDefault verifies that GetPolicy returns
// {MaxTargets: nil} when no record exists for the tenant.
func TestDatabaseBlastRadiusPolicyStore_GetDefault(t *testing.T) {
	store := newTestBlastRadiusPolicyStore(t)
	ctx := context.Background()

	p, err := store.GetPolicy(ctx, "tenant-brp-default")
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "tenant-brp-default", p.TenantID)
	assert.Nil(t, p.MaxTargets)
}

// TestDatabaseBlastRadiusPolicyStore_SetAndGet verifies that SetPolicy persists a
// MaxTargets override and GetPolicy retrieves it correctly.
func TestDatabaseBlastRadiusPolicyStore_SetAndGet(t *testing.T) {
	store := newTestBlastRadiusPolicyStore(t)
	ctx := context.Background()

	maxTargets := 250
	require.NoError(t, store.SetPolicy(ctx, &business.BlastRadiusPolicy{
		TenantID:   "tenant-brp-set",
		MaxTargets: &maxTargets,
	}))

	got, err := store.GetPolicy(ctx, "tenant-brp-set")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "tenant-brp-set", got.TenantID)
	require.NotNil(t, got.MaxTargets)
	assert.Equal(t, 250, *got.MaxTargets)
}

// TestDatabaseBlastRadiusPolicyStore_SetReplaces verifies that a second SetPolicy
// call for the same tenant replaces (upserts) the prior value rather than erroring
// or duplicating rows.
func TestDatabaseBlastRadiusPolicyStore_SetReplaces(t *testing.T) {
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

// TestDatabaseBlastRadiusPolicyStore_SetClearsOverride verifies that SetPolicy
// with MaxTargets == nil clears a previously set override.
func TestDatabaseBlastRadiusPolicyStore_SetClearsOverride(t *testing.T) {
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

// TestDatabaseBlastRadiusPolicyStore_NilPolicyError verifies that SetPolicy
// rejects a nil policy.
func TestDatabaseBlastRadiusPolicyStore_NilPolicyError(t *testing.T) {
	store := newTestBlastRadiusPolicyStore(t)
	ctx := context.Background()
	err := store.SetPolicy(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

// TestDatabaseBlastRadiusPolicyStore_EmptyTenantError verifies that SetPolicy
// rejects a policy with an empty TenantID.
func TestDatabaseBlastRadiusPolicyStore_EmptyTenantError(t *testing.T) {
	store := newTestBlastRadiusPolicyStore(t)
	ctx := context.Background()
	maxTargets := 10
	err := store.SetPolicy(ctx, &business.BlastRadiusPolicy{MaxTargets: &maxTargets})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id")
}
