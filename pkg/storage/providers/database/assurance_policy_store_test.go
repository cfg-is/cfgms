// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides unit tests for the PostgreSQL AssurancePolicyStore (Issue #2845).
package database

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestAssurancePolicyStore creates an AssurancePolicyStore backed by the test
// Postgres database. The schema is initialised fresh via the store constructor;
// the test is skipped when Postgres is unavailable.
func newTestAssurancePolicyStore(t *testing.T) *DatabaseAssurancePolicyStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreateAssurancePolicyOverridesTable(ctx, db))

	store, err := NewDatabaseAssurancePolicyStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestDatabaseAssurancePolicyStore_GetDefault verifies that GetPolicy returns an
// empty override set (Overrides: nil) when no record exists for the tenant.
func TestDatabaseAssurancePolicyStore_GetDefault(t *testing.T) {
	store := newTestAssurancePolicyStore(t)
	ctx := context.Background()

	p, err := store.GetPolicy(ctx, "tenant-ap-default")
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "tenant-ap-default", p.TenantID)
	assert.Nil(t, p.Overrides)
}

// TestDatabaseAssurancePolicyStore_SetAndGet verifies that SetPolicy persists a
// multi-entry override set and GetPolicy retrieves it correctly.
func TestDatabaseAssurancePolicyStore_SetAndGet(t *testing.T) {
	store := newTestAssurancePolicyStore(t)
	ctx := context.Background()

	minVal := 2 // Strong
	policy := &business.AssurancePolicy{
		TenantID: "tenant-ap-set",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "perm:write", MinOverride: &minVal, RequireUserPresence: true},
			{PermissionID: "perm:read"},
		},
	}
	require.NoError(t, store.SetPolicy(ctx, policy))

	got, err := store.GetPolicy(ctx, "tenant-ap-set")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "tenant-ap-set", got.TenantID)
	require.Len(t, got.Overrides, 2)

	// Find and verify each override (order is not guaranteed).
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

// TestDatabaseAssurancePolicyStore_SetReplaces verifies that a second SetPolicy
// call fully replaces the first: a permission dropped from the second call is
// absent from the next GetPolicy.
func TestDatabaseAssurancePolicyStore_SetReplaces(t *testing.T) {
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

	min2 := 2
	require.NoError(t, store.SetPolicy(ctx, &business.AssurancePolicy{
		TenantID: "tenant-ap-replace",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "perm:write", MinOverride: &min2},
		},
	}))

	got, err := store.GetPolicy(ctx, "tenant-ap-replace")
	require.NoError(t, err)
	require.Len(t, got.Overrides, 1, "second SetPolicy must fully replace the first")
	assert.Equal(t, "perm:write", got.Overrides[0].PermissionID)
	require.NotNil(t, got.Overrides[0].MinOverride)
	assert.Equal(t, 2, *got.Overrides[0].MinOverride)
}

// TestDatabaseAssurancePolicyStore_NilPolicyError verifies that SetPolicy
// rejects a nil policy.
func TestDatabaseAssurancePolicyStore_NilPolicyError(t *testing.T) {
	store := newTestAssurancePolicyStore(t)
	ctx := context.Background()
	err := store.SetPolicy(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

// TestDatabaseAssurancePolicyStore_EmptyTenantError verifies that SetPolicy
// rejects a policy with an empty TenantID.
func TestDatabaseAssurancePolicyStore_EmptyTenantError(t *testing.T) {
	store := newTestAssurancePolicyStore(t)
	ctx := context.Background()
	err := store.SetPolicy(ctx, &business.AssurancePolicy{
		Overrides: []business.AssurancePolicyOverride{{PermissionID: "perm:read"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id")
}
