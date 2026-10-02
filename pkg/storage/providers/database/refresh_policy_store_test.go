// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides unit tests for the PostgreSQL RefreshPolicyStore (Issue #2329).
package database

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestRefreshPolicyStore creates a RefreshPolicyStore backed by the test Postgres
// database. The schema is initialised fresh via the store constructor; the test is
// skipped when Postgres is unavailable.
func newTestRefreshPolicyStore(t *testing.T) *DatabaseRefreshPolicyStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreateRefreshPoliciesTable(ctx, db))

	store, err := NewDatabaseRefreshPolicyStore(db, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestDatabaseRefreshPolicyStore_GetDefault verifies that GetPolicy returns the
// default policy when no explicit record exists for the tenant.
func TestDatabaseRefreshPolicyStore_GetDefault(t *testing.T) {
	store := newTestRefreshPolicyStore(t)
	ctx := context.Background()

	p, err := store.GetPolicy(ctx, "tenant-rp-default")
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "tenant-rp-default", p.TenantID)
	assert.Equal(t, "require_approval", p.Mode)
	assert.Nil(t, p.MaxDormancyDays)
}

// TestDatabaseRefreshPolicyStore_SetAndGet verifies that SetPolicy persists the
// policy and GetPolicy retrieves it correctly.
func TestDatabaseRefreshPolicyStore_SetAndGet(t *testing.T) {
	store := newTestRefreshPolicyStore(t)
	ctx := context.Background()

	v := 30
	policy := &business.RefreshPolicy{
		TenantID:        "tenant-rp-set",
		Mode:            "auto_accept",
		MaxDormancyDays: &v,
	}
	require.NoError(t, store.SetPolicy(ctx, policy))

	got, err := store.GetPolicy(ctx, "tenant-rp-set")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "tenant-rp-set", got.TenantID)
	assert.Equal(t, "auto_accept", got.Mode)
	require.NotNil(t, got.MaxDormancyDays)
	assert.Equal(t, 30, *got.MaxDormancyDays)
}

// TestDatabaseRefreshPolicyStore_SetNoMaxDormancy verifies that a nil
// MaxDormancyDays is stored as NULL and returned as nil.
func TestDatabaseRefreshPolicyStore_SetNoMaxDormancy(t *testing.T) {
	store := newTestRefreshPolicyStore(t)
	ctx := context.Background()

	policy := &business.RefreshPolicy{
		TenantID:        "tenant-rp-nodorm",
		Mode:            "reject",
		MaxDormancyDays: nil,
	}
	require.NoError(t, store.SetPolicy(ctx, policy))

	got, err := store.GetPolicy(ctx, "tenant-rp-nodorm")
	require.NoError(t, err)
	assert.Equal(t, "reject", got.Mode)
	assert.Nil(t, got.MaxDormancyDays)
}

// TestDatabaseRefreshPolicyStore_Upsert verifies that a second SetPolicy call
// updates the existing record rather than creating a duplicate.
func TestDatabaseRefreshPolicyStore_Upsert(t *testing.T) {
	store := newTestRefreshPolicyStore(t)
	ctx := context.Background()

	require.NoError(t, store.SetPolicy(ctx, &business.RefreshPolicy{
		TenantID: "tenant-rp-upsert",
		Mode:     "auto_accept",
	}))

	v := 7
	require.NoError(t, store.SetPolicy(ctx, &business.RefreshPolicy{
		TenantID:        "tenant-rp-upsert",
		Mode:            "require_approval",
		MaxDormancyDays: &v,
	}))

	got, err := store.GetPolicy(ctx, "tenant-rp-upsert")
	require.NoError(t, err)
	assert.Equal(t, "require_approval", got.Mode)
	require.NotNil(t, got.MaxDormancyDays)
	assert.Equal(t, 7, *got.MaxDormancyDays)
}

// TestDatabaseRefreshPolicyStore_NilPolicyError verifies that SetPolicy rejects a nil policy.
func TestDatabaseRefreshPolicyStore_NilPolicyError(t *testing.T) {
	store := newTestRefreshPolicyStore(t)
	ctx := context.Background()
	err := store.SetPolicy(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

// TestDatabaseRefreshPolicyStore_EmptyTenantError verifies that SetPolicy rejects
// a policy with an empty TenantID.
func TestDatabaseRefreshPolicyStore_EmptyTenantError(t *testing.T) {
	store := newTestRefreshPolicyStore(t)
	ctx := context.Background()
	err := store.SetPolicy(ctx, &business.RefreshPolicy{TenantID: "", Mode: "auto_accept"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id")
}
