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

// newTestRefreshPolicyStore opens an in-memory SQLite store for testing.
func newTestRefreshPolicyStore(t *testing.T) *SQLiteRefreshPolicyStore {
	t.Helper()
	db, err := openAndInit(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return &SQLiteRefreshPolicyStore{db: db}
}

// TestRefreshPolicyStore_DefaultPolicy verifies that GetPolicy returns the
// default require_approval policy when no record exists (ADR-010 §4, Issue #2093 AC).
func TestRefreshPolicyStore_DefaultPolicy(t *testing.T) {
	store := newTestRefreshPolicyStore(t)
	ctx := context.Background()

	got, err := store.GetPolicy(ctx, "tenant-no-record")
	require.NoError(t, err, "absent record must not be an error")
	require.NotNil(t, got)
	assert.Equal(t, "tenant-no-record", got.TenantID)
	assert.Equal(t, "require_approval", got.Mode)
	assert.Nil(t, got.MaxDormancyDays, "MaxDormancyDays must default to nil (backstop OFF)")
}

func TestRefreshPolicyStore_SetAndGet(t *testing.T) {
	store := newTestRefreshPolicyStore(t)
	ctx := context.Background()

	days := 30
	policy := &business.RefreshPolicy{
		TenantID:        "tenant-1",
		Mode:            "auto_accept",
		MaxDormancyDays: &days,
	}
	require.NoError(t, store.SetPolicy(ctx, policy))

	got, err := store.GetPolicy(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, "tenant-1", got.TenantID)
	assert.Equal(t, "auto_accept", got.Mode)
	require.NotNil(t, got.MaxDormancyDays)
	assert.Equal(t, 30, *got.MaxDormancyDays)
}

func TestRefreshPolicyStore_SetOverwritesExisting(t *testing.T) {
	store := newTestRefreshPolicyStore(t)
	ctx := context.Background()

	require.NoError(t, store.SetPolicy(ctx, &business.RefreshPolicy{
		TenantID: "tenant-upd",
		Mode:     "auto_accept",
	}))
	require.NoError(t, store.SetPolicy(ctx, &business.RefreshPolicy{
		TenantID: "tenant-upd",
		Mode:     "reject",
	}))

	got, err := store.GetPolicy(ctx, "tenant-upd")
	require.NoError(t, err)
	assert.Equal(t, "reject", got.Mode, "second SetPolicy must overwrite")
	assert.Nil(t, got.MaxDormancyDays)
}

func TestRefreshPolicyStore_NilMaxDormancyDays(t *testing.T) {
	store := newTestRefreshPolicyStore(t)
	ctx := context.Background()

	require.NoError(t, store.SetPolicy(ctx, &business.RefreshPolicy{
		TenantID:        "tenant-nil",
		Mode:            "require_approval",
		MaxDormancyDays: nil,
	}))

	got, err := store.GetPolicy(ctx, "tenant-nil")
	require.NoError(t, err)
	assert.Nil(t, got.MaxDormancyDays, "nil MaxDormancyDays must round-trip as nil")
}

func TestRefreshPolicyStore_SetNilPolicy(t *testing.T) {
	store := newTestRefreshPolicyStore(t)
	err := store.SetPolicy(context.Background(), nil)
	require.Error(t, err)
}

func TestRefreshPolicyStore_SetEmptyTenantID(t *testing.T) {
	store := newTestRefreshPolicyStore(t)
	err := store.SetPolicy(context.Background(), &business.RefreshPolicy{Mode: "reject"})
	require.Error(t, err)
}
