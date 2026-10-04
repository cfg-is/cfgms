// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func seedTenant(t *testing.T, m *Manager, id, parent string) {
	t.Helper()
	now := time.Now()
	require.NoError(t, m.store.CreateTenant(context.Background(), &business.TenantData{
		ID: id, Name: id, ParentID: parent, Status: business.TenantStatusActive, CreatedAt: now, UpdatedAt: now}))
}

// TestRootTenantID_Resolution guards Issue #4542's resolution order: "root" when
// it exists, else the single top-level tenant, "root" on an empty store, and ""
// (fail closed) when several top-level tenants exist and none is named root.
func TestRootTenantID_Resolution(t *testing.T) {
	ctx := context.Background()

	t.Run("empty store", func(t *testing.T) {
		assert.Equal(t, RootTenantID, newTestTenantManager(t).RootTenantID(ctx))
	})
	t.Run("single pre-standardisation top-level tenant", func(t *testing.T) {
		m := newTestTenantManager(t)
		seedTenant(t, m, "team-root", "")
		seedTenant(t, m, "infra-hyperv", "team-root")
		assert.Equal(t, "team-root", m.RootTenantID(ctx))
	})
	t.Run("tenant named root wins", func(t *testing.T) {
		m := newTestTenantManager(t)
		seedTenant(t, m, "team-root", "")
		seedTenant(t, m, RootTenantID, "")
		assert.Equal(t, RootTenantID, m.RootTenantID(ctx))
	})
	t.Run("ambiguous tree fails closed", func(t *testing.T) {
		m := newTestTenantManager(t)
		seedTenant(t, m, "msp-a", "")
		seedTenant(t, m, "msp-b", "")
		assert.Empty(t, m.RootTenantID(ctx), "several top-level tenants and no root resolve to no root")
	})
}

// TestRootTenantID_InvalidatedOnCreate verifies the cache does not hide a root
// created through the manager on this node.
func TestRootTenantID_InvalidatedOnCreate(t *testing.T) {
	ctx := context.Background()
	m := newTestTenantManager(t)
	require.Equal(t, RootTenantID, m.RootTenantID(ctx))
	_, err := m.CreateTenant(ctx, &TenantRequest{ID: "acme-corp"})
	require.NoError(t, err)
	require.Equal(t, "acme-corp", m.RootTenantID(ctx), "the first top-level tenant is the root")
}

// TestCreateTenant_RootBesideExistingTopLevelRefused guards the re-run hazard:
// on a deployment whose top tenant predates "root", creating "root" would orphan
// the existing tree from root-scoped principals, so it is refused (Issue #4542).
func TestCreateTenant_RootBesideExistingTopLevelRefused(t *testing.T) {
	ctx := context.Background()
	m := newTestTenantManager(t)
	seedTenant(t, m, "team-root", "")

	_, err := m.CreateTenant(ctx, &TenantRequest{ID: RootTenantID})
	require.ErrorIs(t, err, ErrRootTenantConflict)
	assert.Equal(t, "team-root", m.RootTenantID(ctx), "the existing top tenant stays the root")

	fresh := newTestTenantManager(t)
	_, err = fresh.CreateTenant(ctx, &TenantRequest{ID: RootTenantID})
	require.NoError(t, err, "a fresh deployment creates root")
}

// TestRootTenantGuards_ProtectLiteralRootOnly verifies the protected-tenant
// guards apply to the canonical "root" tenant (Issue #4542) and do not newly
// protect a deployment's pre-standardisation top tenant, which the earlier
// "default" guard never protected either. Authorization, not protection, is what
// follows the resolved root.
func TestRootTenantGuards_ProtectLiteralRootOnly(t *testing.T) {
	ctx := context.Background()
	m := newTestTenantManager(t)
	seedTenant(t, m, RootTenantID, "")
	_, err := m.SuspendTenant(ctx, RootTenantID)
	assert.ErrorIs(t, err, ErrCannotSuspendRoot)
	err = m.DeleteTenant(ctx, RootTenantID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot delete root tenant")

	m2 := newTestTenantManager(t)
	seedTenant(t, m2, "team-root", "")
	require.Equal(t, "team-root", m2.RootTenantID(ctx), "team-root still resolves as the root for authorization")
	_, err = m2.SuspendTenant(ctx, "team-root")
	assert.NotErrorIs(t, err, ErrCannotSuspendRoot)
}
