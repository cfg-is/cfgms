// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"sync"
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
		assert.Equal(t, RootTenantID, newBareTestTenantManager(t).RootTenantID(ctx))
	})
	t.Run("single pre-standardisation top-level tenant", func(t *testing.T) {
		m := newBareTestTenantManager(t)
		seedTenant(t, m, "team-root", "")
		seedTenant(t, m, "infra-hyperv", "team-root")
		assert.Equal(t, "team-root", m.RootTenantID(ctx))
	})
	t.Run("tenant named root wins", func(t *testing.T) {
		m := newBareTestTenantManager(t)
		seedTenant(t, m, "team-root", "")
		seedTenant(t, m, RootTenantID, "")
		assert.Equal(t, RootTenantID, m.RootTenantID(ctx))
	})
	t.Run("ambiguous tree fails closed", func(t *testing.T) {
		m := newBareTestTenantManager(t)
		seedTenant(t, m, "msp-a", "")
		seedTenant(t, m, "msp-b", "")
		assert.Empty(t, m.RootTenantID(ctx), "several top-level tenants and no root resolve to no root")
	})
}

// TestRootTenantID_InvalidatedOnCreate verifies the cache does not hide a root
// created through the manager on this node.
func TestRootTenantID_InvalidatedOnCreate(t *testing.T) {
	ctx := context.Background()
	m := newBareTestTenantManager(t)
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
	m := newBareTestTenantManager(t)
	seedTenant(t, m, "team-root", "")

	_, err := m.CreateTenant(ctx, &TenantRequest{ID: RootTenantID})
	require.ErrorIs(t, err, ErrRootTenantConflict)
	assert.Equal(t, "team-root", m.RootTenantID(ctx), "the existing top tenant stays the root")

	fresh := newBareTestTenantManager(t)
	_, err = fresh.CreateTenant(ctx, &TenantRequest{ID: RootTenantID})
	require.NoError(t, err, "a fresh deployment creates root")
}

// TestRootTenantGuards_ProtectResolvedRoot guards Issue #4542 review item 2: the
// suspend/delete guards follow the resolved root, so a deployment whose top tenant
// predates "root" keeps the protection the old "default" guard gave it.
func TestRootTenantGuards_ProtectResolvedRoot(t *testing.T) {
	ctx := context.Background()

	for _, root := range []string{RootTenantID, "team-root", "default"} {
		t.Run(root, func(t *testing.T) {
			m := newBareTestTenantManager(t)
			seedTenant(t, m, root, "")
			seedTenant(t, m, "child", root)

			_, err := m.SuspendTenant(ctx, root)
			assert.ErrorIs(t, err, ErrCannotSuspendRoot)
			err = m.DeleteTenant(ctx, root)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "cannot delete root tenant")
			_, err = m.RequestTenantDeletion(ctx, root, "alice", 0)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "cannot delete root tenant")

			_, err = m.SuspendTenant(ctx, "child")
			assert.NoError(t, err, "only the root is protected")
		})
	}
}

// TestRootTenantGuards_AmbiguousRootFailsClosed verifies that when the root cannot
// be determined (several top-level tenants, none named "root"), every top-level
// tenant is protected — any of them may be the intended root.
func TestRootTenantGuards_AmbiguousRootFailsClosed(t *testing.T) {
	ctx := context.Background()
	m := newBareTestTenantManager(t)
	seedTenant(t, m, "msp-a", "")
	seedTenant(t, m, "msp-b", "")
	seedTenant(t, m, "client-1", "msp-a")
	require.Empty(t, m.RootTenantID(ctx))

	_, err := m.SuspendTenant(ctx, "msp-a")
	assert.ErrorIs(t, err, ErrCannotSuspendRoot)
	_, err = m.SuspendTenant(ctx, "client-1")
	assert.NoError(t, err, "a non-top-level tenant is never the root")
}

// TestCreateTenant_RootIDReservedForTopLevel guards Issue #4542 review item 1: a
// subtree admin must not be able to create a child named "root", and a non-top-level
// "root" row written by another path is never resolved as the deployment root.
func TestCreateTenant_RootIDReservedForTopLevel(t *testing.T) {
	ctx := context.Background()
	m := newBareTestTenantManager(t)
	seedTenant(t, m, "team-root", "")
	seedTenant(t, m, "msp-a", "team-root")

	_, err := m.CreateTenant(ctx, &TenantRequest{ID: RootTenantID, ParentID: "msp-a"})
	require.ErrorIs(t, err, ErrRootTenantIDReserved)

	seedTenant(t, m, RootTenantID, "msp-a")
	m.invalidateRootTenant()
	assert.Equal(t, "team-root", m.RootTenantID(ctx), "a child named root is not the deployment root")
}

// TestCreateTenant_ConcurrentTopLevelCreatesLeaveOneRoot guards Issue #4542 review
// item 3: a top-level "root" create racing another top-level create on the same
// node must not leave both — either "root" is refused or it was first.
func TestCreateTenant_ConcurrentTopLevelCreatesLeaveOneRoot(t *testing.T) {
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		m := newBareTestTenantManager(t)
		var wg sync.WaitGroup
		wg.Add(2)
		var rootErr error
		go func() { defer wg.Done(); _, rootErr = m.CreateTenant(ctx, &TenantRequest{ID: RootTenantID}) }()
		go func() { defer wg.Done(); _, _ = m.CreateTenant(ctx, &TenantRequest{ID: "team-root"}) }()
		wg.Wait()

		team, err := m.store.GetTenant(ctx, "team-root")
		require.NoError(t, err)
		if rootErr == nil {
			// root won the lock; team-root was created after it as a second top-level
			// tenant. Refusing that sequential case is general single-top-level
			// enforcement, outside this guard (see the PR discussion on #4542's ACs).
			assert.Equal(t, RootTenantID, m.RootTenantID(ctx))
		} else {
			require.ErrorIs(t, rootErr, ErrRootTenantConflict)
			assert.Equal(t, "team-root", m.RootTenantID(ctx))
			assert.Empty(t, team.ParentID)
		}
	}
}
