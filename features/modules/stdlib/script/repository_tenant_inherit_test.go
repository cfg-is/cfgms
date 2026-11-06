// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/features/tenant"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func seedTenantScript(t *testing.T, repo *TenantScriptRepository, tenantID, id string) {
	t.Helper()
	gr, err := repo.ForTenant(tenantID)
	require.NoError(t, err)
	require.NoError(t, gr.Create(&VersionedScript{
		Metadata: &ScriptMetadata{ID: id, Name: id, Version: &Version{Major: 1}, Shell: ShellBash, Platform: []string{"linux"}},
		Content:  "echo " + id + "\n",
	}))
}

func newInheritFixture(t *testing.T) (*TenantScriptRepository, *tenant.Manager) {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	repo, err := NewTenantScriptRepository(sm.GetConfigStore())
	require.NoError(t, err)
	m := tenant.NewManager(sm.GetTenantStore(), nil)
	ctx := context.Background()
	_, err = m.CreateTenant(ctx, &tenant.TenantRequest{ID: "root", Name: "root"})
	require.NoError(t, err)
	for _, r := range []tenant.TenantRequest{
		{ID: "msp", Name: "msp", ParentID: "root"},
		{ID: "client-1", Name: "client-1", ParentID: "msp"},
		{ID: "client-2", Name: "client-2", ParentID: "msp"},
		{ID: "site-a", Name: "site-a", ParentID: "client-1"},
		{ID: "site-b", Name: "site-b", ParentID: "client-1"},
	} {
		r := r
		_, err := m.CreateTenant(ctx, &r)
		require.NoError(t, err)
	}
	return repo, m
}

func chainFor(t *testing.T, m *tenant.Manager, run, ceiling string) []string {
	t.Helper()
	c, err := tenant.LibraryChain(context.Background(), m, run, ceiling)
	require.NoError(t, err)
	return c
}

func TestResolveInherited_ParentFoundWithOwner(t *testing.T) {
	repo, m := newInheritFixture(t)
	seedTenantScript(t, repo, "msp", "shared")

	s, owner, err := repo.ResolveInherited(context.Background(), chainFor(t, m, "client-1", "msp"), "shared", "")
	require.NoError(t, err)
	assert.Equal(t, "shared", s.Metadata.ID)
	assert.Equal(t, "msp", owner)
}

func TestResolveInherited_SiblingNeverFound(t *testing.T) {
	repo, m := newInheritFixture(t)
	seedTenantScript(t, repo, "client-2", "only-c2")
	_, _, err := repo.ResolveInherited(context.Background(), chainFor(t, m, "client-1", "msp"), "only-c2", "")
	assert.ErrorIs(t, err, ErrScriptNotFound)
}

func TestResolveInherited_AboveCeilingAndMovedCeiling(t *testing.T) {
	repo, m := newInheritFixture(t)
	seedTenantScript(t, repo, "root", "root-only")
	ctx := context.Background()

	_, _, err := repo.ResolveInherited(ctx, chainFor(t, m, "client-1", "msp"), "root-only", "")
	assert.ErrorIs(t, err, ErrScriptNotFound)

	_, owner, err := repo.ResolveInherited(ctx, chainFor(t, m, "client-1", "root"), "root-only", "")
	require.NoError(t, err)
	assert.Equal(t, "root", owner)
}

func TestResolveInherited_DescendantNeverFound(t *testing.T) {
	repo, m := newInheritFixture(t)
	seedTenantScript(t, repo, "site-a", "deep")
	_, _, err := repo.ResolveInherited(context.Background(), chainFor(t, m, "client-1", "msp"), "deep", "")
	assert.ErrorIs(t, err, ErrScriptNotFound)
}

func TestResolveInherited_NearestWinsWithOwnOwner(t *testing.T) {
	repo, m := newInheritFixture(t)
	seedTenantScript(t, repo, "msp", "clash")
	seedTenantScript(t, repo, "client-1", "clash")
	s, owner, err := repo.ResolveInherited(context.Background(), chainFor(t, m, "site-a", "msp"), "clash", "")
	require.NoError(t, err)
	assert.Equal(t, "client-1", owner)
	assert.Equal(t, "clash", s.Metadata.ID)
}

func TestResolveInherited_NearestLacksVersionDoesNotFallThrough(t *testing.T) {
	repo, m := newInheritFixture(t)
	seedTenantScript(t, repo, "client-1", "ver")
	seedTenantScript(t, repo, "msp", "ver")
	msp, err := repo.ForTenant("msp")
	require.NoError(t, err)
	up := &VersionedScript{
		Metadata: &ScriptMetadata{ID: "ver", Name: "ver", Version: &Version{Major: 2}, Shell: ShellBash, Platform: []string{"linux"}},
		Content:  "echo v2\n",
	}
	require.NoError(t, msp.Update(up))

	chain := chainFor(t, m, "client-1", "msp")
	_, _, err = repo.ResolveInherited(context.Background(), chain, "ver", "2.0.0")
	assert.ErrorIs(t, err, ErrScriptNotFound)

	_, owner, err := repo.ResolveInherited(context.Background(), chain, "ver", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "client-1", owner)
}

func TestResolveInherited_ThreeLevelMiddleOwnerWithSiblings(t *testing.T) {
	repo, m := newInheritFixture(t)
	seedTenantScript(t, repo, "client-1", "mid")
	seedTenantScript(t, repo, "client-2", "c2")
	seedTenantScript(t, repo, "site-b", "sb")
	seedTenantScript(t, repo, "site-a", "sa")
	chain := chainFor(t, m, "site-a", "msp")
	ctx := context.Background()

	_, owner, err := repo.ResolveInherited(ctx, chain, "mid", "")
	require.NoError(t, err)
	assert.Equal(t, "client-1", owner)
	for _, id := range []string{"c2", "sb"} {
		_, _, err = repo.ResolveInherited(ctx, chain, id, "")
		assert.ErrorIs(t, err, ErrScriptNotFound, id)
	}

	list, err := repo.ListInherited(ctx, chain, nil)
	require.NoError(t, err)
	got := map[string]string{}
	for _, l := range list {
		got[l.ID] = l.OwnerTenant
	}
	assert.Equal(t, map[string]string{"mid": "client-1", "sa": "site-a"}, got)
}

func TestListInherited_DedupNearestWins(t *testing.T) {
	repo, m := newInheritFixture(t)
	seedTenantScript(t, repo, "msp", "clash")
	seedTenantScript(t, repo, "msp", "up")
	seedTenantScript(t, repo, "client-1", "clash")
	list, err := repo.ListInherited(context.Background(), chainFor(t, m, "client-1", "msp"), nil)
	require.NoError(t, err)
	got := map[string]string{}
	for _, l := range list {
		got[l.ID] = l.OwnerTenant
	}
	assert.Equal(t, map[string]string{"clash": "client-1", "up": "msp"}, got)
}

func TestInherited_EmptyOrBadChainFails(t *testing.T) {
	repo, _ := newInheritFixture(t)
	ctx := context.Background()
	_, _, err := repo.ResolveInherited(ctx, nil, "x", "")
	assert.ErrorIs(t, err, ErrTenantRequired)
	_, _, err = repo.ResolveInherited(ctx, []string{"a/b"}, "x", "")
	assert.Error(t, err)
	_, err = repo.ListInherited(ctx, []string{".."}, nil)
	assert.Error(t, err)
}

func TestInherited_HierarchyErrorDoesNotFallBack(t *testing.T) {
	repo, m := newInheritFixture(t)
	seedTenantScript(t, repo, "client-1", "local")
	_, err := tenant.LibraryChain(context.Background(), m, "ghost", "msp")
	assert.Error(t, err, "an unknown tenant must fail, not yield a one-element chain")
	_, err = tenant.LibraryChain(context.Background(), m, "client-1", "client-2")
	assert.Error(t, err)
}
