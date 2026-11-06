// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func inheritFixture(t *testing.T) (cfgconfig.ConfigStore, *tenant.Manager) {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	m := tenant.NewManager(sm.GetTenantStore(), nil)
	ctx := context.Background()
	_, err := m.CreateTenant(ctx, &tenant.TenantRequest{ID: "root", Name: "root"})
	require.NoError(t, err)
	for _, r := range []tenant.TenantRequest{
		{ID: "msp", Name: "msp", ParentID: "root"},
		{ID: "client-1", Name: "client-1", ParentID: "msp"},
		{ID: "client-2", Name: "client-2", ParentID: "msp"},
		{ID: "site-a", Name: "site-a", ParentID: "client-1"},
	} {
		r := r
		_, err := m.CreateTenant(ctx, &r)
		require.NoError(t, err)
	}
	return sm.GetConfigStore(), m
}

func seedInheritWorkflow(t *testing.T, cs cfgconfig.ConfigStore, tenantID, name string, v SemanticVersion, steps ...Step) {
	t.Helper()
	require.NoError(t, NewWorkflowStore(cs, tenantID).StoreWorkflow(context.Background(), &VersionedWorkflow{
		Workflow:        Workflow{Name: name, Steps: steps},
		SemanticVersion: v,
	}))
}

func inheritChain(t *testing.T, m *tenant.Manager, run, ceiling string) []string {
	t.Helper()
	c, err := tenant.LibraryChain(context.Background(), m, run, ceiling)
	require.NoError(t, err)
	return c
}

var v100 = SemanticVersion{Major: 1}

func TestResolveInherited_ParentFoundWithOwner(t *testing.T) {
	cs, m := inheritFixture(t)
	seedInheritWorkflow(t, cs, "msp", "shared", v100)
	wf, owner, err := ResolveInherited(context.Background(), cs, inheritChain(t, m, "client-1", "msp"), "shared", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "shared", wf.Name)
	assert.Equal(t, "msp", owner)
}

func TestResolveInherited_SiblingNeverFound(t *testing.T) {
	cs, m := inheritFixture(t)
	seedInheritWorkflow(t, cs, "client-2", "only-c2", v100)
	_, _, err := ResolveInherited(context.Background(), cs, inheritChain(t, m, "client-1", "msp"), "only-c2", "1.0.0")
	assert.ErrorIs(t, err, ErrWorkflowNotFound)
}

func TestResolveInherited_CeilingAndDescendant(t *testing.T) {
	cs, m := inheritFixture(t)
	seedInheritWorkflow(t, cs, "root", "root-only", v100)
	seedInheritWorkflow(t, cs, "site-a", "deep", v100)
	ctx := context.Background()
	chain := inheritChain(t, m, "client-1", "msp")

	_, _, err := ResolveInherited(ctx, cs, chain, "root-only", "1.0.0")
	assert.ErrorIs(t, err, ErrWorkflowNotFound)
	_, _, err = ResolveInherited(ctx, cs, chain, "deep", "1.0.0")
	assert.ErrorIs(t, err, ErrWorkflowNotFound)

	_, owner, err := ResolveInherited(ctx, cs, inheritChain(t, m, "client-1", "root"), "root-only", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "root", owner)
}

func TestResolveInherited_NearestWinsWithOwnOwner(t *testing.T) {
	cs, m := inheritFixture(t)
	seedInheritWorkflow(t, cs, "msp", "clash", v100)
	seedInheritWorkflow(t, cs, "client-1", "clash", v100)
	_, owner, err := ResolveInherited(context.Background(), cs, inheritChain(t, m, "site-a", "msp"), "clash", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "client-1", owner)
}

func TestResolveInherited_EmptyVersionRefused(t *testing.T) {
	cs, m := inheritFixture(t)
	seedInheritWorkflow(t, cs, "msp", "shared", v100)
	_, _, err := ResolveInherited(context.Background(), cs, inheritChain(t, m, "client-1", "msp"), "shared", "")
	assert.ErrorIs(t, err, ErrWorkflowVersionRequired)
}

func TestResolveInherited_HierarchyErrorFailsCall(t *testing.T) {
	cs, m := inheritFixture(t)
	seedInheritWorkflow(t, cs, "client-1", "local", v100)
	_, err := tenant.LibraryChain(context.Background(), m, "ghost", "msp")
	require.Error(t, err)
	// The failed chain is what the caller would pass; an empty chain is refused.
	_, _, err = ResolveInherited(context.Background(), cs, nil, "local", "1.0.0")
	assert.Error(t, err)
}

func TestResolveInherited_NameDecidesNotVersion(t *testing.T) {
	cs, m := inheritFixture(t)
	seedInheritWorkflow(t, cs, "client-1", "ver", v100)
	seedInheritWorkflow(t, cs, "msp", "ver", v100)
	seedInheritWorkflow(t, cs, "msp", "ver", SemanticVersion{Major: 2})
	chain := inheritChain(t, m, "client-1", "msp")
	ctx := context.Background()

	_, _, err := ResolveInherited(ctx, cs, chain, "ver", "2.0.0")
	assert.ErrorIs(t, err, ErrWorkflowNotFound)

	wf, owner, err := ResolveInherited(ctx, cs, chain, "ver", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "client-1", owner)
	assert.Equal(t, v100, wf.SemanticVersion)
}

func TestResolveInherited_BadIdentifiersRefused(t *testing.T) {
	cs, _ := inheritFixture(t)
	ctx := context.Background()
	for _, chain := range [][]string{{"a/b"}, {"a..b"}, {`a\b`}, {""}} {
		_, _, err := ResolveInherited(ctx, cs, chain, "x", "1.0.0")
		assert.Error(t, err, "%v", chain)
	}
	_, _, err := ResolveInherited(ctx, cs, []string{"msp"}, "../x", "1.0.0")
	assert.Error(t, err)
	_, _, err = ResolveInherited(ctx, cs, []string{"msp"}, "x", "latest")
	assert.Error(t, err)
}

func TestResolveInherited_SubWorkflowReferencePinned(t *testing.T) {
	cs, m := inheritFixture(t)
	seedInheritWorkflow(t, cs, "msp", "child", v100)
	seedInheritWorkflow(t, cs, "root", "root-child", v100)
	seedInheritWorkflow(t, cs, "client-1", "parent", v100, Step{
		Name: "call", Type: StepTypeWorkflow, WorkflowCall: &WorkflowCallConfig{WorkflowName: "child"},
	})
	ctx := context.Background()
	chain := inheritChain(t, m, "client-1", "msp")

	parent, _, err := ResolveInherited(ctx, cs, chain, "parent", "1.0.0")
	require.NoError(t, err)
	ref := parent.Steps[0].WorkflowCall.WorkflowName
	child, owner, err := ResolveInherited(ctx, cs, chain, ref, "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "msp", owner)
	assert.Equal(t, "1.0.0", child.SemanticVersion.String())

	_, _, err = ResolveInherited(ctx, cs, chain, "root-child", "1.0.0")
	assert.ErrorIs(t, err, ErrWorkflowNotFound)
}
