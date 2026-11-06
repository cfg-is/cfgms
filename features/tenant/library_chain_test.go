// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeLibraryHierarchy(t *testing.T) *Manager {
	t.Helper()
	m := newTestTenantManager(t)
	ctx := context.Background()
	for _, r := range []TenantRequest{
		{ID: "msp", Name: "msp", ParentID: testRootTenantID},
		{ID: "client-1", Name: "client-1", ParentID: "msp"},
		{ID: "client-2", Name: "client-2", ParentID: "msp"},
		{ID: "site-a", Name: "site-a", ParentID: "client-1"},
	} {
		r := r
		_, err := m.CreateTenant(ctx, &r)
		require.NoError(t, err)
	}
	return m
}

func TestLibraryChain_OrderAndCeiling(t *testing.T) {
	m := makeLibraryHierarchy(t)
	ctx := context.Background()

	chain, err := LibraryChain(ctx, m, "site-a", "msp")
	require.NoError(t, err)
	assert.Equal(t, []string{"site-a", "client-1", "msp"}, chain)

	chain, err = LibraryChain(ctx, m, "client-1", "client-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"client-1"}, chain)

	chain, err = LibraryChain(ctx, m, "client-1", testRootTenantID)
	require.NoError(t, err)
	assert.Equal(t, []string{"client-1", "msp", testRootTenantID}, chain)
}

func TestLibraryChain_RefusesBadCeiling(t *testing.T) {
	m := makeLibraryHierarchy(t)
	ctx := context.Background()
	for _, ceiling := range []string{"client-2", "site-a"} {
		_, err := LibraryChain(ctx, m, "client-1", ceiling)
		assert.ErrorIs(t, err, ErrCeilingNotAncestor, ceiling)
	}
}

func TestLibraryChain_Errors(t *testing.T) {
	m := makeLibraryHierarchy(t)
	ctx := context.Background()

	_, err := LibraryChain(ctx, m, "no-such-tenant", "msp")
	assert.Error(t, err)

	for _, bad := range []string{"", "a/b", "..", "a..b", `a\b`} {
		_, err = LibraryChain(ctx, m, bad, "msp")
		assert.ErrorIs(t, err, ErrInvalidLibraryTenantID, bad)
		_, err = LibraryChain(ctx, m, "client-1", bad)
		assert.ErrorIs(t, err, ErrInvalidLibraryTenantID, bad)
	}
	_, err = LibraryChain(ctx, nil, "client-1", "msp")
	assert.Error(t, err)
}
