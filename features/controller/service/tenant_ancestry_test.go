// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// newTestTenantAncestry builds a real tenant manager over durable test storage
// holding root > msp-a > client-1, root > msp-b and root > msp-ab (a sibling whose
// ID merely shares msp-a's prefix), and returns its ancestry lookup.
func newTestTenantAncestry(t *testing.T) TenantAncestryFunc {
	t.Helper()
	storageManager := pkgtesting.SetupTestStorage(t)
	m := tenant.NewManager(tenant.NewStorageAdapter(storageManager.GetTenantStore()), nil)
	ctx := context.Background()
	for _, tr := range []*tenant.TenantRequest{
		{ID: "root"},
		{ID: "msp-a", ParentID: "root"},
		{ID: "client-1", ParentID: "msp-a"},
		{ID: "msp-b", ParentID: "root"},
		{ID: "msp-ab", ParentID: "root"},
	} {
		_, err := m.CreateTenant(ctx, tr)
		require.NoError(t, err)
	}
	return m.IsTenantAncestor
}

func failingTenantAncestry(context.Context, string, string) (bool, error) {
	return false, errors.New("tenant store unavailable")
}

func TestTenantScopeContains_ResolvesThroughAncestry(t *testing.T) {
	ancestry := newTestTenantAncestry(t)
	ctx := context.Background()
	logger := logging.NewNoopLogger()

	type scopeFn func(ctx context.Context, ancestry TenantAncestryFunc, logger logging.Logger, caller, resource string) bool
	cases := map[string]struct {
		fn            scopeFn
		emptyCallerOK bool
	}{
		"certTenantScopeContains": {certTenantScopeContains, false},
		"clusterTenantInScope":    {clusterTenantInScope, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.True(t, tc.fn(ctx, ancestry, logger, "msp-a", "msp-a"), "own tenant")
			assert.True(t, tc.fn(ctx, ancestry, logger, "msp-a", "client-1"), "real descendant")
			assert.False(t, tc.fn(ctx, ancestry, logger, "msp-a", "msp-b"), "sibling")
			assert.False(t, tc.fn(ctx, ancestry, logger, "msp-a", "msp-ab"), "shared-prefix sibling")
			assert.False(t, tc.fn(ctx, ancestry, logger, "client-1", "msp-a"), "ancestor is not a descendant")
			assert.Equal(t, tc.emptyCallerOK, tc.fn(ctx, ancestry, logger, "", "msp-b"), "empty caller")

			assert.False(t, tc.fn(ctx, failingTenantAncestry, logger, "msp-a", "client-1"), "lookup error fails closed")
			assert.False(t, tc.fn(ctx, nil, logger, "msp-a", "client-1"), "nil lookup fails closed")
			assert.True(t, tc.fn(ctx, nil, logger, "msp-a", "msp-a"), "own tenant needs no lookup")
		})
	}
}
