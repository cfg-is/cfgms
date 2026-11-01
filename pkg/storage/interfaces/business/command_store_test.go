// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestTenantPathChain pins the tenant set every ListPendingDeliveries
// implementation must scope to (Issue #3757). The chain is what keeps a record
// written under a steward's previous tenant binding (Issue #2341) out of the
// result: only the steward's own tenant and its ancestors are in it, never a
// sibling and never a descendant.
func TestTenantPathChain(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		want     []string
	}{
		{
			name:     "nested path yields leaf then every ancestor",
			tenantID: "root/msp-a/client-1",
			want:     []string{"root/msp-a/client-1", "root/msp-a", "root"},
		},
		{
			name:     "flat tenant is its own chain",
			tenantID: "tenant-a",
			want:     []string{"tenant-a"},
		},
		{
			name:     "empty tenant matches nothing",
			tenantID: "",
			want:     nil,
		},
		{
			name:     "leading separator does not produce an empty ancestor",
			tenantID: "/tenant-a",
			want:     []string{"/tenant-a"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, business.TenantPathChain(tc.tenantID))
		})
	}
}

// TestTenantPathChain_ExcludesSiblingAndDescendant states the isolation property
// directly: a sibling tenant's records and a child tenant's records are never in
// a steward's chain, so neither can be returned for a steward living at
// root/msp-a/client-1.
func TestTenantPathChain_ExcludesSiblingAndDescendant(t *testing.T) {
	chain := business.TenantPathChain("root/msp-a/client-1")
	assert.NotContains(t, chain, "root/msp-a/client-2", "sibling tenant")
	assert.NotContains(t, chain, "root/msp-b", "unrelated MSP")
	assert.NotContains(t, chain, "root/msp-a/client-1/sub", "descendant tenant")
}
