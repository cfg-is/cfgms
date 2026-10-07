// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces

import "slices"

// TenantCut is the caller's tenant visibility cut: the tenant a read is scoped to
// plus the descendant tenant IDs the caller resolved from the tenant tree's
// ParentID ancestry (ADR-025 Amendment 1: a tenant ID is a single DNS-label
// token, so containment is never a string-prefix test). The entity graph has no
// tenant store, so the caller resolves the set once per request and passes it in.
//
// An empty tenant is unrestricted. A tenant with no resolved descendants sees
// only entities it owns directly, which is the fail-closed outcome of a missing
// or errored resolution.
type TenantCut struct {
	tenant string
	ids    []string
}

// NewTenantCut builds the cut for a filter's TenantFilter and TenantSubtreeIDs.
func NewTenantCut(tenant string, subtreeIDs []string) TenantCut {
	return TenantCut{tenant: tenant, ids: subtreeIDs}
}

// Active reports whether the cut restricts visibility at all.
func (c TenantCut) Active() bool { return c.tenant != "" }

// Tenant returns the tenant the cut is scoped to ("" when unrestricted).
func (c TenantCut) Tenant() string { return c.tenant }

// Visible reports whether an entity owned by owningTenant is inside the cut.
func (c TenantCut) Visible(owningTenant string) bool {
	if !c.Active() {
		return true
	}
	if owningTenant == "" {
		return false
	}
	return owningTenant == c.tenant || slices.Contains(c.ids, owningTenant)
}

// Members returns the distinct, non-empty tenant IDs inside the cut: the scoped
// tenant first, then the resolved descendants. It is empty for an inactive cut.
func (c TenantCut) Members() []string {
	if !c.Active() {
		return nil
	}
	members := make([]string, 0, len(c.ids)+1)
	members = append(members, c.tenant)
	for _, id := range c.ids {
		if id == "" || slices.Contains(members, id) {
			continue
		}
		members = append(members, id)
	}
	return members
}
