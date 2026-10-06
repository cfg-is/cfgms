// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// scopeForVerifiedAdminCert builds the TenantScope the authentication middleware
// gives a test principal: root scope for a principal with no tenant (the root
// admin fixtures in this package), a tenant scope otherwise. Test-only: production
// derives root scope from the principal's explicit GlobalScope flag
// (principalTenantScope, Issue #4665), never from an empty tenant.
func scopeForVerifiedAdminCert(tenantID string) ctxkeys.TenantScope {
	if tenantID == "" {
		return ctxkeys.NewRootScope()
	}
	return ctxkeys.NewTenantScope(tenantID)
}

// fixtureCallerTenant is the ctxkeys.TenantID the authentication middleware sets
// for a test principal: a root fixture (no tenant of its own) is bound to the
// deployment's root tenant, as the middleware binds every root principal (Issue
// #4665); any other principal carries its own tenant.
func fixtureCallerTenant(tenantID string) string {
	if tenantID == "" {
		return testRootTenantID
	}
	return tenantID
}

// withCallerTenant gives ctx the caller identity the authentication middleware
// sets: "" is a root caller (root scope, bound to the root tenant), anything else
// a caller confined to that tenant (Issue #4665).
func withCallerTenant(ctx context.Context, callerTenantID string) context.Context {
	ctx = context.WithValue(ctx, ctxkeys.TenantID, fixtureCallerTenant(callerTenantID))
	return context.WithValue(ctx, ctxkeys.TenantScopeKey, scopeForVerifiedAdminCert(callerTenantID))
}
