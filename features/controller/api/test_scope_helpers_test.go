// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import "github.com/cfgis/cfgms/pkg/ctxkeys"

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
