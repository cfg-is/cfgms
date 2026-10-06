// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// noTenantScope is what callerTenantFilter returns for a context that carries
// no usable tenant scope. It is not a valid tenant ID, so it matches no tenant
// and reaches no data — the caller fails closed instead of being read as
// unrestricted.
const noTenantScope = "!no-tenant-scope"

// callerTenantFilter is the caller's tenant restriction for scoping reads and
// tenant checks (Issue #4665): "" — no tenant restriction — only for an
// explicitly root-scoped caller (ctxkeys.TenantRestriction), the caller's own
// tenant for a tenant-scoped caller, and noTenantScope for anything else.
//
// "" here therefore always means an explicit root caller, never a missing
// tenant: the authentication middleware binds a root principal to the
// deployment's root tenant (ctxkeys.TenantID) and refuses any principal that is
// neither root nor bound to a tenant. Code that needs the root caller's own
// tenant — to store something under it — reads ctxkeys.TenantID instead.
func callerTenantFilter(ctx context.Context) string {
	tenant, unrestricted, ok := ctxkeys.TenantRestriction(ctx)
	switch {
	case !ok:
		return noTenantScope
	case unrestricted:
		return ""
	default:
		return tenant
	}
}
