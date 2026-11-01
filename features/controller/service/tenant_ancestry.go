// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"

	"github.com/cfgis/cfgms/pkg/logging"
)

// TenantAncestryFunc reports whether descendant is a descendant of ancestor in
// the tenant store's ParentID ancestry. It is injected at construction because
// this package cannot import features/controller/api, and a tenant ID is a single
// DNS-label token (ADR-025 Amendment 1), so subtree containment is never a
// string-prefix test.
type TenantAncestryFunc func(ctx context.Context, ancestor, descendant string) (bool, error)

// tenantSubtreeContains reports whether resourceTenant is callerTenant itself or
// a descendant of it per ancestry. It fails closed: an empty ID, a nil lookup or
// a lookup error all deny a non-identical tenant.
func tenantSubtreeContains(ctx context.Context, ancestry TenantAncestryFunc, logger logging.Logger, callerTenant, resourceTenant string) bool {
	if callerTenant == "" || resourceTenant == "" {
		return false
	}
	if resourceTenant == callerTenant {
		return true
	}
	if ancestry == nil {
		return false
	}
	ok, err := ancestry(ctx, callerTenant, resourceTenant)
	if err != nil {
		if logger != nil {
			logger.Warn("Tenant ancestry lookup failed; denying",
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return false
	}
	return ok
}
