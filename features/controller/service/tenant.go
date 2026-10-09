// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// extractTenantID returns the tenant ID carried by ctx and whether one was
// present. It never substitutes a tenant: callers must refuse an operation
// whose tenant cannot be resolved (ADR-025 Amendment 7).
func extractTenantID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(ctxkeys.TenantID).(string)
	if !ok || id == "" {
		return "", false
	}
	return id, true
}
