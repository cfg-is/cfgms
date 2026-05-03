// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package service

import (
	"context"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// extractTenantID returns the tenant ID from ctx or "default" if absent.
func extractTenantID(ctx context.Context) string {
	if id, ok := ctx.Value(ctxkeys.TenantID).(string); ok && id != "" {
		return id
	}
	return "default"
}
