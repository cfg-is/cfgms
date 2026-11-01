// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package m365

import (
	"context"
	"fmt"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// requireExecutionTenant reads the CFGMS tenant the current execution is
// authenticated as. It fails closed: a missing or empty tenant context (wrong
// context key, a dropped context.Background() call, a forgotten propagation)
// must never be treated as an unrestricted or default tenant (matches the
// fail-closed convention in pkg/ctxkeys and the entra_* sub-modules).
func requireExecutionTenant(ctx context.Context) (string, error) {
	tenantID, _ := ctx.Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		return "", fmt.Errorf("m365: tenant context required")
	}
	return tenantID, nil
}
