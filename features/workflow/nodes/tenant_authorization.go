// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package nodes

import (
	"fmt"

	"github.com/cfgis/cfgms/features/workflow"
)

// requireAuthorizedTenant resolves the tenant a step executor must use for its
// tenant-scoped operations: the execution's authenticated owner, injected by the
// engine from the caller's verified context and never sourced from
// execution.Variables or step.Config — both are writable by whoever authored or
// triggered the workflow (Issue #4338).
//
// configuredTenantID is whatever a step optionally names through one of those
// author-writable locations. When non-empty it must match the authenticated
// tenant exactly; a step naming a different tenant is refused outright, not
// silently corrected to the authenticated one.
func requireAuthorizedTenant(execution *workflow.WorkflowExecution, configuredTenantID string) (string, error) {
	if execution.TenantID == "" {
		return "", fmt.Errorf("execution has no authenticated tenant_id")
	}
	if configuredTenantID != "" && configuredTenantID != execution.TenantID {
		return "", fmt.Errorf("configured tenant_id %q does not match execution's authenticated tenant %q", configuredTenantID, execution.TenantID)
	}
	return execution.TenantID, nil
}
