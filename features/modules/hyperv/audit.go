// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"log/slog"

	"github.com/cfgis/cfgms/pkg/audit"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// recordHypervOp emits a pkg/audit entry for a Hyper-V mutation operation.
// It is nil-safe: when mgr is nil the function returns immediately so lightweight
// stewards that do not configure an audit manager are unaffected.
//
// Structured fields only — no raw PowerShell script text or user-supplied
// argument values (VM names, VHD paths, switch names) appear in Details.
func recordHypervOp(ctx context.Context, mgr *audit.Manager, tenantID, stewardID, host, verb, resourceID string, opErr error) {
	if mgr == nil {
		return
	}

	builder := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action(verb).
		User(audit.SystemUserID, business.AuditUserTypeSystem).
		Resource("hyperv/"+verb, resourceID, "").
		Detail("host", host).
		Detail("steward_id", stewardID)

	if opErr == nil {
		builder = builder.Result(business.AuditResultSuccess)
	} else {
		builder = builder.Result(business.AuditResultFailure).Error("", opErr.Error())
	}

	if err := mgr.RecordEvent(ctx, builder); err != nil {
		slog.Warn("hyperv: failed to record audit event",
			"verb", verb,
			"resource_id", resourceID,
			"error", err,
		)
	}
}
