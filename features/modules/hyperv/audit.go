// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"github.com/cfgis/cfgms/pkg/audit"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// recordHypervOp emits a pkg/audit entry for a Hyper-V mutation operation.
//
// cfgResourceID is the operator-declared resource identity (e.g. "vm:web-01",
// "vswitch:ext-01") and is used as the audit Resource id. Live VM names, VHD
// paths, and live switch names never appear in the emitted record — only
// non-sensitive scalar state (cpu count, memory MB, power state, cfg switch id).
//
// before and after capture the scalar state before and after the mutation;
// Changes.Fields is derived as the sorted set of keys that differ.
// Create ops pass before=nil; delete ops pass after=nil.
//
// The function is nil-safe: when mgr is nil it returns immediately so
// lightweight stewards that do not configure an audit manager are unaffected.
func recordHypervOp(ctx context.Context, mgr *audit.Manager, tenantID, stewardID, host, verb, cfgResourceID string, before, after map[string]interface{}, opErr error) {
	if mgr == nil {
		return
	}

	builder := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action(verb).
		User(audit.SystemUserID, business.AuditUserTypeSystem).
		Resource("hyperv/"+verb, cfgResourceID, "").
		Detail("host", host).
		Detail("steward_id", stewardID)

	if len(before) > 0 || len(after) > 0 {
		builder = builder.Changes(before, after, changedFields(before, after))
	}

	if opErr == nil {
		builder = builder.Result(business.AuditResultSuccess)
	} else {
		builder = builder.Result(business.AuditResultFailure).Error("", opErr.Error())
	}

	if err := mgr.RecordEvent(ctx, builder); err != nil {
		slog.Warn("hyperv: failed to record audit event",
			"verb", verb,
			"resource_id", cfgResourceID,
			"error", err,
		)
	}
}

// changedFields returns the sorted list of keys whose values differ between
// before and after, including keys present in only one of the maps.
func changedFields(before, after map[string]interface{}) []string {
	seen := make(map[string]struct{})
	for k := range before {
		seen[k] = struct{}{}
	}
	for k := range after {
		seen[k] = struct{}{}
	}
	var fields []string
	for k := range seen {
		bv := fmt.Sprintf("%v", before[k])
		av := fmt.Sprintf("%v", after[k])
		if bv != av {
			fields = append(fields, k)
		}
	}
	sort.Strings(fields)
	return fields
}
