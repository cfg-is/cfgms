// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/fleet/selector"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// stewardOsqueryDispatcher is the minimal interface satisfied by *osquery.OsqueryHandler.
// Defined here to keep the api package self-contained and to allow test doubles.
// The catalog-only constraint (catalog_id validation, SQL construction) is enforced
// entirely at S7's (Issue #3566) admission step — this layer passes through without
// re-validating query content.
type stewardOsqueryDispatcher interface {
	QuerySteward(ctx context.Context, stewardID, catalogID string, params map[string]string) ([]*transportpb.OsqueryRow, error)
}

// osqueryQueryRequest is the JSON body for POST /api/v1/osquery/query.
type osqueryQueryRequest struct {
	CatalogID string            `json:"catalog_id"`
	Params    map[string]string `json:"params,omitempty"`
	Selector  string            `json:"selector"`
}

// osqueryStewardResult is one steward's result within the aggregate response.
type osqueryStewardResult struct {
	StewardID string              `json:"steward_id"`
	Rows      []map[string]string `json:"rows,omitempty"`
	Error     string              `json:"error,omitempty"`
}

// osqueryQueryResponse is returned by POST /api/v1/osquery/query.
type osqueryQueryResponse struct {
	Results []osqueryStewardResult `json:"results"`
}

// handleOsqueryQuery handles POST /api/v1/osquery/query.
//
// Accepts a catalog query ID, optional typed parameters, and a fleet selector.
// Checks leadership, dispatches to each targeted steward via S7's (Issue #3566)
// QuerySteward method, and returns per-steward results with partial success on
// individual steward failures. Every execution is audited.
func (s *Server) handleOsqueryQuery(w http.ResponseWriter, r *http.Request) {
	// s.registrationLeaderStatus is the generic lease-backed authority checker
	// (HasLeadership() bool, satisfied by *ha.Manager, ADR-029 Decision 4)
	// reused here per the same pattern as handlers_module_approval.go (Issue #3411).
	if checker := s.registrationLeaderStatus; checker != nil && !checker.HasLeadership() {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	if s.osqueryDispatcher == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Osquery dispatch not configured", "SERVICE_UNAVAILABLE")
		return
	}

	var req osqueryQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	if req.CatalogID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "catalog_id is required", "MISSING_CATALOG_ID")
		return
	}

	if req.Selector == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "selector is required", "MISSING_SELECTOR")
		return
	}

	filter, parsedTenantPath, err := selector.Parse(req.Selector)
	if err != nil {
		s.logger.Debug("Invalid osquery selector",
			"selector", logging.SanitizeLogValue(req.Selector),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid selector", "INVALID_SELECTOR")
		return
	}

	// Enforce the tenant authz boundary. selector.Parse deliberately does not do
	// this — it returns the parsed tenant path and leaves the decision to the
	// caller. fleet.Filter{TenantSubtree: ""} is unrestricted, so an unset
	// TenantSubtree would fan a catalog query out across every tenant's stewards.
	// An explicit selector prefix must lie at or below the caller's own node;
	// an absent prefix defaults to the caller's entire subtree. Admin callers
	// (empty tenant ID, e.g. mTLS cert admins) remain unrestricted, matching
	// handleResolveSelector and handleDispatchUpgrade.
	callerTenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if parsedTenantPath != "" {
		if !isWithinTenantScope(callerTenantID, parsedTenantPath) {
			s.logger.Info("Osquery selector tenant outside caller subtree",
				"parsed_tenant", logging.SanitizeLogValue(parsedTenantPath),
				"caller_tenant", logging.SanitizeLogValue(callerTenantID))
			s.writeErrorResponse(w, http.StatusForbidden,
				"Target tenant is outside the caller's authorized subtree", "CROSS_TENANT")
			return
		}
		filter.TenantSubtree = parsedTenantPath
	} else if callerTenantID != "" {
		filter.TenantSubtree = callerTenantID
	}

	if s.fleetQuery == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet query not available", "SERVICE_UNAVAILABLE")
		return
	}

	stewards, err := s.fleetQuery.Search(r.Context(), filter)
	if err != nil {
		s.logger.Error("Fleet query failed during osquery dispatch",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to resolve fleet selector", "INTERNAL_ERROR")
		return
	}

	stewardIDs := make([]string, 0, len(stewards))
	for _, sr := range stewards {
		stewardIDs = append(stewardIDs, sr.ID)
	}

	// Fan-out to all targeted stewards concurrently; collect partial results.
	results := make([]osqueryStewardResult, len(stewardIDs))
	var wg sync.WaitGroup
	for i, stewardID := range stewardIDs {
		wg.Add(1)
		go func(idx int, sid string) {
			defer wg.Done()
			rows, dispErr := s.osqueryDispatcher.QuerySteward(r.Context(), sid, req.CatalogID, req.Params)
			res := osqueryStewardResult{StewardID: sid}
			if dispErr != nil {
				res.Error = logging.SanitizeLogValue(dispErr.Error())
			} else {
				res.Rows = rowsToMaps(rows)
			}
			results[idx] = res
		}(i, stewardID)
	}
	wg.Wait()

	s.emitOsqueryAudit(r, req.CatalogID, stewardIDs)

	s.writeSuccessResponse(w, osqueryQueryResponse{Results: results})
}

// rowsToMaps converts a proto OsqueryRow slice to []map[string]string for JSON output.
func rowsToMaps(rows []*transportpb.OsqueryRow) []map[string]string {
	if len(rows) == 0 {
		return nil
	}
	out := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		m := make(map[string]string, len(row.GetColumns()))
		for k, v := range row.GetColumns() {
			m[k] = v
		}
		out = append(out, m)
	}
	return out
}

// emitOsqueryAudit records an osquery dispatch audit event.
// stewardIDs is the list of targeted steward IDs. No-op when auditManager is nil.
func (s *Server) emitOsqueryAudit(r *http.Request, catalogID string, stewardIDs []string) {
	if s.auditManager == nil {
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	callerID := ""
	if principal != nil {
		callerID = principal.ID
	}

	b := audit.NewEventBuilder().
		Tenant("root").
		Type(business.AuditEventSystemAccess).
		Action("osquery.query.dispatch").
		User(callerID, business.AuditUserTypeHuman).
		Resource("osquery_catalog", logging.SanitizeLogValue(catalogID), "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Request(s.getRequestID(r), r.Method, r.URL.Path, extractSourceIP(r, s.trustedProxies), r.Header.Get("User-Agent")).
		Detail("catalog_id", logging.SanitizeLogValue(catalogID)).
		Detail("target_count", fmt.Sprintf("%d", len(stewardIDs)))

	for i, sid := range stewardIDs {
		if i >= 10 {
			// Cap per-steward detail entries to avoid unbounded audit record size.
			b = b.Detail("targets_truncated", "true")
			break
		}
		b = b.Detail(fmt.Sprintf("steward_%d", i), logging.SanitizeLogValue(sid))
	}

	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		s.logger.Warn("Failed to emit osquery audit event",
			"error", logging.SanitizeLogValue(err.Error()),
			"catalog_id", logging.SanitizeLogValue(catalogID))
	}
}
