// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/fleet/selector"
	"github.com/cfgis/cfgms/pkg/logging"
)

// DegradedHeartbeatAge is the heartbeat age beyond which an otherwise-active
// steward is counted as Degraded in the fleet health aggregate
// (GET /api/v1/fleet/health). An active steward whose last heartbeat arrived
// more than DegradedHeartbeatAge ago is experiencing connectivity issues and
// warrants attention. Mirrors the client-side STALE_AFTER_MS threshold
// (web/src/fleet/health.ts) so aggregate counts align with per-row health pills.
const DegradedHeartbeatAge = 5 * time.Minute

// FleetHealthResponse is the response payload for GET /api/v1/fleet/health.
// Hidden is always present (non-suppressible) regardless of include_hidden:
// an operator must always see that concealment is in effect (Issue #2918).
type FleetHealthResponse struct {
	Healthy     int `json:"healthy"`
	Degraded    int `json:"degraded"`
	Unreachable int `json:"unreachable"`
	Hidden      int `json:"hidden"`
}

// SelectorResolveRequest is the request body for POST /api/v1/fleet/resolve.
type SelectorResolveRequest struct {
	Selector string `json:"selector"`
}

// handleResolveSelector resolves a steward filter expression to a concrete steward set.
//
// POST /api/v1/fleet/resolve
// Body: {"selector": "name:es-hv0* os:linux tag:prod"}
//
// An empty or missing selector is rejected — use "all" to match all stewards.
// The expression is parsed by pkg/fleet/selector; unknown keys are a parse error.
func (s *Server) handleResolveSelector(w http.ResponseWriter, r *http.Request) {
	var req SelectorResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	if req.Selector == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"selector is required: use 'all' to match all stewards", "MISSING_SELECTOR")
		return
	}

	filter, parsedTenantPath, err := selector.Parse(req.Selector)
	if err != nil {
		s.logger.Info("Invalid selector expression",
			"selector", logging.SanitizeLogValue(req.Selector), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_SELECTOR")
		return
	}

	// Enforce tenant subtree scope. An explicit tenant prefix in the selector
	// must be at or below the caller's own node; absent prefix defaults to the
	// caller's entire subtree. Admin callers (empty tid) are unrestricted.
	tid, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if parsedTenantPath != "" {
		if tid != "" && parsedTenantPath != tid && !strings.HasPrefix(parsedTenantPath, tid+"/") {
			s.logger.Info("Selector tenant outside caller subtree",
				"parsed_tenant", logging.SanitizeLogValue(parsedTenantPath),
				"caller_tenant", logging.SanitizeLogValue(tid))
			s.writeErrorResponse(w, http.StatusForbidden,
				"Target tenant is outside the caller's authorized subtree", "CROSS_TENANT")
			return
		}
		filter.TenantSubtree = parsedTenantPath
	} else if tid != "" {
		filter.TenantSubtree = tid
	}

	results, err := s.fleetQuery.Search(r.Context(), filter)
	if err != nil {
		s.logger.Error("Fleet query failed", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to query fleet", "INTERNAL_ERROR")
		return
	}

	stewardList := make([]StewardInfo, 0, len(results))
	for _, res := range results {
		info := StewardInfo{
			ID:       res.ID,
			TenantID: res.TenantID,
			Status:   res.Status,
			LastSeen: res.LastHeartbeat,
		}
		if len(res.DNAAttributes) > 0 {
			info.DNA = &DNAInfo{
				Hostname:     res.Hostname,
				OS:           res.OS,
				Architecture: res.Architecture,
				Attributes:   res.DNAAttributes,
			}
		}
		stewardList = append(stewardList, info)
	}

	s.logger.Info("Resolved selector",
		"selector", logging.SanitizeLogValue(req.Selector), "count", len(stewardList))
	s.writeSuccessResponse(w, stewardList)
}

// handleFleetHealth handles GET /api/v1/fleet/health.
//
// Returns tenant-scoped counts of stewards by health classification:
//   - healthy:     status=="active" with a heartbeat within DegradedHeartbeatAge
//   - degraded:    status=="active" with a heartbeat older than DegradedHeartbeatAge
//   - unreachable: status=="lost"
//
// Other lifecycle states (registered, deregistered, archived, dormant, revoked)
// are not counted. Scoping includes the caller's full tenant subtree (the caller
// plus all descendant tenants), consistent with handleResolveSelector.
// Admin callers (empty TenantID) see the full fleet.
func (s *Server) handleFleetHealth(w http.ResponseWriter, r *http.Request) {
	tid, _ := r.Context().Value(ctxkeys.TenantID).(string)

	filter := fleet.Filter{}
	if tid != "" {
		filter.TenantSubtree = tid
	}

	results, err := s.fleetQuery.Search(r.Context(), filter)
	if err != nil {
		s.logger.Error("Fleet health query failed", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to query fleet", "INTERNAL_ERROR")
		return
	}

	now := time.Now()
	resp := FleetHealthResponse{}
	for _, res := range results {
		// Count hidden stewards in the caller's scope regardless of include_hidden
		// (non-suppressible: the operator must always see that concealment is in effect).
		if res.Hidden {
			resp.Hidden++
			continue
		}
		switch res.Status {
		case "active":
			if now.Sub(res.LastHeartbeat) <= DegradedHeartbeatAge {
				resp.Healthy++
			} else {
				resp.Degraded++
			}
		case "lost":
			resp.Unreachable++
		}
	}

	s.logger.Info("Fleet health query",
		"tenant_id", logging.SanitizeLogValue(tid),
		"healthy", resp.Healthy,
		"degraded", resp.Degraded,
		"unreachable", resp.Unreachable,
		"hidden", resp.Hidden,
	)
	s.writeSuccessResponse(w, resp)
}
