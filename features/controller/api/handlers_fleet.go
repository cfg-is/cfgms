// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/fleet/selector"
	"github.com/cfgis/cfgms/pkg/logging"
)

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
			"selector", logging.SanitizeLogValue(req.Selector), "error", err)
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
		s.logger.Error("Fleet query failed", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to query fleet", "INTERNAL_ERROR")
		return
	}

	stewardList := make([]StewardInfo, 0, len(results))
	for _, res := range results {
		info := StewardInfo{
			ID:       res.ID,
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
