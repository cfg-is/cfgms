// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// auditListResponse is the data payload inside the standard {data, timestamp}
// envelope returned by handleListAuditEntries.
type auditListResponse struct {
	Entries []*business.AuditEntry `json:"entries"`
	HasMore bool                   `json:"has_more"`
}

// handleListAuditEntries handles GET /api/v1/audit/entries.
// Returns {"data": {"entries": [...], "has_more": bool}, "timestamp": "..."}.
// TenantID is always sourced from the authenticated principal's context —
// any tenant_id query param supplied by the caller is silently discarded.
//
// has_more uses the limit+1 technique: the handler requests one extra row from
// QueryEntries; if the extra row exists has_more is true and the extra row is
// trimmed before sending. has_more is computed from the pre-module-filter
// result set — see Issue #2989 implementation notes.
func (s *Server) handleListAuditEntries(w http.ResponseWriter, r *http.Request) {
	if s.auditManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Audit service not available", "AUDIT_NOT_AVAILABLE")
		return
	}

	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)

	requestedLimit := 50

	filter := &business.AuditFilter{
		TenantID: tenantID,
	}

	if since := r.URL.Query().Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			if filter.TimeRange == nil {
				filter.TimeRange = &business.TimeRange{}
			}
			filter.TimeRange.Start = &t
		}
	}
	if until := r.URL.Query().Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			if filter.TimeRange == nil {
				filter.TimeRange = &business.TimeRange{}
			}
			filter.TimeRange.End = &t
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			if l < 1 {
				l = 1
			}
			if l > 500 {
				l = 500
			}
			requestedLimit = l
		}
	}

	// Fetch one extra row to detect whether more pages exist without a count query.
	filter.Limit = requestedLimit + 1

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			filter.Offset = o
		}
	}

	if severity := r.URL.Query().Get("severity"); severity != "" {
		filter.Severities = []business.AuditSeverity{business.AuditSeverity(severity)}
	}

	if action := r.URL.Query().Get("action"); action != "" {
		filter.Actions = []string{action}
	}

	if eventType := r.URL.Query().Get("event_type"); eventType != "" {
		filter.EventTypes = []business.AuditEventType{business.AuditEventType(eventType)}
	}

	if userID := r.URL.Query().Get("user_id"); userID != "" {
		filter.UserIDs = []string{userID}
	}

	if result := r.URL.Query().Get("result"); result != "" {
		filter.Results = []business.AuditResult{business.AuditResult(result)}
	}

	// module is a post-query prefix filter; do not set ResourceTypes on the filter
	// because the storage layer does exact-match only.
	module := r.URL.Query().Get("module")

	entries, err := s.auditManager.QueryEntries(r.Context(), filter)
	if err != nil {
		s.logger.Error("Failed to query audit entries",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", err,
		)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve audit entries", "INTERNAL_ERROR")
		return
	}

	// Compute has_more from the raw (pre-module-filter) result set, then trim.
	hasMore := len(entries) > requestedLimit
	if hasMore {
		entries = entries[:requestedLimit]
	}

	if module != "" {
		prefix := module + "/"
		filtered := make([]*business.AuditEntry, 0, len(entries))
		for _, e := range entries {
			if strings.HasPrefix(e.ResourceType, prefix) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	if entries == nil {
		entries = []*business.AuditEntry{}
	}

	s.logger.Info("Retrieved audit entries",
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"count", len(entries),
		"has_more", hasMore,
		"module", logging.SanitizeLogValue(module),
	)
	s.writeSuccessResponse(w, auditListResponse{
		Entries: entries,
		HasMore: hasMore,
	})
}
