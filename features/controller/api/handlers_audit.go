// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/audit"
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

	requestedLimit := 50

	filter := &business.AuditFilter{}

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

	readScope := s.tenantReadScope(r, "GET /api/v1/audit/entries")
	if readScope.boundarySubject() {
		s.listRootBoundaryAudit(w, r, readScope, filter, requestedLimit, module)
		return
	}

	tenantID := callerTenantFilter(r.Context())
	filter.TenantID = tenantID
	filter.Limit = requestedLimit + 1

	entries, err := s.auditManager.QueryEntries(r.Context(), filter)
	if err != nil {
		s.logger.Error("Failed to query audit entries",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve audit entries", "INTERNAL_ERROR")
		return
	}

	// Compute has_more from the raw (pre-module-filter) result set, then trim.
	hasMore := len(entries) > requestedLimit
	if hasMore {
		entries = entries[:requestedLimit]
	}

	entries = filterAuditByModule(entries, module)

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

// filterAuditByModule applies the post-query module prefix filter and never
// returns nil.
func filterAuditByModule(entries []*business.AuditEntry, module string) []*business.AuditEntry {
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
	return entries
}

// rootAuditMaxOffset caps offset on the merged root path, which fetches
// offset+limit+1 rows from every source on each request.
const rootAuditMaxOffset = 5000

// rootAuditFetchChunk is the page size used when draining one source.
const rootAuditFetchChunk = 200

// rootAuditCarveOutRule is one ADR-025 Decision 4 category of tenant audit entry
// that stays visible to a boundary-subject root caller without a crossing. An entry
// matches when its event type equals EventType and, if set, its action is in Actions
// or starts with ActionPrefix and its result is in Results.
type rootAuditCarveOutRule struct {
	Category     string
	EventType    business.AuditEventType
	Actions      []string
	ActionPrefix string
	Results      []business.AuditResult
}

// rootAuditCarveOut is the closed allowlist of Decision 4 categories, one entry per
// category. Growing it is a founder decision (TestRootAuditCarveOut_Pinned).
//
//   - Authentication failures on MSP administrator accounts: the controller emits
//     web.passkey.login.failure for a failed web login or credential assertion. It
//     audits no separate lockout or suspicious-login action today.
//   - Crossing meta-log: every tenant.crossing_* action.
//   - Abuse and resource-exhaustion signals: the controller audits no rate-limit
//     trips today, so there is no entry for them.
//   - Platform events: AuditEventSystemEvent.
var rootAuditCarveOut = []rootAuditCarveOutRule{
	{
		Category:  "msp-admin-authentication-failure",
		EventType: business.AuditEventAuthentication,
		Actions:   []string{"web.passkey.login.failure"},
		Results:   []business.AuditResult{business.AuditResultFailure},
	},
	{
		Category:     "crossing-meta-log",
		EventType:    business.AuditEventSystemAccess,
		ActionPrefix: "tenant.crossing_",
	},
	{
		Category:  "platform-event",
		EventType: business.AuditEventSystemEvent,
	},
}

// rootAuditCarveOutDetailKeys is the projection allowlist for carve-out rows.
var rootAuditCarveOutDetailKeys = []string{"actor", "action", "result", "time", "source_address"}

func (r rootAuditCarveOutRule) matches(e *business.AuditEntry) bool {
	if e.EventType != r.EventType {
		return false
	}
	if len(r.Actions) > 0 {
		found := false
		for _, a := range r.Actions {
			if a == e.Action {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	if r.ActionPrefix != "" && !strings.HasPrefix(e.Action, r.ActionPrefix) {
		return false
	}
	if len(r.Results) > 0 {
		found := false
		for _, res := range r.Results {
			if res == e.Result {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// reduceCarveOutEntry projects an entry to the fixed safe field set; nothing else
// from the stored entry is copied.
func reduceCarveOutEntry(e *business.AuditEntry) *business.AuditEntry {
	return &business.AuditEntry{
		ID:        e.ID,
		TenantID:  e.TenantID,
		Timestamp: e.Timestamp,
		EventType: e.EventType,
		Action:    e.Action,
		UserID:    e.UserID,
		UserType:  e.UserType,
		Result:    e.Result,
		Severity:  e.Severity,
		IPAddress: e.IPAddress,
		Details: map[string]interface{}{
			"actor":          e.UserID,
			"action":         e.Action,
			"result":         string(e.Result),
			"time":           e.Timestamp.UTC().Format(time.RFC3339Nano),
			"source_address": e.IPAddress,
		},
	}
}

// copyAuditFilter returns a shallow copy so per-source queries do not share paging.
func copyAuditFilter(f *business.AuditFilter) *business.AuditFilter {
	c := *f
	return &c
}

// fetchAuditSource drains one source newest first until need accepted entries are
// collected or the source is exhausted.
func (s *Server) fetchAuditSource(ctx context.Context, base *business.AuditFilter, need int, accept func(*business.AuditEntry) bool) ([]*business.AuditEntry, error) {
	var out []*business.AuditEntry
	for offset := 0; len(out) < need; offset += rootAuditFetchChunk {
		f := copyAuditFilter(base)
		f.Offset, f.Limit = offset, rootAuditFetchChunk
		f.SortBy, f.Order = "timestamp", "desc"
		rows, err := s.auditManager.QueryEntries(ctx, f)
		if err != nil {
			return nil, err
		}
		for _, e := range rows {
			if accept == nil || accept(e) {
				out = append(out, e)
			}
		}
		if len(rows) < rootAuditFetchChunk {
			break
		}
	}
	if len(out) > need {
		out = out[:need]
	}
	return out, nil
}

// carveOutBaseFilter narrows the caller's filter to rule, or reports false when the
// caller's event_type or action filter can never match the rule.
func carveOutBaseFilter(base *business.AuditFilter, rule rootAuditCarveOutRule, tenantID string) (*business.AuditFilter, bool) {
	f := copyAuditFilter(base)
	f.TenantID = tenantID
	if len(f.EventTypes) > 0 && f.EventTypes[0] != rule.EventType {
		return nil, false
	}
	f.EventTypes = []business.AuditEventType{rule.EventType}
	if len(f.Actions) > 0 {
		probe := &business.AuditEntry{EventType: rule.EventType, Action: f.Actions[0]}
		if len(rule.Results) > 0 {
			probe.Result = rule.Results[0]
		}
		if !rule.matches(probe) {
			return nil, false
		}
	} else if len(rule.Actions) > 0 {
		f.Actions = rule.Actions
	}
	if len(rule.Results) > 0 {
		if len(f.Results) > 0 && f.Results[0] != rule.Results[0] {
			return nil, false
		}
		f.Results = rule.Results
	}
	return f, true
}

// listRootBoundaryAudit serves GET /api/v1/audit/entries to a root caller subject to
// the ADR-025 crossing boundary: root's own scope and the subtree of every active
// crossing in full, plus the Decision 4 carve-out of direct-child (MSP) tenants
// reduced to a safe field set. Per-source results are merged newest first.
func (s *Server) listRootBoundaryAudit(w http.ResponseWriter, r *http.Request, scope *tenantReadScope, base *business.AuditFilter, limit int, module string) {
	ctx := r.Context()
	offset := base.Offset
	if offset > rootAuditMaxOffset {
		s.writeErrorResponse(w, http.StatusBadRequest, "offset exceeds the maximum for root audit reads", "INVALID_OFFSET")
		return
	}
	need := offset + limit + 1

	// When no single root resolves, fail closed: the principal's own tenant in
	// full and no carve-out.
	rootID := s.rootTenantID(ctx)
	rootResolved := rootID != ""
	if !rootResolved {
		if p, _ := ctx.Value(principalContextKey).(*Principal); p != nil {
			rootID = p.TenantID
		}
	}

	full := map[string]struct{}{}
	if rootID != "" {
		full[rootID] = struct{}{}
	}
	for _, crossed := range scope.CrossingTenants() {
		scope.Allows(crossed) // records grant use, as every other crossing read does
		for id := range s.tenantSubtreeIDs(ctx, crossed) {
			full[id] = struct{}{}
		}
	}
	fullIDs := make([]string, 0, len(full))
	for id := range full {
		fullIDs = append(fullIDs, id)
	}
	sort.Strings(fullIDs)

	seen := map[string]struct{}{}
	var merged []*business.AuditEntry
	add := func(rows []*business.AuditEntry, reduce bool) {
		for _, e := range rows {
			if _, dup := seen[e.ID]; dup {
				continue
			}
			seen[e.ID] = struct{}{}
			if reduce {
				e = reduceCarveOutEntry(e)
			}
			merged = append(merged, e)
		}
	}
	fail := func(err error) {
		s.logger.Error("Failed to query audit entries",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve audit entries", "INTERNAL_ERROR")
	}

	for _, id := range fullIDs {
		f := copyAuditFilter(base)
		f.TenantID = id
		rows, err := s.fetchAuditSource(ctx, f, need, nil)
		if err != nil {
			fail(err)
			return
		}
		add(rows, false)
	}

	// Carve-out: MSPs are the direct children of root. The platform tenant holds
	// events no tenant owns. Deeper tenants never appear.
	var carveTenants []string
	if rootResolved {
		carveTenants = append(carveTenants, audit.SystemTenantID)
	}
	if s.tenantManager != nil && rootResolved {
		children, err := s.tenantManager.GetChildTenants(ctx, rootID)
		if err != nil {
			s.logger.Warn("Root audit carve-out child lookup failed; omitting carve-out",
				"error", logging.SanitizeLogValue(err.Error()))
			carveTenants = nil
		}
		for _, c := range children {
			if c != nil && c.ID != "" {
				carveTenants = append(carveTenants, c.ID)
			}
		}
	}
	for _, tenantID := range carveTenants {
		if _, covered := full[tenantID]; covered {
			continue
		}
		for _, rule := range rootAuditCarveOut {
			f, ok := carveOutBaseFilter(base, rule, tenantID)
			if !ok {
				continue
			}
			rule := rule
			rows, err := s.fetchAuditSource(ctx, f, need, func(e *business.AuditEntry) bool { return rule.matches(e) })
			if err != nil {
				fail(err)
				return
			}
			add(rows, true)
		}
	}

	sort.SliceStable(merged, func(i, j int) bool {
		if !merged[i].Timestamp.Equal(merged[j].Timestamp) {
			return merged[i].Timestamp.After(merged[j].Timestamp)
		}
		return merged[i].ID > merged[j].ID
	})
	if offset >= len(merged) {
		merged = nil
	} else {
		merged = merged[offset:]
	}
	hasMore := len(merged) > limit
	if hasMore {
		merged = merged[:limit]
	}
	scope.LogSummary()
	s.logger.Info("Retrieved root audit entries",
		"count", len(merged),
		"has_more", hasMore,
		"module", logging.SanitizeLogValue(module),
	)
	s.writeSuccessResponse(w, auditListResponse{
		Entries: filterAuditByModule(merged, module),
		HasMore: hasMore,
	})
}
