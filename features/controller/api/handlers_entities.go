// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// egReadProvider is the narrow read-only subset of interfaces.EntityGraphProvider
// that the REST handlers require. *sqlite.SQLiteEntityGraphProvider satisfies it.
type egReadProvider interface {
	GetEntity(ctx context.Context, eid eginterfaces.EIDRef, opts eginterfaces.GetEntityOpts) (*egtypes.EntityView, error)
	QueryEntities(ctx context.Context, filter eginterfaces.EntityFilter, page eginterfaces.PageToken) (*eginterfaces.EntityPage, error)
	GetEdges(ctx context.Context, filter eginterfaces.EdgeFilter) ([]*eginterfaces.EdgeView, error)
	GetNeighborhood(ctx context.Context, eid eginterfaces.EIDRef, edgeTypes []string, direction egtypes.TraversalDirection, depth int) (*egtypes.Neighborhood, error)
	GetHistory(ctx context.Context, eid eginterfaces.EIDRef, r eginterfaces.TimeRange) ([]*eginterfaces.ObservationRecord, error)
	Diff(ctx context.Context, eid eginterfaces.EIDRef, r eginterfaces.TimeRange) (*eginterfaces.StateDiff, error)
	GetTimeline(ctx context.Context, eids []eginterfaces.EIDRef, r eginterfaces.TimeRange) ([]*eginterfaces.TimelineEvent, error)
	GetDriftState(ctx context.Context, eid eginterfaces.EIDRef) (*eginterfaces.DriftState, error)
	ListDrifted(ctx context.Context, filter eginterfaces.DriftFilter) ([]*eginterfaces.DriftState, error)
}

// maxNeighborhoodDepth is the access-contract cap for GetNeighborhood (ADR-022 §9).
const maxNeighborhoodDepth = 3

// entityMaxPageSize caps page_size to prevent resource exhaustion on large fleets.
const entityMaxPageSize = 1000

// parseEIDFromPath extracts and parses the "eid" gorilla/mux variable. The path
// variable uses {eid:.+} so it captures slashes; gorilla/mux URL-decodes the
// value before returning it from mux.Vars.
func parseEIDFromPath(r *http.Request) (egtypes.EID, error) {
	raw := mux.Vars(r)["eid"]
	return egtypes.ParseEID(raw)
}

// parseTimeRangeQuery parses "from" and "to" query parameters as RFC 3339 times.
// Both parameters are required.
func parseTimeRangeQuery(q url.Values) (eginterfaces.TimeRange, error) {
	fromStr := q.Get("from")
	toStr := q.Get("to")
	if fromStr == "" || toStr == "" {
		return eginterfaces.TimeRange{}, errors.New("from and to query parameters are required")
	}
	from, err := time.Parse(time.RFC3339, fromStr)
	if err != nil {
		return eginterfaces.TimeRange{}, errors.New("from must be RFC 3339 (e.g. 2006-01-02T15:04:05Z)")
	}
	to, err := time.Parse(time.RFC3339, toStr)
	if err != nil {
		return eginterfaces.TimeRange{}, errors.New("to must be RFC 3339 (e.g. 2006-01-02T15:04:05Z)")
	}
	if !to.After(from) {
		return eginterfaces.TimeRange{}, errors.New("to must be after from")
	}
	return eginterfaces.TimeRange{From: from, To: to}, nil
}

// callerTenantSubtree returns the authenticated caller's tenant ID from the
// request context. An empty string means the caller has global (cross-tenant)
// scope and sees all entities.
func callerTenantSubtree(r *http.Request) string {
	t, _ := r.Context().Value(ctxkeys.TenantID).(string)
	return t
}

// writeEntityJSON encodes v as JSON and writes it to w with Content-Type application/json.
func writeEntityJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return
	}
}

// isEntityNotFound reports whether err indicates that the requested resource does
// not exist or is outside the caller's tenant subtree. Both conditions surface
// the same error to prevent information disclosure (ADR-022 §7).
func isEntityNotFound(err error) bool {
	return errors.Is(err, eginterfaces.ErrNotFound)
}

// verifyEntityAccess checks that the given EID is visible to the authenticated caller.
// It calls GetEntity with the caller's tenant filter and returns true when access
// is allowed. Returns false on not-found/cross-tenant (caller should return 404)
// and returns an error on unexpected provider failures (caller should return 500).
// Used to gate handlers where the underlying provider method carries no tenant
// parameter (GetHistory, Diff, GetTimeline, GetDriftState, GetNeighborhood).
func (s *Server) verifyEntityAccess(ctx context.Context, eid eginterfaces.EIDRef, callerTenant string) (ok bool, serverErr error) {
	_, err := s.egProvider.GetEntity(ctx, eid, eginterfaces.GetEntityOpts{
		TenantFilter: callerTenant,
	})
	if err != nil {
		if isEntityNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// handleQueryEntities handles GET /api/v1/entities.
// Query params: kind, text_query, as_of (RFC 3339), page_token, page_size (1-1000).
func (s *Server) handleQueryEntities(w http.ResponseWriter, r *http.Request) {
	if s.egProvider == nil {
		http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	filter := eginterfaces.EntityFilter{
		TenantFilter: callerTenantSubtree(r),
		Kind:         q.Get("kind"),
		TextQuery:    q.Get("text_query"),
	}

	if asOfStr := q.Get("as_of"); asOfStr != "" {
		t, err := time.Parse(time.RFC3339, asOfStr)
		if err != nil {
			http.Error(w, "as_of must be RFC 3339", http.StatusBadRequest)
			return
		}
		filter.AsOf = &t
	}

	page := eginterfaces.PageToken{
		Token: q.Get("page_token"),
	}
	if psStr := q.Get("page_size"); psStr != "" {
		ps, err := strconv.Atoi(psStr)
		if err != nil || ps < 1 || ps > entityMaxPageSize {
			http.Error(w, "page_size must be an integer between 1 and 1000", http.StatusBadRequest)
			return
		}
		page.PageSize = ps
	}

	result, err := s.egProvider.QueryEntities(r.Context(), filter, page)
	if err != nil {
		s.logger.Error("handleQueryEntities: query failed",
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	writeEntityJSON(w, result)
}

// handleGetEntity handles GET /api/v1/entities/{eid:.+}.
// Applies mandatory tenant-subtree filter; cross-tenant reads return 404 (ADR-022 §7).
func (s *Server) handleGetEntity(w http.ResponseWriter, r *http.Request) {
	if s.egProvider == nil {
		http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
		return
	}

	eid, err := parseEIDFromPath(r)
	if err != nil {
		http.Error(w, "invalid entity ID", http.StatusBadRequest)
		return
	}

	q := r.URL.Query()
	opts := eginterfaces.GetEntityOpts{
		TenantFilter: callerTenantSubtree(r),
	}

	if asOfStr := q.Get("as_of"); asOfStr != "" {
		t, err := time.Parse(time.RFC3339, asOfStr)
		if err != nil {
			http.Error(w, "as_of must be RFC 3339", http.StatusBadRequest)
			return
		}
		opts.AsOf = &t
	}

	if q.Get("collapse_group") == "true" {
		opts.CollapseGroup = true
	}

	view, err := s.egProvider.GetEntity(r.Context(), eid, opts)
	if err != nil {
		if isEntityNotFound(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.logger.Error("handleGetEntity: lookup failed",
			"eid", logging.SanitizeLogValue(eid.String()),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	if view == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	writeEntityJSON(w, view)
}

// handleGetEdges handles GET /api/v1/entities/{eid:.+}/edges.
// Query params: edge_type (repeatable), source, direction (outbound|inbound).
func (s *Server) handleGetEdges(w http.ResponseWriter, r *http.Request) {
	if s.egProvider == nil {
		http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
		return
	}

	eid, err := parseEIDFromPath(r)
	if err != nil {
		http.Error(w, "invalid entity ID", http.StatusBadRequest)
		return
	}

	q := r.URL.Query()
	filter := eginterfaces.EdgeFilter{
		FromEID:      &eid,
		Types:        q["edge_type"],
		Source:       q.Get("source"),
		TenantFilter: callerTenantSubtree(r),
	}

	if q.Get("direction") == "inbound" {
		filter.FromEID = nil
		filter.ToEID = &eid
	}

	edges, err := s.egProvider.GetEdges(r.Context(), filter)
	if err != nil {
		s.logger.Error("handleGetEdges: query failed",
			"eid", logging.SanitizeLogValue(eid.String()),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	writeEntityJSON(w, edges)
}

// handleGetNeighborhood handles GET /api/v1/entities/{eid:.+}/neighborhood.
// Query params: depth (1-3, default 1), direction (outbound|inbound|both), edge_type (repeatable).
// The caller's tenant is verified via GetEntity before traversal because the provider
// derives the tenant filter from the root entity's own tenant, not the caller's credential.
func (s *Server) handleGetNeighborhood(w http.ResponseWriter, r *http.Request) {
	if s.egProvider == nil {
		http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
		return
	}

	eid, err := parseEIDFromPath(r)
	if err != nil {
		http.Error(w, "invalid entity ID", http.StatusBadRequest)
		return
	}

	q := r.URL.Query()

	depth := 1
	if depthStr := q.Get("depth"); depthStr != "" {
		d, err := strconv.Atoi(depthStr)
		if err != nil || d < 1 || d > maxNeighborhoodDepth {
			http.Error(w, "depth must be 1, 2, or 3", http.StatusBadRequest)
			return
		}
		depth = d
	}

	direction := egtypes.TraversalOutbound
	if dirStr := q.Get("direction"); dirStr != "" {
		switch dirStr {
		case "outbound":
			direction = egtypes.TraversalOutbound
		case "inbound":
			direction = egtypes.TraversalInbound
		case "both":
			direction = egtypes.TraversalBoth
		default:
			http.Error(w, "direction must be outbound, inbound, or both", http.StatusBadRequest)
			return
		}
	}

	// Verify caller can access the root entity before traversing its neighborhood.
	// The provider uses the root entity's owning_tenant as the traversal filter, not
	// the caller's credential — so a cross-tenant caller without this pre-check
	// could retrieve a foreign entity's subgraph (ADR-022 §7).
	ok, accessErr := s.verifyEntityAccess(r.Context(), eid, callerTenantSubtree(r))
	if accessErr != nil {
		s.logger.Error("handleGetNeighborhood: entity access check failed",
			"eid", logging.SanitizeLogValue(eid.String()),
			"error", logging.SanitizeLogValue(accessErr.Error()),
		)
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	neighborhood, err := s.egProvider.GetNeighborhood(r.Context(), eid, q["edge_type"], direction, depth)
	if err != nil {
		if isEntityNotFound(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.logger.Error("handleGetNeighborhood: query failed",
			"eid", logging.SanitizeLogValue(eid.String()),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	writeEntityJSON(w, neighborhood)
}

// handleGetHistory handles GET /api/v1/entities/{eid:.+}/history.
// Query params: from, to (RFC 3339, required).
// GetHistory has no tenant filter parameter; access is verified via GetEntity first (ADR-022 §7).
func (s *Server) handleGetHistory(w http.ResponseWriter, r *http.Request) {
	if s.egProvider == nil {
		http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
		return
	}

	eid, err := parseEIDFromPath(r)
	if err != nil {
		http.Error(w, "invalid entity ID", http.StatusBadRequest)
		return
	}

	tr, err := parseTimeRangeQuery(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// GetHistory has no tenant filter parameter — verify access via GetEntity first.
	ok, accessErr := s.verifyEntityAccess(r.Context(), eid, callerTenantSubtree(r))
	if accessErr != nil {
		s.logger.Error("handleGetHistory: entity access check failed",
			"eid", logging.SanitizeLogValue(eid.String()),
			"error", logging.SanitizeLogValue(accessErr.Error()),
		)
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	records, err := s.egProvider.GetHistory(r.Context(), eid, tr)
	if err != nil {
		if isEntityNotFound(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.logger.Error("handleGetHistory: query failed",
			"eid", logging.SanitizeLogValue(eid.String()),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	writeEntityJSON(w, records)
}

// handleDiff handles GET /api/v1/entities/{eid:.+}/diff.
// Query params: from, to (RFC 3339, required).
// Diff has no tenant filter parameter; access is verified via GetEntity first (ADR-022 §7).
func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	if s.egProvider == nil {
		http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
		return
	}

	eid, err := parseEIDFromPath(r)
	if err != nil {
		http.Error(w, "invalid entity ID", http.StatusBadRequest)
		return
	}

	tr, err := parseTimeRangeQuery(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Diff has no tenant filter parameter — verify access via GetEntity first.
	ok, accessErr := s.verifyEntityAccess(r.Context(), eid, callerTenantSubtree(r))
	if accessErr != nil {
		s.logger.Error("handleDiff: entity access check failed",
			"eid", logging.SanitizeLogValue(eid.String()),
			"error", logging.SanitizeLogValue(accessErr.Error()),
		)
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	diff, err := s.egProvider.Diff(r.Context(), eid, tr)
	if err != nil {
		if isEntityNotFound(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.logger.Error("handleDiff: query failed",
			"eid", logging.SanitizeLogValue(eid.String()),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	writeEntityJSON(w, diff)
}

// handleGetTimeline handles GET /api/v1/entities/timeline.
// Query params: eid (repeatable, at least one required), from, to (RFC 3339, required).
// GetTimeline has no per-eid tenant filter; each EID is verified via GetEntity first (ADR-022 §7).
func (s *Server) handleGetTimeline(w http.ResponseWriter, r *http.Request) {
	if s.egProvider == nil {
		http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	eidStrs := q["eid"]
	if len(eidStrs) == 0 {
		http.Error(w, "at least one eid query parameter is required", http.StatusBadRequest)
		return
	}

	callerTenant := callerTenantSubtree(r)
	eids := make([]eginterfaces.EIDRef, 0, len(eidStrs))
	for _, eidStr := range eidStrs {
		eid, err := egtypes.ParseEID(eidStr)
		if err != nil {
			http.Error(w, "invalid eid: must be authority_type:authority_name[/local_id]", http.StatusBadRequest)
			return
		}
		// GetTimeline has no tenant filter parameter — verify access per EID.
		ok, accessErr := s.verifyEntityAccess(r.Context(), eid, callerTenant)
		if accessErr != nil {
			s.logger.Error("handleGetTimeline: entity access check failed",
				"eid", logging.SanitizeLogValue(eid.String()),
				"error", logging.SanitizeLogValue(accessErr.Error()),
			)
			http.Error(w, "lookup failed", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		eids = append(eids, eid)
	}

	tr, err := parseTimeRangeQuery(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	events, err := s.egProvider.GetTimeline(r.Context(), eids, tr)
	if err != nil {
		s.logger.Error("handleGetTimeline: query failed",
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	writeEntityJSON(w, events)
}

// handleGetDriftState handles GET /api/v1/entities/{eid:.+}/drift.
// GetDriftState has no tenant filter parameter; access is verified via GetEntity first (ADR-022 §7).
func (s *Server) handleGetDriftState(w http.ResponseWriter, r *http.Request) {
	if s.egProvider == nil {
		http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
		return
	}

	eid, err := parseEIDFromPath(r)
	if err != nil {
		http.Error(w, "invalid entity ID", http.StatusBadRequest)
		return
	}

	// GetDriftState has no tenant filter parameter — verify access via GetEntity first.
	ok, accessErr := s.verifyEntityAccess(r.Context(), eid, callerTenantSubtree(r))
	if accessErr != nil {
		s.logger.Error("handleGetDriftState: entity access check failed",
			"eid", logging.SanitizeLogValue(eid.String()),
			"error", logging.SanitizeLogValue(accessErr.Error()),
		)
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	drift, err := s.egProvider.GetDriftState(r.Context(), eid)
	if err != nil {
		if isEntityNotFound(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.logger.Error("handleGetDriftState: query failed",
			"eid", logging.SanitizeLogValue(eid.String()),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	writeEntityJSON(w, drift)
}

// handleListDrifted handles GET /api/v1/entities/drifted.
// Query params: lifecycle_status (detected|acknowledged|resolved|ignored), kind.
func (s *Server) handleListDrifted(w http.ResponseWriter, r *http.Request) {
	if s.egProvider == nil {
		http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	lifecycleStatus := q.Get("lifecycle_status")

	validStatuses := map[string]bool{
		"":             true,
		"detected":     true,
		"acknowledged": true,
		"resolved":     true,
		"ignored":      true,
	}
	if !validStatuses[lifecycleStatus] {
		http.Error(w, "lifecycle_status must be detected, acknowledged, resolved, or ignored", http.StatusBadRequest)
		return
	}

	filter := eginterfaces.DriftFilter{
		TenantFilter:    callerTenantSubtree(r),
		LifecycleStatus: lifecycleStatus,
		Kind:            q.Get("kind"),
	}

	states, err := s.egProvider.ListDrifted(r.Context(), filter)
	if err != nil {
		s.logger.Error("handleListDrifted: query failed",
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	writeEntityJSON(w, states)
}
