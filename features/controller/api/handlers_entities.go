// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// egWriteProvider is the narrow write-only subset of interfaces.EntityGraphProvider
// that the edge-assertion handler requires. *sqlite.SQLiteEntityGraphProvider satisfies it.
type egWriteProvider interface {
	ReportObservations(ctx context.Context, batch eginterfaces.ObservationBatch) error
}

// egReadProvider is the narrow read-only subset of interfaces.EntityGraphProvider
// that the REST handlers require. *sqlite.SQLiteEntityGraphProvider satisfies it.
type egReadProvider interface {
	GetEntity(ctx context.Context, eid eginterfaces.EIDRef, opts eginterfaces.GetEntityOpts) (*egtypes.EntityView, error)
	QueryEntities(ctx context.Context, filter eginterfaces.EntityFilter, page eginterfaces.PageToken) (*eginterfaces.EntityPage, error)
	GetEdges(ctx context.Context, filter eginterfaces.EdgeFilter) ([]*eginterfaces.EdgeView, error)
	GetNeighborhood(ctx context.Context, eid eginterfaces.EIDRef, edgeTypes []string, direction egtypes.TraversalDirection, depth int, cut eginterfaces.TenantCut) (*egtypes.Neighborhood, error)
	GetHistory(ctx context.Context, eid eginterfaces.EIDRef, r eginterfaces.TimeRange) ([]*eginterfaces.ObservationRecord, error)
	Diff(ctx context.Context, eid eginterfaces.EIDRef, r eginterfaces.TimeRange) (*eginterfaces.StateDiff, error)
	GetTimeline(ctx context.Context, eids []eginterfaces.EIDRef, r eginterfaces.TimeRange) ([]*eginterfaces.TimelineEvent, error)
	GetDriftState(ctx context.Context, eid eginterfaces.EIDRef) (*eginterfaces.DriftState, error)
	GetDesiredState(ctx context.Context, eid eginterfaces.EIDRef) (*egtypes.DesiredStateView, error)
	ListDrifted(ctx context.Context, filter eginterfaces.DriftFilter) ([]*eginterfaces.DriftState, error)
	ResolveIdentity(ctx context.Context, claims eginterfaces.IdentityClaims) ([]eginterfaces.EIDRef, error)
}

// maxNeighborhoodDepth is the access-contract cap for GetNeighborhood (ADR-022 §9).
const maxNeighborhoodDepth = 3

// entityMaxPageSize caps page_size to prevent resource exhaustion on large fleets.
const entityMaxPageSize = 1000

// maxTimelineEIDs is the most eid query values one timeline request accepts.
const maxTimelineEIDs = 100

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
	t := callerTenantFilter(r.Context())
	return t
}

// entityCut is the tenant cut the entity-graph provider applies to a read made
// for this caller: the caller's tenant filter and its resolved descendant IDs. A
// root caller's "" cut is unrestricted, so a boundary-subject root caller (ADR-025)
// never reaches a client tenant through it directly: handlers pair it with
// tenantReadScope, which filters every entity the provider returns by the
// crossing decision.
func (s *Server) entityCut(r *http.Request) (string, []string) {
	tenant := callerTenantFilter(r.Context())
	return tenant, s.tenantDescendantIDs(r.Context(), tenant)
}

// authorizeEntityRead gates an entity-keyed read. The entity is looked up inside
// the caller's tenant cut (not found → 404, ADR-022 §7) and its owning tenant is
// then put through authorizeRecordRead: a boundary-subject root caller with no
// crossing for that tenant gets the crossing challenge. It writes the refusal and
// returns false when the read must not proceed.
func (s *Server) authorizeEntityRead(w http.ResponseWriter, r *http.Request, eid eginterfaces.EIDRef, route string) bool {
	tenant, ids := s.entityCut(r)
	view, err := s.egProvider.GetEntity(r.Context(), eid, eginterfaces.GetEntityOpts{TenantFilter: tenant, TenantSubtreeIDs: ids})
	if err != nil {
		if isEntityNotFound(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return false
		}
		s.logger.Error("entity access check failed",
			"route", logging.SanitizeLogValue(route),
			"eid", logging.SanitizeLogValue(eid.String()),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return false
	}
	if view == nil || view.Entity == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return false
	}
	return s.authorizeRecordRead(w, r, view.Entity.OwningTenant, route, func() {
		http.Error(w, "not found", http.StatusNotFound)
	})
}

// entityOwner returns the owning tenant of eid as the caller's tenant cut sees it.
// found is false when the entity does not exist inside the cut.
func (s *Server) entityOwner(ctx context.Context, eid eginterfaces.EIDRef, tenant string, ids []string) (owner string, found bool, err error) {
	view, err := s.egProvider.GetEntity(ctx, eid, eginterfaces.GetEntityOpts{TenantFilter: tenant, TenantSubtreeIDs: ids})
	if err != nil {
		if isEntityNotFound(err) {
			return "", false, nil
		}
		return "", false, err
	}
	if view == nil || view.Entity == nil {
		return "", false, nil
	}
	return view.Entity.OwningTenant, true, nil
}

// entityTenantCut is one tenant the entity provider is asked about together with
// its resolved descendant tenant IDs.
type entityTenantCut struct {
	tenant string
	ids    []string
}

// boundaryReadCuts lists the cuts a boundary-subject root caller may read: the
// root tenant on its own (no descendants, so no client tenant) and every
// crossing-covered tenant with its subtree. It is for provider reads whose rows
// carry no owning tenant (drift), where filtering afterwards is not possible, so
// the provider is asked once per cut and the results are merged.
func (s *Server) boundaryReadCuts(r *http.Request, scope *tenantReadScope) []entityTenantCut {
	var cuts []entityTenantCut
	if own, ok := callerOwnTenant(r.Context()); ok {
		cuts = append(cuts, entityTenantCut{tenant: own})
	}
	for _, id := range scope.CrossingTenants() {
		if !scope.Allows(id) {
			continue
		}
		cuts = append(cuts, entityTenantCut{tenant: id, ids: s.tenantDescendantIDs(r.Context(), id)})
	}
	return cuts
}

// maxEmptyEntityPages bounds how many consecutive pages a boundary-subject query
// skips because every entity on them is unreadable, so a fleet that is almost all
// client tenants cannot turn one request into a full table scan.
const maxEmptyEntityPages = 50

// queryEntitiesInReadScope runs QueryEntities and, for a boundary-subject root
// caller, keeps only the entities the caller may read. The provider cut is
// unrestricted for such a caller, so the filtering happens here on each row's
// owning tenant. A page that filters to nothing is skipped in favour of the next,
// so a short or empty page never hides readable entities further along.
func (s *Server) queryEntitiesInReadScope(r *http.Request, route string, filter eginterfaces.EntityFilter, page eginterfaces.PageToken) (*eginterfaces.EntityPage, error) {
	scope := s.tenantReadScope(r, route)
	if !scope.boundarySubject() {
		return s.egProvider.QueryEntities(r.Context(), filter, page)
	}
	defer scope.LogSummary()
	for skipped := 0; ; skipped++ {
		result, err := s.egProvider.QueryEntities(r.Context(), filter, page)
		if err != nil {
			return nil, err
		}
		readable := make([]*egtypes.EntityView, 0, len(result.Entities))
		for _, v := range result.Entities {
			if v != nil && v.Entity != nil && scope.Allows(v.Entity.OwningTenant) {
				readable = append(readable, v)
			}
		}
		result.Entities = readable
		if len(readable) > 0 || result.NextToken == "" || skipped >= maxEmptyEntityPages {
			return result, nil
		}
		page.Token = result.NextToken
	}
}

// listDriftedInReadScope runs ListDrifted for one page of at most limit states
// and returns the token for the next page ("" on the last one). Drift rows carry
// no owning tenant, so a boundary-subject root caller is served by asking the
// provider once for the root tenant on its own and once per crossing-covered
// tenant (each for limit+1 rows after the same cursor), then merging, sorting by
// subject and truncating to limit, so the limit bounds the whole response. The
// token names the last returned subject, which the caller was allowed to see.
func (s *Server) listDriftedInReadScope(r *http.Request, route string, filter eginterfaces.DriftFilter, limit int) ([]*eginterfaces.DriftState, string, error) {
	scope := s.tenantReadScope(r, route)
	filter.Limit = limit + 1
	var merged []*eginterfaces.DriftState
	if !scope.boundarySubject() {
		states, err := s.egProvider.ListDrifted(r.Context(), filter)
		if err != nil {
			return nil, "", err
		}
		merged = states
	} else {
		defer scope.LogSummary()
		seen := make(map[string]struct{})
		for _, cut := range s.boundaryReadCuts(r, scope) {
			f := filter
			f.TenantFilter = cut.tenant
			f.TenantSubtreeIDs = cut.ids
			states, err := s.egProvider.ListDrifted(r.Context(), f)
			if err != nil {
				return nil, "", err
			}
			for _, st := range states {
				if st == nil {
					continue
				}
				key := st.EID.String()
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				merged = append(merged, st)
			}
		}
		sort.Slice(merged, func(i, j int) bool { return merged[i].EID.String() < merged[j].EID.String() })
	}
	if len(merged) <= limit {
		if merged == nil {
			merged = []*eginterfaces.DriftState{}
		}
		return merged, "", nil
	}
	merged = merged[:limit]
	return merged, merged[limit-1].EID.String(), nil
}

// filterReadableEdges keeps the edges both of whose ends are entities the caller
// may read. An end that cannot be resolved is treated as unreadable.
func (s *Server) filterReadableEdges(ctx context.Context, scope *tenantReadScope, edges []*eginterfaces.EdgeView) ([]*eginterfaces.EdgeView, error) {
	readable := make(map[string]bool)
	allowed := func(eid egtypes.EID) (bool, error) {
		key := eid.String()
		if ok, done := readable[key]; done {
			return ok, nil
		}
		owner, found, err := s.entityOwner(ctx, eid, "", nil)
		if err != nil {
			return false, err
		}
		ok := found && scope.Allows(owner)
		readable[key] = ok
		return ok, nil
	}
	out := make([]*eginterfaces.EdgeView, 0, len(edges))
	for _, e := range edges {
		if e == nil || e.Edge == nil {
			continue
		}
		fromOK, err := allowed(e.Edge.From)
		if err != nil {
			return nil, err
		}
		toOK, err := allowed(e.Edge.To)
		if err != nil {
			return nil, err
		}
		if fromOK && toOK {
			out = append(out, e)
		}
	}
	return out, nil
}

// timelineEventEIDs returns every entity a same-as-change event names: Detail
// "from" and "to" and both endpoints of "edge_subject" (edge_type|from|to). ok is
// false when any of them is missing or does not parse, so the event is dropped.
func timelineEventEIDs(ev *eginterfaces.TimelineEvent) (eids []egtypes.EID, ok bool) {
	fromStr, _ := ev.Detail["from"].(string)
	toStr, _ := ev.Detail["to"].(string)
	subject, _ := ev.Detail["edge_subject"].(string)
	parts := strings.Split(subject, edgeSubjectDelimiter)
	if len(parts) != 3 {
		return nil, false
	}
	for _, raw := range []string{fromStr, toStr, parts[1], parts[2]} {
		eid, err := egtypes.ParseEID(raw)
		if err != nil {
			return nil, false
		}
		eids = append(eids, eid)
	}
	return eids, true
}

// filterReadableTimelineEvents drops the same-as-change events that name an entity
// the caller may not read. The event is dropped whole rather than redacted because
// edge_subject carries the peer EID. An endpoint that does not parse or has no
// entity index row is unreadable; an owner-lookup error is returned.
func (s *Server) filterReadableTimelineEvents(ctx context.Context, scope *tenantReadScope, events []*eginterfaces.TimelineEvent) ([]*eginterfaces.TimelineEvent, error) {
	readable := make(map[string]bool)
	allowed := func(eid egtypes.EID) (bool, error) {
		key := eid.String()
		if ok, done := readable[key]; done {
			return ok, nil
		}
		owner, found, err := s.entityOwner(ctx, eid, "", nil)
		if err != nil {
			return false, err
		}
		ok := found && scope.Allows(owner)
		readable[key] = ok
		return ok, nil
	}
	out := make([]*eginterfaces.TimelineEvent, 0, len(events))
	for _, ev := range events {
		if ev == nil {
			continue
		}
		if ev.Kind != "same-as-change" {
			out = append(out, ev)
			continue
		}
		eids, ok := timelineEventEIDs(ev)
		for _, eid := range eids {
			if !ok {
				break
			}
			var err error
			if ok, err = allowed(eid); err != nil {
				return nil, err
			}
		}
		if ok {
			out = append(out, ev)
		}
	}
	return out, nil
}

// filterReadableNeighborhood drops the nodes the caller may not read and every
// edge that touches a dropped node, so a client-tenant entity is never named as
// the neighbor of a visible one.
func filterReadableNeighborhood(scope *tenantReadScope, n *egtypes.Neighborhood) *egtypes.Neighborhood {
	if n == nil {
		return nil
	}
	kept := make(map[string]struct{}, len(n.Nodes))
	out := &egtypes.Neighborhood{Root: n.Root, Nodes: []*egtypes.Entity{}, Edges: []*egtypes.Edge{}, Truncated: n.Truncated}
	for _, node := range n.Nodes {
		if node == nil || !scope.Allows(node.OwningTenant) {
			continue
		}
		kept[node.EID.String()] = struct{}{}
		out.Nodes = append(out.Nodes, node)
	}
	for _, e := range n.Edges {
		if e == nil {
			continue
		}
		_, fromOK := kept[e.From.String()]
		_, toOK := kept[e.To.String()]
		if fromOK && toOK {
			out.Edges = append(out.Edges, e)
		}
	}
	return out
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
		TenantFilter:     callerTenant,
		TenantSubtreeIDs: s.tenantDescendantIDs(ctx, callerTenant),
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
	tenant, ids := s.entityCut(r)
	filter := eginterfaces.EntityFilter{
		TenantFilter:     tenant,
		TenantSubtreeIDs: ids,
		Kind:             q.Get("kind"),
		TextQuery:        q.Get("text_query"),
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

	result, err := s.queryEntitiesInReadScope(r, "GET /api/v1/entities", filter, page)
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
	tenant, ids := s.entityCut(r)
	opts := eginterfaces.GetEntityOpts{
		TenantFilter:     tenant,
		TenantSubtreeIDs: ids,
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

	const route = "GET /api/v1/entities/{eid}"
	view, err := s.egProvider.GetEntity(r.Context(), eid, opts)
	if err != nil && opts.CollapseGroup && errors.Is(err, eginterfaces.ErrCollapseGroupTooLarge) {
		// Answering 422 would reveal that a group exists, so first prove the
		// caller may read the entity itself: re-read without the group and run
		// the same authorization as a successful read.
		plain := opts
		plain.CollapseGroup = false
		entityView, perr := s.egProvider.GetEntity(r.Context(), eid, plain)
		if perr != nil || entityView == nil || entityView.Entity == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if !s.authorizeRecordRead(w, r, entityView.Entity.OwningTenant, route, func() {
			http.Error(w, "not found", http.StatusNotFound)
		}) {
			return
		}
		s.writeErrorResponse(w, http.StatusUnprocessableEntity,
			"same-as group has too many members to collapse", "COLLAPSE_GROUP_TOO_LARGE")
		return
	}
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
	if view == nil || view.Entity == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if !s.authorizeRecordRead(w, r, view.Entity.OwningTenant, route, func() {
		http.Error(w, "not found", http.StatusNotFound)
	}) {
		return
	}

	// A same-as group merged across an unrestricted cut would fold client-tenant
	// attributes into a root entity: a boundary-subject root caller gets the group
	// cut to the entity's own tenant.
	if opts.CollapseGroup && view.CollapseGroup != nil && s.tenantReadScope(r, route).boundarySubject() {
		opts.TenantFilter = view.Entity.OwningTenant
		opts.TenantSubtreeIDs = nil
		if view, err = s.egProvider.GetEntity(r.Context(), eid, opts); err != nil || view == nil {
			if errors.Is(err, eginterfaces.ErrCollapseGroupTooLarge) {
				s.writeErrorResponse(w, http.StatusUnprocessableEntity,
					"same-as group has too many members to collapse", "COLLAPSE_GROUP_TOO_LARGE")
				return
			}
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}

	writeEntityJSON(w, view)
}

// handleGetEdges handles GET /api/v1/entities/{eid:.+}/edges.
// Query params: edge_type (repeatable), source, direction (outbound|inbound),
// limit (1-MaxEdgePageSize, default DefaultEdgePageSize), page_token.
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

	const route = "GET /api/v1/entities/{eid}/edges"
	if !s.authorizeEntityRead(w, r, eid, route) {
		return
	}

	q := r.URL.Query()
	limit := eginterfaces.DefaultEdgePageSize
	if limStr := q.Get("limit"); limStr != "" {
		l, err := strconv.Atoi(limStr)
		if err != nil || l < 1 || l > eginterfaces.MaxEdgePageSize {
			http.Error(w, "limit must be an integer between 1 and 1000", http.StatusBadRequest)
			return
		}
		limit = l
	}
	tenant, ids := s.entityCut(r)
	filter := eginterfaces.EdgeFilter{
		FromEID:          &eid,
		Types:            q["edge_type"],
		Source:           q.Get("source"),
		TenantFilter:     tenant,
		TenantSubtreeIDs: ids,
		After:            q.Get("page_token"),
	}

	if q.Get("direction") == "inbound" {
		filter.FromEID = nil
		filter.ToEID = &eid
	}

	// A boundary-subject root caller's cut is unrestricted, so an edge whose other
	// end is a client entity would otherwise name it: keep only edges whose both
	// ends the caller may read.
	scope := s.tenantReadScope(r, route)
	boundary := scope.boundarySubject()
	// A boundary-subject caller's provider pages are read in batches of at least
	// DefaultEdgePageSize, so a small requested limit does not exhaust the scan
	// passes on a short run of unreadable edges.
	batch := limit
	if boundary && batch < eginterfaces.DefaultEdgePageSize {
		batch = eginterfaces.DefaultEdgePageSize
	}
	// One row more than the batch tells a full last page from one with more behind it.
	filter.Limit = batch + 1

	// The page may come out short of a full provider page, and the next-page
	// token is always the cursor of the last edge returned. The cursor spells out
	// the edge's endpoints, so a token taken from an edge the caller may not read
	// would name a client-tenant entity; for a boundary-subject caller the walk
	// therefore reads further provider pages until it has a full page of readable
	// edges (at most maxEdgeScanPasses) and never hands out a hidden edge's cursor.
	var edges []*eginterfaces.EdgeView
	nextToken := ""
	for pass := 0; pass < maxEdgeScanPasses; pass++ {
		raw, err := s.egProvider.GetEdges(r.Context(), filter)
		if errors.Is(err, eginterfaces.ErrInvalidEdgeCursor) {
			http.Error(w, "invalid page_token", http.StatusBadRequest)
			return
		}
		if err != nil {
			s.logger.Error("handleGetEdges: query failed",
				"eid", logging.SanitizeLogValue(eid.String()),
				"error", logging.SanitizeLogValue(err.Error()),
			)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		more := len(raw) > batch
		if more {
			raw = raw[:batch]
		}
		page := raw
		if boundary {
			page, err = s.filterReadableEdges(r.Context(), scope, raw)
			if err != nil {
				s.logger.Error("handleGetEdges: endpoint lookup failed",
					"eid", logging.SanitizeLogValue(eid.String()),
					"error", logging.SanitizeLogValue(err.Error()),
				)
				http.Error(w, "query failed", http.StatusInternalServerError)
				return
			}
		}
		if room := limit - len(edges); len(page) > room {
			page = page[:room]
			more = true
		}
		edges = append(edges, page...)
		if !more || len(edges) >= limit || !boundary {
			if more && len(edges) > 0 {
				nextToken = edges[len(edges)-1].Cursor
			}
			break
		}
		// Unreadable edges ended this provider page: continue after it.
		filter.After = raw[len(raw)-1].Cursor
		if pass == maxEdgeScanPasses-1 {
			if len(edges) == 0 {
				// No readable edge to anchor a token on, and the hidden edge's
				// cursor would name its endpoints: refuse rather than end the
				// listing early and silently drop the readable edges behind it.
				s.writeErrorResponse(w, http.StatusUnprocessableEntity,
					"too many unreadable edges to page past", "EDGE_SCAN_LIMIT")
				return
			}
			nextToken = edges[len(edges)-1].Cursor
		}
	}
	if boundary {
		scope.LogSummary()
	}

	if edges == nil {
		edges = []*eginterfaces.EdgeView{}
	}
	writeEntityJSON(w, edgePage{Edges: edges, NextToken: nextToken})
}

// maxEdgeScanPasses bounds the provider pages one edges request reads on behalf
// of a boundary-subject caller whose pages are partly unreadable.
const maxEdgeScanPasses = 10

// edgePage is the response of GET /api/v1/entities/{eid}/edges. NextToken is
// empty on the last page.
type edgePage struct {
	Edges     []*eginterfaces.EdgeView
	NextToken string
}

// handleGetNeighborhood handles GET /api/v1/entities/{eid:.+}/neighborhood.
// Query params: depth (1-3, default 1), direction (outbound|inbound|both), edge_type (repeatable).
// The caller's tenant is verified via GetEntity before traversal, and the traversal
// is cut at the caller's own authorized tenant scope, never the root entity's tenant.
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

	// Verify caller can access the root entity before traversing its neighborhood
	// (ADR-022 §7).
	if !s.authorizeEntityRead(w, r, eid, "GET /api/v1/entities/{eid}/neighborhood") {
		return
	}

	// The traversal cut is the caller's authorized scope. A caller with no
	// resolvable scope is refused rather than walked unrestricted.
	tenant, ids := s.entityCut(r)
	if tenant == noTenantScope {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	neighborhood, err := s.egProvider.GetNeighborhood(r.Context(), eid, q["edge_type"], direction, depth, eginterfaces.NewTenantCut(tenant, ids))
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

	// The provider cuts a traversal at the caller's tenant scope, but a
	// boundary-subject root caller (unrestricted scope) must not rely on that: drop any node it may not
	// read and every edge that touches one.
	if scope := s.tenantReadScope(r, "GET /api/v1/entities/{eid}/neighborhood"); scope.boundarySubject() {
		neighborhood = filterReadableNeighborhood(scope, neighborhood)
		scope.LogSummary()
	}

	writeEntityJSON(w, neighborhood)
}

// handleGetHistory handles GET /api/v1/entities/{eid:.+}/history.
// Query params: from, to (RFC 3339, required), limit (1-MaxHistoryPageSize,
// default DefaultHistoryPageSize), page_token (Version of the last record of the
// previous page).
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

	q := r.URL.Query()
	limit := eginterfaces.DefaultHistoryPageSize
	if limStr := q.Get("limit"); limStr != "" {
		l, err := strconv.Atoi(limStr)
		if err != nil || l < 1 || l > eginterfaces.MaxHistoryPageSize {
			http.Error(w, "limit must be an integer between 1 and 1000", http.StatusBadRequest)
			return
		}
		limit = l
	}
	if tok := q.Get("page_token"); tok != "" {
		v, err := strconv.ParseInt(tok, 10, 64)
		if err != nil || v < 1 {
			http.Error(w, "invalid page_token", http.StatusBadRequest)
			return
		}
		tr.AfterVersion = v
	}
	// One row more than the page tells a full last page from one with more behind it.
	tr.Limit = limit + 1

	// GetHistory has no tenant filter parameter — verify access via GetEntity first.
	if !s.authorizeEntityRead(w, r, eid, "GET /api/v1/entities/{eid}/history") {
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

	nextToken := ""
	if len(records) > limit {
		records = records[:limit]
		nextToken = strconv.FormatInt(records[limit-1].Version, 10)
	}
	if records == nil {
		records = []*eginterfaces.ObservationRecord{}
	}
	writeEntityJSON(w, historyPage{Records: records, NextToken: nextToken})
}

// historyPage is the response of GET /api/v1/entities/{eid}/history. NextToken is
// empty on the last page.
type historyPage struct {
	Records   []*eginterfaces.ObservationRecord
	NextToken string
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
	if !s.authorizeEntityRead(w, r, eid, "GET /api/v1/entities/{eid}/diff") {
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
// Query params: eid (repeatable, 1 to maxTimelineEIDs), from, to (RFC 3339, required).
// Each EID is verified via GetEntity first (ADR-022 §7); the cut is also passed to
// GetTimeline so same-as events whose peer is outside it are dropped.
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
	if len(eidStrs) > maxTimelineEIDs {
		http.Error(w, "too many eid query parameters", http.StatusBadRequest)
		return
	}

	const route = "GET /api/v1/entities/timeline"
	tenant, ids := s.entityCut(r)
	scope := s.tenantReadScope(r, route)
	eids := make([]eginterfaces.EIDRef, 0, len(eidStrs))
	for _, eidStr := range eidStrs {
		eid, err := egtypes.ParseEID(eidStr)
		if err != nil {
			http.Error(w, "invalid eid: must be authority_type:authority_name[/local_id]", http.StatusBadRequest)
			return
		}
		// GetTimeline has no tenant filter parameter — resolve each EID's owner.
		owner, found, accessErr := s.entityOwner(r.Context(), eid, tenant, ids)
		if accessErr != nil {
			s.logger.Error("handleGetTimeline: entity access check failed",
				"eid", logging.SanitizeLogValue(eid.String()),
				"error", logging.SanitizeLogValue(accessErr.Error()),
			)
			http.Error(w, "lookup failed", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		// A timeline is a list: a boundary-subject root caller gets the entities it
		// may read and silently loses the rest (ADR-025 A2.5), as for any bulk read.
		if scope.boundarySubject() && !scope.Allows(owner) {
			continue
		}
		eids = append(eids, eid)
	}
	scope.LogSummary()

	tr, err := parseTimeRangeQuery(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var events []*eginterfaces.TimelineEvent
	if len(eids) > 0 {
		tr.TenantFilter, tr.TenantSubtreeIDs = tenant, ids
		events, err = s.egProvider.GetTimeline(r.Context(), eids, tr)
	} else {
		events = []*eginterfaces.TimelineEvent{}
	}
	if err != nil {
		s.logger.Error("handleGetTimeline: query failed",
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	// A root caller's provider cut is unrestricted, so the providers' own peer check
	// is inactive: drop same-as events naming an entity the caller may not read.
	// This runs before the cap so dropped events never count against it.
	if scope.boundarySubject() {
		events, err = s.filterReadableTimelineEvents(r.Context(), scope, events)
		if err != nil {
			s.logger.Error("handleGetTimeline: peer access check failed",
				"error", logging.SanitizeLogValue(err.Error()),
			)
			http.Error(w, "lookup failed", http.StatusInternalServerError)
			return
		}
	}

	// The provider returns at most MaxTimelineEvents+1 events; the extra one only
	// signals that the stream was cut.
	if len(events) > eginterfaces.MaxTimelineEvents {
		events = events[len(events)-eginterfaces.MaxTimelineEvents:]
		w.Header().Set("X-Timeline-Truncated", "true")
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
	if !s.authorizeEntityRead(w, r, eid, "GET /api/v1/entities/{eid}/drift") {
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

// handleGetDesiredState handles GET /api/v1/entities/{eid:.+}/desired-state.
// GetDesiredState has no tenant filter parameter; access is verified via GetEntity first (ADR-022 §7).
func (s *Server) handleGetDesiredState(w http.ResponseWriter, r *http.Request) {
	if s.egProvider == nil {
		http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
		return
	}

	eid, err := parseEIDFromPath(r)
	if err != nil {
		http.Error(w, "invalid entity ID", http.StatusBadRequest)
		return
	}

	// GetDesiredState has no tenant filter parameter — verify access via GetEntity first.
	if !s.authorizeEntityRead(w, r, eid, "GET /api/v1/entities/{eid}/desired-state") {
		return
	}

	view, err := s.egProvider.GetDesiredState(r.Context(), eid)
	if err != nil {
		if isEntityNotFound(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.logger.Error("handleGetDesiredState: query failed",
			"eid", logging.SanitizeLogValue(eid.String()),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	if view == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	writeEntityJSON(w, view)
}

// assertEdgeRequest is the JSON body for POST /api/v1/entities/edges (Issue #3374).
type assertEdgeRequest struct {
	EdgeType   string                 `json:"edge_type"`
	FromEID    string                 `json:"from_eid"`
	ToEID      string                 `json:"to_eid"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// edgeSubjectDelimiter separates the three fields of an edge observation subject
// ("edge_type|from_eid|to_eid", ADR-022 §4). The providers recover the fields with
// a three-way split on this byte, so any component that contains it shifts the
// field boundaries and lets a caller name endpoint subjects that never passed the
// tenant check — or make the whole subject parse as an EID and land in the entity
// projection instead. Every component is rejected if it contains the delimiter.
const edgeSubjectDelimiter = "|"

// reservedObservationAttrs are the payload keys the entity-graph providers read as
// trusted ingest metadata rather than as opaque edge attributes: tenant_path is
// extracted into the observation log and current-state rows (selecting the
// retention policy and the watch tenant axis), and the remainder are extracted
// verbatim into the entity index (owning tenant, entity kind, and the identity
// keys that drive entity collapse). An operator assertion is untrusted input and
// may not set any of them.
var reservedObservationAttrs = map[string]struct{}{
	"tenant_path":     {},
	"owning_tenant":   {},
	"entity_kind":     {},
	"hostname":        {},
	"mac_addrs":       {},
	"machine_sid":     {},
	"dir_object_guid": {},
	"serial_number":   {},
	"cloud_object_id": {},
}

// validateAssertedEdgeType checks that a caller-supplied edge_type is safe to
// embed in an observation subject: it must carry no subject delimiter and must be
// a taxonomy edge kind or a related:<discriminator> open subtype (ADR-022 §2).
func validateAssertedEdgeType(edgeType string) error {
	if edgeType == "" {
		return errors.New("edge_type is required")
	}
	if len(edgeType) > maxAssertedEdgeTypeBytes {
		return errors.New("edge_type is too long")
	}
	if strings.Contains(edgeType, edgeSubjectDelimiter) {
		return errors.New("edge_type must not contain '|'")
	}
	tx := egtypes.DefaultTaxonomy()
	if _, known := tx.LookupEdgeType(edgeType); known {
		return nil
	}
	if tx.IsRelatedEscape(edgeType) {
		return nil
	}
	return errors.New("edge_type must be a known edge type or a related:<discriminator> subtype")
}

// Bounds on an operator edge assertion. They are enforced before anything is
// written so a caller cannot store an arbitrarily large attribute map up to the
// request body limit.
const (
	maxAssertedEdgeTypeBytes      = 128
	maxAssertedAttributeCount     = 32
	maxAssertedAttributeKeyBytes  = 128
	maxAssertedAttributeValueSize = 4 * 1024
	maxAssertedAttributeDepth     = 4
	maxAssertedAttributesSize     = 16 * 1024

	entityEdgeAssertedAuditAction = "entity.edge_asserted"
)

// attributeDepth returns how many map/array levels v nests (a scalar is 0).
func attributeDepth(v interface{}) int {
	deepest := 0
	switch t := v.(type) {
	case map[string]interface{}:
		for _, child := range t {
			if d := attributeDepth(child); d > deepest {
				deepest = d
			}
		}
		return deepest + 1
	case []interface{}:
		for _, child := range t {
			if d := attributeDepth(child); d > deepest {
				deepest = d
			}
		}
		return deepest + 1
	}
	return 0
}

// validateAssertedAttributes rejects operator-supplied attributes that collide
// with reservedObservationAttrs or exceed the assertion bounds. Errors never
// echo attribute keys or values.
func validateAssertedAttributes(attrs map[string]interface{}) error {
	if len(attrs) > maxAssertedAttributeCount {
		return errors.New("attributes has too many entries")
	}
	for k, v := range attrs {
		if _, reserved := reservedObservationAttrs[k]; reserved {
			return errors.New("attributes must not contain provider-reserved metadata keys")
		}
		if len(k) > maxAssertedAttributeKeyBytes {
			return errors.New("attribute key is too long")
		}
		if attributeDepth(v) > maxAssertedAttributeDepth {
			return errors.New("attribute value is nested too deeply")
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			return errors.New("attribute value is not encodable")
		}
		if len(encoded) > maxAssertedAttributeValueSize {
			return errors.New("attribute value is too large")
		}
	}
	if len(attrs) > 0 {
		encoded, err := json.Marshal(attrs)
		if err != nil {
			return errors.New("attributes are not encodable")
		}
		if len(encoded) > maxAssertedAttributesSize {
			return errors.New("attributes are too large")
		}
	}
	return nil
}

// handleAssertEdge handles POST /api/v1/entities/edges.
// Asserts a manual operator edge sourced as "operator-assertion:<caller>" — the
// operator-assertion source class of ADR-022 §4, which is what makes a manual edge
// an ordinary provenanced observation rather than a privileged side door
// (ADR-022 §9). Both endpoint EIDs are resolved against the caller's tenant
// subtree; cross-tenant or missing endpoint EIDs return 404, matching the
// read-path convention (ADR-022 §7).
func (s *Server) handleAssertEdge(w http.ResponseWriter, r *http.Request) {
	if s.egWriter == nil || s.egProvider == nil {
		http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
		return
	}

	var req assertEdgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := validateAssertedEdgeType(req.EdgeType); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateAssertedAttributes(req.Attributes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// ParseEID permits '|' inside an authority name and local ID, so the parsed
	// endpoints are re-checked against the subject delimiter before they are
	// joined into the subject.
	fromEID, err := egtypes.ParseEID(req.FromEID)
	if err != nil || strings.Contains(fromEID.String(), edgeSubjectDelimiter) {
		http.Error(w, "invalid from_eid", http.StatusBadRequest)
		return
	}
	toEID, err := egtypes.ParseEID(req.ToEID)
	if err != nil || strings.Contains(toEID.String(), edgeSubjectDelimiter) {
		http.Error(w, "invalid to_eid", http.StatusBadRequest)
		return
	}

	callerID, _ := r.Context().Value(ctxkeys.UserIDKey).(string)
	if callerID == "" {
		if p, _ := r.Context().Value(principalContextKey).(*Principal); p != nil {
			callerID = p.ID
		}
	}
	if callerID == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	// Resolve both endpoints inside the caller's tenant cut (ADR-022 §7): a
	// missing or out-of-cut endpoint is 404, and both must be found before any
	// crossing decision is made.
	callerTenant, subtreeIDs := s.entityCut(r)
	fromOwner, found, err := s.entityOwner(r.Context(), fromEID, callerTenant, subtreeIDs)
	if err != nil {
		s.logger.Error("handleAssertEdge: from_eid access check failed",
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	toOwner, found, err := s.entityOwner(r.Context(), toEID, callerTenant, subtreeIDs)
	if err != nil {
		s.logger.Error("handleAssertEdge: to_eid access check failed",
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Decide both endpoints (ADR-025 A7.2) before writing anything.
	const route = "POST /api/v1/entities/edges"
	scope := callerTenantScope(r)
	for _, owner := range []string{fromOwner, toOwner} {
		access := s.tenantAccessForScope(r.Context(), scope, owner, route)
		if access == tenantAuthAllowed {
			continue
		}
		if !s.writeTenantCrossingIfNeeded(w, access, owner) {
			http.Error(w, "not found", http.StatusNotFound)
		}
		return
	}

	// The assertion is audited before it is written: no audit, no edge.
	if err := s.auditEdgeAssertion(r, callerID, fromEID.String(), toEID.String(), req.EdgeType, fromOwner, toOwner); err != nil {
		s.logger.Error("handleAssertEdge: audit failed",
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "assertion failed", http.StatusInternalServerError)
		return
	}

	// The source class is the segment before the first ':', and it must be a
	// declared class constant: "operator" is not one, so it resolves to the
	// observer class and would store untrusted manual input at machine-observation
	// precedence. ADR-022 §4 ranks operator assertion below observer, so the
	// canonical class prefix is emitted here.
	source := string(egtypes.SourceClassOperatorAssertion) + ":" + callerID

	now := time.Now().UTC()
	payload := make(map[string]interface{}, len(req.Attributes))
	for k, v := range req.Attributes {
		payload[k] = v
	}

	// Edge subject format: "edge_type|from_eid|to_eid" (ADR-022 §4). All three
	// components are delimiter-free by the validation above.
	subject := req.EdgeType + edgeSubjectDelimiter + fromEID.String() + edgeSubjectDelimiter + toEID.String()

	batch := eginterfaces.ObservationBatch{
		Source: source,
		Observations: []egtypes.Observation{
			{
				Source:     source,
				ObservedAt: now,
				RecordedAt: now,
				Subject:    subject,
				Kind:       egtypes.ObservationKindState,
				Confidence: egtypes.ConfidenceHigh,
				Payload:    payload,
			},
		},
	}

	if err := s.egWriter.ReportObservations(r.Context(), batch); err != nil {
		s.logger.Error("handleAssertEdge: report failed",
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "assertion failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// auditEdgeAssertion records an accepted edge assertion in the audit scope of
// each endpoint's owning tenant, and in the caller's own tenant when the
// assertion reaches another tenant's entity (a crossing). It names the principal,
// both endpoints and the edge type, never the attribute values.
func (s *Server) auditEdgeAssertion(r *http.Request, callerID, fromEID, toEID, edgeType, fromOwner, toOwner string) error {
	if s.auditManager == nil {
		return errors.New("audit manager unavailable")
	}
	tenants := make([]string, 0, 3)
	seen := map[string]struct{}{}
	add := func(t string) {
		if t == "" {
			return
		}
		if _, dup := seen[t]; dup {
			return
		}
		seen[t] = struct{}{}
		tenants = append(tenants, t)
	}
	add(fromOwner)
	add(toOwner)
	if own, ok := callerOwnTenant(r.Context()); ok {
		for _, t := range tenants {
			if t != own {
				add(own)
				break
			}
		}
	}
	if len(tenants) == 0 {
		return errors.New("no tenant to audit the assertion under")
	}
	for _, t := range tenants {
		b := audit.NewEventBuilder().
			Tenant(t).
			Type(business.AuditEventDataModification).
			Action(entityEdgeAssertedAuditAction).
			User(callerID, business.AuditUserTypeHuman).
			Resource("entity_edge", fromEID, "").
			Result(business.AuditResultSuccess).
			Severity(business.AuditSeverityMedium).
			Details(map[string]interface{}{
				"principal": callerID,
				"from_eid":  fromEID,
				"to_eid":    toEID,
				"edge_type": edgeType,
			})
		if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
			return err
		}
	}
	return nil
}

// handleListDrifted handles GET /api/v1/entities/drifted.
// Query params: lifecycle_status (detected|acknowledged|resolved|ignored), kind,
// limit (1-MaxDriftPageSize, default DefaultDriftPageSize), page_token.
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

	limit := eginterfaces.DefaultDriftPageSize
	if limStr := q.Get("limit"); limStr != "" {
		l, err := strconv.Atoi(limStr)
		if err != nil || l < 1 || l > eginterfaces.MaxDriftPageSize {
			http.Error(w, "limit must be an integer between 1 and 1000", http.StatusBadRequest)
			return
		}
		limit = l
	}
	after := q.Get("page_token")
	if after != "" {
		if _, err := egtypes.ParseEID(after); err != nil {
			http.Error(w, "invalid page_token", http.StatusBadRequest)
			return
		}
	}

	tenant, ids := s.entityCut(r)
	filter := eginterfaces.DriftFilter{
		TenantFilter:     tenant,
		TenantSubtreeIDs: ids,
		LifecycleStatus:  lifecycleStatus,
		Kind:             q.Get("kind"),
		After:            after,
	}

	states, nextToken, err := s.listDriftedInReadScope(r, "GET /api/v1/entities/drifted", filter, limit)
	if err != nil {
		s.logger.Error("handleListDrifted: query failed",
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	writeEntityJSON(w, driftPage{Drifted: states, NextToken: nextToken})
}

// driftPage is the response of GET /api/v1/entities/drifted. NextToken is empty
// on the last page.
type driftPage struct {
	Drifted   []*eginterfaces.DriftState
	NextToken string
}
