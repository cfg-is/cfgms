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
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
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
	GetNeighborhood(ctx context.Context, eid eginterfaces.EIDRef, edgeTypes []string, direction egtypes.TraversalDirection, depth int) (*egtypes.Neighborhood, error)
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

// listDriftedInReadScope runs ListDrifted. Drift rows carry no owning tenant, so a
// boundary-subject root caller is served by asking the provider once for the root
// tenant on its own and once per crossing-covered tenant, and merging the results.
func (s *Server) listDriftedInReadScope(r *http.Request, route string, filter eginterfaces.DriftFilter) ([]*eginterfaces.DriftState, error) {
	scope := s.tenantReadScope(r, route)
	if !scope.boundarySubject() {
		return s.egProvider.ListDrifted(r.Context(), filter)
	}
	defer scope.LogSummary()
	merged := []*eginterfaces.DriftState{}
	seen := make(map[string]struct{})
	for _, cut := range s.boundaryReadCuts(r, scope) {
		f := filter
		f.TenantFilter = cut.tenant
		f.TenantSubtreeIDs = cut.ids
		states, err := s.egProvider.ListDrifted(r.Context(), f)
		if err != nil {
			return nil, err
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
	return merged, nil
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

// filterReadableNeighborhood drops the nodes the caller may not read and every
// edge that touches a dropped node, so a client-tenant entity is never named as
// the neighbor of a visible one.
func filterReadableNeighborhood(scope *tenantReadScope, n *egtypes.Neighborhood) *egtypes.Neighborhood {
	if n == nil {
		return nil
	}
	kept := make(map[string]struct{}, len(n.Nodes))
	out := &egtypes.Neighborhood{Root: n.Root, Nodes: []*egtypes.Entity{}, Edges: []*egtypes.Edge{}}
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
	if view == nil || view.Entity == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	const route = "GET /api/v1/entities/{eid}"
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
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
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

	const route = "GET /api/v1/entities/{eid}/edges"
	if !s.authorizeEntityRead(w, r, eid, route) {
		return
	}

	q := r.URL.Query()
	tenant, ids := s.entityCut(r)
	filter := eginterfaces.EdgeFilter{
		FromEID:          &eid,
		Types:            q["edge_type"],
		Source:           q.Get("source"),
		TenantFilter:     tenant,
		TenantSubtreeIDs: ids,
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

	// A boundary-subject root caller's cut is unrestricted, so an edge whose other
	// end is a client entity would otherwise name it: keep only edges whose both
	// ends the caller may read.
	if scope := s.tenantReadScope(r, route); scope.boundarySubject() {
		edges, err = s.filterReadableEdges(r.Context(), scope, edges)
		if err != nil {
			s.logger.Error("handleGetEdges: endpoint lookup failed",
				"eid", logging.SanitizeLogValue(eid.String()),
				"error", logging.SanitizeLogValue(err.Error()),
			)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		scope.LogSummary()
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
	if !s.authorizeEntityRead(w, r, eid, "GET /api/v1/entities/{eid}/neighborhood") {
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

	// The provider cuts a traversal at the root entity's own tenant, but a
	// boundary-subject root caller must not rely on that: drop any node it may not
	// read and every edge that touches one.
	if scope := s.tenantReadScope(r, "GET /api/v1/entities/{eid}/neighborhood"); scope.boundarySubject() {
		neighborhood = filterReadableNeighborhood(scope, neighborhood)
		scope.LogSummary()
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

// validateAssertedAttributes rejects operator-supplied attributes that collide
// with reservedObservationAttrs.
func validateAssertedAttributes(attrs map[string]interface{}) error {
	for k := range attrs {
		if _, reserved := reservedObservationAttrs[k]; reserved {
			return errors.New("attributes must not contain provider-reserved metadata keys")
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

	callerTenant := callerTenantSubtree(r)

	// Verify from_eid is within the caller's tenant subtree (ADR-022 §7).
	ok, accessErr := s.verifyEntityAccess(r.Context(), fromEID, callerTenant)
	if accessErr != nil {
		s.logger.Error("handleAssertEdge: from_eid access check failed",
			"error", logging.SanitizeLogValue(accessErr.Error()),
		)
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Verify to_eid is within the caller's tenant subtree (ADR-022 §7).
	ok, accessErr = s.verifyEntityAccess(r.Context(), toEID, callerTenant)
	if accessErr != nil {
		s.logger.Error("handleAssertEdge: to_eid access check failed",
			"error", logging.SanitizeLogValue(accessErr.Error()),
		)
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	callerID, _ := r.Context().Value(ctxkeys.UserIDKey).(string)
	if callerID == "" {
		callerID = "unknown"
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

	tenant, ids := s.entityCut(r)
	filter := eginterfaces.DriftFilter{
		TenantFilter:     tenant,
		TenantSubtreeIDs: ids,
		LifecycleStatus:  lifecycleStatus,
		Kind:             q.Get("kind"),
	}

	states, err := s.listDriftedInReadScope(r, "GET /api/v1/entities/drifted", filter)
	if err != nil {
		s.logger.Error("handleListDrifted: query failed",
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	writeEntityJSON(w, states)
}
