// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// noTenantScope is what callerTenantFilter returns for a context that carries
// no usable tenant scope. It is not a valid tenant ID, so it matches no tenant
// and reaches no data — the caller fails closed instead of being read as
// unrestricted.
const noTenantScope = "!no-tenant-scope"

// callerTenantFilter is the caller's tenant restriction for scoping reads and
// tenant checks (Issue #4665): "" — no tenant restriction — only for an
// explicitly root-scoped caller (ctxkeys.TenantRestriction), the caller's own
// tenant for a tenant-scoped caller, and noTenantScope for anything else.
//
// "" here therefore always means an explicit root caller, never a missing
// tenant: the authentication middleware binds a root principal to the
// deployment's root tenant (ctxkeys.TenantID) and refuses any principal that is
// neither root nor bound to a tenant. Code that needs the root caller's own
// tenant — to store something under it — reads ctxkeys.TenantID instead.
func callerTenantFilter(ctx context.Context) string {
	tenant, unrestricted, ok := ctxkeys.TenantRestriction(ctx)
	switch {
	case !ok:
		return noTenantScope
	case unrestricted:
		return ""
	default:
		return tenant
	}
}

// tenantCrossingRequiredError is returned by a lookup that found a record the
// caller may reach only through an ADR-025 tenant crossing, so the handler can
// answer with the crossing challenge (writeTenantCrossingChallenge) rather than
// a not-found.
type tenantCrossingRequiredError struct {
	tenant string
}

func (e *tenantCrossingRequiredError) Error() string {
	return "tenant crossing required"
}

// callerOwnTenant is the tenant the caller authenticated into (ctxkeys.TenantID):
// its own tenant for a tenant-scoped caller and the deployment's root tenant for a
// root caller (Issue #4665). ok is false when the context carries none, which a
// caller refuses rather than substituting a tenant the caller never named
// (Issue #4543).
func callerOwnTenant(ctx context.Context) (string, bool) {
	tenant, _ := ctx.Value(ctxkeys.TenantID).(string)
	return tenant, tenant != ""
}

// selectListTenant resolves the tenant a tenant-keyed listing reads: the caller's
// own tenant, or one it names with ?tenant_id. A named tenant must pass
// tenantAccessForScope — a tenant-scoped caller stays inside its subtree, and a
// root caller subject to the ADR-025 boundary needs a crossing for a tenant below
// root — and must exist; the stored tenant ID is returned, never the raw query
// value. It writes the refusal and returns false otherwise.
func (s *Server) selectListTenant(w http.ResponseWriter, r *http.Request, route string) (string, bool) {
	own, ok := callerOwnTenant(r.Context())
	if !ok {
		s.writeErrorResponse(w, http.StatusForbidden, "No tenant scope", "NO_TENANT_SCOPE")
		return "", false
	}
	requested := r.URL.Query().Get("tenant_id")
	if requested == "" || requested == own {
		return own, true
	}
	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if access := s.tenantAccessForScope(r.Context(), scope, requested, route); access != tenantAuthAllowed {
		if !s.writeTenantCrossingIfNeeded(w, access, requested) {
			s.writeErrorResponse(w, http.StatusForbidden,
				"tenant_id filter must be within the authenticated tenant scope", "TENANT_MISMATCH")
		}
		return "", false
	}
	if s.tenantManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Tenant management not available", "SERVICE_UNAVAILABLE")
		return "", false
	}
	stored, err := s.tenantManager.GetTenant(r.Context(), requested)
	if err != nil || stored == nil || stored.ID == "" {
		s.writeErrorResponse(w, http.StatusNotFound, "Tenant not found", "TENANT_NOT_FOUND")
		return "", false
	}
	return stored.ID, true
}

// authorizeFleetTargets applies tenantAccessForScope to the tenant of every
// steward an action would reach — a batch job, an upgrade, a signed operator
// payload — so a root caller subject to the ADR-025 boundary cannot act on a
// client tenant's stewards through a fleet selector without a crossing (Issue
// #4665). On refusal it writes the crossing challenge, or 404 for a tenant the
// caller may not reach at all, and returns false.
func (s *Server) authorizeFleetTargets(w http.ResponseWriter, r *http.Request, targets []fleet.StewardResult, route string) bool {
	scope := callerTenantScope(r)
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		if seen[target.TenantID] {
			continue
		}
		seen[target.TenantID] = true
		if access := s.tenantAccessForScope(r.Context(), scope, target.TenantID, route); access != tenantAuthAllowed {
			if !s.writeTenantCrossingIfNeeded(w, access, target.TenantID) {
				s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			}
			return false
		}
	}
	return true
}

// tenantAccessFilter returns a predicate reporting whether the caller may act on
// a record in a given tenant, for bulk operations that act on many records at
// once (Issue #4665). A bulk request has no single resource to attach a crossing
// challenge to, so it skips records the caller may not act on rather than
// refusing the whole request — the same reading ADR-025 A2.5 gives bulk lists.
// Decisions are memoized per tenant for the life of the request.
func (s *Server) tenantAccessFilter(r *http.Request, route string) func(tenant string) bool {
	scope := callerTenantScope(r)
	decided := make(map[string]bool)
	return func(tenant string) bool {
		allowed, ok := decided[tenant]
		if !ok {
			allowed = s.tenantAccessForScope(r.Context(), scope, tenant, route) == tenantAuthAllowed
			decided[tenant] = allowed
		}
		return allowed
	}
}

// tenantAccessFunc is the signature of Server.tenantAccessForScope, injected into
// handlers that are not *Server so they make the same tenant decision.
type tenantAccessFunc func(ctx context.Context, scope ctxkeys.TenantScope, resourceTenant, route string) tenantAuthDecision

// auditActionCrossingGrantUsed is the audit action written when a root read is
// admitted only by an MSP's grant, so the MSP can see which root person used it.
const auditActionCrossingGrantUsed = "tenant.crossing_grant_used"

// tenantReadScope is the per-request read decision for a list filter or a by-ID
// read. It gives the answer tenantAccessForScope gives for every tenant, but
// loads the active crossings once per request and resolves each asked-about
// tenant's ancestry once, so deciding thousands of rows costs a handful of store
// calls and logs no per-tenant line. It is built per request and never kept: a
// crossing change takes effect on the next request.
type tenantReadScope struct {
	s     *Server
	r     *http.Request
	route string
	scope ctxkeys.TenantScope

	// principal is set only for a root caller subject to the ADR-025 boundary.
	principal *Principal

	mu          sync.Mutex
	decided     map[string]tenantAuthDecision
	skipped     int
	loaded      bool
	crossings   []*business.TenantCrossing // active crossings that admit the principal
	byTenant    map[string]*business.TenantCrossing
	summarized  bool
	rootTenant  string
	rootChecked bool
}

// tenantReadScope builds the read decision for r. See tenantReadScope.
func (s *Server) tenantReadScope(r *http.Request, route string) *tenantReadScope {
	ts := &tenantReadScope{
		s:       s,
		r:       r,
		route:   route,
		scope:   callerTenantScope(r),
		decided: make(map[string]tenantAuthDecision),
	}
	if ts.scope.IsRoot() { //architecture:allow-root-scope -- selects the boundary-subject path; the crossing is decided in decideRootLocked
		principal, _ := r.Context().Value(principalContextKey).(*Principal)
		if subjectToTenantCrossingBoundary(principal) {
			ts.principal = principal
		}
	}
	return ts
}

// boundarySubject reports whether the caller is a root caller subject to the
// ADR-025 crossing boundary.
func (t *tenantReadScope) boundarySubject() bool { return t.principal != nil }

// Allows reports whether the caller may read a record owned by tenantID.
func (t *tenantReadScope) Allows(tenantID string) bool {
	return t.decide(tenantID) == tenantAuthAllowed
}

// RootTenantOnly reports whether the caller is a boundary-subject root caller
// with no crossing, so only root's own records are readable.
func (t *tenantReadScope) RootTenantOnly() bool {
	if !t.boundarySubject() {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.loadCrossingsLocked()
	return len(t.crossings) == 0
}

// CrossingTenants returns the tenant IDs of the active crossings that admit the
// caller, sorted and de-duplicated; empty for a caller that is not subject to the
// boundary or holds no crossing.
func (t *tenantReadScope) CrossingTenants() []string {
	if !t.boundarySubject() {
		return []string{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.loadCrossingsLocked()
	seen := make(map[string]struct{}, len(t.crossings))
	out := make([]string, 0, len(t.crossings))
	for _, c := range t.crossings {
		if _, dup := seen[c.TenantID]; dup {
			continue
		}
		seen[c.TenantID] = struct{}{}
		out = append(out, c.TenantID)
	}
	sort.Strings(out)
	return out
}

// LogSummary writes the one DEBUG line per request naming the route and how many
// tenants were skipped. List handlers call it once when they finish filtering.
func (t *tenantReadScope) LogSummary() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.summarized || t.skipped == 0 {
		return
	}
	t.summarized = true
	t.s.logger.Debug("Tenant read scope skipped tenants",
		"route", logging.SanitizeLogValue(t.route),
		"tenants_skipped", t.skipped)
}

// decide is tenantAccessForScope's decision for the tenant, memoized per tenant.
func (t *tenantReadScope) decide(tenantID string) tenantAuthDecision {
	t.mu.Lock()
	defer t.mu.Unlock()
	if d, ok := t.decided[tenantID]; ok {
		return d
	}
	d := t.decideLocked(tenantID)
	t.decided[tenantID] = d
	if d != tenantAuthAllowed {
		t.skipped++
	}
	return d
}

func (t *tenantReadScope) decideLocked(tenantID string) tenantAuthDecision {
	ctx := t.r.Context()
	switch {
	case t.scope.IsRoot(): //architecture:allow-root-scope -- read mirror of tenantAccessForScope: boundary-subject callers need a crossing, others keep root breadth
		if !t.boundarySubject() {
			return tenantAuthAllowed
		}
		return t.decideRootLocked(ctx, tenantID)
	case t.scope.IsTenant() && t.scope.Path() != "":
		if t.s.tenantSubtreeContains(ctx, t.scope.Path(), tenantID) {
			return tenantAuthAllowed
		}
		return tenantAuthDenied
	default:
		return tenantAuthDenied
	}
}

func (t *tenantReadScope) decideRootLocked(ctx context.Context, tenantID string) tenantAuthDecision {
	s := t.s
	if !t.rootChecked {
		t.rootTenant = s.rootTenantID(ctx)
		t.rootChecked = true
	}
	if tenantID == "" || (t.rootTenant != "" && tenantID == t.rootTenant) {
		return tenantAuthAllowed
	}
	if s.tenantManager == nil {
		return tenantAuthNeedsCrossing
	}
	if t.rootTenant == "" {
		return tenantAuthDenied
	}
	path, err := s.tenantManager.GetTenantPath(ctx, tenantID)
	if err != nil || len(path) == 0 || path[0] != t.rootTenant {
		return tenantAuthDenied
	}
	t.loadCrossingsLocked()
	var grant *business.TenantCrossing
	for _, id := range path {
		if id == t.rootTenant {
			continue
		}
		c, ok := t.byTenant[id]
		if !ok {
			continue
		}
		if c.Kind != business.TenantCrossingKindGrant {
			return tenantAuthAllowed
		}
		if grant == nil {
			grant = c
		}
	}
	if grant == nil {
		return tenantAuthNeedsCrossing
	}
	t.auditGrantUseLocked(grant)
	return tenantAuthAllowed
}

// loadCrossingsLocked fetches the active crossings that admit the principal once
// per request: its own break-glass records and every grant, because a grant names
// no person. Any store failure leaves no crossings, so reads fail closed.
func (t *tenantReadScope) loadCrossingsLocked() {
	if t.loaded {
		return
	}
	t.loaded = true
	t.byTenant = make(map[string]*business.TenantCrossing)
	if t.principal == nil || t.s.tenantCrossingStore == nil {
		return
	}
	ctx := t.r.Context()
	active, err := t.s.tenantCrossingStore.ListActiveTenantCrossings(ctx, time.Now().UTC())
	if err != nil {
		t.s.logger.Error("Tenant crossing lookup failed; denying crossing reads",
			"route", logging.SanitizeLogValue(t.route),
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	for _, c := range active {
		if c == nil || c.ApprovalState == business.TenantCrossingApprovalPending || t.s.isRootTenantForCrossing(ctx, c.TenantID) {
			continue
		}
		switch c.Kind {
		case business.TenantCrossingKindGrant:
		case business.TenantCrossingKindBreakGlass:
			if c.PrincipalID != t.principal.ID {
				continue
			}
		default:
			continue
		}
		t.crossings = append(t.crossings, c)
		// A break-glass record is the stronger, personal reason: keep it over a grant
		// on the same tenant so the read is not reported as grant use.
		if prev, ok := t.byTenant[c.TenantID]; !ok || prev.Kind == business.TenantCrossingKindGrant {
			t.byTenant[c.TenantID] = c
		}
	}
}

// auditGrantUseLocked writes one tenant.crossing_grant_used entry per principal
// and grant per controller process, under the granting tenant so the MSP sees it.
// The memo is a dedup hint only: after a restart a repeat entry is acceptable.
func (t *tenantReadScope) auditGrantUseLocked(grant *business.TenantCrossing) {
	key := t.principal.ID + "|" + grant.ID
	if _, seen := t.s.crossingGrantUseSeen.LoadOrStore(key, struct{}{}); seen {
		return
	}
	t.s.recordTenantCrossingAudit(t.r, grant.TenantID, t.principal.ID, grant,
		business.AuditSeverityMedium, auditActionCrossingGrantUsed,
		"root principal read client data under a tenant access grant")
}

// authorizeRecordRead decides a by-ID read of a record owned by recordTenant.
// Allowed returns true. A boundary-subject root caller with no crossing gets the
// crossing challenge; every other refusal calls notFound so the handler keeps its
// own 404 shape and error code.
func (s *Server) authorizeRecordRead(w http.ResponseWriter, r *http.Request, recordTenant, route string, notFound func()) bool {
	scope := s.tenantReadScope(r, route)
	switch scope.decide(recordTenant) {
	case tenantAuthAllowed:
		return true
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, recordTenant)
	default:
		notFound()
	}
	return false
}
