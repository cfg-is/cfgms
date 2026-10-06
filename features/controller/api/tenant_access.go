// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
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
