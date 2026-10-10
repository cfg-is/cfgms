// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// isRootTenantForCrossing reports whether tenantID is the deployment root, which
// must never carry a crossing: one there would sit on every descendant's ancestry
// path and act as a fleet-wide key (Issue #4542).
func (s *Server) isRootTenantForCrossing(ctx context.Context, tenantID string) bool {
	root := s.rootTenantID(ctx)
	return root != "" && tenantID == root
}

// rootTenantID returns the deployment's root tenant (ADR-025 Decision 1's
// "root"): the single tenant with no parent, resolved by the tenant manager
// (Issue #4542). "" means no root — no tenants, several parentless tenants, or
// no tenant manager — which callers treat as fail-closed.
func (s *Server) rootTenantID(ctx context.Context) string {
	if s.tenantManager == nil {
		return ""
	}
	return s.tenantManager.RootTenantID(ctx)
}

// authorizeSelectedTenant applies ADR-025's tenant-crossing boundary to a tenant
// the caller selected in the request (query parameter, body field or a stored
// record's tenant) rather than through a tenant path variable the boundary
// middleware sees (Issue #4571). For a caller subject to the boundary (a
// root-scoped principal) the tenant must be the root tenant itself or one covered
// by an active crossing: otherwise the crossing challenge is written when a
// crossing would admit it, 404 when not, and false returned. The decision is
// evaluated and audited through authorizeTenantAccess. Other callers, and an
// empty tenant (handlers reject or scope that themselves), pass unchanged.
func (s *Server) authorizeSelectedTenant(w http.ResponseWriter, r *http.Request, tenantID string) bool {
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if tenantID == "" || !subjectToTenantCrossingBoundary(principal) {
		return true
	}
	if s.tenantManager == nil {
		s.writeTenantCrossingChallenge(w, tenantID)
		return false
	}
	switch s.authorizeTenantAccess(r.Context(), principal, tenantID) {
	case tenantAuthAllowed:
		return true
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, tenantID)
	default:
		s.writeErrorResponse(w, http.StatusNotFound, "Tenant not found", "TENANT_NOT_FOUND")
	}
	return false
}

// selectAuthorizedTenant applies authorizeSelectedTenant to a tenant the caller
// selected and returns that tenant's stored ID (Issue #4576). Handlers carry the
// stored ID onward — into storage keys, execution contexts and logs — never the
// raw request value: for an existing tenant it is the same string, and a tenant
// that does not exist is a 404 even for a caller the crossing boundary does not
// apply to. It writes the response and returns false when the tenant is refused.
func (s *Server) selectAuthorizedTenant(w http.ResponseWriter, r *http.Request, tenantID string) (string, bool) {
	if !s.authorizeSelectedTenant(w, r, tenantID) {
		return "", false
	}
	if s.tenantManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Tenant management not available", "SERVICE_UNAVAILABLE")
		return "", false
	}
	stored, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil || stored == nil || stored.ID == "" {
		s.writeErrorResponse(w, http.StatusNotFound, "Tenant not found", "TENANT_NOT_FOUND")
		return "", false
	}
	return stored.ID, true
}

// tenantAuthDecision explains why authorizeTenantAccess denied a caller, so handlers
// can choose the right HTTP response: tenantAuthDenied means 404 (prevents existence
// disclosure for an ordinary out-of-subtree tenant); tenantAuthNeedsCrossing means a
// step-up-shaped challenge (ADR-025 Decision 3) — the caller is root-scoped and merely
// lacks an active crossing, so a bare 404 would hide a real remedy from a legitimate
// break-glass invocation.
type tenantAuthDecision int

const (
	tenantAuthAllowed tenantAuthDecision = iota
	tenantAuthDenied
	tenantAuthNeedsCrossing
)

// subjectToTenantCrossingBoundary reports whether principal is subject to ADR-025
// Decision 1's root<->MSP crossing boundary at all — the question authorizeTenantAccess,
// requirePermission's boundary gate, tenantScopedTerminalWrapper, and
// handleUpdateStewardConfig all ask before deciding allow/deny/needs-crossing.
//
// Issue #4337 (ADR-025 Amendment 5): for a principal resolved from a durable account
// record (principal.AccountBound), the answer is principal.GlobalScope — which for a
// bound principal is always acct.RootScope (middleware.go:389, :901/:917, :1067/:1079),
// a durable per-account field independent of the current request's assurance. This
// replaces principal.RootScoped for bound principals because RootScoped's session-path
// derivation (rootScopeFromAssertion) requires the CURRENT request to be phishing-resistant
// and goes false the moment it is not, even though the account's RootScope has not
// changed — silently exempting a legitimate, still-root-scoped caller from the boundary
// (and from the crossing audit record) exactly when their proof of identity is weakest.
//
// For a principal that is NOT AccountBound (the mTLS bootstrap fallback with no bound
// account, or a Bearer session with no resolvable account — middleware.go:425, :859),
// GlobalScope carries no account-level root-scope signal at all: it is unconditionally
// true for the former and merely mirrors sess.TenantID == "" for the latter — the exact
// ambiguity ADR-025 Amendment 1 A1.3 introduced RootScoped to resolve. Collapsing that
// case onto GlobalScope too would pull every legacy unscoped admin cert into the crossing
// boundary, which authorizeTenantAccess's cert-authenticated branch below documents as
// provably unchanged. So an unbound principal is still judged on RootScoped alone.
func subjectToTenantCrossingBoundary(principal *Principal) bool {
	if principal == nil {
		return false
	}
	if principal.AccountBound {
		return principal.GlobalScope
	}
	return principal.RootScoped
}

// authorizeTenantAccess decides whether principal may act on resourceTenant.
//
//   - An unscoped, certificate-authenticated principal (TenantID == "", CertSerial != "")
//     that is not subjectToTenantCrossingBoundary has unrestricted access — today's exact
//     behavior, unchanged for every admin cert issued before the ADR-025 Amendment 1 A1.3
//     root-scope marker existed, and for the 31 pre-existing callerTenant=="" branches
//     elsewhere in this package (none of which call this function). The certificate
//     authentication path is out of scope for ADR-025 Amendment 4 and must be provably
//     unchanged by it.
//   - An unscoped, NON-certificate-authenticated principal (session, API key, or any
//     future auth path) that is not subjectToTenantCrossingBoundary is denied (ADR-025
//     Amendment 4 A4.2): the absence of the explicit marker must not be read as
//     unrestricted access for a caller that never went through certificate authentication.
//   - A tenant-scoped principal must have resourceTenant equal to or a genuine
//     ParentID-chain descendant of its own TenantID (ADR-025 Amendment 1 A1.2) — never
//     a string-prefix match against tenant IDs. Real tenant IDs are flat, validated
//     single DNS-label-style tokens (features/tenant/manager.go's k8sNameRegex) and
//     can never contain '/': the prefix-match shape the older isWithinTenantScope
//     helper (middleware.go) uses is dead code against them.
//   - A principal subjectToTenantCrossingBoundary (ADR-025 Amendment 1 A1.3 / Amendment 5)
//     is confined to "root" itself; a strict descendant requires an active grant or
//     break-glass crossing (ADR-025 Decision 1, Decision 2), else tenantAuthNeedsCrossing —
//     evaluated, and audited, on every such request regardless of the caller's current
//     assurance level (Issue #4337).
func (s *Server) authorizeTenantAccess(ctx context.Context, principal *Principal, resourceTenant string) tenantAuthDecision {
	var callerTenant, principalID string
	var certAuthenticated bool
	rootScoped := subjectToTenantCrossingBoundary(principal)
	if principal != nil {
		callerTenant = principal.TenantID
		principalID = principal.ID
		// CertSerial is set in exactly two places, both inside extractAdminPrincipal
		// (middleware.go), both after its revocation check and only when the
		// certificate itself authenticated the request — see
		// TestCertSerial_OnlySetByExtractAdminPrincipal. A session, API-key, or relay
		// principal never has it set.
		certAuthenticated = principal.CertSerial != ""
	}

	// A root principal is recognised by its explicit GlobalScope flag; its
	// TenantID is the deployment's root tenant, never "" (Issue #4665).
	if principal != nil && principal.GlobalScope {
		if !rootScoped {
			if certAuthenticated {
				return tenantAuthAllowed
			}
			// ADR-025 Amendment 4 A4.2: an unmarked, non-certificate root caller
			// must fail closed rather than resolve to unrestricted access purely by
			// omission of the marker.
			return tenantAuthDenied
		}
		return s.authorizeRootScopedTenantAccess(ctx, principalID, resourceTenant)
	}
	if callerTenant == "" {
		// Neither root nor bound to a tenant: no scope at all (Issue #4665).
		return tenantAuthDenied
	}

	isAncestor, err := s.tenantManager.IsTenantAncestor(ctx, callerTenant, resourceTenant)
	if err != nil {
		// Fail closed: a broken ancestry lookup (e.g. a dangling ParentID) must not
		// silently grant cross-tenant access.
		s.logger.Error("Tenant ancestry check failed",
			"caller_tenant", logging.SanitizeLogValue(callerTenant),
			"resource_tenant", logging.SanitizeLogValue(resourceTenant),
			"error", logging.SanitizeLogValue(err.Error()))
		return tenantAuthDenied
	}
	if isAncestor {
		return tenantAuthAllowed
	}
	return tenantAuthDenied
}

// authorizeRootScopedTenantAccess applies ADR-025 Decision 1's root<->MSP boundary.
// Only reachable for a RootScoped principal — an unscoped non-root-scoped principal
// returns tenantAuthAllowed unconditionally in authorizeTenantAccess above and never
// reaches here.
func (s *Server) authorizeRootScopedTenantAccess(ctx context.Context, principalID, resourceTenant string) tenantAuthDecision {
	rootTenantID := s.rootTenantID(ctx)
	if resourceTenant == "" || (rootTenantID != "" && resourceTenant == rootTenantID) {
		return tenantAuthAllowed
	}
	if rootTenantID == "" {
		// Ambiguous tree: no tenant is root, so nothing is in root's subtree.
		return tenantAuthDenied
	}
	isUnderRoot, err := s.tenantManager.IsTenantAncestor(ctx, rootTenantID, resourceTenant)
	if err != nil {
		s.logger.Error("Tenant ancestry check failed",
			"caller_tenant", logging.SanitizeLogValue(rootTenantID),
			"resource_tenant", logging.SanitizeLogValue(resourceTenant),
			"error", logging.SanitizeLogValue(err.Error()))
		return tenantAuthDenied
	}
	if !isUnderRoot {
		// Not part of the "root" subtree at all — an ordinary out-of-scope resource,
		// not a boundary-crossing case, so no challenge/remedy applies.
		return tenantAuthDenied
	}
	if s.tenantCrossingStore == nil {
		// No crossing mechanism wired: fail closed exactly as if no crossing were
		// ever active. Still surfaced as a challenge, not a 404 — the tenant is real
		// and inside "root"'s own subtree, so there is no existence to hide from a
		// root-scoped caller.
		return tenantAuthNeedsCrossing
	}
	active, err := s.hasActiveTenantCrossing(ctx, principalID, resourceTenant)
	if err != nil {
		s.logger.Error("Tenant crossing check failed",
			"principal_id", logging.SanitizeLogValue(principalID),
			"resource_tenant", logging.SanitizeLogValue(resourceTenant),
			"error", logging.SanitizeLogValue(err.Error()))
		return tenantAuthNeedsCrossing
	}
	if active {
		return tenantAuthAllowed
	}
	return tenantAuthNeedsCrossing
}

// hasActiveTenantCrossing reports whether principalID currently holds an active grant
// or break-glass crossing (ADR-025 Decision 2) covering resourceTenant — either
// directly, or via an ancestor in resourceTenant's ParentID chain, so a crossing
// granted on an MSP tenant covers that MSP and all of its descendants.
//
// "root" is excluded from that inheritance: GetTenantPath always begins at the tree
// root, so a single crossing recorded there would cover every MSP at once — a
// fleet-wide skeleton key rather than the per-MSP, consent-or-justification crossing
// ADR-025 Decision 2 describes. Root is the operator's own scope, not an MSP subtree
// that can consent on its descendants' behalf (Decision 1).
func (s *Server) hasActiveTenantCrossing(ctx context.Context, principalID, resourceTenant string) (bool, error) {
	path, err := s.tenantManager.GetTenantPath(ctx, resourceTenant)
	if err != nil {
		return false, err
	}
	for _, tenantID := range path {
		// Grant and break-glass creation both refuse "root" outright
		// (handlers_tenant_crossing.go); this second gate keeps any row written by an
		// earlier build, or directly into the store, inert as well.
		if s.isRootTenantForCrossing(ctx, tenantID) {
			continue
		}
		active, err := s.tenantCrossingStore.HasActiveTenantCrossing(ctx, principalID, tenantID)
		if err != nil {
			return false, err
		}
		if active {
			return true, nil
		}
	}
	return false, nil
}

// isCallerAuthorizedForTenant is the boolean form of authorizeTenantAccess, for
// call sites (handleListTenants' per-item filter) that only need a yes/no answer and
// have no single resource to attach a step-up challenge to.
func (s *Server) isCallerAuthorizedForTenant(ctx context.Context, principal *Principal, resourceTenant string) bool {
	return s.authorizeTenantAccess(ctx, principal, resourceTenant) == tenantAuthAllowed
}

// writeTenantCrossingChallenge responds with a step-up-shaped challenge (ADR-021
// Decision 6's response envelope, cited by ADR-025 Decision 3) when a root-scoped
// caller is denied a specific tenant solely because it lacks an active crossing — as
// opposed to a bare 403/404, which would give a legitimate break-glass invocation no
// path forward. "tenant-crossing" is not a session.AssuranceLevel: this does not touch
// the assurance enum or resolveAssuranceRequirement, only the response shape.
func (s *Server) writeTenantCrossingChallenge(w http.ResponseWriter, resourceTenant string) {
	writeTenantCrossingChallenge(w, resourceTenant)
}

// writeTenantCrossingChallenge is Server.writeTenantCrossingChallenge for handlers
// that are not *Server (RollbackHandler).
func writeTenantCrossingChallenge(w http.ResponseWriter, resourceTenant string) {
	w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="tenant-crossing"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(struct {
		Error              string   `json:"error"`
		RequiredAssurance  string   `json:"required_assurance"`
		BreakGlassEndpoint string   `json:"break_glass_endpoint"`
		ReasonCategories   []string `json:"reason_categories"`
	}{
		Error:              "tenant_crossing_required",
		RequiredAssurance:  "tenant-crossing",
		BreakGlassEndpoint: "/api/v1/tenants/" + resourceTenant + "/break-glass",
		ReasonCategories: []string{
			string(business.TenantCrossingReasonAccountRecovery),
			string(business.TenantCrossingReasonSecurityIncident),
			string(business.TenantCrossingReasonLegalRequest),
			string(business.TenantCrossingReasonBillingDispute),
		},
	})
}

// principalIsUnrestrictedAdmin reports whether principal has today's unrestricted
// tenant-creation behavior: an unscoped, certificate-authenticated principal that is
// not subject to the ADR-025 root<->MSP crossing boundary — exactly
// authorizeTenantAccess's own definition of "unrestricted" (see that function's first
// branch). It may create a root-level tenant or place one anywhere in the tree.
//
// Issue #4336: this used to be `principal == nil || (principal.TenantID == "" &&
// !principal.RootScoped)` — true for a nil principal and for ANY unscoped,
// non-RootScoped principal regardless of how (or whether) it was authenticated. That
// let a caller whose principal was nil, or merely unscoped without ever having
// presented a verified mTLS admin certificate (the ADR-025 Amendment 4 A4.2 gap
// authorizeTenantAccess's own first branch already closes for every other tenant
// route in this file), graft a tenant anywhere in the tree. Routing the "unrestricted"
// decision through this single predicate — the same one authorizeTenantAccess uses —
// keeps handleCreateTenant's guard consistent with every other handler in this file
// instead of carrying its own, narrower-in-appearance-but-actually-wider fail-open path.
func principalIsUnrestrictedAdmin(principal *Principal) bool {
	if principal == nil || !principal.GlobalScope || subjectToTenantCrossingBoundary(principal) {
		return false
	}
	return principal.CertSerial != ""
}

// authorizeTenantCreationParent decides whether principal may create a tenant under
// parentID, writing the denial response itself and reporting false when it does.
//
//   - An unrestricted admin (principalIsUnrestrictedAdmin) keeps today's unrestricted
//     behavior: it may create a root-level tenant or place one anywhere in the tree.
//   - Every scope-constrained principal — tenant-scoped (TenantID != ""), root-scoped
//     (ADR-025 Amendment 1 A1.3), or unscoped-but-not-certificate-authenticated — must
//     name a parent it is authorized for. An omitted parent_id is a denial, not a
//     default: it would create a new top-level tenant outside the caller's subtree.
//     For the not-certificate-authenticated case, authorizeTenantAccess below denies
//     regardless of parentID (ADR-025 Amendment 4 A4.2), so the response is the same
//     403 either way.
//
// A parent that does not exist and a parent in a foreign subtree both fail closed to the
// same 403 (IsTenantAncestor errors on an unknown descendant, which authorizeTenantAccess
// maps to tenantAuthDenied), so this guard is not a cross-tenant existence oracle.
func (s *Server) authorizeTenantCreationParent(w http.ResponseWriter, r *http.Request, principal *Principal, parentID string) bool {
	if principalIsUnrestrictedAdmin(principal) {
		return true
	}

	if parentID == "" {
		callerTenant, principalID := "", ""
		if principal != nil {
			callerTenant, principalID = principal.TenantID, principal.ID
		}
		s.logger.Info("Tenant create refused: scope-constrained caller omitted parent_id",
			"caller_tenant", logging.SanitizeLogValue(callerTenant),
			"principal_id", logging.SanitizeLogValue(principalID))
		s.writeErrorResponse(w, http.StatusForbidden,
			"parent_id is required and must name the caller's own tenant or a descendant",
			"CROSS_TENANT_ACCESS_DENIED")
		return false
	}

	switch s.authorizeTenantAccess(r.Context(), principal, parentID) {
	case tenantAuthAllowed:
		return true
	case tenantAuthNeedsCrossing:
		// Root-scoped caller, real descendant of "root", no active crossing: same
		// step-up-shaped remedy handleGetTenant/handleUpdateTenant give (ADR-025 Decision 3).
		s.writeTenantCrossingChallenge(w, parentID)
		return false
	default:
		callerTenant := ""
		if principal != nil {
			callerTenant = principal.TenantID
		}
		s.logger.Info("Cross-tenant tenant create refused",
			"parent_tenant", logging.SanitizeLogValue(parentID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusForbidden,
			"parent_id is required and must name the caller's own tenant or a descendant",
			"CROSS_TENANT_ACCESS_DENIED")
		return false
	}
}

// handleCreateTenant implements POST /api/v1/tenants.
// Creates a tenant with an optional explicit ID. When req.ID is provided
// the store uses that exact value (K8s-compatible naming required). Returns
// HTTP 201 on success, 409 when the tenant ID already exists (idempotent
// callers should treat 409 as success), 403 when a scope-constrained caller
// asks for a parent outside its own subtree.
//
// Scope guard (Issue #3195): this route carries no {id} path variable, so
// requirePermission's extractTargetTenantFromRequest yields "" and its tenant-isolation
// block treats the request as in-scope, skipping both the subtree check and the
// isolation engine (middleware.go). The ADR-025 root-scoped crossing check keys off the
// same absent target and is skipped too. The parent named in the body is the only tenant
// this request targets, and Manager.CreateTenant takes req.ParentID verbatim, so the
// boundary has to be enforced here: without it any scope-constrained principal holding
// tenant:create could graft a tenant into a foreign subtree, or omit parent_id and create
// a new root-level tenant outside its own scope entirely.
func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req tenant.TenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if !s.authorizeTenantCreationParent(w, r, principal, req.ParentID) {
		return
	}

	td, err := s.tenantManager.CreateTenant(r.Context(), &req)
	if err != nil {
		if errors.Is(err, business.ErrTenantAlreadyExists) {
			s.writeErrorResponse(w, http.StatusConflict, "tenant already exists", "TENANT_EXISTS")
			return
		}
		if errors.Is(err, tenant.ErrTopLevelTenantExists) {
			s.writeErrorResponse(w, http.StatusConflict, "a top-level tenant already exists; specify parent_id", "TOP_LEVEL_TENANT_EXISTS")
			return
		}
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "CREATE_FAILED")
		return
	}

	s.writeResponse(w, http.StatusCreated, td)
}

// handleGetTenant implements GET /api/v1/tenants/{id}.
// Returns 200 + tenant JSON for an existing tenant, 404 for a missing one.
func (s *Server) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}

	td, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}

	// Cross-tenant scope check: reject requests from callers outside the tenant's subtree.
	// 404 instead of 403 to avoid disclosing the tenant's existence across tenant boundaries
	// — except a root-scoped caller lacking an active crossing, which gets a step-up
	// challenge instead (ADR-025 Decision 3): the tenant is real and inside "root"'s own
	// subtree, so there is nothing to hide from that caller.
	// Uses authorizeTenantAccess (ADR-025 Amendment 1 A1.2's ancestry-based check), not the
	// prefix-based isWithinTenantScope — real tenant IDs are flat, so the prefix match is
	// dead code against them; see authorizeTenantAccess's doc comment.
	callerTenant := callerTenantFilter(r.Context())
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	switch s.authorizeTenantAccess(r.Context(), principal, td.ID) {
	case tenantAuthAllowed:
		s.writeSuccessResponse(w, td)
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, td.ID)
	default:
		s.logger.Info("Cross-tenant tenant get refused",
			"resource_tenant", logging.SanitizeLogValue(td.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
	}
}

// handleListTenants implements GET /api/v1/tenants.
// Returns the tenants visible to the caller, filtered to the caller's authorized
// subtree. An unscoped, non-root-scoped mTLS admin (callerTenant == "") sees all
// tenants. A scoped caller sees only tenants that are callerTenant itself or a genuine
// descendant of it in the ParentID hierarchy (isCallerAuthorizedForTenant, ADR-025
// Amendment 1 A1.2). A root-scoped caller (ADR-025 Amendment 1 A1.3) sees "root" plus
// only those descendants it holds an active grant or break-glass crossing for (ADR-025
// Decision 1). Each MSP (direct child of root) it lacks a crossing for is returned as a
// boundary row — MSP-level facts only, accessible=false (ADR-025 Amendment 6, A6.4) — so
// break-glass has a target. Tenants below such an MSP are omitted: a bulk list has no
// single resource to attach a step-up challenge to, and naming a client would leak it.
func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	callerTenant := callerTenantFilter(r.Context())
	principal, _ := r.Context().Value(principalContextKey).(*Principal)

	all, err := s.tenantManager.ListTenants(r.Context(), &business.TenantFilter{})
	if err != nil {
		// The store's text is a backend fault (driver messages naming the schema, the
		// database host:port, a cancelled request context) and never reaches the client;
		// it goes to the log instead, sanitized for the same reason the adjacent
		// caller_tenant field is — see handleUpdateTenant's error branch.
		s.logger.Error("Tenant list failed",
			"caller_tenant", logging.SanitizeLogValue(callerTenant),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to list tenants", "LIST_FAILED")
		return
	}

	result := make([]*business.TenantData, 0, len(all))
	for _, td := range all {
		if s.isCallerAuthorizedForTenant(r.Context(), principal, td.ID) {
			result = append(result, td)
		}
	}

	rollup, err := s.rollupTenants(r.Context(), all)
	if err != nil {
		s.logger.Error("Tenant device count failed",
			"caller_tenant", logging.SanitizeLogValue(callerTenant),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to list tenants", "LIST_FAILED")
		return
	}
	counts := subtreeDeviceCounts(rollup, result)

	items := make([]any, 0, len(result))
	for _, td := range result {
		items = append(items, tenantListItem{TenantData: td, DeviceCount: counts[td.ID], Accessible: true})
	}
	if subjectToTenantCrossingBoundary(principal) {
		for _, td := range s.boundaryMSPs(r.Context(), principal, all) {
			tr := rollup[td.ID]
			items = append(items, newTenantBoundaryRow(td, tr))
		}
	}

	s.logger.Debug("Listed tenants",
		"caller_tenant", logging.SanitizeLogValue(callerTenant),
		"count", len(result))

	s.writeSuccessResponse(w, items)
}

// tenantListItem is a GET /api/v1/tenants item: the tenant record plus the additive
// device_count (Issue #4590).
type tenantListItem struct {
	*business.TenantData
	// DeviceCount is the number of stewards in the tenant's subtree that the caller
	// may see. Same counting rule as the billing roll-up (ADR-025 Amendment 6).
	DeviceCount int `json:"device_count"`
	// Boundary is always false on a full row; Accessible is always true (Issue #4647).
	Boundary   bool `json:"boundary"`
	Accessible bool `json:"accessible"`
}

// tenantBoundaryRow is the list item for a walled-off MSP (ADR-025 Amendment 6, A6.4):
// MSP-level facts only. It is a dedicated struct, never a copy of TenantData with
// fields cleared, so a field added to TenantData cannot reach a caller that holds no
// crossing. ClientCount is a count of direct clients and names none of them.
type tenantBoundaryRow struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ParentID    string `json:"parent_id"`
	Status      string `json:"status,omitempty"`
	Boundary    bool   `json:"boundary"`
	Accessible  bool   `json:"accessible"`
	TechCount   int    `json:"tech_count"`
	DeviceCount int    `json:"device_count"`
	ClientCount int    `json:"client_count"`
}

func newTenantBoundaryRow(td *business.TenantData, tr *tenantRollup) tenantBoundaryRow {
	row := tenantBoundaryRow{ID: td.ID, Name: td.Name, ParentID: td.ParentID, Boundary: true}
	// Only active or suspended is reported, and never why a tenant is suspended.
	if td.Status == business.TenantStatusActive || td.Status == business.TenantStatusSuspended {
		row.Status = string(td.Status)
	}
	if tr != nil {
		row.TechCount = tr.SubtreeTechs
		row.DeviceCount = tr.SubtreeEndpoints
		row.ClientCount = len(tr.Children)
	}
	return row
}

// boundaryMSPs returns the direct children of the root tenant for which principal's
// decision is tenantAuthNeedsCrossing. The direct-child test is mandatory: tenants below
// an MSP also decide NeedsCrossing, and listing them would name clients. An MSP the
// caller may access (grant or break-glass) is tenantAuthAllowed and shows only as a
// normal row.
func (s *Server) boundaryMSPs(ctx context.Context, principal *Principal, all []*business.TenantData) []*business.TenantData {
	root := s.rootTenantID(ctx)
	if root == "" {
		return nil
	}
	var out []*business.TenantData
	for _, td := range all {
		if td.ParentID != root || td.ID == root {
			continue
		}
		if s.authorizeTenantAccess(ctx, principal, td.ID) == tenantAuthNeedsCrossing {
			out = append(out, td)
		}
	}
	return out
}

// subtreeDeviceCounts returns, for each tenant in visible, the number of billable
// endpoints in its subtree that the caller may see. The counts are a projection of the
// whole-tree billing roll-up (rollupTenants, Issue #4646) — the single endpoint
// definition shared with every billing surface — scoped here at the edge: endpoints
// owned by a tenant the caller cannot see are subtracted from each visible ancestor, so
// an ancestor's count never includes a tenant the caller cannot see (e.g. a root-scoped
// caller without a crossing).
func subtreeDeviceCounts(rollup map[string]*tenantRollup, visible []*business.TenantData) map[string]int {
	counts := make(map[string]int, len(visible))
	visibleSet := make(map[string]struct{}, len(visible))
	for _, td := range visible {
		visibleSet[td.ID] = struct{}{}
		counts[td.ID] = rollup[td.ID].SubtreeEndpoints
	}
	for id, tr := range rollup {
		if _, ok := visibleSet[id]; ok || tr.OwnEndpoints == 0 {
			continue
		}
		// Walk the hidden tenant's ancestors; the visited set mirrors rollupTenants'
		// ParentID-cycle guard so each ancestor is subtracted from at most once.
		visited := map[string]struct{}{id: {}}
		for cur := tr.ParentID; cur != ""; {
			if _, seen := visited[cur]; seen {
				break
			}
			visited[cur] = struct{}{}
			if _, ok := visibleSet[cur]; ok {
				counts[cur] -= tr.OwnEndpoints
			}
			anc, ok := rollup[cur]
			if !ok {
				break
			}
			cur = anc.ParentID
		}
	}
	return counts
}

// tenantInputRejectionPrefixes enumerates the error classes tenant.Manager produces
// from data the caller supplied in the request body. Their text describes the
// submitted payload, not the controller's backend, so it is safe — and necessary —
// to return verbatim: the caller cannot correct the request otherwise.
//
//   - "validation failed: "             — Manager.validateTenantRequest (name/description rules)
//   - "invalid config source metadata: " — cfgpkg.ParseConfigSource on caller metadata
//   - "config source validation failed: " — MountPointValidator rejecting the caller's git source
//
// This is an allowlist by construction: an error class added to the manager later,
// or a rephrased message, is not on the list and therefore fails closed to a
// generic 500 rather than leaking whatever text it carries.
var tenantInputRejectionPrefixes = []string{
	"validation failed: ",
	"invalid config source metadata: ",
	"config source validation failed: ",
}

// isTenantInputRejection reports whether err rejects caller-supplied request data
// (as opposed to a controller-side storage, serialization or connectivity fault).
func isTenantInputRejection(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, prefix := range tenantInputRejectionPrefixes {
		if strings.HasPrefix(msg, prefix) {
			return true
		}
	}
	return false
}

// handleUpdateTenant implements PUT /api/v1/tenants/{id}.
// Decodes the request body into TenantRequest, verifies the tenant exists and is
// within the caller's authorized subtree, then delegates to tenantManager.UpdateTenant.
// Returns 404 for a missing or out-of-scope tenant (indistinguishable to prevent
// disclosure), 400 for body-decode failures and caller-actionable rejections
// (isTenantInputRejection), 500 for any other backend failure, 200 with the
// updated tenant on success.
//
// A missing tenant is identified with errors.Is against business.ErrTenantDoesNotExist,
// never by matching the error message. Message matching only recognises whichever
// phrasing one storage provider happens to use; on every other provider the missing
// tenant falls through to 500 while an out-of-scope tenant still returns 404, and that
// status split is a cross-tenant existence oracle for any tenant-scoped caller holding
// tenant:update.
func (s *Server) handleUpdateTenant(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}

	callerTenant := callerTenantFilter(r.Context())
	principal, _ := r.Context().Value(principalContextKey).(*Principal)

	// Fetch the existing tenant to enforce subtree scope before allowing mutation.
	// Returns the same 404 whether the tenant does not exist or is outside the
	// caller's subtree, preventing disclosure of tenants in other scopes — except a
	// root-scoped caller lacking an active crossing, which gets a step-up challenge
	// instead (ADR-025 Decision 3; see handleGetTenant's identical branch).
	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}

	switch s.authorizeTenantAccess(r.Context(), principal, existing.ID) {
	case tenantAuthAllowed:
		// proceed
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, existing.ID)
		return
	default:
		s.logger.Info("Cross-tenant tenant update refused",
			"resource_tenant", logging.SanitizeLogValue(existing.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}

	var req tenant.TenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	updated, err := s.tenantManager.UpdateTenant(r.Context(), tenantID, &req)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		// Only the caller-actionable rejection classes carry their detail back over
		// the wire. Every other failure is a server-side fault whose text is derived
		// from backend internals (storage driver messages naming the schema, host:port
		// of the database, metadata marshal errors) — a tenant-scoped principal holding
		// tenant:update is a downstream MSP-client caller, so echoing that text would
		// leak controller internals across a tenant boundary. Anything unrecognised
		// therefore fails closed to a generic 500; the detail goes to the server log.
		if isTenantInputRejection(err) {
			s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "VALIDATION_FAILED")
			return
		}
		// err is sanitized for the same reason tenant_id is: the residual (non
		// input-rejection) classes include tenant.Manager's
		// fmt.Errorf("failed to update tenant: %w", err), which wraps raw storage-driver
		// text that can embed the caller's submitted Name/Description/Metadata verbatim.
		// Logging it unsanitized lets a request body inject CR/LF or ANSI sequences into
		// the controller log and forge entries.
		s.logger.Error("Tenant update failed",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to update tenant", "UPDATE_FAILED")
		return
	}

	s.logger.Info("Updated tenant",
		"tenant_id", logging.SanitizeLogValue(tenantID))

	s.writeSuccessResponse(w, updated)
}

// handleSuspendTenant implements POST /api/v1/tenants/{id}/suspend.
// Sets the tenant status to TenantStatusSuspended. Used by agent-dispatch cleanup
// paths to deactivate the agent-test/<N> sub-tenant after the agent exits.
// Returns 200 on success, 404 when the tenant does not exist or is outside the
// caller's authorized subtree (indistinguishable, as in handleGetTenant).
func (s *Server) handleSuspendTenant(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}

	// Suspending a tenant is a denial of service against everything inside it, so it
	// carries the same scope guard as handleUpdateTenant rather than relying solely on
	// requirePermission's boundary check. That middleware check is the systemic control
	// (it covers every tenant-targeting route); this is the second line of defence for
	// the destructive mutation, and it keeps the guard attached to the handler for any
	// future call path that does not run the middleware.
	callerTenant := callerTenantFilter(r.Context())
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}
	switch s.authorizeTenantAccess(r.Context(), principal, existing.ID) {
	case tenantAuthAllowed:
		// proceed
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, existing.ID)
		return
	default:
		s.logger.Info("Cross-tenant tenant suspend refused",
			"resource_tenant", logging.SanitizeLogValue(existing.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}

	cascadeResult, err := s.tenantManager.SuspendTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		if errors.Is(err, tenant.ErrCannotSuspendRoot) {
			s.writeErrorResponse(w, http.StatusBadRequest, "cannot suspend root tenant", "PROTECTED_TENANT")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to suspend tenant", "SUSPEND_FAILED")
		return
	}

	s.logger.Info("Suspended tenant",
		"tenant_id", logging.SanitizeLogValue(tenantID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":                      tenantID,
		"status":                  string(business.TenantStatusSuspended),
		"newly_cascade_suspended": cascadeResult.NewlyCascadeSuspended,
		"already_suspended":       cascadeResult.AlreadySuspended,
	})
}

// handleRestoreTenant implements POST /api/v1/tenants/{id}/restore.
// Clears the target tenant's own suspension and lifts cascade-suspended status from
// descendants that were suspended purely because of this tenant's cascade (ADR-027 Decision 2).
// Descendants that carry their own DirectlySuspended flag remain suspended.
func (s *Server) handleRestoreTenant(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}

	callerTenant := callerTenantFilter(r.Context())
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}
	switch s.authorizeTenantAccess(r.Context(), principal, existing.ID) {
	case tenantAuthAllowed:
		// proceed
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, existing.ID)
		return
	default:
		s.logger.Info("Cross-tenant tenant restore refused",
			"resource_tenant", logging.SanitizeLogValue(existing.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}

	cascadeResult, err := s.tenantManager.RestoreTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to restore tenant", "RESTORE_FAILED")
		return
	}

	s.logger.Info("Restored tenant",
		"tenant_id", logging.SanitizeLogValue(tenantID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":              tenantID,
		"status":          string(business.TenantStatusActive),
		"restored":        cascadeResult.Restored,
		"still_suspended": cascadeResult.StillSuspended,
	})
}

// handleRequestTenantDeletion implements POST /api/v1/tenants/{id}/delete.
// Begins the ADR-027 Decision 3 deletion pipeline for the target subtree.
// Returns 409 with a message naming the first unsuspended descendant when the
// subtree is not fully suspended.
func (s *Server) handleRequestTenantDeletion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}

	callerTenant := callerTenantFilter(r.Context())
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}
	switch s.authorizeTenantAccess(r.Context(), principal, existing.ID) {
	case tenantAuthAllowed:
		// proceed
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, existing.ID)
		return
	default:
		s.logger.Info("Cross-tenant delete request refused",
			"resource_tenant", logging.SanitizeLogValue(existing.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}

	requesterID := ""
	if principal != nil {
		requesterID = principal.ID
	}

	holdPeriod := s.cfg.TenantAdmin.GetDeleteHoldPeriod()

	pending, err := s.tenantManager.RequestTenantDeletion(r.Context(), tenantID, requesterID, holdPeriod)
	if err != nil {
		if errors.Is(err, tenant.ErrTenantNotFullySuspended) {
			s.writeErrorResponse(w, http.StatusConflict, err.Error(), "SUBTREE_NOT_SUSPENDED")
			return
		}
		if errors.Is(err, business.ErrPendingDeletionExists) {
			s.writeErrorResponse(w, http.StatusConflict, "pending deletion already exists for this tenant", "PENDING_DELETION_EXISTS")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to request tenant deletion", "REQUEST_FAILED")
		return
	}

	s.logger.Info("Tenant deletion requested",
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"requester_id", logging.SanitizeLogValue(requesterID))

	s.writeResponse(w, http.StatusAccepted, pending)
}

// handleCancelTenantDeletion implements DELETE /api/v1/tenants/{id}/delete.
// Cancels a pending Hold/Eligible deletion and returns the subtree to plain Suspended state.
func (s *Server) handleCancelTenantDeletion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}

	callerTenant := callerTenantFilter(r.Context())
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}
	switch s.authorizeTenantAccess(r.Context(), principal, existing.ID) {
	case tenantAuthAllowed:
		// proceed
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, existing.ID)
		return
	default:
		s.logger.Info("Cross-tenant delete cancel refused",
			"resource_tenant", logging.SanitizeLogValue(existing.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}

	if err := s.tenantManager.CancelTenantDeletion(r.Context(), tenantID); err != nil {
		if errors.Is(err, business.ErrPendingDeletionNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "no pending deletion found for this tenant", "PENDING_DELETION_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to cancel tenant deletion", "CANCEL_FAILED")
		return
	}

	s.logger.Info("Tenant deletion cancelled",
		"tenant_id", logging.SanitizeLogValue(tenantID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":     tenantID,
		"status": string(business.TenantStatusSuspended),
	})
}

// handleGetPendingDeletion implements GET /api/v1/tenants/{id}/delete.
// Returns the current pending-deletion state or 404 if none pending.
func (s *Server) handleGetPendingDeletion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}

	callerTenant := callerTenantFilter(r.Context())
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}
	switch s.authorizeTenantAccess(r.Context(), principal, existing.ID) {
	case tenantAuthAllowed:
		// proceed
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, existing.ID)
		return
	default:
		s.logger.Info("Cross-tenant get pending deletion refused",
			"resource_tenant", logging.SanitizeLogValue(existing.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}

	pending, err := s.tenantManager.GetPendingDeletion(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrPendingDeletionNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "no pending deletion found for this tenant", "PENDING_DELETION_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get pending deletion", "GET_FAILED")
		return
	}

	s.writeResponse(w, http.StatusOK, pending)
}

// handleApproveTenantDeletion implements POST /api/v1/tenants/{id}/delete/approve.
// The dual-control terminal step. Returns 403 on same-approver violation and 409
// if the hold has not elapsed or membership has changed since the request.
func (s *Server) handleApproveTenantDeletion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}

	callerTenant := callerTenantFilter(r.Context())
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}
	switch s.authorizeTenantAccess(r.Context(), principal, existing.ID) {
	case tenantAuthAllowed:
		// proceed
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, existing.ID)
		return
	default:
		s.logger.Info("Cross-tenant delete approve refused",
			"resource_tenant", logging.SanitizeLogValue(existing.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}

	approverID := ""
	if principal != nil {
		approverID = principal.ID
	}

	requireDualControl := s.cfg.TenantAdmin.GetDeleteRequiresDualControl()

	deleted, err := s.tenantManager.ApproveTenantDeletion(r.Context(), tenantID, approverID, requireDualControl)
	if err != nil {
		if errors.Is(err, business.ErrSameApprover) {
			s.writeErrorResponse(w, http.StatusForbidden,
				"approver must differ from the principal who requested this deletion",
				"SAME_APPROVER")
			return
		}
		if errors.Is(err, business.ErrHoldNotElapsed) {
			s.writeErrorResponse(w, http.StatusConflict, "deletion hold period has not yet elapsed", "HOLD_NOT_ELAPSED")
			return
		}
		if errors.Is(err, business.ErrMembershipChanged) {
			s.writeErrorResponse(w, http.StatusConflict,
				"subtree membership has changed since deletion was requested",
				"MEMBERSHIP_CHANGED")
			return
		}
		if errors.Is(err, business.ErrPendingDeletionNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "no pending deletion found for this tenant", "PENDING_DELETION_NOT_FOUND")
			return
		}
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to approve tenant deletion", "APPROVE_FAILED")
		return
	}

	s.logger.Info("Tenant subtree deleted via approval pipeline",
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"approver_id", logging.SanitizeLogValue(approverID),
		"deleted_count", len(deleted))

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":      tenantID,
		"deleted": deleted,
	})
}
