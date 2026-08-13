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
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// rootTenantID is the conventional ID of the top-level tenant (ADR-025 Decision 1's
// "root"), shared in spirit with handlers_installer.go's downloadTenantID.
const rootTenantID = "root"

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

// authorizeTenantAccess decides whether principal may act on resourceTenant.
//
//   - An unscoped principal (TenantID == "") that is NOT RootScoped has unrestricted
//     access — today's exact behavior, unchanged for every admin/session principal
//     issued before the ADR-025 Amendment 1 A1.3 root-scope marker existed, and for
//     the 31 pre-existing callerTenant=="" branches elsewhere in this package (none of
//     which call this function).
//   - A tenant-scoped principal must have resourceTenant equal to or a genuine
//     ParentID-chain descendant of its own TenantID (ADR-025 Amendment 1 A1.2) — never
//     a string-prefix match against tenant IDs. Real tenant IDs are flat, validated
//     single DNS-label-style tokens (features/tenant/manager.go's k8sNameRegex) and
//     can never contain '/': the prefix-match shape the older isWithinTenantScope
//     helper (middleware.go) uses is dead code against them.
//   - A RootScoped principal (ADR-025 Amendment 1 A1.3) is confined to "root" itself;
//     a strict descendant requires an active grant or break-glass crossing (ADR-025
//     Decision 1, Decision 2), else tenantAuthNeedsCrossing.
func (s *Server) authorizeTenantAccess(ctx context.Context, principal *Principal, resourceTenant string) tenantAuthDecision {
	var callerTenant, principalID string
	var rootScoped bool
	if principal != nil {
		callerTenant = principal.TenantID
		rootScoped = principal.RootScoped
		principalID = principal.ID
	}

	if callerTenant == "" {
		if !rootScoped {
			return tenantAuthAllowed
		}
		return s.authorizeRootScopedTenantAccess(ctx, principalID, resourceTenant)
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
	if resourceTenant == "" || resourceTenant == rootTenantID {
		return tenantAuthAllowed
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
		if tenantID == rootTenantID {
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
	w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="tenant-crossing"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(struct {
		Error              string `json:"error"`
		RequiredAssurance  string `json:"required_assurance"`
		BreakGlassEndpoint string `json:"break_glass_endpoint"`
	}{
		Error:              "tenant_crossing_required",
		RequiredAssurance:  "tenant-crossing",
		BreakGlassEndpoint: "/api/v1/tenants/" + resourceTenant + "/break-glass",
	})
}

// authorizeTenantCreationParent decides whether principal may create a tenant under
// parentID, writing the denial response itself and reporting false when it does.
//
//   - An unscoped principal that is not RootScoped keeps today's unrestricted behavior
//     (authorizeTenantAccess's first branch): it may create a root-level tenant or place
//     one anywhere in the tree.
//   - Every scope-constrained principal — tenant-scoped (TenantID != "") or root-scoped
//     (ADR-025 Amendment 1 A1.3) — must name a parent it is authorized for. An omitted
//     parent_id is a denial, not a default: it would create a new top-level tenant
//     outside the caller's subtree.
//
// A parent that does not exist and a parent in a foreign subtree both fail closed to the
// same 403 (IsTenantAncestor errors on an unknown descendant, which authorizeTenantAccess
// maps to tenantAuthDenied), so this guard is not a cross-tenant existence oracle.
func (s *Server) authorizeTenantCreationParent(w http.ResponseWriter, r *http.Request, principal *Principal, parentID string) bool {
	if principal == nil || (principal.TenantID == "" && !principal.RootScoped) {
		return true
	}

	if parentID == "" {
		s.logger.Info("Tenant create refused: scope-constrained caller omitted parent_id",
			"caller_tenant", logging.SanitizeLogValue(principal.TenantID),
			"principal_id", logging.SanitizeLogValue(principal.ID))
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
		s.logger.Info("Cross-tenant tenant create refused",
			"parent_tenant", logging.SanitizeLogValue(parentID),
			"caller_tenant", logging.SanitizeLogValue(principal.TenantID))
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
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
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
// Decision 1) — items it lacks a crossing for are silently omitted, not challenged:
// a bulk list has no single resource to attach a step-up challenge to.
func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
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

	s.logger.Debug("Listed tenants",
		"caller_tenant", logging.SanitizeLogValue(callerTenant),
		"count", len(result))

	s.writeSuccessResponse(w, result)
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

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
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
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
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

	if err := s.tenantManager.SuspendTenant(r.Context(), tenantID); err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		if errors.Is(err, tenant.ErrCannotSuspendDefault) {
			s.writeErrorResponse(w, http.StatusBadRequest, "cannot suspend default tenant", "PROTECTED_TENANT")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to suspend tenant", "SUSPEND_FAILED")
		return
	}

	s.logger.Info("Suspended tenant",
		"tenant_id", logging.SanitizeLogValue(tenantID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":     tenantID,
		"status": string(business.TenantStatusSuspended),
	})
}
