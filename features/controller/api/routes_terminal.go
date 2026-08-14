// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

func init() { RegisterRoutes(registerTerminalRoutes) }

// registerTerminalRoutes registers GET /terminal/ws/{steward_id} behind the
// "terminal:create" permission gate (AssuranceStrong per permissionAssurance).
// The handler is resolved lazily from s.terminalHandler so it can be wired via
// SetTerminalHandler after the server is constructed.
//
// Cross-tenant isolation: requirePermission only checks the RBAC verb; it does
// not scope the {steward_id} resource to the caller's tenant. The handler is
// therefore wrapped in tenantScopedTerminalWrapper, which resolves the steward's
// tenant and rejects (404) any steward outside the caller's tenant subtree —
// the same protection the telemetry route gets from tenantScopedTelemetryWrapper.
func registerTerminalRoutes(s *Server, api *mux.Router) {
	api.Handle(
		"/terminal/ws/{steward_id}",
		s.requirePermission("terminal", "create")(s.tenantScopedTerminalWrapper(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.mu.RLock()
			h := s.terminalHandler
			s.mu.RUnlock()
			if h == nil {
				http.Error(w, "terminal service not available", http.StatusServiceUnavailable)
				return
			}
			h.ServeHTTP(w, r)
		}))),
	).Methods("GET")
}

// tenantScopedTerminalWrapper enforces cross-tenant isolation on the terminal
// WebSocket route. A scoped principal in tenant A holding terminal:create must
// not be able to open an interactive shell to a steward owned by another tenant.
// It replicates the steward-scoping logic used by tenantScopedTelemetryWrapper
// and handleGetStewardDNA: the caller may only reach stewards in its own tenant
// or a descendant tenant. Out-of-scope (or unknown) stewards return 404 so the
// endpoint does not disclose steward existence across tenants. The {steward_id}
// path variable carries the target steward ID.
//
// Root-scoped principals (ADR-025 Decision 1, Issue #3303): the route path carries
// {steward_id} rather than a tenant ID, so requirePermission's
// extractBoundaryTenantFromRequest returns "" and the middleware root-scoped crossing
// check is skipped. The wrapper resolves the steward's tenant from the registry and
// enforces the ADR-025 Decision 1 boundary inline — same approach as the reboot-window
// handler. tenantAuthNeedsCrossing emits a step-up-shaped crossing challenge
// (ADR-025 Decision 3); tenantAuthDenied returns 404 (existence oracle).
func (s *Server) tenantScopedTerminalWrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		stewardID := vars["steward_id"]
		if stewardID == "" {
			s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
			return
		}
		callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
		info, exists := s.controllerService.GetStewardInfo(stewardID)
		if callerTenant != "" {
			stewardTenant := ""
			if exists {
				stewardTenant = info.TenantID
			}
			sameTenant := stewardTenant == callerTenant
			ancestorTenant := strings.HasPrefix(stewardTenant, callerTenant+"/")
			if !exists || (!sameTenant && !ancestorTenant) {
				// 404 instead of 403 to avoid disclosing steward existence across tenants.
				s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
				return
			}
		} else if !exists {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			return
		} else if principal, _ := r.Context().Value(principalContextKey).(*Principal); principal != nil && principal.RootScoped {
			// callerTenant == "" and steward exists: enforce ADR-025 Decision 1 for root-scoped principals.
			stewardTenant := info.TenantID
			if s.tenantManager == nil {
				// Fail closed: no ancestry source wired, treat as if no crossing is active.
				s.writeTenantCrossingChallenge(w, stewardTenant)
				return
			}
			switch s.authorizeTenantAccess(r.Context(), principal, stewardTenant) {
			case tenantAuthAllowed:
				// Active crossing grant or steward is in the root tenant itself.
			case tenantAuthNeedsCrossing:
				s.writeTenantCrossingChallenge(w, stewardTenant)
				return
			default:
				s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
