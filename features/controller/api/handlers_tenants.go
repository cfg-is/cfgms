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

// isCallerAuthorizedForTenant reports whether callerTenant may act on resourceTenant.
// An empty callerTenant (mTLS admin with no tenant scope) has unrestricted access.
// Otherwise resourceTenant must be callerTenant itself or a genuine descendant of it
// per the tenant hierarchy's ParentID chain (business.TenantStore.IsTenantAncestor) —
// never a string-prefix match against tenant IDs. Real tenant IDs are flat,
// validated single DNS-label-style tokens (features/tenant/manager.go's
// k8sNameRegex) and can never contain '/': the prefix-match shape the older
// isWithinTenantScope helper (middleware.go) uses is dead code against them, per
// ADR-025 Amendment 1 (A1.1/A1.2).
//
// This implements A1.2's corrected ancestry mechanism only. It does not implement
// ADR-025 Decision 1's root<->MSP boundary: A1.3 (distinguishing a genuinely
// root-scoped caller from an unscoped superadmin, both of which present as
// callerTenant == "" today) is an open design question the ADR leaves to a
// follow-on decision, and the grant/break-glass override (Decision 2) has no
// store-backed state yet. Tracked as follow-up work in #3228.
func (s *Server) isCallerAuthorizedForTenant(ctx context.Context, callerTenant, resourceTenant string) bool {
	if callerTenant == "" {
		return true
	}
	isAncestor, err := s.tenantManager.IsTenantAncestor(ctx, callerTenant, resourceTenant)
	if err != nil {
		// Fail closed: a broken ancestry lookup (e.g. a dangling ParentID) must not
		// silently grant cross-tenant access.
		s.logger.Error("Tenant ancestry check failed",
			"caller_tenant", logging.SanitizeLogValue(callerTenant),
			"resource_tenant", logging.SanitizeLogValue(resourceTenant),
			"error", logging.SanitizeLogValue(err.Error()))
		return false
	}
	return isAncestor
}

// handleCreateTenant implements POST /api/v1/tenants.
// Creates a tenant with an optional explicit ID. When req.ID is provided
// the store uses that exact value (K8s-compatible naming required). Returns
// HTTP 201 on success, 409 when the tenant ID already exists (idempotent
// callers should treat 409 as success).
func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req tenant.TenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
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
	// 404 instead of 403 to avoid disclosing the tenant's existence across tenant boundaries.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if !isWithinTenantScope(callerTenant, td.ID) {
		s.logger.Info("Cross-tenant tenant get refused",
			"resource_tenant", logging.SanitizeLogValue(td.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}

	s.writeSuccessResponse(w, td)
}

// handleListTenants implements GET /api/v1/tenants.
// Returns the tenants visible to the caller, filtered to the caller's authorized
// subtree. An unscoped mTLS admin (callerTenant == "") sees all tenants. A scoped
// caller sees only tenants that are callerTenant itself or a genuine descendant of
// it in the ParentID hierarchy (isCallerAuthorizedForTenant, ADR-025 Amendment 1
// A1.2). This does not yet enforce ADR-025 Decision 1's root<->MSP boundary — see
// isCallerAuthorizedForTenant's doc comment; that piece needs founder sign-off on
// A1.3 and is tracked as follow-up work in #3228, not delivered here.
func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)

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
		if s.isCallerAuthorizedForTenant(r.Context(), callerTenant, td.ID) {
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

	// Fetch the existing tenant to enforce subtree scope before allowing mutation.
	// Returns the same 404 whether the tenant does not exist or is outside the
	// caller's subtree, preventing disclosure of tenants in other scopes.
	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}

	if !s.isCallerAuthorizedForTenant(r.Context(), callerTenant, existing.ID) {
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
// Returns 200 on success, 404 when the tenant does not exist.
func (s *Server) handleSuspendTenant(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}

	if err := s.tenantManager.SuspendTenant(r.Context(), tenantID); err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
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
