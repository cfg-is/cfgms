// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package api provides REST API handlers for the CFGMS controller
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/config/rollback"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// tenantScopeDecision is the tenant decision for handlers that are not *Server
// (RollbackHandler): it delegates to access — the server's tenantAccessForScope,
// injected at construction — so the decision, ADR-025 crossing included, is the
// same one every Server handler makes (Issue #4665). Without an injected decision
// (handler unit tests) it fails closed for a root caller subject to the crossing
// boundary, since no crossing can be evaluated; a tenant scope is checked by
// subtree containment and an unset scope is refused, exactly as
// tenantAccessForScope does.
func tenantScopeDecision(ctx context.Context, access tenantAccessFunc, scope ctxkeys.TenantScope, resourceTenant, route string) tenantAuthDecision {
	if access != nil {
		return access(ctx, scope, resourceTenant, route)
	}
	switch {
	case scope.IsRoot(): //architecture:allow-root-scope -- no server decision injected: only a root caller outside the crossing boundary is let through
		if principal, _ := ctx.Value(principalContextKey).(*Principal); subjectToTenantCrossingBoundary(principal) {
			return tenantAuthNeedsCrossing
		}
		return tenantAuthAllowed
	case scope.IsTenant() && scope.Path() != "":
		if isWithinTenantScope(scope.Path(), resourceTenant) { //architecture:allow-root-scope -- tenant-scope subtree check, mirroring tenantAccessForScope
			return tenantAuthAllowed
		}
		return tenantAuthDenied
	default:
		return tenantAuthDenied
	}
}

// callerTenantScope reads the caller's ctxkeys.TenantScope from the request context.
func callerTenantScope(r *http.Request) ctxkeys.TenantScope {
	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	return scope
}

// targetTenantAccess resolves targetID's owning tenant via stewardTenantLookup and
// decides it against the caller's ctxkeys.TenantScope (Issue #4335) with the
// server's tenant decision, crossing included (Issue #4665). It returns the
// decision and the resolved tenant. When the lookup is unavailable
// (stewardTenantLookup is nil — e.g. in unit tests) or returns no result (unknown
// target), the underlying manager call decides — it refuses an unresolved target
// for every tenant-scoped caller (Issue #4340) — except for a root caller subject
// to the ADR-025 crossing boundary, which the manager would admit: with no owner
// established no crossing can be evaluated, so that caller is refused here
// (Issue #4665).
func (h *RollbackHandler) targetTenantAccess(r *http.Request, targetID, route string) (tenantAuthDecision, string) {
	if h.stewardTenantLookup == nil {
		return tenantAuthAllowed, ""
	}
	resolvedTenant := h.stewardTenantLookup(targetID)
	if resolvedTenant == "" {
		if principal, _ := r.Context().Value(principalContextKey).(*Principal); subjectToTenantCrossingBoundary(principal) && callerTenantScope(r).IsRoot() { //architecture:allow-root-scope -- refuses, not grants: an unresolved target for a boundary-subject root
			return tenantAuthDenied, ""
		}
		return tenantAuthAllowed, ""
	}
	return tenantScopeDecision(r.Context(), h.tenantAccess, callerTenantScope(r), resolvedTenant, route), resolvedTenant
}

// refuseTarget answers a refused targetTenantAccess decision: the ADR-025 crossing
// challenge when only a crossing is missing, deny otherwise. It reports whether
// the target was refused.
func (h *RollbackHandler) refuseTarget(w http.ResponseWriter, r *http.Request, targetID, route string, deny func()) bool {
	decision, tenant := h.targetTenantAccess(r, targetID, route)
	switch decision {
	case tenantAuthAllowed:
		return false
	case tenantAuthNeedsCrossing:
		writeTenantCrossingChallenge(w, tenant)
	default:
		deny()
	}
	return true
}

// RollbackHandler handles rollback-related API requests
type RollbackHandler struct {
	rollbackManager     rollback.RollbackManager
	PrincipalExtractor  func(r *http.Request) *Principal
	stewardTenantLookup func(stewardID string) string
	// tenantAccess is the server's tenant decision (Server.tenantAccessForScope),
	// set by the server when it wires the handler (Issue #4665).
	tenantAccess tenantAccessFunc
	auditManager *audit.Manager
	logger       logging.Logger
}

// executeRollbackRequest extends RollbackRequest with handler-local cross-tenant check fields.
// StewardTenantPath is an optional caller-supplied hint used as a fallback when the server-side
// lookup function is not available (e.g. in unit tests).
type executeRollbackRequest struct {
	rollback.RollbackRequest
	StewardTenantPath string `json:"steward_tenant_path,omitempty"`
}

// NewRollbackHandler creates a new rollback handler.
//
// principalExtractor retrieves the authenticated principal from the request context
// (set by authenticationMiddleware; captures both mTLS admin certs and scoped API keys).
//
// stewardTenantLookup resolves a steward's registered tenant path from the controller
// registry; the handler uses this for authoritative server-side cross-tenant enforcement.
// When nil the handler falls back to the optional steward_tenant_path field in the request
// body (used by tests; not a secure substitute for server-side resolution in production).
//
// auditManager may be nil — audit writes are skipped when nil.
func NewRollbackHandler(
	rollbackManager rollback.RollbackManager,
	principalExtractor func(*http.Request) *Principal,
	stewardTenantLookup func(stewardID string) string,
	auditManager *audit.Manager,
) *RollbackHandler {
	return &RollbackHandler{
		rollbackManager:     rollbackManager,
		PrincipalExtractor:  principalExtractor,
		stewardTenantLookup: stewardTenantLookup,
		auditManager:        auditManager,
		logger:              logging.ForComponent("rollback-handler"),
	}
}

// RegisterRoutes registers rollback API routes on the provided subrouter.
// The router should already be scoped to the rollback path prefix.
func (h *RollbackHandler) RegisterRoutes(router *mux.Router) {
	// Rollback points
	router.HandleFunc("/points", h.ListRollbackPoints).Methods("GET")

	// Rollback operations
	router.HandleFunc("/preview", h.PreviewRollback).Methods("POST")
	router.HandleFunc("/execute", h.ExecuteRollback).Methods("POST")
	router.HandleFunc("/{rollback_id}/status", h.GetRollbackStatus).Methods("GET")
	router.HandleFunc("/{rollback_id}/cancel", h.CancelRollback).Methods("POST")

	// Rollback history
	router.HandleFunc("/history", h.ListRollbackHistory).Methods("GET")
}

// ListRollbackPoints returns available rollback points
// GET /api/v1/rollback/points?target_type={type}&target_id={id}&limit={limit}
func (h *RollbackHandler) ListRollbackPoints(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	targetType := rollback.TargetType(r.URL.Query().Get("target_type"))
	targetID := r.URL.Query().Get("target_id")

	limit := 50 // default
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	// Validate parameters
	if targetType == "" || targetID == "" {
		h.sendError(w, http.StatusBadRequest, "target_type and target_id are required")
		return
	}

	// Tenant scope check (Issue #4335): an out-of-scope target returns the same
	// empty-list response as a target with no recorded rollback points, so the
	// endpoint cannot be used to probe cross-tenant existence.
	if h.refuseTarget(w, r, targetID, "GET /api/v1/rollback/points", func() {
		h.sendJSON(w, http.StatusOK, map[string]interface{}{
			"rollback_points": []rollback.RollbackPoint{},
		})
	}) {
		return
	}

	// Get rollback points
	points, err := h.rollbackManager.ListRollbackPoints(ctx, targetType, targetID, limit)
	if err != nil {
		h.sendManagerError(w, err, http.StatusInternalServerError)
		return
	}

	// Send response
	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"rollback_points": points,
	})
}

// PreviewRollback previews what will change in a rollback
// POST /api/v1/rollback/preview
func (h *RollbackHandler) PreviewRollback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
	var request rollback.RollbackRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Set dry run for preview
	request.DryRun = true

	// Tenant scope check (Issue #4335), mirroring ExecuteRollback's cross-tenant gate.
	if h.refuseTarget(w, r, request.TargetID, "POST /api/v1/rollback/preview", func() {
		h.sendJSON(w, http.StatusBadRequest, map[string]interface{}{
			"code":    "CROSS_TENANT_ROLLBACK",
			"message": "target version belongs to a different tenant",
		})
	}) {
		return
	}

	// Preview rollback
	preview, err := h.rollbackManager.PreviewRollback(ctx, request)
	if err != nil {
		h.sendManagerError(w, err, http.StatusInternalServerError)
		return
	}

	// Send response
	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"preview": preview,
	})
}

// ExecuteRollback executes a rollback operation
// POST /api/v1/rollback/execute
func (h *RollbackHandler) ExecuteRollback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body using the extended local struct that includes steward_tenant_path.
	var req executeRollbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	var principal *Principal
	if h.PrincipalExtractor != nil {
		principal = h.PrincipalExtractor(r)
	}

	// Cross-tenant enforcement. A caller confined to a tenant — by the request's tenant
	// scope, or by its principal when the request carries no scope — must target a
	// steward in that tenant or a child. Only an explicitly root caller (root
	// TenantScope; GlobalScope principal) bypasses this check (Issue #4665).
	//
	// Two-phase check with segment-boundary comparison (prevents "root/msp-ab" from
	// matching "root/msp-a" — only self and children like "root/msp-a/client-1" pass):
	//   Phase 1 (authoritative): server-side registry lookup via stewardTenantLookup —
	//     this is always used in production and cannot be bypassed by the caller.
	//   Phase 2 (fallback): caller-supplied steward_tenant_path field — used when
	//     stewardTenantLookup is nil (e.g. handler unit tests).
	scopeTenant := callerTenantFilter(r.Context())
	if scopeTenant == "" && principal != nil && !principal.GlobalScope { //architecture:allow-root-scope -- confines a principal with no scope to its own tenant; not a grant
		scopeTenant = principal.TenantID
	}
	if scopeTenant == "" { //architecture:allow-root-scope -- an explicitly root caller: the target passes refuseTarget, the server tenant decision
		// An explicitly root caller: the target steward's tenant passes the server's
		// tenant decision, so a root caller subject to the ADR-025 boundary needs a
		// crossing to roll back a client tenant's steward (Issue #4665).
		if h.refuseTarget(w, r, req.TargetID, "POST /api/v1/rollback/execute", func() {
			h.sendJSON(w, http.StatusBadRequest, map[string]interface{}{
				"code":    "CROSS_TENANT_ROLLBACK",
				"message": "target version belongs to a different tenant",
			})
		}) {
			return
		}
	} else {
		var resolvedTenant string
		if h.stewardTenantLookup != nil {
			resolvedTenant = h.stewardTenantLookup(req.TargetID)
		} else {
			resolvedTenant = req.StewardTenantPath
		}
		if resolvedTenant != "" {
			scope := strings.TrimRight(scopeTenant, "/")
			sameOrChild := resolvedTenant == scope ||
				strings.HasPrefix(resolvedTenant, scope+"/")
			if !sameOrChild {
				h.sendJSON(w, http.StatusBadRequest, map[string]interface{}{
					"code":    "CROSS_TENANT_ROLLBACK",
					"message": "target version belongs to a different tenant",
				})
				return
			}
		}
	}

	// Execute rollback
	operation, err := h.rollbackManager.ExecuteRollback(ctx, req.RollbackRequest)
	if err != nil {
		// Check for specific error types
		var rollbackErr *rollback.RollbackError
		if errors.As(err, &rollbackErr) {
			switch rollbackErr.Code {
			case "APPROVAL_REQUIRED":
				h.sendError(w, http.StatusPreconditionFailed, rollbackErr.Message)
				return
			case "ROLLBACK_PERMISSION_DENIED":
				h.sendError(w, http.StatusForbidden, rollbackErr.Message)
				return
			case "ROLLBACK_VALIDATION_FAILED":
				h.sendError(w, http.StatusUnprocessableEntity, rollbackErr.Message)
				return
			case "ROLLBACK_IN_PROGRESS":
				h.sendError(w, http.StatusConflict, rollbackErr.Message)
				return
			case "ROLLBACK_TENANT_UNVERIFIABLE":
				h.sendError(w, http.StatusServiceUnavailable, rollbackErr.Message)
				return
			}
		}

		h.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Write to central audit log after successful rollback initiation.
	if h.auditManager != nil {
		adminCN := ""
		if principal != nil {
			adminCN = principal.ID
		}
		toVersion := req.RollbackTo
		fromVersion := h.extractFromVersion(operation)

		event := audit.ConfigurationEvent(
			req.TargetID,
			adminCN,
			"steward",
			req.TargetID,
			req.TargetID,
			"rollback_execute",
		).Detail("admin_cn", logging.SanitizeLogValue(adminCN)).
			Detail("steward_id", logging.SanitizeLogValue(req.TargetID)).
			Detail("from_version", logging.SanitizeLogValue(fromVersion)).
			Detail("to_version", logging.SanitizeLogValue(toVersion)).
			Detail("rollback_id", logging.SanitizeLogValue(operation.ID)).
			Result(business.AuditResultSuccess)

		if err := h.auditManager.RecordEvent(ctx, event); err != nil {
			h.logger.Warn("Failed to emit rollback audit event",
				"rollback_id", logging.SanitizeLogValue(operation.ID),
				"error", logging.SanitizeLogValue(err.Error()))
		}
	}

	// Send response
	h.sendJSON(w, http.StatusAccepted, map[string]interface{}{
		"rollback": operation,
	})
}

// extractFromVersion attempts to find the "from_version" in the rollback operation's
// audit trail entries. Returns empty string if not recorded.
func (h *RollbackHandler) extractFromVersion(op *rollback.RollbackOperation) string {
	if op == nil {
		return ""
	}
	for _, entry := range op.AuditTrail {
		if v, ok := entry.Details["from_version"]; ok {
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

// GetRollbackStatus returns the status of a rollback operation
// GET /api/v1/rollback/{rollback_id}/status
func (h *RollbackHandler) GetRollbackStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get rollback ID from path
	vars := mux.Vars(r)
	rollbackID := vars["rollback_id"]

	// Get rollback status
	operation, err := h.rollbackManager.GetRollbackStatus(ctx, rollbackID)
	if err != nil {
		if errors.Is(err, rollback.ErrRollbackNotFound) || errors.Is(err, rollback.ErrRollbackOutsideTenantScope) {
			// A tenant-scope refusal from the manager must read exactly like an
			// unknown ID (Issue #4335/#4340) — reusing the manager's own message
			// here would let a scoped caller distinguish "wrong tenant" from
			// "no such rollback".
			h.sendError(w, http.StatusNotFound, "Rollback operation not found")
			return
		}
		h.sendManagerError(w, err, http.StatusInternalServerError)
		return
	}

	// Tenant scope check (Issue #4335): an out-of-scope operation returns the same
	// 404 as a genuinely unknown rollback ID, so the endpoint cannot be used to
	// probe cross-tenant existence.
	if h.refuseTarget(w, r, operation.Request.TargetID, "GET /api/v1/rollback/{rollback_id}/status", func() {
		h.sendError(w, http.StatusNotFound, "Rollback operation not found")
	}) {
		return
	}

	// Send response
	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"rollback": operation,
	})
}

// CancelRollback cancels an in-progress rollback
// POST /api/v1/rollback/{rollback_id}/cancel
func (h *RollbackHandler) CancelRollback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get rollback ID from path
	vars := mux.Vars(r)
	rollbackID := vars["rollback_id"]

	// Parse request body for reason
	var cancelRequest struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&cancelRequest); err != nil {
		cancelRequest.Reason = "Cancelled by user"
	}

	// Tenant scope check (Issue #4335): fetch the operation first so an out-of-scope
	// cancel returns the same 404 as a genuinely unknown rollback ID, rather than
	// letting a tenant-scoped caller cancel another tenant's in-progress rollback.
	operation, err := h.rollbackManager.GetRollbackStatus(ctx, rollbackID)
	if err != nil {
		if errors.Is(err, rollback.ErrRollbackNotFound) || errors.Is(err, rollback.ErrRollbackOutsideTenantScope) {
			// Same indistinguishable-from-unknown-ID treatment as GetRollbackStatus
			// above (Issue #4335/#4340).
			h.sendError(w, http.StatusNotFound, "Rollback operation not found")
			return
		}
		h.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if h.refuseTarget(w, r, operation.Request.TargetID, "POST /api/v1/rollback/{rollback_id}/cancel", func() {
		h.sendError(w, http.StatusNotFound, "Rollback operation not found")
	}) {
		return
	}

	// Cancel rollback
	if err := h.rollbackManager.CancelRollback(ctx, rollbackID, cancelRequest.Reason); err != nil {
		if errors.Is(err, rollback.ErrRollbackNotFound) {
			h.sendError(w, http.StatusNotFound, "Rollback operation not found")
			return
		}

		var rollbackErr *rollback.RollbackError
		if errors.As(err, &rollbackErr) && rollbackErr.Code == "CANNOT_CANCEL" {
			h.sendError(w, http.StatusConflict, rollbackErr.Message)
			return
		}

		h.sendManagerError(w, err, http.StatusInternalServerError)
		return
	}

	// Send response
	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Rollback cancelled successfully",
	})
}

// ListRollbackHistory returns rollback history
// GET /api/v1/rollback/history?target_type={type}&target_id={id}&limit={limit}
func (h *RollbackHandler) ListRollbackHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	targetType := rollback.TargetType(r.URL.Query().Get("target_type"))
	targetID := r.URL.Query().Get("target_id")

	limit := 50 // default
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	// Validate parameters
	if targetType == "" || targetID == "" {
		h.sendError(w, http.StatusBadRequest, "target_type and target_id are required")
		return
	}

	// Tenant scope check (Issue #4335): an out-of-scope target returns the same
	// empty-list response as a target with no recorded rollback history, so the
	// endpoint cannot be used to probe cross-tenant existence.
	if h.refuseTarget(w, r, targetID, "GET /api/v1/rollback/history", func() {
		h.sendJSON(w, http.StatusOK, map[string]interface{}{
			"rollback_operations": []rollback.RollbackOperation{},
		})
	}) {
		return
	}

	// Get rollback history
	operations, err := h.rollbackManager.ListRollbackHistory(ctx, targetType, targetID, limit)
	if err != nil {
		h.sendManagerError(w, err, http.StatusInternalServerError)
		return
	}

	// Send response
	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"rollback_operations": operations,
	})
}

// Helper methods

func (h *RollbackHandler) sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode rollback response", "status", status, "error", err)
	}
}

func (h *RollbackHandler) sendError(w http.ResponseWriter, status int, message string) {
	h.sendJSON(w, status, map[string]interface{}{
		"error": message,
	})
}

// sendManagerError maps an error from the rollback manager onto an HTTP status.
//
// The manager holds the tenant boundary for every rollback endpoint (Issue
// #4340), so its refusals must reach the caller as refusals: a denial answered
// with the endpoint's generic failure status reads as a server fault and hides
// the fact that access was refused. The manager's own message is used for those
// two codes — both are deliberately free of the target's identity, so neither
// confirms nor denies the existence of another tenant's steward. Any other error
// keeps the endpoint's fallback status.
func (h *RollbackHandler) sendManagerError(w http.ResponseWriter, err error, fallbackStatus int) {
	var rollbackErr *rollback.RollbackError
	if errors.As(err, &rollbackErr) {
		switch rollbackErr.Code {
		case "ROLLBACK_PERMISSION_DENIED":
			h.sendError(w, http.StatusForbidden, rollbackErr.Message)
			return
		case "ROLLBACK_TENANT_UNVERIFIABLE":
			h.sendError(w, http.StatusServiceUnavailable, rollbackErr.Message)
			return
		}
	}

	h.sendError(w, fallbackStatus, err.Error())
}
