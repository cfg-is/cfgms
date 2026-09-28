// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package api provides REST API handlers for the CFGMS controller
package api

import (
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

// tenantScopeAuthorizes reports whether scope permits access to resourceTenant, using
// the same three-state semantics as Server.isAuthorizedForTenant (middleware.go, Issue
// #4316): root scope always allows; a tenant scope is checked via subtree containment
// (isWithinTenantScope); the unset zero value (or a tenant scope with an empty path)
// always denies. RollbackHandler and WorkflowHandler are not *Server, so they cannot
// call Server.isAuthorizedForTenant directly — this package-level equivalent is shared
// by both (Issue #4335).
func tenantScopeAuthorizes(scope ctxkeys.TenantScope, resourceTenant string) bool {
	switch {
	case scope.IsRoot():
		return true
	case scope.IsTenant() && scope.Path() != "":
		return isWithinTenantScope(scope.Path(), resourceTenant)
	default:
		return false
	}
}

// callerTenantScope reads the caller's ctxkeys.TenantScope from the request context.
func callerTenantScope(r *http.Request) ctxkeys.TenantScope {
	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	return scope
}

// authorizedForTargetTenant resolves targetID's owning tenant via stewardTenantLookup
// and checks it against the caller's ctxkeys.TenantScope (Issue #4335), mirroring
// ExecuteRollback's existing cross-tenant gate. When the lookup is unavailable
// (stewardTenantLookup is nil — e.g. in unit tests) or returns no result (unknown
// target), the check is skipped and the underlying manager call decides — the same
// resolvedTenant != "" guard ExecuteRollback already uses.
func (h *RollbackHandler) authorizedForTargetTenant(r *http.Request, targetID string) bool {
	if h.stewardTenantLookup == nil {
		return true
	}
	resolvedTenant := h.stewardTenantLookup(targetID)
	if resolvedTenant == "" {
		return true
	}
	return tenantScopeAuthorizes(callerTenantScope(r), resolvedTenant)
}

// RollbackHandler handles rollback-related API requests
type RollbackHandler struct {
	rollbackManager     rollback.RollbackManager
	PrincipalExtractor  func(r *http.Request) *Principal
	stewardTenantLookup func(stewardID string) string
	auditManager        *audit.Manager
	logger              logging.Logger
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
	if !h.authorizedForTargetTenant(r, targetID) {
		h.sendJSON(w, http.StatusOK, map[string]interface{}{
			"rollback_points": []rollback.RollbackPoint{},
		})
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
	if !h.authorizedForTargetTenant(r, request.TargetID) {
		h.sendJSON(w, http.StatusBadRequest, map[string]interface{}{
			"code":    "CROSS_TENANT_ROLLBACK",
			"message": "target version belongs to a different tenant",
		})
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

	// Cross-tenant enforcement. For a tenant-scoped principal (non-empty TenantID), we
	// must verify the target steward belongs to the principal's tenant or a child.
	// An empty TenantID (mTLS admin) bypasses this check and has unrestricted access.
	//
	// Two-phase check with segment-boundary comparison (prevents "root/msp-ab" from
	// matching "root/msp-a" — only self and children like "root/msp-a/client-1" pass):
	//   Phase 1 (authoritative): server-side registry lookup via stewardTenantLookup —
	//     this is always used in production and cannot be bypassed by the caller.
	//   Phase 2 (fallback): caller-supplied steward_tenant_path field — used when
	//     stewardTenantLookup is nil (e.g. handler unit tests).
	if principal != nil && principal.TenantID != "" {
		var resolvedTenant string
		if h.stewardTenantLookup != nil {
			resolvedTenant = h.stewardTenantLookup(req.TargetID)
		} else {
			resolvedTenant = req.StewardTenantPath
		}
		if resolvedTenant != "" {
			scope := strings.TrimRight(principal.TenantID, "/")
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
		if errors.Is(err, rollback.ErrRollbackNotFound) {
			h.sendError(w, http.StatusNotFound, "Rollback operation not found")
			return
		}
		h.sendManagerError(w, err, http.StatusInternalServerError)
		return
	}

	// Tenant scope check (Issue #4335): an out-of-scope operation returns the same
	// 404 as a genuinely unknown rollback ID, so the endpoint cannot be used to
	// probe cross-tenant existence.
	if !h.authorizedForTargetTenant(r, operation.Request.TargetID) {
		h.sendError(w, http.StatusNotFound, "Rollback operation not found")
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
		if err == rollback.ErrRollbackNotFound {
			h.sendError(w, http.StatusNotFound, "Rollback operation not found")
			return
		}
		h.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !h.authorizedForTargetTenant(r, operation.Request.TargetID) {
		h.sendError(w, http.StatusNotFound, "Rollback operation not found")
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
	if !h.authorizedForTargetTenant(r, targetID) {
		h.sendJSON(w, http.StatusOK, map[string]interface{}{
			"rollback_operations": []rollback.RollbackOperation{},
		})
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
