// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package api provides REST API handlers for the CFGMS controller
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/config/rollback"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

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

	// Get rollback points
	points, err := h.rollbackManager.ListRollbackPoints(ctx, targetType, targetID, limit)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, err.Error())
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

	// Preview rollback
	preview, err := h.rollbackManager.PreviewRollback(ctx, request)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, err.Error())
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

	// Cross-tenant enforcement. For a scoped principal (non-admin with a TenantID), we
	// must verify the target steward belongs to the principal's tenant or a child.
	//
	// Two-phase check with segment-boundary comparison (prevents "root/msp-ab" from
	// matching "root/msp-a" — only self and children like "root/msp-a/client-1" pass):
	//   Phase 1 (authoritative): server-side registry lookup via stewardTenantLookup —
	//     this is always used in production and cannot be bypassed by the caller.
	//   Phase 2 (fallback): caller-supplied steward_tenant_path field — used when
	//     stewardTenantLookup is nil (e.g. handler unit tests).
	if principal != nil && principal.Assurance < session.AssuranceBasic && principal.TenantID != "" {
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
		if rollbackErr, ok := err.(*rollback.RollbackError); ok {
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
				"error", err)
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
		if err == rollback.ErrRollbackNotFound {
			h.sendError(w, http.StatusNotFound, "Rollback operation not found")
			return
		}
		h.sendError(w, http.StatusInternalServerError, err.Error())
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

	// Cancel rollback
	if err := h.rollbackManager.CancelRollback(ctx, rollbackID, cancelRequest.Reason); err != nil {
		if err == rollback.ErrRollbackNotFound {
			h.sendError(w, http.StatusNotFound, "Rollback operation not found")
			return
		}

		if rollbackErr, ok := err.(*rollback.RollbackError); ok && rollbackErr.Code == "CANNOT_CANCEL" {
			h.sendError(w, http.StatusConflict, rollbackErr.Message)
			return
		}

		h.sendError(w, http.StatusInternalServerError, err.Error())
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

	// Get rollback history
	operations, err := h.rollbackManager.ListRollbackHistory(ctx, targetType, targetID, limit)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, err.Error())
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
