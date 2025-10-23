// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package api provides REST API handlers for the CFGMS controller
package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/config/rollback"
)

// RollbackHandler handles rollback-related API requests
type RollbackHandler struct {
	rollbackManager rollback.RollbackManager
}

// NewRollbackHandler creates a new rollback handler
func NewRollbackHandler(rollbackManager rollback.RollbackManager) *RollbackHandler {
	return &RollbackHandler{
		rollbackManager: rollbackManager,
	}
}

// RegisterRoutes registers rollback API routes
func (h *RollbackHandler) RegisterRoutes(router *mux.Router) {
	// Rollback points
	router.HandleFunc("/api/v1/rollback/points", h.ListRollbackPoints).Methods("GET")

	// Rollback operations
	router.HandleFunc("/api/v1/rollback/preview", h.PreviewRollback).Methods("POST")
	router.HandleFunc("/api/v1/rollback/execute", h.ExecuteRollback).Methods("POST")
	router.HandleFunc("/api/v1/rollback/{rollback_id}/status", h.GetRollbackStatus).Methods("GET")
	router.HandleFunc("/api/v1/rollback/{rollback_id}/cancel", h.CancelRollback).Methods("POST")

	// Rollback history
	router.HandleFunc("/api/v1/rollback/history", h.ListRollbackHistory).Methods("GET")
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

	// Parse request body
	var request rollback.RollbackRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Execute rollback
	operation, err := h.rollbackManager.ExecuteRollback(ctx, request)
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

	// Send response
	h.sendJSON(w, http.StatusAccepted, map[string]interface{}{
		"rollback": operation,
	})
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
		// Log error but can't return error from HTTP handler
		_ = err // Explicitly ignore JSON encoding errors in HTTP handler
	}
}

func (h *RollbackHandler) sendError(w http.ResponseWriter, status int, message string) {
	h.sendJSON(w, status, map[string]interface{}{
		"error": message,
	})
}
