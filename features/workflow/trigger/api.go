// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package trigger

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/logging"
)

// APIHandler provides REST API endpoints for trigger management
type APIHandler struct {
	logger         *logging.ModuleLogger
	triggerManager TriggerManager
}

// NewAPIHandler creates a new API handler for triggers
func NewAPIHandler(triggerManager TriggerManager) *APIHandler {
	logger := logging.ForModule("workflow.trigger.api").WithField("component", "rest_api")

	return &APIHandler{
		logger:         logger,
		triggerManager: triggerManager,
	}
}

// RegisterRoutes registers all trigger API routes with the router
func (api *APIHandler) RegisterRoutes(router *mux.Router) {
	// Health check (must be before {id} routes to avoid conflicts)
	router.HandleFunc("/triggers/health", api.handleHealthCheck).Methods("GET")

	// Trigger management endpoints
	router.HandleFunc("/triggers", api.handleCreateTrigger).Methods("POST")
	router.HandleFunc("/triggers", api.handleListTriggers).Methods("GET")
	router.HandleFunc("/triggers/{id}", api.handleGetTrigger).Methods("GET")
	router.HandleFunc("/triggers/{id}", api.handleUpdateTrigger).Methods("PUT")
	router.HandleFunc("/triggers/{id}", api.handleDeleteTrigger).Methods("DELETE")

	// Trigger control endpoints
	router.HandleFunc("/triggers/{id}/enable", api.handleEnableTrigger).Methods("POST")
	router.HandleFunc("/triggers/{id}/disable", api.handleDisableTrigger).Methods("POST")
	router.HandleFunc("/triggers/{id}/execute", api.handleExecuteTrigger).Methods("POST")

	// Trigger execution history
	router.HandleFunc("/triggers/{id}/executions", api.handleGetTriggerExecutions).Methods("GET")
}

// handleCreateTrigger creates a new trigger
func (api *APIHandler) handleCreateTrigger(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := extractTenantFromContext(ctx)
	logger := api.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Creating trigger via API")

	var trigger Trigger
	if err := json.NewDecoder(r.Body).Decode(&trigger); err != nil {
		api.sendErrorResponse(w, http.StatusBadRequest, "Invalid JSON payload", err)
		return
	}

	if err := api.triggerManager.CreateTrigger(ctx, &trigger); err != nil {
		logger.ErrorCtx(ctx, "Failed to create trigger", "error", err.Error())
		api.sendErrorResponse(w, http.StatusInternalServerError, "Failed to create trigger", err)
		return
	}

	api.sendJSONResponse(w, http.StatusCreated, trigger)
	logger.InfoCtx(ctx, "Trigger created successfully via API",
		"trigger_id", trigger.ID)
}

// handleListTriggers lists triggers with optional filtering
func (api *APIHandler) handleListTriggers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := extractTenantFromContext(ctx)
	logger := api.logger.WithTenant(tenantID)

	// Parse query parameters for filtering
	filter, err := api.parseFilterFromQuery(r)
	if err != nil {
		api.sendErrorResponse(w, http.StatusBadRequest, "Invalid query parameters", err)
		return
	}

	triggers, err := api.triggerManager.ListTriggers(ctx, filter)
	if err != nil {
		logger.ErrorCtx(ctx, "Failed to list triggers", "error", err.Error())
		api.sendErrorResponse(w, http.StatusInternalServerError, "Failed to list triggers", err)
		return
	}

	response := map[string]interface{}{
		"triggers": triggers,
		"count":    len(triggers),
	}

	if filter != nil {
		response["filter"] = filter
	}

	api.sendJSONResponse(w, http.StatusOK, response)
}

// handleGetTrigger retrieves a specific trigger
func (api *APIHandler) handleGetTrigger(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := extractTenantFromContext(ctx)
	logger := api.logger.WithTenant(tenantID)

	vars := mux.Vars(r)
	triggerID := vars["id"]

	if triggerID == "" {
		api.sendErrorResponse(w, http.StatusBadRequest, "Trigger ID is required", nil)
		return
	}

	trigger, err := api.triggerManager.GetTrigger(ctx, triggerID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.sendErrorResponse(w, http.StatusNotFound, "Trigger not found", err)
		} else {
			logger.ErrorCtx(ctx, "Failed to get trigger", "trigger_id", triggerID, "error", err.Error())
			api.sendErrorResponse(w, http.StatusInternalServerError, "Failed to get trigger", err)
		}
		return
	}

	api.sendJSONResponse(w, http.StatusOK, trigger)
}

// handleUpdateTrigger updates an existing trigger
func (api *APIHandler) handleUpdateTrigger(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := extractTenantFromContext(ctx)
	logger := api.logger.WithTenant(tenantID)

	vars := mux.Vars(r)
	triggerID := vars["id"]

	if triggerID == "" {
		api.sendErrorResponse(w, http.StatusBadRequest, "Trigger ID is required", nil)
		return
	}

	var trigger Trigger
	if err := json.NewDecoder(r.Body).Decode(&trigger); err != nil {
		api.sendErrorResponse(w, http.StatusBadRequest, "Invalid JSON payload", err)
		return
	}

	// Ensure ID matches URL parameter
	trigger.ID = triggerID

	if err := api.triggerManager.UpdateTrigger(ctx, &trigger); err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.sendErrorResponse(w, http.StatusNotFound, "Trigger not found", err)
		} else {
			logger.ErrorCtx(ctx, "Failed to update trigger", "trigger_id", triggerID, "error", err.Error())
			api.sendErrorResponse(w, http.StatusInternalServerError, "Failed to update trigger", err)
		}
		return
	}

	api.sendJSONResponse(w, http.StatusOK, trigger)
	logger.InfoCtx(ctx, "Trigger updated successfully via API",
		"trigger_id", triggerID)
}

// handleDeleteTrigger deletes a trigger
func (api *APIHandler) handleDeleteTrigger(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := extractTenantFromContext(ctx)
	logger := api.logger.WithTenant(tenantID)

	vars := mux.Vars(r)
	triggerID := vars["id"]

	if triggerID == "" {
		api.sendErrorResponse(w, http.StatusBadRequest, "Trigger ID is required", nil)
		return
	}

	if err := api.triggerManager.DeleteTrigger(ctx, triggerID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.sendErrorResponse(w, http.StatusNotFound, "Trigger not found", err)
		} else {
			logger.ErrorCtx(ctx, "Failed to delete trigger", "trigger_id", triggerID, "error", err.Error())
			api.sendErrorResponse(w, http.StatusInternalServerError, "Failed to delete trigger", err)
		}
		return
	}

	api.sendJSONResponse(w, http.StatusNoContent, map[string]string{
		"message":    "Trigger deleted successfully",
		"trigger_id": triggerID,
	})

	logger.InfoCtx(ctx, "Trigger deleted successfully via API",
		"trigger_id", triggerID)
}

// handleEnableTrigger enables a trigger
func (api *APIHandler) handleEnableTrigger(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := extractTenantFromContext(ctx)
	logger := api.logger.WithTenant(tenantID)

	vars := mux.Vars(r)
	triggerID := vars["id"]

	if triggerID == "" {
		api.sendErrorResponse(w, http.StatusBadRequest, "Trigger ID is required", nil)
		return
	}

	if err := api.triggerManager.EnableTrigger(ctx, triggerID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.sendErrorResponse(w, http.StatusNotFound, "Trigger not found", err)
		} else {
			logger.ErrorCtx(ctx, "Failed to enable trigger", "trigger_id", triggerID, "error", err.Error())
			api.sendErrorResponse(w, http.StatusInternalServerError, "Failed to enable trigger", err)
		}
		return
	}

	api.sendJSONResponse(w, http.StatusOK, map[string]string{
		"message":    "Trigger enabled successfully",
		"trigger_id": triggerID,
		"status":     string(TriggerStatusActive),
	})

	logger.InfoCtx(ctx, "Trigger enabled successfully via API",
		"trigger_id", triggerID)
}

// handleDisableTrigger disables a trigger
func (api *APIHandler) handleDisableTrigger(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := extractTenantFromContext(ctx)
	logger := api.logger.WithTenant(tenantID)

	vars := mux.Vars(r)
	triggerID := vars["id"]

	if triggerID == "" {
		api.sendErrorResponse(w, http.StatusBadRequest, "Trigger ID is required", nil)
		return
	}

	if err := api.triggerManager.DisableTrigger(ctx, triggerID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.sendErrorResponse(w, http.StatusNotFound, "Trigger not found", err)
		} else {
			logger.ErrorCtx(ctx, "Failed to disable trigger", "trigger_id", triggerID, "error", err.Error())
			api.sendErrorResponse(w, http.StatusInternalServerError, "Failed to disable trigger", err)
		}
		return
	}

	api.sendJSONResponse(w, http.StatusOK, map[string]string{
		"message":    "Trigger disabled successfully",
		"trigger_id": triggerID,
		"status":     string(TriggerStatusInactive),
	})

	logger.InfoCtx(ctx, "Trigger disabled successfully via API",
		"trigger_id", triggerID)
}

// handleExecuteTrigger manually executes a trigger
func (api *APIHandler) handleExecuteTrigger(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := extractTenantFromContext(ctx)
	logger := api.logger.WithTenant(tenantID)

	vars := mux.Vars(r)
	triggerID := vars["id"]

	if triggerID == "" {
		api.sendErrorResponse(w, http.StatusBadRequest, "Trigger ID is required", nil)
		return
	}

	// Parse optional execution data
	var executionData map[string]interface{}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&executionData); err != nil {
			// Log error but continue with empty data
			logger.WarnCtx(ctx, "Failed to decode execution data", "error", err.Error())
		}
	}

	execution, err := api.triggerManager.ExecuteTrigger(ctx, triggerID, executionData)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.sendErrorResponse(w, http.StatusNotFound, "Trigger not found", err)
		} else {
			logger.ErrorCtx(ctx, "Failed to execute trigger", "trigger_id", triggerID, "error", err.Error())
			api.sendErrorResponse(w, http.StatusInternalServerError, "Failed to execute trigger", err)
		}
		return
	}

	api.sendJSONResponse(w, http.StatusOK, execution)

	logger.InfoCtx(ctx, "Trigger executed successfully via API",
		"trigger_id", triggerID,
		"execution_id", execution.ID)
}

// handleGetTriggerExecutions retrieves execution history for a trigger
func (api *APIHandler) handleGetTriggerExecutions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := extractTenantFromContext(ctx)
	logger := api.logger.WithTenant(tenantID)

	vars := mux.Vars(r)
	triggerID := vars["id"]

	if triggerID == "" {
		api.sendErrorResponse(w, http.StatusBadRequest, "Trigger ID is required", nil)
		return
	}

	// Parse limit parameter
	limit := 50 // Default limit
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		parsedLimit, err := strconv.Atoi(limitStr)
		if err != nil {
			api.sendErrorResponse(w, http.StatusBadRequest, "Invalid limit parameter", err)
			return
		}
		if parsedLimit <= 0 {
			api.sendErrorResponse(w, http.StatusBadRequest, "Invalid limit parameter: must be greater than 0", nil)
			return
		}
		limit = parsedLimit
	}

	executions, err := api.triggerManager.GetTriggerExecutions(ctx, triggerID, limit)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.sendErrorResponse(w, http.StatusNotFound, "Trigger not found", err)
		} else {
			logger.ErrorCtx(ctx, "Failed to get trigger executions", "trigger_id", triggerID, "error", err.Error())
			api.sendErrorResponse(w, http.StatusInternalServerError, "Failed to get trigger executions", err)
		}
		return
	}

	response := map[string]interface{}{
		"trigger_id": triggerID,
		"executions": executions,
		"count":      len(executions),
		"limit":      limit,
	}

	api.sendJSONResponse(w, http.StatusOK, response)
}

// handleHealthCheck returns the health status of the trigger system
func (api *APIHandler) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"service":   "workflow-trigger-api",
	}

	api.sendJSONResponse(w, http.StatusOK, status)
}

// Helper methods

// parseFilterFromQuery parses query parameters into a TriggerFilter
func (api *APIHandler) parseFilterFromQuery(r *http.Request) (*TriggerFilter, error) {
	query := r.URL.Query()

	filter := &TriggerFilter{}

	// Parse type filter
	if typeStr := query.Get("type"); typeStr != "" {
		filter.Type = TriggerType(typeStr)
	}

	// Parse status filter
	if statusStr := query.Get("status"); statusStr != "" {
		filter.Status = TriggerStatus(statusStr)
	}

	// Parse tenant_id filter
	if tenantID := query.Get("tenant_id"); tenantID != "" {
		filter.TenantID = tenantID
	}

	// Parse tags filter
	if tagsStr := query.Get("tags"); tagsStr != "" {
		filter.Tags = strings.Split(tagsStr, ",")
	}

	// Parse created_after filter
	if createdAfterStr := query.Get("created_after"); createdAfterStr != "" {
		if createdAfter, err := time.Parse(time.RFC3339, createdAfterStr); err == nil {
			filter.CreatedAfter = &createdAfter
		}
	}

	// Parse created_before filter
	if createdBeforeStr := query.Get("created_before"); createdBeforeStr != "" {
		if createdBefore, err := time.Parse(time.RFC3339, createdBeforeStr); err == nil {
			filter.CreatedBefore = &createdBefore
		}
	}

	// Parse limit
	if limitStr := query.Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil {
			return nil, fmt.Errorf("invalid limit parameter: must be a positive integer")
		}
		if limit <= 0 {
			return nil, fmt.Errorf("invalid limit parameter: must be greater than 0")
		}
		filter.Limit = limit
	}

	// Parse offset
	if offsetStr := query.Get("offset"); offsetStr != "" {
		offset, err := strconv.Atoi(offsetStr)
		if err != nil {
			return nil, fmt.Errorf("invalid offset parameter: must be a non-negative integer")
		}
		if offset < 0 {
			return nil, fmt.Errorf("invalid offset parameter: must be greater than or equal to 0")
		}
		filter.Offset = offset
	}

	return filter, nil
}

// sendJSONResponse sends a JSON response
func (api *APIHandler) sendJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		api.logger.Error("Failed to encode JSON response", "error", err.Error())
	}
}

// sendErrorResponse sends an error response
func (api *APIHandler) sendErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	errorResponse := map[string]interface{}{
		"error":     message,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if err != nil {
		errorResponse["details"] = err.Error()
	}

	api.sendJSONResponse(w, statusCode, errorResponse)
}

// TriggerAPIMiddleware provides middleware for trigger API requests
func TriggerAPIMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add CORS headers for browser compatibility
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Extract tenant ID from header and add to context
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			// Default tenant for testing
			tenantID = "default"
		}

		ctx := context.WithValue(r.Context(), TenantIDContextKey, tenantID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
