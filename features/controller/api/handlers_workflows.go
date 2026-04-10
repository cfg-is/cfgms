// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/ctxkeys"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/cfgis/cfgms/pkg/logging"
	storageif "github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// WorkflowHandler handles workflow and trigger REST API requests.
// It bridges the controller REST layer with the workflow engine and trigger manager.
type WorkflowHandler struct {
	engine         *workflow.Engine
	configStore    storageif.ConfigStore
	triggerManager trigger.TriggerManager
	triggerAPI     *trigger.APIHandler
	logger         logging.Logger
	fleetQuery     fleet.FleetQuery // Issue #609: fleet query for script dispatch targeting
}

// NewWorkflowHandler creates a new WorkflowHandler.
func NewWorkflowHandler(
	engine *workflow.Engine,
	configStore storageif.ConfigStore,
	triggerManager trigger.TriggerManager,
	logger logging.Logger,
) *WorkflowHandler {
	h := &WorkflowHandler{
		engine:         engine,
		configStore:    configStore,
		triggerManager: triggerManager,
		logger:         logger,
	}
	if triggerManager != nil {
		h.triggerAPI = trigger.NewAPIHandler(triggerManager)
	}
	return h
}

// SetFleetQuery sets the fleet query implementation used for script dispatch targeting (Issue #609).
// Must be called before workflow execution begins; propagated to script step executors at dispatch time.
func (h *WorkflowHandler) SetFleetQuery(q fleet.FleetQuery) {
	h.fleetQuery = q
}

// RegisterWorkflowRoutes registers workflow CRUD and execution routes on the provided subrouter.
func (h *WorkflowHandler) RegisterWorkflowRoutes(router *mux.Router) {
	router.HandleFunc("", h.handleListWorkflows).Methods("GET")
	router.HandleFunc("", h.handleCreateWorkflow).Methods("POST")
	router.HandleFunc("/{id}", h.handleGetWorkflow).Methods("GET")
	router.HandleFunc("/{id}", h.handleUpdateWorkflow).Methods("PUT")
	router.HandleFunc("/{id}", h.handleDeleteWorkflow).Methods("DELETE")
	router.HandleFunc("/{id}/execute", h.handleExecuteWorkflow).Methods("POST")
	router.HandleFunc("/{id}/executions", h.handleGetWorkflowExecutions).Methods("GET")
}

// NewRegistrationApprovalHook creates a RegistrationApprovalHook backed by this handler's
// workflow engine and config store.  If the engine or config store are unavailable it
// returns a DefaultApprovalHook so the controller always has a valid hook.
func (h *WorkflowHandler) NewRegistrationApprovalHook(logger logging.Logger) RegistrationApprovalHook {
	if h.engine == nil || h.configStore == nil {
		return &DefaultApprovalHook{}
	}
	return NewWorkflowApprovalHook(h.engine, h.configStore, logger)
}

// RegisterTriggerRoutes registers trigger management routes on the provided subrouter.
func (h *WorkflowHandler) RegisterTriggerRoutes(router *mux.Router) {
	if h.triggerAPI == nil {
		return
	}
	h.triggerAPI.RegisterRoutes(router)
}

// workflowStoreForRequest returns a WorkflowStore scoped to the tenant in the request context.
func (h *WorkflowHandler) workflowStoreForRequest(r *http.Request) *workflow.WorkflowStore {
	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	return workflow.NewWorkflowStore(h.configStore, tenantID)
}

// handleListWorkflows handles GET /api/v1/workflows
func (h *WorkflowHandler) handleListWorkflows(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil || h.configStore == nil {
		h.sendError(w, http.StatusServiceUnavailable, "workflow engine not available")
		return
	}

	store := h.workflowStoreForRequest(r)
	workflows, err := store.ListWorkflows(r.Context())
	if err != nil {
		h.logger.Error("Failed to list workflows", "error", err)
		h.sendError(w, http.StatusInternalServerError, "failed to list workflows")
		return
	}

	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"workflows": workflows,
		"count":     len(workflows),
	})
}

// CreateWorkflowRequest is the request body for creating a workflow.
type CreateWorkflowRequest struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Version     string                 `json:"version,omitempty"`
	Steps       []workflow.Step        `json:"steps"`
	Variables   map[string]interface{} `json:"variables,omitempty"`
	Timeout     time.Duration          `json:"timeout,omitempty"`
}

// handleCreateWorkflow handles POST /api/v1/workflows
func (h *WorkflowHandler) handleCreateWorkflow(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil || h.configStore == nil {
		h.sendError(w, http.StatusServiceUnavailable, "workflow engine not available")
		return
	}

	var req CreateWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if req.Name == "" {
		h.sendError(w, http.StatusBadRequest, "workflow name is required")
		return
	}
	if len(req.Steps) == 0 {
		h.sendError(w, http.StatusBadRequest, "workflow must have at least one step")
		return
	}

	version := req.Version
	if version == "" {
		version = "1.0.0"
	}
	semver, err := workflow.ParseSemanticVersion(version)
	if err != nil {
		h.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid version format: %s", err))
		return
	}

	vw := &workflow.VersionedWorkflow{
		Workflow: workflow.Workflow{
			Name:        req.Name,
			Description: req.Description,
			Version:     version,
			Steps:       req.Steps,
			Variables:   req.Variables,
			Timeout:     req.Timeout,
		},
		SemanticVersion: *semver,
	}

	store := h.workflowStoreForRequest(r)
	nameForLog := logging.SanitizeLogValue(req.Name)
	if err := store.StoreWorkflow(r.Context(), vw); err != nil {
		h.logger.Error("Failed to create workflow", "name", nameForLog, "error", err)
		h.sendError(w, http.StatusInternalServerError, "failed to create workflow")
		return
	}

	h.sendJSON(w, http.StatusCreated, vw)
}

// handleGetWorkflow handles GET /api/v1/workflows/{id}
func (h *WorkflowHandler) handleGetWorkflow(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil || h.configStore == nil {
		h.sendError(w, http.StatusServiceUnavailable, "workflow engine not available")
		return
	}

	name := mux.Vars(r)["id"]
	if name == "" {
		h.sendError(w, http.StatusBadRequest, "workflow name is required")
		return
	}

	nameForLog := logging.SanitizeLogValue(name)
	store := h.workflowStoreForRequest(r)
	vw, err := store.GetLatestWorkflow(r.Context(), name)
	if err != nil {
		h.logger.Error("Failed to get workflow", "name", nameForLog, "error", err)
		h.sendError(w, http.StatusNotFound, fmt.Sprintf("workflow %q not found", name))
		return
	}

	h.sendJSON(w, http.StatusOK, vw)
}

// handleUpdateWorkflow handles PUT /api/v1/workflows/{id}
func (h *WorkflowHandler) handleUpdateWorkflow(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil || h.configStore == nil {
		h.sendError(w, http.StatusServiceUnavailable, "workflow engine not available")
		return
	}

	name := mux.Vars(r)["id"]
	if name == "" {
		h.sendError(w, http.StatusBadRequest, "workflow name is required")
		return
	}

	var req CreateWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if len(req.Steps) == 0 {
		h.sendError(w, http.StatusBadRequest, "workflow must have at least one step")
		return
	}

	version := req.Version
	if version == "" {
		version = "1.0.0"
	}
	semver, err := workflow.ParseSemanticVersion(version)
	if err != nil {
		h.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid version format: %s", err))
		return
	}

	vw := &workflow.VersionedWorkflow{
		Workflow: workflow.Workflow{
			Name:        name,
			Description: req.Description,
			Version:     version,
			Steps:       req.Steps,
			Variables:   req.Variables,
			Timeout:     req.Timeout,
		},
		SemanticVersion: *semver,
	}

	nameForLog := logging.SanitizeLogValue(name)
	store := h.workflowStoreForRequest(r)
	if err := store.StoreWorkflow(r.Context(), vw); err != nil {
		h.logger.Error("Failed to update workflow", "name", nameForLog, "error", err)
		h.sendError(w, http.StatusInternalServerError, "failed to update workflow")
		return
	}

	h.sendJSON(w, http.StatusOK, vw)
}

// handleDeleteWorkflow handles DELETE /api/v1/workflows/{id}
func (h *WorkflowHandler) handleDeleteWorkflow(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil || h.configStore == nil {
		h.sendError(w, http.StatusServiceUnavailable, "workflow engine not available")
		return
	}

	name := mux.Vars(r)["id"]
	if name == "" {
		h.sendError(w, http.StatusBadRequest, "workflow name is required")
		return
	}

	nameForLog := logging.SanitizeLogValue(name)
	store := h.workflowStoreForRequest(r)

	// Retrieve all versions to delete
	versions, err := store.ListWorkflowVersions(r.Context(), name)
	if err != nil {
		h.logger.Error("Failed to list workflow versions for deletion", "name", nameForLog, "error", err)
		h.sendError(w, http.StatusInternalServerError, "failed to delete workflow")
		return
	}
	if len(versions) == 0 {
		h.sendError(w, http.StatusNotFound, fmt.Sprintf("workflow %q not found", name))
		return
	}

	for _, vw := range versions {
		if err := store.DeleteWorkflow(r.Context(), name, vw.SemanticVersion); err != nil {
			versionForLog := logging.SanitizeLogValue(vw.SemanticVersion.String())
			h.logger.Error("Failed to delete workflow version", "name", nameForLog, "version", versionForLog, "error", err)
			h.sendError(w, http.StatusInternalServerError, "failed to delete workflow")
			return
		}
	}

	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"deleted":  name,
		"versions": len(versions),
	})
}

// ExecuteWorkflowRequest is the request body for manually triggering a workflow.
type ExecuteWorkflowRequest struct {
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// handleExecuteWorkflow handles POST /api/v1/workflows/{id}/execute
func (h *WorkflowHandler) handleExecuteWorkflow(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil || h.configStore == nil {
		h.sendError(w, http.StatusServiceUnavailable, "workflow engine not available")
		return
	}

	name := mux.Vars(r)["id"]
	if name == "" {
		h.sendError(w, http.StatusBadRequest, "workflow name is required")
		return
	}

	var req ExecuteWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Body is optional; continue with empty variables
		req.Variables = nil
	}

	store := h.workflowStoreForRequest(r)
	vw, err := store.GetLatestWorkflow(r.Context(), name)
	if err != nil {
		h.sendError(w, http.StatusNotFound, fmt.Sprintf("workflow %q not found", name))
		return
	}

	nameForLog := logging.SanitizeLogValue(name)
	execution, err := h.engine.ExecuteWorkflow(r.Context(), vw.Workflow, req.Variables)
	if err != nil {
		h.logger.Error("Failed to execute workflow", "name", nameForLog, "error", err)
		h.sendError(w, http.StatusInternalServerError, "failed to start workflow execution")
		return
	}

	h.sendJSON(w, http.StatusAccepted, map[string]interface{}{
		"execution_id":  execution.ID,
		"workflow_name": execution.WorkflowName,
		"status":        execution.GetStatus(),
		"start_time":    execution.StartTime,
	})
}

// handleGetWorkflowExecutions handles GET /api/v1/workflows/{id}/executions
func (h *WorkflowHandler) handleGetWorkflowExecutions(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		h.sendError(w, http.StatusServiceUnavailable, "workflow engine not available")
		return
	}

	name := mux.Vars(r)["id"]
	if name == "" {
		h.sendError(w, http.StatusBadRequest, "workflow name is required")
		return
	}

	nameForLog := logging.SanitizeLogValue(name)
	all, err := h.engine.ListExecutions()
	if err != nil {
		h.logger.Error("Failed to list workflow executions", "name", nameForLog, "error", err)
		h.sendError(w, http.StatusInternalServerError, "failed to retrieve executions")
		return
	}

	// Filter to the requested workflow
	var executions []*workflow.WorkflowExecution
	for _, ex := range all {
		if ex.WorkflowName == name {
			executions = append(executions, ex)
		}
	}
	if executions == nil {
		executions = []*workflow.WorkflowExecution{}
	}

	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"executions": executions,
		"count":      len(executions),
	})
}

// sendJSON writes a JSON response with the given status code.
func (h *WorkflowHandler) sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// sendError writes a JSON error response.
func (h *WorkflowHandler) sendError(w http.ResponseWriter, status int, message string) {
	h.sendJSON(w, status, map[string]interface{}{
		"error": message,
	})
}
