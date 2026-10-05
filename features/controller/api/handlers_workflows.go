// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// WorkflowHandler handles workflow and trigger REST API requests.
// It bridges the controller REST layer with the workflow engine and trigger manager.
type WorkflowHandler struct {
	engine         *workflow.Engine
	configStore    cfgconfig.ConfigStore
	triggerManager trigger.TriggerManager
	triggerAPI     *trigger.APIHandler
	logger         logging.Logger
	fleetQuery     fleet.FleetQuery // Issue #609: fleet query for script dispatch targeting
	// requirePermFn gates workflow routes by permission. When nil, routes are ungated (test use only).
	// Wired from Server.requirePermission via SetRequirePermFn in SetWorkflowHandler (Issue #2725).
	requirePermFn func(resourceType, action string) func(http.Handler) http.Handler
	// rootTenantFn resolves the deployment's root tenant ("" when none) and
	// authorizeTenantFn applies ADR-025's crossing to a tenant a root-scoped caller
	// selects with ?tenant=. Both are wired from the Server in SetWorkflowHandler
	// (Issue #4576); while unset, a root-scoped caller is refused.
	rootTenantFn      func(ctx context.Context) string
	authorizeTenantFn func(w http.ResponseWriter, r *http.Request, tenantID string) bool
}

// NewWorkflowHandler creates a new WorkflowHandler.
func NewWorkflowHandler(
	engine *workflow.Engine,
	configStore cfgconfig.ConfigStore,
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

// SetRequirePermFn wires the server's permission-check factory into WorkflowHandler so
// RegisterWorkflowRoutes can gate each route without importing the concrete Server type (Issue #2725).
func (h *WorkflowHandler) SetRequirePermFn(fn func(resourceType, action string) func(http.Handler) http.Handler) {
	h.requirePermFn = fn
}

// SetTenantResolution wires how a root-scoped caller's tenant is resolved
// (Issue #4576): rootTenant returns the deployment's root tenant, and authorize
// applies the tenant-crossing boundary to an explicitly selected tenant, writing
// the response and returning false when the caller may not use it.
func (h *WorkflowHandler) SetTenantResolution(
	rootTenant func(ctx context.Context) string,
	authorize func(w http.ResponseWriter, r *http.Request, tenantID string) bool,
) {
	h.rootTenantFn = rootTenant
	h.authorizeTenantFn = authorize
}

// RegisterWorkflowRoutes registers workflow CRUD and execution routes on the provided subrouter.
// Each route is wrapped with the permission gate set by SetRequirePermFn (Issue #2725).
//
// Fails closed (Issue #4316): a nil requirePermFn returns an error and registers no
// routes at all, instead of the previous behavior of silently registering every
// workflow route ungated. A misconfigured gate is a startup-time programming error —
// SetWorkflowHandler always calls SetRequirePermFn before this method in production —
// not a condition a live server should ever serve requests under. Callers that
// deliberately want ungated routes for a unit test must wire an explicit
// always-allow gate via SetRequirePermFn rather than relying on nil to mean that.
func (h *WorkflowHandler) RegisterWorkflowRoutes(router *mux.Router) error {
	gate := h.requirePermFn
	if gate == nil {
		return fmt.Errorf("workflow routes: no permission gate wired; call SetRequirePermFn before RegisterWorkflowRoutes")
	}
	wrap := func(action string, fn http.HandlerFunc) http.Handler {
		return gate("workflow", action)(fn)
	}
	router.Handle("", wrap("list", h.handleListWorkflows)).Methods("GET")
	router.Handle("", wrap("write", h.handleCreateWorkflow)).Methods("POST")
	router.Handle("/{id}", wrap("read", h.handleGetWorkflow)).Methods("GET")
	router.Handle("/{id}", wrap("write", h.handleUpdateWorkflow)).Methods("PUT")
	router.Handle("/{id}", wrap("write", h.handleDeleteWorkflow)).Methods("DELETE")
	router.Handle("/{id}/execute", wrap("execute", h.handleExecuteWorkflow)).Methods("POST")
	router.Handle("/{id}/executions", wrap("read", h.handleGetWorkflowExecutions)).Methods("GET")
	router.Handle("/{id}/executions/{exec_id}", wrap("read", h.handleGetExecution)).Methods("GET")
	router.Handle("/{id}/executions/{exec_id}/cancel", wrap("cancel", h.handleCancelExecution)).Methods("POST")
	return nil
}

// NewRegistrationApprovalHook creates a RegistrationApprovalHook backed by this handler's
// workflow engine and config store. If the engine or config store are unavailable it
// returns an AlwaysApproveHook so the controller always has a valid (if permissive) hook.
func (h *WorkflowHandler) NewRegistrationApprovalHook(logger logging.Logger) RegistrationApprovalHook {
	if h.engine == nil || h.configStore == nil {
		return &AlwaysApproveHook{}
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

// workflowStoreForRequest returns a WorkflowStore scoped to the caller's
// ctxkeys.TenantScope (Issue #4335), or writes a 404 and returns ok=false when the
// scope is unset: a request that lost its tenant scope must never be served from
// some default bucket another caller also uses.
//
// A root-scoped caller's workflows live in the deployment's root tenant, or in a
// tenant it selects with ?tenant=, subject to the ADR-025 crossing (Issue #4576).
// The store is never given an empty tenant: the config store requires one, so an
// empty tenant turned every root-scoped create into a 500. When no root tenant can
// be resolved the request is a 400 asking for ?tenant=.
//
// The store's tenant is also the tenant an execution runs under (Issue #4576),
// so the tenant a workflow is stored in and the tenant its steps act on are
// always the same one.
func (h *WorkflowHandler) workflowStoreForRequest(w http.ResponseWriter, r *http.Request) (*workflow.WorkflowStore, bool) {
	var tenantID string
	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	switch {
	case scope.IsRoot():
		resolved, ok := h.rootScopedTenant(w, r)
		if !ok {
			return nil, false
		}
		tenantID = resolved
	case scope.IsTenant() && scope.Path() != "":
		tenantID = scope.Path()
	default:
		h.logger.Warn("Workflow request refused: caller tenant scope is unset")
		h.sendError(w, http.StatusNotFound, "not found")
		return nil, false
	}
	return workflow.NewWorkflowStore(h.configStore, tenantID), true
}

// rootScopedTenant resolves the tenant a root-scoped request operates on
// (Issue #4576): ?tenant= when given, after the crossing check, else the
// deployment's root tenant. It writes the response and returns false when the
// tenant is refused or cannot be resolved.
func (h *WorkflowHandler) rootScopedTenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.rootTenantFn == nil || h.authorizeTenantFn == nil {
		h.logger.Error("Workflow request refused: tenant resolution is not wired")
		h.sendError(w, http.StatusServiceUnavailable, "workflow tenant resolution not available")
		return "", false
	}
	if tenantID := r.URL.Query().Get("tenant"); tenantID != "" {
		if !h.authorizeTenantFn(w, r, tenantID) {
			return "", false
		}
		return tenantID, true
	}
	if tenantID := h.rootTenantFn(r.Context()); tenantID != "" {
		return tenantID, true
	}
	h.sendError(w, http.StatusBadRequest,
		"tenant is required: no root tenant could be resolved, pass ?tenant=<id>")
	return "", false
}

// refuseFilesystemWorkflowReference writes a 400 and returns false when wf
// references a workflow by filesystem path anywhere in its definition (Issue
// #4638): composed workflows are referenced by workflow_name and resolved from
// the executing tenant's store, never from the controller's filesystem.
func (h *WorkflowHandler) refuseFilesystemWorkflowReference(w http.ResponseWriter, wf *workflow.Workflow) bool {
	found, err := workflow.ContainsFilesystemWorkflowReference(*wf)
	if err != nil {
		h.logger.Error("Failed to inspect workflow definition", "error", logging.SanitizeLogValue(err.Error()))
		h.sendError(w, http.StatusBadRequest, "invalid workflow definition")
		return false
	}
	if found {
		h.sendError(w, http.StatusBadRequest, workflow.ErrFilesystemWorkflowReference.Error())
		return false
	}
	return true
}

// handleListWorkflows handles GET /api/v1/workflows
func (h *WorkflowHandler) handleListWorkflows(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil || h.configStore == nil {
		h.sendError(w, http.StatusServiceUnavailable, "workflow engine not available")
		return
	}

	store, ok := h.workflowStoreForRequest(w, r)
	if !ok {
		return
	}
	workflows, err := store.ListWorkflows(r.Context())
	if err != nil {
		h.logger.Error("Failed to list workflows", "error", err)
		h.sendError(w, http.StatusInternalServerError, "failed to list workflows")
		return
	}

	for i := range workflows {
		workflow.AssignStepIDs(workflows[i].Steps)
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
	if !h.refuseFilesystemWorkflowReference(w, &vw.Workflow) {
		return
	}

	store, ok := h.workflowStoreForRequest(w, r)
	if !ok {
		return
	}
	nameForLog := logging.SanitizeLogValue(req.Name)
	if err := store.StoreWorkflow(r.Context(), vw); err != nil {
		h.logger.Error("Failed to create workflow", "name", nameForLog, "error", logging.SanitizeLogValue(err.Error()))
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
	store, ok := h.workflowStoreForRequest(w, r)
	if !ok {
		return
	}
	vw, err := store.GetLatestWorkflow(r.Context(), name)
	if err != nil {
		h.logger.Error("Failed to get workflow", "name", nameForLog, "error", logging.SanitizeLogValue(err.Error()))
		h.sendError(w, http.StatusNotFound, fmt.Sprintf("workflow %q not found", name))
		return
	}

	workflow.AssignStepIDs(vw.Steps)
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
	if !h.refuseFilesystemWorkflowReference(w, &vw.Workflow) {
		return
	}

	nameForLog := logging.SanitizeLogValue(name)
	store, ok := h.workflowStoreForRequest(w, r)
	if !ok {
		return
	}
	if err := store.StoreWorkflow(r.Context(), vw); err != nil {
		h.logger.Error("Failed to update workflow", "name", nameForLog, "error", logging.SanitizeLogValue(err.Error()))
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
	store, ok := h.workflowStoreForRequest(w, r)
	if !ok {
		return
	}

	// Retrieve all versions to delete
	versions, err := store.ListWorkflowVersions(r.Context(), name)
	if err != nil {
		h.logger.Error("Failed to list workflow versions for deletion", "name", nameForLog, "error", logging.SanitizeLogValue(err.Error()))
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
			h.logger.Error("Failed to delete workflow version", "name", nameForLog, "version", versionForLog, "error", logging.SanitizeLogValue(err.Error()))
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

	store, ok := h.workflowStoreForRequest(w, r)
	if !ok {
		return
	}
	vw, err := store.GetLatestWorkflow(r.Context(), name)
	if err != nil {
		h.sendError(w, http.StatusNotFound, fmt.Sprintf("workflow %q not found", name))
		return
	}

	// The engine takes the execution's authenticated tenant from ctxkeys.TenantID,
	// and tenant-scoped steps act on exactly that tenant (Issue #4338). A
	// root-scoped caller's context carries "", so without this its executions
	// had no tenant and every tenant-scoped step refused to run. Run under the
	// tenant the workflow was resolved in — the root tenant, or one the caller
	// was authorized to select (Issue #4576).
	execCtx := context.WithValue(r.Context(), ctxkeys.TenantID, store.TenantID())

	nameForLog := logging.SanitizeLogValue(name)
	execution, err := h.engine.ExecuteWorkflow(execCtx, vw.Workflow, req.Variables)
	if err != nil {
		h.logger.Error("Failed to execute workflow", "name", nameForLog, "error", logging.SanitizeLogValue(err.Error()))
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

	// Tenant isolation (Issue #4316): the engine's execution list is not itself
	// tenant-scoped, so a caller guessing another tenant's workflow name could
	// otherwise read its execution history. Gate only when there is something to
	// leak — a name with no matching executions (including one nobody has created
	// yet) legitimately answers with an empty list without a store round trip,
	// mirroring handleGetExecution/handleCancelExecution's check on this handler's
	// sibling routes.
	if len(executions) > 0 && h.configStore != nil {
		store, ok := h.workflowStoreForRequest(w, r)
		if !ok {
			return
		}
		if _, storeErr := store.GetLatestWorkflow(r.Context(), name); storeErr != nil {
			h.logger.Error("Tenant isolation check failed for workflow executions list", "name", nameForLog)
			h.sendError(w, http.StatusForbidden, "access denied")
			return
		}
	}

	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"executions": executions,
		"count":      len(executions),
	})
}

// handleGetExecution handles GET /api/v1/workflows/{id}/executions/{exec_id}
func (h *WorkflowHandler) handleGetExecution(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		h.sendError(w, http.StatusServiceUnavailable, "workflow engine not available")
		return
	}

	vars := mux.Vars(r)
	name := vars["id"]
	execID := vars["exec_id"]

	if name == "" || execID == "" {
		h.sendError(w, http.StatusBadRequest, "workflow name and execution ID are required")
		return
	}

	// Sequential-reassignment form required for CodeQL's ReplaceSanitizer to recognise
	// these values as sanitized (logging.SanitizeLogValue alone is not modelled by CodeQL).
	nameForLog := logging.SanitizeLogValue(name)
	nameForLog = strings.ReplaceAll(nameForLog, "\n", "_")
	nameForLog = strings.ReplaceAll(nameForLog, "\r", "_")
	execIDForLog := logging.SanitizeLogValue(execID)
	execIDForLog = strings.ReplaceAll(execIDForLog, "\n", "_")
	execIDForLog = strings.ReplaceAll(execIDForLog, "\r", "_")

	execution, err := h.engine.GetExecution(execID)
	if err != nil || execution == nil {
		// err may embed execID (user-tainted) via engine format strings — sanitize before logging.
		safeErrStr := ""
		if err != nil {
			safeErrStr = logging.SanitizeLogValue(err.Error())
			safeErrStr = strings.ReplaceAll(safeErrStr, "\n", "_")
			safeErrStr = strings.ReplaceAll(safeErrStr, "\r", "_")
		}
		h.logger.Error("Execution not found", "name", nameForLog, "exec_id", execIDForLog, "error", safeErrStr)
		h.sendError(w, http.StatusNotFound, fmt.Sprintf("execution %q not found", execID))
		return
	}

	if execution.WorkflowName != name {
		h.sendError(w, http.StatusNotFound, fmt.Sprintf("execution %q not found for workflow %q", execID, name))
		return
	}

	// Tenant isolation: verify the workflow exists in the calling tenant's namespace.
	// A future GET /api/v1/executions/{exec_id} lookup-by-ID endpoint can bypass this
	// once executions carry a tenant_id field.
	if h.configStore != nil {
		store, ok := h.workflowStoreForRequest(w, r)
		if !ok {
			return
		}
		if _, storeErr := store.GetLatestWorkflow(r.Context(), name); storeErr != nil {
			h.logger.Error("Tenant isolation check failed for execution get",
				"name", nameForLog, "exec_id", execIDForLog)
			h.sendError(w, http.StatusForbidden, "access denied")
			return
		}
	}

	h.sendJSON(w, http.StatusOK, execution)
}

// handleCancelExecution handles POST /api/v1/workflows/{id}/executions/{exec_id}/cancel
func (h *WorkflowHandler) handleCancelExecution(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		h.sendError(w, http.StatusServiceUnavailable, "workflow engine not available")
		return
	}

	vars := mux.Vars(r)
	name := vars["id"]
	execID := vars["exec_id"]

	if name == "" || execID == "" {
		h.sendError(w, http.StatusBadRequest, "workflow name and execution ID are required")
		return
	}

	// Sequential-reassignment form required for CodeQL's ReplaceSanitizer to recognise
	// these values as sanitized (logging.SanitizeLogValue alone is not modelled by CodeQL).
	nameForLog := logging.SanitizeLogValue(name)
	nameForLog = strings.ReplaceAll(nameForLog, "\n", "_")
	nameForLog = strings.ReplaceAll(nameForLog, "\r", "_")
	execIDForLog := logging.SanitizeLogValue(execID)
	execIDForLog = strings.ReplaceAll(execIDForLog, "\n", "_")
	execIDForLog = strings.ReplaceAll(execIDForLog, "\r", "_")

	// Pre-check existence before acting. CancelExecution returns nil for already-terminal
	// executions (it skips the cancel when Cancel func is nil) and a plain error string for
	// not-found — neither signal is suitable for HTTP status mapping, so we gate here.
	execution, err := h.engine.GetExecution(execID)
	if err != nil || execution == nil {
		// err may embed execID (user-tainted) via engine format strings — sanitize before logging.
		safeErrStr := ""
		if err != nil {
			safeErrStr = logging.SanitizeLogValue(err.Error())
			safeErrStr = strings.ReplaceAll(safeErrStr, "\n", "_")
			safeErrStr = strings.ReplaceAll(safeErrStr, "\r", "_")
		}
		h.logger.Error("Execution not found for cancel", "name", nameForLog, "exec_id", execIDForLog, "error", safeErrStr)
		h.sendError(w, http.StatusNotFound, fmt.Sprintf("execution %q not found", execID))
		return
	}

	if execution.WorkflowName != name {
		h.sendError(w, http.StatusNotFound, fmt.Sprintf("execution %q not found for workflow %q", execID, name))
		return
	}

	// Tenant isolation: reject cross-tenant cancellation.
	if h.configStore != nil {
		store, ok := h.workflowStoreForRequest(w, r)
		if !ok {
			return
		}
		if _, storeErr := store.GetLatestWorkflow(r.Context(), name); storeErr != nil {
			h.logger.Error("Tenant isolation check failed for execution cancel",
				"name", nameForLog, "exec_id", execIDForLog)
			h.sendError(w, http.StatusForbidden, "access denied")
			return
		}
	}

	// Reject already-terminal executions before calling CancelExecution.
	status := execution.GetStatus()
	if status == workflow.StatusCompleted || status == workflow.StatusFailed || status == workflow.StatusCancelled {
		h.sendError(w, http.StatusConflict, "execution is already in a terminal state")
		return
	}

	if cancelErr := h.engine.CancelExecution(execID); cancelErr != nil {
		h.logger.Error("Failed to cancel execution", "name", nameForLog, "exec_id", execIDForLog,
			"error", logging.SanitizeLogValue(cancelErr.Error()))
		h.sendError(w, http.StatusInternalServerError, "failed to cancel execution")
		return
	}

	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"cancelled": execID,
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
