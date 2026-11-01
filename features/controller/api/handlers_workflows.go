// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
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
	authorizeTenantFn func(w http.ResponseWriter, r *http.Request, tenantID string) (string, bool)
	// auditManager records approval decisions (Issue #4610); nil disables auditing.
	auditManager *audit.Manager
	// holdsPermissionFn reports whether the request's principal holds a permission.
	// The approval decision checks the gate's own approver_permission with it, in
	// addition to the route's workflow:approve. While unset, a gate that names an
	// approver permission cannot be decided.
	holdsPermissionFn func(r *http.Request, permissionID string) bool
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
// applies the tenant-crossing boundary to an explicitly selected tenant and
// returns its stored ID, writing the response and returning false when the
// caller may not use it.
func (h *WorkflowHandler) SetTenantResolution(
	rootTenant func(ctx context.Context) string,
	authorize func(w http.ResponseWriter, r *http.Request, tenantID string) (string, bool),
) {
	h.rootTenantFn = rootTenant
	h.authorizeTenantFn = authorize
}

// SetAuditManager wires the audit manager that records approval decisions (Issue #4610).
func (h *WorkflowHandler) SetAuditManager(m *audit.Manager) {
	h.auditManager = m
}

// SetPermissionCheck wires how the approval decision checks that the caller holds
// the approval gate's own approver_permission (Issue #4610).
func (h *WorkflowHandler) SetPermissionCheck(fn func(r *http.Request, permissionID string) bool) {
	h.holdsPermissionFn = fn
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
	// Approval routes precede /{id} so "approvals" is never read as a workflow name.
	// /validate precedes /{id} so "validate" is never read as a workflow name.
	router.Handle("/validate", wrap("read", h.handleValidateWorkflow)).Methods("POST")
	router.Handle("/parse-yaml", wrap("read", h.handleParseWorkflowYAML)).Methods("POST")
	router.Handle("/render-yaml", wrap("read", h.handleRenderWorkflowYAML)).Methods("POST")
	router.Handle("/approvals", wrap("read", h.handleListApprovals)).Methods("GET")
	router.Handle("/approvals/{approval_id}/decision", wrap("approve", h.handleDecideApproval)).Methods("POST")
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
// Every trigger route runs behind triggerTenantMiddleware, so the trigger manager
// scopes to the same tenant the workflow routes resolve (Issue #4640).
func (h *WorkflowHandler) RegisterTriggerRoutes(router *mux.Router) {
	if h.triggerAPI == nil {
		return
	}
	router.Use(h.triggerTenantMiddleware)
	h.triggerAPI.RegisterRoutes(router)
}

// triggerTenantMiddleware resolves the tenant a trigger request operates on
// exactly as the workflow routes do — a tenant-scoped caller's own tenant; for a
// root-scoped caller the deployment's root tenant or a ?tenant= that passes the
// ADR-025 crossing — and hands it to the trigger manager as ctxkeys.TenantID
// (Issue #4640). The trigger manager scopes every operation to that value, and a
// root-scoped caller's own context carries none, so before this every trigger
// operation refused root admins with "tenant context required". A trigger and the
// workflow it starts therefore always live in the same tenant.
func (h *WorkflowHandler) triggerTenantMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.workflowStoreForRequest(w, r)
		if !ok {
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxkeys.TenantID, store.TenantID())))
	})
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
	case scope.IsRoot(): //architecture:allow-root-scope -- root selects the tenant explicitly and the selection passes the ADR-025 crossing, or it is the root tenant itself
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

// executionScopeForRequest resolves the tenant whose executions the request reads
// and, when a config store is wired, the workflow store scoped to it. The tenant is
// the one workflows are stored and executions are run under (store.TenantID()), so a
// root-scoped caller reads the root tenant's runs rather than every tenant's. It
// writes the response and returns ok=false when the request is refused.
func (h *WorkflowHandler) executionScopeForRequest(w http.ResponseWriter, r *http.Request) (tenantID string, store *workflow.WorkflowStore, ok bool) {
	if h.configStore == nil {
		tenantID, _ = r.Context().Value(ctxkeys.TenantID).(string)
		return tenantID, nil, true
	}
	store, ok = h.workflowStoreForRequest(w, r)
	if !ok {
		return "", nil, false
	}
	return store.TenantID(), store, true
}

// executionLookupFailed answers a failed GetExecution: not found (including another
// tenant's run) is a 404, a store failure is a 500.
func (h *WorkflowHandler) executionLookupFailed(w http.ResponseWriter, execID, logMsg, nameForLog, execIDForLog string, err error) {
	// err may embed execID (user-tainted) via engine format strings — sanitize before logging.
	safeErrStr := ""
	if err != nil {
		safeErrStr = logging.SanitizeLogValue(err.Error())
		safeErrStr = strings.ReplaceAll(safeErrStr, "\n", "_")
		safeErrStr = strings.ReplaceAll(safeErrStr, "\r", "_")
	}
	if err != nil && !errors.Is(err, workflow.ErrExecutionNotFound) {
		h.logger.Error("Execution lookup failed", "name", nameForLog, "exec_id", execIDForLog, "error", safeErrStr)
		h.sendError(w, http.StatusInternalServerError, "failed to retrieve execution")
		return
	}
	h.logger.Error(logMsg, "name", nameForLog, "exec_id", execIDForLog, "error", safeErrStr)
	h.sendError(w, http.StatusNotFound, fmt.Sprintf("execution %q not found", execID))
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
	if selected := r.URL.Query().Get("tenant"); selected != "" {
		// The stored tenant ID, not the request value, is what the store key and
		// the execution context carry.
		return h.authorizeTenantFn(w, r, selected)
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

// workflowLastExecution is the most recent run of a workflow in the list summary.
type workflowLastExecution struct {
	ID        string                   `json:"id"`
	Status    workflow.ExecutionStatus `json:"status"`
	StartTime time.Time                `json:"start_time"`
}

// workflowListItem is one entry of the workflow list: the stored definition plus
// a summary of its triggers and latest run (Issue #4614). The summary fields are
// additive, so existing consumers of the definition are unaffected.
type workflowListItem struct {
	*workflow.VersionedWorkflow
	TriggerCount        int                    `json:"trigger_count"`
	EnabledTriggerCount int                    `json:"enabled_trigger_count"`
	LastExecution       *workflowLastExecution `json:"last_execution"`
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
		h.logger.Error("Failed to list workflows", "error", logging.SanitizeLogValue(err.Error()))
		h.sendError(w, http.StatusInternalServerError, "failed to list workflows")
		return
	}

	for i := range workflows {
		workflow.AssignStepIDs(workflows[i].Steps)
	}

	// One trigger query and one execution scan serve every row. Both are scoped to
	// the tenant the workflow store resolved, so another tenant's triggers and runs
	// are never counted.
	triggerCounts, enabledCounts := h.triggerCountsByWorkflow(r.Context(), store.TenantID())
	lastRuns := h.lastExecutionsByWorkflow(r.Context(), store.TenantID())

	items := make([]workflowListItem, 0, len(workflows))
	for _, wf := range workflows {
		items = append(items, workflowListItem{
			VersionedWorkflow:   wf,
			TriggerCount:        triggerCounts[wf.Name],
			EnabledTriggerCount: enabledCounts[wf.Name],
			LastExecution:       lastRuns[wf.Name],
		})
	}

	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"workflows": items,
		"count":     len(items),
	})
}

// triggerCountsByWorkflow returns per-workflow trigger totals and enabled
// (active) totals for the tenant, from a single ListTriggers call made with the
// tenant in context so the manager's own authorization applies. A missing manager
// or a failed query yields empty counts: the list stays usable without them.
func (h *WorkflowHandler) triggerCountsByWorkflow(ctx context.Context, tenantID string) (total, enabled map[string]int) {
	total, enabled = map[string]int{}, map[string]int{}
	if h.triggerManager == nil {
		return total, enabled
	}
	triggers, err := h.triggerManager.ListTriggers(context.WithValue(ctx, ctxkeys.TenantID, tenantID), nil)
	if err != nil {
		h.logger.Warn("Failed to list triggers for workflow summary", "error", logging.SanitizeLogValue(err.Error()))
		return total, enabled
	}
	for _, t := range triggers {
		if t.TenantID != tenantID {
			continue
		}
		total[t.WorkflowName]++
		if t.Status == trigger.TriggerStatusActive {
			enabled[t.WorkflowName]++
		}
	}
	return total, enabled
}

// lastExecutionsByWorkflow scans the tenant's executions once and returns the
// most recently started run per workflow name.
func (h *WorkflowHandler) lastExecutionsByWorkflow(ctx context.Context, tenantID string) map[string]*workflowLastExecution {
	last := map[string]*workflowLastExecution{}
	all, err := h.engine.ListExecutions(ctx, tenantID)
	if err != nil {
		h.logger.Warn("Failed to list executions for workflow summary", "error", logging.SanitizeLogValue(err.Error()))
		return last
	}
	for _, ex := range all {
		if ex.TenantID != tenantID {
			continue
		}
		if cur, ok := last[ex.WorkflowName]; ok && !ex.StartTime.After(cur.StartTime) {
			continue
		}
		last[ex.WorkflowName] = &workflowLastExecution{ID: ex.ID, Status: ex.GetStatus(), StartTime: ex.StartTime}
	}
	return last
}

// CreateWorkflowRequest is the request body for creating a workflow.
type CreateWorkflowRequest struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Version     string                 `json:"version,omitempty"`
	Steps       []workflow.Step        `json:"steps"`
	Variables   map[string]interface{} `json:"variables,omitempty"`
	Inputs      []workflow.InputSpec   `json:"inputs,omitempty"`
	Timeout     time.Duration          `json:"timeout,omitempty"`
	// OnFailure and ErrorWorkflows are the workflow-level failure policy
	// (Issue #4577): dropping them stored a workflow that behaved differently
	// from the definition that was submitted.
	OnFailure      workflow.FailureAction         `json:"on_failure,omitempty"`
	ErrorWorkflows []workflow.ErrorWorkflowConfig `json:"error_workflows,omitempty"`
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

	if err := workflow.ValidateInputSpecs(req.Inputs); err != nil {
		h.sendError(w, http.StatusBadRequest, err.Error())
		return
	}

	vw := &workflow.VersionedWorkflow{
		Workflow: workflow.Workflow{
			Name:           req.Name,
			Description:    req.Description,
			Version:        version,
			Steps:          req.Steps,
			Variables:      req.Variables,
			Inputs:         req.Inputs,
			Timeout:        req.Timeout,
			OnFailure:      req.OnFailure,
			ErrorWorkflows: req.ErrorWorkflows,
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

// ValidateWorkflowResponse is the result of a dry-run validation (Issue #4612).
type ValidateWorkflowResponse struct {
	Valid  bool                       `json:"valid"`
	Issues []workflow.ValidationIssue `json:"issues"`
}

// handleValidateWorkflow handles POST /api/v1/workflows/validate. It validates
// the submitted definition and reports every issue; it saves and runs nothing.
func (h *WorkflowHandler) handleValidateWorkflow(w http.ResponseWriter, r *http.Request) {
	var req CreateWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	issues := workflow.NewParser().ValidateWorkflowDetailed(workflow.Workflow{
		Name:           req.Name,
		Description:    req.Description,
		Version:        req.Version,
		Steps:          req.Steps,
		Variables:      req.Variables,
		Inputs:         req.Inputs,
		Timeout:        req.Timeout,
		OnFailure:      req.OnFailure,
		ErrorWorkflows: req.ErrorWorkflows,
	})
	if req.Version != "" {
		if _, err := workflow.ParseSemanticVersion(req.Version); err != nil {
			issues = append(issues, workflow.ValidationIssue{Path: "version", Message: "invalid version format"})
		}
	}
	if issues == nil {
		issues = []workflow.ValidationIssue{}
	}
	h.sendJSON(w, http.StatusOK, ValidateWorkflowResponse{Valid: len(issues) == 0, Issues: issues})
}

// ParseYAMLResponse is the result of parsing a YAML workflow document (Issue #4613).
type ParseYAMLResponse struct {
	Workflow workflow.Workflow          `json:"workflow"`
	Valid    bool                       `json:"valid"`
	Issues   []workflow.ValidationIssue `json:"issues"`
}

// readBoundedBody reads the request body up to maxStructuredRequestBodyBytes and
// answers 413 itself when the body is larger.
func (h *WorkflowHandler) readBoundedBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxStructuredRequestBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			h.sendError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			h.sendError(w, http.StatusBadRequest, "invalid request body")
		}
		return nil, false
	}
	return body, true
}

// handleParseWorkflowYAML handles POST /api/v1/workflows/parse-yaml. The body is
// the YAML document; the server parser is the authority. It stores nothing.
func (h *WorkflowHandler) handleParseWorkflowYAML(w http.ResponseWriter, r *http.Request) {
	body, ok := h.readBoundedBody(w, r)
	if !ok {
		return
	}
	parser := workflow.NewParser()
	wf, err := parser.ParseYAMLUnvalidated(body)
	if err != nil {
		// The error text can quote document content, so it is neither returned nor logged.
		h.logger.Debug("workflow YAML rejected")
		h.sendError(w, http.StatusBadRequest, "invalid workflow YAML")
		return
	}

	issues := parser.ValidateWorkflowDetailed(wf)
	if issues == nil {
		issues = []workflow.ValidationIssue{}
	}
	h.sendJSON(w, http.StatusOK, ParseYAMLResponse{Workflow: wf, Valid: len(issues) == 0, Issues: issues})
}

// handleRenderWorkflowYAML handles POST /api/v1/workflows/render-yaml. The body
// is workflow JSON; the response is the canonical YAML text. It stores nothing.
func (h *WorkflowHandler) handleRenderWorkflowYAML(w http.ResponseWriter, r *http.Request) {
	body, ok := h.readBoundedBody(w, r)
	if !ok {
		return
	}
	var req CreateWorkflowRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	out, err := workflow.NewParser().RenderYAML(workflow.Workflow{
		Name:           req.Name,
		Description:    req.Description,
		Version:        req.Version,
		Steps:          req.Steps,
		Variables:      req.Variables,
		Inputs:         req.Inputs,
		Timeout:        req.Timeout,
		OnFailure:      req.OnFailure,
		ErrorWorkflows: req.ErrorWorkflows,
	})
	if err != nil {
		h.logger.Debug("workflow YAML render rejected")
		h.sendError(w, http.StatusBadRequest, "workflow cannot be rendered as YAML")
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
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

	if err := workflow.ValidateInputSpecs(req.Inputs); err != nil {
		h.sendError(w, http.StatusBadRequest, err.Error())
		return
	}

	vw := &workflow.VersionedWorkflow{
		Workflow: workflow.Workflow{
			Name:           name,
			Description:    req.Description,
			Version:        version,
			Steps:          req.Steps,
			Variables:      req.Variables,
			Inputs:         req.Inputs,
			Timeout:        req.Timeout,
			OnFailure:      req.OnFailure,
			ErrorWorkflows: req.ErrorWorkflows,
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
	// Inputs are values for the workflow's declared inputs. They are merged
	// with Variables (an input wins on a name clash) and validated by the engine.
	Inputs map[string]interface{} `json:"inputs,omitempty"`
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
		req = ExecuteWorkflowRequest{}
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
	// ExecuteWorkflow is asynchronous and derives the execution's context from
	// this one, and the server cancels the request context as soon as the handler
	// returns — so the execution keeps the request's values (tenant, identity)
	// but not its cancellation, or every execution that outlives its request is
	// cancelled (Issue #4658).
	execCtx := context.WithValue(context.WithoutCancel(r.Context()), ctxkeys.TenantID, store.TenantID())

	nameForLog := logging.SanitizeLogValue(name)
	supplied := make(map[string]interface{}, len(req.Variables)+len(req.Inputs))
	for k, v := range req.Variables {
		supplied[k] = v
	}
	for k, v := range req.Inputs {
		supplied[k] = v
	}
	execution, err := h.engine.ExecuteWorkflow(execCtx, vw.Workflow, supplied)
	if err != nil {
		if inputErr, ok := workflow.AsInputsError(err); ok {
			h.sendJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":  "invalid workflow inputs",
				"fields": inputErr.Fields,
			})
			return
		}
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
	tenantID, _, ok := h.executionScopeForRequest(w, r)
	if !ok {
		return
	}
	all, err := h.engine.ListExecutions(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to list workflow executions", "name", nameForLog, "error", logging.SanitizeLogValue(err.Error()))
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

	tenantID, store, ok := h.executionScopeForRequest(w, r)
	if !ok {
		return
	}
	execution, err := h.engine.GetExecution(r.Context(), tenantID, execID)
	if err != nil || execution == nil {
		h.executionLookupFailed(w, execID, "Execution not found", nameForLog, execIDForLog, err)
		return
	}

	if execution.WorkflowName != name {
		h.sendError(w, http.StatusNotFound, fmt.Sprintf("execution %q not found for workflow %q", execID, name))
		return
	}

	// Tenant isolation: verify the workflow exists in the calling tenant's namespace.
	// A future GET /api/v1/executions/{exec_id} lookup-by-ID endpoint can bypass this
	// once executions carry a tenant_id field.
	if store != nil {
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
	tenantID, store, ok := h.executionScopeForRequest(w, r)
	if !ok {
		return
	}
	execution, err := h.engine.GetExecution(r.Context(), tenantID, execID)
	if err != nil || execution == nil {
		h.executionLookupFailed(w, execID, "Execution not found for cancel", nameForLog, execIDForLog, err)
		return
	}

	if execution.WorkflowName != name {
		h.sendError(w, http.StatusNotFound, fmt.Sprintf("execution %q not found for workflow %q", execID, name))
		return
	}

	// Tenant isolation: reject cross-tenant cancellation.
	if store != nil {
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
		// A record read from the store has no live owner on this node: only the node
		// running the execution can cancel it.
		if errors.Is(cancelErr, workflow.ErrExecutionNotFound) {
			h.sendError(w, http.StatusNotFound, fmt.Sprintf("execution %q not found", execID))
			return
		}
		h.logger.Error("Failed to cancel execution", "name", nameForLog, "exec_id", execIDForLog,
			"error", logging.SanitizeLogValue(cancelErr.Error()))
		h.sendError(w, http.StatusInternalServerError, "failed to cancel execution")
		return
	}

	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"cancelled": execID,
	})
}

// approvalView is the API shape of a workflow approval. It never carries the
// checkpoint reference or resume-claim state.
type approvalView struct {
	ApprovalID         string     `json:"approval_id"`
	WorkflowName       string     `json:"workflow_name"`
	ExecutionID        string     `json:"execution_id"`
	StepID             string     `json:"step_id"`
	StepName           string     `json:"step_name"`
	Message            string     `json:"message"`
	ApproverPermission string     `json:"approver_permission,omitempty"`
	RequestedBy        string     `json:"requested_by,omitempty"`
	Status             string     `json:"status"`
	RequestedAt        time.Time  `json:"requested_at"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
	DecidedBy          string     `json:"decided_by,omitempty"`
	DecidedAt          *time.Time `json:"decided_at,omitempty"`
	Justification      string     `json:"justification,omitempty"`
}

func toApprovalView(a *business.WorkflowApproval) approvalView {
	v := approvalView{
		ApprovalID:         a.ApprovalID,
		WorkflowName:       a.WorkflowName,
		ExecutionID:        a.ExecutionID,
		StepID:             a.StepID,
		StepName:           a.StepName,
		Message:            a.Message,
		ApproverPermission: a.ApproverPermission,
		RequestedBy:        a.RequestedBy,
		Status:             a.Status,
		RequestedAt:        a.RequestedAt,
		DecidedBy:          a.DecidedBy,
		Justification:      a.Justification,
	}
	if !a.ExpiresAt.IsZero() {
		v.ExpiresAt = &a.ExpiresAt
	}
	if !a.DecidedAt.IsZero() {
		v.DecidedAt = &a.DecidedAt
	}
	return v
}

// ApprovalDecisionRequest is the body of POST /api/v1/workflows/approvals/{approval_id}/decision.
type ApprovalDecisionRequest struct {
	Decision      string `json:"decision"` // "approve" or "reject"
	Justification string `json:"justification"`
}

// maxApprovalDecisionBody bounds the decision request body.
const maxApprovalDecisionBody = 16 << 10

// approvalStore returns the engine's approval store, writing a 503 when the
// engine or its store is not available.
func (h *WorkflowHandler) approvalStore(w http.ResponseWriter) (business.ApprovalStore, bool) {
	if h.engine == nil || h.engine.ApprovalStore() == nil {
		h.sendError(w, http.StatusServiceUnavailable, "workflow approvals not available")
		return nil, false
	}
	return h.engine.ApprovalStore(), true
}

// handleListApprovals handles GET /api/v1/workflows/approvals: the caller's
// tenant's pending approvals, oldest first.
func (h *WorkflowHandler) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	store, ok := h.approvalStore(w)
	if !ok {
		return
	}
	tenantStore, ok := h.workflowStoreForRequest(w, r)
	if !ok {
		return
	}
	tenantID := tenantStore.TenantID()
	pending, err := store.ListPending(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to list workflow approvals", "error", logging.SanitizeLogValue(err.Error()))
		h.sendError(w, http.StatusInternalServerError, "failed to list approvals")
		return
	}
	views := make([]approvalView, 0, len(pending))
	for _, a := range pending {
		views = append(views, toApprovalView(a))
	}
	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"approvals": views,
		"total":     len(views),
	})
}

// handleDecideApproval handles POST /api/v1/workflows/approvals/{approval_id}/decision.
// The route gate has already required workflow:approve at strong assurance. Here the
// approval is looked up in the caller's tenant only (a foreign approval is a 404), the
// gate's own approver_permission is checked, the run's initiator is refused, and the
// decision is recorded with a compare-and-set before the run is resumed.
func (h *WorkflowHandler) handleDecideApproval(w http.ResponseWriter, r *http.Request) {
	store, ok := h.approvalStore(w)
	if !ok {
		return
	}
	tenantStore, ok := h.workflowStoreForRequest(w, r)
	if !ok {
		return
	}
	tenantID := tenantStore.TenantID()
	approvalID := mux.Vars(r)["approval_id"]

	var req ApprovalDecisionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxApprovalDecisionBody)).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var status string
	switch req.Decision {
	case "approve":
		status = business.ApprovalStatusApproved
	case "reject":
		status = business.ApprovalStatusRejected
	default:
		h.sendError(w, http.StatusBadRequest, `decision must be "approve" or "reject"`)
		return
	}

	rec, err := store.GetApproval(r.Context(), tenantID, approvalID)
	if err != nil {
		if errors.Is(err, business.ErrApprovalNotFound) {
			h.sendError(w, http.StatusNotFound, "approval not found")
			return
		}
		h.logger.Error("Failed to load workflow approval", "error", logging.SanitizeLogValue(err.Error()))
		h.sendError(w, http.StatusInternalServerError, "failed to load approval")
		return
	}

	if rec.ApproverPermission != "" && (h.holdsPermissionFn == nil || !h.holdsPermissionFn(r, rec.ApproverPermission)) {
		h.sendError(w, http.StatusForbidden, "caller lacks the permission this approval requires")
		return
	}

	// A decision is attributed to a named principal, and a lapsed gate stays lapsed
	// even before ExpireDue has swept it.
	principalID, _ := r.Context().Value(ctxkeys.UserIDKey).(string)
	if principalID == "" {
		h.sendError(w, http.StatusForbidden, "decision requires an identified principal")
		return
	}
	if !rec.ExpiresAt.IsZero() && !time.Now().Before(rec.ExpiresAt) {
		h.sendError(w, http.StatusConflict, "approval has expired")
		return
	}
	if principalID == rec.RequestedBy {
		h.sendJSON(w, http.StatusForbidden, map[string]interface{}{
			"error": "the principal that started a run cannot approve it",
			"code":  "SELF_APPROVAL",
		})
		return
	}

	justification := strings.TrimSpace(req.Justification)
	if err := store.DecideApproval(r.Context(), tenantID, approvalID, status, principalID, justification, time.Now()); err != nil {
		switch {
		case errors.Is(err, business.ErrApprovalAlreadyDecided):
			h.sendError(w, http.StatusConflict, "approval already decided")
		case errors.Is(err, business.ErrApprovalNotFound):
			h.sendError(w, http.StatusNotFound, "approval not found")
		default:
			h.logger.Error("Failed to record workflow approval decision", "error", logging.SanitizeLogValue(err.Error()))
			h.sendError(w, http.StatusInternalServerError, "failed to record decision")
		}
		return
	}
	h.emitApprovalDecisionAudit(r.Context(), rec, req.Decision, principalID, justification)

	// The decision is durable. A resume that cannot start now is retried by engine
	// recovery, so the caller is told the decision stands rather than that it failed.
	resumed := true
	var executionStatus string
	exec, err := h.engine.ResumeFromApproval(r.Context(), rec.TenantID, rec.ApprovalID)
	if err != nil {
		resumed = false
		h.logger.Warn("Approved workflow run could not be resumed; recovery will retry",
			"approval_id", logging.SanitizeLogValue(rec.ApprovalID),
			"error", logging.SanitizeLogValue(err.Error()))
	} else if exec != nil {
		executionStatus = string(exec.GetStatus())
	}
	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"approval_id":      rec.ApprovalID,
		"decision":         req.Decision,
		"execution_id":     rec.ExecutionID,
		"resumed":          resumed,
		"execution_status": executionStatus,
	})
}

// emitApprovalDecisionAudit records who decided which approval, how, and why.
func (h *WorkflowHandler) emitApprovalDecisionAudit(ctx context.Context, rec *business.WorkflowApproval, decision, principalID, justification string) {
	if h.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(rec.TenantID).
		Type(business.AuditEventAuthorization).
		Action("workflow.approval_decided").
		User(principalID, business.AuditUserTypeHuman).
		Resource("workflow_approval", logging.SanitizeLogValue(rec.ApprovalID), logging.SanitizeLogValue(rec.WorkflowName)).
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityMedium).
		Details(map[string]interface{}{
			"approval_id":   logging.SanitizeLogValue(rec.ApprovalID),
			"execution_id":  logging.SanitizeLogValue(rec.ExecutionID),
			"decision":      decision,
			"justification": logging.SanitizeLogValue(justification),
			"requested_by":  logging.SanitizeLogValue(rec.RequestedBy),
		})
	if err := h.auditManager.RecordEvent(ctx, b); err != nil {
		h.logger.Warn("Failed to emit approval decision audit event",
			"approval_id", logging.SanitizeLogValue(rec.ApprovalID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
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
