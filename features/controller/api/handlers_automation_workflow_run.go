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

	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	automationActionWorkflowRun = "automation.workflow.run"

	// automationArtifactKindExecution is the artifact kind under which a run records
	// the workflow executions it started.
	automationArtifactKindExecution = "workflow_execution"

	// automationWorkflowBodyMaxBytes bounds the request body of a workflow start.
	automationWorkflowBodyMaxBytes = 64 << 10
	// automationWorkflowMaxInputs bounds how many inputs one start may supply.
	automationWorkflowMaxInputs = 64
	// automationWorkflowInputMaxLen bounds the encoded size of one input value.
	automationWorkflowInputMaxLen = 4096
)

// AutomationWorkflowRunRequest starts one workflow version. Version is required: there
// is no "latest" for a grant. Inputs are the values for the workflow's declared inputs
// and nothing else; the restricted mode, the run, the grant and the ceiling are never
// request fields (an unknown field is refused).
type AutomationWorkflowRunRequest struct {
	Version string                 `json:"version"`
	Inputs  map[string]interface{} `json:"inputs"`
}

// AutomationWorkflowRunResponse describes the execution a grant started. OwnerTenant is
// the tenant whose library holds the workflow; it differs from TenantID for an inherited
// workflow, while the execution itself belongs to TenantID.
type AutomationWorkflowRunResponse struct {
	ExecutionID  string `json:"execution_id"`
	TenantID     string `json:"tenant_id"`
	OwnerTenant  string `json:"owner_tenant"`
	WorkflowName string `json:"workflow_name"`
	Version      string `json:"version"`
	ApprovalHash string `json:"approval_hash"`
	Status       string `json:"status"`
}

// workflowRunEvidence is what the audit record of a workflow call names: the workflow
// as far as it was resolved and evaluated when the call ended.
type workflowRunEvidence struct {
	name         string
	version      string
	approvalHash string
	owner        string
}

func (e *workflowRunEvidence) details() []auditDetail {
	return []auditDetail{
		{Key: "workflow_name", Value: e.name},
		{Key: "workflow_version", Value: e.version},
		{Key: "approval_hash", Value: e.approvalHash},
		{Key: "workflow_owner_tenant", Value: e.owner},
	}
}

// automationWorkflowEnv is what the workflow routes need from the server.
type automationWorkflowEnv struct {
	handler   *WorkflowHandler
	evaluator *ContentApprovalEvaluator
}

// workflowHandlerOrNil returns the wired workflow handler, or nil while the workflow
// engine is not wired.
func (s *Server) workflowHandlerOrNil() *WorkflowHandler {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.workflowHandler
}

// automationWorkflowEnv gathers the engine, the workflow store and the approval
// evaluator the workflow routes depend on. An error means a dependency is not wired.
func (s *Server) automationWorkflowEnv() (*automationWorkflowEnv, error) {
	h := s.workflowHandlerOrNil()
	if h == nil || h.engine == nil || h.configStore == nil {
		return nil, errors.New("the workflow engine is not wired")
	}
	if s.tenantManager == nil {
		return nil, errors.New("tenant manager is not wired")
	}
	ev, err := NewContentApprovalEvaluator(s.ContentApprovalStore(),
		NewConfigServiceTrustedKeyResolver(s.configService), s.PrivilegeStore())
	if err != nil {
		return nil, err
	}
	return &automationWorkflowEnv{handler: h, evaluator: ev.WithWorkflowPublicationVerifier(s.VerifyWorkflowPublication)}, nil
}

// auditWorkflowCall records one outcome of a workflow route under the grant, run and
// event, naming the workflow evidence.
func (s *Server) auditWorkflowCall(ctx context.Context, run *RunBinding, result business.AuditResult, ev *workflowRunEvidence, extra ...auditDetail) {
	details := append(ev.details(), extra...)
	s.emitAutomationAudit(ctx, run.GrantID, run.ID, run.TenantID, run.GrantTenantID, run.EventRef,
		automationActionWorkflowRun, result, details...)
}

// refuseWorkflowRun audits a refused workflow start with its reason and answers it.
func (s *Server) refuseWorkflowRun(w http.ResponseWriter, r *http.Request, run *RunBinding, ev *workflowRunEvidence, status int, message, code, reason string) {
	s.auditWorkflowCall(r.Context(), run, business.AuditResultDenied, ev,
		auditDetail{Key: "reason", Value: reason}, auditDetail{Key: "code", Value: code})
	s.writeErrorResponse(w, status, message, code)
}

// workflowRunGuard is the run guard handed to the engine: the run is live and its grant
// is neither revoked nor expired. The engine calls it before every step, so a revocation
// or an end reaches a running workflow at its next step. It re-reads the durable stores
// on every call.
func (s *Server) workflowRunGuard(run *RunBinding) workflow.RunGuard {
	return func(ctx context.Context) error { return s.automationRunGuard(ctx, run.ID, run.GrantID) }
}

// handleAutomationPostWorkflowRun handles
// POST /api/v1/automation/runs/{run_id}/workflows/{name}.
//
// It is the grant counterpart of handleExecuteWorkflow and a separate path on purpose:
// handleExecuteWorkflow runs the latest version for an operator, unrestricted, under the
// operator's tenant. This route has no operator; the version must be named, it is
// resolved once through the run tenant's library chain (run tenant first, up to the
// ceiling of the grant), evaluated under the owner tenant's mode and records, and the
// object that was evaluated is the object that runs. The execution is always
// restricted: the only engine entry point used here is the restricted one.
func (s *Server) handleAutomationPostWorkflowRun(w http.ResponseWriter, r *http.Request) {
	run := automationRunFromContext(r.Context())
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if run == nil || principal == nil {
		s.writeErrorResponse(w, http.StatusForbidden, "The automation run does not permit this request", "AUTOMATION_RUN_DENIED")
		return
	}
	ev := &workflowRunEvidence{name: mux.Vars(r)["name"]}
	env, ok := s.requireWorkflowRunServices(w, r, run, ev)
	if !ok {
		return
	}
	req, ok := s.decodeAutomationWorkflowRun(w, r, run, ev)
	if !ok {
		return
	}
	res, ok := s.resolveGrantWorkflow(w, r, run, env, req, ev)
	if !ok {
		return
	}
	decision, ok := s.requireApprovedWorkflow(w, r, run, env, res, ev)
	if !ok {
		return
	}
	inputs, ok := s.grantWorkflowInputs(w, r, run, res.vw, req.Inputs, ev)
	if !ok {
		return
	}
	s.startGrantWorkflow(w, r, run, env, res, decision, inputs, ev)
}

// requireWorkflowRunServices answers 503 and audits the refusal when a service the
// start needs is not wired, and returns the workflow environment otherwise.
func (s *Server) requireWorkflowRunServices(w http.ResponseWriter, r *http.Request, run *RunBinding, ev *workflowRunEvidence) (*automationWorkflowEnv, bool) {
	if s.automationRunStore() == nil {
		s.refuseWorkflowRun(w, r, run, ev, http.StatusServiceUnavailable, "Workflow service not available", "SERVICE_UNAVAILABLE", "run_service_unavailable")
		return nil, false
	}
	env, err := s.automationWorkflowEnv()
	if err != nil {
		s.logger.Error("Automation workflow run: dependencies are not wired", "error", logging.SanitizeLogValue(err.Error()))
		s.refuseWorkflowRun(w, r, run, ev, http.StatusServiceUnavailable, "Workflow service not available", "SERVICE_UNAVAILABLE", "dependencies_unavailable")
		return nil, false
	}
	return env, true
}

// validWorkflowPathSegment reports whether v can name a workflow or a version: not
// empty, no path separator and no parent reference.
func validWorkflowPathSegment(v string) bool {
	return v != "" && !strings.ContainsAny(v, `/\`) && !strings.Contains(v, "..")
}

// decodeAutomationWorkflowRun reads and validates the request body. The version is
// required and must be an exact semantic version; "latest" and an empty version are
// refused.
func (s *Server) decodeAutomationWorkflowRun(w http.ResponseWriter, r *http.Request, run *RunBinding, ev *workflowRunEvidence) (*AutomationWorkflowRunRequest, bool) {
	if !validWorkflowPathSegment(ev.name) {
		s.refuseWorkflowRun(w, r, run, ev, http.StatusBadRequest, "workflow name is not valid", "INVALID_REQUEST", "workflow_name_invalid")
		return nil, false
	}
	var req AutomationWorkflowRunRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, automationWorkflowBodyMaxBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.refuseWorkflowRun(w, r, run, ev, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST", "malformed_body")
		return nil, false
	}
	ev.version = req.Version
	if req.Version == "" {
		s.refuseWorkflowRun(w, r, run, ev, http.StatusBadRequest, "version is required", "MISSING_VERSION", "version_missing")
		return nil, false
	}
	if _, err := workflow.ParseSemanticVersion(req.Version); err != nil {
		s.refuseWorkflowRun(w, r, run, ev, http.StatusBadRequest, "version is not a valid workflow version", "INVALID_VERSION", "version_invalid")
		return nil, false
	}
	return &req, true
}

// workflowResolved is the one resolution a start is evaluated, executed and audited on.
type workflowResolved struct {
	vw    *workflow.VersionedWorkflow
	owner string
}

// resolveGrantWorkflow loads the exact version through the inheriting resolver, once.
// The chain is the run tenant's, capped at the tenant of the grant record the run was
// begun under (RunBinding.GrantTenantID, fixed when the run began and re-read from the
// grant on every call by requireAutomationRun); nothing in the request can move it. A
// workflow of any tenant outside the chain is not found.
func (s *Server) resolveGrantWorkflow(w http.ResponseWriter, r *http.Request, run *RunBinding, env *automationWorkflowEnv, req *AutomationWorkflowRunRequest, ev *workflowRunEvidence) (*workflowResolved, bool) {
	chain, err := s.libraryChain(r.Context(), run)
	if err != nil {
		s.logger.Error("Automation workflow run: library chain failed", "error", logging.SanitizeLogValue(err.Error()))
		s.refuseWorkflowRun(w, r, run, ev, http.StatusServiceUnavailable, "Authorization data is temporarily unavailable", "SERVICE_UNAVAILABLE", "library_chain_failed")
		return nil, false
	}
	vw, owner, err := workflow.ResolveInherited(r.Context(), env.handler.configStore, chain, ev.name, req.Version)
	if err != nil {
		if errors.Is(err, workflow.ErrWorkflowNotFound) {
			s.refuseWorkflowRun(w, r, run, ev, http.StatusNotFound, "Workflow not found", "WORKFLOW_NOT_FOUND", "workflow_not_found")
			return nil, false
		}
		s.logger.Error("Automation workflow run: workflow resolution failed", "error", logging.SanitizeLogValue(err.Error()))
		s.refuseWorkflowRun(w, r, run, ev, http.StatusServiceUnavailable, "Authorization data is temporarily unavailable", "SERVICE_UNAVAILABLE", "workflow_resolution_failed")
		return nil, false
	}
	if vw == nil {
		s.refuseWorkflowRun(w, r, run, ev, http.StatusNotFound, "Workflow not found", "WORKFLOW_NOT_FOUND", "workflow_not_found")
		return nil, false
	}
	ev.version, ev.owner = vw.SemanticVersion.String(), owner
	return &workflowResolved{vw: vw, owner: owner}, true
}

// requireApprovedWorkflow evaluates the exact resolved version for the run tenant,
// under the owner tenant's mode and records. A pending outcome asks for approval and
// never falls back to an older approved version; a denied outcome and every evaluator
// failure refuse the start. It returns the approving decision and whether the start may
// go on.
func (s *Server) requireApprovedWorkflow(w http.ResponseWriter, r *http.Request, run *RunBinding, env *automationWorkflowEnv, res *workflowResolved, ev *workflowRunEvidence) (Decision, bool) {
	d, err := env.evaluator.EvaluateWorkflow(r.Context(), run.TenantID, res.vw, res.owner)
	ev.approvalHash = d.ApprovalHash
	if err != nil {
		s.logger.Error("Automation workflow run: evaluation failed", "error", logging.SanitizeLogValue(err.Error()))
		s.refuseWorkflowRun(w, r, run, ev, http.StatusServiceUnavailable, "Authorization data is temporarily unavailable", "SERVICE_UNAVAILABLE", "evaluation_failed")
		return Decision{}, false
	}
	switch d.State {
	case ContentDecisionApproved:
		return d, true
	case ContentDecisionPending:
		s.refuseWorkflowRun(w, r, run, ev, http.StatusConflict,
			"This workflow version awaits approval", "APPROVAL_PENDING", "approval_pending")
	default:
		s.refuseWorkflowRun(w, r, run, ev, http.StatusForbidden,
			"This workflow version is not approved for automation", "CONTENT_NOT_APPROVED", "content_not_approved")
	}
	return Decision{}, false
}

// grantWorkflowInputs validates the inputs of a start against the workflow's declared
// inputs. The request is attacker-influenced, so only declared inputs are accepted, the
// count and the encoded size of each value are capped, and the engine's own typed check
// (type, enum options, required) runs before anything starts. A refusal names the field,
// never the value.
func (s *Server) grantWorkflowInputs(w http.ResponseWriter, r *http.Request, run *RunBinding, vw *workflow.VersionedWorkflow, raw map[string]interface{}, ev *workflowRunEvidence) (map[string]interface{}, bool) {
	reason, message := checkWorkflowInputBounds(vw, raw)
	if reason != "" {
		s.refuseWorkflowRun(w, r, run, ev, http.StatusBadRequest, message, "INPUT_REFUSED", reason)
		return nil, false
	}
	if _, err := vw.ResolveInputs(raw); err != nil {
		if inputErr, ok := workflow.AsInputsError(err); ok {
			s.auditWorkflowCall(r.Context(), run, business.AuditResultDenied, ev,
				auditDetail{Key: "reason", Value: "inputs_invalid"}, auditDetail{Key: "code", Value: "INVALID_INPUTS"},
				auditDetail{Key: "fields", Value: inputFieldNames(inputErr)})
			s.writeErrorResponse(w, http.StatusBadRequest, "The workflow inputs are not valid: "+inputFieldNames(inputErr), "INVALID_INPUTS")
			return nil, false
		}
		s.refuseWorkflowRun(w, r, run, ev, http.StatusBadRequest, "The workflow inputs are not valid", "INVALID_INPUTS", "inputs_invalid")
		return nil, false
	}
	return raw, true
}

// checkWorkflowInputBounds returns why the supplied inputs are refused, or "" reason.
func checkWorkflowInputBounds(vw *workflow.VersionedWorkflow, raw map[string]interface{}) (reason, message string) {
	if len(raw) > automationWorkflowMaxInputs {
		return "inputs_too_many", "Too many inputs"
	}
	declared := make(map[string]bool, len(vw.Inputs))
	for _, spec := range vw.Inputs {
		declared[spec.Name] = true
	}
	for name, value := range raw {
		if !declared[name] {
			return "input_undeclared", "An input is not declared by the workflow"
		}
		encoded, err := json.Marshal(value)
		if err != nil || len(encoded) > automationWorkflowInputMaxLen {
			return "input_too_large", "An input value is too large"
		}
	}
	return "", ""
}

// inputFieldNames lists the inputs a validation error names, never their values.
func inputFieldNames(e *workflow.InputsError) string {
	names := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		names = append(names, f.Field+" "+f.Message)
	}
	return strings.Join(names, "; ")
}

// startGrantWorkflow starts the evaluated object as a restricted execution under the
// run tenant and the run's guard, records the execution against the run so the read
// routes show it, and answers. The workflow handed to the engine is res.vw.Workflow, the
// very object that was evaluated: there is no second load between the two.
func (s *Server) startGrantWorkflow(w http.ResponseWriter, r *http.Request, run *RunBinding, env *automationWorkflowEnv, res *workflowResolved, decision Decision, inputs map[string]interface{}, ev *workflowRunEvidence) {
	if s.runExecutionQueue != nil {
		s.registerAutomationQueueGuards()
	}
	// The engine is asynchronous and derives the execution's context from this one,
	// and the server cancels the request context when the handler returns: the
	// execution keeps the request's values but not its cancellation, and always runs
	// under the run tenant (Issue #4658), never a tenant taken from the request.
	execCtx := context.WithValue(context.WithoutCancel(r.Context()), ctxkeys.TenantID, run.TenantID)
	exec, err := env.handler.engine.ExecuteRestrictedWorkflowWithOptions(execCtx, res.vw.Workflow, inputs,
		workflow.RestrictedRun{RunID: run.ID, GrantID: run.GrantID, Ceiling: run.GrantTenantID},
		workflow.RestrictedOptions{RunGuard: s.workflowRunGuard(run)})
	if err != nil {
		s.refuseWorkflowStart(w, r, run, ev, err)
		return
	}
	if err := s.automationRunStore().RecordArtifact(r.Context(), run.ID, automationArtifactKindExecution, exec.ID); err != nil {
		s.logger.Error("Automation workflow run: artifact record failed", "error", logging.SanitizeLogValue(err.Error()))
		// An execution the grant cannot read back must not run: stop it.
		if cerr := env.handler.engine.CancelExecution(exec.ID); cerr != nil {
			s.logger.Error("Automation workflow run: cancel after artifact failure failed", "error", logging.SanitizeLogValue(cerr.Error()))
		}
		s.refuseWorkflowRun(w, r, run, ev, http.StatusInternalServerError, "Failed to start workflow", "INTERNAL_ERROR", "artifact_record_failed")
		return
	}
	s.auditWorkflowCall(r.Context(), run, business.AuditResultSuccess, ev,
		auditDetail{Key: "execution_id", Value: exec.ID},
		auditDetail{Key: "method", Value: string(decision.Method)})
	s.writeResponse(w, http.StatusAccepted, AutomationWorkflowRunResponse{
		ExecutionID: exec.ID, TenantID: run.TenantID, OwnerTenant: res.owner, WorkflowName: ev.name,
		Version: ev.version, ApprovalHash: decision.ApprovalHash, Status: string(exec.GetStatus()),
	})
}

// refuseWorkflowStart answers a start the engine refused. A workflow that fails the
// restricted step-type validation is unprocessable; anything else is an internal error.
func (s *Server) refuseWorkflowStart(w http.ResponseWriter, r *http.Request, run *RunBinding, ev *workflowRunEvidence, err error) {
	var violations *workflow.RestrictedWorkflowError
	if errors.As(err, &violations) {
		s.refuseWorkflowRun(w, r, run, ev, http.StatusUnprocessableEntity,
			"This workflow is not permitted in restricted automation", "WORKFLOW_NOT_RESTRICTED_SAFE", "restricted_validation_failed")
		return
	}
	if inputErr, ok := workflow.AsInputsError(err); ok {
		s.refuseWorkflowRun(w, r, run, ev, http.StatusBadRequest,
			"The workflow inputs are not valid: "+inputFieldNames(inputErr), "INVALID_INPUTS", "inputs_invalid")
		return
	}
	s.logger.Error("Automation workflow run: start failed", "error", logging.SanitizeLogValue(err.Error()))
	s.refuseWorkflowRun(w, r, run, ev, http.StatusInternalServerError, "Failed to start workflow", "INTERNAL_ERROR", "start_failed")
}

// automationScriptApprover is the approver the script step of a restricted execution
// asks before it queues a library script. It answers by calling the script evaluator
// (story #5838) for the exact version the step names, resolved through the library
// chain of the run tenant capped at the ceiling carried by the execution's
// RestrictedRun, which the start route took from the grant record. Approving a workflow
// does not approve the scripts its steps name: each one is judged here, under its own
// owner tenant's mode and records.
type automationScriptApprover struct{ s *Server }

// AutomationScriptApprover returns the approver to install on the script step executor
// of the workflow engine (ScriptStepExecutor.SetApprover). Until it is installed a
// script step of a restricted execution fails closed with nothing queued.
func (s *Server) AutomationScriptApprover() workflow.ScriptApprover {
	return &automationScriptApprover{s: s}
}

// Approve implements workflow.ScriptApprover. It never approves on an error: the
// returned decision is denied together with the error.
func (a *automationScriptApprover) Approve(ctx context.Context, runTenant, ceiling, id, version string) (workflow.ScriptApprovalDecision, error) {
	denied := workflow.ScriptApprovalDecision{State: workflow.ScriptApprovalDenied}
	if runTenant == "" || ceiling == "" || id == "" || version == "" {
		denied.Reason = "the step does not name a pinned script for a run tenant"
		return denied, nil
	}
	env, err := a.s.automationScriptEnv()
	if err != nil {
		return denied, err
	}
	vs, owner, err := a.resolve(ctx, env, runTenant, ceiling, id, version)
	if err != nil {
		return denied, err
	}
	if vs == nil {
		denied.Reason = "script not found"
		return denied, nil
	}
	d, err := env.evaluator.Evaluate(ctx, runTenant, vs, owner)
	if err != nil {
		return denied, err
	}
	return a.decision(ctx, vs, owner, d), nil
}

// resolve loads the exact version through the library chain of the run tenant, capped
// at the ceiling. A script that is not in the chain, or that has no version, resolves to
// nil rather than to an error.
func (a *automationScriptApprover) resolve(ctx context.Context, env *automationScriptEnv, runTenant, ceiling, id, version string) (*script.VersionedScript, string, error) {
	chain, err := tenant.LibraryChain(ctx, a.s.tenantManager, runTenant, ceiling)
	if err != nil {
		return nil, "", err
	}
	vs, owner, err := env.repo.ResolveInherited(ctx, chain, id, version)
	if errors.Is(err, script.ErrScriptNotFound) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	if vs == nil || vs.Metadata == nil || vs.Metadata.Version == nil {
		return nil, "", nil
	}
	return vs, owner, nil
}

// decision turns the evaluator's decision for the resolved script into the pin the
// queue binds the command to. A pending change is recorded and announced to the owner
// tenant, as the script route does.
func (a *automationScriptApprover) decision(ctx context.Context, vs *script.VersionedScript, owner string, d Decision) workflow.ScriptApprovalDecision {
	out := workflow.ScriptApprovalDecision{
		State: workflow.ScriptApprovalDenied, Reason: d.Reason,
		OwnerTenant: owner, Version: vs.Metadata.Version.String(), ApprovalHash: d.ApprovalHash,
	}
	switch d.State {
	case ContentDecisionApproved:
		out.State = workflow.ScriptApprovalApproved
	case ContentDecisionPending:
		out.State = workflow.ScriptApprovalPending
		if err := a.s.RecordPendingAndNotify(ctx, owner, vs, d); err != nil {
			a.s.logger.Warn("Automation workflow script step: pending change could not be recorded",
				"error", logging.SanitizeLogValue(err.Error()))
		}
	}
	return out
}
