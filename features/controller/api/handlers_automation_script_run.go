// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/cfgis/cfgms/features/controller/fleet"
	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	automationActionScriptRun  = "automation.script.run"
	automationActionScriptList = "automation.script.list"

	// automationParamValueMaxLen bounds one literal param value.
	automationParamValueMaxLen = 4096
)

// AutomationScriptRunRequest starts one library script on devices of the run tenant.
// Version is optional: left off, the latest version is resolved once and that exact
// version is evaluated and pinned. Each Params value is a JSON string (a literal);
// an object value is read as a ParamBinding so a secret-store binding can be refused
// by name rather than misread.
type AutomationScriptRunRequest struct {
	Target   string                     `json:"target"`
	ScriptID string                     `json:"script_id"`
	Version  string                     `json:"version"`
	Params   map[string]json.RawMessage `json:"params"`
}

// AutomationScriptRunResponse describes a script run a grant started. OwnerTenant is
// the tenant whose library holds the script; it differs from TenantID for an
// inherited script.
type AutomationScriptRunResponse struct {
	RunID        string `json:"run_id"`
	TenantID     string `json:"tenant_id"`
	OwnerTenant  string `json:"owner_tenant"`
	ScriptID     string `json:"script_id"`
	Version      string `json:"version"`
	ApprovalHash string `json:"approval_hash"`
	DeviceCount  int    `json:"device_count"`
}

// AutomationScriptEntry is one script visible to the run with the evaluator's state
// for its latest version.
type AutomationScriptEntry struct {
	ScriptID     string               `json:"script_id"`
	Name         string               `json:"name"`
	Version      string               `json:"version"`
	OwnerTenant  string               `json:"owner_tenant"`
	State        ContentDecisionState `json:"state"`
	Reason       string               `json:"reason,omitempty"`
	ApprovalHash string               `json:"approval_hash,omitempty"`
}

// scriptRunEvidence is what the audit record of a script call names: the script as
// far as it was resolved and evaluated when the call ended.
type scriptRunEvidence struct {
	scriptID     string
	version      string
	approvalHash string
	owner        string
}

func (e *scriptRunEvidence) details() []auditDetail {
	return []auditDetail{
		{Key: "script_id", Value: e.scriptID},
		{Key: "script_version", Value: e.version},
		{Key: "approval_hash", Value: e.approvalHash},
		{Key: "script_owner_tenant", Value: e.owner},
	}
}

// automationScriptEnv is what the script routes need from the server.
type automationScriptEnv struct {
	repo      *script.TenantScriptRepository
	evaluator *ContentApprovalEvaluator
}

// automationScriptEnv gathers the library, the approval evaluator and the stores the
// script routes depend on. An error means a dependency is not wired.
func (s *Server) automationScriptEnv() (*automationScriptEnv, error) {
	repo, ok := s.ScriptRepository().(*script.TenantScriptRepository)
	if !ok || repo == nil {
		return nil, errors.New("the script library is not tenant-resolved")
	}
	if s.tenantManager == nil {
		return nil, errors.New("tenant manager is not wired")
	}
	ev, err := NewContentApprovalEvaluator(s.ContentApprovalStore(),
		NewConfigServiceTrustedKeyResolver(s.configService), s.PrivilegeStore())
	if err != nil {
		return nil, err
	}
	return &automationScriptEnv{repo: repo, evaluator: ev}, nil
}

// libraryChain is the run tenant's library chain, capped at the tenant of the grant
// record the run was begun under.
func (s *Server) libraryChain(ctx context.Context, run *RunBinding) ([]string, error) {
	return tenant.LibraryChain(ctx, s.tenantManager, run.TenantID, run.GrantTenantID)
}

// auditScriptCall records one outcome of a script route under the grant, run and
// event, naming the script evidence.
func (s *Server) auditScriptCall(ctx context.Context, run *RunBinding, action string, result business.AuditResult, ev *scriptRunEvidence, extra ...auditDetail) {
	details := append(ev.details(), extra...)
	s.emitAutomationAudit(ctx, run.GrantID, run.ID, run.TenantID, run.GrantTenantID, run.EventRef, action, result, details...)
}

// refuseScriptRun audits a refused script run with its reason and answers it.
func (s *Server) refuseScriptRun(w http.ResponseWriter, r *http.Request, run *RunBinding, ev *scriptRunEvidence, status int, message, code, reason string) {
	s.auditScriptCall(r.Context(), run, automationActionScriptRun, business.AuditResultDenied, ev,
		auditDetail{Key: "reason", Value: reason}, auditDetail{Key: "code", Value: code})
	s.writeErrorResponse(w, status, message, code)
}

// registerAutomationQueueGuards registers on the run queue the guard that cancels a
// command whose run has ended or whose grant is revoked or expired, and the lookup
// that refuses a pinned script that now requires an API scope. Both are re-read from
// the durable stores on every call, so a revocation or an end is seen by the next
// dequeue or dispatch. Registering the same functions again is harmless.
func (s *Server) registerAutomationQueueGuards() {
	q := s.runExecutionQueue
	q.SetGuardResolver(s.automationRunGuard)
	q.SetPrivilegeScopeLookup(s.automationScopeLookup)
}

// automationRunGuard fails unless the run is the grant's, is open, and the grant is
// neither revoked nor expired.
func (s *Server) automationRunGuard(ctx context.Context, runID, grantID string) error {
	grantStore, runStore := s.grantStoreOrNil(), s.automationRunStore()
	if grantStore == nil || runStore == nil {
		return errors.New("automation stores are not wired")
	}
	run, err := runStore.findByID(ctx, runID)
	if err != nil {
		return errors.New("the automation run is not available")
	}
	if run.GrantID != grantID {
		return errors.New("the run does not belong to the grant")
	}
	if !run.Open(runStore.now()) {
		return errors.New("the automation run has ended")
	}
	grant, err := grantStore.Get(ctx, run.GrantTenantID, grantID)
	if err != nil {
		return errors.New("the automation grant is not available")
	}
	if reason := grantRefusalReason(grant, grantStore.now()); reason != "" {
		return errors.New("the automation grant is no longer valid")
	}
	return nil
}

// automationScopeLookup returns the RequiredAPIScope that applies to scriptID for a
// run in tenantID. Privilege metadata is kept in the tenant that owns the script,
// which the lookup does not know, so it reads the run tenant and every ancestor and
// returns the first non-empty scope. A failed read fails the lookup (closed).
func (s *Server) automationScopeLookup(ctx context.Context, tenantID, scriptID string) ([]string, error) {
	if s.tenantManager == nil {
		return nil, errors.New("tenant manager is not wired")
	}
	path, err := s.tenantManager.GetTenantPath(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, owner := range path {
		meta, err := s.loadPrivilegeMetadata(ctx, owner, scriptID)
		if err != nil {
			if configMissing(err) {
				continue
			}
			return nil, err
		}
		if meta != nil && len(meta.RequiredAPIScope) > 0 {
			return meta.RequiredAPIScope, nil
		}
	}
	return nil, nil
}

// handleAutomationPostScriptRun handles POST /api/v1/automation/runs/{run_id}/scripts.
//
// It is the grant counterpart of handlePostRunScript and a separate path on purpose:
// handlePostRunScript runs for an operator who has just tapped a presence check, takes
// the library of the caller's tenant and queues whatever version it names. This one
// has no tap; a pre-approval evaluated for the exact version resolved stands in for it,
// the script is resolved through the run tenant's library chain and the queue is pinned
// to the owner tenant, version and approval hash that were evaluated, and every queued
// command carries the run and grant it belongs to so it dies with them. The
// orchestration is not copied: targets go through resolveAuthorizedRunTargets and the
// run is built by the shared run synthesis.
func (s *Server) handleAutomationPostScriptRun(w http.ResponseWriter, r *http.Request) {
	run := automationRunFromContext(r.Context())
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if run == nil || principal == nil {
		s.writeErrorResponse(w, http.StatusForbidden, "The automation run does not permit this request", "AUTOMATION_RUN_DENIED")
		return
	}
	ev := &scriptRunEvidence{}
	env, ok := s.requireScriptRunServices(w, r, run, ev)
	if !ok {
		return
	}
	req, ok := s.decodeAutomationScriptRun(w, r, run, ev)
	if !ok {
		return
	}
	res, ok := s.resolveGrantScript(w, r, run, env, req, ev)
	if !ok {
		return
	}
	if !s.requireApprovedScript(w, r, run, env, res, ev) {
		return
	}
	params, ok := s.grantRunParams(w, r, run, res.vs.Metadata, req.Params, ev)
	if !ok {
		return
	}
	devices, filter, ok := s.resolveGrantRunTargets(w, r, principal, run, req.Target, ev)
	if !ok {
		return
	}
	s.startGrantScriptRun(w, r, principal, run, res, params, devices, filter, ev)
}

// requireScriptRunServices answers 503 and audits the refusal when a service the run
// needs is not wired, and returns the script environment otherwise.
func (s *Server) requireScriptRunServices(w http.ResponseWriter, r *http.Request, run *RunBinding, ev *scriptRunEvidence) (*automationScriptEnv, bool) {
	if s.runManager == nil || s.runExecutionQueue == nil || s.fleetQuery == nil || s.automationRunStore() == nil {
		s.refuseScriptRun(w, r, run, ev, http.StatusServiceUnavailable, "Run service not available", "SERVICE_UNAVAILABLE", "run_service_unavailable")
		return nil, false
	}
	env, err := s.automationScriptEnv()
	if err != nil {
		s.logger.Error("Automation script run: dependencies are not wired", "error", logging.SanitizeLogValue(err.Error()))
		s.refuseScriptRun(w, r, run, ev, http.StatusServiceUnavailable, "Run service not available", "SERVICE_UNAVAILABLE", "dependencies_unavailable")
		return nil, false
	}
	return env, true
}

// decodeAutomationScriptRun reads and validates the request body.
func (s *Server) decodeAutomationScriptRun(w http.ResponseWriter, r *http.Request, run *RunBinding, ev *scriptRunEvidence) (*AutomationScriptRunRequest, bool) {
	var req AutomationScriptRunRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.refuseScriptRun(w, r, run, ev, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST", "malformed_body")
		return nil, false
	}
	ev.scriptID = req.ScriptID
	ev.version = req.Version
	if req.ScriptID == "" {
		s.refuseScriptRun(w, r, run, ev, http.StatusBadRequest, "script_id is required", "MISSING_SCRIPT_ID", "script_id_missing")
		return nil, false
	}
	if strings.ContainsAny(req.ScriptID, `/\`) || strings.Contains(req.ScriptID, "..") {
		s.refuseScriptRun(w, r, run, ev, http.StatusBadRequest, "script_id is not valid", "INVALID_REQUEST", "script_id_invalid")
		return nil, false
	}
	if req.Version != "" {
		if _, err := script.ParseVersion(req.Version); err != nil {
			s.refuseScriptRun(w, r, run, ev, http.StatusBadRequest, "version is not a valid script version", "INVALID_VERSION", "version_invalid")
			return nil, false
		}
	}
	return &req, true
}

// resolveGrantScript resolves the script through the run tenant's library chain
// exactly once. With no version this is the latest version, and from here on that
// exact version is the one evaluated, pinned and audited. ev gains the resolved
// version and owner.
func (s *Server) resolveGrantScript(w http.ResponseWriter, r *http.Request, run *RunBinding, env *automationScriptEnv, req *AutomationScriptRunRequest, ev *scriptRunEvidence) (*scriptResolved, bool) {
	chain, err := s.libraryChain(r.Context(), run)
	if err != nil {
		s.logger.Error("Automation script run: library chain failed", "error", logging.SanitizeLogValue(err.Error()))
		s.refuseScriptRun(w, r, run, ev, http.StatusServiceUnavailable, "Authorization data is temporarily unavailable", "SERVICE_UNAVAILABLE", "library_chain_failed")
		return nil, false
	}
	vs, owner, err := env.repo.ResolveInherited(r.Context(), chain, req.ScriptID, req.Version)
	if err != nil {
		if errors.Is(err, script.ErrScriptNotFound) {
			s.refuseScriptRun(w, r, run, ev, http.StatusNotFound, "Script not found", "SCRIPT_NOT_FOUND", "script_not_found")
			return nil, false
		}
		s.logger.Error("Automation script run: script resolution failed", "error", logging.SanitizeLogValue(err.Error()))
		s.refuseScriptRun(w, r, run, ev, http.StatusServiceUnavailable, "Authorization data is temporarily unavailable", "SERVICE_UNAVAILABLE", "script_resolution_failed")
		return nil, false
	}
	if vs == nil || vs.Metadata == nil || vs.Metadata.Version == nil {
		s.refuseScriptRun(w, r, run, ev, http.StatusNotFound, "Script not found", "SCRIPT_NOT_FOUND", "script_not_found")
		return nil, false
	}
	ev.version, ev.owner = vs.Metadata.Version.String(), owner
	return &scriptResolved{vs: vs, owner: owner, version: ev.version}, true
}

// scriptResolved is the one resolution a run is evaluated, pinned and audited on.
type scriptResolved struct {
	vs      *script.VersionedScript
	owner   string
	version string
	// decision is set once the evaluator approved the version.
	decision Decision
}

// requireApprovedScript evaluates the exact resolved version for the run tenant. A
// pending outcome records the pending change and asks for approval; it never falls
// back to an older approved version. A denied outcome and every evaluator failure
// refuse the run. It reports whether the run may go on.
func (s *Server) requireApprovedScript(w http.ResponseWriter, r *http.Request, run *RunBinding, env *automationScriptEnv, res *scriptResolved, ev *scriptRunEvidence) bool {
	d, err := env.evaluator.Evaluate(r.Context(), run.TenantID, res.vs, res.owner)
	ev.approvalHash = d.ApprovalHash
	if err != nil {
		s.logger.Error("Automation script run: evaluation failed", "error", logging.SanitizeLogValue(err.Error()))
		s.refuseScriptRun(w, r, run, ev, http.StatusServiceUnavailable, "Authorization data is temporarily unavailable", "SERVICE_UNAVAILABLE", "evaluation_failed")
		return false
	}
	switch d.State {
	case ContentDecisionApproved:
		res.decision = d
		return true
	case ContentDecisionPending:
		if err := s.RecordPendingAndNotify(r.Context(), res.owner, res.vs, d); err != nil {
			s.logger.Warn("Automation script run: pending change could not be recorded",
				"error", logging.SanitizeLogValue(err.Error()))
		}
		s.refuseScriptRun(w, r, run, ev, http.StatusConflict,
			"This script version awaits approval", "APPROVAL_PENDING", "approval_pending")
	default:
		s.refuseScriptRun(w, r, run, ev, http.StatusForbidden,
			"This script version is not approved for automation", "CONTENT_NOT_APPROVED", "content_not_approved")
	}
	return false
}

// paramRefusal says why the params of a grant run were refused.
type paramRefusal struct{ reason, message string }

// grantRunParams validates the params of a grant run and returns them as literal
// strings. Ticket text is attacker-influenced and the script runs with high
// privilege, so a grant may supply only literal values for parameters the script
// declares, each matching the declared type and allowed values; a secret-store
// binding is never accepted. A value is only ever data: it travels in the queue
// entry's parameter map and reaches the script as an environment variable, never
// spliced into script text or a command line.
func (s *Server) grantRunParams(w http.ResponseWriter, r *http.Request, run *RunBinding, meta *script.ScriptMetadata, raw map[string]json.RawMessage, ev *scriptRunEvidence) (map[string]string, bool) {
	params, refusal := validateGrantParams(meta, raw)
	if refusal != nil {
		s.refuseScriptRun(w, r, run, ev, http.StatusBadRequest, refusal.message, "PARAM_REFUSED", refusal.reason)
		return nil, false
	}
	return params, true
}

func validateGrantParams(meta *script.ScriptMetadata, raw map[string]json.RawMessage) (map[string]string, *paramRefusal) {
	declared := make(map[string]script.ScriptParameter, len(meta.Parameters))
	for _, p := range meta.Parameters {
		declared[p.Name] = p
	}
	out := make(map[string]string, len(raw))
	for name, value := range raw {
		decl, ok := declared[name]
		if !ok {
			return nil, &paramRefusal{"param_undeclared", "A param is not declared by the script"}
		}
		literal, refusal := grantParamLiteral(value)
		if refusal != nil {
			return nil, refusal
		}
		if refusal := checkParamValue(decl, literal); refusal != nil {
			return nil, refusal
		}
		out[name] = literal
	}
	if missingRequiredParam(meta, out) {
		return nil, &paramRefusal{"param_required_missing", "A required param has no value"}
	}
	return out, nil
}

// missingRequiredParam reports whether a required parameter has no supplied value
// and no default or DNA source to fall back on.
func missingRequiredParam(meta *script.ScriptMetadata, supplied map[string]string) bool {
	for _, p := range meta.Parameters {
		if _, given := supplied[p.Name]; !given && p.Required && p.Default == nil && p.DNAPath == "" {
			return true
		}
	}
	return false
}

// grantParamLiteral returns the literal a params value carries. A JSON string is a
// literal; a ParamBinding object is accepted only for the literal source. Anything
// else, including a secret-store binding, is refused.
func grantParamLiteral(value json.RawMessage) (string, *paramRefusal) {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 {
		return "", &paramRefusal{"param_value_invalid", "A param value is not valid"}
	}
	switch trimmed[0] {
	case '"':
		var literal string
		if err := json.Unmarshal(trimmed, &literal); err != nil {
			return "", &paramRefusal{"param_value_invalid", "A param value is not valid"}
		}
		return literal, nil
	case '{':
		var binding script.ParamBinding
		if err := json.Unmarshal(trimmed, &binding); err != nil || binding.From != script.ParamSourceLiteral {
			return "", &paramRefusal{"param_binding_refused", "A grant run accepts literal params only"}
		}
		return binding.Value, nil
	}
	return "", &paramRefusal{"param_value_invalid", "A param value must be a string"}
}

// checkParamValue checks a literal against the declared type, the allowed values and
// the length bound.
func checkParamValue(decl script.ScriptParameter, value string) *paramRefusal {
	if len(value) > automationParamValueMaxLen || strings.ContainsRune(value, 0) {
		return &paramRefusal{"param_value_invalid", "A param value is not valid"}
	}
	if !paramMatchesType(decl.Type, value) {
		return &paramRefusal{"param_type_mismatch", "A param value does not match the declared type"}
	}
	if len(decl.AllowedValues) > 0 {
		for _, allowed := range decl.AllowedValues {
			if value == allowed {
				return nil
			}
		}
		return &paramRefusal{"param_value_not_allowed", "A param value is not among the allowed values"}
	}
	return nil
}

// paramMatchesType reports whether value is a well-formed value of the declared
// type. An unknown type matches nothing (closed).
func paramMatchesType(declared, value string) bool {
	switch strings.ToLower(declared) {
	case "", "string":
		return true
	case "int", "integer":
		_, err := strconv.ParseInt(value, 10, 64)
		return err == nil
	case "bool", "boolean":
		_, err := strconv.ParseBool(value)
		return err == nil
	case "float", "number":
		_, err := strconv.ParseFloat(value, 64)
		return err == nil
	}
	return false
}

// isRunTenantTarget reports whether the selector names the run tenant's devices as a
// whole: an empty selector or "all". Such a selector is the run tenant by definition,
// so it is resolved scoped to the run tenant. Any other selector is resolved over the
// whole fleet first, so a match outside the run tenant refuses the request instead of
// being dropped from it.
func isRunTenantTarget(target string) bool {
	return target == "" || target == "all"
}

// resolveGrantRunTargets resolves the request's devices for the run tenant. A target
// that reaches a device outside the run tenant (another tenant, a descendant tenant,
// or a group or filter that spans tenants) refuses the whole request; it is never
// narrowed. Every resolved device passes runTenantOnly.
func (s *Server) resolveGrantRunTargets(w http.ResponseWriter, r *http.Request, principal *Principal, run *RunBinding, target string, ev *scriptRunEvidence) ([]fleet.StewardResult, fleet.Filter, bool) {
	filter, err := parseRunTarget(target)
	if err != nil {
		s.refuseScriptRun(w, r, run, ev, http.StatusBadRequest, "Invalid target selector", "INVALID_TARGET", "target_invalid")
		return nil, filter, false
	}
	if !isRunTenantTarget(target) && !s.targetStaysInRunTenant(w, r, run, filter, ev) {
		return nil, filter, false
	}
	buf := newBufferedResponse()
	devices, ok := s.resolveAuthorizedRunTargets(buf, r, principal, run.TenantID, filter)
	if !ok {
		s.auditScriptCall(r.Context(), run, automationActionScriptRun, business.AuditResultDenied, ev,
			auditDetail{Key: "reason", Value: "targets_unresolved"})
		buf.replay(w)
		return nil, filter, false
	}
	return s.admitGrantDevices(w, r, run, devices, filter, ev)
}

// targetStaysInRunTenant searches the whole fleet for the selector and requires every
// match, and every explicitly named device, to be a device of exactly the run tenant.
// An id that matches nothing is refused the same way as one in another tenant, so the
// answer is no existence oracle.
func (s *Server) targetStaysInRunTenant(w http.ResponseWriter, r *http.Request, run *RunBinding, filter fleet.Filter, ev *scriptRunEvidence) bool {
	filter.TenantID, filter.TenantSubtree, filter.TenantSubtreeIDs = "", "", nil
	found, err := s.fleetQuery.Search(r.Context(), filter)
	if err != nil {
		s.refuseScriptRun(w, r, run, ev, http.StatusServiceUnavailable, "Fleet query not available", "SERVICE_UNAVAILABLE", "fleet_query_failed")
		return false
	}
	seen := make(map[string]bool, len(found))
	for _, d := range found {
		if !runTenantOnly(run.TenantID, d.TenantID) {
			s.refuseTargetOutOfTenant(w, r, run, ev)
			return false
		}
		seen[d.ID] = true
	}
	requested := append([]string(nil), filter.IDs...)
	if filter.DeviceID != "" {
		requested = append(requested, filter.DeviceID)
	}
	for _, id := range requested {
		if !seen[id] {
			s.refuseTargetOutOfTenant(w, r, run, ev)
			return false
		}
	}
	return true
}

func (s *Server) refuseTargetOutOfTenant(w http.ResponseWriter, r *http.Request, run *RunBinding, ev *scriptRunEvidence) {
	s.refuseScriptRun(w, r, run, ev, http.StatusForbidden,
		"The target is outside the run's tenant", "TARGET_OUT_OF_TENANT", "target_outside_run_tenant")
}

// admitGrantDevices requires at least one device, every device to be exactly in the
// run tenant, and the device count to stay within the tenant's blast-radius bound.
func (s *Server) admitGrantDevices(w http.ResponseWriter, r *http.Request, run *RunBinding, devices []fleet.StewardResult, filter fleet.Filter, ev *scriptRunEvidence) ([]fleet.StewardResult, fleet.Filter, bool) {
	for _, d := range devices {
		if !runTenantOnly(run.TenantID, d.TenantID) {
			s.refuseTargetOutOfTenant(w, r, run, ev)
			return nil, filter, false
		}
	}
	if len(devices) == 0 {
		s.refuseScriptRun(w, r, run, ev, http.StatusNotFound, "No device matches the target", "NO_TARGETS", "no_devices")
		return nil, filter, false
	}
	if limit := s.resolveMaxTargetsForTenant(r.Context(), run.TenantID); len(devices) > limit {
		s.refuseScriptRun(w, r, run, ev, http.StatusUnprocessableEntity,
			fmt.Sprintf("The target matches more than %d devices", limit), "TOO_MANY_TARGETS", "too_many_targets")
		return nil, filter, false
	}
	return devices, filter, true
}

// startGrantScriptRun queues the approved, pinned and guarded script on the devices,
// records the run under the automation run so the read routes show it, and answers.
func (s *Server) startGrantScriptRun(w http.ResponseWriter, r *http.Request, principal *Principal, run *RunBinding, res *scriptResolved, params map[string]string, devices []fleet.StewardResult, filter fleet.Filter, ev *scriptRunEvidence) {
	d := res.decision
	s.registerAutomationQueueGuards()
	resultRunID, err := controllerrun.SynthesizeScriptRunForDevicesPinned(
		r.Context(), s.runManager, s.runExecutionQueue, devices, run.TenantID, principal.ID, filter,
		ev.scriptID, res.vs.Metadata.Shell, params, res.vs.Metadata,
		controllerrun.ScriptRunPin{
			OwnerTenant: res.owner, Version: res.version, ApprovalHash: d.ApprovalHash,
			GuardRunID: run.ID, GuardGrantID: run.GrantID,
		})
	if err != nil {
		s.logger.Error("Automation script run: synthesis failed", "error", logging.SanitizeLogValue(err.Error()))
		s.refuseScriptRun(w, r, run, ev, http.StatusInternalServerError, "Failed to create run", "INTERNAL_ERROR", "synthesis_failed")
		return
	}
	if err := s.automationRunStore().RecordArtifact(r.Context(), run.ID, automationArtifactKindRun, resultRunID); err != nil {
		s.logger.Error("Automation script run: artifact record failed", "error", logging.SanitizeLogValue(err.Error()))
		// A run the grant cannot read back must not run: cancel what was queued.
		if cerr := s.runManager.CancelRun(r.Context(), resultRunID); cerr != nil {
			s.logger.Error("Automation script run: cancel after artifact failure failed", "error", logging.SanitizeLogValue(cerr.Error()))
		}
		s.refuseScriptRun(w, r, run, ev, http.StatusInternalServerError, "Failed to create run", "INTERNAL_ERROR", "artifact_record_failed")
		return
	}
	s.auditScriptCall(r.Context(), run, automationActionScriptRun, business.AuditResultSuccess, ev,
		auditDetail{Key: "result_run_id", Value: resultRunID},
		auditDetail{Key: "device_count", Value: strconv.Itoa(len(devices))},
		auditDetail{Key: "method", Value: string(d.Method)})
	s.writeResponse(w, http.StatusCreated, AutomationScriptRunResponse{
		RunID: resultRunID, TenantID: run.TenantID, OwnerTenant: res.owner, ScriptID: ev.scriptID,
		Version: res.version, ApprovalHash: d.ApprovalHash, DeviceCount: len(devices),
	})
}

// handleAutomationListScripts handles GET /api/v1/automation/runs/{run_id}/scripts. It
// lists the scripts the run tenant sees through its library chain (ListInherited),
// each with its owner tenant and the evaluator's state for its latest version.
func (s *Server) handleAutomationListScripts(w http.ResponseWriter, r *http.Request) {
	run := automationRunFromContext(r.Context())
	if run == nil {
		s.writeErrorResponse(w, http.StatusForbidden, "The automation run does not permit this request", "AUTOMATION_RUN_DENIED")
		return
	}
	env, err := s.automationScriptEnv()
	if err != nil {
		s.writeAutomationUnavailable(w, "Automation script list: dependencies are not wired", err)
		return
	}
	entries, err := s.listGrantScripts(r.Context(), run, env)
	if err != nil {
		s.writeAutomationUnavailable(w, "Automation script list failed", err)
		return
	}
	s.emitAutomationAudit(r.Context(), run.GrantID, run.ID, run.TenantID, run.GrantTenantID, run.EventRef,
		automationActionScriptList, business.AuditResultSuccess,
		auditDetail{Key: "script_count", Value: strconv.Itoa(len(entries))})
	s.writeSuccessResponse(w, entries)
}

func (s *Server) listGrantScripts(ctx context.Context, run *RunBinding, env *automationScriptEnv) ([]AutomationScriptEntry, error) {
	chain, err := s.libraryChain(ctx, run)
	if err != nil {
		return nil, err
	}
	listed, err := env.repo.ListInherited(ctx, chain, nil)
	if err != nil {
		return nil, err
	}
	entries := make([]AutomationScriptEntry, 0, len(listed))
	for _, m := range listed {
		entry, err := s.scriptEntry(ctx, run, env, chain, m)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// scriptEntry evaluates the latest version of one listed script. An evaluation that
// fails is shown as denied, the state a run would meet; a library read that fails is
// an error.
func (s *Server) scriptEntry(ctx context.Context, run *RunBinding, env *automationScriptEnv, chain []string, m *script.InheritedScriptMetadata) (AutomationScriptEntry, error) {
	entry := AutomationScriptEntry{ScriptID: m.ID, Name: m.Name, OwnerTenant: m.OwnerTenant, State: ContentDecisionDenied}
	vs, owner, err := env.repo.ResolveInherited(ctx, chain, m.ID, "")
	if err != nil {
		return entry, err
	}
	if vs == nil || vs.Metadata == nil || vs.Metadata.Version == nil {
		return entry, nil
	}
	entry.Version, entry.OwnerTenant = vs.Metadata.Version.String(), owner
	d, evalErr := env.evaluator.Evaluate(ctx, run.TenantID, vs, owner)
	entry.State, entry.ApprovalHash = d.State, d.ApprovalHash
	if evalErr == nil {
		entry.Reason = d.Reason
	}
	return entry, nil
}
