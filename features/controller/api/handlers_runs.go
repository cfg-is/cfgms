// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/fleet"
	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	scriptmodule "github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// bannedCommandPatterns lists strings that are rejected before dispatch (defence-in-depth,
// path 3 per CLAUDE.md). Do NOT log the command string — log only the matched pattern name.
var bannedCommandPatterns = []struct {
	pattern string
	name    string
}{
	{"iex", "iex"},
	{"invoke-expression", "Invoke-Expression"},
	{"-encodedcommand", "-EncodedCommand"},
	{"-executionpolicy bypass", "-ExecutionPolicy Bypass"},
	{"bash -c", "bash -c"},
	{"eval", "eval"},
	{"python -c", "python -c"},
}

// allowedCommandShells is the set of shell values accepted by POST /api/v1/runs/command.
var allowedCommandShells = map[string]bool{
	"bash": true,
	"sh":   true,
	"pwsh": true,
	"cmd":  true,
}

// matchBannedPattern returns the pattern name if cmd contains a banned pattern (case-insensitive).
// Returns "" when no banned pattern is found.
func matchBannedPattern(cmd string) string {
	lower := strings.ToLower(cmd)
	for _, p := range bannedCommandPatterns {
		if strings.Contains(lower, p.pattern) {
			return p.name
		}
	}
	return ""
}

// extractSingleStewardID returns the steward ID when target is exactly "id:<id>".
// Returns "" for any other target form (fleet selector, "all", empty, etc.).
func extractSingleStewardID(target string) string {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "id:") {
		return ""
	}
	id := strings.TrimPrefix(t, "id:")
	// Reject multi-token targets like "id:foo os:linux"
	if strings.ContainsAny(id, " \t") {
		return ""
	}
	return id
}

// isAdminTenantScopeAllowed reports whether an admin with adminTenant may target a steward
// with stewardTenant. An empty adminTenant (global mTLS admin) always returns true.
// Otherwise the admin's tenant must be equal to or a path-prefix of the steward's tenant.
func isAdminTenantScopeAllowed(adminTenant, stewardTenant string) bool {
	if adminTenant == "" {
		return true
	}
	if stewardTenant == "" {
		return true
	}
	return stewardTenant == adminTenant || strings.HasPrefix(stewardTenant, adminTenant+"/")
}

// commandSignatureRequest is the signature block sent by the CLI in POST /api/v1/runs/command.
type commandSignatureRequest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`      // base64-encoded raw signature bytes
	PublicKey string `json:"public_key"` // cert PEM from the operator bundle
}

// postRunScriptRequest is the body of POST /api/v1/runs/script.
type postRunScriptRequest struct {
	Target        string            `json:"target"`         // fleet selector string
	ScriptID      string            `json:"script_id"`      // script identifier in the library
	ScriptVersion string            `json:"script_version"` // optional; empty = latest
	Shell         string            `json:"shell"`          // optional shell override
	Params        map[string]string `json:"params"`         // script parameters
}

// postRunCommandRequest is the body of POST /api/v1/runs/command.
// Content is the inline script body, base64-encoded.
type postRunCommandRequest struct {
	Target         string                   `json:"target"`                    // fleet selector string
	Content        string                   `json:"content"`                   // base64-encoded inline script
	Shell          string                   `json:"shell"`                     // shell to use (e.g. "bash")
	Params         map[string]string        `json:"params"`                    // script parameters
	Signature      *commandSignatureRequest `json:"signature,omitempty"`       // mTLS admin signature for audit
	TimeoutSeconds int                      `json:"timeout_seconds,omitempty"` // exec timeout; 0 = no limit
}

// handlePostRunScript handles POST /api/v1/runs/script.
// Creates a run record and fans out one QueuedExecution per matched steward.
func (s *Server) handlePostRunScript(w http.ResponseWriter, r *http.Request) {
	if s.runManager == nil || s.runExecutionQueue == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Run service not available", "SERVICE_UNAVAILABLE")
		return
	}

	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	var req postRunScriptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return
	}
	if req.ScriptID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "script_id is required", "MISSING_SCRIPT_ID")
		return
	}

	filter, err := parseRunTarget(req.Target)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid target selector: "+err.Error(), "INVALID_TARGET")
		return
	}

	if s.fleetQuery == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet query not available", "SERVICE_UNAVAILABLE")
		return
	}

	// Look up script metadata for per-steward parameter resolution. Non-fatal if
	// the repo is unavailable or the script is not found — params resolve from
	// runtime overrides and defaults only.
	var scriptMeta *scriptmodule.ScriptMetadata
	if s.scriptRepo != nil {
		if vs, err := s.scriptRepo.Get(req.ScriptID, req.ScriptVersion); err == nil && vs != nil {
			scriptMeta = vs.Metadata
		}
	}

	// Look up admin-configured privilege metadata: DNA path overrides for
	// parameter resolution and the required API scope (Issue #1675). The scope
	// is read from the store — never from the request body — so callers cannot
	// widen it beyond what was set by script:admin.
	var paramPlatformBindings map[string]string
	var requiredAPIScope []string
	if s.privilegeStore != nil {
		meta, loadErr := s.loadPrivilegeMetadata(r.Context(), tenantID, req.ScriptID)
		if loadErr == nil && meta != nil {
			paramPlatformBindings = meta.ParamPlatformBindings
			requiredAPIScope = meta.RequiredAPIScope
		}
	}

	runID, err := controllerrun.SynthesizeScriptRun(
		r.Context(),
		s.runManager,
		s.runExecutionQueue,
		s.fleetQuery,
		tenantID,
		principal.ID,
		filter,
		req.ScriptID,
		req.ScriptVersion,
		scriptmodule.ShellType(req.Shell),
		req.Params,
		scriptMeta,
		paramPlatformBindings,
		requiredAPIScope,
	)
	if err != nil {
		s.logger.Error("Failed to synthesize script run",
			"script_id", logging.SanitizeLogValue(req.ScriptID),
			"error", err,
		)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create run", "INTERNAL_ERROR")
		return
	}

	s.writeSuccessResponse(w, map[string]string{"run_id": runID})
}

// handlePostRunCommand handles POST /api/v1/runs/command.
// Creates a run record for an inline (ad-hoc) script and fans out one
// QueuedExecution per matched steward.
func (s *Server) handlePostRunCommand(w http.ResponseWriter, r *http.Request) {
	if s.runManager == nil || s.runExecutionQueue == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Run service not available", "SERVICE_UNAVAILABLE")
		return
	}

	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	var req postRunCommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return
	}
	if req.Content == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "content is required", "MISSING_CONTENT")
		return
	}
	if req.Shell == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "shell is required", "MISSING_SHELL")
		return
	}

	// Shell allowlist check.
	if !allowedCommandShells[strings.ToLower(req.Shell)] {
		s.writeErrorResponse(w, http.StatusBadRequest, "unsupported shell value", "UNSUPPORTED_SHELL")
		return
	}

	inlineContent, err := base64.StdEncoding.DecodeString(req.Content)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "content must be base64-encoded", "INVALID_CONTENT")
		return
	}

	// Banned-pattern enforcement (defence-in-depth, path 3). Log the pattern name only,
	// never the command string itself.
	if matched := matchBannedPattern(string(inlineContent)); matched != "" {
		s.logger.Warn("run-command rejected: banned pattern", "pattern", matched)
		s.writeErrorResponse(w, http.StatusBadRequest, "command contains a prohibited pattern", "BANNED_PATTERN")
		return
	}

	filter, err := parseRunTarget(req.Target)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid target selector: "+err.Error(), "INVALID_TARGET")
		return
	}

	// Cross-tenant RBAC check for single-steward targeting (id: selector).
	// Admin mTLS principals (tenantID == "") have global scope and skip this check.
	if stewardID := extractSingleStewardID(req.Target); stewardID != "" && tenantID != "" {
		if s.controllerService != nil {
			info, exists := s.controllerService.GetStewardInfo(stewardID)
			if exists && !isAdminTenantScopeAllowed(tenantID, info.TenantID) {
				s.writeErrorResponse(w, http.StatusForbidden,
					"admin scope does not cover the target steward's tenant", "CROSS_TENANT_ACCESS_DENIED")
				return
			}
		}
	}

	if s.fleetQuery == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Fleet query not available", "SERVICE_UNAVAILABLE")
		return
	}

	// Compute command_hash (SHA-256 of raw command bytes) for audit. The raw command string
	// itself is never stored.
	cmdHash := sha256.Sum256(inlineContent)
	commandHash := hex.EncodeToString(cmdHash[:])

	runID, err := controllerrun.SynthesizeCommandRun(
		r.Context(),
		s.runManager,
		s.runExecutionQueue,
		s.fleetQuery,
		tenantID,
		principal.ID,
		filter,
		string(inlineContent),
		scriptmodule.ShellType(req.Shell),
		req.Params,
	)
	if err != nil {
		s.logger.Error("Failed to synthesize command run",
			"shell", logging.SanitizeLogValue(req.Shell),
			"error", err,
		)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create run", "INTERNAL_ERROR")
		return
	}

	// Audit record: write what is known at dispatch time. command string and raw output are NOT stored.
	if s.auditManager != nil {
		signatureID := ""
		if req.Signature != nil && req.Signature.Value != "" {
			// signature_id = SHA-256 of the base64-encoded signature value (unique fingerprint).
			sigHash := sha256.Sum256([]byte(req.Signature.Value))
			signatureID = hex.EncodeToString(sigHash[:])
		}
		auditTenantID := tenantID
		if auditTenantID == "" {
			auditTenantID = audit.SystemTenantID
		}
		targetStewardID := extractSingleStewardID(req.Target)
		if targetStewardID == "" {
			targetStewardID = req.Target
		}
		evt := audit.NewEventBuilder().
			Tenant(auditTenantID).
			Type(business.AuditEventSystemAccess).
			Action("exec-command").
			User(principal.ID, business.AuditUserTypeHuman).
			Resource("steward", targetStewardID, "").
			Detail("run_id", runID).
			Detail("command_hash", commandHash).
			Detail("signature_id", signatureID).
			Detail("admin_cn", principal.ID).
			Detail("steward_id", targetStewardID).
			Severity(business.AuditSeverityHigh)
		_ = s.auditManager.RecordEvent(r.Context(), evt)
	}

	s.writeSuccessResponse(w, map[string]string{"run_id": runID})
}

// handleGetRun handles GET /api/v1/runs/{run_id}.
func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	if s.runManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Run service not available", "SERVICE_UNAVAILABLE")
		return
	}

	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	vars := mux.Vars(r)
	runID := vars["run_id"]
	if runID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "run_id is required", "MISSING_RUN_ID")
		return
	}

	run, err := s.runManager.GetRun(r.Context(), runID)
	if err != nil {
		if errors.Is(err, controllerrun.ErrNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Run not found", "NOT_FOUND")
			return
		}
		s.logger.Error("Failed to get run", "run_id", logging.SanitizeLogValue(runID), "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get run", "INTERNAL_ERROR")
		return
	}

	// Tenant isolation: return 404 (not 403) to avoid leaking existence across tenants.
	if run.TenantID != tenantID {
		s.writeErrorResponse(w, http.StatusNotFound, "Run not found", "NOT_FOUND")
		return
	}

	s.writeSuccessResponse(w, run)
}

// handleGetRunJobs handles GET /api/v1/runs/{run_id}/jobs.
func (s *Server) handleGetRunJobs(w http.ResponseWriter, r *http.Request) {
	if s.runManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Run service not available", "SERVICE_UNAVAILABLE")
		return
	}

	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	vars := mux.Vars(r)
	runID := vars["run_id"]
	if runID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "run_id is required", "MISSING_RUN_ID")
		return
	}

	// Verify run existence and tenant ownership before returning job details.
	run, err := s.runManager.GetRun(r.Context(), runID)
	if err != nil {
		if errors.Is(err, controllerrun.ErrNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Run not found", "NOT_FOUND")
			return
		}
		s.logger.Error("Failed to get run", "run_id", logging.SanitizeLogValue(runID), "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list jobs", "INTERNAL_ERROR")
		return
	}
	if run.TenantID != tenantID {
		s.writeErrorResponse(w, http.StatusNotFound, "Run not found", "NOT_FOUND")
		return
	}

	jobs, err := s.runManager.ListRunJobs(r.Context(), runID)
	if err != nil {
		s.logger.Error("Failed to list run jobs", "run_id", logging.SanitizeLogValue(runID), "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list jobs", "INTERNAL_ERROR")
		return
	}

	if jobs == nil {
		jobs = []*controllerrun.JobRecord{}
	}
	s.writeSuccessResponse(w, jobs)
}

// handleDeleteRun handles DELETE /api/v1/runs/{run_id}.
// Returns 200 on success, 404 when not found, 409 when already terminal.
func (s *Server) handleDeleteRun(w http.ResponseWriter, r *http.Request) {
	if s.runManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Run service not available", "SERVICE_UNAVAILABLE")
		return
	}

	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	vars := mux.Vars(r)
	runID := vars["run_id"]
	if runID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "run_id is required", "MISSING_RUN_ID")
		return
	}

	// Verify tenant ownership before cancelling. Returns 404 on mismatch to avoid
	// leaking cross-tenant run existence (IDOR prevention).
	run, err := s.runManager.GetRun(r.Context(), runID)
	if err != nil {
		if errors.Is(err, controllerrun.ErrNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Run not found", "NOT_FOUND")
			return
		}
		s.logger.Error("Failed to get run for cancel", "run_id", logging.SanitizeLogValue(runID), "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to cancel run", "INTERNAL_ERROR")
		return
	}
	if run.TenantID != tenantID {
		s.writeErrorResponse(w, http.StatusNotFound, "Run not found", "NOT_FOUND")
		return
	}

	if run.Status.IsTerminal() {
		s.writeErrorResponse(w, http.StatusConflict, "Run is already in a terminal state", "ALREADY_TERMINAL")
		return
	}

	err = s.runManager.CancelRun(r.Context(), runID)
	if err != nil {
		if errors.Is(err, controllerrun.ErrNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Run not found", "NOT_FOUND")
			return
		}
		if errors.Is(err, controllerrun.ErrAlreadyTerminal) {
			s.writeErrorResponse(w, http.StatusConflict, "Run is already in a terminal state", "ALREADY_TERMINAL")
			return
		}
		s.logger.Error("Failed to cancel run", "run_id", logging.SanitizeLogValue(runID), "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to cancel run", "INTERNAL_ERROR")
		return
	}

	s.writeSuccessResponse(w, map[string]bool{"cancelled": true})
}

// parseRunTarget converts an optional fleet selector string to a fleet.Filter.
// An empty target matches all stewards (within the caller's tenant, enforced by synthesis).
func parseRunTarget(target string) (fleet.Filter, error) {
	if target == "" || target == "all" {
		return fleet.Filter{}, nil
	}
	return fleet.ParseTargetSelector(target)
}

// loadPrivilegeMetadata retrieves ScriptPrivilegeMetadata for the given script from
// the privilege store. Returns (nil, nil) when the entry does not exist.
func (s *Server) loadPrivilegeMetadata(ctx context.Context, tenantID, scriptID string) (*ScriptPrivilegeMetadata, error) {
	if s.privilegeStore == nil {
		return nil, nil
	}
	entry, err := s.privilegeStore.GetConfig(ctx, &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "script-privilege",
		Name:      scriptID,
	})
	if err != nil {
		return nil, err
	}
	var meta ScriptPrivilegeMetadata
	if err := json.Unmarshal(entry.Data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}
