// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/fleet"
	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	scriptmodule "github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/fleet/selector"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// bannedPatterns is the controller-side command denylist (CLAUDE.md §Modules,
// execution path 3). The steward re-applies the same list at exec time for
// defense-in-depth. Do NOT log the command string — log only the matched name.
var bannedPatterns = []struct {
	name    string
	pattern string
}{
	{"iex", "iex"},
	{"Invoke-Expression", "invoke-expression"},
	{"EncodedCommand", "-encodedcommand"},
	{"ExecutionPolicyBypass", "-executionpolicy bypass"},
	{"bash-c", "bash -c"},
	{"eval", "eval"},
	{"python-c", "python -c"},
}

// allowedShells is the set of shells accepted by POST /api/v1/runs/command.
// Any value outside this set is rejected with UNSUPPORTED_SHELL.
// The set is kept in lockstep with the steward executor's accepted shells
// (features/modules/stdlib/script/executor.go). Valid taxonomy per platform:
//   - Unix:    bash, sh
//   - Windows: powershell (Windows PowerShell 5.1), pwsh (PowerShell Core), cmd
//   - pwsh is also valid on Unix (PowerShell Core is cross-platform).
var allowedShells = map[string]bool{
	"bash":       true,
	"sh":         true,
	"powershell": true,
	"pwsh":       true,
	"cmd":        true,
}

// containsBannedPattern returns the pattern name and true if s contains any
// entry from bannedPatterns (case-insensitive). The raw command string is never
// returned to avoid logging it.
func containsBannedPattern(s string) (string, bool) {
	lower := strings.ToLower(s)
	for _, bp := range bannedPatterns {
		if strings.Contains(lower, bp.pattern) {
			return bp.name, true
		}
	}
	return "", false
}

// execCommandSignature is the optional signature block sent by cfg steward exec.
type execCommandSignature struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
	PublicKey string `json:"public_key"`
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
//
// Targets, Nonce, and ExpiresAt (Issue #3694) are the client-resolved, signed
// coordinates of the operator's operatorpayload.Envelope: Targets is the frozen list
// of steward IDs the signature authorizes, Nonce is a single-use replay token, and
// ExpiresAt (RFC3339) bounds the envelope's validity. All three are forwarded to the
// steward unmodified — the controller never re-signs or strips them.
type postRunCommandRequest struct {
	Target    string                `json:"target"`     // fleet selector string
	Content   string                `json:"content"`    // base64-encoded inline script
	Shell     string                `json:"shell"`      // shell to use (e.g. "bash")
	Params    map[string]string     `json:"params"`     // script parameters
	Signature *execCommandSignature `json:"signature"`  // operator signing envelope (mandatory)
	Targets   []string              `json:"targets"`    // resolved steward IDs the signature binds
	Nonce     string                `json:"nonce"`      // single-use replay-prevention token
	ExpiresAt string                `json:"expires_at"` // RFC3339 envelope expiry
}

// validatePublicBetaCommandSignature verifies the operator signature over the
// reconstructed operatorpayload.Envelope canonical bytes (content, shell, targets,
// nonce, expiry) — never over content alone. It runs unconditionally for every caller
// of POST /api/v1/runs/command (Issue #3694): the prior SecurityProfilePublicBeta gate
// is gone, so this now changes behavior for every deployment, not just public-beta
// ones. It performs cryptographic verification plus operator-credential trust
// (CA chain, payload-signing marker, revocation); expiry and nonce-replay enforcement
// are the steward's responsibility (independent of the outer command's own replay
// window), not re-checked here.
//
// The marker requirement is HasPayloadSigningMarker, not HasAdminMarker (Issue #3696).
// This endpoint sits on the trust boundary between the two ends of the signed ad-hoc
// path, and all three must agree on one credential type: cfg signs with the zero-custody
// CSR credential (signCommandContent, cmd/cfg/cmd/steward.go), this check mediates the
// submission, and the steward re-verifies on delivery (verifyOperatorCert,
// features/steward/commands/execute_script.go). An admin transport bundle authenticates
// mTLS; it does not authorize signing an operator payload.
// It returns the operator signing certificate's serial number on success — the
// signing-credential identifier the Issue #3698 audit trail records — so callers
// never need to re-parse sig.PublicKey just to learn which credential authorized
// the dispatch.
func (s *Server) validatePublicBetaCommandSignature(content []byte, shell string, targets []string, nonce string, expiresAt time.Time, sig *execCommandSignature) (string, error) {
	if sig == nil || sig.Algorithm == "" || sig.Value == "" || sig.PublicKey == "" {
		return "", fmt.Errorf("ad-hoc execution requires an operator signature")
	}
	if s.certManager == nil {
		return "", fmt.Errorf("ad-hoc execution requires loaded controller signing roots")
	}

	envelope := operatorpayload.Envelope{
		Content:   content,
		Shell:     shell,
		Targets:   targets,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
	}
	canonicalBytes, err := operatorpayload.CanonicalBytes(envelope)
	if err != nil {
		return "", fmt.Errorf("invalid operator envelope: %w", err)
	}

	scriptSig := &scriptmodule.ScriptSignature{
		Algorithm: sig.Algorithm,
		Signature: sig.Value,
		PublicKey: sig.PublicKey,
	}
	if err := scriptmodule.VerifyScriptSignature(
		canonicalBytes,
		scriptSig,
		scriptmodule.ShellType(shell),
		scriptmodule.ModuleSigningConfig{TrustMode: scriptmodule.TrustModeAnyValid},
	); err != nil {
		return "", fmt.Errorf("invalid operator signature: %w", err)
	}

	caPEM, err := s.certManager.GetCACertificate()
	if err != nil {
		return "", fmt.Errorf("controller signing roots unavailable: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return "", fmt.Errorf("controller signing roots are invalid")
	}
	block, _ := pem.Decode([]byte(sig.PublicKey))
	if block == nil {
		return "", fmt.Errorf("operator signing certificate is not valid PEM")
	}
	operatorCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("operator signing certificate is invalid: %w", err)
	}
	if _, err := operatorCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return "", fmt.Errorf("operator signing certificate is not trusted by the controller CA: %w", err)
	}
	if !cert.HasPayloadSigningMarker(operatorCert) {
		return "", fmt.Errorf("operator signing certificate is not a payload-signing certificate")
	}
	revoked, err := s.certManager.IsRevoked(operatorCert.SerialNumber.String())
	if err != nil {
		return "", fmt.Errorf("failed to check operator signing certificate revocation status: %w", err)
	}
	if revoked {
		return "", fmt.Errorf("operator signing certificate is revoked")
	}
	return operatorCert.SerialNumber.String(), nil
}

// authRunAccess authenticates a request to the ad-hoc run API and returns the
// principal and its tenant scope. Admin mTLS and session principals carry global
// (cross-tenant) scope with an empty TenantID (middleware.go); the run path is
// designed for that — an empty tenant yields an unscoped fleet search, the
// dispatch RBAC check is skipped, and the audit uses the system-tenant sentinel.
// Only a machine (API-key) principal with no tenant is a genuine auth failure.
//
// This deliberately checks principal.Assurance == session.AssuranceMachine rather
// than !principal.GlobalScope: Assurance is the direct signal for machine-authenticated
// principals; GlobalScope models tenant-visibility breadth — an orthogonal axis that
// must not be collapsed with authentication method (see Principal doc comment). Both
// session paths now compute GlobalScope from actual scope (web-session: acct.RootScope
// at middleware.go:433; cfg-CLI Bearer: sess.TenantID=="" at middleware.go:357), so
// !GlobalScope is no longer a dead check — but it would answer the wrong question.
//
// On failure it writes the 401 and returns ok=false (Issue #1990).
func (s *Server) authRunAccess(w http.ResponseWriter, r *http.Request) (principal *Principal, tenantID string, ok bool) {
	principal, hasPrincipal := r.Context().Value(principalContextKey).(*Principal)
	if !hasPrincipal || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return nil, "", false
	}
	tenantID, _ = r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" && principal.Assurance == session.AssuranceMachine {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return nil, "", false
	}
	return principal, tenantID, true
}

// runVisibleTo reports whether the caller may read/cancel the given run.
// Callers scoped to a tenant see only runs within their authorized subtree; an
// empty tenantID (mTLS admin) has unrestricted access. Callers return 404 (not
// 403) on false to avoid leaking cross-tenant run existence (Issue #1990).
func runVisibleTo(_ *Principal, run *controllerrun.RunRecord, tenantID string) bool {
	return isWithinTenantScope(tenantID, run.TenantID)
}

// handlePostRunScript handles POST /api/v1/runs/script.
// Creates a run record and fans out one QueuedExecution per matched steward.
func (s *Server) handlePostRunScript(w http.ResponseWriter, r *http.Request) {
	if s.runManager == nil || s.runExecutionQueue == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Run service not available", "SERVICE_UNAVAILABLE")
		return
	}

	principal, tenantID, ok := s.authRunAccess(w, r)
	if !ok {
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
	// Privilege metadata is tenant-scoped. A global admin (empty tenant) is not
	// bound by per-tenant script scope, so skip the lookup rather than querying the
	// store with an empty tenant key (which is undefined/store-dependent) — Issue #1990.
	var paramPlatformBindings map[string]string
	var requiredAPIScope []string
	if s.privilegeStore != nil && tenantID != "" {
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
			"error", logging.SanitizeLogValue(err.Error()),
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

	principal, tenantID, ok := s.authRunAccess(w, r)
	if !ok {
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
	if !allowedShells[req.Shell] {
		s.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("unsupported shell %q; allowed: bash, sh, powershell, pwsh, cmd", logging.SanitizeLogValue(req.Shell)),
			"UNSUPPORTED_SHELL")
		return
	}

	inlineContent, err := base64.StdEncoding.DecodeString(req.Content)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "content must be base64-encoded", "INVALID_CONTENT")
		return
	}
	expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "expires_at must be RFC3339", "INVALID_EXPIRES_AT")
		return
	}
	credentialID, err := s.validatePublicBetaCommandSignature(inlineContent, req.Shell, req.Targets, req.Nonce, expiresAt, req.Signature)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_SIGNATURE")
		return
	}

	// Blast-radius bound (Issue #3698): a hard reject at admission, checked against the
	// operator-signed, already-resolved Targets list — after signature verification (so a
	// malformed or forged request is never what trips this check) and before dispatch. A
	// good signature does not exempt an oversized target set: the bound is a compensating
	// control for a compromised-controller UI-trust gap, not a defense against forgery.
	if maxTargets := s.resolveMaxTargetsForTenant(r.Context(), tenantID); len(req.Targets) > maxTargets {
		s.emitOperatorPayloadDispatchAudit(r.Context(), tenantID, principal.ID, string(inlineContent),
			credentialID, req.Targets, "", business.AuditResultDenied,
			fmt.Sprintf("resolved target count %d exceeds tenant bound of %d", len(req.Targets), maxTargets))
		s.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("resolved target count %d exceeds the maximum of %d targets allowed for this tenant", len(req.Targets), maxTargets),
			"BLAST_RADIUS_EXCEEDED")
		return
	}

	// Banned-pattern enforcement — controller-side (defense-in-depth; steward also checks).
	if patternName, found := containsBannedPattern(string(inlineContent)); found {
		s.logger.Warn("command rejected: banned pattern detected", "pattern", patternName)
		s.writeErrorResponse(w, http.StatusBadRequest, "command contains a prohibited pattern", "BANNED_PATTERN")
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

	// Tenant RBAC check for id: targets — enforce admin.tenant_path is a prefix of
	// steward.tenant_path. Applied only when the principal has a non-empty TenantID
	// (API key users). Admin mTLS principals (TenantID="") have global access.
	// selector.Parse populates filter.IDs (comma-OR list); filter.DeviceID is the
	// legacy query-param path only.
	if principal.TenantID != "" {
		for _, targetID := range filter.IDs {
			if forbidden := s.enforceExecTenantScope(r.Context(), targetID, principal.TenantID); forbidden {
				s.writeErrorResponse(w, http.StatusForbidden,
					"access denied: steward is not in your tenant scope", "FORBIDDEN")
				return
			}
		}
		if filter.DeviceID != "" {
			if forbidden := s.enforceExecTenantScope(r.Context(), filter.DeviceID, principal.TenantID); forbidden {
				s.writeErrorResponse(w, http.StatusForbidden,
					"access denied: steward is not in your tenant scope", "FORBIDDEN")
				return
			}
		}
	}

	var commandSignature *controllerrun.CommandSignature
	if req.Signature != nil {
		commandSignature = &controllerrun.CommandSignature{
			Algorithm: req.Signature.Algorithm,
			Value:     req.Signature.Value,
			PublicKey: req.Signature.PublicKey,
		}
	}

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
		commandSignature,
		req.Targets,
		req.Nonce,
		expiresAt,
	)
	if err != nil {
		s.logger.Error("Failed to synthesize command run",
			"shell", logging.SanitizeLogValue(req.Shell),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create run", "INTERNAL_ERROR")
		return
	}

	// Audit every accepted dispatch (Issue #3698) — literal payload text, the full
	// operator-signed target list, the signing credential id, and the caller identity.
	s.emitOperatorPayloadDispatchAudit(r.Context(), tenantID, principal.ID, string(inlineContent),
		credentialID, req.Targets, runID, business.AuditResultSuccess, "")

	s.writeSuccessResponse(w, map[string]string{"run_id": runID})
}

// handleListRuns handles GET /api/v1/runs.
// Returns a tenant-scoped, paginated list of runs. TenantID is always sourced
// from the authenticated principal's context — any tenant_id query param supplied
// by the caller is silently discarded. Global-scope (admin mTLS) principals
// receive runs across all tenants.
func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	if s.runManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Run service not available", "SERVICE_UNAVAILABLE")
		return
	}

	_, tenantID, ok := s.authRunAccess(w, r)
	if !ok {
		return
	}

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			if l < 1 {
				l = 1
			}
			if l > 500 {
				l = 500
			}
			limit = l
		}
	}

	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	runs, err := s.runManager.ListRuns(r.Context(), tenantID, limit, offset)
	if err != nil {
		s.logger.Error("Failed to list runs",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", err,
		)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list runs", "INTERNAL_ERROR")
		return
	}

	if runs == nil {
		runs = []*controllerrun.RunRecord{}
	}
	s.writeSuccessResponse(w, runs)
}

// handleGetRun handles GET /api/v1/runs/{run_id}.
func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	if s.runManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Run service not available", "SERVICE_UNAVAILABLE")
		return
	}

	principal, tenantID, ok := s.authRunAccess(w, r)
	if !ok {
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
	if !runVisibleTo(principal, run, tenantID) {
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

	principal, tenantID, ok := s.authRunAccess(w, r)
	if !ok {
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
	if !runVisibleTo(principal, run, tenantID) {
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

	principal, tenantID, ok := s.authRunAccess(w, r)
	if !ok {
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
	if !runVisibleTo(principal, run, tenantID) {
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
// The tenant path extracted by selector.Parse is discarded here; exec tenant enforcement
// uses enforceExecTenantScope (device-ID prefix check) rather than Filter.TenantSubtree.
func parseRunTarget(target string) (fleet.Filter, error) {
	if target == "" || target == "all" {
		return fleet.Filter{}, nil
	}
	f, _, err := selector.Parse(target)
	return f, err
}

// enforceExecTenantScope checks whether the principal's tenantID is a path-prefix
// (or exact match) of the target steward's tenantID. Returns true (forbidden) when
// the steward is found but is outside the principal's tenant scope.
// Returns false (allowed) when the steward is not found — synthesis will create a
// zero-job run, and we return 200 with an empty result rather than 404, because
// steward IDs are not secret (admins get them via cfg steward list).
func (s *Server) enforceExecTenantScope(ctx context.Context, deviceID, principalTenantID string) bool {
	if s.fleetQuery == nil {
		return false
	}
	results, err := s.fleetQuery.Search(ctx, fleet.Filter{DeviceID: deviceID})
	if err != nil {
		return false
	}
	for _, sr := range results {
		if sr.ID != deviceID {
			continue
		}
		// Steward found — check tenant path prefix.
		if sr.TenantID == principalTenantID {
			return false
		}
		if strings.HasPrefix(sr.TenantID, principalTenantID+"/") {
			return false
		}
		return true // steward exists but outside tenant scope
	}
	return false // steward not found — allow, synthesis yields zero jobs
}

// defaultMaxOperatorPayloadTargets is the blast-radius bound applied when no tenant
// along the root-to-leaf path (including the root) has configured a narrower
// override (Issue #3698). It is a flat count, never a percentage-of-fleet — a
// percentage grows exactly as the fleet gets more dangerous — and it is the
// deliberately chosen enforced primitive for the epic, not a placeholder for a
// future percentage-based or more elaborate policy engine.
const defaultMaxOperatorPayloadTargets = 1000

// resolveMaxTargetsForTenant resolves the per-tenant maximum-target-count bound for
// operator payload dispatch (Issue #3698), walking the tenant path root-to-leaf via
// the identical override-walk pattern as resolveAssuranceRequirement (middleware.go)
// and resolveAssuranceRequirementForPath (handlers_assurance_policy.go): a parent
// tenant's MaxTargets is the default, and a tenant closer to the caller's leaf
// narrows it by setting its own. When blastRadiusPolicyStore or tenantStore is nil,
// or tenantID is empty, it returns defaultMaxOperatorPayloadTargets unchanged —
// preserving safe behavior for bare Server instances built without these stores.
//
// GetTenantPath or GetPolicy errors are logged at Warn and fall back to the default:
// consistent with resolveAssuranceRequirement, a storage hiccup must never turn into
// an unbounded blast radius (fail-open past the default) or a fleet-wide dispatch
// outage (treating the error as "reject everything") — falling back to the
// conservative default is safe in both directions.
func (s *Server) resolveMaxTargetsForTenant(ctx context.Context, tenantID string) int {
	if s.blastRadiusPolicyStore == nil || s.tenantStore == nil || tenantID == "" {
		return defaultMaxOperatorPayloadTargets
	}

	path, err := s.tenantStore.GetTenantPath(ctx, tenantID)
	if err != nil {
		s.logger.Warn("resolveMaxTargetsForTenant: failed to get tenant path; using default bound",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		return defaultMaxOperatorPayloadTargets
	}

	result := defaultMaxOperatorPayloadTargets
	for _, t := range path {
		policy, err := s.blastRadiusPolicyStore.GetPolicy(ctx, t)
		if err != nil {
			s.logger.Warn("resolveMaxTargetsForTenant: failed to get blast-radius policy; using default bound",
				"tenant_id", logging.SanitizeLogValue(t),
				"error", logging.SanitizeLogValue(err.Error()),
			)
			return defaultMaxOperatorPayloadTargets
		}
		if policy.MaxTargets != nil {
			result = *policy.MaxTargets
		}
	}
	return result
}

// emitOperatorPayloadDispatchAudit records an operator payload dispatch attempt —
// accepted or rejected, either credential path — via audit.NewEventBuilder, mirroring
// emitOsqueryAudit's field shape (handlers_osquery.go). It is a no-op when auditManager
// is nil.
//
// The payload is recorded as a SHA-256 digest and a byte length, never as literal
// text. Issue #3698 makes the blast-radius bound and this audit trail the compensating
// controls for the epic's accepted UI-trust residual risk (a compromised controller
// could show an operator one payload and sign another), and a digest discharges that:
// an investigator holding a candidate payload can prove or disprove that it is the one
// dispatched. Storing the text itself cannot be reconciled with the project rule against
// writing secrets to disk — an operator payload is arbitrary operator-authored script
// text and routinely carries credentials inline. Redaction was attempted and rejected:
// a filter over free-form script text in any shell leaks on the shapes it does not
// model, so the digest is the enforced form rather than a best-effort scrub.
//
// Every steward reference in targets is already a cfg-declared resource id (steward ID),
// never a live hostname. Target entries beyond the first 10 are counted but not
// individually recorded, to keep audit record size bounded — the same cap
// emitOsqueryAudit applies.
func (s *Server) emitOperatorPayloadDispatchAudit(ctx context.Context, tenantID, callerID, payloadText, credentialID string, targets []string, runID string, result business.AuditResult, rejectionReason string) {
	if s.auditManager == nil {
		return
	}
	// Use a non-empty sentinel when tenantID is empty (mTLS admin with global scope).
	auditTenantID := tenantID
	if auditTenantID == "" {
		auditTenantID = audit.SystemTenantID
	}

	severity := business.AuditSeverityHigh
	if result != business.AuditResultSuccess {
		severity = business.AuditSeverityCritical
	}

	// The payload is identified by digest, never stored. hex.EncodeToString of a
	// sha256 sum is fixed-width and contains no operator-supplied bytes, so it needs
	// no sanitizing before it reaches the audit record.
	digest := sha256.Sum256([]byte(payloadText))
	payloadDigest := hex.EncodeToString(digest[:])

	// AuditEntry.ResourceID is a required, non-empty field (Manager.validateEntry) — but
	// the WebAuthn path's begin-time blast-radius rejection has no credential yet (the
	// operator has not authenticated an assertion), so credentialID can legitimately be
	// "". Recording that absence must not silently drop the whole audit event: the
	// resource identifier falls back to a sentinel, while the actual (possibly empty)
	// credential id is always recorded verbatim in the "credential_id" detail — the field
	// the AC requires.
	resourceID := credentialID
	if resourceID == "" {
		resourceID = "unresolved"
	}

	b := audit.NewEventBuilder().
		Tenant(auditTenantID).
		Type(business.AuditEventSystemAccess).
		Action("operator_payload.dispatch").
		User(callerID, business.AuditUserTypeHuman).
		Resource("operator_credential", logging.SanitizeLogValue(resourceID), "").
		Result(result).
		Severity(severity).
		Detail("payload_sha256", payloadDigest).
		Detail("payload_bytes", fmt.Sprintf("%d", len(payloadText))).
		Detail("credential_id", logging.SanitizeLogValue(credentialID)).
		Detail("target_count", fmt.Sprintf("%d", len(targets))).
		Detail("run_id", runID)
	if rejectionReason != "" {
		b = b.Detail("rejection_reason", rejectionReason)
	}

	for i, target := range targets {
		if i >= 10 {
			// Cap per-target detail entries to avoid unbounded audit record size.
			b = b.Detail("targets_truncated", "true")
			break
		}
		b = b.Detail(fmt.Sprintf("target_%d", i), logging.SanitizeLogValue(target))
	}

	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit operator payload dispatch audit event",
			"error", logging.SanitizeLogValue(err.Error()),
			"run_id", logging.SanitizeLogValue(runID),
		)
	}
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
