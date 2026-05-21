// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/fleet"
	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	scriptmodule "github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

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
	Target  string            `json:"target"`  // fleet selector string
	Content string            `json:"content"` // base64-encoded inline script
	Shell   string            `json:"shell"`   // shell to use (e.g. "bash")
	Params  map[string]string `json:"params"`  // script parameters
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

	inlineContent, err := base64.StdEncoding.DecodeString(req.Content)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "content must be base64-encoded", "INVALID_CONTENT")
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
