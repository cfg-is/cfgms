// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/batchjob"
	"github.com/cfgis/cfgms/pkg/fleet/selector"
	"github.com/cfgis/cfgms/pkg/logging"
)

// jobExecutor is the minimal interface satisfied by *batchjob.RollingBatchExecutor.
// Defined here (not in batchjob) to keep the api package self-contained and to let
// test components inject a controlled executor without depending on the concrete type.
type jobExecutor interface {
	Execute(ctx context.Context, job *batchjob.BatchJob) error
}

// createJobRequest is the JSON body for POST /api/v1/jobs.
type createJobRequest struct {
	Selector          string `json:"selector"`
	BatchSize         int    `json:"batch_size"`
	PreviousConfigRef string `json:"previous_config_ref,omitempty"`
}

// createJobResponse is the JSON body returned on 202 Accepted.
type createJobResponse struct {
	JobID       string `json:"job_id"`
	Status      string `json:"status"`
	TargetCount int    `json:"target_count"`
}

// handleCreateJob handles POST /api/v1/jobs.
//
// Accepts a fleet selector and batch size, resolves the selector to a steward
// set, persists an initial BatchJob record, starts the rolling-batch executor
// asynchronously, and returns 202 Accepted with the job ID and target count.
func (s *Server) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	if s.batchJobStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Batch job service not available", "SERVICE_UNAVAILABLE")
		return
	}

	// Reject non-admin callers with no tenant — mirrors authRunAccess (Issue #1990).
	principal, tenantID, ok := s.authRunAccess(w, r)
	if !ok {
		return
	}

	var req createJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	if req.Selector == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"selector is required: use 'all' to match all stewards", "MISSING_SELECTOR")
		return
	}

	batchSize := req.BatchSize
	if batchSize <= 0 {
		batchSize = 10
	}

	// safeSelector strips control characters for safe log inclusion. SanitizeLogValue
	// handles the full control-character set; the sequential strings.ReplaceAll pair is
	// required additionally because CodeQL's ReplaceSanitizer only recognises top-level
	// variable re-assignments with literal "\n"/"\r", not function-call boundaries.
	safeSelector := logging.SanitizeLogValue(req.Selector)
	safeSelector = strings.ReplaceAll(safeSelector, "\n", "_")
	safeSelector = strings.ReplaceAll(safeSelector, "\r", "_")

	filter, parsedTenantPath, err := selector.Parse(req.Selector)
	if err != nil {
		// err embeds req.Selector via selector.Parse format strings — sanitize before logging.
		safeParseErr := err.Error()
		safeParseErr = strings.ReplaceAll(safeParseErr, "\n", "_")
		safeParseErr = strings.ReplaceAll(safeParseErr, "\r", "_")
		s.logger.Info("Invalid selector expression",
			"selector", safeSelector, "error", safeParseErr)
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_SELECTOR")
		return
	}

	// Scope to the caller's subtree. An explicit selector prefix must be within
	// the caller's subtree; absent prefix defaults to tenantID and all descendants.
	// Global-scope callers (empty tenantID) are unrestricted.
	if parsedTenantPath != "" {
		if !principal.GlobalScope && tenantID != "" &&
			parsedTenantPath != tenantID &&
			!strings.HasPrefix(parsedTenantPath, tenantID+"/") {
			s.writeErrorResponse(w, http.StatusForbidden,
				"Target tenant is outside the caller's authorized subtree", "CROSS_TENANT")
			return
		}
		filter.TenantSubtree = parsedTenantPath
	} else if !principal.GlobalScope {
		filter.TenantSubtree = tenantID
	}

	results, err := s.fleetQuery.Search(r.Context(), filter)
	if err != nil {
		s.logger.Error("Fleet query failed during job creation", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to query fleet", "INTERNAL_ERROR")
		return
	}

	targetIDs := make([]string, 0, len(results))
	for _, res := range results {
		targetIDs = append(targetIDs, res.ID)
	}

	// jobID is captured before the struct so log calls in this handler and the
	// goroutine reference a local that CodeQL does not taint via job.Selector.
	jobID := uuid.New().String()
	now := time.Now().UTC()
	job := &batchjob.BatchJob{
		ID:       jobID,
		TenantID: tenantID,
		Selector: req.Selector,
		Config: batchjob.BatchJobConfig{
			BatchSize:         batchSize,
			PreviousConfigRef: req.PreviousConfigRef,
		},
		Targets:   targetIDs,
		Status:    batchjob.BatchJobStatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.batchJobStore.CreateBatchJob(r.Context(), job); err != nil {
		s.logger.Error("Failed to persist batch job", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create job", "INTERNAL_ERROR")
		return
	}

	s.logger.Info("Batch job created",
		"job_id", jobID,
		"selector", safeSelector,
		"target_count", len(targetIDs),
		"batch_size", strings.ReplaceAll(strconv.Itoa(batchSize), "\n", ""))

	// Start the executor asynchronously — the HTTP response returns immediately.
	if s.batchJobExecutor != nil {
		executor := s.batchJobExecutor
		go func() {
			if execErr := executor.Execute(context.Background(), job); execErr != nil {
				// execErr may embed job.Selector (user-tainted) via executor error messages.
				// Sanitize with the sequential-reassignment form that CodeQL's ReplaceSanitizer
				// recognises; logging.SanitizeLogValue alone is not recognised at call sites.
				safeExecErr := execErr.Error()
				safeExecErr = strings.ReplaceAll(safeExecErr, "\n", "_")
				safeExecErr = strings.ReplaceAll(safeExecErr, "\r", "_")
				s.logger.Error("Batch job execution failed",
					"job_id", jobID, "error", safeExecErr)
			}
		}()
	}

	s.writeResponse(w, http.StatusAccepted, createJobResponse{
		JobID:       job.ID,
		Status:      string(job.Status),
		TargetCount: len(targetIDs),
	})
}

// handleListJobs handles GET /api/v1/jobs.
// Returns a tenant-scoped, paginated list of batch jobs. TenantID is always sourced
// from the authenticated principal's context — any tenant_id query param supplied
// by the caller is silently discarded. Global-scope (admin mTLS) principals
// receive jobs across all tenants.
func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	if s.batchJobStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Batch job service not available", "SERVICE_UNAVAILABLE")
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

	jobs, err := s.batchJobStore.ListBatchJobs(r.Context(), tenantID, limit, offset)
	if err != nil {
		s.logger.Error("Failed to list batch jobs",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", err,
		)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list jobs", "INTERNAL_ERROR")
		return
	}

	if jobs == nil {
		jobs = []*batchjob.BatchJob{}
	}
	s.writeSuccessResponse(w, jobs)
}

// handleGetJob handles GET /api/v1/jobs/{id}.
//
// Returns the full BatchJob JSON for the caller's tenant. Rejects with 404
// when the job does not exist and 403 when the job belongs to a different tenant.
func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	if s.batchJobStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Batch job service not available", "SERVICE_UNAVAILABLE")
		return
	}

	// Reject non-admin callers with no tenant — mirrors authRunAccess (Issue #1990).
	principal, tenantID, ok := s.authRunAccess(w, r)
	if !ok {
		return
	}

	vars := mux.Vars(r)
	jobID := vars["id"]

	job, err := s.batchJobStore.GetBatchJob(r.Context(), jobID)
	if err != nil {
		if errors.Is(err, batchjob.ErrBatchJobNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Job not found", "NOT_FOUND")
			return
		}
		s.logger.Error("Failed to retrieve batch job",
			"job_id", logging.SanitizeLogValue(jobID), "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve job", "INTERNAL_ERROR")
		return
	}

	if !principal.GlobalScope && job.TenantID != tenantID {
		s.writeErrorResponse(w, http.StatusForbidden, "Access denied", "FORBIDDEN")
		return
	}

	s.writeSuccessResponse(w, job)
}
