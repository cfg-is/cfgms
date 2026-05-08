// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ScriptExecutionInfo represents script execution information for API responses
type ScriptExecutionInfo struct {
	ID            string                  `json:"id"`
	StewardID     string                  `json:"steward_id"`
	ResourceID    string                  `json:"resource_id"`
	ExecutionTime time.Time               `json:"execution_time"`
	Duration      int64                   `json:"duration_ms"`
	Status        script.ExecutionStatus  `json:"status"`
	ExitCode      int                     `json:"exit_code"`
	ErrorMessage  string                  `json:"error_message,omitempty"`
	ScriptConfig  ScriptConfigInfo        `json:"script_config"`
	Metrics       script.ExecutionMetrics `json:"metrics"`
	UserID        string                  `json:"user_id,omitempty"`
	TenantID      string                  `json:"tenant_id,omitempty"`
	CorrelationID string                  `json:"correlation_id,omitempty"`
}

// ScriptConfigInfo represents sanitized script configuration for API responses
type ScriptConfigInfo struct {
	Shell         string            `json:"shell"`
	Timeout       int64             `json:"timeout_ms"`
	WorkingDir    string            `json:"working_dir,omitempty"`
	Environment   map[string]string `json:"environment,omitempty"`
	SigningPolicy string            `json:"signing_policy"`
	Description   string            `json:"description,omitempty"`
	ContentHash   string            `json:"content_hash"`
	ContentLength int               `json:"content_length"`
}

// ScriptMetricsInfo represents aggregated script metrics for API responses
type ScriptMetricsInfo struct {
	StewardID       string         `json:"steward_id"`
	Since           time.Time      `json:"since"`
	Until           time.Time      `json:"until"`
	TotalExecutions int            `json:"total_executions"`
	SuccessCount    int            `json:"success_count"`
	FailureCount    int            `json:"failure_count"`
	SuccessRate     float64        `json:"success_rate_percent"`
	AverageDuration int64          `json:"average_duration_ms"`
	ShellUsage      map[string]int `json:"shell_usage"`
}

// executionRecordToInfo maps a durable ExecutionRecord to the API response type.
func executionRecordToInfo(r *script.ExecutionRecord) ScriptExecutionInfo {
	info := ScriptExecutionInfo{
		ID:            r.ExecutionID,
		StewardID:     r.DeviceID,
		ResourceID:    r.ScriptRef,
		ExecutionTime: r.CompletedAt,
		Duration:      r.DurationMs,
		Status:        script.ExecutionStatus(r.State),
		ExitCode:      r.ExitCode,
		ScriptConfig: ScriptConfigInfo{
			Shell:         r.Shell,
			SigningPolicy: "none",
		},
		Metrics: script.ExecutionMetrics{
			EndTime:  r.CompletedAt,
			Duration: r.DurationMs,
		},
	}
	if r.Stderr != "" {
		info.ErrorMessage = r.Stderr
	}
	if r.DurationMs > 0 {
		info.Metrics.StartTime = r.CompletedAt.Add(-time.Duration(r.DurationMs) * time.Millisecond)
	}
	return info
}

// handleGetScriptExecutions handles GET /api/v1/stewards/{id}/scripts/executions
func (s *Server) handleGetScriptExecutions(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	if s.scriptTracker == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Script module not available", "SERVICE_UNAVAILABLE")
		return
	}

	sanitizedID := logging.SanitizeLogValue(stewardID)

	// Parse query filters
	query := &script.AuditQuery{
		StewardID: stewardID,
	}

	if resourceID := r.URL.Query().Get("resource_id"); resourceID != "" {
		query.ResourceID = resourceID
	}
	if status := r.URL.Query().Get("status"); status != "" {
		query.Status = script.ExecutionStatus(status)
	}
	if userID := r.URL.Query().Get("user_id"); userID != "" {
		query.UserID = userID
	}
	if tenantID := r.URL.Query().Get("tenant_id"); tenantID != "" {
		query.TenantID = tenantID
	}
	if since := r.URL.Query().Get("since"); since != "" {
		if sinceTime, err := time.Parse(time.RFC3339, since); err == nil {
			query.StartTime = &sinceTime
		}
	}
	if until := r.URL.Query().Get("until"); until != "" {
		if untilTime, err := time.Parse(time.RFC3339, until); err == nil {
			query.EndTime = &untilTime
		}
	}

	limit := 100 // default
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	// Fetch from durable tracker; request extra to accommodate in-memory offset slicing.
	fetchLimit := limit + offset
	records, err := s.scriptTracker.QueryByDevice(r.Context(), stewardID, fetchLimit)
	if err != nil {
		s.logger.Error("Failed to query script executions", "steward_id", sanitizedID, "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve executions", "INTERNAL_ERROR")
		return
	}

	// Apply in-memory filters for fields the tracker index does not cover.
	filtered := make([]*script.ExecutionRecord, 0, len(records))
	for _, rec := range records {
		if query.ResourceID != "" && rec.ScriptRef != query.ResourceID {
			continue
		}
		if query.Status != "" && script.ExecutionStatus(rec.State) != query.Status {
			continue
		}
		if query.StartTime != nil && rec.CompletedAt.Before(*query.StartTime) {
			continue
		}
		if query.EndTime != nil && rec.CompletedAt.After(*query.EndTime) {
			continue
		}
		filtered = append(filtered, rec)
	}

	// Apply offset then limit.
	if offset > 0 {
		if offset >= len(filtered) {
			filtered = nil
		} else {
			filtered = filtered[offset:]
		}
	}
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}

	executions := make([]ScriptExecutionInfo, len(filtered))
	for i, rec := range filtered {
		executions[i] = executionRecordToInfo(rec)
	}

	s.logger.Info("Retrieved script executions", "steward_id", sanitizedID, "count", len(executions))
	s.writeSuccessResponse(w, executions)
}

// handleGetScriptExecution handles GET /api/v1/stewards/{id}/scripts/executions/{execution_id}
func (s *Server) handleGetScriptExecution(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]
	executionID := vars["execution_id"]

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}
	if executionID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Execution ID is required", "MISSING_EXECUTION_ID")
		return
	}

	if s.scriptTracker == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Script module not available", "SERVICE_UNAVAILABLE")
		return
	}

	sanitizedStewardID := logging.SanitizeLogValue(stewardID)
	sanitizedExecutionID := logging.SanitizeLogValue(executionID)

	// 0 = no limit: scan all records for this device to locate the execution.
	records, err := s.scriptTracker.QueryByDevice(r.Context(), stewardID, 0)
	if err != nil {
		s.logger.Error("Failed to query script executions", "steward_id", sanitizedStewardID, "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve execution", "INTERNAL_ERROR")
		return
	}

	for _, rec := range records {
		if rec.ExecutionID == executionID {
			s.logger.Info("Retrieved script execution", "steward_id", sanitizedStewardID, "execution_id", sanitizedExecutionID)
			s.writeSuccessResponse(w, executionRecordToInfo(rec))
			return
		}
	}

	s.writeErrorResponse(w, http.StatusNotFound, "Execution not found", "EXECUTION_NOT_FOUND")
}

// handleGetScriptMetrics handles GET /api/v1/stewards/{id}/scripts/metrics
func (s *Server) handleGetScriptMetrics(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	if s.scriptAuditLogger == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Script module not available", "SERVICE_UNAVAILABLE")
		return
	}

	sanitizedID := logging.SanitizeLogValue(stewardID)

	since := time.Now().Add(-24 * time.Hour) // default: last 24 hours
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if sinceTime, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = sinceTime
		}
	}

	aggregated, err := s.scriptAuditLogger.GetExecutionMetrics(stewardID, since)
	if err != nil {
		s.logger.Error("Failed to get script metrics", "steward_id", sanitizedID, "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve metrics", "INTERNAL_ERROR")
		return
	}

	metrics := ScriptMetricsInfo{
		StewardID:       aggregated.StewardID,
		Since:           aggregated.Since,
		Until:           aggregated.Until,
		TotalExecutions: aggregated.TotalExecutions,
		SuccessCount:    aggregated.SuccessCount,
		FailureCount:    aggregated.FailureCount,
		SuccessRate:     aggregated.SuccessRate,
		AverageDuration: aggregated.AverageDuration,
		ShellUsage:      aggregated.ShellUsage,
	}
	if metrics.StewardID == "" {
		metrics.StewardID = stewardID
	}
	if metrics.Since.IsZero() {
		metrics.Since = since
	}
	if metrics.Until.IsZero() {
		metrics.Until = time.Now()
	}

	s.logger.Info("Retrieved script metrics", "steward_id", sanitizedID, "since", since)
	s.writeSuccessResponse(w, metrics)
}

// handleGetScriptStatus handles GET /api/v1/stewards/{id}/scripts/status
func (s *Server) handleGetScriptStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	if s.scriptTracker == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Script module not available", "SERVICE_UNAVAILABLE")
		return
	}

	sanitizedID := logging.SanitizeLogValue(stewardID)

	// Most-recent completed execution provides the "last execution" summary.
	recent, err := s.scriptTracker.QueryByDevice(r.Context(), stewardID, 1)
	if err != nil {
		s.logger.Error("Failed to get script status", "steward_id", sanitizedID, "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve script status", "INTERNAL_ERROR")
		return
	}

	var lastExecution map[string]interface{}
	if len(recent) > 0 {
		rec := recent[0]
		lastExecution = map[string]interface{}{
			"execution_id": rec.ExecutionID,
			"resource_id":  rec.ScriptRef,
			"status":       rec.State,
			"exit_code":    rec.ExitCode,
			"completed_at": rec.CompletedAt,
			"duration_ms":  rec.DurationMs,
		}
	}

	// Active executions come from the in-memory monitor (running + pending).
	activeExecutions := []map[string]interface{}{}
	if s.scriptMonitor != nil {
		for _, exec := range s.scriptMonitor.ListExecutions("") {
			for _, dev := range exec.Devices {
				if dev.DeviceID == stewardID &&
					(dev.Status == script.StatusRunning || dev.Status == script.StatusPending) {
					activeExecutions = append(activeExecutions, map[string]interface{}{
						"execution_id": exec.ID,
						"resource_id":  exec.ScriptName,
						"status":       dev.Status,
						"started_at":   dev.StartTime,
					})
				}
			}
		}
	}

	status := map[string]interface{}{
		"steward_id":         stewardID,
		"script_capability":  "enabled",
		"current_executions": activeExecutions,
		"last_execution":     lastExecution,
	}

	s.logger.Info("Retrieved script status", "steward_id", sanitizedID)
	s.writeSuccessResponse(w, status)
}

// handlePostScriptRetry handles POST /api/v1/stewards/{id}/scripts/executions/{execution_id}/retry
func (s *Server) handlePostScriptRetry(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]
	executionID := vars["execution_id"]

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}
	if executionID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Execution ID is required", "MISSING_EXECUTION_ID")
		return
	}

	s.logger.Info("Script retry is not supported via REST: retries are managed by the job scheduler",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"execution_id", logging.SanitizeLogValue(executionID),
	)
	s.writeErrorResponse(w, http.StatusNotImplemented, "Script retry is managed by the job scheduler", "NOT_IMPLEMENTED")
}
