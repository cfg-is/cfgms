// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/modules/script"
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

// handleGetScriptExecutions handles GET /api/v1/stewards/{id}/scripts/executions
func (s *Server) handleGetScriptExecutions(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Get query parameters
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

	// Parse time range
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

	// Parse pagination
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			query.Limit = limit
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			query.Offset = offset
		}
	}

	// TODO: Get script module instance for the steward
	// This would need integration with the steward manager to get the script module
	// For now, we'll return a placeholder response

	executions := []ScriptExecutionInfo{
		{
			ID:            "example-exec-1",
			StewardID:     stewardID,
			ResourceID:    "test-script",
			ExecutionTime: time.Now().Add(-1 * time.Hour),
			Duration:      5000,
			Status:        script.StatusCompleted,
			ExitCode:      0,
			ScriptConfig: ScriptConfigInfo{
				Shell:         "bash",
				Timeout:       30000,
				SigningPolicy: "none",
				Description:   "Example script execution",
				ContentHash:   "sha256:abcd1234",
				ContentLength: 45,
			},
			Metrics: script.ExecutionMetrics{
				StartTime: time.Now().Add(-1 * time.Hour),
				EndTime:   time.Now().Add(-1*time.Hour + 5*time.Second),
				Duration:  5000,
				ProcessID: 12345,
			},
		},
	}

	s.logger.Info("Retrieved script executions", "steward_id", stewardID, "count", len(executions))
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

	// TODO: Get specific execution by ID from script module
	// For now, return a placeholder response

	execution := ScriptExecutionInfo{
		ID:            executionID,
		StewardID:     stewardID,
		ResourceID:    "test-script",
		ExecutionTime: time.Now().Add(-1 * time.Hour),
		Duration:      5000,
		Status:        script.StatusCompleted,
		ExitCode:      0,
		ScriptConfig: ScriptConfigInfo{
			Shell:         "bash",
			Timeout:       30000,
			SigningPolicy: "none",
			Description:   "Example script execution",
			ContentHash:   "sha256:abcd1234",
			ContentLength: 45,
		},
		Metrics: script.ExecutionMetrics{
			StartTime: time.Now().Add(-1 * time.Hour),
			EndTime:   time.Now().Add(-1*time.Hour + 5*time.Second),
			Duration:  5000,
			ProcessID: 12345,
		},
	}

	s.logger.Info("Retrieved script execution", "steward_id", stewardID, "execution_id", executionID)
	s.writeSuccessResponse(w, execution)
}

// handleGetScriptMetrics handles GET /api/v1/stewards/{id}/scripts/metrics
func (s *Server) handleGetScriptMetrics(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Parse since parameter
	since := time.Now().Add(-24 * time.Hour) // Default to last 24 hours
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if sinceTime, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = sinceTime
		}
	}

	// TODO: Get metrics from script module
	// For now, return placeholder metrics

	metrics := ScriptMetricsInfo{
		StewardID:       stewardID,
		Since:           since,
		Until:           time.Now(),
		TotalExecutions: 42,
		SuccessCount:    38,
		FailureCount:    4,
		SuccessRate:     90.48,
		AverageDuration: 3500,
		ShellUsage: map[string]int{
			"bash":       25,
			"powershell": 12,
			"python":     5,
		},
	}

	s.logger.Info("Retrieved script metrics", "steward_id", stewardID, "since", since)
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

	// TODO: Get current script execution status from steward
	// For now, return placeholder status

	status := map[string]interface{}{
		"steward_id":        stewardID,
		"script_capability": "enabled",
		"current_executions": []map[string]interface{}{
			{
				"resource_id": "backup-script",
				"status":      "running",
				"started_at":  time.Now().Add(-5 * time.Minute),
				"progress":    75,
			},
		},
		"last_execution": map[string]interface{}{
			"resource_id":  "health-check",
			"status":       "completed",
			"exit_code":    0,
			"completed_at": time.Now().Add(-10 * time.Minute),
			"duration_ms":  2340,
		},
		"capabilities": map[string]interface{}{
			"supported_shells": []string{"bash", "sh", "python"},
			"max_timeout_ms":   300000,
			"signing_support":  true,
		},
	}

	s.logger.Info("Retrieved script status", "steward_id", stewardID)
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

	// TODO: Implement retry logic
	// This would need to:
	// 1. Get the original execution configuration
	// 2. Re-execute the script with the same parameters
	// 3. Return the new execution ID

	result := map[string]interface{}{
		"original_execution_id": executionID,
		"new_execution_id":      fmt.Sprintf("%s-retry-1", executionID),
		"status":                "initiated",
		"retry_count":           1,
		"initiated_at":          time.Now(),
	}

	s.logger.Info("Initiated script retry", "steward_id", stewardID, "execution_id", executionID)
	s.writeSuccessResponse(w, result)
}
