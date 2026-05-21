// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ScriptPrivilegeMetadata holds controller-side privilege configuration for a library script.
// It is stored per-tenant and never included in VersionedScript (steward-visible).
type ScriptPrivilegeMetadata struct {
	ScriptID              string            `json:"script_id"`
	RequiredAPIScope      []string          `json:"required_api_scope,omitempty"`
	ParamPlatformBindings map[string]string `json:"param_platform_bindings,omitempty"`
	SetByUserID           string            `json:"set_by_user_id"`
	SetAt                 time.Time         `json:"set_at"`
}

// SetPrivilegeRequest is the body of PUT /api/v1/scripts/{id}/privilege.
type SetPrivilegeRequest struct {
	RequiredAPIScope      []string          `json:"required_api_scope,omitempty"`
	ParamPlatformBindings map[string]string `json:"param_platform_bindings,omitempty"`
}

// storePrivilegeMetadata writes privilege metadata to the config store under the tenant namespace.
func (s *Server) storePrivilegeMetadata(ctx context.Context, tenantID, scriptID string, meta *ScriptPrivilegeMetadata) error {
	if s.privilegeStore == nil {
		return fmt.Errorf("privilege store not configured")
	}

	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal privilege metadata: %w", err)
	}

	checksum := fmt.Sprintf("%x", sha256.Sum256(data))
	entry := &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{
			TenantID:  tenantID,
			Namespace: "script-privilege",
			Name:      scriptID,
		},
		Data:      data,
		Format:    cfgconfig.ConfigFormatJSON,
		Checksum:  checksum,
		UpdatedAt: meta.SetAt,
		UpdatedBy: meta.SetByUserID,
		Source:    "script-admin",
	}

	return s.privilegeStore.StoreConfig(ctx, entry)
}

// loadPrivilegeMetadata reads privilege metadata from the config store.
func (s *Server) loadPrivilegeMetadata(ctx context.Context, tenantID, scriptID string) (*ScriptPrivilegeMetadata, error) {
	if s.privilegeStore == nil {
		return nil, fmt.Errorf("privilege store not configured")
	}

	key := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "script-privilege",
		Name:      scriptID,
	}

	entry, err := s.privilegeStore.GetConfig(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("privilege metadata not found: %w", err)
	}

	var meta ScriptPrivilegeMetadata
	if err := json.Unmarshal(entry.Data, &meta); err != nil {
		return nil, fmt.Errorf("failed to parse privilege metadata: %w", err)
	}

	return &meta, nil
}

// handleListScripts handles GET /api/v1/scripts.
func (s *Server) handleListScripts(w http.ResponseWriter, r *http.Request) {
	if s.scriptRepo == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Script library not available", "SERVICE_UNAVAILABLE")
		return
	}

	scripts, err := s.scriptRepo.List(nil)
	if err != nil {
		s.logger.Error("Failed to list scripts", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list scripts", "INTERNAL_ERROR")
		return
	}

	s.writeSuccessResponse(w, scripts)
}

// handleGetScriptLibraryItem handles GET /api/v1/scripts/{id}.
func (s *Server) handleGetScriptLibraryItem(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	if id == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Script ID is required", "MISSING_SCRIPT_ID")
		return
	}

	if s.scriptRepo == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Script library not available", "SERVICE_UNAVAILABLE")
		return
	}

	sanitizedID := logging.SanitizeLogValue(id)

	vs, err := s.scriptRepo.Get(id, "")
	if err != nil {
		s.logger.Warn("Script not found", "id", sanitizedID, "error", err)
		s.writeErrorResponse(w, http.StatusNotFound, "Script not found", "NOT_FOUND")
		return
	}

	s.logger.Info("Retrieved script", "id", sanitizedID)
	s.writeSuccessResponse(w, vs)
}

// handlePutScriptPrivilege handles PUT /api/v1/scripts/{id}/privilege.
// The PermissionScriptAdmin gate is enforced by requirePermission middleware.
// Additionally, the caller must hold every scope listed in RequiredAPIScope,
// and must have steward:read-dna for any ParamPlatformBindings entry.
func (s *Server) handlePutScriptPrivilege(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	if id == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Script ID is required", "MISSING_SCRIPT_ID")
		return
	}

	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	if s.privilegeStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Privilege store not available", "SERVICE_UNAVAILABLE")
		return
	}

	var req SetPrivilegeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return
	}

	// Held-scope ceiling: caller must personally hold every scope they are granting.
	for _, scope := range req.RequiredAPIScope {
		if !s.hasPermission(principal, scope) {
			s.logger.Warn("Scope ceiling violation: caller lacks scope being granted",
				"caller", logging.SanitizeLogValue(principal.ID),
				"scope", logging.SanitizeLogValue(scope),
			)
			s.writeErrorResponse(w, http.StatusForbidden,
				fmt.Sprintf("cannot grant scope %q: caller does not hold it", scope),
				"INSUFFICIENT_PERMISSIONS")
			return
		}
	}

	// DNA path check: any param-platform binding requires steward:read-dna.
	if len(req.ParamPlatformBindings) > 0 && !s.hasPermission(principal, "steward:read-dna") {
		s.logger.Warn("DNA path binding requires steward:read-dna",
			"caller", logging.SanitizeLogValue(principal.ID),
		)
		s.writeErrorResponse(w, http.StatusForbidden,
			"cannot bind parameters to DNA key paths without steward:read-dna permission",
			"INSUFFICIENT_PERMISSIONS")
		return
	}

	sanitizedID := logging.SanitizeLogValue(id)

	meta := &ScriptPrivilegeMetadata{
		ScriptID:              id,
		RequiredAPIScope:      req.RequiredAPIScope,
		ParamPlatformBindings: req.ParamPlatformBindings,
		SetByUserID:           principal.ID,
		SetAt:                 time.Now().UTC(),
	}

	if err := s.storePrivilegeMetadata(r.Context(), tenantID, id, meta); err != nil {
		s.logger.Error("Failed to store privilege metadata", "id", sanitizedID, "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to store privilege metadata", "INTERNAL_ERROR")
		return
	}

	s.logger.Info("Script privilege metadata updated", "id", sanitizedID, "tenant_id", logging.SanitizeLogValue(tenantID))
	s.writeSuccessResponse(w, meta)
}

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
