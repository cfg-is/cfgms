// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// handleGetConfigDeployments implements GET /api/v1/configs/{id}/deployments.
//
// Returns aggregate deployment counts (applied/pending/failed/halted) and a
// per-steward status table derived from the push history for the given config ID.
// The query is always scoped to the authenticated tenant to prevent cross-tenant
// data disclosure (mirrors the tenant-isolation pattern in handleListConfigs).
func (s *Server) handleGetConfigDeployments(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	configID := vars["id"]
	if configID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "config ID is required", "CONFIG_ID_REQUIRED")
		return
	}

	// Authenticated tenant is the scope for the query — prevents cross-tenant enumeration.
	tenantID := "default"
	if tid, ok := r.Context().Value(ctxkeys.TenantID).(string); ok && tid != "" {
		tenantID = tid
	}

	if s.pushStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "deployment store not available", "STORE_UNAVAILABLE")
		return
	}

	pushRecords, err := s.pushStore.ListPushesByConfigID(r.Context(), configID, tenantID)
	if err != nil {
		s.logger.Error("Failed to list push records",
			"config_id", logging.SanitizeLogValue(configID),
			"error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to retrieve deployment history", "INTERNAL_ERROR")
		return
	}

	// Build push history summary (most recent first, already ordered by the store).
	history := make([]PushSummary, 0, len(pushRecords))
	for _, rec := range pushRecords {
		history = append(history, PushSummary{
			PushID:      rec.ID,
			Status:      string(rec.Status),
			Version:     rec.Version,
			InitiatedBy: rec.InitiatedBy,
			CreatedAt:   rec.CreatedAt,
			UpdatedAt:   rec.UpdatedAt,
		})
	}

	// Derive per-steward status from the most recent push and the live steward registry,
	// scoped to the authenticated tenant. This is a best-effort view: per-steward
	// delivery records are not stored individually.
	stewards := s.deriveStewardDeploymentStatus(pushRecords, tenantID)
	summary := buildDeploymentSummary(stewards)

	s.writeSuccessResponse(w, ConfigDeploymentsResponse{
		ConfigID:    configID,
		Summary:     summary,
		Stewards:    stewards,
		PushHistory: history,
	})
}

// deriveStewardDeploymentStatus computes a per-steward deployment status by
// combining the most recent push record with the live steward registry scoped
// to tenantID. When no push records exist all matching stewards show as "unknown".
func (s *Server) deriveStewardDeploymentStatus(pushRecords []*business.PushRecord, tenantID string) []StewardDeploymentStatus {
	if s.controllerService == nil {
		return []StewardDeploymentStatus{}
	}

	allStewards := s.controllerService.GetAllStewards()
	if len(allStewards) == 0 {
		return []StewardDeploymentStatus{}
	}

	// Determine the deployment status to apply across matching stewards from the
	// most recent push (index 0 — store returns records newest-first).
	deployStatus := "unknown"
	var lastUpdated time.Time
	if len(pushRecords) > 0 {
		latest := pushRecords[0]
		lastUpdated = latest.UpdatedAt
		switch latest.Status {
		case business.PushStatusCompleted:
			deployStatus = "applied"
		case business.PushStatusInProgress, business.PushStatusPending:
			deployStatus = "pending"
		case business.PushStatusFailed:
			deployStatus = "failed"
		}
	}

	// Scope the steward list to the authenticated tenant to prevent cross-tenant
	// disclosure in the per-steward table.
	result := make([]StewardDeploymentStatus, 0, len(allStewards))
	for _, st := range allStewards {
		if st.TenantID != tenantID {
			continue
		}
		result = append(result, StewardDeploymentStatus{
			StewardID:   st.ID,
			Status:      deployStatus,
			LastUpdated: lastUpdated,
		})
	}
	return result
}

// buildDeploymentSummary counts per-status steward entries.
func buildDeploymentSummary(stewards []StewardDeploymentStatus) DeploymentSummary {
	var s DeploymentSummary
	for _, st := range stewards {
		switch st.Status {
		case "applied":
			s.Applied++
		case "pending":
			s.Pending++
		case "failed":
			s.Failed++
		case "halted":
			s.Halted++
		}
	}
	s.Total = s.Applied + s.Pending + s.Failed + s.Halted
	return s
}
