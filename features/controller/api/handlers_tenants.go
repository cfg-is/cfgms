// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// handleCreateTenant implements POST /api/v1/tenants.
// Creates a tenant with an optional explicit ID. When req.ID is provided
// the store uses that exact value (K8s-compatible naming required). Returns
// HTTP 201 on success, 409 when the tenant ID already exists (idempotent
// callers should treat 409 as success).
func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req tenant.TenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	td, err := s.tenantManager.CreateTenant(r.Context(), &req)
	if err != nil {
		if errors.Is(err, business.ErrTenantAlreadyExists) {
			s.writeErrorResponse(w, http.StatusConflict, "tenant already exists", "TENANT_EXISTS")
			return
		}
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "CREATE_FAILED")
		return
	}

	s.writeResponse(w, http.StatusCreated, td)
}

// handleGetTenant implements GET /api/v1/tenants/{id}.
// Returns 200 + tenant JSON for an existing tenant, 404 for a missing one.
func (s *Server) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}

	td, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if strings.Contains(err.Error(), "tenant not found") {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}

	s.writeSuccessResponse(w, td)
}

// handleSuspendTenant implements POST /api/v1/tenants/{id}/suspend.
// Sets the tenant status to TenantStatusSuspended. Used by agent-dispatch cleanup
// paths to deactivate the agent-test/<N> sub-tenant after the agent exits.
// Returns 200 on success, 404 when the tenant does not exist.
func (s *Server) handleSuspendTenant(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}

	if err := s.tenantManager.SuspendTenant(r.Context(), tenantID); err != nil {
		if strings.Contains(err.Error(), "tenant not found") {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to suspend tenant", "SUSPEND_FAILED")
		return
	}

	s.logger.Info("Suspended tenant",
		"tenant_id", logging.SanitizeLogValue(tenantID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":     tenantID,
		"status": string(business.TenantStatusSuspended),
	})
}
