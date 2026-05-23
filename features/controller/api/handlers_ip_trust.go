// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// addIPTrustRequest is the request body for POST /api/v1/registration/ip-trust.
type addIPTrustRequest struct {
	TenantID  string `json:"tenant_id"`
	CIDR      string `json:"cidr"`
	PreSeeded bool   `json:"pre_seeded"`
}

// handleAddIPTrust handles POST /api/v1/registration/ip-trust.
// Adds a trusted CIDR range for a tenant; pre_seeded marks the range as operator-seeded.
func (s *Server) handleAddIPTrust(w http.ResponseWriter, r *http.Request) {
	if s.ipTrustStore == nil {
		http.Error(w, "ip-trust store unavailable", http.StatusServiceUnavailable)
		return
	}

	var req addIPTrustRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.TenantID == "" || req.CIDR == "" {
		http.Error(w, "tenant_id and cidr are required", http.StatusBadRequest)
		return
	}

	if err := s.ipTrustStore.AddTrustedRange(r.Context(), req.TenantID, req.CIDR, req.PreSeeded); err != nil {
		s.logger.Error("Failed to add IP trust range",
			"tenant_id", logging.SanitizeLogValue(req.TenantID),
			"cidr", logging.SanitizeLogValue(req.CIDR),
			"error", err)
		http.Error(w, "Failed to add IP trust range", http.StatusInternalServerError)
		return
	}

	s.logger.Info("IP trust range added",
		"tenant_id", logging.SanitizeLogValue(req.TenantID),
		"cidr", logging.SanitizeLogValue(req.CIDR),
		"pre_seeded", req.PreSeeded)
	w.WriteHeader(http.StatusNoContent)
}

// handleRevokeIPTrust handles DELETE /api/v1/registration/ip-trust/{tenant_id}/{cidr:.+}.
// Revokes a trusted CIDR range for a tenant. The {cidr:.+} pattern allows the CIDR slash
// to appear in the URL path (gorilla/mux decodes %2F before extraction).
func (s *Server) handleRevokeIPTrust(w http.ResponseWriter, r *http.Request) {
	if s.ipTrustStore == nil {
		http.Error(w, "ip-trust store unavailable", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["tenant_id"]
	cidr := vars["cidr"]

	if tenantID == "" || cidr == "" {
		http.Error(w, "tenant_id and cidr are required", http.StatusBadRequest)
		return
	}

	if err := s.ipTrustStore.RevokeTrustedRange(r.Context(), tenantID, cidr); err != nil {
		if err == business.ErrIPTrustEntryNotFound {
			http.Error(w, "ip trust entry not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to revoke IP trust range",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"cidr", logging.SanitizeLogValue(cidr),
			"error", err)
		http.Error(w, "Failed to revoke IP trust range", http.StatusInternalServerError)
		return
	}

	s.logger.Info("IP trust range revoked",
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"cidr", logging.SanitizeLogValue(cidr))
	w.WriteHeader(http.StatusNoContent)
}
