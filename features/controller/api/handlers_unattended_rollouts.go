// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	unattendedRolloutAuditAction = "unattended_rollouts_changed"
	unattendedRolloutMaxBody     = 1 << 10
)

// unattendedRolloutRequest is the PUT body. Enabled is a pointer so a body that
// omits it is rejected rather than read as false.
type unattendedRolloutRequest struct {
	Enabled *bool `json:"enabled"`
}

// UnattendedRolloutStore returns the wired store, or nil when unwired.
func (s *Server) UnattendedRolloutStore() *UnattendedRolloutStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unattendedRolloutStore
}

// handleGetUnattendedRollout handles GET /api/v1/rollout-settings/unattended.
func (s *Server) handleGetUnattendedRollout(w http.ResponseWriter, r *http.Request) {
	st := s.UnattendedRolloutStore()
	if st == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Unattended rollout store not available", "SERVICE_UNAVAILABLE")
		return
	}
	setting, err := st.Get(r.Context())
	if err != nil {
		s.logger.Error("Failed to read unattended rollout setting", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read unattended rollout setting", "INTERNAL_ERROR")
		return
	}
	s.writeSuccessResponse(w, setting)
}

// handlePutUnattendedRollout handles PUT /api/v1/rollout-settings/unattended.
//
// The setting bounds what a phished admin can leave running, so the change is
// audited before it is made: if the audit event cannot be recorded the setting is
// left as it was. Setting the value the cell already has goes through the same
// permission, tap and audit.
func (s *Server) handlePutUnattendedRollout(w http.ResponseWriter, r *http.Request) {
	st := s.UnattendedRolloutStore()
	if st == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Unattended rollout store not available", "SERVICE_UNAVAILABLE")
		return
	}
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal == nil || principal.ID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	enabled, ok := s.decodeUnattendedRolloutRequest(w, r)
	if !ok {
		return
	}
	if s.auditManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Audit trail not available", "SERVICE_UNAVAILABLE")
		return
	}

	previous, err := st.Get(r.Context())
	if err != nil {
		s.logger.Error("Failed to read unattended rollout setting before change", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read unattended rollout setting", "INTERNAL_ERROR")
		return
	}

	if err := s.recordUnattendedRolloutAudit(r, principal, previous.Enabled, enabled, business.AuditResultSuccess); err != nil {
		s.logger.Error("Unattended rollout change refused: audit event not recorded", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Audit trail unavailable; setting not changed", "AUDIT_UNAVAILABLE")
		return
	}
	setting, err := st.Set(r.Context(), enabled, principal.ID)
	if err != nil {
		s.logger.Error("Failed to set unattended rollout setting", "error", logging.SanitizeLogValue(err.Error()))
		// The success event is already recorded; this one corrects it.
		if aerr := s.recordUnattendedRolloutAudit(r, principal, previous.Enabled, enabled, business.AuditResultFailure); aerr != nil {
			s.logger.Warn("Failed to record unattended rollout failure audit", "error", logging.SanitizeLogValue(aerr.Error()))
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to set unattended rollout setting", "INTERNAL_ERROR")
		return
	}
	s.writeSuccessResponse(w, setting)
}

// decodeUnattendedRolloutRequest reads the PUT body: exactly one JSON object with
// a boolean enabled and no unknown fields. It writes the response and returns
// false when the body is rejected.
func (s *Server) decodeUnattendedRolloutRequest(w http.ResponseWriter, r *http.Request) (bool, bool) {
	var req unattendedRolloutRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, unattendedRolloutMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return false, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return false, false
	}
	if req.Enabled == nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "enabled must be true or false", "INVALID_REQUEST")
		return false, false
	}
	return *req.Enabled, true
}

// recordUnattendedRolloutAudit records one unattended_rollouts_changed event naming
// the principal and the old and new value. It returns the error: the caller must
// not change the setting without the event.
func (s *Server) recordUnattendedRolloutAudit(r *http.Request, principal *Principal, previous, next bool, result business.AuditResult) error {
	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		tenantID = unattendedRolloutTenant
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action(unattendedRolloutAuditAction).
		User(principal.ID, principalAuditUserType(principal)).
		Resource("rollout_setting", "unattended", "").
		Result(result).
		Severity(business.AuditSeverityHigh).
		Detail("principal", principal.ID).
		Detail("previous", previous).
		Detail("new", next)
	auditCtx, cancel := detachedAuditContext(r.Context())
	defer cancel()
	return s.auditManager.RecordEvent(auditCtx, b)
}
