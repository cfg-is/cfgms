// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// AlertAcknowledgeRequest is the optional body for POST /api/v1/alerts/{id}/acknowledge.
type AlertAcknowledgeRequest struct {
	Reason string `json:"reason,omitempty"`
}

// AlertSilenceRequest is the body for POST /api/v1/alerts/{id}/silence.
type AlertSilenceRequest struct {
	Until time.Time `json:"until"` // RFC3339: when the silence expires
}

// handleAcknowledgeAlert handles POST /api/v1/alerts/{id}/acknowledge.
// Requires "alert:acknowledge" permission.
func (s *Server) handleAcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	alertID := mux.Vars(r)["id"]

	// The body is optional: an empty body (io.EOF) acknowledges without a reason.
	// A malformed body is a client error and must not be silently ignored.
	var req AlertAcknowledgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if s.alertStore == nil {
		http.Error(w, "alert store unavailable", http.StatusServiceUnavailable)
		return
	}

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	principalID := ""
	if principal != nil {
		principalID = principal.ID
	}

	now := time.Now().UTC()
	if err := s.alertStore.AcknowledgeAlert(r.Context(), callerTenant, alertID, principalID, now); err != nil {
		s.logger.Error("Failed to acknowledge alert",
			"alert_id", logging.SanitizeLogValue(alertID),
			"tenant_id", logging.SanitizeLogValue(callerTenant),
			"error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "failed to acknowledge alert", http.StatusInternalServerError)
		return
	}

	s.logger.Info("Alert acknowledged",
		"alert_id", logging.SanitizeLogValue(alertID),
		"tenant_id", logging.SanitizeLogValue(callerTenant),
		"principal", logging.SanitizeLogValue(principalID))
	details := map[string]interface{}{}
	if req.Reason != "" {
		details["reason"] = req.Reason
	}
	s.emitAlertAudit(r, "alert.acknowledged", alertID, callerTenant, principalID, details)

	w.WriteHeader(http.StatusNoContent)
}

// handleSilenceAlert handles POST /api/v1/alerts/{id}/silence.
// Requires "alert:silence" permission (AssuranceStrong).
func (s *Server) handleSilenceAlert(w http.ResponseWriter, r *http.Request) {
	alertID := mux.Vars(r)["id"]

	if s.alertStore == nil {
		http.Error(w, "alert store unavailable", http.StatusServiceUnavailable)
		return
	}

	var req AlertSilenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Until.IsZero() {
		http.Error(w, "until is required", http.StatusBadRequest)
		return
	}

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	principalID := ""
	if principal != nil {
		principalID = principal.ID
	}

	if err := s.alertStore.SilenceAlert(r.Context(), callerTenant, alertID, principalID, req.Until); err != nil {
		s.logger.Error("Failed to silence alert",
			"alert_id", logging.SanitizeLogValue(alertID),
			"tenant_id", logging.SanitizeLogValue(callerTenant),
			"error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, "failed to silence alert", http.StatusInternalServerError)
		return
	}

	s.logger.Info("Alert silenced",
		"alert_id", logging.SanitizeLogValue(alertID),
		"tenant_id", logging.SanitizeLogValue(callerTenant),
		"principal", logging.SanitizeLogValue(principalID))
	s.emitAlertAudit(r, "alert.silenced", alertID, callerTenant, principalID, map[string]interface{}{
		"silenced_until": req.Until.UTC().Format(time.RFC3339),
	})

	w.WriteHeader(http.StatusNoContent)
}

// emitAlertAudit records an alert-state audit event.
// details carries action-specific fields (acknowledge reason, silence expiry).
// It is a no-op when auditManager is nil.
func (s *Server) emitAlertAudit(r *http.Request, action, alertID, tenantID, principalID string, details map[string]interface{}) {
	if s.auditManager == nil {
		return
	}
	auditTenant := tenantID
	if auditTenant == "" {
		auditTenant = audit.SystemTenantID
	}
	b := audit.NewEventBuilder().
		Tenant(auditTenant).
		Type(business.AuditEventSystemAccess).
		Action(action).
		User(principalID, business.AuditUserTypeHuman).
		Resource("alert", alertID, "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityMedium).
		Detail("alert_id", alertID)
	for k, v := range details {
		b = b.Detail(k, v)
	}
	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		// alertID is caller-supplied and travels back out inside err, so the error
		// text is tainted and must be sanitized before it reaches the log sink.
		s.logger.Warn("Failed to emit alert audit event",
			"error", logging.SanitizeLogValue(err.Error()),
			"action", logging.SanitizeLogValue(action))
	}
}
