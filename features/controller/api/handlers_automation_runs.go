// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// automationBeginBodyLimit bounds the begin request body; its three short fields
// never approach it.
const automationBeginBodyLimit = 4 << 10

// AutomationRunBeginRequest opens a run on one tenant for one triggering event.
type AutomationRunBeginRequest struct {
	TenantID    string `json:"tenant_id"`
	EventRef    string `json:"event_ref"`
	EventSource string `json:"event_source"`
}

// AutomationRunResponse describes a run. It carries no credential.
type AutomationRunResponse struct {
	RunID       string    `json:"run_id"`
	TenantID    string    `json:"tenant_id"`
	EventRef    string    `json:"event_ref"`
	EventSource string    `json:"event_source"`
	ExpiresAt   time.Time `json:"expires_at"`
	Ended       bool      `json:"ended"`
}

func toAutomationRunResponse(b *RunBinding) AutomationRunResponse {
	return AutomationRunResponse{
		RunID: b.ID, TenantID: b.TenantID, EventRef: b.EventRef, EventSource: b.EventSource,
		ExpiresAt: b.ExpiresAt, Ended: b.Ended,
	}
}

// beginRejection is a refused begin: the response and the audit reason.
type beginRejection struct {
	status               int
	message, code        string
	reason, tenant, eref string
}

// parseAutomationBegin decodes and validates the begin body. Every unreadable or
// invalid body is a rejection; nothing is trusted yet.
func parseAutomationBegin(w http.ResponseWriter, r *http.Request) (AutomationRunBeginRequest, *beginRejection) {
	var req AutomationRunBeginRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, automationBeginBodyLimit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, &beginRejection{http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST", "malformed_body", "", ""}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return req, &beginRejection{http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST", "malformed_body", "", ""}
	}
	if req.TenantID == "" {
		return req, &beginRejection{http.StatusBadRequest, "tenant_id is required", "INVALID_REQUEST", "tenant_missing", "", req.EventRef}
	}
	if err := validateEventField("event_ref", req.EventRef); err != nil {
		return req, &beginRejection{http.StatusBadRequest, err.Error(), "INVALID_REQUEST", "event_ref_invalid", req.TenantID, ""}
	}
	if err := validateEventField("event_source", req.EventSource); err != nil {
		return req, &beginRejection{http.StatusBadRequest, err.Error(), "INVALID_REQUEST", "event_source_invalid", req.TenantID, req.EventRef}
	}
	return req, nil
}

// openAutomationRun creates the binding for a verified request, mapping the store's
// refusals to rejections. A non-nil error is a store failure.
func (s *Server) openAutomationRun(ctx context.Context, grantTenant, grantID string, req AutomationRunBeginRequest) (*RunBinding, *beginRejection, error) {
	grantStore, runStore := s.grantStoreOrNil(), s.automationRunStore()
	if grantStore == nil || runStore == nil {
		return nil, nil, errors.New("automation stores are not wired")
	}
	grant, err := grantStore.Get(ctx, grantTenant, grantID)
	if err != nil {
		return nil, nil, err
	}
	run, err := runStore.Begin(ctx, grant, req.TenantID, req.EventSource, req.EventRef)
	switch {
	case errors.Is(err, ErrAutomationEventBound):
		return nil, &beginRejection{http.StatusConflict, "The event is already bound to another tenant",
			"EVENT_BOUND_TO_OTHER_TENANT", "event_bound_to_other_tenant", req.TenantID, req.EventRef}, nil
	case errors.Is(err, ErrAutomationRunCap):
		return nil, &beginRejection{http.StatusTooManyRequests, "The grant has the maximum number of open runs",
			"OPEN_RUN_CAP", "open_run_cap", req.TenantID, req.EventRef}, nil
	}
	return run, nil, err
}

// handleAutomationRunBegin handles POST /api/v1/automation/runs. The principal is the
// grant principal at its grant tenant (begin is the one route with no run lock yet).
// It verifies the declared tenant is the grant tenant or one of its descendants, then
// creates the durable binding that makes the declaration immutable.
func (s *Server) handleAutomationRunBegin(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	grantID, ownerTenant := "", ""
	if principal != nil {
		grantID, ownerTenant = principal.ID, principal.TenantID
	}
	refuse := func(rej *beginRejection) {
		s.emitAutomationAudit(r.Context(), grantID, "", rej.tenant, ownerTenant, rej.eref,
			"automation.run.begin", business.AuditResultDenied, auditDetail{Key: "reason", Value: rej.reason})
		s.writeErrorResponse(w, rej.status, rej.message, rej.code)
	}

	if principal == nil || principal.Channel != AuthChannelAutomationGrant {
		refuse(&beginRejection{http.StatusForbidden, "The automation run does not permit this request",
			"AUTOMATION_RUN_DENIED", "not_a_grant_principal", "", ""})
		return
	}
	// Every attempt counts toward the rate bound, valid or not.
	if !s.admitAutomationBegin(r.Context(), grantID) {
		refuse(&beginRejection{http.StatusTooManyRequests, "Too many runs begun — try again later",
			"RATE_LIMITED", "begin_rate_limit", "", ""})
		return
	}
	req, rej := parseAutomationBegin(w, r)
	if rej != nil {
		refuse(rej)
		return
	}
	// The declared tenant is the grant tenant or a ParentID descendant of it.
	if !s.tenantSubtreeContains(r.Context(), ownerTenant, req.TenantID) {
		refuse(&beginRejection{http.StatusForbidden, "The tenant is outside the grant's tenant",
			"TENANT_OUT_OF_SCOPE", "tenant_outside_grant_subtree", req.TenantID, req.EventRef})
		return
	}

	run, rej, err := s.openAutomationRun(r.Context(), ownerTenant, grantID, req)
	if err != nil {
		s.logger.Error("Automation run begin failed",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to begin the run", "INTERNAL_ERROR")
		return
	}
	if rej != nil {
		refuse(rej)
		return
	}
	s.emitAutomationAudit(r.Context(), grantID, run.ID, run.TenantID, ownerTenant, run.EventRef,
		"automation.run.begin", business.AuditResultSuccess,
		auditDetail{Key: "event_source", Value: run.EventSource})
	s.writeResponse(w, http.StatusCreated, toAutomationRunResponse(run))
}

// handleAutomationRunEnd handles POST /api/v1/automation/runs/{run_id}/end. The
// wrapper has already admitted the run, so the binding is in the request context.
func (s *Server) handleAutomationRunEnd(w http.ResponseWriter, r *http.Request) {
	run := automationRunFromContext(r.Context())
	runStore := s.automationRunStore()
	if run == nil || runStore == nil {
		s.writeErrorResponse(w, http.StatusForbidden,
			"The automation run does not permit this request", "AUTOMATION_RUN_DENIED")
		return
	}
	ended, err := runStore.End(r.Context(), run.GrantTenantID, run.ID)
	if err != nil {
		s.logger.Error("Automation run end failed",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to end the run", "INTERNAL_ERROR")
		return
	}
	s.emitAutomationAudit(r.Context(), run.GrantID, run.ID, run.TenantID, run.GrantTenantID, run.EventRef,
		"automation.run.end", business.AuditResultSuccess)
	s.writeResponse(w, http.StatusOK, toAutomationRunResponse(ended))
}
