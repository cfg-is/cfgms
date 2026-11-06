// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	libraryModeAuditAction = "content_library.mode_change"
	libraryModeMaxBody     = 1 << 10
)

// libraryModeRequest is the PUT body.
type libraryModeRequest struct {
	Mode ApprovalMode `json:"mode"`
}

// libraryModeResponse is the body of GET and PUT.
type libraryModeResponse struct {
	Kind string       `json:"kind"`
	Mode ApprovalMode `json:"mode"`
}

// libraryModeTarget resolves the library the request addresses: the caller's own
// tenant and the kind in the path. It writes the response and returns false when
// the store is unwired, the kind is unknown or the caller has no tenant.
func (s *Server) libraryModeTarget(w http.ResponseWriter, r *http.Request) (string, LibraryKind, bool) {
	if s.contentApprovalStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Content approval store not available", "SERVICE_UNAVAILABLE")
		return "", "", false
	}
	kind := LibraryKind(mux.Vars(r)["kind"])
	if !kind.Valid() {
		s.writeErrorResponse(w, http.StatusBadRequest, "kind must be script or workflow", "INVALID_KIND")
		return "", "", false
	}
	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "A tenant is required", "TENANT_REQUIRED")
		return "", "", false
	}
	return tenantID, kind, true
}

// handleGetLibraryMode handles GET /api/v1/automation/libraries/{kind}/mode.
func (s *Server) handleGetLibraryMode(w http.ResponseWriter, r *http.Request) {
	tenantID, kind, ok := s.libraryModeTarget(w, r)
	if !ok {
		return
	}
	mode, err := s.contentApprovalStore.GetMode(r.Context(), tenantID, kind)
	if err != nil {
		s.logger.Error("Failed to read library approval mode",
			"kind", logging.SanitizeLogValue(string(kind)), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read approval mode", "INTERNAL_ERROR")
		return
	}
	s.writeSuccessResponse(w, libraryModeResponse{Kind: string(kind), Mode: mode})
}

// handlePutLibraryMode handles PUT /api/v1/automation/libraries/{kind}/mode.
//
// The mode bounds the blast radius of a phished admin, so the change is audited
// before it is made: if the audit event cannot be recorded the mode is left as it
// was. Setting the mode the library already has changes nothing, but it goes
// through the same permission, tap and audit, so the response never reveals the
// current mode to a caller who has not passed the tap.
func (s *Server) handlePutLibraryMode(w http.ResponseWriter, r *http.Request) {
	tenantID, kind, ok := s.libraryModeTarget(w, r)
	if !ok {
		return
	}
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal == nil || principal.ID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	mode, ok := s.decodeLibraryModeRequest(w, r)
	if !ok {
		return
	}
	if s.auditManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Audit trail not available", "SERVICE_UNAVAILABLE")
		return
	}

	previous, err := s.contentApprovalStore.GetMode(r.Context(), tenantID, kind)
	if err != nil {
		s.logger.Error("Failed to read library approval mode before change",
			"kind", logging.SanitizeLogValue(string(kind)), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read approval mode", "INTERNAL_ERROR")
		return
	}

	if err := s.recordLibraryModeAudit(r, principal, tenantID, kind, previous, mode, business.AuditResultSuccess); err != nil {
		s.logger.Error("Library approval mode change refused: audit event not recorded",
			"kind", logging.SanitizeLogValue(string(kind)), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Audit trail unavailable; mode not changed", "AUDIT_UNAVAILABLE")
		return
	}
	if !s.applyLibraryMode(w, r, principal, tenantID, kind, previous, mode) {
		return
	}
	s.writeSuccessResponse(w, libraryModeResponse{Kind: string(kind), Mode: mode})
}

// decodeLibraryModeRequest reads the PUT body: exactly one JSON object with a
// valid mode and no unknown fields. It writes the response and returns false when
// the body is rejected.
func (s *Server) decodeLibraryModeRequest(w http.ResponseWriter, r *http.Request) (ApprovalMode, bool) {
	var req libraryModeRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, libraryModeMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return "", false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return "", false
	}
	if !req.Mode.Valid() {
		s.writeErrorResponse(w, http.StatusBadRequest, "mode must be signed, approve or comment", "INVALID_MODE")
		return "", false
	}
	return req.Mode, true
}

// applyLibraryMode stores the new mode after its success audit event has been
// recorded. Setting the mode the library already has writes nothing. If the write
// fails it records a failure event correcting the success event, writes the
// response and returns false.
func (s *Server) applyLibraryMode(w http.ResponseWriter, r *http.Request, principal *Principal, tenantID string, kind LibraryKind, previous, next ApprovalMode) bool {
	if next == previous {
		return true
	}
	err := s.contentApprovalStore.SetMode(r.Context(), tenantID, kind, next, principal.ID)
	if err == nil {
		return true
	}
	s.logger.Error("Failed to set library approval mode",
		"kind", logging.SanitizeLogValue(string(kind)), "error", logging.SanitizeLogValue(err.Error()))
	// The success event is already recorded; this one corrects it.
	if aerr := s.recordLibraryModeAudit(r, principal, tenantID, kind, previous, next, business.AuditResultFailure); aerr != nil {
		s.logger.Warn("Failed to record library mode failure audit",
			"error", logging.SanitizeLogValue(aerr.Error()))
	}
	s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to set approval mode", "INTERNAL_ERROR")
	return false
}

// recordLibraryModeAudit records one content_library.mode_change event naming the
// kind, tenant, previous and new mode, and the actor. Unlike emitOperatorAudit it
// returns the error: the caller must not change the mode without the event.
func (s *Server) recordLibraryModeAudit(r *http.Request, principal *Principal, tenantID string, kind LibraryKind, previous, next ApprovalMode, result business.AuditResult) error {
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action(libraryModeAuditAction).
		User(principal.ID, principalAuditUserType(principal)).
		Resource("content_library", string(kind), "").
		Result(result).
		Severity(business.AuditSeverityHigh).
		Detail("kind", logging.SanitizeLogValue(string(kind))).
		Detail("tenant", tenantID).
		Detail("previous", string(previous)).
		Detail("new", string(next)).
		Detail("actor", principal.ID)
	auditCtx, cancel := detachedAuditContext(r.Context())
	defer cancel()
	return s.auditManager.RecordEvent(auditCtx, b)
}
