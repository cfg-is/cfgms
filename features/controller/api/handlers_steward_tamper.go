// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Audit actions written by the operator tamper verbs.
const (
	auditActionTamperRestored       = "steward_tamper_restored"
	auditActionTamperRestoreRefused = "steward_tamper_restore_refused"
	auditActionTamperBanned         = "steward_tamper_banned"
)

const (
	// tamperRestoreFaultWindow is how recent the steward's last heartbeat must be
	// for a tamper code in it to block a restore: a steward that is still
	// reporting a fault is repaired, not restored.
	tamperRestoreFaultWindow = 5 * time.Minute

	// tamperReasonMaxRunes bounds the operator's free-text reason before it is
	// stored in the audit event.
	tamperReasonMaxRunes = 500

	// tamperVerbBodyLimit bounds the request body of the tamper verbs.
	tamperVerbBodyLimit = 4096

	// faultStillReportedError is the machine-readable error of a refused restore.
	faultStillReportedError = "fault_still_reported"
)

// TamperStateNotifier tells a connected steward its current tamper state. The
// controller's lockdown predicate satisfies it; the steward reads the durable
// status, so a restore sends locked=false and an offline steward is told on its
// next connect.
type TamperStateNotifier interface {
	NotifyTransition(ctx context.Context, stewardID string) error
}

// SetTamperStateNotifier binds the sender of the tamper state used by restore.
// Call after New() returns and before Start().
func (s *Server) SetTamperStateNotifier(n TamperStateNotifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tamperNotifier = n
}

// tamperVerbRequest is the body of the restore and ban verbs. Unknown fields are
// ignored: there is no field that overrides the live-fault check.
type tamperVerbRequest struct {
	Reason string `json:"reason,omitempty"`
}

// tamperVerbResponse is the body of a successful restore or ban.
type tamperVerbResponse struct {
	ID             string   `json:"id"`
	Status         string   `json:"status"`
	RevokedSerials []string `json:"revoked_serials,omitempty"`
	Note           string   `json:"note"`
}

// faultStillReportedResponse is the 409 body of a restore refused because the
// steward still reports a tamper code.
type faultStillReportedResponse struct {
	Error   string   `json:"error"`
	Codes   []string `json:"codes"`
	Message string   `json:"message"`
}

// decodeTamperVerbRequest reads the optional body. An empty body is a request
// without a reason. On false the response has been written.
func (s *Server) decodeTamperVerbRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req tamperVerbRequest
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, tamperVerbBodyLimit)).Decode(&req)
	if err != nil && !errors.Is(err, io.EOF) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return "", false
	}
	return sanitizeTamperReason(req.Reason), true
}

// sanitizeTamperReason trims the reason, drops control characters and caps its
// length; the result is stored in the audit event.
func sanitizeTamperReason(reason string) string {
	reason = strings.TrimSpace(logging.SanitizeLogValue(reason))
	if utf8.RuneCountInString(reason) > tamperReasonMaxRunes {
		reason = string([]rune(reason)[:tamperReasonMaxRunes])
	}
	return reason
}

// tamperedStewardRecord resolves the steward for a tamper verb: 404 for a missing
// steward or one outside the caller's tenant, 409 for one that is not tampered.
// On false the response has been written.
func (s *Server) tamperedStewardRecord(w http.ResponseWriter, r *http.Request, route string) (*business.StewardRecord, bool) {
	record, ok := s.operatorStewardLookup(w, r, route)
	if !ok {
		return nil, false
	}
	if record.Status != business.StewardStatusTampered {
		s.writeErrorResponse(w, http.StatusConflict, "Steward is "+string(record.Status)+", not tampered", "STEWARD_NOT_TAMPERED")
		return nil, false
	}
	return record, true
}

// liveTamperCodes returns the tamper codes in the steward's last reported health
// reasons when that heartbeat is inside the restore window, and nil otherwise.
func liveTamperCodes(record *business.StewardRecord, now time.Time) []string {
	if record.LastHeartbeatAt.IsZero() || now.Sub(record.LastHeartbeatAt) > tamperRestoreFaultWindow {
		return nil
	}
	reasons := make([]controlplaneTypes.HealthReason, 0, len(record.HealthReasons))
	for _, hr := range record.HealthReasons {
		reasons = append(reasons, controlplaneTypes.HealthReason{Component: hr.Component, Code: hr.Code})
	}
	return tamperCodesIn(reasons)
}

// handleRestoreTamperedSteward handles POST /api/v1/stewards/{id}/tamper/restore.
// The steward returns to trusted (active, or registered if it never heartbeated)
// and normal traffic resumes. A steward that still reports a tamper code is
// refused: nothing overrides that check.
func (s *Server) handleRestoreTamperedSteward(w http.ResponseWriter, r *http.Request) {
	record, ok := s.tamperedStewardRecord(w, r, "POST /api/v1/stewards/{id}/tamper/restore")
	if !ok {
		return
	}
	reason, ok := s.decodeTamperVerbRequest(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	if s.refuseRestoreOfLinkableCopy(ctx, w, record) {
		return
	}
	if s.refuseRestoreWhileFaulted(w, r, record, reason) {
		return
	}

	target := business.StewardStatusActive
	if record.LastHeartbeatAt.IsZero() {
		target = business.StewardStatusRegistered
	}
	transitioned, err := s.stewardStore.TransitionStewardStatus(ctx, record.ID, target, business.StewardStatusTampered)
	if err != nil {
		s.logger.Error("tamper restore: status transition failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to restore steward", "INTERNAL_ERROR")
		return
	}
	if !transitioned {
		s.writeErrorResponse(w, http.StatusConflict, "Steward is no longer tampered", "STEWARD_NOT_TAMPERED")
		return
	}
	if s.controllerService != nil {
		if err := s.controllerService.UpdateStewardStatusDurable(record.ID, record.TenantID, string(target)); err != nil {
			s.logger.Debug("tamper restore: in-memory status update skipped",
				"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		}
	}
	s.emitIdentityOperatorAudit(ctx, r, auditActionTamperRestored, record, map[string]interface{}{
		"previous_status": string(record.Status),
		"new_status":      string(target),
		"reason":          reason,
	})

	s.notifyTamperReleased(ctx, record.ID)
	s.logger.Info("Tampered steward restored", "steward_id", logging.SanitizeLogValue(record.ID))
	s.writeSuccessResponse(w, tamperVerbResponse{
		ID:     record.ID,
		Status: string(target),
		Note:   "Restored: the steward is trusted again and normal traffic resumes. If it still reports a tamper code on its next heartbeat it returns to tampered.",
	})
}

// refuseRestoreOfLinkableCopy answers 409 LINK_REQUIRED when record is a locked
// copy that names an old identity: it is resolved by linking it to that
// identity, not by restoring it as a new one. It reports whether it refused
// (including on a lookup failure, answered 500).
func (s *Server) refuseRestoreOfLinkableCopy(ctx context.Context, w http.ResponseWriter, record *business.StewardRecord) bool {
	copyEntry, err := s.lockedCopyNamingOldID(ctx, record)
	if err != nil {
		s.logger.Error("tamper restore: locked copy lookup failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to restore steward", "INTERNAL_ERROR")
		return true
	}
	if copyEntry != nil {
		s.writeErrorResponse(w, http.StatusConflict, "This steward was admitted locked and names an old identity; link it to that identity instead of restoring it", "LINK_REQUIRED")
		return true
	}
	return false
}

// refuseRestoreWhileFaulted answers 409 fault_still_reported, and audits the
// refusal with the codes, when the steward's latest heartbeat inside the window
// still carries a tamper code. It reports whether it refused.
func (s *Server) refuseRestoreWhileFaulted(w http.ResponseWriter, r *http.Request, record *business.StewardRecord, reason string) bool {
	codes := liveTamperCodes(record, time.Now())
	if len(codes) == 0 {
		return false
	}
	s.emitOperatorAuditResult(r.Context(), r, auditActionTamperRestoreRefused, business.AuditResultDenied, record, map[string]interface{}{
		"codes":  codes,
		"reason": reason,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(faultStillReportedResponse{
		Error: faultStillReportedError,
		Codes: codes,
		Message: "The steward still reports a fault. It must be repaired and restored instead; " +
			"restoring it now would not clear the fault.",
	})
	return true
}

// notifyTamperReleased tells a connected steward it is released (locked=false).
// One that is offline is told on its next connect, so a failed send is not a
// failed restore.
func (s *Server) notifyTamperReleased(ctx context.Context, stewardID string) {
	s.mu.RLock()
	notifier := s.tamperNotifier
	s.mu.RUnlock()
	if notifier == nil {
		return
	}
	if err := notifier.NotifyTransition(ctx, stewardID); err != nil {
		s.logger.Debug("tamper restore: tamper state not delivered, steward is told on its next connect",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
	}
}

// handleBanTamperedSteward handles POST /api/v1/stewards/{id}/tamper/ban. The
// identity is revoked: every client certificate serial is revoked, the status
// becomes revoked, and the live control stream is closed. It affects only the
// identity named.
func (s *Server) handleBanTamperedSteward(w http.ResponseWriter, r *http.Request) {
	record, ok := s.tamperedStewardRecord(w, r, "POST /api/v1/stewards/{id}/tamper/ban")
	if !ok {
		return
	}
	reason, ok := s.decodeTamperVerbRequest(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	// Status first: the transition is the atomic step that lets exactly one of
	// two parallel restore/ban calls win, and a revoked status refuses admission
	// on its own.
	transitioned, err := s.stewardStore.TransitionStewardStatus(ctx, record.ID, business.StewardStatusRevoked, business.StewardStatusTampered)
	if err != nil {
		s.logger.Error("tamper ban: status transition failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to ban steward", "INTERNAL_ERROR")
		return
	}
	if !transitioned {
		s.writeErrorResponse(w, http.StatusConflict, "Steward is no longer tampered", "STEWARD_NOT_TAMPERED")
		return
	}
	serials, err := revokeStewardSerials(s.certManager, record.ID)
	if err != nil {
		s.logger.Error("tamper ban: revocation failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		// Put the steward back to tampered so the operator can retry the ban.
		if _, rbErr := s.stewardStore.TransitionStewardStatus(ctx, record.ID, business.StewardStatusTampered, business.StewardStatusRevoked); rbErr != nil {
			s.logger.Error("tamper ban: rollback to tampered failed",
				"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(rbErr.Error()))
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to revoke certificates; the steward is still tampered, retry", "INTERNAL_ERROR")
		return
	}
	if s.controllerService != nil {
		if err := s.controllerService.UpdateStewardStatus(record.ID, string(business.StewardStatusRevoked)); err != nil {
			s.logger.Debug("tamper ban: in-memory status update skipped",
				"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		}
	}
	s.evictStewardStream(record.ID)
	s.emitIdentityOperatorAudit(ctx, r, auditActionTamperBanned, record, map[string]interface{}{
		"previous_status": string(record.Status),
		"revoked_serials": serials,
		"reason":          reason,
	})
	s.logger.Info("Tampered steward banned",
		"steward_id", logging.SanitizeLogValue(record.ID), "revoked_serials", len(serials))
	s.writeSuccessResponse(w, tamperVerbResponse{
		ID:             record.ID,
		Status:         string(business.StewardStatusRevoked),
		RevokedSerials: serials,
		Note:           "Banned: the identity is revoked and refused from now on. This affects only this identity; a locked copy that names it is a different identity and is banned or linked through its own verbs.",
	})
}

// evictStewardStream closes the steward's live control stream on this node. The
// periodic revocation re-check closes streams held by other nodes.
func (s *Server) evictStewardStream(stewardID string) {
	s.mu.RLock()
	reg := s.registry
	s.mu.RUnlock()
	if reg == nil {
		return
	}
	if conn, ok := reg.Get(stewardID); ok && conn.Evict != nil {
		conn.Evict(status.Error(codes.PermissionDenied, "steward banned"))
	}
}
