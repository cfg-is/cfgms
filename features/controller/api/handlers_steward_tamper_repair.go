// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/pkg/audit"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Repair and restore of a tampered steward.
//
// The operator asks for the repair (one passkey tap, AssuranceStrong). The steward
// resets rights on its own files and makes a new identity key; the controller
// revokes the old client certificate serials and rebinds the record to the new
// key. The steward keeps its ID, tenant, local logs and action history. A repair
// that would lose logs or action history needs the operator to approve exactly
// that loss, and the controller and the steward each check it.
//
// The pending request is held as audit events plus a business.NonceStore entry
// (no storage of its own). The nonce entry is the single-use right to complete
// the repair; the audit events are what GET reports and what on-connect delivery
// reads to find the latest unresolved request.
//
// Residual, stated here and in the completion response: when two parties hold
// identical keys (a thief who copied the data folder) no protocol can tell them
// apart, so the first valid completion wins and consumes the nonce. A thief
// connected first holds the control channel and would receive the request. The
// loser is always loud: its credentials are refused and the repair guard turns that into
// repair.contested and a tampered status. A compromised controller can also
// request repairs: a lossless repair destroys nothing, and a lossy one needs an
// approving passkey at the controller, which already holds copies of the logs
// and action history.

// Audit actions of the repair state machine. steward_tamper_repair_contested is
// written by the guards of a finished repair (handlers_steward_repair_guard.go).
const (
	auditActionTamperRepairRequested = "steward_tamper_repair_requested"
	auditActionTamperRepairCancelled = "steward_tamper_repair_cancelled"
	auditActionTamperRepairRunning   = "steward_tamper_repair_running"
	auditActionTamperRepairFailed    = "steward_tamper_repair_failed"
	auditActionTamperRepairCompleted = "steward_tamper_repair_completed"
	auditActionTamperRepairContested = "steward_tamper_repair_contested"
)

// NonceStore key prefixes of the repair records.
const (
	repairRequestKeyPrefix = "steward-repair/"         // steward-repair/<stewardID>/<repair_id>
	repairResultKeyPrefix  = "steward-repair-result/"  // steward-repair-result/<repair_id>
	repairRetiredKeyPrefix = "steward-repair-retired/" // steward-repair-retired/<oldDeviceID> (read by the repair guard)
)

const (
	// repairRequestTTL is how long a repair request stays valid; it is also the
	// expiry signed into the RepairRequest.
	repairRequestTTL = 7 * 24 * time.Hour

	// repairResultTTL is how long the completion result is kept so a lost
	// response can be retried with the same key.
	repairResultTTL = 24 * time.Hour

	// repairRetiredTTL is the watch window of the repair guard for a retired device identity.
	repairRetiredTTL = 24 * time.Hour

	// repairAuditLimit bounds the audit events read for one steward's repair state.
	repairAuditLimit = 500

	// repairLossApprovalRequiredError is the machine-readable error of a request
	// whose approval is not exactly the loss the steward reported.
	repairLossApprovalRequiredError = "loss_approval_required"
)

// Repair states reported by GET.
const (
	repairStateWaiting         = "waiting"
	repairStateRunning         = "running"
	repairStateCompleted       = "completed"
	repairStateRestored        = "restored"
	repairStateFailed          = "failed"
	repairStateRefusedDataLoss = "refused_data_loss"
	repairStateCancelled       = "cancelled"
	repairStateContested       = "contested"
)

// RepairSender delivers a RepairRequest to a connected steward. The control-plane
// provider satisfies it.
type RepairSender interface {
	SendRepair(ctx context.Context, stewardID string, req controlplaneTypes.RepairRequest) error
}

// repairDelivery is what the server needs to sign and send a repair request.
type repairDelivery struct {
	sender RepairSender
	signer signature.Signer
	chains *commands.SignerChainBuilder
}

// SetRepairDelivery binds the sender, the signer and the signer-chain builder
// used to deliver repair requests. Call after New() returns and before Start().
func (s *Server) SetRepairDelivery(sender RepairSender, signer signature.Signer, chains *commands.SignerChainBuilder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sender == nil || signer == nil || chains == nil {
		s.repair = nil
		return
	}
	s.repair = &repairDelivery{sender: sender, signer: signer, chains: chains}
}

func (s *Server) repairDeliveryConfig() *repairDelivery {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.repair
}

// repairRequestBody is the body of POST /stewards/{id}/tamper/repair.
type repairRequestBody struct {
	Reason            string   `json:"reason,omitempty"`
	ApprovedLossCodes []string `json:"approved_loss_codes"`
}

// repairAcceptedResponse is the 202 body of an accepted repair request.
type repairAcceptedResponse struct {
	RepairID  string   `json:"repair_id"`
	State     string   `json:"state"`
	Delivered bool     `json:"delivered"`
	LossCodes []string `json:"loss_codes"`
	ExpiresAt string   `json:"expires_at"`
	Note      string   `json:"note"`
}

// repairLossApprovalRequiredResponse is the 409 body of a request whose approval
// is not exactly the loss the steward reported.
type repairLossApprovalRequiredResponse struct {
	Error     string   `json:"error"`
	LossCodes []string `json:"loss_codes"`
	Message   string   `json:"message"`
}

// repairStatusResponse is the body of GET /stewards/{id}/tamper/repair.
type repairStatusResponse struct {
	RepairID      string   `json:"repair_id"`
	State         string   `json:"state"`
	RequestedBy   string   `json:"requested_by"`
	RequestedAt   string   `json:"requested_at"`
	LossCodes     []string `json:"loss_codes"`
	OutcomeCodes  []string `json:"outcome_codes"`
	CompletedFrom string   `json:"completed_from,omitempty"`
}

// repairRequestEntry is the value stored under steward-repair/<steward>/<id>.
type repairRequestEntry struct {
	ExpiresAtUnix     int64    `json:"expires_at_unix"`
	ApprovedBy        string   `json:"approved_by"`
	LossDigest        string   `json:"loss_digest"`
	ApprovedLossCodes []string `json:"approved_loss_codes"`
}

// repairView is the repair state derived from the audit events of one request.
type repairView struct {
	RepairID          string
	State             string
	RequestedBy       string
	RequestedAt       time.Time
	ExpiresAt         time.Time
	LossDigest        string
	ApprovedLossCodes []string
	OutcomeCodes      []string
	CompletedFrom     string
	// Unresolved is true while the request has no completed, failed, cancelled
	// or contested event.
	Unresolved  bool
	completedAt time.Time
}

func repairRequestKey(stewardID, repairID string) string {
	return repairRequestKeyPrefix + stewardID + "/" + repairID
}

// newRepairID returns a random 128-bit identifier.
func newRepairID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// repairLossCodes returns the distinct, sorted loss-risk codes in the steward's
// last reported health reasons.
func repairLossCodes(record *business.StewardRecord) []string {
	seen := make(map[string]struct{})
	for _, hr := range record.HealthReasons {
		if controlplaneTypes.IsRepairLossCode(hr.Code) {
			seen[hr.Code] = struct{}{}
		}
	}
	return repairSortedKeys(seen)
}

func repairSortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// normalizeLossCodes returns the distinct, sorted codes of in.
func normalizeLossCodes(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	for _, c := range in {
		seen[c] = struct{}{}
	}
	return repairSortedKeys(seen)
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// handleRepairTamperedSteward handles POST /api/v1/stewards/{id}/tamper/repair.
// The steward must be tampered. The approval must be exactly the loss set the
// steward last reported, else 409 loss_approval_required and nothing changes.
// The request is signed and sent at once to a connected steward, otherwise on its
// next connect. Repair and ban race through the same compare-and-swap.
func (s *Server) handleRepairTamperedSteward(w http.ResponseWriter, r *http.Request) {
	record, ok := s.tamperedStewardRecord(w, r, "POST /api/v1/stewards/{id}/tamper/repair")
	if !ok {
		return
	}
	delivery := s.repairDeliveryConfig()
	if s.nonceStore == nil || s.auditManager == nil || delivery == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Repair is not available", "SERVICE_UNAVAILABLE")
		return
	}
	approved, reason, ok := s.decodeRepairRequest(w, r)
	if !ok || !s.repairLossApproved(w, record, approved) {
		return
	}
	ctx := r.Context()
	// The same compare-and-swap as ban: a banned steward is refused here.
	if !s.repairClaimTampered(ctx, w, record) {
		return
	}
	// A new request cancels the previous unresolved one.
	s.cancelUnresolvedRepair(ctx, r, record, "superseded")

	repairID, expires, ok := s.storeRepairRequest(ctx, w, r, record, approved, reason)
	if !ok || !s.repairNotRacedByBan(ctx, w, r, record, repairID) {
		return
	}
	digest := controlplaneTypes.LossDigest(approved)
	delivered := s.deliverRepairNow(ctx, delivery, record.ID, repairID, digest, approved, expires)
	s.writeRepairAccepted(w, repairID, approved, expires, delivered)
}

// decodeRepairRequest reads and checks the body: every approved code must be a
// known loss code. On false the response has been written.
func (s *Server) decodeRepairRequest(w http.ResponseWriter, r *http.Request) (approved []string, reason string, ok bool) {
	var body repairRequestBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, tamperVerbBodyLimit)).Decode(&body); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return nil, "", false
	}
	approved = normalizeLossCodes(body.ApprovedLossCodes)
	for _, c := range approved {
		if !controlplaneTypes.IsRepairLossCode(c) {
			s.writeErrorResponse(w, http.StatusBadRequest, "approved_loss_codes holds an unknown loss code", "INVALID_REQUEST")
			return nil, "", false
		}
	}
	return approved, sanitizeTamperReason(body.Reason), true
}

// repairLossApproved is the controller's side of the loss gate: the approval must
// be exactly the loss the steward last reported. On false the 409 has been
// written and nothing has changed.
func (s *Server) repairLossApproved(w http.ResponseWriter, record *business.StewardRecord, approved []string) bool {
	lossCodes := repairLossCodes(record)
	if equalStringSets(lossCodes, approved) {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	s.encodeJSONBody(w, repairLossApprovalRequiredResponse{
		Error:     repairLossApprovalRequiredError,
		LossCodes: lossCodes,
		Message:   "Repairing would discard this local data. Approve exactly these codes to proceed.",
	}, "tamper repair loss gate")
	return false
}

// repairClaimTampered runs the compare-and-swap shared with ban. On false the
// response has been written.
func (s *Server) repairClaimTampered(ctx context.Context, w http.ResponseWriter, record *business.StewardRecord) bool {
	stillTampered, err := s.stewardStore.TransitionStewardStatus(ctx, record.ID, business.StewardStatusTampered, business.StewardStatusTampered)
	if err != nil {
		s.logger.Error("tamper repair: status check failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to request repair", "INTERNAL_ERROR")
		return false
	}
	if !stillTampered {
		s.writeErrorResponse(w, http.StatusConflict, "Steward is no longer tampered", "STEWARD_NOT_TAMPERED")
	}
	return stillTampered
}

// storeRepairRequest writes the single-use nonce entry and audits the request.
// On false the response has been written.
func (s *Server) storeRepairRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, record *business.StewardRecord, approved []string, reason string) (repairID string, expiresUnix int64, ok bool) {
	repairID, err := newRepairID()
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to request repair", "INTERNAL_ERROR")
		return "", 0, false
	}
	expires := time.Now().UTC().Add(repairRequestTTL)
	digest := controlplaneTypes.LossDigest(approved)
	entry, _ := json.Marshal(repairRequestEntry{
		ExpiresAtUnix: expires.Unix(), ApprovedBy: principalIDOf(r), LossDigest: digest, ApprovedLossCodes: approved,
	})
	if err := s.nonceStore.PutNonce(ctx, repairRequestKey(record.ID, repairID), entry, repairRequestTTL); err != nil {
		s.logger.Error("tamper repair: storing the request failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to request repair", "INTERNAL_ERROR")
		return "", 0, false
	}
	s.emitIdentityOperatorAudit(ctx, r, auditActionTamperRepairRequested, record, map[string]interface{}{
		"repair_id":           repairID,
		"approved_loss_codes": approved,
		"loss_digest":         digest,
		"expires_at_unix":     expires.Unix(),
		"reason":              reason,
	})
	return repairID, expires.Unix(), true
}

// repairNotRacedByBan withdraws the request when a ban won after the
// compare-and-swap. On false the response has been written.
func (s *Server) repairNotRacedByBan(ctx context.Context, w http.ResponseWriter, r *http.Request, record *business.StewardRecord, repairID string) bool {
	if s.stewardIsTampered(ctx, record.ID) {
		return true
	}
	if _, _, err := s.nonceStore.GetAndConsumeNonce(ctx, repairRequestKey(record.ID, repairID)); err != nil {
		s.logger.Warn("tamper repair: withdrawing the request failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
	}
	s.emitIdentityOperatorAudit(ctx, r, auditActionTamperRepairCancelled, record, map[string]interface{}{
		"repair_id": repairID, "reason": "steward_no_longer_tampered",
	})
	s.writeErrorResponse(w, http.StatusConflict, "Steward is no longer tampered", "STEWARD_NOT_TAMPERED")
	return false
}

// deliverRepairNow sends the request to a connected steward. A steward that is
// not connected is sent it on its next connect.
func (s *Server) deliverRepairNow(ctx context.Context, d *repairDelivery, stewardID, repairID, digest string, approved []string, expiresUnix int64) bool {
	if err := s.sendRepair(ctx, d, stewardID, repairID, digest, approved, expiresUnix); err != nil {
		s.logger.Debug("tamper repair: request not delivered, steward is sent it on its next connect",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
		return false
	}
	return true
}

func (s *Server) writeRepairAccepted(w http.ResponseWriter, repairID string, approved []string, expiresUnix int64, delivered bool) {
	s.logger.Info("Tamper repair requested", "repair_id", repairID, "delivered", delivered)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	s.encodeJSONBody(w, map[string]interface{}{"data": repairAcceptedResponse{
		RepairID:  repairID,
		State:     repairStateWaiting,
		Delivered: delivered,
		LossCodes: approved,
		ExpiresAt: time.Unix(expiresUnix, 0).UTC().Format(time.RFC3339),
		Note: "Repair requested: the steward resets rights on its own files, makes a new identity key and its old certificate is revoked. " +
			"It keeps its ID, local logs and action history, except for the loss you approved. If an unauthorized party holds a copy of the " +
			"steward's keys and completes first, that party wins and the steward's credentials are refused; the controller then marks it contested.",
	}}, "tamper repair accepted")
}

func principalIDOf(r *http.Request) string {
	if p, _ := r.Context().Value(principalContextKey).(*Principal); p != nil {
		return p.ID
	}
	return ""
}

// sendRepair signs the repair request over (steward ID, repair ID, loss digest,
// expiry) with the command signer, attaches the signer chain, and sends it. An
// error means it was not delivered now.
func (s *Server) sendRepair(ctx context.Context, d *repairDelivery, stewardID, repairID, digest string, approved []string, expiresUnix int64) error {
	sig, chain, err := d.chains.SignWithChain(d.signer, controlplaneTypes.RepairSigningPayload(stewardID, repairID, digest, expiresUnix))
	if err != nil {
		return fmt.Errorf("sign repair request: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return fmt.Errorf("decode repair signature: %w", err)
	}
	return d.sender.SendRepair(ctx, stewardID, controlplaneTypes.RepairRequest{
		RepairID:          repairID,
		ApprovedLossCodes: approved,
		LossDigest:        digest,
		ExpiresAtUnix:     expiresUnix,
		Signature:         sigBytes,
		SignerChainPEM:    chain,
	})
}

// DeliverPendingRepair sends a steward its latest unresolved repair request, if
// it has one and is still tampered. It is the on-connect delivery of a request
// made while the steward was offline. A steward that already completed, failed
// or had the request cancelled receives nothing.
func (s *Server) DeliverPendingRepair(ctx context.Context, stewardID string) error {
	delivery := s.repairDeliveryConfig()
	if delivery == nil || !s.repairReadable() {
		return nil
	}
	record, err := s.stewardStore.GetSteward(ctx, stewardID)
	if err != nil || record == nil || record.Status != business.StewardStatusTampered {
		return nil
	}
	view, err := s.latestRepair(ctx, record)
	if err != nil || view == nil || !view.Unresolved || !view.ExpiresAt.After(time.Now()) {
		return err
	}
	return s.sendRepair(ctx, delivery, record.ID, view.RepairID, view.LossDigest, view.ApprovedLossCodes, view.ExpiresAt.Unix())
}

func (s *Server) repairReadable() bool { return s.stewardStore != nil && s.auditManager != nil }

// cancelUnresolvedRepair cancels the steward's previous unresolved repair, if any:
// the nonce is consumed so it can no longer complete, and the cancellation is
// audited.
func (s *Server) cancelUnresolvedRepair(ctx context.Context, r *http.Request, record *business.StewardRecord, why string) {
	view, err := s.latestRepair(ctx, record)
	if err != nil || view == nil || !view.Unresolved {
		return
	}
	if _, _, err := s.nonceStore.GetAndConsumeNonce(ctx, repairRequestKey(record.ID, view.RepairID)); err != nil {
		s.logger.Warn("tamper repair: consuming the previous request failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
	}
	s.emitIdentityOperatorAudit(ctx, r, auditActionTamperRepairCancelled, record, map[string]interface{}{
		"repair_id": view.RepairID, "reason": why,
	})
}

// repairAuditActions are the audit actions read to derive a repair's state.
var repairAuditActions = []string{
	auditActionTamperRepairRequested, auditActionTamperRepairCancelled,
	auditActionTamperRepairRunning, auditActionTamperRepairFailed,
	auditActionTamperRepairCompleted, auditActionTamperRepairContested,
	auditActionTamperRestored,
}

// latestRepair derives the state of the steward's latest repair request from the
// audit events. It returns nil when the steward has none. Event details are
// treated as untrusted when read back: only events of the same tenant and the
// same repair_id count.
func (s *Server) latestRepair(ctx context.Context, record *business.StewardRecord) (*repairView, error) {
	entries, err := s.queryRepairEvents(ctx, record)
	if err != nil {
		return nil, err
	}
	latest := latestRequestIndex(entries, record)
	if latest < 0 {
		return nil, nil
	}
	view := newRepairView(entries[latest])
	view.fold(entries[latest+1:], record)
	return view, nil
}

// queryRepairEvents reads the steward's repair events oldest first.
func (s *Server) queryRepairEvents(ctx context.Context, record *business.StewardRecord) ([]*business.AuditEntry, error) {
	if s.auditManager == nil {
		return nil, errors.New("audit manager unavailable")
	}
	if err := s.auditManager.Flush(ctx); err != nil {
		s.logger.Debug("tamper repair: audit flush failed before reading state",
			"error", logging.SanitizeLogValue(err.Error()))
	}
	entries, err := s.auditManager.QueryEntries(ctx, &business.AuditFilter{
		TenantID:      record.TenantID,
		Actions:       repairAuditActions,
		ResourceTypes: []string{"steward"},
		ResourceIDs:   []string{record.ID},
		Limit:         repairAuditLimit,
		SortBy:        "timestamp",
		Order:         "asc",
	})
	if err != nil {
		return nil, fmt.Errorf("read repair events: %w", err)
	}
	return entries, nil
}

// belongsTo reports whether the event is the steward's own, in its tenant.
func belongsTo(e *business.AuditEntry, record *business.StewardRecord) bool {
	return e.TenantID == record.TenantID && e.ResourceID == record.ID
}

// latestRequestIndex returns the index of the latest requested event, or -1.
func latestRequestIndex(entries []*business.AuditEntry, record *business.StewardRecord) int {
	latest := -1
	for i, e := range entries {
		if e.Action == auditActionTamperRepairRequested && belongsTo(e, record) {
			latest = i
		}
	}
	return latest
}

func newRepairView(req *business.AuditEntry) *repairView {
	return &repairView{
		RepairID:          auditString(req.Details, "repair_id"),
		State:             repairStateWaiting,
		RequestedBy:       req.UserID,
		RequestedAt:       req.Timestamp,
		LossDigest:        auditString(req.Details, "loss_digest"),
		ApprovedLossCodes: sanitizeRepairCodes(auditStringSlice(req.Details["approved_loss_codes"])),
		ExpiresAt:         time.Unix(auditInt64(req.Details["expires_at_unix"]), 0),
		Unresolved:        true,
	}
}

// fold applies the events after the request, oldest first. A restore after the
// completion makes the state restored; any other event counts only when it names
// this repair.
func (v *repairView) fold(events []*business.AuditEntry, record *business.StewardRecord) {
	for _, e := range events {
		if !belongsTo(e, record) {
			continue
		}
		if e.Action == auditActionTamperRestored {
			v.applyRestore(e)
			continue
		}
		if auditString(e.Details, "repair_id") == v.RepairID {
			v.applyRepairEvent(e)
		}
	}
}

func (v *repairView) applyRestore(e *business.AuditEntry) {
	if v.State == repairStateCompleted && e.Timestamp.After(v.completedAt) {
		v.State = repairStateRestored
	}
}

// applyRepairEvent folds one audit event of the current repair into the view. A
// terminal state is never overwritten except completed, which can become
// contested.
func (v *repairView) applyRepairEvent(e *business.AuditEntry) {
	switch e.Action {
	case auditActionTamperRepairRunning:
		v.applyRunning()
	case auditActionTamperRepairFailed:
		v.applyFailed(e)
	case auditActionTamperRepairCancelled:
		v.resolve(repairStateCancelled)
	case auditActionTamperRepairCompleted:
		v.applyCompleted(e)
	case auditActionTamperRepairContested:
		v.applyContested()
	}
}

// resolve moves an unresolved request to a terminal state.
func (v *repairView) resolve(state string) bool {
	if !v.Unresolved {
		return false
	}
	v.State = state
	v.Unresolved = false
	return true
}

func (v *repairView) applyRunning() {
	if v.Unresolved && v.State == repairStateWaiting {
		v.State = repairStateRunning
		v.OutcomeCodes = addUnique(v.OutcomeCodes, controlplaneTypes.ReasonCodeRepairRunning)
	}
}

func (v *repairView) applyFailed(e *business.AuditEntry) {
	codes := sanitizeRepairCodes(auditStringSlice(e.Details["codes"]))
	state := repairStateFailed
	for _, c := range codes {
		if c == controlplaneTypes.ReasonCodeRepairRefusedDataLoss {
			state = repairStateRefusedDataLoss
		}
	}
	if v.resolve(state) {
		v.OutcomeCodes = addUnique(v.OutcomeCodes, codes...)
	}
}

func (v *repairView) applyCompleted(e *business.AuditEntry) {
	if v.resolve(repairStateCompleted) {
		v.CompletedFrom = logging.SanitizeLogValue(auditString(e.Details, "completed_from"))
		v.OutcomeCodes = addUnique(v.OutcomeCodes, controlplaneTypes.ReasonCodeRepairCompleted)
		v.completedAt = e.Timestamp
	}
}

func (v *repairView) applyContested() {
	if v.State == repairStateCompleted || v.Unresolved {
		v.State = repairStateContested
		v.Unresolved = false
		v.OutcomeCodes = addUnique(v.OutcomeCodes, controlplaneTypes.ReasonCodeRepairContested)
	}
}

// sanitizeRepairCodes applies the S1 reason caps to codes read back from audit
// events and drops control characters.
func sanitizeRepairCodes(codes []string) []string {
	return sanitizeTamperCodes(codes)
}

// auditInt64 reads a number from audit details, which a store may return as
// int64, float64 or json.Number.
func auditInt64(v interface{}) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	case json.Number:
		n, _ := t.Int64()
		return n
	}
	return 0
}

// handleGetTamperRepair handles GET /api/v1/stewards/{id}/tamper/repair.
func (s *Server) handleGetTamperRepair(w http.ResponseWriter, r *http.Request) {
	record, ok := s.operatorStewardLookup(w, r, "GET /api/v1/stewards/{id}/tamper/repair")
	if !ok {
		return
	}
	view, err := s.latestRepair(r.Context(), record)
	if err != nil {
		s.logger.Error("tamper repair: reading state failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read repair state", "INTERNAL_ERROR")
		return
	}
	if view == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "No repair has been requested for this steward", "REPAIR_NOT_FOUND")
		return
	}
	s.writeSuccessResponse(w, repairStatusResponse{
		RepairID:      view.RepairID,
		State:         view.State,
		RequestedBy:   view.RequestedBy,
		RequestedAt:   view.RequestedAt.UTC().Format(time.RFC3339),
		LossCodes:     nonNilStrings(view.ApprovedLossCodes),
		OutcomeCodes:  nonNilStrings(view.OutcomeCodes),
		CompletedFrom: view.CompletedFrom,
	})
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// recordRepairAudit writes a repair audit event that has no operator request: a
// completion by the steward, or a failure the controller itself hit.
func (s *Server) recordRepairAudit(ctx context.Context, record *business.StewardRecord, action string, result business.AuditResult, details map[string]interface{}) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(record.TenantID).
		Type(business.AuditEventSecurityEvent).
		Action(action).
		User(record.ID, business.AuditUserTypeSystem).
		Resource("steward", record.ID, "").
		Result(result).
		Severity(business.AuditSeverityHigh).
		Detail("steward_id", record.ID)
	for k, v := range details {
		b = b.Detail(k, v)
	}
	auditCtx, cancel := detachedAuditContext(ctx)
	defer cancel()
	if err := s.auditManager.RecordEvent(auditCtx, b); err != nil {
		s.logger.Warn("Failed to emit tamper repair audit event",
			"action", action, "error", logging.SanitizeLogValue(err.Error()))
	}
}

// ---- Completion: key rotation in the refresh-complete flow ------------------

// repairResultEntry is the value stored under steward-repair-result/<repair_id>
// after a completion, so a retry of a lost response with the same key reads the
// same result. It holds the certificate and issuer chain only; the controller
// never sees a private key.
type repairResultEntry struct {
	StewardID    string `json:"steward_id"`
	OldDeviceID  string `json:"old_device_id"`
	OldKeyPub    []byte `json:"old_key_pub"`
	OldKeyAlg    string `json:"old_key_alg"`
	NewKeyPub    []byte `json:"new_key_pub"`
	CSRSHA256    string `json:"csr_sha256"`
	ExpiresAt    int64  `json:"expires_at_unix"`
	ResponseJSON []byte `json:"response_json"`
}

// repairRetiredEntry is the retired-device tombstone the repair guard reads with
// GetAndConsumeNonce: completion (this file) is its single producer.
//
// It records the retired public key and its algorithm: a request addressed to the
// retired device ID contests the repair only when it proves possession of that
// key, since the device ID itself is public. TenantID is the steward's own tenant,
// for audit context only.
type repairRetiredEntry struct {
	StewardID   string    `json:"steward_id"`
	TenantID    string    `json:"tenant_id"`
	OldDeviceID string    `json:"old_device_id"`
	OldKeyPub   []byte    `json:"old_key_pub"`
	OldKeyAlg   string    `json:"old_key_alg"`
	CompletedAt time.Time `json:"completed_at"`
}

// keyProtectionRank orders the protection levels: software below hardware-backed.
// csrDigestHex is the hex SHA-256 of the CSR text, used to bind a retry to the
// request that was answered.
func csrDigestHex(csrPEM string) string {
	sum := sha256.Sum256([]byte(csrPEM))
	return hex.EncodeToString(sum[:])
}

func keyProtectionRank(level string) (int, bool) {
	switch level {
	case "", "file":
		return 0, true
	case "tpm", "secure-enclave":
		return 1, true
	}
	return 0, false
}

// repairRotation is a parsed and checked completion request.
type repairRotation struct {
	newKeyPub   []byte
	newAlg      KeyAlgorithm
	newLevel    string
	newDeviceID string
	oldProof    []byte
	newProof    []byte
}

// refuseRepairComplete audits a refused completion and answers it. Nothing has
// been changed when it is called, and the nonce has not been consumed.
func (s *Server) refuseRepairComplete(w http.ResponseWriter, r *http.Request, record *business.StewardRecord, deviceID string, status int, message, reason string) {
	tenantID := ""
	if record != nil {
		tenantID = record.TenantID
	}
	s.emitRefreshAudit(r.Context(), deviceID, tenantID,
		business.AuditEventSecurityEvent, "refresh_rejected",
		business.AuditResultFailure, business.AuditSeverityHigh,
		map[string]interface{}{"reason": reason, "repair": true})
	s.writeStatusError(w, status, message)
}

// parseRepairRotation decodes and checks the format of the rotation fields of a
// completion request against the key protection level being replaced. The second
// result is the refusal reason, empty when the request is well formed.
func parseRepairRotation(req *RefreshCompleteRequest, oldLevel string) (*repairRotation, string) {
	newPub, alg, reason := decodeRotationKey(req)
	if reason != "" {
		return nil, reason
	}
	level, reason := checkRotationLevel(req.NewIdentityKeyLevel, oldLevel)
	if reason != "" {
		return nil, reason
	}
	oldProof, err := base64.RawURLEncoding.DecodeString(req.OldKeyProof)
	if err != nil || len(oldProof) == 0 {
		return nil, "missing_old_key_proof"
	}
	newProof, err := base64.RawURLEncoding.DecodeString(req.NewKeyProof)
	if err != nil || len(newProof) == 0 {
		return nil, "missing_new_key_proof"
	}
	return &repairRotation{
		newKeyPub: newPub, newAlg: alg, newLevel: level, newDeviceID: deviceIDForKey(newPub),
		oldProof: oldProof, newProof: newProof,
	}, ""
}

// decodeRotationKey decodes the new public key and its algorithm.
func decodeRotationKey(req *RefreshCompleteRequest) ([]byte, KeyAlgorithm, string) {
	newPub, err := base64.RawURLEncoding.DecodeString(req.NewIdentityKeyPub)
	if err != nil || len(newPub) == 0 {
		return nil, "", "invalid_new_key"
	}
	alg, ok := normalizeKeyAlgorithm(req.NewIdentityKeyAlg)
	if !ok {
		return nil, "", "invalid_new_key_algorithm"
	}
	if _, err := parseDevicePublicKey(alg, newPub); err != nil {
		return nil, "", "invalid_new_key"
	}
	return newPub, alg, ""
}

// checkRotationLevel applies the downgrade rule: the new key's protection level
// must not be lower than the old one's. An absent new level means "file".
func checkRotationLevel(newLevel, oldLevel string) (string, string) {
	if newLevel == "" {
		newLevel = "file"
	}
	newRank, okNew := keyProtectionRank(newLevel)
	oldRank, okOld := keyProtectionRank(oldLevel)
	switch {
	case !okNew || !okOld:
		return "", "invalid_key_protection_level"
	case newRank < oldRank:
		return "", "key_protection_downgrade"
	}
	return newLevel, ""
}

// verifyRepairProofs checks that the old identity key (as stored) and the new
// identity key both signed the rotation digest.
func (s *Server) verifyRepairProofs(stewardID string, req *RefreshCompleteRequest, rot *repairRotation, oldAlgName string, oldKey []byte) bool {
	if !s.verifyRepairOldKeyProof(stewardID, req, rot, oldAlgName, oldKey) {
		return false
	}
	newPub, err := parseDevicePublicKey(rot.newAlg, rot.newKeyPub)
	if err != nil {
		return false
	}
	digest := controlplaneTypes.RepairRotationProofDigest(stewardID, req.RepairID, rot.newKeyPub, req.CSRPEM)
	return s.popVerifier.Verify(rot.newAlg, newPub, digest, rot.newProof)
}

// verifyRepairOldKeyProof checks that oldKey signed the rotation digest of req:
// proof that the caller holds the old identity key. rot may be nil (a malformed
// request), which never verifies.
func (s *Server) verifyRepairOldKeyProof(stewardID string, req *RefreshCompleteRequest, rot *repairRotation, oldAlgName string, oldKey []byte) bool {
	if rot == nil || len(oldKey) == 0 {
		return false
	}
	oldAlg, ok := normalizeKeyAlgorithm(oldAlgName)
	if !ok {
		return false
	}
	oldPub, err := parseDevicePublicKey(oldAlg, oldKey)
	if err != nil {
		return false
	}
	digest := controlplaneTypes.RepairRotationProofDigest(stewardID, req.RepairID, rot.newKeyPub, req.CSRPEM)
	return s.popVerifier.Verify(oldAlg, oldPub, digest, rot.oldProof)
}

// retiredKeyProven reports whether a repair-shaped request proves possession of
// the retired key oldKey of stewardID: its old-key proof over its own rotation
// digest verifies. Only such a request may contest a finished repair; the retired
// device ID and the repair ID are not secrets.
func (s *Server) retiredKeyProven(stewardID string, req *RefreshCompleteRequest, oldAlgName string, oldKey []byte) bool {
	rot, bad := parseRepairRotation(req, "")
	if bad != "" {
		return false
	}
	return s.verifyRepairOldKeyProof(stewardID, req, rot, oldAlgName, oldKey)
}

// handleRepairComplete is the repair shape of POST /stewards/{device_id}/refresh/complete.
// The record is looked up by the OLD device ID. Order, aborting on any failure
// with nothing swapped: revocation, status and format checks; both proofs against
// the CURRENT stored key (so garbage from a holder of the stolen certificate
// cannot burn the nonce); consume the single-use nonce; compare-and-swap rebind;
// revoke every serial (before the new CSR is signed); evict the live stream; sign
// the CSR; respond with certificate and issuer chain only.
//
//architecture:allow-unscoped-tenant-read -- pre-authentication handshake, identity proven by both identity keys and the single-use repair nonce (Issue #4336)
func (s *Server) handleRepairComplete(w http.ResponseWriter, r *http.Request, deviceID string, req *RefreshCompleteRequest) {
	ctx := r.Context()
	record, err := s.stewardStore.GetStewardByDeviceID(ctx, deviceID)
	if err != nil {
		s.repairLookupFailed(w, r, deviceID, req, err)
		return
	}
	rot, ok := s.checkRepairCompletion(w, r, record, deviceID, req)
	if !ok || !s.consumeRepairNonce(w, r, record, deviceID, req.RepairID) {
		return
	}
	resp, serials, newSerial, ok := s.rotateIdentity(w, r, record, rot, req)
	if !ok {
		return
	}
	// The wire shape is the #5673 shape: certificate and issuer chain only.
	out := RefreshCompleteResponse{Status: "approved", ClientCert: resp.ClientCert, IssuerChain: resp.IssuerChain}
	respJSON, _ := json.Marshal(out)
	oldDeviceID := record.DeviceID

	s.storeRepairResult(ctx, record, rot, req, respJSON)
	s.recordRepairAudit(ctx, record, auditActionTamperRepairCompleted, business.AuditResultSuccess, map[string]interface{}{
		"repair_id":       req.RepairID,
		"completed_from":  extractSourceIP(r, s.trustedProxies),
		"old_device_id":   oldDeviceID,
		"new_device_id":   rot.newDeviceID,
		"revoked_serials": serials,
		"new_serial":      newSerial,
		"completed_at":    time.Now().UTC().Format(time.RFC3339),
	})
	s.logger.Info("Tamper repair completed",
		"steward_id", logging.SanitizeLogValue(record.ID), "repair_id", logging.SanitizeLogValue(req.RepairID),
		"revoked_serials", len(serials))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// #nosec G117 -- the response carries the signed client certificate and its
	// issuer chain only; the controller never holds a private key (Issue #3781).
	s.encodeJSONBody(w, out, "tamper repair complete")
}

// repairLookupFailed answers a completion whose old device ID did not resolve:
// not-found is a lost-response retry or a race loser; anything else is a store
// error.
func (s *Server) repairLookupFailed(w http.ResponseWriter, r *http.Request, deviceID string, req *RefreshCompleteRequest, err error) {
	if errors.Is(err, business.ErrStewardNotFound) {
		s.serveRepairRetry(w, r, deviceID, req)
		return
	}
	s.logger.Error("Failed to look up steward by device ID", "device_id", logging.SanitizeLogValue(deviceID), "error", logging.SanitizeLogValue(err.Error()))
	s.writeStatusError(w, http.StatusInternalServerError, "failed to look up device")
}

// checkRepairCompletion runs every check that happens before the nonce is
// consumed: revocation first (before any proof), status, CSR and rotation format,
// then both proofs against the stored key. On false the response has been written
// and nothing has changed.
func (s *Server) checkRepairCompletion(w http.ResponseWriter, r *http.Request, record *business.StewardRecord, deviceID string, req *RefreshCompleteRequest) (*repairRotation, bool) {
	if record.Status == business.StewardStatusRevoked {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultDenied, business.AuditSeverityCritical,
			map[string]interface{}{"decision": "denied", "reason": "revoked", "repair": true})
		s.writeStatusError(w, http.StatusForbidden, "device is revoked")
		return nil, false
	}
	if record.Status != business.StewardStatusTampered {
		s.refuseRepairComplete(w, r, record, deviceID, http.StatusConflict, "steward is not tampered", "not_tampered")
		return nil, false
	}
	if s.nonceStore == nil || s.certManager == nil {
		s.writeStatusError(w, http.StatusServiceUnavailable, "repair is not available")
		return nil, false
	}
	if !s.validateRefreshCSR(w, req.CSRPEM) {
		return nil, false
	}
	rot, bad := parseRepairRotation(req, record.KeyProtectionLevel)
	if bad == "" && rot.newDeviceID == record.DeviceID {
		bad = "key_not_rotated"
	}
	if bad != "" {
		s.refuseRepairComplete(w, r, record, deviceID, http.StatusBadRequest, "invalid repair completion", bad)
		return nil, false
	}
	if !s.verifyRepairProofs(record.ID, req, rot, record.KeyAlgorithm, record.IdentityKeyPub) {
		s.refuseRepairComplete(w, r, record, deviceID, http.StatusUnauthorized, "proof-of-possession verification failed", "invalid_repair_proof")
		return nil, false
	}
	return rot, true
}

// consumeRepairNonce takes the single-use right to complete. It is consumed only
// after both proofs hold. On false the response has been written.
func (s *Server) consumeRepairNonce(w http.ResponseWriter, r *http.Request, record *business.StewardRecord, deviceID, repairID string) bool {
	raw, found, err := s.nonceStore.GetAndConsumeNonce(r.Context(), repairRequestKey(record.ID, repairID))
	if err != nil {
		s.logger.Error("Failed to consume repair nonce", "error", logging.SanitizeLogValue(err.Error()))
		s.writeStatusError(w, http.StatusInternalServerError, "internal error reading repair request")
		return false
	}
	var nonce repairRequestEntry
	if !found || json.Unmarshal(raw, &nonce) != nil || time.Now().Unix() > nonce.ExpiresAtUnix {
		s.refuseRepairComplete(w, r, record, deviceID, http.StatusUnauthorized, "repair request expired or not found", "repair_nonce_not_found")
		return false
	}
	return true
}

// rotateIdentity swaps the identity key and credentials after the nonce is
// consumed: compare-and-swap rebind, revoke every serial BEFORE the new CSR is
// signed (the new certificate shares the steward's CN), evict the live stream,
// drop the refreshes queued under the old device ID, sign the CSR. A failure
// after the rebind restores the old key; the repair is then failed and the
// steward stays tampered. On false the response has been written.
func (s *Server) rotateIdentity(w http.ResponseWriter, r *http.Request, record *business.StewardRecord, rot *repairRotation, req *RefreshCompleteRequest) (resp *RefreshCompleteResponse, serials []string, newSerial string, ok bool) {
	ctx := r.Context()
	if !s.rebindForRepair(w, r, record, rot, req.RepairID) {
		return nil, nil, "", false
	}
	serials, err := revokeStewardSerials(s.certManager, record.ID)
	if err != nil {
		s.logger.Error("repair: revocation failed", "steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		s.abortRepairRotation(w, r, record, rot, req.RepairID, "revoke_failed", "failed to revoke the previous certificates")
		return nil, nil, "", false
	}
	s.evictStewardStream(record.ID)
	if s.pendingRefreshStore != nil {
		s.supersedeOpenRefreshes(ctx, record.DeviceID, record.TenantID)
	}
	resp, newSerial, err = s.buildRefreshClaimResponse(ctx, record, req.CSRPEM)
	if err != nil {
		s.logger.Error("repair: certificate issuance failed", "steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		s.abortRepairRotation(w, r, record, rot, req.RepairID, "cert_issuance_failed", "failed to issue certificate")
		return nil, nil, "", false
	}
	return resp, serials, newSerial, true
}

// rebindForRepair performs the compare-and-swap rebind against the key the
// completion was authorized with. Of two completions authorized against the same
// key exactly one succeeds. On false the response has been written.
func (s *Server) rebindForRepair(w http.ResponseWriter, r *http.Request, record *business.StewardRecord, rot *repairRotation, repairID string) bool {
	err := s.stewardStore.RebindStewardIdentityIf(r.Context(), record.ID, record.IdentityKeyPub, rot.newDeviceID, rot.newKeyPub, rot.newLevel, string(rot.newAlg))
	switch {
	case err == nil:
		return true
	case errors.Is(err, business.ErrIdentityKeyChanged) || errors.Is(err, business.ErrStewardNotFound):
		s.refuseRepairComplete(w, r, record, record.DeviceID, http.StatusConflict, "the identity changed; repair was completed elsewhere", "identity_key_changed")
	case errors.Is(err, business.ErrStewardDeviceIDConflict):
		s.failRepairComplete(w, r, record, repairID, http.StatusConflict, "device identity is held by another steward", "device_id_conflict")
	default:
		s.logger.Error("repair: rebind failed", "steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		s.failRepairComplete(w, r, record, repairID, http.StatusInternalServerError, "failed to rotate identity", "rebind_failed")
	}
	return false
}

// abortRepairRotation puts the old identity key back after the rebind and fails
// the repair. The record still holds the old values: record is the pre-rebind
// read.
func (s *Server) abortRepairRotation(w http.ResponseWriter, r *http.Request, record *business.StewardRecord, rot *repairRotation, repairID, reason, message string) {
	err := s.stewardStore.RebindStewardIdentityIf(r.Context(), record.ID, rot.newKeyPub, record.DeviceID, record.IdentityKeyPub, record.KeyProtectionLevel, record.KeyAlgorithm)
	if err != nil {
		s.logger.Error("repair: rollback of rebind failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
	}
	s.failRepairComplete(w, r, record, repairID, http.StatusInternalServerError, message, reason)
}

// failRepairComplete answers a completion that failed after the nonce was
// consumed, with nothing swapped: the repair failed, the steward is still
// tampered, and the operator asks again.
func (s *Server) failRepairComplete(w http.ResponseWriter, r *http.Request, record *business.StewardRecord, repairID string, status int, message, reason string) {
	s.recordRepairAudit(r.Context(), record, auditActionTamperRepairFailed, business.AuditResultFailure, map[string]interface{}{
		"repair_id": repairID,
		"codes":     []string{controlplaneTypes.ReasonCodeRepairFailed},
		"reason":    reason,
	})
	s.writeStatusError(w, status, message)
}

// storeRepairResult keeps the completion result for retries and writes the
// retired-device tombstone the repair guard reads. A store failure is logged: the repair itself
// has already happened, and a missed retry fails closed. record is the pre-rebind
// read, so it still names the old identity.
func (s *Server) storeRepairResult(ctx context.Context, record *business.StewardRecord, rot *repairRotation, req *RefreshCompleteRequest, respJSON []byte) {
	res, _ := json.Marshal(repairResultEntry{
		StewardID: record.ID, OldDeviceID: record.DeviceID, OldKeyPub: record.IdentityKeyPub, OldKeyAlg: record.KeyAlgorithm,
		NewKeyPub: rot.newKeyPub, CSRSHA256: csrDigestHex(req.CSRPEM),
		ExpiresAt: time.Now().Add(repairResultTTL).Unix(), ResponseJSON: respJSON,
	})
	if err := s.nonceStore.PutNonce(ctx, repairResultKeyPrefix+req.RepairID, res, repairResultTTL); err != nil {
		s.logger.Error("repair: storing the completion result failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
	}
	tomb, _ := json.Marshal(repairRetiredEntry{
		StewardID: record.ID, TenantID: record.TenantID, OldDeviceID: record.DeviceID,
		OldKeyPub: record.IdentityKeyPub, OldKeyAlg: record.KeyAlgorithm, CompletedAt: time.Now().UTC(),
	})
	if err := s.nonceStore.PutNonce(ctx, repairRetiredKeyPrefix+record.DeviceID, tomb, repairRetiredTTL); err != nil {
		s.logger.Error("repair: writing the retired-device tombstone failed",
			"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
	}
}

// serveRepairRetry handles a completion whose old device ID no longer resolves:
// either a lost response being retried, or the loser of a race. Only a retry with
// the same repair ID, the same new key and the same CSR, with both proofs valid
// against the keys recorded at completion, is answered with the stored result; a
// different key is refused. Anything else is the usual "device not found".
func (s *Server) serveRepairRetry(w http.ResponseWriter, r *http.Request, deviceID string, req *RefreshCompleteRequest) {
	ctx := r.Context()
	res, ok := s.readRepairResult(ctx, req.RepairID)
	if !ok || res.OldDeviceID != deviceID {
		s.repairDeviceNotFound(w, r, deviceID, req)
		return
	}
	record, err := s.stewardStore.GetSteward(ctx, res.StewardID)
	if err != nil || record == nil {
		s.repairDeviceNotFound(w, r, deviceID, req)
		return
	}
	if record.Status == business.StewardStatusRevoked {
		s.writeStatusError(w, http.StatusForbidden, "device is revoked")
		return
	}
	if status, reason := s.checkRepairRetry(record, res, req); reason != "" {
		s.refuseRepairComplete(w, r, record, deviceID, status, "repair retry refused", reason)
		// A refused retry that still proves possession of the retired key (a
		// different new key signed by the old one) is the other holder of the
		// retired credentials (Issue #5727). Without that proof it is only the
		// audited refusal: the device ID and repair ID are not secrets, so they
		// alone must never change state.
		if s.retiredKeyProven(res.StewardID, req, res.OldKeyAlg, res.OldKeyPub) {
			s.markRepairContested(ctx, record.ID, repairContestRetiredKeyRefresh)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// #nosec G117 -- the stored response is the signed client certificate and its issuer chain only.
	if _, err := w.Write(res.ResponseJSON); err != nil {
		s.logger.Error("Failed to write repair retry response", "error", logging.SanitizeLogValue(err.Error()))
	}
}

func (s *Server) repairDeviceNotFound(w http.ResponseWriter, r *http.Request, deviceID string, req *RefreshCompleteRequest) {
	s.emitUnauthenticatedRefreshAudit(r.Context(), deviceID, req.TenantID,
		business.AuditEventSecurityEvent, "refresh_rejected",
		business.AuditResultFailure, business.AuditSeverityMedium,
		map[string]interface{}{"decision": "rejected", "reason": "unknown_device", "repair": true})
	// The loser of a race can land here: its old device ID was retired by the
	// repair the other party completed (Issue #5727). It contests only when its
	// old-key proof verifies against the retired key; otherwise the refusal audit
	// above is the only record.
	s.contestOnRetiredDevice(r.Context(), deviceID, func(tomb *repairRetiredEntry) bool {
		return s.retiredKeyProven(tomb.StewardID, req, tomb.OldKeyAlg, tomb.OldKeyPub)
	})
	s.writeStatusError(w, http.StatusNotFound, "device not found")
}

// readRepairResult reads the stored completion result without consuming it.
func (s *Server) readRepairResult(ctx context.Context, repairID string) (*repairResultEntry, bool) {
	if s.nonceStore == nil || repairID == "" {
		return nil, false
	}
	key := repairResultKeyPrefix + repairID
	raw, found, err := s.nonceStore.GetAndConsumeNonce(ctx, key)
	if err != nil || !found {
		return nil, false
	}
	var res repairResultEntry
	remaining := time.Duration(0)
	if json.Unmarshal(raw, &res) == nil {
		remaining = time.Until(time.Unix(res.ExpiresAt, 0))
	}
	if remaining <= 0 {
		return nil, false
	}
	if err := s.nonceStore.PutNonce(ctx, key, raw, remaining); err != nil {
		s.logger.Error("repair: restoring the completion result failed", "error", logging.SanitizeLogValue(err.Error()))
	}
	return &res, true
}

// checkRepairRetry checks a retry against the recorded completion: the same new
// key and CSR, the record still holding that key, and both proofs valid against
// the keys recorded at completion. It returns the HTTP status and refusal reason,
// empty when the retry is the same request.
func (s *Server) checkRepairRetry(record *business.StewardRecord, res *repairResultEntry, req *RefreshCompleteRequest) (int, string) {
	rot, bad := parseRepairRotation(req, "")
	if bad != "" || !bytes.Equal(rot.newKeyPub, res.NewKeyPub) || csrDigestHex(req.CSRPEM) != res.CSRSHA256 ||
		!bytes.Equal(record.IdentityKeyPub, res.NewKeyPub) {
		return http.StatusConflict, "repair_key_mismatch"
	}
	if !s.verifyRepairProofs(res.StewardID, req, rot, res.OldKeyAlg, res.OldKeyPub) {
		return http.StatusUnauthorized, "invalid_repair_proof"
	}
	return 0, ""
}
