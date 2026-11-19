// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	notifif "github.com/cfgis/cfgms/pkg/notification/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// mspEmailSenderMaxBodyBytes bounds the PUT body; the fields are short and the
// password is capped at mspEmailMaxPasswordLen.
const mspEmailSenderMaxBodyBytes = 8 * 1024

const (
	mspEmailSenderAuditSet    = "tenant.email_sender_updated"
	mspEmailSenderAuditRemove = "tenant.email_sender_removed"
	mspEmailSenderAuditTested = "tenant.email_sender_tested"
)

// mspEmailTestMaxBodyBytes bounds how much of a test-send body is read before the
// request is refused; the body must be empty, so any content at all is an error.
const mspEmailTestMaxBodyBytes = 1024

// mspEmailSenderWriteMu serializes the secret-then-record write pair (and the
// removal pair) within this process, so a PUT cannot interleave with another PUT or
// a DELETE between its password check and its two writes.
var mspEmailSenderWriteMu sync.Mutex

// mspEmailSenderRequest is the body of PUT /tenants/{id}/email-sender. The password
// is optional only when one is already stored (a settings-only edit keeps it).
type mspEmailSenderRequest struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	TLSMode  string `json:"tls_mode"`
	From     string `json:"from"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// mspEmailSenderResponse is the response of all three routes. It never carries the
// password; PasswordPresent only says whether one is stored. Configured is true
// when a sender record exists.
type mspEmailSenderResponse struct {
	Configured      bool   `json:"configured"`
	PasswordPresent bool   `json:"password_present"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	TLSMode         string `json:"tls_mode"`
	From            string `json:"from"`
	Username        string `json:"username"`
}

func newMSPEmailSenderResponse(sender *MSPEmailSender, passwordPresent bool) mspEmailSenderResponse {
	resp := mspEmailSenderResponse{Configured: sender != nil, PasswordPresent: passwordPresent}
	if sender != nil {
		resp.Host, resp.Port, resp.TLSMode, resp.From, resp.Username = sender.Host, sender.Port, sender.TLSMode, sender.From, sender.Username
	}
	return resp
}

// authorizeMSPEmailSenderAccess resolves the {id} tenant as an MSP tenant and
// applies the ordinary tenant-scope decision, as authorizeTenantContactsAccess
// does. It writes the response and returns "" when the caller is refused: 404 for a
// missing, out-of-scope or non-MSP tenant (a client tenant has no sender of its own),
// the crossing challenge for a root-scoped caller lacking a crossing.
func (s *Server) authorizeMSPEmailSenderAccess(w http.ResponseWriter, r *http.Request, principal *Principal) string {
	tenantID := mux.Vars(r)["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return ""
	}
	td, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return ""
		}
		s.logger.Error("Failed to load tenant for MSP email sender route",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return ""
	}
	switch s.authorizeTenantAccess(r.Context(), principal, td.ID) {
	case tenantAuthAllowed:
		if !s.m365IsMSP(r.Context(), td) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return ""
		}
		return td.ID
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, td.ID)
	default:
		s.logger.Info("Cross-tenant MSP email sender access refused",
			"resource_tenant", logging.SanitizeLogValue(td.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenantFilter(r.Context())))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
	}
	return ""
}

// mspEmailSenderState reads the stored sender and whether a password is stored. It
// writes a 503 or 500 and returns ok=false when the stores are unavailable or fail.
func (s *Server) mspEmailSenderState(w http.ResponseWriter, r *http.Request, mspID string) (*MSPEmailSender, bool, bool) {
	st := s.MSPEmailSenderStore()
	if st == nil || s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "MSP email sender storage unavailable", "SERVICE_UNAVAILABLE")
		return nil, false, false
	}
	sender, err := st.Get(r.Context(), mspID)
	if err != nil {
		s.mspEmailSenderInternal(w, "failed to read email sender", mspID, err)
		return nil, false, false
	}
	smtpSecret, err := s.readMSPEmailPassword(r.Context(), mspID)
	if err != nil {
		s.mspEmailSenderInternal(w, "failed to read email sender", mspID, err)
		return nil, false, false
	}
	return sender, smtpSecret != "", true
}

func (s *Server) mspEmailSenderInternal(w http.ResponseWriter, msg, mspID string, err error) {
	s.logger.Error(msg,
		"tenant_id", logging.SanitizeLogValue(mspID),
		"error", logging.SanitizeLogValue(err.Error()))
	s.writeErrorResponse(w, http.StatusInternalServerError, msg, "EMAIL_SENDER_STORE_FAILED")
}

// handleGetMSPEmailSender implements GET /api/v1/tenants/{id}/email-sender.
func (s *Server) handleGetMSPEmailSender(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	mspID := s.authorizeMSPEmailSenderAccess(w, r, principal)
	if mspID == "" {
		return
	}
	sender, present, ok := s.mspEmailSenderState(w, r, mspID)
	if !ok {
		return
	}
	s.writeSuccessResponse(w, newMSPEmailSenderResponse(sender, present))
}

// refuseRootScopedEmailSenderSend writes the 403 and returns true for a root-scoped
// caller, even one holding a crossing: sending mail as the MSP is a write.
func (s *Server) refuseRootScopedEmailSenderSend(w http.ResponseWriter, principal *Principal) bool {
	if !subjectToTenantCrossingBoundary(principal) {
		return false
	}
	s.writeErrorResponse(w, http.StatusForbidden,
		"root-scoped callers cannot send mail as the MSP", "ROOT_SCOPED_CANNOT_EDIT_EMAIL_SENDER")
	return true
}

// refuseRootScopedEmailSenderWrite writes the 403 and returns true for a
// root-scoped caller, even one holding a crossing: the sender is what notifies the
// MSP about root's own access, so root replacing it would defeat that notice.
func (s *Server) refuseRootScopedEmailSenderWrite(w http.ResponseWriter, principal *Principal) bool {
	if !subjectToTenantCrossingBoundary(principal) {
		return false
	}
	s.writeErrorResponse(w, http.StatusForbidden,
		"root-scoped callers cannot change the MSP email sender", "ROOT_SCOPED_CANNOT_EDIT_EMAIL_SENDER")
	return true
}

// decodeMSPEmailSenderRequest reads the PUT body. Unknown fields, trailing data and
// an oversized body are refused; it writes the 400 and returns ok=false in that case.
func (s *Server) decodeMSPEmailSenderRequest(w http.ResponseWriter, r *http.Request) (req mspEmailSenderRequest, ok bool) {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, mspEmailSenderMaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return req, false
	}
	return req, true
}

// validateMSPEmailSenderUpdate checks the sender and the password against the sender
// contract. The password is required unless one is already stored and none is sent.
func validateMSPEmailSenderUpdate(sender MSPEmailSender, smtpSecret string, passwordStored bool) error {
	if smtpSecret == "" && passwordStored {
		return sender.validate()
	}
	return ValidateMSPEmailSender(sender, smtpSecret)
}

// handlePutMSPEmailSender implements PUT /api/v1/tenants/{id}/email-sender. It sets
// or replaces the MSP's sender. The password is write-only: it is required when
// none is stored and optional afterwards, where leaving it out keeps the stored one.
// Nothing is stored for an invalid body.
func (s *Server) handlePutMSPEmailSender(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireActingPrincipal(w, r)
	if !ok {
		return
	}
	mspID := s.authorizeMSPEmailSenderAccess(w, r, principal)
	if mspID == "" || s.refuseRootScopedEmailSenderWrite(w, principal) {
		return
	}
	req, ok := s.decodeMSPEmailSenderRequest(w, r)
	if !ok {
		return
	}
	sender := MSPEmailSender{Host: req.Host, Port: req.Port, TLSMode: req.TLSMode, From: req.From, Username: req.Username}
	if sender.TLSMode == "" {
		sender.TLSMode = config.EmailTLSModeStartTLS
	}

	mspEmailSenderWriteMu.Lock()
	defer mspEmailSenderWriteMu.Unlock()

	_, stored, ok := s.mspEmailSenderState(w, r, mspID)
	if !ok {
		return
	}
	if err := validateMSPEmailSenderUpdate(sender, req.Password, stored); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_EMAIL_SENDER")
		return
	}
	saved, err := s.writeMSPEmailSender(r, mspID, sender, req.Password, principal.ID)
	if err != nil {
		s.mspEmailSenderInternal(w, "failed to store email sender", mspID, err)
		return
	}

	s.recordMSPEmailSenderAudit(r, mspID, principal, mspEmailSenderAuditSet, saved)
	s.logger.Info("Updated MSP email sender", "tenant_id", logging.SanitizeLogValue(mspID))
	s.writeSuccessResponse(w, newMSPEmailSenderResponse(saved, stored || req.Password != ""))
}

// writeMSPEmailSender writes the password (when one is sent) and then the record, in
// that order, so a failed secret write stores no record. A record write that fails
// after the secret was stored does not roll the secret back: the sender then reads
// as not configured with a password present, and delivers nothing.
func (s *Server) writeMSPEmailSender(r *http.Request, mspID string, sender MSPEmailSender, smtpSecret, actor string) (*MSPEmailSender, error) {
	if smtpSecret != "" {
		if err := s.storeMSPEmailPassword(r.Context(), mspID, smtpSecret, actor); err != nil {
			return nil, err
		}
	}
	return s.MSPEmailSenderStore().Put(r.Context(), mspID, sender, actor)
}

// handleDeleteMSPEmailSender implements DELETE /api/v1/tenants/{id}/email-sender.
// It removes the password and the record; removing an absent sender succeeds.
func (s *Server) handleDeleteMSPEmailSender(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	mspID := s.authorizeMSPEmailSenderAccess(w, r, principal)
	if mspID == "" || s.refuseRootScopedEmailSenderWrite(w, principal) {
		return
	}

	mspEmailSenderWriteMu.Lock()
	defer mspEmailSenderWriteMu.Unlock()

	removed, _, ok := s.mspEmailSenderState(w, r, mspID)
	if !ok {
		return
	}
	if err := s.deleteMSPEmailPassword(r.Context(), mspID); err != nil {
		s.mspEmailSenderInternal(w, "failed to remove email sender", mspID, err)
		return
	}
	if err := s.MSPEmailSenderStore().Delete(r.Context(), mspID); err != nil {
		s.mspEmailSenderInternal(w, "failed to remove email sender", mspID, err)
		return
	}

	s.recordMSPEmailSenderAudit(r, mspID, principal, mspEmailSenderAuditRemove, removed)
	s.logger.Info("Removed MSP email sender", "tenant_id", logging.SanitizeLogValue(mspID))
	s.writeSuccessResponse(w, newMSPEmailSenderResponse(nil, false))
}

// recordMSPEmailSenderAudit writes the tenant-scoped, high-severity audit event for a
// change. The detail names the settings (host, port, tls mode, from) only: neither
// the password nor the username is written. sender is nil when nothing was stored.
func (s *Server) recordMSPEmailSenderAudit(r *http.Request, mspID string, principal *Principal, action string, sender *MSPEmailSender) {
	b := newMSPEmailSenderAuditEvent(mspID, principal, action, business.AuditResultSuccess)
	if sender != nil {
		b = b.Detail("host", sender.Host).Detail("port", sender.Port).
			Detail("tls_mode", sender.TLSMode).Detail("from", sender.From)
	}
	s.writeMSPEmailSenderAudit(r, mspID, b)
}

// newMSPEmailSenderAuditEvent starts the tenant-scoped, high-severity audit event
// for an action on the MSP's sender, naming the acting principal.
func newMSPEmailSenderAuditEvent(mspID string, principal *Principal, action string, result business.AuditResult) *audit.AuditEventBuilder {
	var actorID string
	if principal != nil {
		actorID = principal.ID
	}
	return audit.NewEventBuilder().
		Tenant(mspID).
		Type(business.AuditEventConfiguration).
		Action(action).
		User(actorID, business.AuditUserTypeHuman).
		Resource("tenant", mspID, "").
		Result(result).
		Severity(business.AuditSeverityHigh)
}

func (s *Server) writeMSPEmailSenderAudit(r *http.Request, mspID string, b *audit.AuditEventBuilder) {
	if s.auditManager == nil {
		return
	}
	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		s.logger.Error("Failed to record MSP email sender audit event",
			"tenant_id", logging.SanitizeLogValue(mspID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// mspEmailTestFailureReason is the short reason a test send reports. It is chosen
// from the fixed failure kinds, never from the error text, so neither a resolved
// address nor anything the mail server said can reach the response.
func mspEmailTestFailureReason(err error) string {
	switch emailSendFailureKind(err) {
	case emailFailTimeout:
		return "delivery timed out"
	case emailFailCanceled:
		return "delivery canceled"
	case emailFailCertificate:
		return "server certificate verification failed"
	case emailFailRejected:
		return "mail server rejected the message"
	default:
		return "delivery failed"
	}
}

// requireEmptyTestBody writes the 400 and returns false when the request carries
// any content: the recipient and the message are fixed on the server.
func (s *Server) requireEmptyTestBody(w http.ResponseWriter, r *http.Request) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, mspEmailTestMaxBodyBytes))
	if err != nil || len(bytes.TrimSpace(body)) > 0 {
		s.writeErrorResponse(w, http.StatusBadRequest, "request body must be empty: the recipient and content are fixed", "INVALID_REQUEST")
		return false
	}
	return true
}

// handleTestMSPEmailSender implements POST /api/v1/tenants/{id}/email-sender/test.
// It sends one fixed message to the sender's own from-address through the MSP's
// sender and reports the per-recipient result. The platform sender is never used.
// The notifier is the guarded one, so a host that resolves to a loopback, private or
// link-local address is refused and reports delivered=false.
func (s *Server) handleTestMSPEmailSender(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	mspID := s.authorizeMSPEmailSenderAccess(w, r, principal)
	if mspID == "" || s.refuseRootScopedEmailSenderSend(w, principal) {
		return
	}
	if !s.requireEmptyTestBody(w, r) {
		return
	}
	sender, _, ok := s.mspEmailSenderState(w, r, mspID)
	if !ok {
		return
	}
	n, err := s.buildMSPEmailNotifier(r.Context(), mspID)
	if err != nil {
		s.mspEmailSenderInternal(w, "failed to prepare email sender", mspID, err)
		return
	}
	if n == nil || sender == nil {
		s.writeErrorResponse(w, http.StatusConflict, "the MSP email sender is not configured or its password has not been stored", "EMAIL_NOT_CONFIGURED")
		return
	}

	resp := s.sendMSPEmailTest(r.Context(), mspID, n, sender.From)

	result := business.AuditResultSuccess
	if !resp.Delivered {
		result = business.AuditResultFailure
	}
	s.writeMSPEmailSenderAudit(r, mspID, newMSPEmailSenderAuditEvent(mspID, principal, mspEmailSenderAuditTested, result))
	s.writeSuccessResponse(w, resp)
}

// sendMSPEmailTest sends the fixed test message to the from-address through n and
// turns the outcome into the response shape. Only fixed failure reasons are
// reported, never the error text.
func (s *Server) sendMSPEmailTest(parent context.Context, mspID string, n notifif.Notifier, to string) emailTestResponse {
	ctx, cancel := context.WithTimeout(parent, emailTestSendTimeout)
	defer cancel()
	res, err := n.Send(ctx, notifif.Message{To: []string{to}, Subject: emailTestSubject, Body: emailTestBody})
	resp := emailTestResponse{Recipients: []emailTestRecipient{}}
	if err != nil {
		s.logger.Warn("MSP email sender test send failed",
			"tenant_id", logging.SanitizeLogValue(mspID),
			"kind", emailSendFailureKind(err))
		resp.FailureReason = mspEmailTestFailureReason(err)
		return resp
	}
	for _, rr := range res.Recipients {
		resp.Recipients = append(resp.Recipients, emailTestRecipient{Address: rr.Address, Accepted: rr.Accepted, Reason: rr.Reason})
	}
	resp.Delivered = len(res.Failed()) == 0 && len(res.Recipients) > 0
	if !resp.Delivered {
		resp.FailureReason = "recipient not accepted"
	}
	return resp
}
