// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3718 (Epic #3711): the approve decision for a pending credential request.
//
// Amendment (see the issue): approval signs nothing. The shipped steward registration
// path already works this way — handleApproveRegistration's own doc comment says "no
// cert is generated here (generate-on-claim)" — and this endpoint mirrors it: it
// validates the approver's own authority, decides which certificate markers the
// eventual credential will carry, selects or creates the account it will bind to, and
// records all three together on the pending request before moving it to "approved".
// Signing the lodged public key and writing the account binding atomically happen in
// the collect story that follows; a request that is approved and then abandoned must
// never have left a live credential behind.
package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// The three certificate markers this endpoint can grant (Epic #3711 D3). These are
// the only values that ever appear in pendingCredentialRequest.GrantedMarkers.
const (
	credentialMarkerAdmin          = "admin"
	credentialMarkerPayloadSigning = "payload_signing"
	credentialMarkerRootScope      = "root_scope"
)

// ApproveCredentialRequestBody is the POST /api/v1/credential-requests/{id}/approve
// body. Exactly one of AccountID or NewAccountUsername must be set: select an existing
// account within the caller's tenant subtree, or create one — a headless host is
// represented by its own account (Issue #3718 implementation note). Each Grant* field
// defaults to false; the marker set is an explicit per-marker choice, never inherited
// from the request.
type ApproveCredentialRequestBody struct {
	// Fingerprint is the public-key fingerprint the approver saw on screen, full or
	// short form. It must match the request's stored fingerprint or the call is
	// rejected with conflict — this closes the window where a second lodge re-sorts
	// the queue between rendering and clicking.
	Fingerprint string `json:"fingerprint"`

	AccountID          string `json:"account_id,omitempty"`
	NewAccountUsername string `json:"new_account_username,omitempty"`
	NewAccountTenantID string `json:"new_account_tenant_id,omitempty"`

	GrantAdminMarker          bool `json:"grant_admin_marker,omitempty"`
	GrantPayloadSigningMarker bool `json:"grant_payload_signing_marker,omitempty"`
	GrantRootScopeMarker      bool `json:"grant_root_scope_marker,omitempty"`
}

// ApproveCredentialRequestResponse is returned on a successful approval.
type ApproveCredentialRequestResponse struct {
	ID             string   `json:"id"`
	Status         string   `json:"status"`
	AccountID      string   `json:"account_id"`
	GrantedMarkers []string `json:"granted_markers"`
	SelfApproved   bool     `json:"self_approved"`
}

// ---- marker authority ---------------------------------------------------------------

// principalMayAdministerController reports whether principal is entitled to grant
// AdminMarkerOID to a new credential. ImplicitAdmin identifies exactly the three
// platform-administrator principal types — mTLS admin cert, a CLI Bearer session with
// no bound account or a root-scope account, and a root-scope web account (see
// hasPermission's doc comment) — which is precisely what AdminMarkerOID means ("may
// administer the controller", Epic #3711 D3). A tenant-scoped account, however many
// individual permissions it holds, administers only its own tenant subtree and must
// not be able to mint another admin-marked credential.
func principalMayAdministerController(p *Principal) bool {
	return p != nil && p.ImplicitAdmin
}

// principalMayGrantPayloadSigningMarker reports whether principal is entitled to grant
// PayloadSigningMarkerOID. Mirrors the gate handleRequestSigningCredential (#3693)
// enforces on itself: hold signing-credential:request at AssuranceStrong. hasPermission
// already grants this to every ImplicitAdmin principal — unlike the root-scope gate
// below, that is intentional here: an administrator entitled to request their own
// payload-signing credential is equally entitled to grant one to someone else.
func (s *Server) principalMayGrantPayloadSigningMarker(p *Principal) bool {
	return p != nil && p.Assurance >= session.AssuranceStrong && s.hasPermission(p, "signing-credential:request")
}

// principalHasCertifiedRootScope reports whether principal is entitled to grant
// RootScopeMarkerOID. This is the one gate in this file that is deliberately NOT a
// permission-string check and NOT principal.RootScoped alone:
//
//   - A permission check is wrong: hasPermission short-circuits to true for any
//     ImplicitAdmin principal (middleware.go), and an ordinary admin-marked mTLS
//     certificate with no root-scope marker of its own is ImplicitAdmin: true. The
//     check would silently pass for every platform administrator, not just root-scoped
//     ones.
//   - principal.RootScoped alone is wrong: it is always false for a browser caller
//     today, so the check would look correct and be unexercised — and it would
//     silently reopen the day a passkey session is amended to carry it.
//   - Reading r.TLS.PeerCertificates[0] directly instead of the derived principal is a
//     revocation bypass: the server accepts a client certificate the TLS handshake did
//     not require (tls.VerifyClientCertIfGiven, no VerifyPeerCertificate callback), and
//     revocation is checked in exactly one place — extractAdminPrincipal — which
//     returns nil (not an error) for a revoked certificate and falls through to the
//     session/cookie branches rather than rejecting the request outright.
//
// CertSerial is set in exactly two places, both inside extractAdminPrincipal
// (middleware.go), both after its revocation check and only when the certificate
// itself authenticated the request — see TestCertSerial_OnlySetByExtractAdminPrincipal.
// That is why the derived principal is the correct source and the raw certificate is
// not: a principal reaching this predicate with CertSerial set has already survived
// that revocation check; one that has not (session, cookie, or a revoked certificate
// that fell through to one of those) never has CertSerial set at all.
func principalHasCertifiedRootScope(p *Principal) bool {
	return p != nil && p.RootScoped && p.CertSerial != ""
}

// resolveGrantedMarkers validates each requested marker against the approver's own
// authority and returns the granted set. A marker the approver cannot grant refuses the
// whole call rather than silently dropping it (Issue #3718 AC) — deniedMarker names the
// first one that failed.
func (s *Server) resolveGrantedMarkers(principal *Principal, body ApproveCredentialRequestBody) (granted []string, deniedMarker string) {
	if body.GrantAdminMarker {
		if !principalMayAdministerController(principal) {
			return nil, credentialMarkerAdmin
		}
		granted = append(granted, credentialMarkerAdmin)
	}
	if body.GrantPayloadSigningMarker {
		if !s.principalMayGrantPayloadSigningMarker(principal) {
			return nil, credentialMarkerPayloadSigning
		}
		granted = append(granted, credentialMarkerPayloadSigning)
	}
	if body.GrantRootScopeMarker {
		if !principalHasCertifiedRootScope(principal) {
			return nil, credentialMarkerRootScope
		}
		granted = append(granted, credentialMarkerRootScope)
	}
	return granted, ""
}

// ---- fingerprint confirmation ---------------------------------------------------------

// fingerprintsMatch reports whether supplied — the fingerprint the approver saw on
// screen, in either full (64 hex chars) or short grouped form — matches storedFull, the
// pending request's full fingerprint recorded at lodge time. Accepting either form lets
// the approval body carry whatever format the UI rendered.
func fingerprintsMatch(supplied, storedFull string) bool {
	if supplied == "" || storedFull == "" {
		return false
	}
	normalize := func(v string) string {
		return strings.ToUpper(strings.ReplaceAll(v, "-", ""))
	}
	normSupplied := normalize(supplied)
	if normSupplied == normalize(storedFull) {
		return true
	}
	shortStored := normalize(shortFingerprintFromFull(storedFull))
	return normSupplied == shortStored
}

// ---- handler --------------------------------------------------------------------------

// handleApproveCredentialRequest handles POST /api/v1/credential-requests/{id}/approve.
// Validates the approver's authority for each requested marker, resolves the account
// the eventual credential will bind to, and records the decision on the pending
// request — it signs nothing (see package doc comment).
func (s *Server) handleApproveCredentialRequest(w http.ResponseWriter, r *http.Request) {
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Secret store not available", "SERVICE_UNAVAILABLE")
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "id is required", "MISSING_ID")
		return
	}

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	reqRecord, err := s.getPendingCredentialRequestByID(r.Context(), id)
	if err != nil {
		s.logger.Error("Failed to look up credential request", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up credential request", "STORE_ERROR")
		return
	}
	if reqRecord == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Credential request not found", "REQUEST_NOT_FOUND")
		return
	}
	callerTenant := s.callerTenantID(r)
	if !isWithinTenantScope(callerTenant, reqRecord.TenantID) {
		s.writeErrorResponse(w, http.StatusNotFound, "Credential request not found", "REQUEST_NOT_FOUND")
		return
	}
	if reqRecord.Status != credentialRequestStatusPending {
		s.writeErrorResponse(w, http.StatusConflict, "Credential request is not pending", "REQUEST_NOT_PENDING")
		return
	}

	var body ApproveCredentialRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}
	if body.Fingerprint == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "fingerprint is required", "MISSING_FINGERPRINT")
		return
	}
	if !fingerprintsMatch(body.Fingerprint, reqRecord.PublicKeyFingerprint) {
		s.writeErrorResponse(w, http.StatusConflict,
			"Supplied fingerprint does not match the pending request", "FINGERPRINT_MISMATCH")
		return
	}

	granted, deniedMarker := s.resolveGrantedMarkers(principal, body)
	if deniedMarker != "" {
		s.writeErrorResponse(w, http.StatusForbidden,
			"Approver is not entitled to grant the "+deniedMarker+" marker", "MARKER_NOT_GRANTABLE")
		return
	}

	hasExisting := body.AccountID != ""
	hasNew := body.NewAccountUsername != ""
	if hasExisting == hasNew {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"exactly one of account_id or new_account_username is required", "INVALID_ACCOUNT_SELECTION")
		return
	}

	var boundAccountID string
	if hasExisting {
		acct, err := s.getAccountByID(r.Context(), body.AccountID)
		if err != nil {
			s.logger.Error("Failed to look up account for approval", "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up account", "STORE_ERROR")
			return
		}
		if acct == nil || !isWithinTenantScope(callerTenant, acct.TenantID) {
			s.writeErrorResponse(w, http.StatusNotFound, "Account not found", "ACCOUNT_NOT_FOUND")
			return
		}
		if acct.Disabled {
			s.writeErrorResponse(w, http.StatusConflict, "Account is disabled", "ACCOUNT_DISABLED")
			return
		}
		boundAccountID = acct.ID
	} else {
		if err := validateUsername(body.NewAccountUsername); err != nil {
			s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_USERNAME")
			return
		}
		targetTenant := body.NewAccountTenantID
		if targetTenant == "" {
			targetTenant = reqRecord.TenantID
		}
		if !isWithinTenantScope(callerTenant, targetTenant) {
			s.writeErrorResponse(w, http.StatusForbidden, "Target tenant is outside caller's tenant subtree", "FORBIDDEN")
			return
		}
		existing, err := s.getAccount(r.Context(), body.NewAccountUsername)
		if err != nil {
			s.logger.Error("Failed to look up account for approval", "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up account", "STORE_ERROR")
			return
		}
		if existing != nil {
			s.writeErrorResponse(w, http.StatusConflict, "Account already exists", "ACCOUNT_EXISTS")
			return
		}
		newAcct := &account{
			ID:          uuid.New().String(),
			Username:    body.NewAccountUsername,
			TenantID:    targetTenant,
			Permissions: []string{},
			CreatedAt:   time.Now().UTC(),
		}
		if err := s.persistAccount(r.Context(), newAcct, principal.ID); err != nil {
			s.logger.Error("Failed to persist headless-host account", "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create account", "STORE_ERROR")
			return
		}
		s.cacheAccount(newAcct)
		boundAccountID = newAcct.ID
	}

	// Self-approval is explicitly permitted: because a marker set can only be weaker
	// than or equal to the approver's own (resolveGrantedMarkers above), approving a
	// request bound to one's own account grants nothing new. Recorded on the audit
	// event so it is visible, not something a reviewer has to infer.
	selfApproved := boundAccountID == principal.ID

	now := time.Now().UTC()
	reqRecord.Status = credentialRequestStatusApproved
	reqRecord.ApprovedAt = &now
	reqRecord.ApprovedBy = principal.ID
	reqRecord.BoundAccountID = boundAccountID
	reqRecord.GrantedMarkers = granted
	reqRecord.SelfApproved = selfApproved

	// The pending->approved transition is a durable compare-and-set keyed on the
	// version read alongside reqRecord at the top of this handler (Issue #3775): this
	// call site previously had no protection of any kind, on any node count, so two
	// concurrent approvals of the same pending request could both pass the pending
	// check above and both write, binding two different accounts or granting two
	// different marker sets to one CSR with the second write silently winning. A lost
	// race now surfaces as 409 Conflict rather than a silent second write.
	if _, ok, err := s.persistPendingCredentialRequestCAS(r.Context(), reqRecord); err != nil {
		s.logger.Error("Failed to persist credential request approval", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to approve credential request", "STORE_ERROR")
		return
	} else if !ok {
		s.writeErrorResponse(w, http.StatusConflict,
			"Credential request was concurrently modified; it is no longer pending", "REQUEST_NOT_PENDING")
		return
	}

	s.logger.Info("Credential request approved",
		"request_id", logging.SanitizeLogValue(reqRecord.ID),
		"account_id", logging.SanitizeLogValue(boundAccountID),
		"self_approved", selfApproved)
	s.emitCredentialRequestAudit(r.Context(), "credential_request.approved", reqRecord.TenantID, principal.ID,
		business.AuditUserTypeHuman, "credential_request", reqRecord.ID,
		business.AuditResultSuccess, business.AuditSeverityHigh,
		map[string]interface{}{
			"bound_account_id": boundAccountID,
			"granted_markers":  granted,
			"self_approved":    selfApproved,
		})

	s.writeResponse(w, http.StatusOK, ApproveCredentialRequestResponse{
		ID:             reqRecord.ID,
		Status:         reqRecord.Status,
		AccountID:      boundAccountID,
		GrantedMarkers: granted,
		SelfApproved:   selfApproved,
	})
}
