// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3719 (Epic #3711): the single-use, secret-authenticated collect endpoint that
// closes the enrolment loop.
//
// Amendment (see the issue): approval (#3718) signs nothing — it only records the
// decision (marker set, bound account, approver identity). This handler is where the
// certificate is actually minted: it signs the lodged CSR's public key with exactly the
// marker set and account recorded at approval, and binds the result to that account in
// the same operation. An approved request that is never collected therefore leaves no
// certificate in existence. This mirrors handleApproveRegistration /
// handleRegistrationStatus's generate-on-claim shape (see that handler's own doc
// comment): approval decides, collect (claim) mints.
//
// Authentication is the collect secret alone, presented as a bearer credential exactly
// once by the machine that lodged the request — never the request ID or the public-key
// fingerprint, both of which an observer of the approval screen has already seen. A
// wrong or absent secret is rejected identically to an unknown ID: this endpoint never
// confirms a request ID exists to a caller who cannot prove they hold its secret.
//
// The state transition (approved -> collected) is a durable compare-and-set that
// commits BEFORE the certificate is signed. A process restart between that commit and
// the response — or a concurrent second caller — always finds the request already
// "collected" and receives 410 Gone; there is never a second certificate for one
// request. The account binding is written before the certificate is returned to the
// caller; any failure after signing revokes the just-issued certificate immediately, so
// a signed certificate is never observable without an account it resolves through — an
// admin-marked certificate with no binding would otherwise fall through
// extractAdminPrincipal's bootstrap fallback and be granted implicit root
// (middleware.go, ADR-025 Amendment 3).
package api

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// credentialCollectValidityDays is the validity period for a certificate minted by
// collect. This credential is unrelated to steward mTLS transport auth, so it carries
// its own constant rather than sharing one across packages (mirrors
// signingCredentialValidityDays in handlers_signing_credential.go).
const credentialCollectValidityDays = 365

// credentialRequestCollectActor identifies the collect endpoint as the acting audit /
// binding principal — there is no authenticated principal on this call, only the
// collect secret (mirrors credentialRequestSweepActor's role for the background sweep).
const credentialRequestCollectActor = "credential-request-collect"

// errCredentialRequestAlreadyCollected signals a lost compare-and-set: another caller,
// or this same request replayed after a restart, already transitioned this request to
// "collected". Surfaced as 410 Gone.
var errCredentialRequestAlreadyCollected = errors.New("credential request already collected")

// CollectCredentialRequestResponse is returned on a successful collection.
type CollectCredentialRequestResponse struct {
	CertificatePEM   string   `json:"certificate_pem"`
	CACertificatePEM string   `json:"ca_certificate_pem"`
	SerialNumber     string   `json:"serial_number"`
	AccountID        string   `json:"account_id"`
	GrantedMarkers   []string `json:"granted_markers"`
	ExpiresAt        string   `json:"expires_at"`
}

// credentialRequestCollectStatusResponse is returned once the caller has proven
// possession of the collect secret but the request is not, or no longer, collectible.
type credentialRequestCollectStatusResponse struct {
	Status string `json:"status"`
}

// collectSecretMatches reports whether raw, hashed, matches storedHash in constant
// time. Comparing SHA-256 hex digests (never the raw secrets) mirrors
// verifyEnrollmentToken (handlers_accounts.go) — the codebase's established
// constant-time-compare shape for a secret whose only durable form is its hash.
func collectSecretMatches(raw, storedHash string) bool {
	if raw == "" || storedHash == "" {
		return false
	}
	presented := hashCredentialSecret(raw)
	return subtle.ConstantTimeCompare([]byte(presented), []byte(storedHash)) == 1
}

// credentialMarkerModifier returns a cert.ClientCertConfig.TemplateModifier that stamps
// exactly markers, verbatim, in whatever combination was recorded at approval (Issue
// #3718). It reads nothing else — no account field, no caller input — that could ever
// widen this set.
func credentialMarkerModifier(markers []string) func(*x509.Certificate) {
	return func(template *x509.Certificate) {
		for _, m := range markers {
			switch m {
			case credentialMarkerAdmin:
				cert.SetAdminMarker(template)
			case credentialMarkerPayloadSigning:
				cert.SetPayloadSigningMarker(template)
			case credentialMarkerRootScope:
				cert.SetRootScopeMarker(template)
			}
		}
	}
}

// claimCredentialRequestForCollection performs the approved->collected compare-and-set:
// re-fetch the record, verify it is still "approved", and persist the transition via
// CompareAndSwapSecret keyed on the version just read — mirroring the enrolment-token
// spend section of handleLodgeCredentialRequest. The transition is durable and
// committed before any certificate is signed, so a process restart, or a second
// caller anywhere in the cluster, between this commit and the eventual response
// always observes "collected" and never causes a second certificate to be minted
// (Issue #3775).
//
// The "anywhere in the cluster" half of that rests on the secret store's swap being
// atomic across nodes, which is not true of every backend and is therefore not
// assumed: NewSecretStore refuses to start a cluster-mode controller on a store that
// does not provide it (secretsif.CompareAndSwapIsClusterAtomic). Read this comment as
// a consequence of that gate, not as an independent promise.
func (s *Server) claimCredentialRequestForCollection(ctx context.Context, id string) (*pendingCredentialRequest, error) {
	fresh, err := s.getPendingCredentialRequestByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if fresh == nil || fresh.Status != credentialRequestStatusApproved {
		return nil, errCredentialRequestAlreadyCollected
	}
	now := time.Now().UTC()
	fresh.Status = credentialRequestStatusCollected
	fresh.CollectedAt = &now
	newVersion, ok, err := s.persistPendingCredentialRequestCAS(ctx, fresh)
	if err != nil {
		return nil, err
	}
	if !ok {
		// Lost the race: a concurrent collect (or containment action) already
		// transitioned this request away from "approved".
		return nil, errCredentialRequestAlreadyCollected
	}
	fresh.Version = newVersion
	return fresh, nil
}

// signAndBindCollectedCertificate signs claimed's lodged CSR with exactly its recorded
// marker set and binds the result to its recorded account, in that order (Issue #3719
// amendment). Any failure after signing revokes the just-issued certificate before
// returning: a signed certificate must never be observable with no account binding,
// because extractAdminPrincipal's bootstrap fallback (middleware.go, ADR-025 Amendment
// 3) would otherwise resolve it as implicit root.
func (s *Server) signAndBindCollectedCertificate(ctx context.Context, claimed *pendingCredentialRequest) (*cert.Certificate, *account, error) {
	csr, err := parseAndVerifyCSR(claimed.CSRPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse lodged certificate signing request: %w", err)
	}

	acct, err := s.getAccountByID(ctx, claimed.BoundAccountID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to look up bound account: %w", err)
	}
	if acct == nil {
		return nil, nil, fmt.Errorf("bound account %s no longer exists", claimed.BoundAccountID)
	}

	issued, err := s.certManager.SignClientCertificateRequest(csr.PublicKey, &cert.ClientCertConfig{
		CommonName:       acct.Username,
		Organization:     "CFGMS",
		ClientID:         acct.ID,
		ValidityDays:     credentialCollectValidityDays,
		TemplateModifier: credentialMarkerModifier(claimed.GrantedMarkers),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign collected certificate: %w", err)
	}

	// Durably record the signed serial before attempting the bind, so a crash in the
	// window between them leaves evidence sweepOrphanedCollectedCertificates can find
	// and revoke, rather than an untracked live credential.
	claimed.CollectedSerial = issued.SerialNumber
	if err := s.persistPendingCredentialRequest(ctx, claimed); err != nil {
		if revokeErr := s.certManager.Revoke(issued.SerialNumber); revokeErr != nil {
			s.logger.Error("Failed to revoke collected certificate after serial-persist failure",
				"error", logging.SanitizeLogValue(revokeErr.Error()))
		}
		return nil, nil, fmt.Errorf("failed to record collected certificate serial: %w", err)
	}

	newBinding := CertBinding{
		Serial:      issued.SerialNumber,
		Fingerprint: claimed.PublicKeyFingerprint,
		Label:       claimed.Label,
		BoundAt:     time.Now().UTC(),
		// HumanApprovedAt records the moment a human approved this credential
		// (Issue #3718's ApprovedAt) — the fixed point later renewals (Issue #3724)
		// carry forward unchanged, so an indefinitely-renewing credential never loses
		// the date a person last vouched for it.
		HumanApprovedAt: claimed.ApprovedAt,
	}
	if err := s.bindCertOnAccount(ctx, acct.Username, newBinding, credentialRequestCollectActor); err != nil {
		if revokeErr := s.certManager.Revoke(issued.SerialNumber); revokeErr != nil {
			s.logger.Error("Failed to revoke collected certificate after bind failure",
				"error", logging.SanitizeLogValue(revokeErr.Error()))
		}
		return nil, nil, fmt.Errorf("failed to bind collected certificate to account: %w", err)
	}

	return issued, acct, nil
}

// handleCollectCredentialRequest handles POST /api/v1/credential-requests/{id}/collect.
// Unauthenticated by API key or mTLS — gated entirely on the collect secret presented
// as a bearer credential (Issue #3719), mirroring handleLodgeCredentialRequest.
// Registered on the base router, not the authenticated api subrouter.
func (s *Server) handleCollectCredentialRequest(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "id is required", "MISSING_ID")
		return
	}
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Secret store not available", "SERVICE_UNAVAILABLE")
		return
	}

	rawSecret := ""
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		rawSecret = strings.TrimPrefix(authHeader, "Bearer ")
	}

	reqRecord, err := s.getPendingCredentialRequestByID(r.Context(), id)
	if err != nil {
		s.logger.Error("Failed to look up credential request for collect",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up credential request", "STORE_ERROR")
		return
	}
	// A wrong secret and an unknown ID are indistinguishable: this endpoint never
	// confirms a request ID exists to a caller who cannot prove they hold its secret
	// (Issue #3719 [REQUIRED TEST]).
	if reqRecord == nil || !collectSecretMatches(rawSecret, reqRecord.CollectSecretHash) {
		s.writeErrorResponse(w, http.StatusNotFound, "Credential request not found", "REQUEST_NOT_FOUND")
		return
	}

	if reqRecord.Status == credentialRequestStatusCollected {
		w.WriteHeader(http.StatusGone)
		return
	}
	if time.Now().UTC().After(reqRecord.ExpiresAt) {
		s.writeSuccessResponse(w, credentialRequestCollectStatusResponse{Status: "expired"})
		return
	}
	switch reqRecord.Status {
	case credentialRequestStatusPending:
		s.writeSuccessResponse(w, credentialRequestCollectStatusResponse{Status: "pending"})
		return
	case credentialRequestStatusDenied:
		s.writeSuccessResponse(w, credentialRequestCollectStatusResponse{Status: "denied"})
		return
	case credentialRequestStatusApproved:
		// Fall through to the minting branch below.
	default:
		s.writeSuccessResponse(w, credentialRequestCollectStatusResponse{Status: reqRecord.Status})
		return
	}

	if s.certManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Certificate manager not available", "SERVICE_UNAVAILABLE")
		return
	}

	claimed, err := s.claimCredentialRequestForCollection(r.Context(), id)
	if err != nil {
		if errors.Is(err, errCredentialRequestAlreadyCollected) {
			w.WriteHeader(http.StatusGone)
			return
		}
		s.logger.Error("Failed to claim credential request for collection",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to collect credential request", "STORE_ERROR")
		return
	}

	issued, acct, err := s.signAndBindCollectedCertificate(r.Context(), claimed)
	if err != nil {
		s.logger.Error("Failed to sign and bind collected certificate",
			"request_id", logging.SanitizeLogValue(claimed.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to collect credential request", "INTERNAL_ERROR")
		return
	}

	caPEM, err := s.certManager.GetCACertificate()
	if err != nil {
		s.logger.Error("Failed to load CA certificate for collect response",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to collect credential request", "INTERNAL_ERROR")
		return
	}

	s.logger.Info("Credential request collected",
		"request_id", logging.SanitizeLogValue(claimed.ID),
		"account_id", logging.SanitizeLogValue(acct.ID),
		"serial", issued.SerialNumber)
	s.emitCredentialRequestAudit(r.Context(), "credential_request.collected", claimed.TenantID, claimed.ID,
		business.AuditUserTypeSystem, "credential_request", claimed.ID,
		business.AuditResultSuccess, business.AuditSeverityHigh,
		map[string]interface{}{
			"account_id":      acct.ID,
			"granted_markers": claimed.GrantedMarkers,
			"serial":          issued.SerialNumber,
		})

	s.writeResponse(w, http.StatusOK, CollectCredentialRequestResponse{
		CertificatePEM:   string(issued.CertificatePEM),
		CACertificatePEM: string(caPEM),
		SerialNumber:     issued.SerialNumber,
		AccountID:        acct.ID,
		GrantedMarkers:   claimed.GrantedMarkers,
		ExpiresAt:        issued.ExpiresAt.UTC().Format(time.RFC3339),
	})
}
