// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3724 (Epic #3711): unattended renewal for enrolment-issued credentials.
//
// A credential issued through enrolment (#3717/#3718/#3719) renews itself before it
// expires with no human present. The renewing host generates a fresh keypair,
// presents its expiring certificate over mutual TLS to prove identity, and submits
// only the new public half as a certificate signing request — mirroring the
// zero-custody shape of collect (#3719): the controller never sees, generates, or
// holds a private key.
//
// Authorization is the presented certificate itself, resolved by the same
// extractAdminPrincipal path (middleware.go) every other mTLS-authenticated admin
// request uses. That gives renewal, for free, the two things bounding it:
//   - certManager.IsRevoked is checked before a Principal is ever constructed, so a
//     revoked certificate never reaches this handler.
//   - a certificate bound to a disabled account resolves to no Principal at all — the
//     epic's off switch is the bound account, not a separate renewal credential.
//
// What extractAdminPrincipal does NOT bound, this handler checks explicitly:
//   - the renewal window and certificate expiry (extractAdminPrincipal has no notion
//     of NotAfter — a unit test can hand it an already-expired certificate and it
//     resolves the principal anyway);
//   - the bootstrap-fallback case (an admin-marked certificate with no account
//     binding) — refused outright, because that principal has no account to renew
//     against, never treated as "renew into the fallback";
//   - that the request cannot select, name, or widen anything: the request body
//     carries only a CSR (DisallowUnknownFields rejects any attempt to name an
//     account), and the marker set is copied verbatim from the presented
//     certificate via credentialMarkerModifier — the same allow-listed call site
//     handlers_credential_requests_collect.go (#3719) uses, never a new one (see
//     pkg/cert/architecture_test.go's restricted-caller rules for SetAdminMarker /
//     SetPayloadSigningMarker / SetRootScopeMarker).
//
// Issue-and-rebind follows approval's atomicity shape (#3718 amendment) rather than
// extending handleRotateCert (out of scope by story instruction): sign, then bind the
// new serial, then revoke and unbind the old one. A failure before the new serial is
// bound leaves the old certificate as the host's only, still-valid credential. A
// failure after — old-serial revoke or unbind — leaves both certificates live rather
// than either failing the response or losing the new one; that window is logged, not
// silently dropped, and is the same "two live certificates" shape handleRotateCert's
// own doc comment describes for its analogous partial-failure window.
package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// credentialRenewalWindow bounds how long before expiry a certificate may be
// renewed. Renewal outside this window is refused (Issue #3724 AC) — a certificate
// with most of its life left has no reason to renew, and refusing early renewal
// keeps a compromised-but-not-yet-detected credential from indefinitely extending
// its own life by renewing far ahead of schedule.
const credentialRenewalWindow = 30 * 24 * time.Hour

// errCredentialRenewalNoAccountBinding is returned when the presented certificate's
// serial resolves to no bound account — the bootstrap-fallback case. Refused outright
// (Issue #3724 AC): that principal has no account to renew against.
var errCredentialRenewalNoAccountBinding = errors.New("no account is bound to the presented certificate")

// errCredentialRenewalInProgress is returned when a concurrent renewal of the same
// certificate has already claimed it (Issue #3775). Surfaced as 409 Conflict — the
// caller may safely retry once the earlier renewal (or its claim's short TTL) resolves.
var errCredentialRenewalInProgress = errors.New("a renewal of this certificate is already in progress")

// credentialRenewalClaimTTL bounds how long a renewal claim blocks a second attempt
// at the same certificate. Short: a legitimate renewal completes in one round trip
// (sign, bind, revoke, unbind), so this only needs to outlive that — not the
// certificate's own renewal window — and a short TTL bounds how long a crashed
// renewal attempt can block a legitimate retry.
//
// The TTL is load-bearing, not decorative. SecretStore.CompareAndSwapSecret treats
// a record past its expiry as absent, so the create-if-absent claim below takes
// over an abandoned claim once this elapses (Issue #3775). Without that rule, a
// controller that died between claim and release would leave a version-1 record no
// read path can see and no sweeper removes, and every future renewal of that serial
// would answer 409 forever — a permanent lockout for a host whose only credential is
// the certificate it can no longer renew. Shortening or lengthening this changes how
// long that recovery takes; removing the expiry-as-absent rule removes recovery
// altogether.
const credentialRenewalClaimTTL = 2 * time.Minute

// credentialRenewalClaimKey namespaces the durable claim record renewBoundCertificate
// creates to atomically claim exclusive renewal rights over oldSerial, distinct from
// any account or credential-request record.
func credentialRenewalClaimKey(oldSerial string) string {
	return "credential-renewal-claim-" + oldSerial
}

// claimCertificateRenewal atomically claims exclusive renewal rights over oldSerial
// via a create-if-absent compare-and-set (expectedVersion 0): the durable record this
// creates cannot be created twice, so of any number of concurrent renewal attempts for
// the same certificate — on this node or a different one — at most one ever proceeds
// to sign a new certificate (Issue #3775).
//
// expectedVersion is always 0, including when an abandoned claim record is still
// present: the store treats a record past credentialRenewalClaimTTL as absent, and
// the takeover it then performs is itself a compare-and-set against that record's
// actual version. So a crashed renewal delays the next attempt by at most the TTL
// and still cannot let two attempts claim the same certificate at once.
func (s *Server) claimCertificateRenewal(ctx context.Context, tenantID, oldSerial, actingPrincipalID string) (bool, error) {
	key := credentialRenewalClaimKey(oldSerial)
	_, ok, err := s.secretStore.CompareAndSwapSecret(ctx, tenantID+"/"+key, 0, &secretsif.SecretRequest{
		Key:         key,
		Value:       "",
		TenantID:    tenantID,
		CreatedBy:   actingPrincipalID,
		Description: "credential renewal claim",
		Tags:        []string{"credential_renewal_claim"},
		TTL:         credentialRenewalClaimTTL,
	})
	if err != nil {
		return false, err
	}
	return ok, nil
}

// releaseCertificateRenewalClaim deletes the claim record claimCertificateRenewal
// created, so a subsequent renewal attempt for the same certificate — whether this
// one succeeded or failed — is not blocked until credentialRenewalClaimTTL expires.
// Mirrors a mutex's unconditional unlock-on-return: the claim exists only to
// serialize callers racing *inside* one renewal attempt, not to rate-limit
// sequential attempts. Logged, not propagated — a failed delete costs the next
// renewal of this serial a wait of at most credentialRenewalClaimTTL, after which
// claimCertificateRenewal takes the expired record over, so it degrades the
// experience without stranding the credential.
func (s *Server) releaseCertificateRenewalClaim(ctx context.Context, tenantID, oldSerial string) {
	key := credentialRenewalClaimKey(oldSerial)
	if err := s.secretStore.DeleteSecret(ctx, tenantID+"/"+key); err != nil {
		s.logger.Warn("Failed to release credential renewal claim; the next renewal of this serial takes it over once it expires",
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// RenewCredentialRequest is the POST /api/v1/credential-renewal body. CSRPEM is the
// only field: the account being renewed into is derived exclusively from the
// certificate presented over mutual TLS, never from the request (Issue #3724). The
// handler decodes this with json.Decoder.DisallowUnknownFields, so any attempt to
// smuggle an account selector under an unrecognised key is refused at decode time
// rather than silently ignored.
type RenewCredentialRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// RenewCredentialResponse is returned on a successful renewal.
type RenewCredentialResponse struct {
	CertificatePEM   string   `json:"certificate_pem"`
	CACertificatePEM string   `json:"ca_certificate_pem"`
	SerialNumber     string   `json:"serial_number"`
	AccountID        string   `json:"account_id"`
	GrantedMarkers   []string `json:"granted_markers"`
	ExpiresAt        string   `json:"expires_at"`
}

// markersFromCertificate derives the marker set to carry into a renewed certificate
// directly from peerCert — never from the request, and never widened (Issue #3724).
// Uses the same three marker predicates the collect and approve handlers use
// (#3718/#3719): HasAdminMarker, HasPayloadSigningMarker, HasRootScopeMarker.
func markersFromCertificate(peerCert *x509.Certificate) []string {
	var markers []string
	if cert.HasAdminMarker(peerCert) {
		markers = append(markers, credentialMarkerAdmin)
	}
	if cert.HasPayloadSigningMarker(peerCert) {
		markers = append(markers, credentialMarkerPayloadSigning)
	}
	if cert.HasRootScopeMarker(peerCert) {
		markers = append(markers, credentialMarkerRootScope)
	}
	return markers
}

// renewBoundCertificate performs the issue-and-rebind sequence. It first claims
// exclusive renewal rights over oldSerial via claimCertificateRenewal — a durable
// compare-and-set create-if-absent record — before signing anything, so two
// concurrent renewals of the same certificate, on this node or a different one,
// cannot both succeed and leave two unrelated new certificates bound (Issue #3775).
//
// Re-resolves the account and the old binding fresh, before claiming, rather than
// trusting the caller's earlier lookup — the same freshness discipline
// claimCredentialRequestForCollection (#3719) uses for its compare-and-set.
//
// Returns oldSerialCleanedUp=false (with err=nil) when the new certificate is
// issued and bound successfully but revoking or unbinding the old serial afterward
// fails — the host has a working credential either way (Issue #3724 AC), so this is
// reported as a successful renewal with the cleanup gap logged, not a failure.
func (s *Server) renewBoundCertificate(
	ctx context.Context,
	oldSerial string,
	csr *x509.CertificateRequest,
	newKeyFingerprint string,
	markers []string,
	actingPrincipalID string,
) (issued *cert.Certificate, acct *account, oldSerialCleanedUp bool, err error) {
	fresh, err := s.getAccountByCertSerial(ctx, oldSerial)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to look up account bound to presented certificate: %w", err)
	}
	if fresh == nil {
		return nil, nil, false, errCredentialRenewalNoAccountBinding
	}
	var oldBinding *CertBinding
	for i := range fresh.CertBindings {
		if fresh.CertBindings[i].Serial == oldSerial {
			oldBinding = &fresh.CertBindings[i]
			break
		}
	}
	if oldBinding == nil {
		// The account lookup found the serial a moment ago (getAccountByCertSerial
		// scans CertBindings itself), but a concurrent revoke could have removed the
		// binding between that lookup and the claim below. Same refusal as no account
		// at all: there is nothing left to renew.
		return nil, nil, false, errCredentialRenewalNoAccountBinding
	}

	claimTenant := accountStorageTenant(fresh.TenantID)
	claimed, err := s.claimCertificateRenewal(ctx, claimTenant, oldSerial, actingPrincipalID)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to claim certificate renewal: %w", err)
	}
	if !claimed {
		return nil, nil, false, errCredentialRenewalInProgress
	}
	defer s.releaseCertificateRenewalClaim(ctx, claimTenant, oldSerial)

	newCert, err := s.certManager.SignClientCertificateRequest(csr.PublicKey, &cert.ClientCertConfig{
		CommonName:       fresh.Username,
		Organization:     "CFGMS",
		ClientID:         fresh.ID,
		ValidityDays:     credentialCollectValidityDays,
		TemplateModifier: credentialMarkerModifier(markers),
	})
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to sign renewed certificate: %w", err)
	}

	newBinding := CertBinding{
		Serial:      newCert.SerialNumber,
		Fingerprint: newKeyFingerprint,
		Label:       oldBinding.Label,
		BoundAt:     time.Now().UTC(),
		// Carried forward unchanged from the binding being replaced — never reset to
		// "now" by a renewal (Issue #3724 AC).
		HumanApprovedAt: oldBinding.HumanApprovedAt,
	}

	if err := s.bindCertOnAccount(ctx, fresh.Username, newBinding, actingPrincipalID); err != nil {
		// The old certificate is still bound and valid — the host has not lost
		// authentication. Revoke the orphaned new certificate rather than leaving it
		// live with no binding (mirrors signAndBindCollectedCertificate, #3719).
		if revokeErr := s.certManager.Revoke(newCert.SerialNumber); revokeErr != nil {
			s.logger.Error("Failed to revoke renewed certificate after bind failure",
				"error", logging.SanitizeLogValue(revokeErr.Error()))
		}
		return nil, nil, false, fmt.Errorf("failed to bind renewed certificate: %w", err)
	}

	// The new certificate is now live and bound: the host has a working credential
	// regardless of what happens below. Revoke and unbind the old one.
	if revokeErr := s.certManager.Revoke(oldSerial); revokeErr != nil {
		s.logger.Error("Renewed certificate issued and bound, but revoking the old certificate failed; "+
			"two certificates are live for this account until this is retried",
			"old_serial", logging.SanitizeLogValue(oldSerial),
			"new_serial", newCert.SerialNumber,
			"error", logging.SanitizeLogValue(revokeErr.Error()))
		return newCert, fresh, false, nil
	}
	if removeErr := s.removeCertBindingFromAccount(ctx, fresh.Username, oldSerial, actingPrincipalID); removeErr != nil {
		s.logger.Error("Renewed certificate issued and bound and the old certificate was revoked, but removing "+
			"its binding failed; the old binding will appear active for a certificate that is no longer valid",
			"old_serial", logging.SanitizeLogValue(oldSerial),
			"new_serial", newCert.SerialNumber,
			"error", logging.SanitizeLogValue(removeErr.Error()))
		return newCert, fresh, false, nil
	}

	return newCert, fresh, true, nil
}

// handleRenewCredential handles POST /api/v1/credential-renewal. Registered on the
// authenticated api subrouter (routes_credential_renewal.go): authenticationMiddleware
// has already run, so a Principal in context means the caller authenticated somehow —
// this handler additionally requires that "somehow" to have been the certificate
// being renewed, never an API key or session.
func (s *Server) handleRenewCredential(w http.ResponseWriter, r *http.Request) {
	if checker := s.registrationLeaderStatus; checker != nil && !checker.HasLeadership() {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.certManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Certificate manager not available", "SERVICE_UNAVAILABLE")
		return
	}

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil || principal.CertSerial == "" {
		// Renewal is authorised exclusively by presenting the expiring certificate
		// itself over mutual TLS (Issue #3724) — no API key or session credential can
		// stand in for it. principal.CertSerial is set only by extractAdminPrincipal
		// (middleware.go), never by the API-key or session branches.
		s.writeErrorResponse(w, http.StatusUnauthorized,
			"Renewal requires authentication via the certificate being renewed", "CERTIFICATE_AUTH_REQUIRED")
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.writeErrorResponse(w, http.StatusUnauthorized,
			"Renewal requires authentication via the certificate being renewed", "CERTIFICATE_AUTH_REQUIRED")
		return
	}
	presentedCert := r.TLS.PeerCertificates[0]

	now := time.Now().UTC()
	if !now.Before(presentedCert.NotAfter) {
		s.writeErrorResponse(w, http.StatusForbidden, "Certificate has already expired", "CERTIFICATE_EXPIRED")
		return
	}
	if now.Add(credentialRenewalWindow).Before(presentedCert.NotAfter) {
		s.writeErrorResponse(w, http.StatusForbidden,
			"Renewal window has not yet opened for this certificate", "OUTSIDE_RENEWAL_WINDOW")
		return
	}

	// The bound account is derived exclusively from the presented certificate's
	// serial. No account is ever selectable or nameable in the request (enforced
	// below by DisallowUnknownFields); this early check also refuses the
	// bootstrap-fallback case — a certificate with no account binding — before any
	// CSR parsing happens.
	acct, err := s.getAccountByCertSerial(r.Context(), principal.CertSerial)
	if err != nil {
		s.logger.Error("Failed to look up account bound to presented certificate",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusForbidden,
			"No account is bound to the presented certificate; renewal is not permitted", "NO_ACCOUNT_BINDING")
		return
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var body RenewCredentialRequest
	if err := dec.Decode(&body); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Invalid JSON body: only csr_pem is accepted; the bound account cannot be named or changed", "INVALID_JSON")
		return
	}
	if body.CSRPEM == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "csr_pem is required", "MISSING_CSR")
		return
	}
	if containsPrivateKeyMaterial(body.CSRPEM) {
		s.writeErrorResponse(w, http.StatusBadRequest, "private key material is not accepted", "PRIVATE_KEY_REJECTED")
		return
	}
	csr, err := parseAndVerifyCSR(body.CSRPEM)
	if err != nil {
		s.logger.Warn("Rejected invalid certificate signing request at renewal",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid certificate signing request", "INVALID_CSR")
		return
	}

	// A fresh keypair is required on every renewal (Issue #3724): reusing the
	// expiring certificate's own public key is refused.
	newKeyFP, _ := publicKeyFingerprint(csr.RawSubjectPublicKeyInfo)
	oldKeyFP, _ := publicKeyFingerprint(presentedCert.RawSubjectPublicKeyInfo)
	if newKeyFP == oldKeyFP {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"certificate signing request must present a newly generated public key", "KEY_REUSE_REJECTED")
		return
	}

	// The marker set is copied verbatim from the presented certificate — never from
	// the request, and never widened.
	markers := markersFromCertificate(presentedCert)

	issued, boundAcct, oldSerialCleanedUp, err := s.renewBoundCertificate(
		r.Context(), principal.CertSerial, csr, newKeyFP, markers, principal.ID)
	if err != nil {
		s.logger.Error("Failed to renew certificate", "error", logging.SanitizeLogValue(err.Error()))
		if errors.Is(err, errCredentialRenewalNoAccountBinding) {
			s.writeErrorResponse(w, http.StatusForbidden,
				"No account is bound to the presented certificate; renewal is not permitted", "NO_ACCOUNT_BINDING")
			return
		}
		if errors.Is(err, errCredentialRenewalInProgress) {
			s.writeErrorResponse(w, http.StatusConflict,
				"A renewal of this certificate is already in progress", "RENEWAL_IN_PROGRESS")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to renew certificate", "RENEWAL_FAILED")
		return
	}

	caPEM, err := s.certManager.GetCACertificate()
	if err != nil {
		s.logger.Error("Failed to load CA certificate for renewal response",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to renew certificate", "INTERNAL_ERROR")
		return
	}

	s.logger.Info("Credential renewed",
		"account_id", logging.SanitizeLogValue(boundAcct.ID),
		"old_serial", logging.SanitizeLogValue(principal.CertSerial),
		"new_serial", issued.SerialNumber,
		"old_serial_cleaned_up", oldSerialCleanedUp)
	s.emitAccountAudit(r.Context(), "account.cert_binding.renewed", boundAcct.TenantID, principal.ID, boundAcct.Username,
		map[string]interface{}{
			"old_serial":            principal.CertSerial,
			"new_serial":            issued.SerialNumber,
			"granted_markers":       markers,
			"old_serial_cleaned_up": oldSerialCleanedUp,
		})

	s.writeResponse(w, http.StatusOK, RenewCredentialResponse{
		CertificatePEM:   string(issued.CertificatePEM),
		CACertificatePEM: string(caPEM),
		SerialNumber:     issued.SerialNumber,
		AccountID:        boundAcct.ID,
		GrantedMarkers:   markers,
		ExpiresAt:        issued.ExpiresAt.UTC().Format(time.RFC3339),
	})
}
