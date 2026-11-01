// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/registration"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// refreshNonceEntry is the value stored in the durable NonceStore keyed by
// "refresh-nonce:<device_id>" (Issue #3755, ADR-031 amendment to ADR-011).
type refreshNonceEntry struct {
	NonceBytes []byte    `json:"nonce_bytes"`
	ServerTS   uint64    `json:"server_ts"` // Unix nanoseconds; encoded BE-uint64 in the PoP message
	IssuedAt   time.Time `json:"issued_at"` // wall-clock time for the 60s expiry check
}

// nonce store constants (ADR-010 §2).
const (
	refreshNonceKeyPrefix = "refresh-nonce:"
	nonceTTL              = 65 * time.Second // store TTL; IssuedAt check enforces 60s
	nonceMaxAge           = 60 * time.Second // enforced window for IssuedAt
)

// ---- Request / response types -----------------------------------------------

// RefreshChallengeRequest is the optional body for the challenge endpoint.
type RefreshChallengeRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
}

// RefreshChallengeResponse is returned by POST /api/v1/stewards/{device_id}/refresh/challenge.
type RefreshChallengeResponse struct {
	Nonce    string `json:"nonce"`     // base64url-encoded 32-byte random value
	ServerTS uint64 `json:"server_ts"` // Unix nanoseconds when the nonce was issued
}

// RefreshCompleteRequest is the body for the complete endpoint.
type RefreshCompleteRequest struct {
	TenantID  string `json:"tenant_id"`
	Nonce     string `json:"nonce"`     // base64url nonce from challenge response
	IssuedAt  int64  `json:"issued_at"` // server_ts from challenge (Unix nanoseconds)
	Signature string `json:"signature"` // base64url signature over PoP message (ed25519, or ASN.1 DER ecdsa-p256)
	// KeyAlgorithm is the device key algorithm the steward signed with: "ed25519"
	// or "ecdsa-p256"; absent means ed25519 (ADR-011 Amendment 3). It must equal
	// the stored algorithm for the device.
	KeyAlgorithm string            `json:"key_algorithm,omitempty"`
	Provenance   map[string]string `json:"provenance,omitempty"`

	// CSRPEM is a PEM-encoded CERTIFICATE REQUEST over a fresh keypair the steward
	// generates locally for the renewed credential (Issue #3781). The controller signs
	// this public key into the renewed mTLS client certificate; the matching private
	// key never crosses the wire.
	CSRPEM string `json:"csr_pem,omitempty"`
}

// RefreshCompleteResponse is returned by POST /api/v1/stewards/{device_id}/refresh/complete.
type RefreshCompleteResponse struct {
	Status    string `json:"status"`
	PendingID string `json:"pending_id,omitempty"` // set when queued for approval
	// Certificate fields: populated only on the auto-accept path
	ClientCert  string `json:"client_cert,omitempty"`
	CACert      string `json:"ca_cert,omitempty"`
	IssuerChain string `json:"issuer_chain,omitempty"` // Issue #3778: chain from ClientCert's direct issuer up to (not including) CACert
	SigningCert string `json:"signing_cert,omitempty"`
	ServerCert  string `json:"server_cert,omitempty"` // same value as signing_cert; matches initial registration response field name

	// Identity fields, set with the certificate, so a steward that re-admits with
	// its device key after losing its stored identity record can rebuild it
	// (Issue #4532).
	StewardID        string `json:"steward_id,omitempty"`
	TenantID         string `json:"tenant_id,omitempty"`
	TransportAddress string `json:"transport_address,omitempty"`
}

// RefreshClaimRequest is the body of POST /api/v1/stewards/{device_id}/refresh/claim:
// a fresh challenge's proof-of-possession plus the pending refresh to collect
// (Issue #4532).
type RefreshClaimRequest struct {
	PendingID string `json:"pending_id"`
	Nonce     string `json:"nonce"`     // base64url nonce from challenge response
	IssuedAt  int64  `json:"issued_at"` // server_ts from challenge (Unix nanoseconds)
	Signature string `json:"signature"` // base64url signature over PoP message (ed25519, or ASN.1 DER ecdsa-p256)
	// KeyAlgorithm is the device key algorithm the steward signed with; absent
	// means ed25519 (ADR-011 Amendment 3). It must equal the stored algorithm.
	KeyAlgorithm string `json:"key_algorithm,omitempty"`

	// Provenance is the host attributes the steward collected on this machine.
	// When the claim delivers an operator-approved refresh they become the
	// steward's new provenance baseline (ADR-034 §2): a legitimate hardware
	// change re-baselines through an operator, never automatically.
	Provenance map[string]string `json:"provenance,omitempty"`
}

// ---- Handlers ---------------------------------------------------------------

// handleRefreshChallenge handles POST /api/v1/stewards/{device_id}/refresh/challenge.
// Revocation is the authoritative pre-nonce gate: revoked devices receive 403 before
// any nonce is generated (ADR-010 §3 revocation-before-PoP invariant).
//
// Pre-authentication credential-refresh handshake (ADR-010 §2): {device_id} is
// caller-asserted but unauthenticated at this point — there is no principal,
// session, or API key on this route, and no caller tenant to scope against. The
// nonce this issues is inert on its own; ownership is established afterward, in
// handleRefreshComplete, by proof-of-possession against the resolved device's
// stored Ed25519 public key, not by a request-supplied tenant field.
//
//architecture:allow-unscoped-tenant-read -- pre-authentication handshake, no caller tenant established yet (Issue #4336)
func (s *Server) handleRefreshChallenge(w http.ResponseWriter, r *http.Request) {
	deviceID := mux.Vars(r)["device_id"]

	var req RefreshChallengeRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // body is optional; TenantID defaults to "" if absent or malformed

	if s.stewardStore == nil {
		s.emitUnauthenticatedRefreshAudit(r.Context(), deviceID, req.TenantID,
			business.AuditEventSystemEvent, "refresh_challenge_error",
			business.AuditResultError, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "steward_store_unavailable"})
		s.writeStatusError(w, http.StatusServiceUnavailable, "steward store unavailable")
		return
	}

	record, err := s.stewardStore.GetStewardByDeviceID(r.Context(), deviceID)
	if err != nil {
		if err == business.ErrStewardNotFound {
			s.emitUnauthenticatedRefreshAudit(r.Context(), deviceID, req.TenantID,
				business.AuditEventSecurityEvent, "refresh_challenge_rejected",
				business.AuditResultFailure, business.AuditSeverityMedium,
				map[string]interface{}{"decision": "rejected", "reason": "unknown_device"})
			s.writeStatusError(w, http.StatusNotFound, "device not found")
			return
		}
		s.logger.Error("Failed to look up steward by device ID", "device_id", logging.SanitizeLogValue(deviceID), "error", logging.SanitizeLogValue(err.Error()))
		s.emitUnauthenticatedRefreshAudit(r.Context(), deviceID, req.TenantID,
			business.AuditEventSystemEvent, "refresh_challenge_error",
			business.AuditResultError, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "store_error"})
		s.writeStatusError(w, http.StatusInternalServerError, "failed to look up device")
		return
	}

	// Revocation gate — MUST be checked before generating any nonce.
	if record.Status == business.StewardStatusRevoked {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_challenge_rejected",
			business.AuditResultDenied, business.AuditSeverityCritical,
			map[string]interface{}{"decision": "denied", "reason": "revoked"})
		s.writeStatusError(w, http.StatusForbidden, "device is revoked")
		return
	}

	// req.TenantID is unauthenticated (caller-asserted, optional body field on a
	// pre-authentication endpoint) and is never used for a security decision —
	// see the package doc on GetStewardByDeviceID. It is retained only for audit
	// context on the emitRefreshAudit calls in this handler.
	if s.nonceStore == nil {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSystemEvent, "refresh_challenge_error",
			business.AuditResultError, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "nonce_store_unavailable"})
		s.writeStatusError(w, http.StatusServiceUnavailable, "nonce store unavailable")
		return
	}

	// Generate 32-byte cryptographically random nonce.
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		s.logger.Error("Failed to generate refresh nonce", "error", logging.SanitizeLogValue(err.Error()))
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSystemEvent, "refresh_challenge_error",
			business.AuditResultError, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "nonce_generation_failed"})
		s.writeStatusError(w, http.StatusInternalServerError, "failed to generate challenge")
		return
	}

	issuedAt := time.Now().UTC()
	issuedAtNanos := issuedAt.UnixNano()
	if issuedAtNanos <= 0 {
		s.writeStatusError(w, http.StatusInternalServerError, "failed to issue challenge")
		return
	}
	// #nosec G115 -- current UTC UnixNano is checked positive above; the
	// conversion is lossless through time.Time's supported 2262 limit.
	serverTS := uint64(issuedAtNanos)

	nonceKey := refreshNonceKeyPrefix + deviceID
	entryBytes, err := json.Marshal(&refreshNonceEntry{
		NonceBytes: nonceBytes,
		ServerTS:   serverTS,
		IssuedAt:   issuedAt,
	})
	if err != nil {
		s.logger.Error("Failed to marshal nonce entry", "error", logging.SanitizeLogValue(err.Error()))
		s.writeStatusError(w, http.StatusInternalServerError, "failed to issue challenge")
		return
	}
	if err := s.nonceStore.PutNonce(r.Context(), nonceKey, entryBytes, nonceTTL); err != nil {
		s.logger.Error("Failed to store nonce", "error", logging.SanitizeLogValue(err.Error()))
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSystemEvent, "refresh_challenge_error",
			business.AuditResultError, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "store_write_failed"})
		s.writeStatusError(w, http.StatusInternalServerError, "failed to issue challenge")
		return
	}

	s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
		business.AuditEventAuthentication, "refresh_challenge_issued",
		business.AuditResultSuccess, business.AuditSeverityLow, nil)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(RefreshChallengeResponse{
		Nonce:    base64.RawURLEncoding.EncodeToString(nonceBytes),
		ServerTS: serverTS,
	}); err != nil {
		s.logger.Error("Failed to encode challenge response", "error", logging.SanitizeLogValue(err.Error()))
	}
}

// handleRefreshComplete handles POST /api/v1/stewards/{device_id}/refresh/complete.
// Gate order (ADR-010 §3): (1) lookup, (2) revocation, (3) CSR validation,
// (4) nonce, (5) IssuedAt, (6) consume nonce, (7) PoP verify, (8) lifecycle
// policy, (9) issue cert or queue. Audit is emitted before WriteHeader on every
// outcome. CSR validation (Issue #3781) is a pure request-format check —
// device-independent — but runs after revocation so a rejection there never
// depends on whether the caller also bothered to send a well-formed CSR
// (mirrors the existing revoked-before-PoP invariant: the security-relevant
// gates never take a back seat to format checks). There is no caller-asserted
// cross-tenant gate: identity is confirmed by PoP verification against the
// resolved record's IdentityKeyPub, not by a request field (Issue #4350).
//
// Pre-authentication credential-refresh handshake (ADR-010 §2/§3): {device_id} is
// caller-asserted but unauthenticated until gate (7) below verifies
// proof-of-possession against the resolved device's stored Ed25519 public key.
// There is no principal, session, or API key on this route and therefore no
// caller tenant to scope against; record.TenantID (the device's OWN tenant,
// resolved from the store, never from a request field) is what every downstream
// audit call and policy lookup uses.
//
//architecture:allow-unscoped-tenant-read -- pre-authentication handshake, no caller tenant established until PoP verifies (Issue #4336)
func (s *Server) handleRefreshComplete(w http.ResponseWriter, r *http.Request) {
	deviceID := mux.Vars(r)["device_id"]

	var req RefreshCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeStatusError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if s.stewardStore == nil {
		s.writeStatusError(w, http.StatusServiceUnavailable, "steward store unavailable")
		return
	}

	// Gate (1): lookup → 404
	record, err := s.stewardStore.GetStewardByDeviceID(r.Context(), deviceID)
	if err != nil {
		if err == business.ErrStewardNotFound {
			s.emitUnauthenticatedRefreshAudit(r.Context(), deviceID, req.TenantID,
				business.AuditEventSecurityEvent, "refresh_rejected",
				business.AuditResultFailure, business.AuditSeverityMedium,
				map[string]interface{}{"decision": "rejected", "reason": "unknown_device"})
			s.writeStatusError(w, http.StatusNotFound, "device not found")
			return
		}
		s.logger.Error("Failed to look up steward by device ID", "device_id", logging.SanitizeLogValue(deviceID), "error", logging.SanitizeLogValue(err.Error()))
		s.emitUnauthenticatedRefreshAudit(r.Context(), deviceID, req.TenantID,
			business.AuditEventSystemEvent, "refresh_error",
			business.AuditResultError, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "store_error"})
		s.writeStatusError(w, http.StatusInternalServerError, "failed to look up device")
		return
	}

	// Gate (2): revocation — PoPVerifier must NEVER be called for revoked devices.
	if record.Status == business.StewardStatusRevoked {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultDenied, business.AuditSeverityCritical,
			map[string]interface{}{"decision": "denied", "reason": "revoked"})
		s.writeStatusError(w, http.StatusForbidden, "device is revoked")
		return
	}

	// req.TenantID is unauthenticated (caller-asserted, optional body field on a
	// pre-authentication endpoint) and is never used for a security decision —
	// see the package doc on GetStewardByDeviceID. It is retained only for audit
	// context on the emitRefreshAudit calls in this handler. Identity is instead
	// confirmed below by proof-of-possession against record.IdentityKeyPub.

	// Gate (3): CSR validation (Issue #3781) — the steward generates its renewed
	// mTLS keypair locally and submits only the public half. Rejected before any
	// nonce operation or certificate is signed, mirroring the registration
	// handler's same two checks (handlers_registration.go handleRegister).
	if req.CSRPEM == "" {
		s.writeStatusError(w, http.StatusBadRequest, "csr_pem is required")
		return
	}
	if containsPrivateKeyMaterial(req.CSRPEM) {
		s.writeStatusError(w, http.StatusBadRequest, "private key material is not accepted")
		return
	}
	if _, err := parseAndVerifyCSR(req.CSRPEM); err != nil {
		s.logger.Warn("Rejected invalid certificate signing request at refresh complete",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeStatusError(w, http.StatusBadRequest, "invalid certificate signing request")
		return
	}

	// Gates (4)-(7): nonce, IssuedAt, consume, proof-of-possession.
	if !s.verifyRefreshProof(w, r, record, deviceID, req.Nonce, req.Signature, req.KeyAlgorithm, req.IssuedAt) {
		return
	}

	// Gate (8): lifecycle gate
	switch record.Status {
	case business.StewardStatusArchived:
		// Archived: add pending refresh and return 202 — policy is skipped.
		s.handleRefreshQueueEntry(w, r, record, deviceID, req.Provenance, req.CSRPEM, 0, 0, "archived")

	default:
		// active / registered / dormant / lost / deregistered — consult policy.
		if s.refreshPolicyStore == nil {
			// No policy store: default to require_approval.
			s.handleRefreshQueueEntry(w, r, record, deviceID, req.Provenance, req.CSRPEM, 0, 0, "no_policy_store")
			return
		}
		policy, err := s.refreshPolicyStore.GetPolicy(r.Context(), record.TenantID)
		if err != nil {
			s.logger.Error("Failed to get refresh policy", "tenant_id", logging.SanitizeLogValue(record.TenantID), "error", logging.SanitizeLogValue(err.Error()))
			s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
				business.AuditEventSystemEvent, "refresh_error",
				business.AuditResultError, business.AuditSeverityMedium,
				map[string]interface{}{"reason": "policy_store_error"})
			s.writeStatusError(w, http.StatusInternalServerError, "failed to get refresh policy")
			return
		}
		s.handleRefreshByPolicy(w, r, record, deviceID, req.Provenance, req.CSRPEM, policy)
	}
}

// verifyRefreshProof runs the shared nonce and proof-of-possession gates (4)-(7)
// of the refresh handshake for record, the device resolved from the path: the
// challenge nonce must exist and is consumed, IssuedAt must be fresh, and the
// signature must verify against record.IdentityKeyPub. It writes the error
// response and returns false on any failure. Used by /refresh/complete and
// /refresh/claim.
func (s *Server) verifyRefreshProof(w http.ResponseWriter, r *http.Request, record *business.StewardRecord, deviceID, nonceB64, sigB64, reqKeyAlgorithm string, issuedAt int64) bool {
	if s.nonceStore == nil {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSystemEvent, "refresh_error",
			business.AuditResultError, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "nonce_store_unavailable"})
		s.writeStatusError(w, http.StatusServiceUnavailable, "nonce store unavailable")
		return false
	}

	// Gates (4) and (6): nonce absent/expired → 401; found → consumed atomically
	// in the same store call (Issue #3755, ADR-031). A separate peek-then-delete
	// would reopen the cross-node race this store exists to close, so lookup and
	// consume collapse into one GetAndConsumeNonce call — deleted regardless of
	// the outcome of the gates below, exactly as the prior cache.Delete did.
	nonceKey := refreshNonceKeyPrefix + deviceID
	rawEntry, found, err := s.nonceStore.GetAndConsumeNonce(r.Context(), nonceKey)
	if err != nil {
		s.logger.Error("Failed to consume nonce", "error", logging.SanitizeLogValue(err.Error()))
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSystemEvent, "refresh_error",
			business.AuditResultError, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "store_read_failed"})
		s.writeStatusError(w, http.StatusInternalServerError, "internal error reading challenge")
		return false
	}
	if !found {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultFailure, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "nonce_not_found"})
		s.writeStatusError(w, http.StatusUnauthorized, "challenge expired or not found")
		return false
	}
	var nonce refreshNonceEntry
	if err := json.Unmarshal(rawEntry, &nonce); err != nil {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSystemEvent, "refresh_error",
			business.AuditResultError, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "nonce_type_error"})
		s.writeStatusError(w, http.StatusInternalServerError, "internal error reading challenge")
		return false
	}

	// Algorithm gate (ADR-011 Amendment 3): after the nonce is consumed and before
	// any signature verification, the algorithm the request names must equal the
	// stored one. A change (in either direction) is a downgrade attempt and
	// answers 401, the same as an invalid signature.
	storedAlg, storedOK := normalizeKeyAlgorithm(record.KeyAlgorithm)
	reqAlg, reqOK := normalizeKeyAlgorithm(reqKeyAlgorithm)
	if !storedOK || !reqOK || storedAlg != reqAlg {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultFailure, business.AuditSeverityCritical,
			map[string]interface{}{
				"reason":                "key_algorithm_mismatch",
				"stored_key_algorithm":  string(storedAlg),
				"request_key_algorithm": logging.SanitizeLogValue(reqKeyAlgorithm),
			})
		s.writeStatusError(w, http.StatusUnauthorized, "proof-of-possession verification failed")
		return false
	}

	// Gate (5): IssuedAt > 60s → 401
	issuedAtTime := time.Unix(0, issuedAt)
	if time.Since(issuedAtTime) > nonceMaxAge {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultFailure, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "nonce_expired_issuedAt"})
		s.writeStatusError(w, http.StatusUnauthorized, "challenge nonce has expired")
		return false
	}

	// Decode nonce bytes from base64url.
	nonceBytes, err := base64.RawURLEncoding.DecodeString(nonceB64)
	if err != nil {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultFailure, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "invalid_nonce_encoding"})
		s.writeStatusError(w, http.StatusUnauthorized, "invalid nonce encoding")
		return false
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultFailure, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "invalid_signature_encoding"})
		s.writeStatusError(w, http.StatusUnauthorized, "invalid signature encoding")
		return false
	}

	// Gate (7): PoP verify — message = sha256(nonce_bytes || device_id_utf8 || server_ts_be_uint64)
	pubKey, keyErr := parseDevicePublicKey(storedAlg, record.IdentityKeyPub)
	if keyErr != nil {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultDenied, business.AuditSeverityHigh,
			map[string]interface{}{"reason": "no_identity_key"})
		s.writeStatusError(w, http.StatusForbidden, "device has no identity key registered")
		return false
	}

	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], nonce.ServerTS)
	h := sha256.New()
	h.Write(nonceBytes)
	h.Write([]byte(deviceID))
	h.Write(tsBytes[:])
	popMsg := h.Sum(nil)

	if !s.popVerifier.Verify(storedAlg, pubKey, popMsg, sigBytes) {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultFailure, business.AuditSeverityCritical,
			map[string]interface{}{"reason": "invalid_pop"})
		s.writeStatusError(w, http.StatusUnauthorized, "proof-of-possession verification failed")
		return false
	}

	return true
}

// handleRefreshClaim handles POST /api/v1/stewards/{device_id}/refresh/claim: a
// steward whose refresh was queued for approval collects the outcome (Issue
// #4532). Before this endpoint an approved refresh was signed and stored but
// never delivered, so under require_approval a steward re-queued forever.
//
// Identity is proven exactly as for /refresh/complete — a fresh challenge nonce
// signed with the device identity key — and the pending entry must belong to
// that device. Outcomes: 200 with the certificate bundle (once; the entry is
// then marked claimed), 202 still pending, 403 rejected or revoked, 404 unknown,
// expired or already claimed — the steward then starts a new refresh.
//
//architecture:allow-unscoped-tenant-read -- pre-authentication handshake, no caller tenant established until PoP verifies (Issue #4336)
func (s *Server) handleRefreshClaim(w http.ResponseWriter, r *http.Request) {
	deviceID := mux.Vars(r)["device_id"]

	var req RefreshClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PendingID == "" {
		s.writeStatusError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if s.stewardStore == nil || s.pendingRefreshStore == nil {
		s.writeStatusError(w, http.StatusServiceUnavailable, "refresh stores unavailable")
		return
	}

	record, err := s.stewardStore.GetStewardByDeviceID(r.Context(), deviceID)
	if err != nil {
		if err == business.ErrStewardNotFound {
			s.writeStatusError(w, http.StatusNotFound, "device not found")
			return
		}
		s.logger.Error("Failed to look up steward by device ID", "device_id", logging.SanitizeLogValue(deviceID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeStatusError(w, http.StatusInternalServerError, "failed to look up device")
		return
	}
	if record.Status == business.StewardStatusRevoked {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_claim_rejected",
			business.AuditResultDenied, business.AuditSeverityCritical,
			map[string]interface{}{"decision": "denied", "reason": "revoked"})
		s.writeStatusError(w, http.StatusForbidden, "device is revoked")
		return
	}
	if !s.verifyRefreshProof(w, r, record, deviceID, req.Nonce, req.Signature, req.KeyAlgorithm, req.IssuedAt) {
		return
	}

	entry, err := s.pendingRefreshStore.GetPendingRefreshByID(r.Context(), req.PendingID)
	if err != nil {
		if err == business.ErrPendingRefreshNotFound {
			s.writeStatusError(w, http.StatusNotFound, "pending refresh not found")
			return
		}
		s.logger.Error("Failed to get pending refresh", "pending_id", logging.SanitizeLogValue(req.PendingID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeStatusError(w, http.StatusInternalServerError, "failed to get pending refresh")
		return
	}
	// The entry must belong to the device that just proved possession; another
	// device's pending ID is indistinguishable from an unknown one.
	if entry.DeviceID != deviceID || entry.TenantID != record.TenantID {
		s.writeStatusError(w, http.StatusNotFound, "pending refresh not found")
		return
	}

	switch entry.Status {
	case business.PendingRefreshStatusPending:
		if time.Now().UTC().After(entry.ExpiresAt) {
			s.writeStatusError(w, http.StatusNotFound, "pending refresh expired")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(RefreshCompleteResponse{Status: "queued", PendingID: entry.PendingID}); err != nil {
			s.logger.Error("Failed to encode refresh claim response", "error", logging.SanitizeLogValue(err.Error()))
		}
	case business.PendingRefreshStatusApproved:
		if len(entry.ClaimBundle) == 0 {
			s.writeStatusError(w, http.StatusInternalServerError, "approved refresh has no certificate bundle")
			return
		}
		// Compare-and-swap approved -> claimed: of two racing claims exactly one
		// receives the bundle; the other sees it as already collected.
		claimed, err := s.pendingRefreshStore.ClaimApprovedRefresh(r.Context(), entry.PendingID)
		if err != nil {
			s.logger.Error("Failed to mark refresh claimed", "pending_id", logging.SanitizeLogValue(entry.PendingID), "error", logging.SanitizeLogValue(err.Error()))
			s.writeStatusError(w, http.StatusInternalServerError, "failed to claim refresh")
			return
		}
		if !claimed {
			s.writeStatusError(w, http.StatusNotFound, "pending refresh not available")
			return
		}
		s.rebaselineProvenance(r.Context(), record, deviceID, entry.PendingID, req.Provenance)
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventAuthentication, "refresh_claimed",
			business.AuditResultSuccess, business.AuditSeverityMedium,
			map[string]interface{}{"pending_id": logging.SanitizeLogValue(entry.PendingID)})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// #nosec G117 -- the stored bundle is the signed client certificate set
		// produced at approval; it carries no private key (Issue #3781).
		if _, err := w.Write(entry.ClaimBundle); err != nil {
			s.logger.Error("Failed to write refresh claim bundle", "error", logging.SanitizeLogValue(err.Error()))
		}
	case business.PendingRefreshStatusRejected:
		s.writeStatusError(w, http.StatusForbidden, "refresh rejected")
	default: // expired, claimed
		s.writeStatusError(w, http.StatusNotFound, "pending refresh not available")
	}
}

// maxProvenanceAttrs and maxProvenanceValueLen bound a caller-supplied
// provenance map before it is stored as a baseline.
const (
	maxProvenanceAttrs    = 16
	maxProvenanceValueLen = 1024
)

// rebaselineProvenance records the attributes a steward presented when it
// collected an operator-approved refresh as its new provenance baseline. DNA
// fields are dropped; with no usable attributes the existing baseline is kept.
// A store failure is logged and audited but does not withhold the certificate
// the operator already approved.
func (s *Server) rebaselineProvenance(ctx context.Context, record *business.StewardRecord, deviceID, pendingID string, provenance map[string]string) {
	if len(provenance) == 0 || len(provenance) > maxProvenanceAttrs {
		return
	}
	bounded := make(map[string]string, len(provenance))
	for k, v := range provenance {
		if len(v) > maxProvenanceValueLen {
			continue
		}
		bounded[k] = v
	}
	attrs := registration.NormalizeProvenance(bounded)
	if attrs == nil {
		return
	}
	raw, err := json.Marshal(attrs)
	if err != nil {
		return
	}
	if err := s.stewardStore.SetStewardProvenance(ctx, record.ID, string(raw)); err != nil {
		s.logger.Error("Failed to re-baseline steward provenance", "steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		s.emitRefreshAudit(ctx, deviceID, record.TenantID,
			business.AuditEventSystemEvent, "refresh_error",
			business.AuditResultError, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "provenance_rebaseline_failed"})
		return
	}
	s.emitRefreshAudit(ctx, deviceID, record.TenantID,
		business.AuditEventSecurityEvent, "steward_provenance_rebaselined",
		business.AuditResultSuccess, business.AuditSeverityMedium,
		map[string]interface{}{"pending_id": logging.SanitizeLogValue(pendingID), "reason": "operator_approved_refresh"})
}

// handleRefreshByPolicy applies the per-tenant policy gate for non-archived stewards.
func (s *Server) handleRefreshByPolicy(
	w http.ResponseWriter, r *http.Request,
	record *business.StewardRecord, deviceID string,
	provenance map[string]string, csrPEM string, policy *business.RefreshPolicy,
) {
	switch policy.Mode {
	case "reject":
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultDenied, business.AuditSeverityHigh,
			map[string]interface{}{"reason": "policy_reject", "decision": "rejected"})
		s.writeStatusError(w, http.StatusForbidden, "refresh rejected by tenant policy")

	case "auto_accept":
		// Only compare provenance when a baseline exists. A missing baseline (first
		// refresh after initial registration) is not evidence of device change —
		// the check is skipped and the cert is issued immediately.
		if record.LastProvenanceJSON != "" {
			pm := registration.ProvenanceMatcher{}
			result := pm.FuzzyMatch(registration.NormalizeStoredProvenance(record.LastProvenanceJSON), registration.NormalizeProvenance(provenance))
			if result.Score < registration.ProvenanceMatchThreshold {
				// Demote to require_approval (demote-only invariant).
				s.handleRefreshQueueEntry(w, r, record, deviceID, provenance, csrPEM,
					result.MatchedFields, result.TotalFields, "auto_accept_demoted")
				return
			}
		}
		// No stored provenance baseline, or sufficient provenance match: issue cert immediately.
		resp, _, err := s.buildRefreshClaimResponse(r.Context(), record, csrPEM)
		if err != nil {
			s.logger.Error("Failed to issue refresh certificate", "steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
			s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
				business.AuditEventSystemEvent, "refresh_error",
				business.AuditResultError, business.AuditSeverityMedium,
				map[string]interface{}{"reason": "cert_issuance_failed"})
			s.writeStatusError(w, http.StatusInternalServerError, "failed to issue certificate")
			return
		}
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventAuthentication, "refresh_cert_issued",
			business.AuditResultSuccess, business.AuditSeverityLow,
			map[string]interface{}{"decision": "approved", "reason": "auto_accept"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// #nosec G117 -- authenticated refresh returns the signed client certificate;
		// no private key is ever generated or held by the controller for this
		// credential (Issue #3781).
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			s.logger.Error("Failed to encode refresh complete response", "error", logging.SanitizeLogValue(err.Error()))
		}

	default: // require_approval (and unknown modes)
		s.handleRefreshQueueEntry(w, r, record, deviceID, provenance, csrPEM, 0, 0, "require_approval")
	}
}

// handleRefreshQueueEntry writes a pending refresh record and responds with 202.
func (s *Server) handleRefreshQueueEntry(
	w http.ResponseWriter, r *http.Request,
	record *business.StewardRecord, deviceID string,
	_ map[string]string, csrPEM string, matchedFields, totalFields int, reason string,
) {
	if s.pendingRefreshStore == nil {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSystemEvent, "refresh_error",
			business.AuditResultError, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "pending_store_unavailable"})
		s.writeStatusError(w, http.StatusServiceUnavailable, "pending refresh store unavailable")
		return
	}

	// One open request per device (Issue #4532): a steward that files a new
	// request (it lost its pending state, or its earlier request expired)
	// supersedes its own open one, so repeated re-admission attempts never grow
	// the approval queue.
	s.supersedeOpenRefreshes(r.Context(), deviceID, record.TenantID)

	pendingID := fmt.Sprintf("refresh-%d", time.Now().UnixNano())
	entry := &business.PendingRefreshEntry{
		PendingID:               pendingID,
		DeviceID:                deviceID,
		TenantID:                record.TenantID,
		SourceIP:                extractSourceIP(r, s.trustedProxies),
		CSRPEM:                  csrPEM,
		ProvenanceMatchedFields: matchedFields,
		ProvenanceTotalFields:   totalFields,
		Status:                  business.PendingRefreshStatusPending,
		CreatedAt:               time.Now().UTC(),
		ExpiresAt:               time.Now().UTC().Add(7 * 24 * time.Hour),
	}
	if err := s.pendingRefreshStore.AddPendingRefresh(r.Context(), entry); err != nil {
		s.logger.Error("Failed to add pending refresh", "steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSystemEvent, "refresh_error",
			business.AuditResultError, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "pending_store_write_failed"})
		s.writeStatusError(w, http.StatusInternalServerError, "failed to queue refresh request")
		return
	}

	s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
		business.AuditEventAuthentication, "refresh_queued",
		business.AuditResultSuccess, business.AuditSeverityMedium,
		map[string]interface{}{
			"pending_id": pendingID,
			"decision":   "queued",
			"reason":     reason,
		})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	// #nosec G117 -- this queued response contains only status and pending ID; the
	// RefreshCompleteResponse type carries no private-key field at all (Issue #3781).
	if err := json.NewEncoder(w).Encode(RefreshCompleteResponse{
		Status:    "queued",
		PendingID: pendingID,
	}); err != nil {
		s.logger.Error("Failed to encode refresh queued response", "error", logging.SanitizeLogValue(err.Error()))
	}
}

// supersedeOpenRefreshes expires deviceID's open pending refreshes in tenantID.
// Best-effort: a failure leaves an extra entry for an operator to see, never a
// refusal of the new request.
func (s *Server) supersedeOpenRefreshes(ctx context.Context, deviceID, tenantID string) {
	entries, err := s.pendingRefreshStore.ListPendingRefresh(ctx, tenantID)
	if err != nil {
		s.logger.Warn("Failed to list pending refreshes for supersede", "device_id", logging.SanitizeLogValue(deviceID), "error", logging.SanitizeLogValue(err.Error()))
		return
	}
	for _, e := range entries {
		if e.DeviceID != deviceID || e.Status != business.PendingRefreshStatusPending {
			continue
		}
		if err := s.pendingRefreshStore.UpdateRefreshStatus(ctx, e.PendingID, business.PendingRefreshStatusExpired); err != nil {
			s.logger.Warn("Failed to supersede pending refresh", "pending_id", logging.SanitizeLogValue(e.PendingID), "error", logging.SanitizeLogValue(err.Error()))
		}
	}
}

// buildRefreshClaimResponse signs the steward-submitted CSR into a new mTLS
// certificate for a steward that has passed the registration-refresh gate
// (Issue #3781). Mirrors the cert issuance in buildClaimResponse — the
// controller never generates or sees a private key for this credential.
// The returned serial is non-empty whenever signing succeeded, even if a later
// step returned an error, so callers can audit the issuance regardless.
func (s *Server) buildRefreshClaimResponse(ctx context.Context, record *business.StewardRecord, csrPEM string) (*RefreshCompleteResponse, string, error) {
	if s.certManager == nil {
		return nil, "", fmt.Errorf("certificate manager not initialized")
	}

	validityDays := 365
	if s.cfg.Certificate != nil && s.cfg.Certificate.ClientCertValidityDays > 0 {
		validityDays = s.cfg.Certificate.ClientCertValidityDays
	}

	csr, err := parseAndVerifyCSR(csrPEM)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse refresh certificate signing request: %w", err)
	}

	clientCert, err := s.certManager.SignClientCertificateRequest(csr.PublicKey, &cert.ClientCertConfig{
		CommonName:   record.ID,
		Organization: "CFGMS Stewards",
		ClientID:     record.ID,
		ValidityDays: validityDays,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to sign client certificate: %w", err)
	}
	serial := clientCert.SerialNumber

	caCert, err := s.certManager.GetCACertificate()
	if err != nil || len(caCert) == 0 {
		return nil, serial, fmt.Errorf("CA certificate unavailable: %w", err)
	}

	resp := &RefreshCompleteResponse{
		Status:      "approved",
		ClientCert:  string(clientCert.CertificatePEM),
		CACert:      string(caCert),
		IssuerChain: string(clientCert.IssuerChainPEM),
		StewardID:   record.ID,
		TenantID:    record.TenantID,
	}
	// Best-effort: a steward that still has its identity record keeps its stored
	// transport address when this is empty.
	if transportAddr, addrErr := s.getTransportAddress(); addrErr == nil {
		resp.TransportAddress = transportAddr
	}

	if signingCertPEM, sigErr := s.certManager.GetSigningCertificate(); sigErr == nil && len(signingCertPEM) > 0 {
		resp.SigningCert = string(signingCertPEM)
		resp.ServerCert = string(signingCertPEM) // matches initial registration response field name
	}

	// Promote steward back to registered status after cert issuance. This must be
	// written to the PERSISTENT steward store, because the registration-refresh
	// lifecycle gate reads status via stewardStore.GetStewardByDeviceID. Updating
	// only the in-memory service registry (below) leaves an admin-approved *archived*
	// steward looking archived to the next challenge, so it re-queues indefinitely
	// and only converges via slow background reconciliation
	// (Issue #2098: TestFleetRegistrationRefresh/Archived).
	if s.stewardStore != nil {
		// Never resurrect a revoked or deregistered record that changed after the
		// lifecycle gate read it (Issue #4851).
		if _, err := s.stewardStore.TransitionStewardStatus(ctx, record.ID, business.StewardStatusRegistered,
			business.StewardStatusRegistered, business.StewardStatusActive, business.StewardStatusLost,
			business.StewardStatusArchived, business.StewardStatusDormant); err != nil {
			s.logger.Warn("Failed to persist steward status after refresh cert issuance",
				"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		}
	}
	if s.controllerService != nil {
		if err := s.controllerService.UpdateStewardStatus(record.ID, "registered"); err != nil {
			s.logger.Warn("Failed to update steward status after refresh cert issuance",
				"steward_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(err.Error()))
		}
	}

	s.logger.Info("Issued refresh certificate",
		"steward_id", logging.SanitizeLogValue(record.ID),
		"validity_days", validityDays)

	return resp, serial, nil
}

// ---- Admin request / response types -----------------------------------------

// AdminRefreshApproveRequest is the optional body for the admin approve endpoint.
type AdminRefreshApproveRequest struct {
	Reason string `json:"reason,omitempty"`
}

// AdminRefreshApproveResponse is returned by POST /api/v1/stewards/refresh/{pending_id}/approve.
type AdminRefreshApproveResponse struct {
	Status      string `json:"status"`
	PendingID   string `json:"pending_id"`
	ClientCert  string `json:"client_cert,omitempty"`
	CACert      string `json:"ca_cert,omitempty"`
	IssuerChain string `json:"issuer_chain,omitempty"`
	SigningCert string `json:"signing_cert,omitempty"`
}

// AdminRefreshRejectRequest is the body for the admin reject endpoint.
type AdminRefreshRejectRequest struct {
	Reason string `json:"reason,omitempty"`
}

// AdminRefreshPolicyRequest is the body for PUT /api/v1/tenants/{id}/refresh-policy.
type AdminRefreshPolicyRequest struct {
	Mode            string `json:"mode"`
	MaxDormancyDays *int   `json:"max_dormancy_days,omitempty"`
}

// AdminRefreshPolicyResponse is returned by GET /api/v1/tenants/{id}/refresh-policy.
type AdminRefreshPolicyResponse struct {
	TenantID        string `json:"tenant_id"`
	Mode            string `json:"mode"`
	MaxDormancyDays *int   `json:"max_dormancy_days,omitempty"`
}

// APIPendingRefreshEntry is the wire representation of a pending refresh entry.
type APIPendingRefreshEntry struct {
	PendingID string `json:"pending_id"`
	DeviceID  string `json:"device_id"`
	// Hostname is the steward-reported hostname for DeviceID within TenantID;
	// empty when the device is unknown. Untrusted — render as text only.
	Hostname                string    `json:"hostname"`
	TenantID                string    `json:"tenant_id"`
	SourceIP                string    `json:"source_ip"`
	ProvenanceMatchedFields int       `json:"provenance_matched_fields"`
	ProvenanceTotalFields   int       `json:"provenance_total_fields"`
	Status                  string    `json:"status"`
	CreatedAt               time.Time `json:"created_at"`
	ExpiresAt               time.Time `json:"expires_at"`
}

// pendingRefreshHostname resolves the steward hostname for a pending refresh
// entry. The lookup is scoped to the entry's own tenant, so a device_id shared
// with another tenant's steward never leaks that tenant's hostname. Returns ""
// when the store is unavailable or the device is unknown.
func (s *Server) pendingRefreshHostname(ctx context.Context, e *business.PendingRefreshEntry) string {
	if s.stewardStore == nil {
		return ""
	}
	record, err := s.stewardStore.GetStewardByDeviceIDForTenant(ctx, e.DeviceID, e.TenantID)
	if err != nil || record == nil {
		return ""
	}
	return record.Hostname
}

// ---- Admin handlers ----------------------------------------------------------

// handleListPendingRefreshes handles GET /api/v1/stewards/refresh/pending.
// Requires "refresh:list-pending" permission.
func (s *Server) handleListPendingRefreshes(w http.ResponseWriter, r *http.Request) {
	if s.pendingRefreshStore == nil {
		s.writeStatusError(w, http.StatusServiceUnavailable, "pending refresh store unavailable")
		return
	}

	// TenantID is always taken from the authenticated context for scoped callers;
	// unscoped admins may use the query param to filter. The store is read
	// unfiltered for a scoped caller and narrowed by the shared read decision: a
	// scoped caller sees its own tenant and every descendant, and a root caller
	// subject to the ADR-025 boundary sees only root-tenant and crossing-covered
	// entries (Issue #4715).
	readScope := s.tenantReadScope(r, "GET /api/v1/stewards/refresh/pending")
	tenantID := r.URL.Query().Get("tenant_id")
	if callerTenantScope(r).IsTenant() {
		tenantID = ""
	}

	entries, err := s.pendingRefreshStore.ListPendingRefresh(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("Failed to list pending refreshes", "error", logging.SanitizeLogValue(err.Error()))
		s.writeStatusError(w, http.StatusInternalServerError, "failed to list pending refreshes")
		return
	}
	scoped := make([]*business.PendingRefreshEntry, 0, len(entries))
	for _, e := range entries {
		if readScope.Allows(e.TenantID) {
			scoped = append(scoped, e)
		}
	}
	entries = scoped
	readScope.LogSummary()

	out := make([]APIPendingRefreshEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, APIPendingRefreshEntry{
			PendingID:               e.PendingID,
			DeviceID:                e.DeviceID,
			Hostname:                s.pendingRefreshHostname(r.Context(), e),
			TenantID:                e.TenantID,
			SourceIP:                e.SourceIP,
			ProvenanceMatchedFields: e.ProvenanceMatchedFields,
			ProvenanceTotalFields:   e.ProvenanceTotalFields,
			Status:                  e.Status,
			CreatedAt:               e.CreatedAt,
			ExpiresAt:               e.ExpiresAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		s.logger.Error("Failed to encode pending refreshes", "error", err)
	}
}

// handleApproveRefresh handles POST /api/v1/stewards/refresh/{pending_id}/approve.
// Generates a cert bundle for the steward, stores it, sets status to approved, and
// emits an audit event. The cert bundle is returned to the caller and stored for
// delivery on the steward's next poll.
func (s *Server) handleApproveRefresh(w http.ResponseWriter, r *http.Request) {
	pendingID := mux.Vars(r)["pending_id"]

	var req AdminRefreshApproveRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	if s.pendingRefreshStore == nil {
		s.writeStatusError(w, http.StatusServiceUnavailable, "pending refresh store unavailable")
		return
	}

	entry, err := s.pendingRefreshStore.GetPendingRefreshByID(r.Context(), pendingID)
	if err != nil {
		if err == business.ErrPendingRefreshNotFound {
			s.writeStatusError(w, http.StatusNotFound, "pending refresh not found")
			return
		}
		s.logger.Error("Failed to get pending refresh", "pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeStatusError(w, http.StatusInternalServerError, "failed to get pending refresh")
		return
	}

	// Cross-tenant: a scoped caller may only approve refreshes within their tenant hierarchy.
	callerTenant := callerTenantFilter(r.Context())
	if callerTenant != "" { //architecture:allow-root-scope -- tenant-scoped callers only; a root caller passes authorizeTenantAccess below, refused as 404 like every other outcome
		if !s.tenantSubtreeContains(r.Context(), callerTenant, entry.TenantID) {
			// 404 to avoid disclosing existence of pending refreshes across tenants.
			s.writeStatusError(w, http.StatusNotFound, "pending refresh not found")
			return
		}
	}

	// ADR-025 Decision 1 root-scoped boundary (Issue #3303): the route path carries
	// {pending_id}, not a tenant ID, so requirePermission's extractBoundaryTenantFromRequest
	// returns "" and the middleware root-scoped crossing check is skipped entirely. Enforce
	// the boundary inline using the resolved entry.TenantID after the record is loaded.
	// Existence-oracle stance: all denial outcomes (no tenantManager, tenantAuthNeedsCrossing,
	// tenantAuthDenied) return 404 "pending refresh not found" — the same response as the
	// tenant-scoped case above and the ErrPendingRefreshNotFound path — so the endpoint never
	// discloses pending-refresh existence across tenant boundaries to a root-scoped caller.
	// "Root-scoped" is the boundary's own predicate (GlobalScope for an account-bound
	// principal, Issue #4337), so a bound root-scope caller without the marker is covered.
	if principal, _ := r.Context().Value(principalContextKey).(*Principal); subjectToTenantCrossingBoundary(principal) {
		if s.tenantManager == nil {
			s.writeStatusError(w, http.StatusNotFound, "pending refresh not found")
			return
		}
		if s.authorizeTenantAccess(r.Context(), principal, entry.TenantID) != tenantAuthAllowed {
			s.writeStatusError(w, http.StatusNotFound, "pending refresh not found")
			return
		}
	}

	// Authorization above runs before the status check so an unauthorized caller
	// gets the same 404 for an entry in any status (Issue #5315).
	if entry.Status != business.PendingRefreshStatusPending {
		s.writeStatusError(w, http.StatusConflict, "refresh request is not in pending state")
		return
	}

	if s.stewardStore == nil {
		s.writeStatusError(w, http.StatusServiceUnavailable, "steward store unavailable")
		return
	}

	// entry.TenantID is authorized above (same-tenant/ancestor check and, for a
	// root-scoped caller, authorizeTenantAccess), so the lookup is tenant-scoped —
	// a device_id collision with a different tenant's steward can never be
	// returned here (Issue #4350).
	record, err := s.stewardStore.GetStewardByDeviceIDForTenant(r.Context(), entry.DeviceID, entry.TenantID)
	if err != nil {
		if err == business.ErrStewardNotFound {
			s.emitRefreshAudit(r.Context(), entry.DeviceID, entry.TenantID,
				business.AuditEventSystemEvent, "refresh_admin_approve_error",
				business.AuditResultError, business.AuditSeverityMedium,
				map[string]interface{}{"pending_id": logging.SanitizeLogValue(pendingID), "reason": "steward_not_found"})
			s.writeStatusError(w, http.StatusNotFound, "steward not found")
			return
		}
		s.logger.Error("Failed to get steward for refresh approval", "device_id", logging.SanitizeLogValue(entry.DeviceID), "error", logging.SanitizeLogValue(err.Error()))
		s.emitRefreshAudit(r.Context(), entry.DeviceID, entry.TenantID,
			business.AuditEventSystemEvent, "refresh_admin_approve_error",
			business.AuditResultError, business.AuditSeverityMedium,
			map[string]interface{}{"pending_id": logging.SanitizeLogValue(pendingID), "reason": "store_error"})
		s.writeStatusError(w, http.StatusInternalServerError, "failed to get steward")
		return
	}

	// Gate: revocation re-check before issuing a cert. The challenge and complete
	// paths reject revoked devices, but a device can be revoked AFTER its refresh
	// was queued as pending. Approving a now-revoked device must NOT issue a cert —
	// and must not let buildRefreshClaimResponse promote revoked->registered,
	// silently un-revoking it. Mirror the challenge/complete revocation gate.
	if record.Status == business.StewardStatusRevoked {
		s.emitRefreshAudit(r.Context(), entry.DeviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_admin_approve_rejected",
			business.AuditResultDenied, business.AuditSeverityCritical,
			map[string]interface{}{"pending_id": logging.SanitizeLogValue(pendingID), "decision": "denied", "reason": "revoked"})
		s.writeStatusError(w, http.StatusForbidden, "device is revoked")
		return
	}

	certResp, certSerial, err := s.buildRefreshClaimResponse(r.Context(), record, entry.CSRPEM)
	if certSerial != "" {
		// Audit the issuance before any fallible step that follows signing.
		issuedDetails := map[string]interface{}{
			"pending_id":  logging.SanitizeLogValue(pendingID),
			"device_id":   logging.SanitizeLogValue(entry.DeviceID),
			"tenant_id":   logging.SanitizeLogValue(entry.TenantID),
			"cert_serial": logging.SanitizeLogValue(certSerial),
		}
		if principal, _ := r.Context().Value(principalContextKey).(*Principal); principal != nil {
			s.emitOperatorAudit(r, principal, entry.TenantID, business.AuditEventAuthentication,
				"refresh_admin_cert_issued", "steward", entry.DeviceID,
				business.AuditResultSuccess, business.AuditSeverityHigh, issuedDetails)
		} else {
			s.emitRefreshAudit(r.Context(), entry.DeviceID, entry.TenantID,
				business.AuditEventAuthentication, "refresh_admin_cert_issued",
				business.AuditResultSuccess, business.AuditSeverityHigh, issuedDetails)
		}
	}
	if err != nil {
		s.logger.Error("Failed to build refresh cert for approval", "pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
		s.emitRefreshAudit(r.Context(), entry.DeviceID, entry.TenantID,
			business.AuditEventSystemEvent, "refresh_admin_approve_error",
			business.AuditResultError, business.AuditSeverityMedium,
			map[string]interface{}{"pending_id": logging.SanitizeLogValue(pendingID), "reason": "cert_issuance_failed"})
		s.writeStatusError(w, http.StatusInternalServerError, "failed to issue certificate")
		return
	}

	// #nosec G117 -- the claim bundle is stored only in the pending-refresh
	// secure store for one-time authenticated retrieval; it is not logged.
	bundle, err := json.Marshal(certResp)
	if err != nil {
		s.logger.Error("Failed to marshal claim bundle", "pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeStatusError(w, http.StatusInternalServerError, "internal error serializing cert bundle")
		return
	}

	if err := s.pendingRefreshStore.StoreClaimBundle(r.Context(), pendingID, bundle); err != nil {
		s.logger.Error("Failed to store claim bundle", "pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeStatusError(w, http.StatusInternalServerError, "failed to store claim bundle")
		return
	}

	if err := s.pendingRefreshStore.UpdateRefreshStatus(r.Context(), pendingID, business.PendingRefreshStatusApproved); err != nil {
		s.logger.Error("Failed to update refresh status to approved", "pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeStatusError(w, http.StatusInternalServerError, "failed to update refresh status")
		return
	}

	details := map[string]interface{}{
		"pending_id": logging.SanitizeLogValue(pendingID),
		"device_id":  logging.SanitizeLogValue(entry.DeviceID),
		"tenant_id":  logging.SanitizeLogValue(entry.TenantID),
		"decision":   "approved",
		"reason":     logging.SanitizeLogValue(req.Reason),
	}
	if principal, _ := r.Context().Value(principalContextKey).(*Principal); principal != nil {
		s.emitOperatorAudit(r, principal, entry.TenantID, business.AuditEventAuthentication,
			"refresh_admin_approved", "steward", entry.DeviceID,
			business.AuditResultSuccess, business.AuditSeverityHigh, details)
	} else {
		s.emitRefreshAudit(r.Context(), entry.DeviceID, entry.TenantID,
			business.AuditEventAuthentication, "refresh_admin_approved",
			business.AuditResultSuccess, business.AuditSeverityHigh, details)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// #nosec G117 -- an authenticated administrator approved this delivery of the
	// signed client certificate; no private key is ever generated or held by the
	// controller for this credential (Issue #3781).
	if err := json.NewEncoder(w).Encode(AdminRefreshApproveResponse{
		Status:      "approved",
		PendingID:   pendingID,
		ClientCert:  certResp.ClientCert,
		CACert:      certResp.CACert,
		IssuerChain: certResp.IssuerChain,
		SigningCert: certResp.SigningCert,
	}); err != nil {
		s.logger.Error("Failed to encode approve response", "error", logging.SanitizeLogValue(err.Error()))
	}
}

// handleRejectRefresh handles POST /api/v1/stewards/refresh/{pending_id}/reject.
// Sets status to rejected and emits an audit event.
func (s *Server) handleRejectRefresh(w http.ResponseWriter, r *http.Request) {
	pendingID := mux.Vars(r)["pending_id"]

	var req AdminRefreshRejectRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	if s.pendingRefreshStore == nil {
		s.writeStatusError(w, http.StatusServiceUnavailable, "pending refresh store unavailable")
		return
	}

	entry, err := s.pendingRefreshStore.GetPendingRefreshByID(r.Context(), pendingID)
	if err != nil {
		if err == business.ErrPendingRefreshNotFound {
			s.writeStatusError(w, http.StatusNotFound, "pending refresh not found")
			return
		}
		s.logger.Error("Failed to get pending refresh for rejection", "pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeStatusError(w, http.StatusInternalServerError, "failed to get pending refresh")
		return
	}

	// Authorization runs before the status check so an unauthorized caller gets the
	// same 404 for an entry in any status (Issue #5315).
	// Cross-tenant: a scoped caller may only reject refreshes within their tenant hierarchy.
	if !s.isAuthorizedForTenant(r.Context(), callerTenantScope(r), entry.TenantID, "POST /api/v1/stewards/refresh/{pending_id}/reject") {
		s.writeStatusError(w, http.StatusNotFound, "pending refresh not found")
		return
	}

	if entry.Status != business.PendingRefreshStatusPending {
		s.writeStatusError(w, http.StatusConflict, "refresh request is not in pending state")
		return
	}

	if err := s.pendingRefreshStore.UpdateRefreshStatus(r.Context(), pendingID, business.PendingRefreshStatusRejected); err != nil {
		s.logger.Error("Failed to update refresh status to rejected", "pending_id", logging.SanitizeLogValue(pendingID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeStatusError(w, http.StatusInternalServerError, "failed to update refresh status")
		return
	}

	details := map[string]interface{}{
		"pending_id": logging.SanitizeLogValue(pendingID),
		"device_id":  logging.SanitizeLogValue(entry.DeviceID),
		"tenant_id":  logging.SanitizeLogValue(entry.TenantID),
		"decision":   "rejected",
		"reason":     logging.SanitizeLogValue(req.Reason),
	}
	if principal, _ := r.Context().Value(principalContextKey).(*Principal); principal != nil {
		s.emitOperatorAudit(r, principal, entry.TenantID, business.AuditEventSecurityEvent,
			"refresh_admin_rejected", "steward", entry.DeviceID,
			business.AuditResultDenied, business.AuditSeverityMedium, details)
	} else {
		s.emitRefreshAudit(r.Context(), entry.DeviceID, entry.TenantID,
			business.AuditEventSecurityEvent, "refresh_admin_rejected",
			business.AuditResultDenied, business.AuditSeverityMedium, details)
	}

	w.WriteHeader(http.StatusOK)
}

// handleGetRefreshPolicy handles GET /api/v1/tenants/{tenant_path}/refresh-policy.
func (s *Server) handleGetRefreshPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["tenant_path"]

	// Cross-tenant: a scoped caller may only read policy for their own tenant hierarchy.
	callerTenant := callerTenantFilter(r.Context())
	if callerTenant != "" { //architecture:allow-root-scope -- tenant-path route; requirePermission's boundary gate applies the crossing to a root caller
		if !s.tenantSubtreeContains(r.Context(), callerTenant, tenantID) {
			s.writeStatusError(w, http.StatusNotFound, "tenant not found")
			return
		}
	}

	if s.refreshPolicyStore == nil {
		s.writeStatusError(w, http.StatusServiceUnavailable, "refresh policy store unavailable")
		return
	}

	policy, err := s.refreshPolicyStore.GetPolicy(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("Failed to get refresh policy", "tenant_id", logging.SanitizeLogValue(tenantID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeStatusError(w, http.StatusInternalServerError, "failed to get refresh policy")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(AdminRefreshPolicyResponse{
		TenantID:        policy.TenantID,
		Mode:            policy.Mode,
		MaxDormancyDays: policy.MaxDormancyDays,
	}); err != nil {
		s.logger.Error("Failed to encode refresh policy", "error", logging.SanitizeLogValue(err.Error()))
	}
}

// handleSetRefreshPolicy handles PUT /api/v1/tenants/{tenant_path}/refresh-policy.
func (s *Server) handleSetRefreshPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["tenant_path"]

	// Cross-tenant: a scoped caller may only write policy for their own tenant hierarchy.
	callerTenant := callerTenantFilter(r.Context())
	if callerTenant != "" { //architecture:allow-root-scope -- tenant-path route; requirePermission's boundary gate applies the crossing to a root caller
		if !s.tenantSubtreeContains(r.Context(), callerTenant, tenantID) {
			s.writeStatusError(w, http.StatusNotFound, "tenant not found")
			return
		}
	}

	var req AdminRefreshPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeStatusError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	switch req.Mode {
	case "auto_accept", "require_approval", "reject":
	default:
		s.writeStatusError(w, http.StatusBadRequest, "invalid mode: must be auto_accept, require_approval, or reject")
		return
	}

	if s.refreshPolicyStore == nil {
		s.writeStatusError(w, http.StatusServiceUnavailable, "refresh policy store unavailable")
		return
	}

	policy := &business.RefreshPolicy{
		TenantID:        tenantID,
		Mode:            req.Mode,
		MaxDormancyDays: req.MaxDormancyDays,
	}
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	details := map[string]interface{}{
		"tenant_id": tenantID,
		"new_mode":  req.Mode,
	}
	if req.MaxDormancyDays != nil {
		details["new_max_dormancy_days"] = *req.MaxDormancyDays
	}
	if old, getErr := s.refreshPolicyStore.GetPolicy(r.Context(), tenantID); getErr == nil && old != nil {
		details["old_mode"] = old.Mode
		if old.MaxDormancyDays != nil {
			details["old_max_dormancy_days"] = *old.MaxDormancyDays
		}
	}
	if err := s.refreshPolicyStore.SetPolicy(r.Context(), policy); err != nil {
		s.logger.Error("Failed to set refresh policy", "tenant_id", logging.SanitizeLogValue(tenantID), "error", logging.SanitizeLogValue(err.Error()))
		s.emitOperatorAudit(r, principal, tenantID, business.AuditEventConfiguration,
			"refresh_policy.changed", "refresh_policy", tenantID,
			business.AuditResultFailure, business.AuditSeverityHigh, details)
		s.writeStatusError(w, http.StatusInternalServerError, "failed to set refresh policy")
		return
	}

	s.emitOperatorAudit(r, principal, tenantID, business.AuditEventConfiguration,
		"refresh_policy.changed", "refresh_policy", tenantID,
		business.AuditResultSuccess, business.AuditSeverityHigh, details)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(AdminRefreshPolicyResponse{
		TenantID:        tenantID,
		Mode:            req.Mode,
		MaxDormancyDays: req.MaxDormancyDays,
	}); err != nil {
		s.logger.Error("Failed to encode refresh policy response", "error", logging.SanitizeLogValue(err.Error()))
	}
}

// unauthenticatedRefreshActor is the fixed audit actor for refresh events
// emitted before the steward record is resolved.
const unauthenticatedRefreshActor = "unauthenticated-refresh"

// emitUnauthenticatedRefreshAudit records a refresh audit event for a request
// whose device could not be resolved. Nothing the caller supplied is trusted
// as identity: the event lands in the system tenant under a fixed actor, and the
// asserted device ID and tenant are carried only as sanitized detail fields.
func (s *Server) emitUnauthenticatedRefreshAudit(
	ctx context.Context,
	assertedDeviceID, assertedTenantID string,
	eventType business.AuditEventType,
	action string,
	result business.AuditResult,
	severity business.AuditSeverity,
	extras map[string]interface{},
) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(audit.SystemTenantID).
		Type(eventType).
		Action(action).
		User(unauthenticatedRefreshActor, business.AuditUserTypeSystem).
		Resource("steward", "unresolved", "").
		Result(result).
		Severity(severity).
		Detail("asserted_device_id", logging.SanitizeLogValue(assertedDeviceID)).
		Detail("asserted_tenant_id", logging.SanitizeLogValue(assertedTenantID))
	for k, v := range extras {
		b = b.Detail(k, v)
	}
	auditCtx, cancel := detachedAuditContext(ctx)
	defer cancel()
	if err := s.auditManager.RecordEvent(auditCtx, b); err != nil {
		s.logger.Warn("Failed to emit refresh audit event", "error", logging.SanitizeLogValue(err.Error()), "action", action)
	}
}

// emitRefreshAudit records a registration-refresh audit event.
// It is a no-op when auditManager is nil.
// Must be called BEFORE WriteHeader on every code path.
func (s *Server) emitRefreshAudit(
	ctx context.Context,
	deviceID, tenantID string,
	eventType business.AuditEventType,
	action string,
	result business.AuditResult,
	severity business.AuditSeverity,
	extras map[string]interface{},
) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(eventType).
		Action(action).
		User(deviceID, business.AuditUserTypeSystem).
		Resource("steward", deviceID, "").
		Result(result).
		Severity(severity).
		Detail("device_id", deviceID).
		Detail("tenant_id", tenantID)
	for k, v := range extras {
		b = b.Detail(k, v)
	}
	auditCtx, cancel := detachedAuditContext(ctx)
	defer cancel()
	if err := s.auditManager.RecordEvent(auditCtx, b); err != nil {
		s.logger.Warn("Failed to emit refresh audit event", "error", logging.SanitizeLogValue(err.Error()), "action", action)
	}
}
