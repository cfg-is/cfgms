// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/registration"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// PoPVerifier verifies an Ed25519 proof-of-possession signature.
// Injected on the Server so tests can assert it is never called for revoked devices.
type PoPVerifier interface {
	Verify(pub ed25519.PublicKey, message, sig []byte) bool
}

// ed25519PoPVerifier is the default PoPVerifier backed by the stdlib ed25519.Verify.
type ed25519PoPVerifier struct{}

func (ed25519PoPVerifier) Verify(pub ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(pub, message, sig)
}

// nonceEntry is the value stored in the nonce cache keyed by "refresh-nonce:<device_id>".
type nonceEntry struct {
	NonceBytes []byte
	ServerTS   uint64    // Unix nanoseconds; encoded BE-uint64 in the PoP message
	IssuedAt   time.Time // wall-clock time for the 60s expiry check
}

// nonce cache constants (ADR-010 §2).
const (
	nonceCacheKeyPrefix = "refresh-nonce:"
	nonceTTL            = 65 * time.Second // cache TTL; IssuedAt check enforces 60s
	nonceMaxAge         = 60 * time.Second // enforced window for IssuedAt
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
	TenantID   string            `json:"tenant_id"`
	Nonce      string            `json:"nonce"`     // base64url nonce from challenge response
	IssuedAt   int64             `json:"issued_at"` // server_ts from challenge (Unix nanoseconds)
	Signature  string            `json:"signature"` // base64url Ed25519 sig over PoP message
	Provenance map[string]string `json:"provenance,omitempty"`
}

// RefreshCompleteResponse is returned by POST /api/v1/stewards/{device_id}/refresh/complete.
type RefreshCompleteResponse struct {
	Status    string `json:"status"`
	PendingID string `json:"pending_id,omitempty"` // set when queued for approval
	// Certificate fields: populated only on the auto-accept path
	ClientCert  string `json:"client_cert,omitempty"`
	ClientKey   string `json:"client_key,omitempty"`
	CACert      string `json:"ca_cert,omitempty"`
	SigningCert string `json:"signing_cert,omitempty"`
}

// ---- Handlers ---------------------------------------------------------------

// handleRefreshChallenge handles POST /api/v1/stewards/{device_id}/refresh/challenge.
// Revocation is the authoritative pre-nonce gate: revoked devices receive 403 before
// any nonce is generated (ADR-010 §3 revocation-before-PoP invariant).
func (s *Server) handleRefreshChallenge(w http.ResponseWriter, r *http.Request) {
	deviceID := mux.Vars(r)["device_id"]

	var req RefreshChallengeRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // body is optional; TenantID defaults to "" if absent or malformed

	if s.stewardStore == nil {
		s.emitRefreshAudit(r.Context(), deviceID, req.TenantID,
			business.AuditEventSystemEvent, "refresh_challenge_error",
			business.AuditResultError, business.AuditSeverityHigh,
			map[string]interface{}{"reason": "steward_store_unavailable"})
		http.Error(w, "steward store unavailable", http.StatusServiceUnavailable)
		return
	}

	record, err := s.stewardStore.GetStewardByDeviceID(r.Context(), deviceID)
	if err != nil {
		if err == business.ErrStewardNotFound {
			s.emitRefreshAudit(r.Context(), deviceID, req.TenantID,
				business.AuditEventSecurityEvent, "refresh_challenge_rejected",
				business.AuditResultFailure, business.AuditSeverityMedium,
				map[string]interface{}{"reason": "unknown_device"})
			http.Error(w, "device not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to look up steward by device ID", "device_id", logging.SanitizeLogValue(deviceID), "error", err)
		s.emitRefreshAudit(r.Context(), deviceID, req.TenantID,
			business.AuditEventSystemEvent, "refresh_challenge_error",
			business.AuditResultError, business.AuditSeverityHigh,
			map[string]interface{}{"reason": "store_error"})
		http.Error(w, "failed to look up device", http.StatusInternalServerError)
		return
	}

	// Revocation gate — MUST be checked before generating any nonce.
	if record.Status == business.StewardStatusRevoked {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_challenge_rejected",
			business.AuditResultDenied, business.AuditSeverityCritical,
			map[string]interface{}{"reason": "revoked"})
		http.Error(w, "device is revoked", http.StatusForbidden)
		return
	}

	// Cross-tenant isolation: request tenant must match the steward's registered tenant.
	if req.TenantID != "" && req.TenantID != record.TenantID {
		s.emitRefreshAudit(r.Context(), deviceID, req.TenantID,
			business.AuditEventSecurityEvent, "refresh_challenge_rejected",
			business.AuditResultDenied, business.AuditSeverityCritical,
			map[string]interface{}{"reason": "cross_tenant"})
		http.Error(w, "tenant mismatch", http.StatusForbidden)
		return
	}

	// Generate 32-byte cryptographically random nonce.
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		s.logger.Error("Failed to generate refresh nonce", "error", err)
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSystemEvent, "refresh_challenge_error",
			business.AuditResultError, business.AuditSeverityHigh,
			map[string]interface{}{"reason": "nonce_generation_failed"})
		http.Error(w, "failed to generate challenge", http.StatusInternalServerError)
		return
	}

	issuedAt := time.Now().UTC()
	serverTS := uint64(issuedAt.UnixNano())

	cacheKey := nonceCacheKeyPrefix + deviceID
	if err := s.nonceCache.Set(cacheKey, &nonceEntry{
		NonceBytes: nonceBytes,
		ServerTS:   serverTS,
		IssuedAt:   issuedAt,
	}, nonceTTL); err != nil {
		s.logger.Error("Failed to store nonce in cache", "error", err)
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSystemEvent, "refresh_challenge_error",
			business.AuditResultError, business.AuditSeverityHigh,
			map[string]interface{}{"reason": "cache_store_failed"})
		http.Error(w, "failed to issue challenge", http.StatusInternalServerError)
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
		s.logger.Error("Failed to encode challenge response", "error", err)
	}
}

// handleRefreshComplete handles POST /api/v1/stewards/{device_id}/refresh/complete.
// Gate order (ADR-010 §3): (1) lookup, (2) revocation, (3) nonce, (4) IssuedAt,
// (5) consume nonce, (6) PoP verify, (7) lifecycle policy, (8) issue cert or queue.
// Audit is emitted before WriteHeader on every outcome.
func (s *Server) handleRefreshComplete(w http.ResponseWriter, r *http.Request) {
	deviceID := mux.Vars(r)["device_id"]

	var req RefreshCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if s.stewardStore == nil {
		http.Error(w, "steward store unavailable", http.StatusServiceUnavailable)
		return
	}

	// Gate (1): lookup → 404
	record, err := s.stewardStore.GetStewardByDeviceID(r.Context(), deviceID)
	if err != nil {
		if err == business.ErrStewardNotFound {
			s.emitRefreshAudit(r.Context(), deviceID, req.TenantID,
				business.AuditEventSecurityEvent, "refresh_rejected",
				business.AuditResultFailure, business.AuditSeverityMedium,
				map[string]interface{}{"reason": "unknown_device"})
			http.Error(w, "device not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to look up steward by device ID", "device_id", logging.SanitizeLogValue(deviceID), "error", err)
		s.emitRefreshAudit(r.Context(), deviceID, req.TenantID,
			business.AuditEventSystemEvent, "refresh_error",
			business.AuditResultError, business.AuditSeverityHigh,
			map[string]interface{}{"reason": "store_error"})
		http.Error(w, "failed to look up device", http.StatusInternalServerError)
		return
	}

	// Gate (2): revocation — PoPVerifier must NEVER be called for revoked devices.
	if record.Status == business.StewardStatusRevoked {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultDenied, business.AuditSeverityCritical,
			map[string]interface{}{"reason": "revoked"})
		http.Error(w, "device is revoked", http.StatusForbidden)
		return
	}

	// Cross-tenant isolation before any nonce operations.
	if req.TenantID != "" && req.TenantID != record.TenantID {
		s.emitRefreshAudit(r.Context(), deviceID, req.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultDenied, business.AuditSeverityCritical,
			map[string]interface{}{"reason": "cross_tenant"})
		http.Error(w, "tenant mismatch", http.StatusForbidden)
		return
	}

	// Gate (3): nonce absent or expired → 401
	cacheKey := nonceCacheKeyPrefix + deviceID
	raw, found := s.nonceCache.Get(cacheKey)
	if !found {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultFailure, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "nonce_not_found"})
		http.Error(w, "challenge expired or not found", http.StatusUnauthorized)
		return
	}
	nonce, ok := raw.(*nonceEntry)
	if !ok {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSystemEvent, "refresh_error",
			business.AuditResultError, business.AuditSeverityHigh,
			map[string]interface{}{"reason": "nonce_type_error"})
		http.Error(w, "internal error reading challenge", http.StatusInternalServerError)
		return
	}

	// Gate (4): IssuedAt > 60s → 401
	issuedAtTime := time.Unix(0, req.IssuedAt)
	if time.Since(issuedAtTime) > nonceMaxAge {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultFailure, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "nonce_expired_issuedAt"})
		http.Error(w, "challenge nonce has expired", http.StatusUnauthorized)
		return
	}

	// Gate (5): consume nonce — deleted regardless of subsequent result.
	s.nonceCache.Delete(cacheKey)

	// Decode nonce bytes from base64url.
	nonceBytes, err := base64.RawURLEncoding.DecodeString(req.Nonce)
	if err != nil {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultFailure, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "invalid_nonce_encoding"})
		http.Error(w, "invalid nonce encoding", http.StatusUnauthorized)
		return
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(req.Signature)
	if err != nil {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultFailure, business.AuditSeverityMedium,
			map[string]interface{}{"reason": "invalid_signature_encoding"})
		http.Error(w, "invalid signature encoding", http.StatusUnauthorized)
		return
	}

	// Gate (6): PoP verify — message = sha256(nonce_bytes || device_id_utf8 || server_ts_be_uint64)
	if len(record.IdentityKeyPub) != ed25519.PublicKeySize {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultDenied, business.AuditSeverityHigh,
			map[string]interface{}{"reason": "no_identity_key"})
		http.Error(w, "device has no identity key registered", http.StatusForbidden)
		return
	}

	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], nonce.ServerTS)
	h := sha256.New()
	h.Write(nonceBytes)
	h.Write([]byte(deviceID))
	h.Write(tsBytes[:])
	popMsg := h.Sum(nil)

	if !s.popVerifier.Verify(ed25519.PublicKey(record.IdentityKeyPub), popMsg, sigBytes) {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultFailure, business.AuditSeverityCritical,
			map[string]interface{}{"reason": "invalid_pop"})
		http.Error(w, "proof-of-possession verification failed", http.StatusUnauthorized)
		return
	}

	// Gate (7): lifecycle gate
	switch record.Status {
	case business.StewardStatusArchived:
		// Archived: add pending refresh and return 202 — policy is skipped.
		s.handleRefreshQueueEntry(w, r, record, deviceID, req.Provenance, 0, 0, "archived")

	default:
		// active / registered / dormant / lost / deregistered — consult policy.
		if s.refreshPolicyStore == nil {
			// No policy store: default to require_approval.
			s.handleRefreshQueueEntry(w, r, record, deviceID, req.Provenance, 0, 0, "no_policy_store")
			return
		}
		policy, err := s.refreshPolicyStore.GetPolicy(r.Context(), record.TenantID)
		if err != nil {
			s.logger.Error("Failed to get refresh policy", "tenant_id", logging.SanitizeLogValue(record.TenantID), "error", err)
			s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
				business.AuditEventSystemEvent, "refresh_error",
				business.AuditResultError, business.AuditSeverityHigh,
				map[string]interface{}{"reason": "policy_store_error"})
			http.Error(w, "failed to get refresh policy", http.StatusInternalServerError)
			return
		}
		s.handleRefreshByPolicy(w, r, record, deviceID, req.Provenance, policy)
	}
}

// handleRefreshByPolicy applies the per-tenant policy gate for non-archived stewards.
func (s *Server) handleRefreshByPolicy(
	w http.ResponseWriter, r *http.Request,
	record *business.StewardRecord, deviceID string,
	provenance map[string]string, policy *business.RefreshPolicy,
) {
	switch policy.Mode {
	case "reject":
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSecurityEvent, "refresh_rejected",
			business.AuditResultDenied, business.AuditSeverityHigh,
			map[string]interface{}{"reason": "policy_reject", "decision": "rejected"})
		http.Error(w, "refresh rejected by tenant policy", http.StatusForbidden)

	case "auto_accept":
		pm := registration.ProvenanceMatcher{}
		result := pm.FuzzyMatch(record.LastProvenanceJSON, provenance)
		if result.Score < registration.ProvenanceMatchThreshold {
			// Demote to require_approval (demote-only invariant).
			s.handleRefreshQueueEntry(w, r, record, deviceID, provenance,
				result.MatchedFields, result.TotalFields, "auto_accept_demoted")
			return
		}
		// Sufficient provenance: issue new certificate immediately.
		resp, err := s.buildRefreshClaimResponse(r.Context(), record)
		if err != nil {
			s.logger.Error("Failed to issue refresh certificate", "steward_id", record.ID, "error", err)
			s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
				business.AuditEventSystemEvent, "refresh_error",
				business.AuditResultError, business.AuditSeverityHigh,
				map[string]interface{}{"reason": "cert_issuance_failed"})
			http.Error(w, "failed to issue certificate", http.StatusInternalServerError)
			return
		}
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventAuthentication, "refresh_cert_issued",
			business.AuditResultSuccess, business.AuditSeverityHigh,
			map[string]interface{}{
				"decision":       "approved",
				"matched_fields": result.MatchedFields,
				"total_fields":   result.TotalFields,
			})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			s.logger.Error("Failed to encode refresh complete response", "error", err)
		}

	default: // require_approval (and unknown modes)
		s.handleRefreshQueueEntry(w, r, record, deviceID, provenance, 0, 0, "require_approval")
	}
}

// handleRefreshQueueEntry writes a pending refresh record and responds with 202.
func (s *Server) handleRefreshQueueEntry(
	w http.ResponseWriter, r *http.Request,
	record *business.StewardRecord, deviceID string,
	_ map[string]string, matchedFields, totalFields int, reason string,
) {
	if s.pendingRefreshStore == nil {
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSystemEvent, "refresh_error",
			business.AuditResultError, business.AuditSeverityHigh,
			map[string]interface{}{"reason": "pending_store_unavailable"})
		http.Error(w, "pending refresh store unavailable", http.StatusServiceUnavailable)
		return
	}

	pendingID := fmt.Sprintf("refresh-%d", time.Now().UnixNano())
	entry := &business.PendingRefreshEntry{
		PendingID:               pendingID,
		DeviceID:                deviceID,
		TenantID:                record.TenantID,
		SourceIP:                extractSourceIP(r, s.trustedProxies),
		ProvenanceMatchedFields: matchedFields,
		ProvenanceTotalFields:   totalFields,
		Status:                  business.PendingRefreshStatusPending,
		CreatedAt:               time.Now().UTC(),
		ExpiresAt:               time.Now().UTC().Add(7 * 24 * time.Hour),
	}
	if err := s.pendingRefreshStore.AddPendingRefresh(r.Context(), entry); err != nil {
		s.logger.Error("Failed to add pending refresh", "steward_id", record.ID, "error", err)
		s.emitRefreshAudit(r.Context(), deviceID, record.TenantID,
			business.AuditEventSystemEvent, "refresh_error",
			business.AuditResultError, business.AuditSeverityHigh,
			map[string]interface{}{"reason": "pending_store_write_failed"})
		http.Error(w, "failed to queue refresh request", http.StatusInternalServerError)
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
	if err := json.NewEncoder(w).Encode(RefreshCompleteResponse{
		Status:    "queued",
		PendingID: pendingID,
	}); err != nil {
		s.logger.Error("Failed to encode refresh queued response", "error", err)
	}
}

// buildRefreshClaimResponse generates a new mTLS certificate for a steward that has
// passed the registration-refresh gate. Mirrors the cert issuance in buildClaimResponse.
func (s *Server) buildRefreshClaimResponse(ctx context.Context, record *business.StewardRecord) (*RefreshCompleteResponse, error) {
	if s.certManager == nil {
		return nil, fmt.Errorf("certificate manager not initialized")
	}

	validityDays := 365
	if s.cfg.Certificate != nil && s.cfg.Certificate.ClientCertValidityDays > 0 {
		validityDays = s.cfg.Certificate.ClientCertValidityDays
	}

	clientCert, err := s.certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   record.ID,
		Organization: "CFGMS Stewards",
		ClientID:     record.ID,
		ValidityDays: validityDays,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate client certificate: %w", err)
	}

	caCert, err := s.certManager.GetCACertificate()
	if err != nil || len(caCert) == 0 {
		return nil, fmt.Errorf("CA certificate unavailable: %w", err)
	}

	resp := &RefreshCompleteResponse{
		Status:     "approved",
		ClientCert: string(clientCert.CertificatePEM),
		ClientKey:  string(clientCert.PrivateKeyPEM),
		CACert:     string(caCert),
	}

	if signingCertPEM, sigErr := s.certManager.GetSigningCertificate(); sigErr == nil && len(signingCertPEM) > 0 {
		resp.SigningCert = string(signingCertPEM)
	}

	// Promote steward back to registered status after cert issuance.
	if s.controllerService != nil {
		if err := s.controllerService.UpdateStewardStatus(record.ID, "registered"); err != nil {
			s.logger.Warn("Failed to update steward status after refresh cert issuance",
				"steward_id", record.ID, "error", err)
		}
	}

	s.logger.Info("Issued refresh certificate",
		"steward_id", record.ID,
		"validity_days", validityDays)

	return resp, nil
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
	ClientKey   string `json:"client_key,omitempty"`
	CACert      string `json:"ca_cert,omitempty"`
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
	PendingID               string    `json:"pending_id"`
	DeviceID                string    `json:"device_id"`
	TenantID                string    `json:"tenant_id"`
	SourceIP                string    `json:"source_ip"`
	ProvenanceMatchedFields int       `json:"provenance_matched_fields"`
	ProvenanceTotalFields   int       `json:"provenance_total_fields"`
	Status                  string    `json:"status"`
	CreatedAt               time.Time `json:"created_at"`
	ExpiresAt               time.Time `json:"expires_at"`
}

// ---- Admin handlers ----------------------------------------------------------

// handleListPendingRefreshes handles GET /api/v1/stewards/refresh/pending.
// Requires "refresh:list-pending" permission.
func (s *Server) handleListPendingRefreshes(w http.ResponseWriter, r *http.Request) {
	if s.pendingRefreshStore == nil {
		http.Error(w, "pending refresh store unavailable", http.StatusServiceUnavailable)
		return
	}

	// TenantID is always taken from the authenticated context for scoped callers;
	// unscoped admins (TenantID=="") may use the query param to filter.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	tenantID := callerTenant
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}

	entries, err := s.pendingRefreshStore.ListPendingRefresh(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("Failed to list pending refreshes", "error", err)
		http.Error(w, "failed to list pending refreshes", http.StatusInternalServerError)
		return
	}

	out := make([]APIPendingRefreshEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, APIPendingRefreshEntry{
			PendingID:               e.PendingID,
			DeviceID:                e.DeviceID,
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
		http.Error(w, "pending refresh store unavailable", http.StatusServiceUnavailable)
		return
	}

	entry, err := s.pendingRefreshStore.GetPendingRefreshByID(r.Context(), pendingID)
	if err != nil {
		if err == business.ErrPendingRefreshNotFound {
			http.Error(w, "pending refresh not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to get pending refresh", "pending_id", logging.SanitizeLogValue(pendingID), "error", err)
		http.Error(w, "failed to get pending refresh", http.StatusInternalServerError)
		return
	}

	if entry.Status != business.PendingRefreshStatusPending {
		http.Error(w, "refresh request is not in pending state", http.StatusConflict)
		return
	}

	// Cross-tenant: a scoped caller may only approve refreshes within their tenant hierarchy.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" {
		sameTenant := entry.TenantID == callerTenant
		ancestorTenant := strings.HasPrefix(entry.TenantID, callerTenant+"/")
		if !sameTenant && !ancestorTenant {
			// 404 to avoid disclosing existence of pending refreshes across tenants.
			http.Error(w, "pending refresh not found", http.StatusNotFound)
			return
		}
	}

	if s.stewardStore == nil {
		http.Error(w, "steward store unavailable", http.StatusServiceUnavailable)
		return
	}

	record, err := s.stewardStore.GetStewardByDeviceID(r.Context(), entry.DeviceID)
	if err != nil {
		if err == business.ErrStewardNotFound {
			s.emitRefreshAudit(r.Context(), entry.DeviceID, entry.TenantID,
				business.AuditEventSystemEvent, "refresh_admin_approve_error",
				business.AuditResultError, business.AuditSeverityHigh,
				map[string]interface{}{"pending_id": logging.SanitizeLogValue(pendingID), "reason": "steward_not_found"})
			http.Error(w, "steward not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to get steward for refresh approval", "device_id", logging.SanitizeLogValue(entry.DeviceID), "error", err)
		s.emitRefreshAudit(r.Context(), entry.DeviceID, entry.TenantID,
			business.AuditEventSystemEvent, "refresh_admin_approve_error",
			business.AuditResultError, business.AuditSeverityHigh,
			map[string]interface{}{"pending_id": logging.SanitizeLogValue(pendingID), "reason": "store_error"})
		http.Error(w, "failed to get steward", http.StatusInternalServerError)
		return
	}

	certResp, err := s.buildRefreshClaimResponse(r.Context(), record)
	if err != nil {
		s.logger.Error("Failed to build refresh cert for approval", "pending_id", logging.SanitizeLogValue(pendingID), "error", err)
		s.emitRefreshAudit(r.Context(), entry.DeviceID, entry.TenantID,
			business.AuditEventSystemEvent, "refresh_admin_approve_error",
			business.AuditResultError, business.AuditSeverityHigh,
			map[string]interface{}{"pending_id": logging.SanitizeLogValue(pendingID), "reason": "cert_issuance_failed"})
		http.Error(w, "failed to issue certificate", http.StatusInternalServerError)
		return
	}

	bundle, err := json.Marshal(certResp)
	if err != nil {
		s.logger.Error("Failed to marshal claim bundle", "pending_id", logging.SanitizeLogValue(pendingID), "error", err)
		http.Error(w, "internal error serializing cert bundle", http.StatusInternalServerError)
		return
	}

	if err := s.pendingRefreshStore.StoreClaimBundle(r.Context(), pendingID, bundle); err != nil {
		s.logger.Error("Failed to store claim bundle", "pending_id", logging.SanitizeLogValue(pendingID), "error", err)
		http.Error(w, "failed to store claim bundle", http.StatusInternalServerError)
		return
	}

	if err := s.pendingRefreshStore.UpdateRefreshStatus(r.Context(), pendingID, business.PendingRefreshStatusApproved); err != nil {
		s.logger.Error("Failed to update refresh status to approved", "pending_id", logging.SanitizeLogValue(pendingID), "error", err)
		http.Error(w, "failed to update refresh status", http.StatusInternalServerError)
		return
	}

	s.emitRefreshAudit(r.Context(), entry.DeviceID, entry.TenantID,
		business.AuditEventAuthentication, "refresh_admin_approved",
		business.AuditResultSuccess, business.AuditSeverityHigh,
		map[string]interface{}{
			"pending_id": logging.SanitizeLogValue(pendingID),
			"device_id":  logging.SanitizeLogValue(entry.DeviceID),
			"tenant_id":  logging.SanitizeLogValue(entry.TenantID),
			"decision":   "approved",
			"reason":     logging.SanitizeLogValue(req.Reason),
		})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(AdminRefreshApproveResponse{
		Status:      "approved",
		PendingID:   pendingID,
		ClientCert:  certResp.ClientCert,
		ClientKey:   certResp.ClientKey,
		CACert:      certResp.CACert,
		SigningCert: certResp.SigningCert,
	}); err != nil {
		s.logger.Error("Failed to encode approve response", "error", err)
	}
}

// handleRejectRefresh handles POST /api/v1/stewards/refresh/{pending_id}/reject.
// Sets status to rejected and emits an audit event.
func (s *Server) handleRejectRefresh(w http.ResponseWriter, r *http.Request) {
	pendingID := mux.Vars(r)["pending_id"]

	var req AdminRefreshRejectRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	if s.pendingRefreshStore == nil {
		http.Error(w, "pending refresh store unavailable", http.StatusServiceUnavailable)
		return
	}

	entry, err := s.pendingRefreshStore.GetPendingRefreshByID(r.Context(), pendingID)
	if err != nil {
		if err == business.ErrPendingRefreshNotFound {
			http.Error(w, "pending refresh not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to get pending refresh for rejection", "pending_id", logging.SanitizeLogValue(pendingID), "error", err)
		http.Error(w, "failed to get pending refresh", http.StatusInternalServerError)
		return
	}

	if entry.Status != business.PendingRefreshStatusPending {
		http.Error(w, "refresh request is not in pending state", http.StatusConflict)
		return
	}

	// Cross-tenant: a scoped caller may only reject refreshes within their tenant hierarchy.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" {
		sameTenant := entry.TenantID == callerTenant
		ancestorTenant := strings.HasPrefix(entry.TenantID, callerTenant+"/")
		if !sameTenant && !ancestorTenant {
			http.Error(w, "pending refresh not found", http.StatusNotFound)
			return
		}
	}

	if err := s.pendingRefreshStore.UpdateRefreshStatus(r.Context(), pendingID, business.PendingRefreshStatusRejected); err != nil {
		s.logger.Error("Failed to update refresh status to rejected", "pending_id", logging.SanitizeLogValue(pendingID), "error", err)
		http.Error(w, "failed to update refresh status", http.StatusInternalServerError)
		return
	}

	s.emitRefreshAudit(r.Context(), entry.DeviceID, entry.TenantID,
		business.AuditEventSecurityEvent, "refresh_admin_rejected",
		business.AuditResultDenied, business.AuditSeverityMedium,
		map[string]interface{}{
			"pending_id": logging.SanitizeLogValue(pendingID),
			"device_id":  logging.SanitizeLogValue(entry.DeviceID),
			"tenant_id":  logging.SanitizeLogValue(entry.TenantID),
			"decision":   "rejected",
			"reason":     logging.SanitizeLogValue(req.Reason),
		})

	w.WriteHeader(http.StatusOK)
}

// handleGetRefreshPolicy handles GET /api/v1/tenants/{id}/refresh-policy.
func (s *Server) handleGetRefreshPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]

	// Cross-tenant: a scoped caller may only read policy for their own tenant hierarchy.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" {
		sameTenant := tenantID == callerTenant
		ancestorTenant := strings.HasPrefix(tenantID, callerTenant+"/")
		if !sameTenant && !ancestorTenant {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
	}

	if s.refreshPolicyStore == nil {
		http.Error(w, "refresh policy store unavailable", http.StatusServiceUnavailable)
		return
	}

	policy, err := s.refreshPolicyStore.GetPolicy(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("Failed to get refresh policy", "tenant_id", logging.SanitizeLogValue(tenantID), "error", err)
		http.Error(w, "failed to get refresh policy", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(AdminRefreshPolicyResponse{
		TenantID:        policy.TenantID,
		Mode:            policy.Mode,
		MaxDormancyDays: policy.MaxDormancyDays,
	}); err != nil {
		s.logger.Error("Failed to encode refresh policy", "error", err)
	}
}

// handleSetRefreshPolicy handles PUT /api/v1/tenants/{id}/refresh-policy.
func (s *Server) handleSetRefreshPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]

	// Cross-tenant: a scoped caller may only write policy for their own tenant hierarchy.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" {
		sameTenant := tenantID == callerTenant
		ancestorTenant := strings.HasPrefix(tenantID, callerTenant+"/")
		if !sameTenant && !ancestorTenant {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
	}

	var req AdminRefreshPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	switch req.Mode {
	case "auto_accept", "require_approval", "reject":
	default:
		http.Error(w, "invalid mode: must be auto_accept, require_approval, or reject", http.StatusBadRequest)
		return
	}

	if s.refreshPolicyStore == nil {
		http.Error(w, "refresh policy store unavailable", http.StatusServiceUnavailable)
		return
	}

	policy := &business.RefreshPolicy{
		TenantID:        tenantID,
		Mode:            req.Mode,
		MaxDormancyDays: req.MaxDormancyDays,
	}
	if err := s.refreshPolicyStore.SetPolicy(r.Context(), policy); err != nil {
		s.logger.Error("Failed to set refresh policy", "tenant_id", logging.SanitizeLogValue(tenantID), "error", err)
		http.Error(w, "failed to set refresh policy", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(AdminRefreshPolicyResponse{
		TenantID:        tenantID,
		Mode:            req.Mode,
		MaxDormancyDays: req.MaxDormancyDays,
	}); err != nil {
		s.logger.Error("Failed to encode refresh policy response", "error", err)
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
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit refresh audit event", "error", err, "action", action)
	}
}
