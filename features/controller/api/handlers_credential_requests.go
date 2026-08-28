// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3717 (Epic #3711): mint/revoke enrolment tokens, lodge a signing request
// against one, list and deny pending requests, and reap both on expiry. This story's
// queue is inert — no handler here issues a certificate, binds an account, or
// collects a credential; those are later stories in the epic.
package api

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// credentialRequestSweepInterval controls how often the background sweep reaps
// expired enrolment tokens and pending credential requests (Issue #3717 AC: "removed
// by a background sweep, not only lazily on read").
const credentialRequestSweepInterval = 5 * time.Minute

// credentialRequestSweepActor is the audit UserID recorded for expiry-sweep events.
// The sweep runs with no authenticated principal, but audit.Manager.validateEntry
// rejects an empty UserID, so a fixed, non-secret sentinel identifies the actor as
// the background job rather than any human or token.
const credentialRequestSweepActor = "credential-request-expiry-sweep"

// ---- random secret generation ----------------------------------------------------

// generateRandomHexSecret returns a hex-encoded random secret of n bytes.
func generateRandomHexSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// ---- enrolment token persistence ---------------------------------------------------

func enrolmentTokenStoreKey(id string) string { return enrolmentTokenKeyPrefix + id }

// persistEnrolmentToken writes tok through the central secret store (M-AUTH-1),
// mirroring persistAccount in handlers_accounts.go. created_at and expires_at are
// duplicated into metadata (not read back from the store's own CreatedAt/ExpiresAt)
// because StoreSecret always stamps CreatedAt fresh on every call, including updates
// (spend, revoke) — the same reason accounts.go persists its own "created_at" key.
func (s *Server) persistEnrolmentToken(ctx context.Context, tok *enrolmentToken) error {
	meta := map[string]string{
		secretsif.MetadataKeySecretType: enrolmentTokenSecretType,
		"id":                            tok.ID,
		"token_hash":                    tok.TokenHash,
		"token_prefix":                  tok.TokenPrefix,
		"created_by":                    tok.CreatedBy,
		"created_at":                    tok.CreatedAt.UTC().Format(time.RFC3339),
		"expires_at":                    tok.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if tok.Revoked {
		meta["revoked"] = "true"
	}
	if tok.RevokedAt != nil {
		meta["revoked_at"] = tok.RevokedAt.UTC().Format(time.RFC3339)
	}
	if tok.SpentAt != nil {
		meta["spent_at"] = tok.SpentAt.UTC().Format(time.RFC3339)
		meta["spent_by_request_id"] = tok.SpentByRequestID
	}
	ttl := time.Until(tok.ExpiresAt)
	if ttl <= 0 {
		ttl = time.Second // already past expiry; persist briefly so the sweep can find and remove it
	}
	return s.secretStore.StoreSecret(ctx, &secretsif.SecretRequest{
		Key:         enrolmentTokenStoreKey(tok.ID),
		Value:       "", // no secret value — the hash lives in metadata, matching accounts.go
		TenantID:    tok.TenantID,
		CreatedBy:   tok.CreatedBy,
		Description: "enrolment token",
		Tags:        []string{"enrolment_token"},
		TTL:         ttl,
		Metadata:    meta,
	})
}

// enrolmentTokenFromMetadata reconstructs an enrolmentToken from a stored record.
func enrolmentTokenFromMetadata(m *secretsif.SecretMetadata) *enrolmentToken {
	tok := &enrolmentToken{
		ID:               m.Metadata["id"],
		TenantID:         m.TenantID,
		TokenHash:        m.Metadata["token_hash"],
		TokenPrefix:      m.Metadata["token_prefix"],
		CreatedBy:        m.Metadata["created_by"],
		Revoked:          m.Metadata["revoked"] == "true",
		SpentByRequestID: m.Metadata["spent_by_request_id"],
	}
	if ts := m.Metadata["created_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			tok.CreatedAt = t
		}
	}
	if ts := m.Metadata["expires_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			tok.ExpiresAt = t
		}
	}
	if ts := m.Metadata["revoked_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			tok.RevokedAt = &t
		}
	}
	if ts := m.Metadata["spent_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			tok.SpentAt = &t
		}
	}
	return tok
}

// getEnrolmentTokenByHash looks up an enrolment token by the SHA-256 hash of its raw
// value — the lookup direction the lodge endpoint needs (bearer value → record).
// IncludeExpired is set so expired-but-not-yet-swept tokens are found and rejected
// with the same uniform response as any other invalid token, rather than "not found".
func (s *Server) getEnrolmentTokenByHash(ctx context.Context, hash string) (*enrolmentToken, error) {
	if s.secretStore == nil {
		return nil, nil
	}
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Tags: []string{"enrolment_token"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: enrolmentTokenSecretType,
			"token_hash":                    hash,
		},
		IncludeExpired: true,
	})
	if err != nil {
		return nil, err
	}
	if len(metas) == 0 {
		return nil, nil
	}
	return enrolmentTokenFromMetadata(metas[0]), nil
}

// getEnrolmentTokenByID looks up an enrolment token by its server-generated ID — the
// lookup direction the revoke endpoint needs (admin-supplied ID → record).
func (s *Server) getEnrolmentTokenByID(ctx context.Context, id string) (*enrolmentToken, error) {
	if s.secretStore == nil {
		return nil, nil
	}
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Tags: []string{"enrolment_token"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: enrolmentTokenSecretType,
			"id":                            id,
		},
		IncludeExpired: true,
	})
	if err != nil {
		return nil, err
	}
	if len(metas) == 0 {
		return nil, nil
	}
	return enrolmentTokenFromMetadata(metas[0]), nil
}

func enrolmentTokenToResponse(tok *enrolmentToken, rawToken string) EnrolmentTokenResponse {
	resp := EnrolmentTokenResponse{
		ID:          tok.ID,
		Token:       rawToken,
		TokenPrefix: tok.TokenPrefix,
		TenantID:    tok.TenantID,
		CreatedAt:   tok.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt:   tok.ExpiresAt.UTC().Format(time.RFC3339),
		Revoked:     tok.Revoked,
	}
	if tok.RevokedAt != nil {
		rv := tok.RevokedAt.UTC().Format(time.RFC3339)
		resp.RevokedAt = &rv
	}
	return resp
}

// enrolmentTokenToResponseRedacted omits the raw token value — use for every
// response except the mint response, which is the one-time disclosure window.
func enrolmentTokenToResponseRedacted(tok *enrolmentToken) EnrolmentTokenResponse {
	return enrolmentTokenToResponse(tok, "")
}

// ---- pending credential request persistence ----------------------------------------

func credentialRequestStoreKey(id string) string { return credentialRequestKeyPrefix + id }

func (s *Server) persistPendingCredentialRequest(ctx context.Context, req *pendingCredentialRequest) error {
	meta := map[string]string{
		secretsif.MetadataKeySecretType: credentialRequestSecretType,
		"id":                            req.ID,
		"status":                        req.Status,
		"fingerprint":                   req.PublicKeyFingerprint,
		"csr_pem":                       req.CSRPEM,
		"source_ip":                     req.SourceIP,
		"hostname":                      req.Hostname,
		"label":                         req.Label,
		"platform":                      req.Platform,
		"purpose":                       req.Purpose,
		"created_at":                    req.CreatedAt.UTC().Format(time.RFC3339),
		"expires_at":                    req.ExpiresAt.UTC().Format(time.RFC3339),
		"collect_secret_hash":           req.CollectSecretHash,
		"enrolment_token_id":            req.EnrolmentTokenID,
	}
	if req.DeniedAt != nil {
		meta["denied_at"] = req.DeniedAt.UTC().Format(time.RFC3339)
		meta["denied_by"] = req.DeniedBy
	}
	if req.ApprovedAt != nil {
		meta["approved_at"] = req.ApprovedAt.UTC().Format(time.RFC3339)
		meta["approved_by"] = req.ApprovedBy
		meta["bound_account_id"] = req.BoundAccountID
		meta["granted_markers"] = strings.Join(req.GrantedMarkers, ",")
		if req.SelfApproved {
			meta["self_approved"] = "true"
		}
	}
	if req.CollectedAt != nil {
		meta["collected_at"] = req.CollectedAt.UTC().Format(time.RFC3339)
	}
	if req.CollectedSerial != "" {
		meta["collected_serial"] = req.CollectedSerial
	}
	ttl := time.Until(req.ExpiresAt)
	if ttl <= 0 {
		ttl = time.Second
	}
	return s.secretStore.StoreSecret(ctx, &secretsif.SecretRequest{
		Key:         credentialRequestStoreKey(req.ID),
		Value:       "",
		TenantID:    req.TenantID,
		Description: "pending credential request",
		Tags:        []string{"credential_request"},
		TTL:         ttl,
		Metadata:    meta,
	})
}

func pendingCredentialRequestFromMetadata(m *secretsif.SecretMetadata) *pendingCredentialRequest {
	req := &pendingCredentialRequest{
		ID:                   m.Metadata["id"],
		TenantID:             m.TenantID,
		Status:               m.Metadata["status"],
		PublicKeyFingerprint: m.Metadata["fingerprint"],
		CSRPEM:               m.Metadata["csr_pem"],
		SourceIP:             m.Metadata["source_ip"],
		Hostname:             m.Metadata["hostname"],
		Label:                m.Metadata["label"],
		Platform:             m.Metadata["platform"],
		Purpose:              m.Metadata["purpose"],
		CollectSecretHash:    m.Metadata["collect_secret_hash"],
		EnrolmentTokenID:     m.Metadata["enrolment_token_id"],
		CollectedSerial:      m.Metadata["collected_serial"],
		DeniedBy:             m.Metadata["denied_by"],
		ApprovedBy:           m.Metadata["approved_by"],
		BoundAccountID:       m.Metadata["bound_account_id"],
		SelfApproved:         m.Metadata["self_approved"] == "true",
	}
	if gm := m.Metadata["granted_markers"]; gm != "" {
		req.GrantedMarkers = strings.Split(gm, ",")
	}
	if ts := m.Metadata["created_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			req.CreatedAt = t
		}
	}
	if ts := m.Metadata["expires_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			req.ExpiresAt = t
		}
	}
	if ts := m.Metadata["denied_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			req.DeniedAt = &t
		}
	}
	if ts := m.Metadata["approved_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			req.ApprovedAt = &t
		}
	}
	if ts := m.Metadata["collected_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			req.CollectedAt = &t
		}
	}
	return req
}

func (s *Server) getPendingCredentialRequestByID(ctx context.Context, id string) (*pendingCredentialRequest, error) {
	if s.secretStore == nil {
		return nil, nil
	}
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Tags: []string{"credential_request"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: credentialRequestSecretType,
			"id":                            id,
		},
		IncludeExpired: true,
	})
	if err != nil {
		return nil, err
	}
	if len(metas) == 0 {
		return nil, nil
	}
	return pendingCredentialRequestFromMetadata(metas[0]), nil
}

// countPendingCredentialRequests counts live (non-expired) pending requests for
// tenantID — the outstanding-request cap denominator (Issue #3717 implementation note).
func (s *Server) countPendingCredentialRequests(ctx context.Context, tenantID string) (int, error) {
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		TenantID: tenantID,
		Tags:     []string{"credential_request"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: credentialRequestSecretType,
			"status":                        credentialRequestStatusPending,
		},
	})
	if err != nil {
		return 0, err
	}
	return len(metas), nil
}

// ---- CSR validation -----------------------------------------------------------------

// containsPrivateKeyMaterial reports whether pemData carries any PEM block whose type
// names private key material. The lodge endpoint accepts a public-key-only signing
// request; a body that also smuggles a private key is rejected outright (Issue #3717 AC).
func containsPrivateKeyMaterial(pemData string) bool {
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return false
		}
		if strings.Contains(strings.ToUpper(block.Type), "PRIVATE KEY") {
			return true
		}
	}
}

// parseAndVerifyCSR decodes a single PEM-encoded CERTIFICATE REQUEST block and
// verifies its self-signature. A CSR whose signature does not verify is rejected
// before any store write (Issue #3717 AC).
func parseAndVerifyCSR(pemData string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("no CERTIFICATE REQUEST PEM block found")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("certificate request signature verification failed: %w", err)
	}
	return csr, nil
}

// ---- handlers -------------------------------------------------------------------

// writeUniformLodgeUnauthorized rejects a lodge attempt with a single response body
// that does not distinguish an absent, unknown, revoked, expired or already-spent
// token (Issue #3717 implementation note).
func writeUniformLodgeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="cfgms-credential-requests"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// handleMintEnrolmentToken handles POST /api/v1/enrolment-tokens. Mints a single-use,
// short-lived enrolment token for tenantID; the raw value is returned exactly once.
func (s *Server) handleMintEnrolmentToken(w http.ResponseWriter, r *http.Request) {
	if checker := s.registrationLeaderStatus; checker != nil && !checker.HasLeadership() {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Secret store not available", "SERVICE_UNAVAILABLE")
		return
	}

	var req MintEnrolmentTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}
	if req.TenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant_id is required", "MISSING_TENANT")
		return
	}
	// go/log-injection + storage-key safety guard, matching handleCreateAccount.
	req.TenantID = strings.ReplaceAll(strings.ReplaceAll(req.TenantID, "\n", ""), "\r", "")

	callerTenant := s.callerTenantID(r)
	if !isWithinTenantScope(callerTenant, req.TenantID) {
		s.writeErrorResponse(w, http.StatusForbidden, "target tenant is outside caller's tenant subtree", "FORBIDDEN")
		return
	}

	rawToken, err := generateRandomHexSecret(enrolmentTokenBytes)
	if err != nil {
		s.logger.Error("Failed to generate enrolment token", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to mint enrolment token", "TOKEN_ERROR")
		return
	}

	now := time.Now().UTC()
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	createdBy := ""
	if principal != nil {
		createdBy = principal.ID
	}

	tok := &enrolmentToken{
		ID:          "et-" + uuid.New().String(),
		TenantID:    req.TenantID,
		TokenHash:   hashCredentialSecret(rawToken),
		TokenPrefix: enrolmentTokenDisplayPrefix(rawToken),
		CreatedAt:   now,
		CreatedBy:   createdBy,
		ExpiresAt:   now.Add(enrolmentTokenTTL),
	}
	if err := s.persistEnrolmentToken(r.Context(), tok); err != nil {
		s.logger.Error("Failed to persist enrolment token", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to mint enrolment token", "STORE_ERROR")
		return
	}

	s.logger.Info("Enrolment token minted",
		"token_id", logging.SanitizeLogValue(tok.ID),
		"token_prefix", logging.SanitizeLogValue(tok.TokenPrefix),
		"tenant_id", logging.SanitizeLogValue(tok.TenantID))
	s.emitCredentialRequestAudit(r.Context(), "enrolment_token.minted", tok.TenantID, createdBy,
		business.AuditUserTypeHuman, "enrolment_token", tok.ID,
		business.AuditResultSuccess, business.AuditSeverityHigh, nil)

	s.writeResponse(w, http.StatusCreated, enrolmentTokenToResponse(tok, rawToken))
}

// handleRevokeEnrolmentToken handles POST /api/v1/enrolment-tokens/{id}/revoke.
// Revokes an unspent token so it can never be used to lodge a request. A token that
// has already been spent is not revocable — its one use is already consumed.
func (s *Server) handleRevokeEnrolmentToken(w http.ResponseWriter, r *http.Request) {
	if checker := s.registrationLeaderStatus; checker != nil && !checker.HasLeadership() {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Secret store not available", "SERVICE_UNAVAILABLE")
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "id is required", "MISSING_ID")
		return
	}
	tok, err := s.getEnrolmentTokenByID(r.Context(), id)
	if err != nil {
		s.logger.Error("Failed to look up enrolment token", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up enrolment token", "STORE_ERROR")
		return
	}
	if tok == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Enrolment token not found", "TOKEN_NOT_FOUND")
		return
	}
	// Tenant subtree enforcement before any state disclosure (404, not 403 — no
	// existence disclosure across tenants), matching handleRevokeRegistrationToken.
	callerTenant := s.callerTenantID(r)
	if !isWithinTenantScope(callerTenant, tok.TenantID) {
		s.writeErrorResponse(w, http.StatusNotFound, "Enrolment token not found", "TOKEN_NOT_FOUND")
		return
	}
	if tok.SpentAt != nil {
		s.writeErrorResponse(w, http.StatusConflict, "Enrolment token has already been spent", "TOKEN_ALREADY_SPENT")
		return
	}
	if tok.Revoked {
		s.writeErrorResponse(w, http.StatusConflict, "Enrolment token is already revoked", "TOKEN_ALREADY_REVOKED")
		return
	}

	now := time.Now().UTC()
	tok.Revoked = true
	tok.RevokedAt = &now
	if err := s.persistEnrolmentToken(r.Context(), tok); err != nil {
		s.logger.Error("Failed to persist enrolment token revocation", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to revoke enrolment token", "STORE_ERROR")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	actingID := ""
	if principal != nil {
		actingID = principal.ID
	}
	s.logger.Info("Enrolment token revoked",
		"token_id", logging.SanitizeLogValue(tok.ID),
		"token_prefix", logging.SanitizeLogValue(tok.TokenPrefix))
	s.emitCredentialRequestAudit(r.Context(), "enrolment_token.revoked", tok.TenantID, actingID,
		business.AuditUserTypeHuman, "enrolment_token", tok.ID,
		business.AuditResultSuccess, business.AuditSeverityHigh, nil)

	s.writeResponse(w, http.StatusOK, enrolmentTokenToResponseRedacted(tok))
}

// handleLodgeCredentialRequest handles POST /api/v1/credential-requests/lodge.
// Unauthenticated by API key or mTLS — gated entirely on the pre-shared enrolment
// token presented as a bearer credential (Issue #3717). Registered on the base
// router, not the authenticated /api/v1 subrouter, mirroring handleRegister.
func (s *Server) handleLodgeCredentialRequest(w http.ResponseWriter, r *http.Request) {
	if checker := s.registrationLeaderStatus; checker != nil && !checker.HasLeadership() {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.secretStore == nil {
		http.Error(w, "credential request service unavailable", http.StatusServiceUnavailable)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeUniformLodgeUnauthorized(w)
		return
	}
	rawToken := strings.TrimPrefix(authHeader, "Bearer ")

	// Resolve and validate the token BEFORE any store write (Issue #3717 reference
	// shape: handleRegister). Unknown, revoked, expired and already-spent tokens all
	// take this same rejection path with a uniform body.
	tok, err := s.getEnrolmentTokenByHash(r.Context(), hashCredentialSecret(rawToken))
	if err != nil {
		s.logger.Error("Failed to look up enrolment token for lodge", "error", logging.SanitizeLogValue(err.Error()))
		writeUniformLodgeUnauthorized(w)
		return
	}
	now := time.Now().UTC()
	if !tok.valid(now) {
		// Log only the resolved store record's prefix, never a value derived from
		// the request's bearer token itself — CodeQL go/clear-text-logging flags any
		// value computed directly from the Authorization header, even a short prefix.
		if tok != nil {
			s.logger.Warn("Lodge attempted with unusable enrolment token",
				"token_prefix", logging.SanitizeLogValue(tok.TokenPrefix))
		} else {
			s.logger.Warn("Lodge attempted with unknown enrolment token")
		}
		writeUniformLodgeUnauthorized(w)
		return
	}

	var body LodgeCredentialRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
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
		s.logger.Warn("Rejected invalid certificate signing request at lodge",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid certificate signing request", "INVALID_CSR")
		return
	}

	pendingCount, err := s.countPendingCredentialRequests(r.Context(), tok.TenantID)
	if err != nil {
		s.logger.Error("Failed to count pending credential requests", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "credential request service unavailable", "STORE_ERROR")
		return
	}
	if pendingCount >= maxPendingCredentialRequestsPerTenant {
		// Refuse rather than evict — see maxPendingCredentialRequestsPerTenant.
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "pending credential request queue is full", "QUEUE_FULL")
		return
	}

	fullFingerprint, shortFingerprint := publicKeyFingerprint(csr.RawSubjectPublicKeyInfo)
	collectSecret, err := generateRandomHexSecret(collectSecretBytes)
	if err != nil {
		s.logger.Error("Failed to generate collect secret", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "credential request service unavailable", "TOKEN_ERROR")
		return
	}
	reqID := "cr-" + uuid.New().String()

	// Spend the token before persisting the pending request — it is spent the moment
	// a request is lodged against it, whether or not that request is ever approved
	// (Issue #3717 implementation note). credentialRequestMu serializes this
	// check-then-write section so two concurrent lodges on this node cannot both
	// observe an unspent token; a cross-node race under HA remains a known, accepted
	// limitation (worst case: two pending requests recorded against one token — this
	// story issues no certificate, so that is not a trust bypass).
	s.credentialRequestMu.Lock()
	freshTok, freshErr := s.getEnrolmentTokenByHash(r.Context(), hashCredentialSecret(rawToken))
	if freshErr != nil || !freshTok.valid(time.Now().UTC()) {
		s.credentialRequestMu.Unlock()
		writeUniformLodgeUnauthorized(w)
		return
	}
	spentAt := time.Now().UTC()
	freshTok.SpentAt = &spentAt
	freshTok.SpentByRequestID = reqID
	spendErr := s.persistEnrolmentToken(r.Context(), freshTok)
	s.credentialRequestMu.Unlock()
	if spendErr != nil {
		s.logger.Error("Failed to spend enrolment token", "error", logging.SanitizeLogValue(spendErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "credential request service unavailable", "STORE_ERROR")
		return
	}

	pending := &pendingCredentialRequest{
		ID:                   reqID,
		TenantID:             freshTok.TenantID,
		Status:               credentialRequestStatusPending,
		PublicKeyFingerprint: fullFingerprint,
		CSRPEM:               body.CSRPEM,
		SourceIP:             extractSourceIP(r, s.trustedProxies),
		Hostname:             body.Hostname,
		Label:                body.Label,
		Platform:             body.Platform,
		Purpose:              body.Purpose,
		CreatedAt:            now,
		ExpiresAt:            now.Add(credentialRequestTTL),
		CollectSecretHash:    hashCredentialSecret(collectSecret),
		EnrolmentTokenID:     freshTok.ID,
	}
	if err := s.persistPendingCredentialRequest(r.Context(), pending); err != nil {
		s.logger.Error("Failed to persist lodged credential request", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "credential request service unavailable", "STORE_ERROR")
		return
	}

	s.logger.Info("Credential request lodged",
		"request_id", logging.SanitizeLogValue(pending.ID),
		"tenant_id", logging.SanitizeLogValue(pending.TenantID),
		"fingerprint_short", logging.SanitizeLogValue(shortFingerprint))
	// The lodging machine holds no authenticated identity — the audit "user" is the
	// enrolment token that authorized the lodge, matching the record UserID cannot be
	// empty invariant enforced by audit.Manager.validateEntry.
	s.emitCredentialRequestAudit(r.Context(), "credential_request.lodged", pending.TenantID, freshTok.ID,
		business.AuditUserTypeSystem, "credential_request", pending.ID,
		business.AuditResultSuccess, business.AuditSeverityHigh,
		map[string]interface{}{"fingerprint_short": shortFingerprint, "source_ip": pending.SourceIP})

	s.writeResponse(w, http.StatusCreated, LodgeCredentialRequestResponse{
		RequestID:                 pending.ID,
		PublicKeyFingerprint:      fullFingerprint,
		PublicKeyFingerprintShort: shortFingerprint,
		CollectSecret:             collectSecret,
		ExpiresAt:                 pending.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// handleListCredentialRequests handles GET /api/v1/credential-requests. Lists pending
// requests scoped to the caller's tenant subtree (unscoped mTLS admins see all).
func (s *Server) handleListCredentialRequests(w http.ResponseWriter, r *http.Request) {
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Secret store not available", "SERVICE_UNAVAILABLE")
		return
	}
	callerTenant := s.callerTenantID(r)
	metas, err := s.secretStore.ListSecrets(r.Context(), &secretsif.SecretFilter{
		Tags: []string{"credential_request"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: credentialRequestSecretType,
			"status":                        credentialRequestStatusPending,
		},
	})
	if err != nil {
		s.logger.Error("Failed to list credential requests", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list credential requests", "STORE_ERROR")
		return
	}

	result := make([]PendingCredentialRequestInfo, 0, len(metas))
	for _, m := range metas {
		if callerTenant != "" {
			if m.TenantID != callerTenant && !strings.HasPrefix(m.TenantID, callerTenant+"/") {
				continue
			}
		}
		req := pendingCredentialRequestFromMetadata(m)
		result = append(result, PendingCredentialRequestInfo{
			ID:                        req.ID,
			TenantID:                  req.TenantID,
			Status:                    req.Status,
			PublicKeyFingerprint:      req.PublicKeyFingerprint,
			PublicKeyFingerprintShort: shortFingerprintFromFull(req.PublicKeyFingerprint),
			SourceIP:                  req.SourceIP,
			Hostname:                  req.Hostname,
			Label:                     req.Label,
			Platform:                  req.Platform,
			Purpose:                   req.Purpose,
			CreatedAt:                 req.CreatedAt.UTC().Format(time.RFC3339),
			ExpiresAt:                 req.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	s.writeSuccessResponse(w, result)
}

// handleDenyCredentialRequest handles POST /api/v1/credential-requests/{id}/deny.
// Marks a pending request denied so it can never later be approved or collected —
// a terminal transition (Issue #3717 AC).
func (s *Server) handleDenyCredentialRequest(w http.ResponseWriter, r *http.Request) {
	if checker := s.registrationLeaderStatus; checker != nil && !checker.HasLeadership() {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Secret store not available", "SERVICE_UNAVAILABLE")
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "id is required", "MISSING_ID")
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

	// The deny reason is optional; an absent body is not an error, mirroring
	// handleDenyRegistration. A present-but-malformed body is rejected so the
	// reason is never silently dropped.
	var body denyCredentialRequestRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body", "INVALID_JSON")
		return
	}

	now := time.Now().UTC()
	reqRecord.Status = credentialRequestStatusDenied
	reqRecord.DeniedAt = &now
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal != nil {
		reqRecord.DeniedBy = principal.ID
	}

	if err := s.persistPendingCredentialRequest(r.Context(), reqRecord); err != nil {
		s.logger.Error("Failed to persist credential request denial", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to deny credential request", "STORE_ERROR")
		return
	}

	s.logger.Info("Credential request denied",
		"request_id", logging.SanitizeLogValue(reqRecord.ID),
		"has_reason", body.Reason != "")
	s.emitCredentialRequestAudit(r.Context(), "credential_request.denied", reqRecord.TenantID, reqRecord.DeniedBy,
		business.AuditUserTypeHuman, "credential_request", reqRecord.ID,
		business.AuditResultSuccess, business.AuditSeverityHigh,
		map[string]interface{}{"reason": body.Reason})

	s.writeSuccessResponse(w, map[string]interface{}{"id": reqRecord.ID, "status": reqRecord.Status})
}

// ---- audit ------------------------------------------------------------------------

// emitCredentialRequestAudit records an audit event for a token-mint, token-revoke,
// lodge, or deny action. It is a no-op when auditManager is nil. Mirrors
// emitTokenManagementAudit / emitRegistrationManagementAudit in shape: resource
// identifiers only, never the token value or the collect secret (Issue #3717 AC).
func (s *Server) emitCredentialRequestAudit(
	ctx context.Context,
	action, tenantID, principalID string,
	userType business.AuditUserType,
	resourceType, resourceID string,
	result business.AuditResult,
	severity business.AuditSeverity,
	extras map[string]interface{},
) {
	if s.auditManager == nil {
		return
	}
	auditTenant := tenantID
	if auditTenant == "" {
		auditTenant = audit.SystemTenantID
	}
	b := audit.NewEventBuilder().
		Tenant(auditTenant).
		Type(business.AuditEventSystemAccess).
		Action(action).
		User(principalID, userType).
		Resource(resourceType, resourceID, "").
		Result(result).
		Severity(severity)
	for k, v := range extras {
		b = b.Detail(k, v)
	}
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit credential-request audit event",
			"error", logging.SanitizeLogValue(err.Error()), "action", action)
	}
}

// ---- expiry sweep -------------------------------------------------------------------

// startCredentialRequestSweep starts the background expiry sweep goroutine. Mirrors
// startAPIKeyCleanup's stop/done channel shape exactly (stopCleanup/cleanupDone),
// using its own dedicated pair so the two cleanup loops stop independently.
func (s *Server) startCredentialRequestSweep() {
	go func() {
		defer close(s.credentialRequestSweepDone)
		ticker := time.NewTicker(credentialRequestSweepInterval)
		defer ticker.Stop()

		s.logger.Info("Started credential-request expiry sweep",
			"interval", credentialRequestSweepInterval)

		for {
			select {
			case <-s.stopCredentialRequestSweep:
				return
			case <-ticker.C:
				s.sweepExpiredCredentialRequests(context.Background())
				s.sweepOrphanedCollectedCertificates(context.Background())
			}
		}
	}()
}

// sweepExpiredCredentialRequests deletes expired, unspent enrolment tokens and
// expired, still-pending credential requests. Denied requests and spent/revoked
// tokens are left in place — only records past ExpiresAt are removed here.
func (s *Server) sweepExpiredCredentialRequests(ctx context.Context) {
	if s.secretStore == nil {
		return
	}
	now := time.Now().UTC()

	tokenMetas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Tags:           []string{"enrolment_token"},
		Metadata:       map[string]string{secretsif.MetadataKeySecretType: enrolmentTokenSecretType},
		IncludeExpired: true,
	})
	if err != nil {
		s.logger.Error("Credential-request expiry sweep: failed to list enrolment tokens",
			"error", logging.SanitizeLogValue(err.Error()))
	} else {
		for _, m := range tokenMetas {
			tok := enrolmentTokenFromMetadata(m)
			if tok.SpentAt != nil || !tok.ExpiresAt.Before(now) {
				continue
			}
			if delErr := s.secretStore.DeleteSecret(ctx, m.TenantID+"/"+m.Key); delErr != nil {
				s.logger.Warn("Credential-request expiry sweep: failed to delete expired enrolment token",
					"error", logging.SanitizeLogValue(delErr.Error()))
				continue
			}
			s.emitCredentialRequestAudit(ctx, "enrolment_token.expired", tok.TenantID, credentialRequestSweepActor,
				business.AuditUserTypeSystem, "enrolment_token", tok.ID,
				business.AuditResultSuccess, business.AuditSeverityLow, nil)
		}
	}

	reqMetas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Tags: []string{"credential_request"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: credentialRequestSecretType,
			"status":                        credentialRequestStatusPending,
		},
		IncludeExpired: true,
	})
	if err != nil {
		s.logger.Error("Credential-request expiry sweep: failed to list pending requests",
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	for _, m := range reqMetas {
		req := pendingCredentialRequestFromMetadata(m)
		if !req.ExpiresAt.Before(now) {
			continue
		}
		if delErr := s.secretStore.DeleteSecret(ctx, m.TenantID+"/"+m.Key); delErr != nil {
			s.logger.Warn("Credential-request expiry sweep: failed to delete expired pending request",
				"error", logging.SanitizeLogValue(delErr.Error()))
			continue
		}
		s.emitCredentialRequestAudit(ctx, "credential_request.expired", req.TenantID, credentialRequestSweepActor,
			business.AuditUserTypeSystem, "credential_request", req.ID,
			business.AuditResultSuccess, business.AuditSeverityLow, nil)
	}
}

// sweepOrphanedCollectedCertificates revokes any certificate the collect endpoint
// (Issue #3719) signed but never finished binding to an account — the crash window
// between signAndBindCollectedCertificate's SignClientCertificateRequest call and its
// bindCertOnAccount call. A "collected" request with a recorded CollectedSerial that
// does not appear in its bound account's CertBindings is exactly that window: the
// process died (or the account changed underneath the request) after the certificate
// became durable but before the binding did. Left alone, such a certificate resolves
// through no account and would fall through extractAdminPrincipal's bootstrap fallback
// as implicit root (middleware.go, ADR-025 Amendment 3) if it happens to carry the
// admin marker — this sweep closes that window on the same interval as the expiry sweep.
func (s *Server) sweepOrphanedCollectedCertificates(ctx context.Context) {
	if s.secretStore == nil || s.certManager == nil {
		return
	}
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Tags: []string{"credential_request"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: credentialRequestSecretType,
			"status":                        credentialRequestStatusCollected,
		},
		IncludeExpired: true,
	})
	if err != nil {
		s.logger.Error("Credential-request expiry sweep: failed to list collected requests",
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	for _, m := range metas {
		req := pendingCredentialRequestFromMetadata(m)
		if req.CollectedSerial == "" || req.BoundAccountID == "" {
			continue
		}
		if s.certManager.IsRevoked(req.CollectedSerial) {
			continue
		}
		acct, err := s.getAccountByID(ctx, req.BoundAccountID)
		if err != nil {
			s.logger.Error("Credential-request expiry sweep: failed to look up bound account",
				"error", logging.SanitizeLogValue(err.Error()))
			continue
		}
		bound := false
		if acct != nil {
			for _, b := range acct.CertBindings {
				if b.Serial == req.CollectedSerial {
					bound = true
					break
				}
			}
		}
		if bound {
			continue
		}
		if revokeErr := s.certManager.Revoke(req.CollectedSerial); revokeErr != nil {
			s.logger.Error("Credential-request expiry sweep: failed to revoke orphaned collected certificate",
				"error", logging.SanitizeLogValue(revokeErr.Error()))
			continue
		}
		s.logger.Warn("Revoked orphaned collected certificate with no account binding",
			"request_id", logging.SanitizeLogValue(req.ID))
		s.emitCredentialRequestAudit(ctx, "credential_request.orphaned_certificate_revoked", req.TenantID, credentialRequestSweepActor,
			business.AuditUserTypeSystem, "credential_request", req.ID,
			business.AuditResultSuccess, business.AuditSeverityHigh, nil)
	}
}
