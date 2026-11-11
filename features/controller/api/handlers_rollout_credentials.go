// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	// metadataKeyCredentialKind is the secret-store record metadata key that holds an
	// API key's durable kind (Issue #6066). The literal appears in this file only, and
	// handleCreateRolloutCredential is the only code that writes it
	// (TestCredentialKindWrittenOnlyByRolloutCredentialRoute). Other code reads it
	// through this constant.
	metadataKeyCredentialKind = "credential_kind"

	// credentialKindRollout marks the scoped rollout credential.
	credentialKindRollout = "rollout"

	// rolloutCredentialMaxExpiry is the longest lifetime a rollout credential may be
	// minted with: 90 days. A longer requested expiry is refused with 400. The
	// credential can publish binaries and start fleet-wide rollouts, so it is short
	// lived and re-minted with a presence tap rather than left standing.
	rolloutCredentialMaxExpiry = 90 * 24 * time.Hour

	rolloutCredentialDefaultName = "rollout-credential"
	rolloutCredentialMaxNameLen  = 128
	rolloutCredentialMaxBody     = 1 << 10

	rolloutCredentialAuditAction = "rollout_credential_created"
)

// rolloutCredentialPermissions is the exact permission set of a rollout credential:
// start and halt rollouts and dispatch and roll back upgrades, read their status,
// publish steward binaries and post deploy markers. The request cannot add or remove
// any of them.
var rolloutCredentialPermissions = []string{
	"installer:dispatch:steward",
	"installer:read",
	"installer:publish:steward",
	"monitoring:write-markers",
}

// rolloutCredentialRequest is the POST body. Unknown fields (a permission list, a tenant,
// a credential_kind) are refused, not ignored.
type rolloutCredentialRequest struct {
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// isRolloutCredential reports whether the principal authenticated with a key minted by
// POST /api/v1/rollout-credentials. It reads the durable kind on the key record and
// never the permission list: a key with the same four permissions minted any other way,
// or a superset of them, is not a rollout credential.
func isRolloutCredential(p *Principal) bool {
	return p != nil && p.CredentialKind == credentialKindRollout
}

// handleCreateRolloutCredential handles POST /api/v1/rollout-credentials
// (rollout-credential:create: Strong with a presence tap, no machine access).
//
// The caller must itself hold all four credential permissions, as handleCreateAPIKey
// requires for any key it mints (Issue #4334). The key belongs to the caller's own
// tenant, expires within rolloutCredentialMaxExpiry, and its plaintext is returned
// once. It is minted by the same helper as every other API key, with the kind as the
// one extra metadata field.
func (s *Server) handleCreateRolloutCredential(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal == nil || principal.ID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	for _, p := range rolloutCredentialPermissions {
		if !s.hasPermission(principal, p) {
			s.writeErrorResponse(w, http.StatusForbidden,
				"Cannot grant a permission you do not hold: "+p, "PERMISSION_ESCALATION")
			return
		}
	}

	req, expiresAt, ok := s.decodeRolloutCredentialRequest(w, r)
	if !ok {
		return
	}
	tenantID, ok := callerOwnTenant(r.Context())
	if !ok {
		s.writeErrorResponse(w, http.StatusForbidden, "No tenant scope", "NO_TENANT_SCOPE")
		return
	}
	if s.auditManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Audit trail not available", "SERVICE_UNAVAILABLE")
		return
	}

	minted, err := s.mintAPIKey(r.Context(), apiKeyMintSpec{
		Name:          req.Name,
		Permissions:   append([]string(nil), rolloutCredentialPermissions...),
		TenantID:      tenantID,
		ExpiresAt:     &expiresAt,
		ExtraMetadata: map[string]string{metadataKeyCredentialKind: credentialKindRollout},
	})
	if err != nil {
		s.writeMintAPIKeyError(w, err)
		return
	}
	s.auditRolloutCredentialCreated(r, principal, minted.apiKey)
	s.writeResponse(w, http.StatusCreated, APIKeyCreateResult{
		APIKeyInfo: apiKeyInfoFromCache(minted.apiKey),
		Key:        minted.plaintext,
	})
}

// auditRolloutCredentialCreated logs and audits a minted rollout credential: the
// principal, the key id and the expiry. The plaintext is never recorded.
func (s *Server) auditRolloutCredentialCreated(r *http.Request, principal *Principal, key *APIKey) {
	s.logger.Info("Created rollout credential",
		"id", logging.SanitizeLogValue(key.ID),
		"name", logging.SanitizeLogValue(key.Name),
		"tenant_id", logging.SanitizeLogValue(key.TenantID))
	s.emitOperatorAudit(r, principal, auditTenantOrSystem(key.TenantID), business.AuditEventSecurityEvent,
		rolloutCredentialAuditAction, "api_key", key.ID,
		business.AuditResultSuccess, business.AuditSeverityHigh,
		map[string]interface{}{
			"principal":  principal.ID,
			"key_id":     key.ID,
			"expires_at": key.ExpiresAt.UTC().Format(time.RFC3339),
		})
}

// decodeRolloutCredentialRequest reads and validates the POST body: one JSON object
// with no unknown fields, a name within its length bound (defaulted when empty), and an
// expires_at in the future and no later than rolloutCredentialMaxExpiry from now. It
// writes the response and returns false when the body is rejected.
func (s *Server) decodeRolloutCredentialRequest(w http.ResponseWriter, r *http.Request) (rolloutCredentialRequest, time.Time, bool) {
	var req rolloutCredentialRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, rolloutCredentialMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return req, time.Time{}, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return req, time.Time{}, false
	}
	if req.Name == "" {
		req.Name = rolloutCredentialDefaultName
	}
	if utf8.RuneCountInString(req.Name) > rolloutCredentialMaxNameLen {
		s.writeErrorResponse(w, http.StatusBadRequest, "name is too long", "INVALID_REQUEST")
		return req, time.Time{}, false
	}
	if req.ExpiresAt == nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "expires_at is required", "MISSING_EXPIRY")
		return req, time.Time{}, false
	}
	now := s.apiKeyNow()
	expiresAt := req.ExpiresAt.UTC()
	if !expiresAt.After(now) {
		s.writeErrorResponse(w, http.StatusBadRequest, "expires_at must be in the future", "INVALID_EXPIRY")
		return req, time.Time{}, false
	}
	if expiresAt.After(now.Add(rolloutCredentialMaxExpiry)) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"expires_at is later than the maximum rollout credential lifetime of "+rolloutCredentialMaxExpiry.String(), "EXPIRY_TOO_LONG")
		return req, time.Time{}, false
	}
	return req, expiresAt, true
}
