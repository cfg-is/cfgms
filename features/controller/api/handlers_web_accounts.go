// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2490: web-admin credential store.
// Issue #2993: password removed — accounts are now passkey-only (ADR-021 Amendment 1).
// Issue #2974: account-create mints a single-use TTL-bounded enrollment magic link (step-up gated).
//
// Accounts back the browser passkey login (ADR-018 addendum, ADR-021): the store holds
// the account identity and registered WebAuthn credentials, persisted durably through the
// central pkg/secrets seam — the same seam API keys use (handlers_apikeys.go) — with the
// in-memory map as cache only. Provisioning is Tier-3 (admin mTLS only).
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ErrInvalidWebCredential is the uniform verification failure sentinel. Kept for
// backward compatibility with any callers that check for this error type.
var ErrInvalidWebCredential = errors.New("invalid credentials")

const (
	// webAccountSecretType is the distinct MetadataKeySecretType value for
	// web-admin account records in the central secret store.
	webAccountSecretType = "web_account"

	// webAccountKeyPrefix namespaces web-account records in the secret store,
	// mirroring how API-key records use their hash as the key.
	webAccountKeyPrefix = "web-account-"

	// enrollmentTokenBytes is the random source length for enrollment magic links.
	// 20 bytes = 160 bits of entropy — exceeds the >=128-bit requirement (Issue #2974).
	enrollmentTokenBytes = 20
)

// webUsernameRegex keeps usernames log- and path-safe (security A4.1): usernames
// appear in DELETE /api/v1/web/accounts/{username} URL paths, which are logged.
// 3..64 characters, starting alphanumeric; then alphanumerics, '.', '_', '-'.
var webUsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$`)

// webAccount is a web-admin account record.
// Accounts carry the same principal fields the session path builds (Principal):
// they are RBAC-equivalent to API-key principals (ADR-014 §7 parity), NOT
// implicit global admins.
//
// RootScope: true means this account has no tenant restriction (TenantID == "").
// It must be set explicitly at creation — an empty TenantID alone never grants
// root scope (defense-in-depth; Issue #2919).
//
// Credentials holds registered WebAuthn passkeys / FIDO2 credentials (Issue #2782).
// These are public keys — they are stored in the same secrets-store record as the
// account identity (one persistence path per account). See WebAuthnCredential.
type webAccount struct {
	ID          string
	Username    string
	TenantID    string
	RootScope   bool // true when TenantID == "" by explicit grant (Issue #2919)
	Permissions []string
	CreatedAt   time.Time
	Credentials []WebAuthnCredential // Issue #2782: registered WebAuthn credentials (public keys only)
	// Issue #2974: enrollment magic link (minted on create; #2966 redeems it).
	// EnrollmentLinkHash stores the SHA-256 hex digest of the raw token — never the plaintext.
	// EnrollmentLinkExpiresAt is zero when no outstanding link exists.
	// EnrollmentLinkRevoked is true after an admin explicitly revokes the link.
	EnrollmentLinkHash      string
	EnrollmentLinkExpiresAt time.Time
	EnrollmentLinkRevoked   bool
}

// WebAccountRequest is the POST /api/v1/web/accounts body. The same endpoint
// creates a new account or resets an existing one (upsert): on reset, omitted
// tenant_id/permissions are retained from the existing record.
//
// root_scope and tenant_id are mutually exclusive. Setting root_scope:true grants
// cross-tenant visibility; an explicit tenant_id scopes to that subtree. If neither
// is set on creation the account defaults to "default" (backward-compat); on reset
// the existing scope is retained.
//
// ResetCredentials is the admin-mediated reset of ADR-021 Amendment 1 Decision 4:
// it re-provisions an existing account to the zero-authenticator state, discarding
// every registered passkey, so that a fresh enrollment magic link may be minted.
// It is the only way to obtain a new link for an account that already holds a
// passkey — Decision 3 states "no magic link is involved after the first passkey".
type WebAccountRequest struct {
	Username         string   `json:"username"`
	TenantID         string   `json:"tenant_id,omitempty"`
	RootScope        bool     `json:"root_scope,omitempty"` // Issue #2919: explicit root grant
	Permissions      []string `json:"permissions,omitempty"`
	ResetCredentials bool     `json:"reset_credentials,omitempty"` // Issue #2974: ADR-021 Am.1 Decision 4
}

// WebAccountInfo is the response shape for account list and identity. It never
// carries any secret material. HasOutstandingEnrollmentLink is true when an
// unredeemed, non-expired, non-revoked link exists for the account (Issue #2974).
type WebAccountInfo struct {
	ID                           string    `json:"id"`
	Username                     string    `json:"username"`
	TenantID                     string    `json:"tenant_id"`
	RootScope                    bool      `json:"root_scope"` // Issue #2919
	Permissions                  []string  `json:"permissions"`
	CreatedAt                    time.Time `json:"created_at"`
	HasOutstandingEnrollmentLink bool      `json:"has_outstanding_enrollment_link"` // Issue #2974
}

// WebAccountCreateResponse is returned by POST /api/v1/web/accounts only.
// EnrollmentMagicLink is the single-use, TTL-bounded token shown exactly once
// to the admin for out-of-band handoff (Issue #2974). It is never stored in
// plaintext and is not present in list or subsequent responses. It is absent
// when no link was minted — an account that already holds a passkey gets none
// (ADR-021 Amendment 1 Decision 3).
type WebAccountCreateResponse struct {
	WebAccountInfo
	// EnrollmentMagicLink is the raw token (>=128-bit random, hex-encoded).
	// Shown once in the admin UI for copy-to-clipboard; not logged or audited.
	EnrollmentMagicLink string `json:"enrollment_magic_link,omitempty"`
}

// webAccountStorageTenant returns the tenant key to use in the secret store
// for a web account. Root-scoped accounts (logicalTenantID == "") are stored
// under the system sentinel because the secret store requires non-empty TenantID.
// The metadata field "root_scope" is the authoritative indicator; this mapping is
// only for storage routing (Issue #2919).
func webAccountStorageTenant(logicalTenantID string) string {
	if logicalTenantID == "" {
		return audit.SystemTenantID
	}
	return logicalTenantID
}

// --- input validation (security A4.1) ---

func validateWebUsername(username string) error {
	if !webUsernameRegex.MatchString(username) {
		return fmt.Errorf("username must be 3-64 characters: alphanumerics, '.', '_', '-', starting with an alphanumeric")
	}
	return nil
}

// --- account store: in-memory cache over the central secret store ---

// webAccountStoreKey returns the secret-store lookup key for a web account.
// The key is an identifier (prefix + username), never credential material.
func webAccountStoreKey(username string) string {
	return webAccountKeyPrefix + username
}

// cacheWebAccount inserts acct into the in-memory cache (lazy-init under s.mu).
func (s *Server) cacheWebAccount(acct *webAccount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.webAccounts == nil {
		s.webAccounts = make(map[string]*webAccount)
	}
	s.webAccounts[acct.Username] = acct
}

// getWebAccount returns the account for username from the cache, falling back to
// the central secret store on a miss (so accounts survive controller restart).
// Returns (nil, nil) when the account does not exist.
func (s *Server) getWebAccount(ctx context.Context, username string) (*webAccount, error) {
	s.mu.RLock()
	acct := s.webAccounts[username]
	s.mu.RUnlock()
	if acct != nil {
		return acct, nil
	}
	return s.loadWebAccountFromStore(ctx, username)
}

// getWebAccountByID resolves the durable principal ID stored in a web session
// back to its account. Session principal IDs are deliberately stable across
// account updates, so authentication middleware must not treat the ID
// as a username when loading permissions and tenant scope.
func (s *Server) getWebAccountByID(ctx context.Context, principalID string) (*webAccount, error) {
	s.mu.RLock()
	for _, acct := range s.webAccounts {
		if acct != nil && acct.ID == principalID {
			s.mu.RUnlock()
			return acct, nil
		}
	}
	s.mu.RUnlock()

	if s.secretStore == nil {
		return nil, nil
	}
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: webAccountSecretType,
			"id":                            principalID,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list web accounts by principal ID: %w", err)
	}
	if len(metas) == 0 {
		return nil, nil
	}
	username := metas[0].Metadata["username"]
	if username == "" {
		return nil, fmt.Errorf("web account for principal ID is missing username metadata")
	}
	return s.loadWebAccountFromStore(ctx, username)
}

// loadWebAccountFromStore reloads an account record from the central secret store
// and re-caches it. The tenant is not known at lookup time, so the record is
// located by metadata filter.
func (s *Server) loadWebAccountFromStore(ctx context.Context, username string) (*webAccount, error) {
	if s.secretStore == nil {
		return nil, nil
	}
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: webAccountSecretType,
			"username":                      username,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list web accounts: %w", err)
	}
	if len(metas) == 0 {
		return nil, nil
	}
	secret, err := s.secretStore.GetSecret(ctx, metas[0].TenantID+"/"+metas[0].Key)
	if err != nil {
		return nil, fmt.Errorf("failed to load web account: %w", err)
	}
	acct := &webAccount{
		ID:          secret.Metadata["id"],
		Username:    secret.Metadata["username"],
		TenantID:    secret.TenantID,
		Permissions: parsePermissions(secret.Metadata["permissions"]),
		CreatedAt:   secret.CreatedAt,
	}
	// Issue #2919: restore root-scoped accounts. They are stored under the
	// "system" sentinel tenant; the metadata flag is the authoritative marker.
	if secret.Metadata["root_scope"] == "true" {
		acct.TenantID = ""
		acct.RootScope = true
	}
	// Issue #2782: deserialize stored WebAuthn credentials (public keys; non-secret).
	if credsJSON, ok := secret.Metadata["credentials"]; ok && credsJSON != "" {
		var creds []WebAuthnCredential
		if err := json.Unmarshal([]byte(credsJSON), &creds); err == nil {
			acct.Credentials = creds
		}
	}
	// Issue #2974: restore enrollment magic link state (hash only — never plaintext).
	acct.EnrollmentLinkHash = secret.Metadata["enrollment_link_hash"]
	acct.EnrollmentLinkRevoked = secret.Metadata["enrollment_link_revoked"] == "true"
	if ts, ok := secret.Metadata["enrollment_link_expires_at"]; ok && ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			acct.EnrollmentLinkExpiresAt = t
		}
	}
	s.cacheWebAccount(acct)
	return acct, nil
}

// persistWebAccount writes the account record through the central pkg/secrets seam
// (same seam as API keys — handlers_apikeys.go). WebAuthn credentials (public keys)
// are serialized to JSON in the metadata.
func (s *Server) persistWebAccount(ctx context.Context, acct *webAccount, createdBy string) error {
	meta := map[string]string{
		secretsif.MetadataKeySecretType: webAccountSecretType,
		"id":                            acct.ID,
		"username":                      acct.Username,
		"permissions":                   serializePermissions(acct.Permissions),
		"created_at":                    acct.CreatedAt.UTC().Format(time.RFC3339),
	}
	// Issue #2919: mark root-scoped accounts so loadWebAccountFromStore can restore
	// TenantID="" on reload (the store holds them under the "system" sentinel tenant).
	if acct.RootScope {
		meta["root_scope"] = "true"
	}
	// Issue #2782: persist WebAuthn credentials (public keys) in metadata.
	if len(acct.Credentials) > 0 {
		credsJSON, err := json.Marshal(acct.Credentials)
		if err == nil {
			meta["credentials"] = string(credsJSON)
		}
	}
	// Issue #2974: persist enrollment magic link state (hash only — never plaintext).
	if acct.EnrollmentLinkHash != "" {
		meta["enrollment_link_hash"] = acct.EnrollmentLinkHash
		meta["enrollment_link_expires_at"] = acct.EnrollmentLinkExpiresAt.UTC().Format(time.RFC3339)
		if acct.EnrollmentLinkRevoked {
			meta["enrollment_link_revoked"] = "true"
		}
	}
	secretReq := &secretsif.SecretRequest{
		Key:         webAccountStoreKey(acct.Username),
		Value:       "",                                     // no secret value — accounts are passkey-only (Issue #2993)
		TenantID:    webAccountStorageTenant(acct.TenantID), // Issue #2919: sentinel for root-scope
		CreatedBy:   createdBy,
		Description: "web admin account",
		Tags:        []string{"web-account"},
		Metadata:    meta,
	}
	return s.secretStore.StoreSecret(ctx, secretReq)
}

// --- audit (founder condition 2) ---

// emitWebAccountAudit records a web-account lifecycle audit event with the
// sanitized username and the acting admin principal. No-op when auditManager is
// nil. In-package precedent: emitDecommissionAudit (handlers_stewards.go).
// details is optional extra context (delivery_method, etc.); the raw token is
// NEVER a key or value here (Issue #2974 audit requirement).
func (s *Server) emitWebAccountAudit(ctx context.Context, action, tenantID, actingPrincipalID, username string, details map[string]interface{}) {
	if s.auditManager == nil {
		return
	}
	if tenantID == "" {
		tenantID = audit.SystemTenantID
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSystemAccess).
		Action(action).
		User(actingPrincipalID, business.AuditUserTypeHuman).
		Resource("web-account", logging.SanitizeLogValue(username), "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh)
	if len(details) > 0 {
		b = b.Details(details)
	}
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit web-account audit event",
			"action", action,
			"username", logging.SanitizeLogValue(username),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// getWebAccountByEnrollmentToken finds the web account whose enrollment token hash
// matches hash(rawToken). The scan is necessary because tokens identify accounts —
// the lookup direction is token→account, not account→token. Cache is checked first;
// if not found there, the durable store is scanned.
//
// Returns (nil, nil) when no account with the given token exists. The caller MUST
// call verifyEnrollmentToken on the returned account to confirm validity, expiry, and
// revocation status — the store lookup finds by hash only and does not check liveness.
func (s *Server) getWebAccountByEnrollmentToken(ctx context.Context, rawToken string) (*webAccount, error) {
	tokenHash := hashEnrollmentToken(rawToken)

	// Check the in-memory cache first — the fresh handler path uses loadWebAccountFromStore
	// for CAS purposes, but begin can use the cache for a fast validity check.
	s.mu.RLock()
	for _, acct := range s.webAccounts {
		if acct != nil && acct.EnrollmentLinkHash == tokenHash {
			s.mu.RUnlock()
			return acct, nil
		}
	}
	s.mu.RUnlock()

	if s.secretStore == nil {
		return nil, nil
	}
	// Cache miss: scan the store by token hash. Filtering by the hash directly avoids
	// loading all accounts. An account with a consumed/expired token will still match
	// here; the caller checks validity separately via verifyEnrollmentToken.
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: webAccountSecretType,
			"enrollment_link_hash":          tokenHash,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan accounts by enrollment token: %w", err)
	}
	if len(metas) == 0 {
		return nil, nil
	}
	username := metas[0].Metadata["username"]
	if username == "" {
		return nil, fmt.Errorf("account matched by enrollment token is missing username metadata")
	}
	return s.loadWebAccountFromStore(ctx, username)
}

// --- enrollment magic link (Issue #2974) ---

// hashEnrollmentToken returns the SHA-256 hex digest of a raw enrollment token.
// Only the hash is stored — the raw token is returned to the admin once and then
// discarded. Constant-time compare is used at redemption time (#2966).
func hashEnrollmentToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// mintEnrollmentToken generates a new single-use enrollment magic link token.
// Returns the raw hex-encoded token (for the admin UI) and its SHA-256 hash
// (for durable storage). Token entropy: 20 bytes = 160 bits > 128-bit requirement.
func mintEnrollmentToken() (rawToken, tokenHash string, err error) {
	buf := make([]byte, enrollmentTokenBytes)
	if _, err = rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("failed to generate enrollment token: %w", err)
	}
	rawToken = hex.EncodeToString(buf)
	tokenHash = hashEnrollmentToken(rawToken)
	return rawToken, tokenHash, nil
}

// enrollmentLinkOutstanding reports whether acct has an outstanding (non-expired,
// non-revoked) enrollment link. This is exposed in list responses so admins can see
// which accounts are still awaiting first-passkey enrollment.
func enrollmentLinkOutstanding(acct *webAccount) bool {
	return acct.EnrollmentLinkHash != "" &&
		!acct.EnrollmentLinkRevoked &&
		!acct.EnrollmentLinkExpiresAt.IsZero() &&
		time.Now().Before(acct.EnrollmentLinkExpiresAt)
}

// verifyEnrollmentToken performs constant-time comparison of a presented raw token
// against the stored hash. Returns true only when the presented token is valid,
// unexpired, and not revoked — satisfying the constant-time compare requirement.
// Called at redemption time (#2966) when the recipient presents the link.
func verifyEnrollmentToken(acct *webAccount, presentedRaw string) bool {
	if acct == nil || !enrollmentLinkOutstanding(acct) {
		return false
	}
	presentedHash := hashEnrollmentToken(presentedRaw)
	storedHash := acct.EnrollmentLinkHash
	return subtle.ConstantTimeCompare([]byte(presentedHash), []byte(storedHash)) == 1
}

// --- handlers (Tier-3: admin mTLS only; wired in setupRouter) ---

// handleCreateWebAccount handles POST /api/v1/web/accounts (Tier-3). It creates a
// web-admin account, or resets an existing one (upsert): on reset, omitted
// tenant_id/permissions are retained. Passkeys are registered separately via the
// WebAuthn registration endpoints (Issue #2993).
func (s *Server) handleCreateWebAccount(w http.ResponseWriter, r *http.Request) {
	var req WebAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	if err := validateWebUsername(req.Username); err != nil {
		// Error text describes the rule only — never echoes the submitted value.
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_USERNAME")
		return
	}
	// root_scope and tenant_id are mutually exclusive (Issue #2919).
	if req.RootScope && req.TenantID != "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"root_scope and tenant_id are mutually exclusive", "INVALID_SCOPE")
		return
	}
	// Same permission allow-list discipline as API keys ("*" and unknown IDs rejected):
	// web accounts are RBAC-equivalent to API-key principals, not implicit admins.
	for _, p := range req.Permissions {
		if !isKnownPermission(p) {
			s.writeErrorResponse(w, http.StatusBadRequest,
				"Unknown or reserved permission ID: "+p, "INVALID_PERMISSION")
			return
		}
	}
	// go/log-injection (CWE-117) + storage-key safety: strip CR/LF from json.Decoded
	// identifier fields at the source using strings.ReplaceAll — the form CodeQL's
	// ReplaceSanitizer recognises. Runs after validateWebUsername (a mangled username
	// cannot pass the regex); TenantID has no charset guard, so this is its guard.
	req.Username = strings.ReplaceAll(strings.ReplaceAll(req.Username, "\n", ""), "\r", "")
	req.TenantID = strings.ReplaceAll(strings.ReplaceAll(req.TenantID, "\n", ""), "\r", "")

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	actingPrincipalID := ""
	if principal != nil {
		actingPrincipalID = principal.ID
	}

	existing, err := s.getWebAccount(r.Context(), req.Username)
	if err != nil {
		s.logger.Error("Failed to look up web account", "error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(req.Username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up web account", "STORE_ERROR")
		return
	}

	acct := &webAccount{
		ID:          uuid.New().String(),
		Username:    req.Username,
		TenantID:    req.TenantID,
		RootScope:   req.RootScope,
		Permissions: req.Permissions,
		CreatedAt:   time.Now().UTC(),
	}
	action := "web_account.created"
	status := http.StatusCreated
	if existing != nil {
		// Reset (upsert): keep the principal identity stable; retain omitted fields.
		acct.ID = existing.ID
		acct.CreatedAt = existing.CreatedAt
		// Retain existing scope when the reset doesn't explicitly set either field
		// (Issue #2919: an empty TenantID alone must not silently grant root scope).
		if !req.RootScope && req.TenantID == "" {
			acct.TenantID = existing.TenantID
			acct.RootScope = existing.RootScope
		}
		if acct.Permissions == nil {
			acct.Permissions = existing.Permissions
		}
		// Issue #2782: preserve registered WebAuthn credentials across account resets,
		// unless the admin explicitly re-provisions to the zero-authenticator state
		// (ADR-021 Amendment 1 Decision 4 — reset_credentials invalidates residual
		// credentials so a fresh enrollment link may be issued).
		if !req.ResetCredentials {
			acct.Credentials = existing.Credentials
		}
		action = "web_account.reset"
		status = http.StatusOK
	}
	// Resolve final scope (Issue #2919):
	//   RootScope:true  → explicit root grant; clear TenantID for uniformity
	//   TenantID != ""  → tenant-scoped (already set above)
	//   neither         → default to "default" (backward-compat; never silently root)
	if acct.RootScope {
		acct.TenantID = ""
	} else if acct.TenantID == "" {
		acct.TenantID = "default"
	}
	if acct.Permissions == nil {
		acct.Permissions = []string{}
	}

	// Issue #2974: enforce tenant-subtree scope, matching handleRevokeEnrollmentLink
	// and handleListWebAccounts. This endpoint issues a bearer enrollment credential,
	// so a tenant-scoped caller must not be able to target a username outside its own
	// subtree, nor mint a root-scoped account (root scope resolves to TenantID "",
	// which is inside no scoped caller's subtree). Both the record being replaced and
	// the requested destination scope are checked, so a reset cannot pull an
	// out-of-subtree account into the caller's tenant.
	callerTenant := s.callerTenantID(r)
	if existing != nil && !isWithinTenantScope(callerTenant, existing.TenantID) {
		s.writeErrorResponse(w, http.StatusForbidden, "Access to this account is not permitted", "FORBIDDEN")
		return
	}
	if !isWithinTenantScope(callerTenant, acct.TenantID) {
		s.writeErrorResponse(w, http.StatusForbidden, "Access to this account is not permitted", "FORBIDDEN")
		return
	}

	// If a reset moves the account to a different storage tenant, remove the old
	// record so the store never holds two live records for one username.
	if existing != nil && webAccountStorageTenant(existing.TenantID) != webAccountStorageTenant(acct.TenantID) {
		oldKey := fmt.Sprintf("%s/%s", webAccountStorageTenant(existing.TenantID), webAccountStoreKey(existing.Username))
		if delErr := s.secretStore.DeleteSecret(r.Context(), oldKey); delErr != nil {
			s.logger.Warn("Failed to delete web account record from previous tenant",
				"username", logging.SanitizeLogValue(acct.Username),
				"error", logging.SanitizeLogValue(delErr.Error()))
		}
	}

	// Issue #2974: mint a single-use, TTL-bounded enrollment magic link, but only for
	// an account in the zero-authenticator state. An enrollment link is a bearer
	// credential that registers a *first* passkey, so minting one against an account
	// that already holds passkeys would let its bearer attach an authenticator of
	// their own to a fully enrolled (possibly privileged) account. ADR-021 Amendment 1
	// Decision 3: "No magic link is involved after the first passkey"; Decision 4
	// allows a fresh link only from an admin-mediated reset that re-provisions the
	// account to zero authenticators (reset_credentials, handled above).
	//
	// Invariant established here: an outstanding link implies zero registered
	// credentials. The else-branch neutralises any residual link on an enrolled
	// account so records written before this rule converge on that invariant.
	var rawToken string
	if len(acct.Credentials) == 0 {
		tokenHash := ""
		rawToken, tokenHash, err = mintEnrollmentToken()
		if err != nil {
			s.logger.Error("Failed to mint enrollment token", "error", logging.SanitizeLogValue(err.Error()),
				"username", logging.SanitizeLogValue(acct.Username))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to mint enrollment link", "TOKEN_ERROR")
			return
		}
		acct.EnrollmentLinkHash = tokenHash
		acct.EnrollmentLinkExpiresAt = time.Now().UTC().Add(s.cfg.Registration.GetEnrollmentLinkTTL())
		acct.EnrollmentLinkRevoked = false
	} else {
		acct.EnrollmentLinkHash = existing.EnrollmentLinkHash
		acct.EnrollmentLinkExpiresAt = existing.EnrollmentLinkExpiresAt
		acct.EnrollmentLinkRevoked = existing.EnrollmentLinkHash != ""
	}

	if err := s.persistWebAccount(r.Context(), acct, actingPrincipalID); err != nil {
		s.logger.Error("Failed to persist web account to secret store", "error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(acct.Username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to persist web account", "STORE_ERROR")
		return
	}
	s.cacheWebAccount(acct)

	// Audit records account + whether a link was minted and how it is delivered.
	// The raw token is NEVER logged or audited.
	auditDetails := map[string]interface{}{"enrollment_link_minted": rawToken != ""}
	if rawToken != "" {
		auditDetails["delivery_method"] = "ui-shown"
	}
	s.emitWebAccountAudit(r.Context(), action, acct.TenantID, actingPrincipalID, acct.Username, auditDetails)
	s.logger.Info("Web admin account provisioned",
		"action", action,
		"username", logging.SanitizeLogValue(acct.Username),
		"tenant_id", logging.SanitizeLogValue(acct.TenantID),
		"root_scope", acct.TenantID == "",
		"enrollment_link_minted", rawToken != "",
		"principal_id", logging.SanitizeLogValue(actingPrincipalID))

	s.writeResponse(w, status, WebAccountCreateResponse{
		WebAccountInfo: WebAccountInfo{
			ID:                           acct.ID,
			Username:                     acct.Username,
			TenantID:                     acct.TenantID,
			RootScope:                    acct.RootScope,
			Permissions:                  acct.Permissions,
			CreatedAt:                    acct.CreatedAt,
			HasOutstandingEnrollmentLink: enrollmentLinkOutstanding(acct),
		},
		EnrollmentMagicLink: rawToken,
	})
}

// handleRevokeEnrollmentLink handles POST /api/v1/web/accounts/{username}/enrollment-link/revoke.
// It invalidates an outstanding enrollment magic link before it is redeemed — for wrong
// recipient, departed employee, or suspected token leak (Issue #2974).
func (s *Server) handleRevokeEnrollmentLink(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	if err := validateWebUsername(username); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_USERNAME")
		return
	}

	acct, err := s.getWebAccount(r.Context(), username)
	if err != nil {
		s.logger.Error("Failed to look up web account for enrollment link revoke",
			"error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up web account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Web account not found", "WEB_ACCOUNT_NOT_FOUND")
		return
	}
	// Issue #2974: enforce tenant-subtree scope before revealing any link state.
	// An out-of-subtree caller receives 403 regardless of whether a link is
	// outstanding — checking link state first would create an enrollment-state oracle.
	if !isWithinTenantScope(s.callerTenantID(r), acct.TenantID) {
		s.writeErrorResponse(w, http.StatusForbidden, "Access to this account is not permitted", "FORBIDDEN")
		return
	}
	if !enrollmentLinkOutstanding(acct) {
		s.writeErrorResponse(w, http.StatusConflict,
			"No outstanding enrollment link to revoke", "NO_OUTSTANDING_LINK")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	actingPrincipalID := ""
	if principal != nil {
		actingPrincipalID = principal.ID
	}

	// Persist a copy first, then mutate the cache — never the other way round.
	// getWebAccount hands back the pointer held in s.webAccounts, so revoking on
	// that object before the durable write would leave the cache claiming "revoked"
	// while the store still holds a live link: the retry would see no outstanding
	// link and answer 409, making revocation unrecoverable, and a restart would
	// reload the live link for the rest of its TTL. Revocation must fail closed.
	pending := *acct
	pending.EnrollmentLinkRevoked = true
	if err := s.persistWebAccount(r.Context(), &pending, actingPrincipalID); err != nil {
		s.logger.Error("Failed to persist enrollment link revocation",
			"error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to revoke enrollment link", "STORE_ERROR")
		return
	}
	// Durable write succeeded — now reflect it in the cached record. The cached
	// pointer identity is preserved so concurrent holders observe the revocation.
	s.mu.Lock()
	acct.EnrollmentLinkRevoked = true
	s.mu.Unlock()
	s.cacheWebAccount(acct)

	s.emitWebAccountAudit(r.Context(), "web_account.enrollment_link.revoked", acct.TenantID, actingPrincipalID, username,
		map[string]interface{}{"action": "revoke"})
	s.logger.Info("Enrollment magic link revoked",
		"username", logging.SanitizeLogValue(username),
		"principal_id", logging.SanitizeLogValue(actingPrincipalID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"username": username,
		"revoked":  true,
	})
}

// handleListWebAccounts handles GET /api/v1/web/accounts (requirePermission only,
// no Tier-3 wrapper — reads are categorically outside the Tier-3 surface; see
// Implementation Notes in Issue #2733). The response uses WebAccountInfo: no
// secret material is ever included.
//
// Issue #3137: results are scoped to the caller's tenant subtree. An unscoped
// mTLS admin (callerTenant == "") sees all accounts. Any other caller sees only
// accounts whose storage TenantID equals callerTenant or is a descendant of it
// (i.e. starts with callerTenant + "/"), which covers the full subtree of child
// tenants without requiring an exact-match-only TenantID filter.
func (s *Server) handleListWebAccounts(w http.ResponseWriter, r *http.Request) {
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Secret store not available", "SERVICE_UNAVAILABLE")
		return
	}

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)

	metas, err := s.secretStore.ListSecrets(r.Context(), &secretsif.SecretFilter{
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: webAccountSecretType,
		},
	})
	if err != nil {
		s.logger.Error("Failed to list web accounts", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list web accounts", "STORE_ERROR")
		return
	}

	accounts := make([]WebAccountInfo, 0, len(metas))
	for _, meta := range metas {
		// Issue #3137: enforce tenant-subtree scope. Skip accounts outside the
		// caller's subtree. Unscoped admins (callerTenant == "") see everything.
		if callerTenant != "" {
			if meta.TenantID != callerTenant && !strings.HasPrefix(meta.TenantID, callerTenant+"/") {
				continue
			}
		}

		createdAt := meta.CreatedAt
		if ts, ok := meta.Metadata["created_at"]; ok {
			if t, parseErr := time.Parse(time.RFC3339, ts); parseErr == nil {
				createdAt = t
			}
		}
		// Issue #2919: root-scoped accounts are stored under the system sentinel;
		// restore the logical empty TenantID for the response.
		rootScope := meta.Metadata["root_scope"] == "true"
		tenantID := meta.TenantID
		if rootScope {
			tenantID = ""
		}
		// Issue #2974: determine whether an outstanding enrollment link exists.
		// Check hash, expiry, and revoked flag from stored metadata.
		hasOutstandingLink := false
		if linkHash := meta.Metadata["enrollment_link_hash"]; linkHash != "" {
			notRevoked := meta.Metadata["enrollment_link_revoked"] != "true"
			if notRevoked {
				if expiryStr := meta.Metadata["enrollment_link_expires_at"]; expiryStr != "" {
					if expiry, parseErr := time.Parse(time.RFC3339, expiryStr); parseErr == nil {
						hasOutstandingLink = time.Now().Before(expiry)
					}
				}
			}
		}

		accounts = append(accounts, WebAccountInfo{
			ID:                           meta.Metadata["id"],
			Username:                     meta.Metadata["username"],
			TenantID:                     tenantID,
			RootScope:                    rootScope,
			Permissions:                  parsePermissions(meta.Metadata["permissions"]),
			CreatedAt:                    createdAt,
			HasOutstandingEnrollmentLink: hasOutstandingLink,
		})
	}

	s.writeSuccessResponse(w, accounts)
}

// handleDeleteWebAccount handles DELETE /api/v1/web/accounts/{username} (Tier-3).
// It removes the account from the in-memory cache and the central secret store.
func (s *Server) handleDeleteWebAccount(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	if err := validateWebUsername(username); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_USERNAME")
		return
	}

	acct, err := s.getWebAccount(r.Context(), username)
	if err != nil {
		s.logger.Error("Failed to look up web account", "error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up web account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Web account not found", "WEB_ACCOUNT_NOT_FOUND")
		return
	}

	s.mu.Lock()
	delete(s.webAccounts, username)
	s.mu.Unlock()

	storeKey := fmt.Sprintf("%s/%s", webAccountStorageTenant(acct.TenantID), webAccountStoreKey(username))
	if err := s.secretStore.DeleteSecret(r.Context(), storeKey); err != nil {
		s.logger.Warn("Failed to delete web account from secret store (memory cache already cleared)",
			"username", logging.SanitizeLogValue(username),
			"error", logging.SanitizeLogValue(err.Error()))
		// Continue anyway — mirrors handleDeleteAPIKey; the cache entry is gone and
		// the durable record will be unreachable once re-listed accounts are pruned.
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	actingPrincipalID := ""
	if principal != nil {
		actingPrincipalID = principal.ID
	}
	s.emitWebAccountAudit(r.Context(), "web_account.deleted", acct.TenantID, actingPrincipalID, username, nil)
	s.logger.Info("Web admin account deleted",
		"username", logging.SanitizeLogValue(username),
		"tenant_id", logging.SanitizeLogValue(acct.TenantID),
		"root_scope", acct.TenantID == "",
		"principal_id", logging.SanitizeLogValue(actingPrincipalID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"username": username,
		"deleted":  true,
	})
}
