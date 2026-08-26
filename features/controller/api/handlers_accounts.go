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
	// accountSecretType is the distinct MetadataKeySecretType value for
	// web-admin account records in the central secret store.
	accountSecretType = "account"

	// accountKeyPrefix namespaces account records in the secret store,
	// mirroring how API-key records use their hash as the key.
	accountKeyPrefix = "account-"

	// enrollmentTokenBytes is the random source length for enrollment magic links.
	// 20 bytes = 160 bits of entropy — exceeds the >=128-bit requirement (Issue #2974).
	enrollmentTokenBytes = 20
)

// usernameRegex keeps usernames log- and path-safe (security A4.1): usernames
// appear in DELETE /api/v1/accounts/{username} URL paths, which are logged.
// 3..64 characters, starting alphanumeric; then alphanumerics, '.', '_', '-'.
var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$`)

// account is a web-admin account record.
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
//
// Disabled: true prevents login via VerifyCredential regardless of valid
// credentials. It does not remove RBAC role assignments or WebAuthn credentials
// (Issue #3126: it is a login gate, not a data-removal operation).
type account struct {
	ID           string
	Username     string
	TenantID     string
	RootScope    bool // true when TenantID == "" by explicit grant (Issue #2919)
	Permissions  []string
	Disabled     bool // Issue #3126: login gate — does not remove credentials or roles
	CreatedAt    time.Time
	Credentials  []WebAuthnCredential // Issue #2782: registered WebAuthn credentials (public keys only)
	CertBindings []CertBinding        // Issue #3578: bound mTLS admin certificates, keyed by serial
	// Issue #2974: enrollment magic link (minted on create; #2966 redeems it).
	// EnrollmentLinkHash stores the SHA-256 hex digest of the raw token — never the plaintext.
	// EnrollmentLinkExpiresAt is zero when no outstanding link exists.
	// EnrollmentLinkRevoked is true after an admin explicitly revokes the link.
	EnrollmentLinkHash      string
	EnrollmentLinkExpiresAt time.Time
	EnrollmentLinkRevoked   bool
}

// AccountRequest is the POST /api/v1/accounts body. The same endpoint
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
type AccountRequest struct {
	Username         string   `json:"username"`
	TenantID         string   `json:"tenant_id,omitempty"`
	RootScope        bool     `json:"root_scope,omitempty"` // Issue #2919: explicit root grant
	Permissions      []string `json:"permissions,omitempty"`
	ResetCredentials bool     `json:"reset_credentials,omitempty"` // Issue #2974: ADR-021 Am.1 Decision 4
}

// AccountInfo is the response shape for account list, get-one, and update. It never
// carries any secret material. HasOutstandingEnrollmentLink is true when an
// unredeemed, non-expired, non-revoked link exists for the account (Issue #2974).
// Disabled is true when the account has been administratively disabled (Issue #3126).
type AccountInfo struct {
	ID                           string    `json:"id"`
	Username                     string    `json:"username"`
	TenantID                     string    `json:"tenant_id"`
	RootScope                    bool      `json:"root_scope"` // Issue #2919
	Permissions                  []string  `json:"permissions"`
	Disabled                     bool      `json:"disabled"` // Issue #3126
	CreatedAt                    time.Time `json:"created_at"`
	HasOutstandingEnrollmentLink bool      `json:"has_outstanding_enrollment_link"` // Issue #2974
}

// AccountUpdateRequest is the PUT /api/v1/accounts/{username} body (Issue #3126).
// All fields are optional — omitted fields retain their current values, allowing
// independent update of permissions, disabled state, and credentials without
// requiring a full account record. A nil pointer means "not provided; keep
// existing value".
//
// ResetCredentials is the update-side equivalent of AccountRequest.ResetCredentials
// (ADR-021 Amendment 1 Decision 4): accounts are passkey-only, so "reset the
// password" re-provisions the account to the zero-authenticator state and mints
// a fresh enrollment magic link, exactly mirroring handleCreateAccount's
// reset path. It is independent of Permissions and Disabled.
type AccountUpdateRequest struct {
	Permissions      *[]string `json:"permissions"`
	Disabled         *bool     `json:"disabled"`
	ResetCredentials bool      `json:"reset_credentials,omitempty"`
}

// AccountUpdateResponse is returned by PUT /api/v1/accounts/{username}.
// EnrollmentMagicLink is present only when reset_credentials was set to true —
// the same single-use, TTL-bounded token minted by the create/reset path
// (Issue #2974); absent for all other update shapes since no new link is minted.
type AccountUpdateResponse struct {
	AccountInfo
	EnrollmentMagicLink string `json:"enrollment_magic_link,omitempty"`
}

// AccountCreateResponse is returned by POST /api/v1/accounts only.
// EnrollmentMagicLink is the single-use, TTL-bounded token shown exactly once
// to the admin for out-of-band handoff (Issue #2974). It is never stored in
// plaintext and is not present in list or subsequent responses. It is absent
// when no link was minted — an account that already holds a passkey gets none
// (ADR-021 Amendment 1 Decision 3).
type AccountCreateResponse struct {
	AccountInfo
	// EnrollmentMagicLink is the raw token (>=128-bit random, hex-encoded).
	// Shown once in the admin UI for copy-to-clipboard; not logged or audited.
	EnrollmentMagicLink string `json:"enrollment_magic_link,omitempty"`
}

// accountStorageTenant returns the tenant key to use in the secret store
// for an account. Root-scoped accounts (logicalTenantID == "") are stored
// under the system sentinel because the secret store requires non-empty TenantID.
// The metadata field "root_scope" is the authoritative indicator; this mapping is
// only for storage routing (Issue #2919).
func accountStorageTenant(logicalTenantID string) string {
	if logicalTenantID == "" {
		return audit.SystemTenantID
	}
	return logicalTenantID
}

// --- input validation (security A4.1) ---

func validateUsername(username string) error {
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("username must be 3-64 characters: alphanumerics, '.', '_', '-', starting with an alphanumeric")
	}
	return nil
}

// --- account store: in-memory cache over the central secret store ---

// accountStoreKey returns the secret-store lookup key for an account.
// The key is an identifier (prefix + username), never credential material.
func accountStoreKey(username string) string {
	return accountKeyPrefix + username
}

// cacheAccount inserts acct into the in-memory cache (lazy-init under s.mu).
func (s *Server) cacheAccount(acct *account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accounts == nil {
		s.accounts = make(map[string]*account)
	}
	s.accounts[acct.Username] = acct
}

// getAccount returns the account for username, re-verifying the disabled status
// from the durable store on every call — including a cache hit — so that a disable
// performed on another controller node is honoured on this node's very next request
// (Issue #3311). On a cache hit the store is queried; if the store has no entry (e.g.
// the account was injected into the cache for testing without a backing store record),
// the cached value is returned so callers are not surprised by a sudden nil.
func (s *Server) getAccount(ctx context.Context, username string) (*account, error) {
	s.mu.RLock()
	cached := s.accounts[username]
	s.mu.RUnlock()
	if cached == nil {
		return s.loadAccountFromStore(ctx, username, "")
	}
	// Issue #3311: Re-verify from the durable store on every cache hit so a status
	// change written by another controller node propagates on this node's very next
	// request. If the store returns nil (no matching record — e.g. account injected
	// into cache for tests but not persisted, or concurrently deleted), fall back to
	// the cached value so behaviour is equivalent to the pre-fix cache-hit path.
	fresh, err := s.loadAccountFromStore(ctx, username, "")
	if err != nil {
		return nil, err
	}
	if fresh != nil {
		return fresh, nil
	}
	return cached, nil
}

// getAccountByID resolves the durable principal ID stored in a web session
// back to its account. Session principal IDs are deliberately stable across
// account updates, so authentication middleware must not treat the ID
// as a username when loading permissions and tenant scope.
//
// Issue #3311: On a cache hit the disabled status is re-verified against the
// durable store, so a disable on another controller node propagates on this
// node's very next request. If the store returns no matching record (e.g. account
// was injected via cacheAccount without a backing store record, or was
// concurrently deleted), the cached value is returned so behaviour matches the
// pre-fix cache-hit path.
//
// The cache is keyed by username while this lookup is by principal ID, so the
// re-verified record is only trusted when its ID still matches the requested
// principal. A username that has been deleted and recreated resolves to a
// different principal, which must never inherit the requesting session's identity.
func (s *Server) getAccountByID(ctx context.Context, principalID string) (*account, error) {
	s.mu.RLock()
	var cached *account
	for _, acct := range s.accounts {
		if acct != nil && acct.ID == principalID {
			cached = acct
			break
		}
	}
	s.mu.RUnlock()

	if cached != nil {
		// Issue #3311: Re-verify from the durable store on every cache hit.
		// Issue #3347: Scope the first lookup to the cached account's tenant so only
		// that tenant's secrets are decrypted (the hot path).
		fresh, err := s.loadAccountFromStore(ctx, cached.Username, accountStorageTenant(cached.TenantID))
		if err != nil {
			return nil, err
		}
		if fresh == nil {
			// Scoped lookup returned nil. Two causes are possible:
			//   a) No backing store record (account injected via cacheAccount for tests,
			//      or concurrently deleted): return the cached value as before.
			//   b) Account recreated under a different tenant: the stale cache entry must
			//      NOT be returned — returning it would hand an orphaned session the old
			//      principal's permissions and tenant scope.
			// Distinguish by a follow-up unscoped reload. If the unscoped lookup also
			// returns nil (case a), return the cached account. If it finds a record, fall
			// through to the identity check below (case b).
			fresh, err = s.loadAccountFromStore(ctx, cached.Username, "")
			if err != nil {
				return nil, err
			}
			if fresh == nil {
				// Truly absent: return the cached account (e.g. test-injected or deleted).
				return cached, nil
			}
			// fresh != nil means the account moved to a different tenant; identity check follows.
		}
		if fresh.ID == principalID {
			return fresh, nil
		}
		// Identity guard: the cache is keyed by username, but this lookup is by
		// principal ID, and IDs are minted fresh on every create (uuid.New). A
		// delete-and-recreate of the same username therefore yields a record whose
		// ID differs from the one this session holds. Returning it would hand the
		// caller a different principal's permissions and tenant scope, so the
		// mismatched record is discarded here. loadAccountFromStore has already
		// replaced the stale username-keyed cache entry with what it just read, so
		// nothing stale is left behind; fall through to the authoritative
		// ID-filtered store lookup, which reports the orphaned principal as absent.
	}

	if s.secretStore == nil {
		return nil, nil
	}
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Tags: []string{"account"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: accountSecretType,
			"id":                            principalID,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list accounts by principal ID: %w", err)
	}
	if len(metas) == 0 {
		return nil, nil
	}
	username := metas[0].Metadata["username"]
	if username == "" {
		return nil, fmt.Errorf("account for principal ID is missing username metadata")
	}
	return s.loadAccountFromStore(ctx, username, metas[0].TenantID)
}

// loadAccountFromStore reloads an account record from the central secret store
// and re-caches it. The tenant is not known at lookup time, so the record is
// located by metadata filter.
//
// All account fields are stored in the ListSecrets metadata map; the secret
// Value is always empty (Issue #2993 passkey-only). Reading from the metadata
// returned by ListSecrets avoids a second GetSecret round-trip and works correctly
// for multi-level tenant IDs (e.g., root/msp-a/client-2) where GetSecret's
// single-slash key splitting would produce the wrong TenantID. ListSecrets also
// bypasses the SOPS in-process cache, so the result always reflects the latest
// on-disk state — which is the property required for cross-node propagation (Issue #3311).
func (s *Server) loadAccountFromStore(ctx context.Context, username, tenantHint string) (*account, error) {
	if s.secretStore == nil {
		return nil, nil
	}
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		TenantID: tenantHint,
		Tags:     []string{"account"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: accountSecretType,
			"username":                      username,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list accounts: %w", err)
	}
	if len(metas) == 0 {
		return nil, nil
	}
	m := metas[0]
	acct := &account{
		ID:          m.Metadata["id"],
		Username:    m.Metadata["username"],
		TenantID:    m.TenantID,
		Permissions: parsePermissions(m.Metadata["permissions"]),
		CreatedAt:   m.CreatedAt,
	}
	// Issue #2919: restore root-scoped accounts. They are stored under the
	// "system" sentinel tenant; the metadata flag is the authoritative marker.
	if m.Metadata["root_scope"] == "true" {
		acct.TenantID = ""
		acct.RootScope = true
	}
	// Issue #3126: restore the disabled flag. Absent key means not disabled.
	acct.Disabled = m.Metadata["disabled"] == "true"
	// Issue #2782: deserialize stored WebAuthn credentials (public keys; non-secret).
	if credsJSON, ok := m.Metadata["credentials"]; ok && credsJSON != "" {
		var creds []WebAuthnCredential
		if err := json.Unmarshal([]byte(credsJSON), &creds); err == nil {
			acct.Credentials = creds
		}
	}
	// Issue #3578: deserialize bound mTLS certificate bindings (public metadata; non-secret).
	if bindJSON, ok := m.Metadata["cert_bindings"]; ok && bindJSON != "" {
		var bindings []CertBinding
		if err := json.Unmarshal([]byte(bindJSON), &bindings); err == nil {
			acct.CertBindings = bindings
		}
	}
	// Issue #2974: restore enrollment magic link state (hash only — never plaintext).
	acct.EnrollmentLinkHash = m.Metadata["enrollment_link_hash"]
	acct.EnrollmentLinkRevoked = m.Metadata["enrollment_link_revoked"] == "true"
	if ts, ok := m.Metadata["enrollment_link_expires_at"]; ok && ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			acct.EnrollmentLinkExpiresAt = t
		}
	}
	s.cacheAccount(acct)
	return acct, nil
}

// persistAccount writes the account record through the central pkg/secrets seam
// (same seam as API keys — handlers_apikeys.go). WebAuthn credentials (public keys)
// are serialized to JSON in the metadata.
func (s *Server) persistAccount(ctx context.Context, acct *account, createdBy string) error {
	meta := map[string]string{
		secretsif.MetadataKeySecretType: accountSecretType,
		"id":                            acct.ID,
		"username":                      acct.Username,
		"permissions":                   serializePermissions(acct.Permissions),
		"created_at":                    acct.CreatedAt.UTC().Format(time.RFC3339),
	}
	// Issue #2919: mark root-scoped accounts so loadAccountFromStore can restore
	// TenantID="" on reload (the store holds them under the "system" sentinel tenant).
	if acct.RootScope {
		meta["root_scope"] = "true"
	}
	// Issue #3126: persist the disabled flag. Only stored when true to keep
	// metadata sparse for non-disabled accounts (omitted key == not disabled).
	if acct.Disabled {
		meta["disabled"] = "true"
	}
	// Issue #2782: persist WebAuthn credentials (public keys) in metadata.
	if len(acct.Credentials) > 0 {
		credsJSON, err := json.Marshal(acct.Credentials)
		if err == nil {
			meta["credentials"] = string(credsJSON)
		}
	}
	// Issue #3578: persist bound mTLS certificate bindings (public metadata) in metadata.
	if len(acct.CertBindings) > 0 {
		bindJSON, err := json.Marshal(acct.CertBindings)
		if err == nil {
			meta["cert_bindings"] = string(bindJSON)
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
		Key:         accountStoreKey(acct.Username),
		Value:       "",                                  // no secret value — accounts are passkey-only (Issue #2993)
		TenantID:    accountStorageTenant(acct.TenantID), // Issue #2919: sentinel for root-scope
		CreatedBy:   createdBy,
		Description: "web admin account",
		Tags:        []string{"account"},
		Metadata:    meta,
	}
	return s.secretStore.StoreSecret(ctx, secretReq)
}

// --- audit (founder condition 2) ---

// emitAccountAudit records an account lifecycle audit event with the
// sanitized username and the acting admin principal. No-op when auditManager is
// nil. In-package precedent: emitDecommissionAudit (handlers_stewards.go).
// details is optional extra context (delivery_method, etc.); the raw token is
// NEVER a key or value here (Issue #2974 audit requirement).
func (s *Server) emitAccountAudit(ctx context.Context, action, tenantID, actingPrincipalID, username string, details map[string]interface{}) {
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
		Resource("account", logging.SanitizeLogValue(username), "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh)
	if len(details) > 0 {
		b = b.Details(details)
	}
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit account audit event",
			"action", action,
			"username", logging.SanitizeLogValue(username),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// getAccountByCertSerial resolves the account whose CertBindings contains serial.
// Cache scan first (O(n)); re-verifies via the durable store on a cache hit (Issue #3311
// cross-node disable propagation). On a cache miss performs a full store scan — the same
// accepted O(n) limitation as the bind-collision scan in handleBindCert.
//
// Returns (nil, nil) when no account has serial in its CertBindings.
func (s *Server) getAccountByCertSerial(ctx context.Context, serial string) (*account, error) {
	s.mu.RLock()
	var cached *account
	for _, acct := range s.accounts {
		if acct == nil {
			continue
		}
		for _, b := range acct.CertBindings {
			if b.Serial == serial {
				cached = acct
				break
			}
		}
		if cached != nil {
			break
		}
	}
	s.mu.RUnlock()

	if cached != nil {
		fresh, err := s.loadAccountFromStore(ctx, cached.Username, accountStorageTenant(cached.TenantID))
		if err != nil {
			return nil, err
		}
		if fresh != nil {
			// Verify the serial is still in the fresh bindings — it may have been removed
			// since the cache was last populated (e.g. binding revoked via handleRevokeCertBinding).
			for _, b := range fresh.CertBindings {
				if b.Serial == serial {
					return fresh, nil
				}
			}
			// Serial no longer bound: binding removed after cache was populated.
			return nil, nil
		}
		// Store returned nil: account not persisted (test-injected) or concurrently deleted.
		return cached, nil
	}

	// Cache miss: scan all account records in the store.
	if s.secretStore == nil {
		return nil, nil
	}
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Tags: []string{"account"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: accountSecretType,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list accounts for cert serial lookup: %w", err)
	}
	for _, m := range metas {
		bindJSON, ok := m.Metadata["cert_bindings"]
		if !ok || bindJSON == "" {
			continue
		}
		var bindings []CertBinding
		if jsonErr := json.Unmarshal([]byte(bindJSON), &bindings); jsonErr != nil {
			continue
		}
		for _, b := range bindings {
			if b.Serial == serial {
				username := m.Metadata["username"]
				if username == "" {
					continue
				}
				return s.loadAccountFromStore(ctx, username, m.TenantID)
			}
		}
	}
	return nil, nil
}

// getAccountByEnrollmentToken finds the account whose enrollment token hash
// matches hash(rawToken). The scan is necessary because tokens identify accounts —
// the lookup direction is token→account, not account→token. Cache is checked first;
// if not found there, the durable store is scanned.
//
// Returns (nil, nil) when no account with the given token exists. The caller MUST
// call verifyEnrollmentToken on the returned account to confirm validity, expiry, and
// revocation status — the store lookup finds by hash only and does not check liveness.
func (s *Server) getAccountByEnrollmentToken(ctx context.Context, rawToken string) (*account, error) {
	tokenHash := hashEnrollmentToken(rawToken)

	// Check the in-memory cache first — the fresh handler path uses loadAccountFromStore
	// for CAS purposes, but begin can use the cache for a fast validity check.
	s.mu.RLock()
	for _, acct := range s.accounts {
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
			secretsif.MetadataKeySecretType: accountSecretType,
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
	return s.loadAccountFromStore(ctx, username, "")
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
func enrollmentLinkOutstanding(acct *account) bool {
	return acct.EnrollmentLinkHash != "" &&
		!acct.EnrollmentLinkRevoked &&
		!acct.EnrollmentLinkExpiresAt.IsZero() &&
		time.Now().Before(acct.EnrollmentLinkExpiresAt)
}

// verifyEnrollmentToken performs constant-time comparison of a presented raw token
// against the stored hash. Returns true only when the presented token is valid,
// unexpired, and not revoked — satisfying the constant-time compare requirement.
// Called at redemption time (#2966) when the recipient presents the link.
func verifyEnrollmentToken(acct *account, presentedRaw string) bool {
	if acct == nil || !enrollmentLinkOutstanding(acct) {
		return false
	}
	presentedHash := hashEnrollmentToken(presentedRaw)
	storedHash := acct.EnrollmentLinkHash
	return subtle.ConstantTimeCompare([]byte(presentedHash), []byte(storedHash)) == 1
}

// --- handlers (Tier-3: admin mTLS only; wired in setupRouter) ---

// handleCreateAccount handles POST /api/v1/accounts (Tier-3). It creates a
// web-admin account, or resets an existing one (upsert): on reset, omitted
// tenant_id/permissions are retained. Passkeys are registered separately via the
// WebAuthn registration endpoints (Issue #2993).
func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req AccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	if err := validateUsername(req.Username); err != nil {
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
	// accounts are RBAC-equivalent to API-key principals, not implicit admins.
	for _, p := range req.Permissions {
		if !isKnownPermission(p) {
			s.writeErrorResponse(w, http.StatusBadRequest,
				"Unknown or reserved permission ID: "+p, "INVALID_PERMISSION")
			return
		}
	}
	// go/log-injection (CWE-117) + storage-key safety: strip CR/LF from json.Decoded
	// identifier fields at the source using strings.ReplaceAll — the form CodeQL's
	// ReplaceSanitizer recognises. Runs after validateUsername (a mangled username
	// cannot pass the regex); TenantID has no charset guard, so this is its guard.
	req.Username = strings.ReplaceAll(strings.ReplaceAll(req.Username, "\n", ""), "\r", "")
	req.TenantID = strings.ReplaceAll(strings.ReplaceAll(req.TenantID, "\n", ""), "\r", "")

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	actingPrincipalID := ""
	if principal != nil {
		actingPrincipalID = principal.ID
	}

	existing, err := s.getAccount(r.Context(), req.Username)
	if err != nil {
		s.logger.Error("Failed to look up account", "error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(req.Username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up account", "STORE_ERROR")
		return
	}

	acct := &account{
		ID:          uuid.New().String(),
		Username:    req.Username,
		TenantID:    req.TenantID,
		RootScope:   req.RootScope,
		Permissions: req.Permissions,
		CreatedAt:   time.Now().UTC(),
	}
	action := "account.created"
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
		// Issue #3126: a reset must never re-enable a disabled account. Disable is a
		// containment control (an admin account suspected of takeover); persistAccount
		// rebuilds the metadata from the record it is handed, so dropping this carry-forward
		// would silently clear the "disabled" key and revive the account — with retained
		// passkeys — under an account.reset audit action that never reads as an enable.
		// Re-enabling is an explicit PUT {"disabled": false}, which emits account.enabled.
		acct.Disabled = existing.Disabled
		// Issue #3578: a reset must never drop the account's mTLS certificate bindings.
		// The bindings are what scope a bound certificate in extractAdminPrincipal; an
		// account with no bindings sends every one of its still-valid certificates back
		// to the unbound bootstrap-fallback path, which is unscoped root. persistAccount
		// rebuilds the metadata from the record it is handed and writes cert_bindings only
		// when the slice is non-empty, and cacheAccount replaces the in-memory copy, so
		// omitting this carry-forward would erase the bindings from both the durable record
		// and the cache that getAccountByCertSerial scans — turning a tenant-scoped admin's
		// own reset of their own account into root over every tenant, in one request.
		//
		// Carry-forward rather than a 409 refusal (the DELETE rule at handleDeleteAccount):
		// a reset is the takeover-containment operation — it re-provisions to the
		// zero-authenticator state and terminates live sessions — so refusing it for exactly
		// the accounts that hold admin certificates would block containment on the most
		// privileged accounts in the deployment. Unlike a delete, a reset keeps the account
		// record and its ID, so the record that scopes each binding survives; carrying the
		// slice forward closes the transition completely. A reset that also moves the
		// account's scope moves the bindings with it, and the destination scope is already
		// bounded by the caller's own subtree by the isWithinTenantScope checks below.
		acct.CertBindings = existing.CertBindings
		// Issue #2782: preserve registered WebAuthn credentials across account resets,
		// unless the admin explicitly re-provisions to the zero-authenticator state
		// (ADR-021 Amendment 1 Decision 4 — reset_credentials invalidates residual
		// credentials so a fresh enrollment link may be issued).
		if !req.ResetCredentials {
			acct.Credentials = existing.Credentials
		}
		action = "account.reset"
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
	// and handleListAccounts. This endpoint issues a bearer enrollment credential,
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
	if existing != nil && accountStorageTenant(existing.TenantID) != accountStorageTenant(acct.TenantID) {
		oldKey := fmt.Sprintf("%s/%s", accountStorageTenant(existing.TenantID), accountStoreKey(existing.Username))
		if delErr := s.secretStore.DeleteSecret(r.Context(), oldKey); delErr != nil {
			s.logger.Warn("Failed to delete account record from previous tenant",
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

	if err := s.persistAccount(r.Context(), acct, actingPrincipalID); err != nil {
		s.logger.Error("Failed to persist account to secret store", "error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(acct.Username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to persist account", "STORE_ERROR")
		return
	}
	s.cacheAccount(acct)

	// Issue #3126: a reset that re-provisions to the zero-authenticator state must also
	// terminate the account's live browser sessions. Same reasoning as the PUT path —
	// this is the takeover-containment operation, and sessions minted by the passkeys
	// being wiped would otherwise stay usable for the absolute session lifetime.
	if existing != nil && req.ResetCredentials {
		// Best-effort: account still exists, so session-revocation failure does not escalate
		// privileges (the disabled-or-absent-passkey check still rejects the session on next
		// use). Error is logged inside revokeSessionsForPrincipal.
		revoked, _ := s.revokeSessionsForPrincipal(r.Context(), acct.ID)
		s.logger.Info("Revoked live web sessions for credential reset",
			"username", logging.SanitizeLogValue(acct.Username),
			"revoked_sessions", revoked)
	}

	// Audit records account + whether a link was minted and how it is delivered.
	// The raw token is NEVER logged or audited.
	auditDetails := map[string]interface{}{"enrollment_link_minted": rawToken != ""}
	if rawToken != "" {
		auditDetails["delivery_method"] = "ui-shown"
	}
	s.emitAccountAudit(r.Context(), action, acct.TenantID, actingPrincipalID, acct.Username, auditDetails)
	s.logger.Info("Web admin account provisioned",
		"action", action,
		"username", logging.SanitizeLogValue(acct.Username),
		"tenant_id", logging.SanitizeLogValue(acct.TenantID),
		"root_scope", acct.TenantID == "",
		"enrollment_link_minted", rawToken != "",
		"principal_id", logging.SanitizeLogValue(actingPrincipalID))

	s.writeResponse(w, status, AccountCreateResponse{
		AccountInfo: AccountInfo{
			ID:                           acct.ID,
			Username:                     acct.Username,
			TenantID:                     acct.TenantID,
			RootScope:                    acct.RootScope,
			Permissions:                  acct.Permissions,
			Disabled:                     acct.Disabled, // Issue #3126: a reset retains the disable
			CreatedAt:                    acct.CreatedAt,
			HasOutstandingEnrollmentLink: enrollmentLinkOutstanding(acct),
		},
		EnrollmentMagicLink: rawToken,
	})
}

// handleRevokeEnrollmentLink handles POST /api/v1/accounts/{username}/enrollment-link/revoke.
// It invalidates an outstanding enrollment magic link before it is redeemed — for wrong
// recipient, departed employee, or suspected token leak (Issue #2974).
func (s *Server) handleRevokeEnrollmentLink(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	if err := validateUsername(username); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_USERNAME")
		return
	}

	acct, err := s.getAccount(r.Context(), username)
	if err != nil {
		s.logger.Error("Failed to look up account for enrollment link revoke",
			"error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Account not found", "ACCOUNT_NOT_FOUND")
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
	// getAccount hands back the pointer held in s.accounts, so revoking on
	// that object before the durable write would leave the cache claiming "revoked"
	// while the store still holds a live link: the retry would see no outstanding
	// link and answer 409, making revocation unrecoverable, and a restart would
	// reload the live link for the rest of its TTL. Revocation must fail closed.
	pending := *acct
	pending.EnrollmentLinkRevoked = true
	if err := s.persistAccount(r.Context(), &pending, actingPrincipalID); err != nil {
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
	s.cacheAccount(acct)

	s.emitAccountAudit(r.Context(), "account.enrollment_link.revoked", acct.TenantID, actingPrincipalID, username,
		map[string]interface{}{"action": "revoke"})
	s.logger.Info("Enrollment magic link revoked",
		"username", logging.SanitizeLogValue(username),
		"principal_id", logging.SanitizeLogValue(actingPrincipalID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"username": username,
		"revoked":  true,
	})
}

// handleListAccounts handles GET /api/v1/accounts (requirePermission only,
// no Tier-3 wrapper — reads are categorically outside the Tier-3 surface; see
// Implementation Notes in Issue #2733). The response uses AccountInfo: no
// secret material is ever included.
//
// Issue #3137: results are scoped to the caller's tenant subtree. An unscoped
// mTLS admin (callerTenant == "") sees all accounts. Any other caller sees only
// accounts whose storage TenantID equals callerTenant or is a descendant of it
// (i.e. starts with callerTenant + "/"), which covers the full subtree of child
// tenants without requiring an exact-match-only TenantID filter.
func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Secret store not available", "SERVICE_UNAVAILABLE")
		return
	}

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)

	metas, err := s.secretStore.ListSecrets(r.Context(), &secretsif.SecretFilter{
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: accountSecretType,
		},
	})
	if err != nil {
		s.logger.Error("Failed to list accounts", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list accounts", "STORE_ERROR")
		return
	}

	accounts := make([]AccountInfo, 0, len(metas))
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

		accounts = append(accounts, AccountInfo{
			ID:                           meta.Metadata["id"],
			Username:                     meta.Metadata["username"],
			TenantID:                     tenantID,
			RootScope:                    rootScope,
			Permissions:                  parsePermissions(meta.Metadata["permissions"]),
			Disabled:                     meta.Metadata["disabled"] == "true", // Issue #3126
			CreatedAt:                    createdAt,
			HasOutstandingEnrollmentLink: hasOutstandingLink,
		})
	}

	s.writeSuccessResponse(w, accounts)
}

// VerifyCredential is the login-gate enforcement point for accounts (Issue #3126).
// It is called after successful WebAuthn assertion to check whether the account may
// proceed to session issuance. Returns ErrInvalidWebCredential when the account is
// disabled — the caller must not leak whether the account is disabled vs. not found.
func (s *Server) VerifyCredential(acct *account) error {
	if acct == nil {
		return ErrInvalidWebCredential
	}
	if acct.Disabled {
		return ErrInvalidWebCredential
	}
	return nil
}

// revokeSessionsForPrincipal revokes every live web session belonging to the
// given account ID and drops the session-bound CSRF token for each
// (Issue #3126, retrofitted in Issue #3581). Returns the number of sessions revoked.
//
// The revocation path calls webSessionManager.RevokeAllForPrincipal, which queries
// the durable store directly — cluster-safe: sessions issued on other controller nodes
// are found and revoked regardless of this node's in-memory state (Issue #3581, Story 3).
//
// CSRF tokens are node-local (in-process map); a preceding List call collects the
// session IDs visible on this node so their CSRF entries can be dropped before the
// durable revocation runs. Cross-node session CSRF tokens do not exist in this map.
//
// A second pass calls mgr.Revoke on each locally-visible session. This is necessary
// because the cliMgr.RevokeAllForPrincipal step (step 3) may have already deleted the
// web sessions from the shared store, leaving this webMgr's in-memory map with sessions
// that are marked as NOT revoked. Without the individual Revoke calls, webMgr.Validate
// would still succeed for those tokens on this node until the process restarts.
//
// Returns the durable-store revocation count and any error from RevokeAllForPrincipal.
// The error matters for the offboarding cascade (caller must abort before delete on error);
// credential-reset callers may discard the error (account still exists; sessions expire).
func (s *Server) revokeSessionsForPrincipal(ctx context.Context, principalID string) (int, error) {
	if principalID == "" {
		return 0, nil
	}
	s.mu.RLock()
	mgr := s.webSessionManager
	s.mu.RUnlock()
	if mgr == nil {
		return 0, nil
	}

	// Collect locally-visible sessions for CSRF cleanup and in-memory revocation.
	var localIDs []string
	if sessions, listErr := mgr.List(ctx); listErr == nil {
		for _, sess := range sessions {
			if sess != nil && sess.PrincipalID == principalID {
				s.csrfTokens.Delete(sess.ID)
				localIDs = append(localIDs, sess.ID)
			}
		}
	} else {
		s.logger.Warn("Failed to list web sessions for CSRF cleanup; CSRF tokens for this principal may linger on this node",
			"principal_id", logging.SanitizeLogValue(principalID),
			"error", logging.SanitizeLogValue(listErr.Error()))
	}

	// RevokeAllForPrincipal queries the durable store directly — cluster-safe.
	// Returns (0, err) only when the initial ListAll fails; individual delete
	// failures are logged inside RevokeAllForPrincipal and do not stop the rest.
	revoked, err := mgr.RevokeAllForPrincipal(ctx, principalID)
	if err != nil {
		s.logger.Error("Failed to revoke all web sessions for principal",
			"principal_id", logging.SanitizeLogValue(principalID),
			"error", logging.SanitizeLogValue(err.Error()))
		return 0, err
	}

	// Mark each locally-visible session as revoked in this manager's in-memory map.
	// RevokeAllForPrincipal mirrors in-memory only for sessions it finds in the store.
	// If step 3 (cliMgr) already deleted them from the store, this ensures the
	// webMgr's in-memory state is also updated — preventing stale in-memory sessions
	// from validating on this node.
	for _, id := range localIDs {
		if revokeErr := mgr.Revoke(ctx, id); revokeErr != nil {
			s.logger.Warn("Failed to mark web session as revoked in local state",
				"session_id", logging.SanitizeLogValue(id),
				"error", logging.SanitizeLogValue(revokeErr.Error()))
		}
	}

	return revoked, nil
}

// handleGetAccount handles GET /api/v1/accounts/{username} (Issue #3126).
// Returns the account's identity and status — no secret material, no WebAuthn credentials.
// A cross-tenant caller gets 404 to avoid disclosing account existence.
func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	if err := validateUsername(username); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_USERNAME")
		return
	}

	acct, err := s.getAccount(r.Context(), username)
	if err != nil {
		s.logger.Error("Failed to look up account", "error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Account not found", "ACCOUNT_NOT_FOUND")
		return
	}

	// Issue #3126: enforce tenant-subtree scope. A cross-tenant caller gets 404 —
	// not 403 — to avoid disclosing that the account exists in another tenant.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if !isWithinTenantScope(callerTenant, acct.TenantID) {
		s.writeErrorResponse(w, http.StatusNotFound, "Account not found", "ACCOUNT_NOT_FOUND")
		return
	}

	s.writeSuccessResponse(w, AccountInfo{
		ID:                           acct.ID,
		Username:                     acct.Username,
		TenantID:                     acct.TenantID,
		RootScope:                    acct.RootScope,
		Permissions:                  acct.Permissions,
		Disabled:                     acct.Disabled,
		CreatedAt:                    acct.CreatedAt,
		HasOutstandingEnrollmentLink: enrollmentLinkOutstanding(acct),
	})
}

// handleUpdateAccount handles PUT /api/v1/accounts/{username} (Issue #3126, Tier-3).
// All request fields are optional — omitted fields retain existing values.
// A cross-tenant caller gets 404 to avoid disclosing account existence.
func (s *Server) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	if err := validateUsername(username); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_USERNAME")
		return
	}

	var req AccountUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	// Validate any provided permissions against the allow-list.
	if req.Permissions != nil {
		for _, p := range *req.Permissions {
			if !isKnownPermission(p) {
				s.writeErrorResponse(w, http.StatusBadRequest,
					"Unknown or reserved permission ID: "+p, "INVALID_PERMISSION")
				return
			}
		}
	}

	acct, err := s.getAccount(r.Context(), username)
	if err != nil {
		s.logger.Error("Failed to look up account", "error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Account not found", "ACCOUNT_NOT_FOUND")
		return
	}

	// Issue #3126: enforce tenant-subtree scope before mutating anything.
	// A cross-tenant caller gets 404 — not 403 — to avoid disclosing account existence.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if !isWithinTenantScope(callerTenant, acct.TenantID) {
		s.writeErrorResponse(w, http.StatusNotFound, "Account not found", "ACCOUNT_NOT_FOUND")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	actingPrincipalID := ""
	if principal != nil {
		actingPrincipalID = principal.ID
	}

	// Apply partial updates — only modify fields that were provided.
	updated := *acct
	if req.Permissions != nil {
		updated.Permissions = *req.Permissions
		if updated.Permissions == nil {
			updated.Permissions = []string{}
		}
	}
	disabledChanged := req.Disabled != nil && *req.Disabled != acct.Disabled
	if req.Disabled != nil {
		updated.Disabled = *req.Disabled
	}

	// Issue #3126 (review follow-up): "reset the password" in the passkey-only
	// model (ADR-021 Amendment 1) is a credential reset — re-provision to the
	// zero-authenticator state and mint a fresh enrollment link, exactly
	// mirroring handleCreateAccount's ResetCredentials path. Independent of
	// permissions/disabled changes above.
	var rawToken string
	if req.ResetCredentials {
		updated.Credentials = nil
		tokenHash := ""
		var mintErr error
		rawToken, tokenHash, mintErr = mintEnrollmentToken()
		if mintErr != nil {
			s.logger.Error("Failed to mint enrollment token", "error", logging.SanitizeLogValue(mintErr.Error()),
				"username", logging.SanitizeLogValue(username))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to mint enrollment link", "TOKEN_ERROR")
			return
		}
		updated.EnrollmentLinkHash = tokenHash
		updated.EnrollmentLinkExpiresAt = time.Now().UTC().Add(s.cfg.Registration.GetEnrollmentLinkTTL())
		updated.EnrollmentLinkRevoked = false
	}

	if err := s.persistAccount(r.Context(), &updated, actingPrincipalID); err != nil {
		s.logger.Error("Failed to persist account update", "error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update account", "STORE_ERROR")
		return
	}
	s.cacheAccount(&updated)

	// Issue #3126: both containment operations terminate the account's live browser
	// sessions. The login gate alone would leave an already-authenticated session
	// usable for the remainder of the absolute session lifetime, so containment must
	// reach sessions that already exist — authenticationMiddleware rejects any that
	// survive a revocation failure, this makes the termination immediate.
	//   - disable: the account is being taken out of service.
	//   - reset_credentials: in the passkey-only model (ADR-021 Amendment 1 Decision 4)
	//     this is the "reset the password" operation an admin reaches for on a suspected
	//     account takeover. Wiping the passkeys without cutting the sessions they already
	//     minted would leave the attacker's cookie live, so the containment operation
	//     would not contain.
	if (disabledChanged && updated.Disabled) || req.ResetCredentials {
		// Best-effort: account still exists, so session-revocation failure does not escalate
		// privileges (authentication middleware rejects future requests for the account).
		// Error is logged inside revokeSessionsForPrincipal.
		revoked, _ := s.revokeSessionsForPrincipal(r.Context(), updated.ID)
		// go/log-injection: derive from an explicit branch to a string literal so no
		// value flows from the request to the log sink (CodeQL taint-tracks request
		// booleans through struct fields regardless of type; strconv.FormatBool would
		// still count as a value-propagating conversion).
		disabledState, resetState := "false", "false"
		if updated.Disabled {
			disabledState = "true"
		}
		if req.ResetCredentials {
			resetState = "true"
		}
		s.logger.Info("Revoked live web sessions for account",
			"username", logging.SanitizeLogValue(username),
			"disabled", disabledState,
			"credentials_reset", resetState,
			"revoked_sessions", revoked)
	}

	// Emit granular audit events. A disable/enable transition and a credential reset
	// are independent operations that one request can perform together, so each emits
	// its own event: a first-match switch would let a combined request bury the
	// credential reset behind account.disabled, leaving the passkey wipe and the
	// bearer enrollment-link mint with no audit trace at all — an audit-evasion path
	// for a privileged actor. Other field changes fall back to the generic action.
	var actions []string
	if disabledChanged {
		action := "account.enabled"
		if updated.Disabled {
			action = "account.disabled"
		}
		actions = append(actions, action)
		s.emitAccountAudit(r.Context(), action, updated.TenantID, actingPrincipalID, username, nil)
	}
	if req.ResetCredentials {
		// Mirrors handleCreateAccount: minting a bearer enrollment credential records
		// that it was minted and how it is delivered (Issue #2974). The raw token is
		// NEVER logged or audited.
		actions = append(actions, "account.credentials_reset")
		s.emitAccountAudit(r.Context(), "account.credentials_reset", updated.TenantID,
			actingPrincipalID, username, map[string]interface{}{
				"enrollment_link_minted": rawToken != "",
				"delivery_method":        "ui-shown",
			})
	}
	if len(actions) == 0 {
		actions = append(actions, "account.updated")
		s.emitAccountAudit(r.Context(), "account.updated", updated.TenantID, actingPrincipalID, username, nil)
	}
	s.logger.Info("Web admin account updated",
		"actions", strings.Join(actions, ","),
		"username", logging.SanitizeLogValue(username),
		"tenant_id", logging.SanitizeLogValue(updated.TenantID),
		"principal_id", logging.SanitizeLogValue(actingPrincipalID))

	s.writeSuccessResponse(w, AccountUpdateResponse{
		AccountInfo: AccountInfo{
			ID:                           updated.ID,
			Username:                     updated.Username,
			TenantID:                     updated.TenantID,
			RootScope:                    updated.RootScope,
			Permissions:                  updated.Permissions,
			Disabled:                     updated.Disabled,
			CreatedAt:                    updated.CreatedAt,
			HasOutstandingEnrollmentLink: enrollmentLinkOutstanding(&updated),
		},
		EnrollmentMagicLink: rawToken,
	})
}

// handleDeleteAccount handles DELETE /api/v1/accounts/{username} (Tier-3).
// It executes the offboarding cascade: disable → revoke certs → revoke sessions → delete.
//
// Ordering is the safety property (Issue #3581): the account is disabled before any
// revocation attempt so that a bound certificate or live session is rejected by the
// existing disabled-account checks on its very next request, even before the revocation
// steps complete. Do not reorder steps 1–5 for convenience.
//
// Certificate revocation is best-effort per serial: all bindings are attempted even if
// one fails, but the operation stops before step 5 (delete) if any revocation could not
// be completed — leaving the account disabled and undeleted for retry. Session revocation
// (steps 3–4) calls RevokeAllForPrincipal, which is cluster-safe: sessions issued on
// other controller nodes are revoked via the shared durable store.
//
// A partial failure leaves the account in the more-restrictive state (disabled, partially
// or fully revoked) — never the less-restrictive one — so a repeated delete call is safe.
func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	if err := validateUsername(username); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_USERNAME")
		return
	}

	acct, err := s.getAccount(r.Context(), username)
	if err != nil {
		s.logger.Error("Failed to look up account", "error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Account not found", "ACCOUNT_NOT_FOUND")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	actingPrincipalID := ""
	if principal != nil {
		actingPrincipalID = principal.ID
	}

	// Step 1: disable the account first (fail-closed — the safety property, not an
	// implementation detail). A bound certificate or live session is rejected on its
	// very next request by the disabled-account check, even if steps 2–4 haven't run.
	// Copy before mutating — acct points into the in-memory cache and a concurrent
	// getAccountByCertSerial iterates s.accounts under RLock; writing a field on the
	// shared pointer without holding the write lock is a data race.
	disabled := *acct
	disabled.Disabled = true
	if err := s.persistAccount(r.Context(), &disabled, actingPrincipalID); err != nil {
		s.logger.Error("Failed to disable account before offboarding",
			"username", logging.SanitizeLogValue(username),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to disable account before offboarding", "STORE_ERROR")
		return
	}
	s.cacheAccount(&disabled)
	acct = &disabled

	// Step 2: revoke every bound certificate (best effort per serial — try all even
	// when one fails, then stop before delete if any revocation could not be completed).
	certsRevoked := 0
	var certRevokeFailed bool
	for _, binding := range acct.CertBindings {
		if s.certManager == nil {
			s.logger.Warn("Cannot revoke certificate binding: certManager not configured; account remains disabled",
				"username", logging.SanitizeLogValue(username),
				"serial", logging.SanitizeLogValue(binding.Serial))
			certRevokeFailed = true
			continue
		}
		if revokeErr := s.certManager.Revoke(binding.Serial); revokeErr != nil {
			s.logger.Warn("Failed to revoke bound certificate during account offboarding; continuing to attempt remaining certs",
				"username", logging.SanitizeLogValue(username),
				"serial", logging.SanitizeLogValue(binding.Serial),
				"error", logging.SanitizeLogValue(revokeErr.Error()))
			certRevokeFailed = true
			continue
		}
		certsRevoked++
	}
	if certRevokeFailed {
		s.logger.Error("One or more certificate revocations failed during offboarding; account is disabled but not deleted — retry to complete",
			"username", logging.SanitizeLogValue(username),
			"certs_revoked", certsRevoked,
			"binding_count", len(acct.CertBindings))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"One or more certificate revocations failed; account is disabled but not deleted",
			"CERT_REVOKE_FAILED")
		return
	}

	// Step 3: revoke all CLI Bearer sessions (cluster-safe via RevokeAllForPrincipal).
	// Abort before delete on failure: a surviving session for a deleted account would
	// resolve to acct==nil in the CLI Bearer middleware, yielding ImplicitAdmin=true.
	cliSessionsRevoked := 0
	if s.sessionManager != nil {
		revoked, revokeErr := s.sessionManager.RevokeAllForPrincipal(r.Context(), acct.ID)
		if revokeErr != nil {
			s.logger.Error("Failed to revoke CLI sessions during account offboarding; account is disabled but not deleted — retry to complete",
				"username", logging.SanitizeLogValue(username),
				"error", logging.SanitizeLogValue(revokeErr.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError,
				"One or more session revocations failed; account is disabled but not deleted",
				"SESSION_REVOKE_FAILED")
			return
		}
		cliSessionsRevoked = revoked
	}

	// Step 4: revoke all web sessions (cluster-safe via retrofitted revokeSessionsForPrincipal).
	// Abort before delete on failure — same escalation risk as step 3.
	webSessionsRevoked, webRevokeErr := s.revokeSessionsForPrincipal(r.Context(), acct.ID)
	if webRevokeErr != nil {
		s.logger.Error("Failed to revoke web sessions during account offboarding; account is disabled but not deleted — retry to complete",
			"username", logging.SanitizeLogValue(username),
			"error", logging.SanitizeLogValue(webRevokeErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"One or more session revocations failed; account is disabled but not deleted",
			"SESSION_REVOKE_FAILED")
		return
	}

	// Step 5: delete the account record. Reached only when all revocations succeeded.
	s.mu.Lock()
	delete(s.accounts, username)
	s.mu.Unlock()

	storeKey := fmt.Sprintf("%s/%s", accountStorageTenant(acct.TenantID), accountStoreKey(username))
	if delErr := s.secretStore.DeleteSecret(r.Context(), storeKey); delErr != nil {
		s.logger.Warn("Failed to delete account from secret store (memory cache already cleared)",
			"username", logging.SanitizeLogValue(username),
			"error", logging.SanitizeLogValue(delErr.Error()))
		// Continue — mirrors handleDeleteAPIKey; the cache entry is gone and
		// the durable record will be unreachable once re-listed accounts are pruned.
	}

	s.emitAccountAudit(r.Context(), "account.offboarded", acct.TenantID, actingPrincipalID, username,
		map[string]interface{}{
			"certs_revoked":        certsRevoked,
			"cli_sessions_revoked": cliSessionsRevoked,
			"web_sessions_revoked": webSessionsRevoked,
		})
	s.emitAccountAudit(r.Context(), "account.deleted", acct.TenantID, actingPrincipalID, username, nil)
	s.logger.Info("Web admin account offboarded and deleted",
		"username", logging.SanitizeLogValue(username),
		"tenant_id", logging.SanitizeLogValue(acct.TenantID),
		"root_scope", acct.TenantID == "",
		"certs_revoked", certsRevoked,
		"cli_sessions_revoked", cliSessionsRevoked,
		"web_sessions_revoked", webSessionsRevoked,
		"principal_id", logging.SanitizeLogValue(actingPrincipalID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"username": username,
		"deleted":  true,
	})
}
