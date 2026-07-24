// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2490: web-admin credential store with argon2id password verification.
// Accounts back the browser credential login (ADR-018 addendum): the store holds
// only argon2id PHC hashes (never cleartext), persisted durably through the central
// pkg/secrets seam — the same seam API keys use (handlers_apikeys.go) — with the
// in-memory map as cache only. Provisioning and reset are Tier-3 (admin mTLS only).
// Lockout ENFORCEMENT is #2493's; this file owns the per-account lockout STATE.
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/argon2"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ErrInvalidWebCredential is the uniform verification failure. Unknown-user,
// wrong-password, and malformed-input all return exactly this error so nothing in
// the error contract discloses whether a username exists (no enumeration).
var ErrInvalidWebCredential = errors.New("invalid credentials")

const (
	// webAccountSecretType is the distinct MetadataKeySecretType value for
	// web-admin account records in the central secret store.
	webAccountSecretType = "web_account"

	// webAccountKeyPrefix namespaces web-account records in the secret store,
	// mirroring how API-key records use their hash as the key.
	webAccountKeyPrefix = "web-account-"

	// Password length bounds in BYTES, validated before hashing (security A4.1).
	webPasswordMinBytes = 8
	webPasswordMaxBytes = 128

	// Lockout state (security B4.1, state half — pinned mechanism shared verbatim
	// with #2493): 5 consecutive verification failures lock the account for 15
	// minutes; a successful verification resets the counter. In-memory only,
	// resets on controller restart (consistent with the in-memory session store).
	webAccountMaxConsecutiveFailures = 5
	webAccountLockoutDuration        = 15 * time.Minute

	// argon2id production cost parameters — OWASP-recommended settings (19 MiB memory,
	// 2 iterations, 1 lane). Named *Default so tests can reference the intended
	// production values even when the active vars are overridden to minimal values
	// for CI speed (Issue #2591). TestWebAccounts_HashParametersEncodedInPHCString
	// pins these to the OWASP values.
	webArgon2TimeDefault    uint32 = 2
	webArgon2MemoryDefault  uint32 = 19 * 1024 // KiB (19 MiB)
	webArgon2ThreadsDefault uint8  = 1
	webArgon2SaltLen               = 16
	webArgon2KeyLen         uint32 = 32
)

// webArgon2Time/Memory/Threads are the active cost parameters used by hashWebPassword
// and dummyWebAccountHash. Initialized to the OWASP production defaults; the test
// suite's TestMain substitutes minimal values (t=1, 64 KiB) to avoid timeout panics
// on 2-3 vCPU hosted macOS/Windows runners where OWASP-cost argon2id ops are
// disproportionately slow under -race instrumentation (Issue #2591).
var (
	webArgon2Time    = webArgon2TimeDefault
	webArgon2Memory  = webArgon2MemoryDefault
	webArgon2Threads = webArgon2ThreadsDefault
)

// webUsernameRegex keeps usernames log- and path-safe (security A4.1): usernames
// appear in DELETE /api/v1/web/accounts/{username} URL paths, which are logged.
// 3..64 characters, starting alphanumeric; then alphanumerics, '.', '_', '-'.
var webUsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$`)

// webAccount is a web-admin account record. Only the argon2id PHC hash of the
// password is ever held — in memory and in the secret store — never the cleartext.
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
// argon2id hash (one persistence path per account). See WebAuthnCredential.
type webAccount struct {
	ID           string
	Username     string
	TenantID     string
	RootScope    bool // true when TenantID == "" by explicit grant (Issue #2919)
	Permissions  []string
	PasswordHash string // argon2id PHC string
	CreatedAt    time.Time
	Credentials  []WebAuthnCredential // Issue #2782: registered WebAuthn credentials (public keys only)
}

// webAccountLockout is the per-account lockout state owned by this store.
type webAccountLockout struct {
	ConsecutiveFailures int
	LockedUntil         time.Time
}

// WebAccountRequest is the POST /api/v1/web/accounts body. The same endpoint
// creates a new account or resets an existing one (upsert): on reset, omitted
// tenant_id/permissions are retained from the existing record.
//
// root_scope and tenant_id are mutually exclusive. Setting root_scope:true grants
// cross-tenant visibility; an explicit tenant_id scopes to that subtree. If neither
// is set on creation the account defaults to "default" (backward-compat); on reset
// the existing scope is retained.
type WebAccountRequest struct {
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	TenantID    string   `json:"tenant_id,omitempty"`
	RootScope   bool     `json:"root_scope,omitempty"` // Issue #2919: explicit root grant
	Permissions []string `json:"permissions,omitempty"`
}

// WebAccountInfo is the response shape for account provisioning. It never carries
// the password or the hash.
type WebAccountInfo struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	TenantID    string    `json:"tenant_id"`
	RootScope   bool      `json:"root_scope"` // Issue #2919
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
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

// --- argon2id PHC hashing ---

// hashWebPassword derives an argon2id hash of password under the current cost
// parameters and encodes it as a PHC string with a fresh random salt.
func hashWebPassword(password string) (string, error) {
	salt := make([]byte, webArgon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	return encodeArgon2idHash(password, salt, webArgon2Time, webArgon2Memory, webArgon2Threads), nil
}

// encodeArgon2idHash derives and PHC-encodes an argon2id hash under explicit
// parameters. Split out from hashWebPassword so tests can pin legacy parameters.
func encodeArgon2idHash(password string, salt []byte, timeCost, memoryKiB uint32, threads uint8) string {
	key := argon2.IDKey([]byte(password), salt, timeCost, memoryKiB, threads, webArgon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, timeCost, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// verifyWebPassword reports whether password matches the argon2id PHC hash. The
// cost parameters are parsed from the hash string (not assumed), so hashes created
// under older parameters keep verifying after the defaults are raised. The final
// comparison is constant-time.
func verifyWebPassword(password, phcHash string) (bool, error) {
	parts := strings.Split(phcHash, "$")
	// Expected: ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, fmt.Errorf("malformed argon2id hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("malformed argon2id version: %w", err)
	}
	if version != argon2.Version {
		return false, fmt.Errorf("unsupported argon2 version %d", version)
	}
	var memoryKiB, timeCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memoryKiB, &timeCost, &threads); err != nil {
		return false, fmt.Errorf("malformed argon2id parameters: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("malformed argon2id salt: %w", err)
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("malformed argon2id hash value: %w", err)
	}
	derived := argon2.IDKey([]byte(password), salt, timeCost, memoryKiB, threads, uint32(len(expected))) // #nosec G115 — hash length is 32
	return subtle.ConstantTimeCompare(derived, expected) == 1, nil
}

// dummyWebAccountHash returns a fixed argon2id hash of a random, never-disclosed
// password. Unknown-user verification runs against this hash so the unknown-user
// path performs the same key-derivation work as the wrong-password path (timing
// uniformity, security A4.2). Computed once, lazily.
var (
	dummyWebAccountHashOnce  sync.Once
	dummyWebAccountHashValue string
)

func dummyWebAccountHash() string {
	dummyWebAccountHashOnce.Do(func() {
		random := make([]byte, 32)
		if _, err := rand.Read(random); err != nil {
			// Fall back to a fixed input: the dummy hash is never a credential,
			// it only equalizes timing, so a deterministic value is acceptable.
			random = []byte("cfgms-dummy-web-account-password")
		}
		phc, err := hashWebPassword(base64.RawStdEncoding.EncodeToString(random))
		if err != nil {
			// hashWebPassword only fails if crypto/rand fails; reuse the fixed path.
			phc = encodeArgon2idHash(string(random), []byte("cfgms-dummy-salt"),
				webArgon2Time, webArgon2Memory, webArgon2Threads)
		}
		dummyWebAccountHashValue = phc
	})
	return dummyWebAccountHashValue
}

// --- input validation (security A4.1) ---

func validateWebUsername(username string) error {
	if !webUsernameRegex.MatchString(username) {
		return fmt.Errorf("username must be 3-64 characters: alphanumerics, '.', '_', '-', starting with an alphanumeric")
	}
	return nil
}

func validateWebPassword(password string) error {
	if len(password) < webPasswordMinBytes || len(password) > webPasswordMaxBytes {
		return fmt.Errorf("password must be between %d and %d bytes", webPasswordMinBytes, webPasswordMaxBytes)
	}
	return nil
}

// --- account store: in-memory cache over the central secret store ---

// webAccountStoreKey returns the secret-store lookup key for a web account.
// The key is an identifier (prefix + username), never credential material —
// the value stored under it is the argon2id hash.
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

// loadWebAccountFromStore reloads an account record from the central secret store
// and re-caches it. The tenant is not known at lookup time (login sends only
// username + password), so the record is located by metadata filter.
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
		ID:           secret.Metadata["id"],
		Username:     secret.Metadata["username"],
		TenantID:     secret.TenantID,
		Permissions:  parsePermissions(secret.Metadata["permissions"]),
		PasswordHash: secret.Value,
		CreatedAt:    secret.CreatedAt,
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
	s.cacheWebAccount(acct)
	return acct, nil
}

// persistWebAccount writes the account record through the central pkg/secrets seam
// (same seam as API keys — handlers_apikeys.go): value is the argon2id PHC hash,
// never the password. WebAuthn credentials (public keys) are serialized to JSON
// in the metadata — they are not secret material so the secrets store's encryption
// is incidental (the same record is used for simplicity).
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
	secretReq := &secretsif.SecretRequest{
		Key:         webAccountStoreKey(acct.Username),
		Value:       acct.PasswordHash,                      // argon2id PHC hash only — plaintext is never stored
		TenantID:    webAccountStorageTenant(acct.TenantID), // Issue #2919: sentinel for root-scope
		CreatedBy:   createdBy,
		Description: "web admin account",
		Tags:        []string{"web-account"},
		Metadata:    meta,
	}
	return s.secretStore.StoreSecret(ctx, secretReq)
}

// --- lockout state (security B4.1, state half; enforcement is #2493's) ---

// recordWebAccountFailure increments the consecutive-failure counter for username
// and sets the 15-minute lockout when the threshold is reached.
func (s *Server) recordWebAccountFailure(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.webAccountLockouts == nil {
		s.webAccountLockouts = make(map[string]*webAccountLockout)
	}
	state := s.webAccountLockouts[username]
	if state == nil {
		state = &webAccountLockout{}
		s.webAccountLockouts[username] = state
	}
	state.ConsecutiveFailures++
	if state.ConsecutiveFailures >= webAccountMaxConsecutiveFailures {
		state.LockedUntil = time.Now().Add(webAccountLockoutDuration)
	}
}

// resetWebAccountLockout clears the failure counter and lockout for username
// (called on successful verification).
func (s *Server) resetWebAccountLockout(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.webAccountLockouts, username)
}

// webAccountLocked reports whether username is currently locked out and until
// when. #2493 (login endpoint) consumes this for lockout ENFORCEMENT; verification
// itself never branches on it, so a locked account's failure stays
// indistinguishable from bad-password.
func (s *Server) webAccountLocked(username string) (bool, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.webAccountLockouts[username]
	if state == nil || state.LockedUntil.IsZero() {
		return false, time.Time{}
	}
	if time.Now().After(state.LockedUntil) {
		return false, time.Time{}
	}
	return true, state.LockedUntil
}

// --- verification API (consumed by the #2493 login endpoint) ---

// VerifyWebCredential verifies a username + password credential and returns the
// account's principal identity (ID, tenant, permissions) on success. Every failure
// — unknown user, wrong password, malformed input — returns the identical
// ErrInvalidWebCredential with identical latency characteristics: unknown-user
// verification runs against a dummy argon2id hash so its timing matches the
// wrong-password path (no username enumeration). Web accounts are RBAC-equivalent
// to API-key principals; success grants exactly the stored permission set.
func (s *Server) VerifyWebCredential(ctx context.Context, username, password string) (principalID, tenantID string, permissions []string, err error) {
	if validateWebUsername(username) != nil || validateWebPassword(password) != nil {
		// Burn the same key-derivation work as a real verification.
		_, _ = verifyWebPassword(password, dummyWebAccountHash())
		return "", "", nil, ErrInvalidWebCredential
	}

	acct, lookupErr := s.getWebAccount(ctx, username)
	if lookupErr != nil || acct == nil {
		if lookupErr != nil {
			s.logger.Warn("Web account lookup failed during verification",
				"username", logging.SanitizeLogValue(username),
				"error", logging.SanitizeLogValue(lookupErr.Error()))
		}
		// Unknown user: verify against the dummy hash so response timing matches
		// the wrong-password path (security A4.2).
		_, _ = verifyWebPassword(password, dummyWebAccountHash())
		return "", "", nil, ErrInvalidWebCredential
	}

	ok, verr := verifyWebPassword(password, acct.PasswordHash)
	if verr != nil || !ok {
		s.recordWebAccountFailure(username)
		return "", "", nil, ErrInvalidWebCredential
	}

	s.resetWebAccountLockout(username)
	return acct.ID, acct.TenantID, append([]string(nil), acct.Permissions...), nil
}

// --- audit (founder condition 2) ---

// emitWebAccountAudit records a web-account lifecycle audit event with the
// sanitized username and the acting admin principal. No-op when auditManager is
// nil. In-package precedent: emitDecommissionAudit (handlers_stewards.go).
func (s *Server) emitWebAccountAudit(ctx context.Context, action, tenantID, actingPrincipalID, username string) {
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
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit web-account audit event",
			"action", action,
			"username", logging.SanitizeLogValue(username),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// --- handlers (Tier-3: admin mTLS only; wired in setupRouter) ---

// handleCreateWebAccount handles POST /api/v1/web/accounts (Tier-3). It creates a
// web-admin account, or resets an existing one (upsert): the password is replaced,
// and omitted tenant_id/permissions are retained. The password value never appears
// in any log or response; only its argon2id PHC hash is stored.
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
	if err := validateWebPassword(req.Password); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_PASSWORD")
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
	// Severs the json.Decode→field→sink dataflow CodeQL tracks for alert #1205.
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

	phcHash, err := hashWebPassword(req.Password)
	if err != nil {
		s.logger.Error("Failed to hash web account password", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create web account", "INTERNAL_ERROR")
		return
	}

	acct := &webAccount{
		ID:           uuid.New().String(),
		Username:     req.Username,
		TenantID:     req.TenantID,
		RootScope:    req.RootScope,
		Permissions:  req.Permissions,
		PasswordHash: phcHash,
		CreatedAt:    time.Now().UTC(),
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
		// Issue #2782: preserve registered WebAuthn credentials across password resets.
		acct.Credentials = existing.Credentials
		action = "web_account.password_reset"
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

	if err := s.persistWebAccount(r.Context(), acct, actingPrincipalID); err != nil {
		s.logger.Error("Failed to persist web account to secret store", "error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(acct.Username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to persist web account", "STORE_ERROR")
		return
	}
	s.cacheWebAccount(acct)

	s.emitWebAccountAudit(r.Context(), action, acct.TenantID, actingPrincipalID, acct.Username)
	s.logger.Info("Web admin account provisioned",
		"action", action,
		"username", logging.SanitizeLogValue(acct.Username),
		"tenant_id", logging.SanitizeLogValue(acct.TenantID),
		"root_scope", acct.RootScope,
		"principal_id", logging.SanitizeLogValue(actingPrincipalID))

	s.writeResponse(w, status, WebAccountInfo{
		ID:          acct.ID,
		Username:    acct.Username,
		TenantID:    acct.TenantID,
		RootScope:   acct.RootScope,
		Permissions: acct.Permissions,
		CreatedAt:   acct.CreatedAt,
	})
}

// handleListWebAccounts handles GET /api/v1/web/accounts (requirePermission only,
// no Tier-3 wrapper — reads are categorically outside the Tier-3 surface; see
// Implementation Notes in Issue #2733). The response uses WebAccountInfo: no
// password hash or any other secret material is ever included.
func (s *Server) handleListWebAccounts(w http.ResponseWriter, r *http.Request) {
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Secret store not available", "SERVICE_UNAVAILABLE")
		return
	}

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
		accounts = append(accounts, WebAccountInfo{
			ID:          meta.Metadata["id"],
			Username:    meta.Metadata["username"],
			TenantID:    tenantID,
			RootScope:   rootScope,
			Permissions: parsePermissions(meta.Metadata["permissions"]),
			CreatedAt:   createdAt,
		})
	}

	s.writeSuccessResponse(w, accounts)
}

// handleDeleteWebAccount handles DELETE /api/v1/web/accounts/{username} (Tier-3).
// It removes the account from the in-memory cache, the lockout state, and the
// central secret store.
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
	delete(s.webAccountLockouts, username)
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
	s.emitWebAccountAudit(r.Context(), "web_account.deleted", acct.TenantID, actingPrincipalID, username)
	s.logger.Info("Web admin account deleted",
		"username", logging.SanitizeLogValue(username),
		"tenant_id", logging.SanitizeLogValue(acct.TenantID),
		"root_scope", acct.RootScope,
		"principal_id", logging.SanitizeLogValue(actingPrincipalID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"username": username,
		"deleted":  true,
	})
}
