// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2490: web-admin credential store.
// Issue #2993: password removed — accounts are now passkey-only (ADR-021 Amendment 1).
//
// Accounts back the browser passkey login (ADR-018 addendum, ADR-021): the store holds
// the account identity and registered WebAuthn credentials, persisted durably through the
// central pkg/secrets seam — the same seam API keys use (handlers_apikeys.go) — with the
// in-memory map as cache only. Provisioning is Tier-3 (admin mTLS only).
package api

import (
	"context"
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
	TenantID    string   `json:"tenant_id,omitempty"`
	RootScope   bool     `json:"root_scope,omitempty"` // Issue #2919: explicit root grant
	Permissions []string `json:"permissions,omitempty"`
}

// WebAccountInfo is the response shape for account provisioning. It never carries
// any secret material.
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
		// Issue #2782: preserve registered WebAuthn credentials across account resets.
		acct.Credentials = existing.Credentials
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
		"root_scope", acct.TenantID == "",
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
	s.emitWebAccountAudit(r.Context(), "web_account.deleted", acct.TenantID, actingPrincipalID, username)
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
