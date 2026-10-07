// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// ErrTenantMismatch is returned when a stored credential's recorded tenant does
// not match the tenant that asked for it.
//
// This is a fail-closed cross-check layered on top of the key derivation, not a
// substitute for it. SecretStore.GetSecret(ctx, key) takes no tenant argument and
// every provider resolves purely by key — the steward provider returns
// entry.TenantID as metadata it never compares — so the store will never refuse a
// cross-tenant read on this package's behalf. Comparing the recorded tenant here
// means a key collision (or a credential written under a previous, non-injective
// key scheme) surfaces as an error rather than as one tenant reading another's
// OAuth2 client secret.
var ErrTenantMismatch = errors.New("stored m365 credential belongs to a different tenant")

// SecretStoreCredentialStore implements CredentialStore via pkg/secrets.
//
// Every method's tenantID parameter must be the real, authenticated CFGMS
// tenant the credential belongs to — never the M365 (Azure AD) tenant a
// workflow step happens to be managing. Callers historically passed the
// caller-supplied M365 tenant identifier here and this store wrote every
// SecretRequest.TenantID as the constant "m365", which collapsed every CFGMS
// tenant's M365 credentials into one shared secrets namespace (Issue #4325).
// The M365 tenant a token is valid for is still tracked, as data, on
// AccessToken.TenantID / OAuth2Config.TenantID — it is never the addressing
// key here.
//
// Partitioning by tenant rests on two properties, both enforced in this file
// because no layer below provides them:
//
//  1. Key derivation is injective (sanitizeSegment), so two distinct CFGMS
//     tenant IDs can never address one secret key. A CFGMS tenant ID is a
//     hierarchical path, so a segment encoding that is merely "safe" is not
//     enough — it must also be collision-free.
//  2. Every read re-checks the tenant recorded on the stored secret
//     (assertTenant), and every method rejects a tenant ID that is empty or
//     structurally invalid (validateTenantID). SecretStore has no tenant
//     parameter on any operation and no provider compares tenants, so an
//     unchecked read would trust the key alone.
type SecretStoreCredentialStore struct {
	store secretsif.SecretStore
}

// NewSecretStoreCredentialStore creates a credential store backed by a SecretStore.
func NewSecretStoreCredentialStore(store secretsif.SecretStore) *SecretStoreCredentialStore {
	return &SecretStoreCredentialStore{store: store}
}

// sanitizeSegment encodes s as a single, unambiguous secret-key path segment.
//
// The encoding must be injective: CFGMS tenant IDs are hierarchical paths where
// internal "/" is legitimate (keysafe.ValidateTenantID permits it), so a scheme
// that flattens "/" onto a character already allowed inside a segment maps two
// distinct tenants onto one key. Replacing "/" with "_" did exactly that —
// "root/acme/corp" and "root/acme_corp" both became "root_acme_corp", and since
// nothing downstream re-separates them the two tenants shared one bucket.
//
// url.PathEscape is used instead because it is a total, reversible encoding:
// "/" becomes "%2F" and "%" itself becomes "%25", so no input can forge another
// input's encoding and distinct segments always yield distinct keys.
func sanitizeSegment(s string) string {
	return url.PathEscape(s)
}

// validateTenantID rejects tenant IDs that cannot be addressed safely.
//
// The rules mirror keysafe.ValidateTenantID; that package lives under
// pkg/storage/providers/internal/ and is import-restricted to the storage
// providers, so it cannot be reused from here. Hierarchical "/" separators are
// legitimate; anything that makes the path ambiguous or traversable is not.
//
// Empty is rejected as ErrTenantRequired rather than tolerated: the steward
// secrets provider does not enforce ErrTenantRequired, so an empty tenant would
// otherwise address the shared bucket "m365//token" that every unattributed
// caller lands in.
//
// The tenant ID is never echoed into the error — these errors reach workflow
// callers and logs.
func validateTenantID(tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("m365 credential store: %w", secretsif.ErrTenantRequired)
	}
	if strings.ContainsRune(tenantID, '\x00') {
		return errors.New("invalid tenant ID: must not contain null bytes")
	}
	if strings.ContainsRune(tenantID, '\\') {
		return errors.New("invalid tenant ID: must not contain a backslash")
	}
	if strings.HasPrefix(tenantID, "/") || strings.HasSuffix(tenantID, "/") {
		return errors.New("invalid tenant ID: must not start or end with '/'")
	}
	if strings.Contains(tenantID, "//") {
		return errors.New("invalid tenant ID: must not contain '//'")
	}
	for _, seg := range strings.Split(tenantID, "/") {
		if seg == "." || seg == ".." {
			return errors.New("invalid tenant ID: must not contain '.' or '..' segments")
		}
	}
	return nil
}

// assertTenant verifies that a secret the store handed back is recorded against
// the tenant that requested it. See ErrTenantMismatch.
func assertTenant(secret *secretsif.Secret, tenantID string) error {
	if secret == nil || secret.TenantID != tenantID {
		return ErrTenantMismatch
	}
	return nil
}

func tokenKey(tenantID string) string {
	return "m365/" + sanitizeSegment(tenantID) + "/token"
}

func configKey(tenantID string) string {
	return "m365/" + sanitizeSegment(tenantID) + "/config"
}

func delegatedKey(tenantID, userID string) string {
	return "m365/" + sanitizeSegment(tenantID) + "/delegated/" + sanitizeSegment(userID)
}

func userContextKey(tenantID, userID string) string {
	return "m365/" + sanitizeSegment(tenantID) + "/user_context/" + sanitizeSegment(userID)
}

// isNotFoundError returns true when err indicates the secret does not exist.
// The steward provider does not wrap ErrSecretNotFound in DeleteSecret, so we
// also check the error message as a fallback.
func isNotFoundError(err error) bool {
	if errors.Is(err, secretsif.ErrSecretNotFound) {
		return true
	}
	return strings.Contains(err.Error(), "not found")
}

func (s *SecretStoreCredentialStore) StoreToken(tenantID string, token *AccessToken) error {
	if err := validateTenantID(tenantID); err != nil {
		return err
	}
	// #nosec G117 -- token JSON is immediately stored in the secrets provider;
	// it is never logged, returned, or persisted in a general-purpose store.
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}
	return s.store.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:       tokenKey(tenantID),
		Value:     string(data),
		TenantID:  tenantID,
		CreatedBy: "m365-auth",
	})
}

func (s *SecretStoreCredentialStore) GetToken(tenantID string) (*AccessToken, error) {
	if err := validateTenantID(tenantID); err != nil {
		return nil, err
	}
	secret, err := s.store.GetSecret(context.Background(), tokenKey(tenantID))
	if err != nil {
		if errors.Is(err, secretsif.ErrSecretNotFound) {
			return nil, fmt.Errorf("no token for tenant %s: %w", tenantID, secretsif.ErrSecretNotFound)
		}
		return nil, fmt.Errorf("get token: %w", err)
	}
	if err := assertTenant(secret, tenantID); err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}
	var token AccessToken
	if err := json.Unmarshal([]byte(secret.Value), &token); err != nil {
		return nil, fmt.Errorf("unmarshal token: %w", err)
	}
	return &token, nil
}

func (s *SecretStoreCredentialStore) DeleteToken(tenantID string) error {
	if err := validateTenantID(tenantID); err != nil {
		return err
	}
	err := s.store.DeleteSecret(context.Background(), tokenKey(tenantID))
	if err != nil && !isNotFoundError(err) {
		return fmt.Errorf("delete token: %w", err)
	}
	return nil
}

func (s *SecretStoreCredentialStore) StoreConfig(tenantID string, config *OAuth2Config) error {
	if err := validateTenantID(tenantID); err != nil {
		return err
	}
	// #nosec G117 -- OAuth client-secret JSON is intentionally serialized only
	// for the tenant-scoped SecretStore value.
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return s.store.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:       configKey(tenantID),
		Value:     string(data),
		TenantID:  tenantID,
		CreatedBy: "m365-auth",
	})
}

func (s *SecretStoreCredentialStore) GetConfig(tenantID string) (*OAuth2Config, error) {
	if err := validateTenantID(tenantID); err != nil {
		return nil, err
	}
	secret, err := s.store.GetSecret(context.Background(), configKey(tenantID))
	if err != nil {
		if errors.Is(err, secretsif.ErrSecretNotFound) {
			return nil, fmt.Errorf("no config for tenant %s: %w", tenantID, secretsif.ErrSecretNotFound)
		}
		return nil, fmt.Errorf("get config: %w", err)
	}
	if err := assertTenant(secret, tenantID); err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}
	var cfg OAuth2Config
	if err := json.Unmarshal([]byte(secret.Value), &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return &cfg, nil
}

func (s *SecretStoreCredentialStore) StoreDelegatedToken(tenantID, userID string, token *AccessToken) error {
	if err := validateTenantID(tenantID); err != nil {
		return err
	}
	// #nosec G117 -- delegated token JSON is immediately stored under a
	// sanitized tenant/user SecretStore key and never exposed as ordinary data.
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("marshal delegated token: %w", err)
	}
	return s.store.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:       delegatedKey(tenantID, userID),
		Value:     string(data),
		TenantID:  tenantID,
		CreatedBy: "m365-auth",
	})
}

func (s *SecretStoreCredentialStore) GetDelegatedToken(tenantID, userID string) (*AccessToken, error) {
	if err := validateTenantID(tenantID); err != nil {
		return nil, err
	}
	secret, err := s.store.GetSecret(context.Background(), delegatedKey(tenantID, userID))
	if err != nil {
		if errors.Is(err, secretsif.ErrSecretNotFound) {
			return nil, fmt.Errorf("no delegated token for user %s in tenant %s: %w", userID, tenantID, secretsif.ErrSecretNotFound)
		}
		return nil, fmt.Errorf("get delegated token: %w", err)
	}
	if err := assertTenant(secret, tenantID); err != nil {
		return nil, fmt.Errorf("get delegated token: %w", err)
	}
	var token AccessToken
	if err := json.Unmarshal([]byte(secret.Value), &token); err != nil {
		return nil, fmt.Errorf("unmarshal delegated token: %w", err)
	}
	return &token, nil
}

func (s *SecretStoreCredentialStore) DeleteDelegatedToken(tenantID, userID string) error {
	if err := validateTenantID(tenantID); err != nil {
		return err
	}
	err := s.store.DeleteSecret(context.Background(), delegatedKey(tenantID, userID))
	if err != nil && !isNotFoundError(err) {
		return fmt.Errorf("delete delegated token: %w", err)
	}
	return nil
}

func (s *SecretStoreCredentialStore) StoreUserContext(tenantID, userID string, uctx *UserContext) error {
	if err := validateTenantID(tenantID); err != nil {
		return err
	}
	data, err := json.Marshal(uctx)
	if err != nil {
		return fmt.Errorf("marshal user context: %w", err)
	}
	return s.store.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:       userContextKey(tenantID, userID),
		Value:     string(data),
		TenantID:  tenantID,
		CreatedBy: "m365-auth",
	})
}

func (s *SecretStoreCredentialStore) GetUserContext(tenantID, userID string) (*UserContext, error) {
	if err := validateTenantID(tenantID); err != nil {
		return nil, err
	}
	secret, err := s.store.GetSecret(context.Background(), userContextKey(tenantID, userID))
	if err != nil {
		if errors.Is(err, secretsif.ErrSecretNotFound) {
			return nil, fmt.Errorf("no user context for user %s in tenant %s: %w", userID, tenantID, secretsif.ErrSecretNotFound)
		}
		return nil, fmt.Errorf("get user context: %w", err)
	}
	if err := assertTenant(secret, tenantID); err != nil {
		return nil, fmt.Errorf("get user context: %w", err)
	}
	var uctx UserContext
	if err := json.Unmarshal([]byte(secret.Value), &uctx); err != nil {
		return nil, fmt.Errorf("unmarshal user context: %w", err)
	}
	return &uctx, nil
}

func (s *SecretStoreCredentialStore) DeleteUserContext(tenantID, userID string) error {
	if err := validateTenantID(tenantID); err != nil {
		return err
	}
	err := s.store.DeleteSecret(context.Background(), userContextKey(tenantID, userID))
	if err != nil && !isNotFoundError(err) {
		return fmt.Errorf("delete user context: %w", err)
	}
	return nil
}

func (s *SecretStoreCredentialStore) IsAvailable() bool {
	return s.store.HealthCheck(context.Background()) == nil
}
