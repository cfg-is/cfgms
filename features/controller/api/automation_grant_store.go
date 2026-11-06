// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// Automation grants (ADR-036 section 3) are scoped machine principals, a distinct
// type from API keys. The metadata record lives in the config store and the
// SHA-256 of the credential secret in the secrets provider. Nothing is cached: every
// call reads the stores, so a revocation is seen by every controller node on its
// next call.

const (
	// MaxGrantLifetime caps how far in the future a grant may expire.
	MaxGrantLifetime = 90 * 24 * time.Hour

	automationGrantCredentialPrefix = "cfgag_"
	automationGrantConfigNamespace  = "automation-grants"
	automationGrantSecretPrefix     = "automation-grant-"
	automationGrantSecretBytes      = 32
	automationGrantIDBytes          = 16
)

var (
	// ErrInvalidGrantCredential is the single error GetByCredential returns for an
	// unknown, expired or revoked grant and for a wrong secret.
	ErrInvalidGrantCredential = errors.New("invalid automation grant credential")
	// ErrGrantNotFound is returned by Get and Revoke for an unknown grant id.
	ErrGrantNotFound = errors.New("automation grant not found")
	// ErrInvalidGrantRequest is returned by Create for a request that fails validation.
	ErrInvalidGrantRequest = errors.New("invalid automation grant request")
)

// GrantRejectReason classifies, for internal logging only, why a credential was
// refused. It is never part of the returned error.
type GrantRejectReason string

const (
	GrantRejectMalformed GrantRejectReason = "malformed"
	GrantRejectUnknown   GrantRejectReason = "unknown"
	GrantRejectExpired   GrantRejectReason = "expired"
	GrantRejectRevoked   GrantRejectReason = "revoked"
	GrantRejectSecret    GrantRejectReason = "secret_mismatch"
)

// AutomationGrant is the metadata record of a grant. It never holds the secret.
type AutomationGrant struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Name      string     `json:"name"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	RevokedBy string     `json:"revoked_by,omitempty"`
}

// Revoked reports whether the grant has been revoked.
func (g *AutomationGrant) Revoked() bool { return g.RevokedAt != nil }

// AutomationGrantStore creates, reads, lists and revokes automation grants.
type AutomationGrantStore struct {
	configs cfgconfig.ConfigStore
	secrets secretsif.SecretStore
	now     func() time.Time
}

// NewAutomationGrantStore returns a store over the given durable providers.
func NewAutomationGrantStore(configs cfgconfig.ConfigStore, secrets secretsif.SecretStore) (*AutomationGrantStore, error) {
	if configs == nil || secrets == nil {
		return nil, errors.New("automation grant store requires a config store and a secret store")
	}
	return &AutomationGrantStore{configs: configs, secrets: secrets, now: time.Now}, nil
}

func grantConfigKey(tenantID, id string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: tenantID, Namespace: automationGrantConfigNamespace, Name: id}
}

// Create stores a new grant and returns it with its plaintext credential, which is
// not recoverable afterwards.
func (s *AutomationGrantStore) Create(ctx context.Context, tenantID, name, createdBy string, expiresAt time.Time) (*AutomationGrant, string, error) {
	now := s.now().UTC()
	switch {
	case strings.TrimSpace(tenantID) == "":
		return nil, "", fmt.Errorf("%w: tenant is required", ErrInvalidGrantRequest)
	case strings.TrimSpace(name) == "":
		return nil, "", fmt.Errorf("%w: name is required", ErrInvalidGrantRequest)
	case expiresAt.IsZero():
		return nil, "", fmt.Errorf("%w: expiry is required", ErrInvalidGrantRequest)
	case !expiresAt.After(now):
		return nil, "", fmt.Errorf("%w: expiry is in the past", ErrInvalidGrantRequest)
	case expiresAt.After(now.Add(MaxGrantLifetime)):
		return nil, "", fmt.Errorf("%w: expiry exceeds the maximum lifetime of %s", ErrInvalidGrantRequest, MaxGrantLifetime)
	}

	id, err := randomToken(automationGrantIDBytes, hex.EncodeToString)
	if err != nil {
		return nil, "", err
	}
	secret, err := randomToken(automationGrantSecretBytes, base64.RawURLEncoding.EncodeToString)
	if err != nil {
		return nil, "", err
	}

	grant := &AutomationGrant{
		ID: id, TenantID: tenantID, Name: name, CreatedBy: createdBy,
		CreatedAt: now, ExpiresAt: expiresAt.UTC(),
	}

	// Hash first: a grant without a hash can never authenticate, so a failure
	// between the two writes leaves nothing usable.
	if err := s.secrets.StoreSecret(ctx, &secretsif.SecretRequest{
		Key:         automationGrantSecretPrefix + id,
		Value:       hashAPIKey(secret),
		TenantID:    tenantID,
		CreatedBy:   createdBy,
		Description: "automation grant credential hash",
		Tags:        []string{"automation-grant"},
		Metadata:    map[string]string{secretsif.MetadataKeySecretType: string(secretsif.SecretTypeAPIKey), "id": id},
	}); err != nil {
		return nil, "", fmt.Errorf("failed to store automation grant secret: %w", err)
	}
	if err := s.writeGrant(ctx, grant); err != nil {
		_ = s.deleteSecret(ctx, tenantID, id)
		return nil, "", err
	}
	return grant, automationGrantCredentialPrefix + id + "_" + secret, nil
}

// getSecret reads the hash record (the same accessor-or-combined-reference choice as
// the API-key store in handlers_apikeys.go, which is bound to Server) by explicit (tenant, key) when the store offers
// it, since the combined "<tenant>/<key>" reference is ambiguous for hierarchical
// tenant ids.
func (s *AutomationGrantStore) getSecret(ctx context.Context, tenantID, id string) (*secretsif.Secret, error) {
	key := automationGrantSecretPrefix + id
	if a, ok := s.secrets.(secretsif.TenantSecretAccessor); ok {
		return a.GetTenantSecret(ctx, tenantID, key)
	}
	return s.secrets.GetSecret(ctx, apiKeyStoreRef(tenantID, key))
}

func (s *AutomationGrantStore) deleteSecret(ctx context.Context, tenantID, id string) error {
	key := automationGrantSecretPrefix + id
	if a, ok := s.secrets.(secretsif.TenantSecretAccessor); ok {
		return a.DeleteTenantSecret(ctx, tenantID, key)
	}
	return s.secrets.DeleteSecret(ctx, apiKeyStoreRef(tenantID, key))
}

func randomToken(n int, enc func([]byte) string) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate automation grant token: %w", err)
	}
	return enc(b), nil
}

func (s *AutomationGrantStore) writeGrant(ctx context.Context, g *AutomationGrant) error {
	data, err := json.Marshal(g)
	if err != nil {
		return fmt.Errorf("failed to encode automation grant: %w", err)
	}
	if err := s.configs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:       grantConfigKey(g.TenantID, g.ID),
		Data:      data,
		Format:    cfgconfig.ConfigFormatJSON,
		CreatedBy: g.CreatedBy,
		UpdatedBy: g.CreatedBy,
		Tags:      []string{"automation-grant"},
		Source:    "automation-grant-store",
	}); err != nil {
		return fmt.Errorf("failed to store automation grant: %w", err)
	}
	return nil
}

func decodeGrant(entry *cfgconfig.ConfigEntry) (*AutomationGrant, error) {
	var g AutomationGrant
	if err := json.Unmarshal(entry.Data, &g); err != nil {
		return nil, fmt.Errorf("failed to decode automation grant: %w", err)
	}
	// The record body must agree with the key it is stored under.
	if entry.Key == nil || g.TenantID != entry.Key.TenantID || g.ID != entry.Key.Name {
		return nil, errors.New("automation grant record does not match its storage key")
	}
	return &g, nil
}

// Get returns the grant with the given id in the given tenant.
func (s *AutomationGrantStore) Get(ctx context.Context, tenantID, id string) (*AutomationGrant, error) {
	entry, err := s.configs.GetConfig(ctx, grantConfigKey(tenantID, id))
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) || isConfigNotFound(err) {
			return nil, ErrGrantNotFound
		}
		return nil, fmt.Errorf("failed to read automation grant: %w", err)
	}
	if entry == nil {
		return nil, ErrGrantNotFound
	}
	return decodeGrant(entry)
}

func isConfigNotFound(err error) bool {
	var ve *cfgconfig.ConfigValidationError
	return errors.As(err, &ve) && ve.Code == cfgconfig.ErrConfigNotFound.Code
}

// findByID locates a grant whose tenant is not known (the credential carries only
// the id).
func (s *AutomationGrantStore) findByID(ctx context.Context, id string) (*AutomationGrant, error) {
	entries, err := s.configs.ListConfigs(ctx, &cfgconfig.ConfigFilter{
		Namespace: automationGrantConfigNamespace,
		Names:     []string{id},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to look up automation grant: %w", err)
	}
	for _, e := range entries {
		g, err := decodeGrant(e)
		if err != nil {
			return nil, err
		}
		if g.ID == id {
			return g, nil
		}
	}
	return nil, ErrGrantNotFound
}

// GetByCredential verifies a plaintext credential and returns its grant. Every
// refusal returns ErrInvalidGrantCredential; the reason class is returned
// separately so the caller can log it internally.
func (s *AutomationGrantStore) GetByCredential(ctx context.Context, credential string) (*AutomationGrant, GrantRejectReason, error) {
	id, secret, ok := parseGrantCredential(credential)
	if !ok {
		return nil, GrantRejectMalformed, ErrInvalidGrantCredential
	}
	grant, err := s.findByID(ctx, id)
	if errors.Is(err, ErrGrantNotFound) {
		return nil, GrantRejectUnknown, ErrInvalidGrantCredential
	}
	if err != nil {
		return nil, "", err
	}
	if grant.Revoked() {
		return nil, GrantRejectRevoked, ErrInvalidGrantCredential
	}
	if !s.now().Before(grant.ExpiresAt) {
		return nil, GrantRejectExpired, ErrInvalidGrantCredential
	}
	stored, err := s.getSecret(ctx, grant.TenantID, id)
	if err != nil {
		if errors.Is(err, secretsif.ErrSecretNotFound) || errors.Is(err, secretsif.ErrSecretExpired) {
			return nil, GrantRejectUnknown, ErrInvalidGrantCredential
		}
		return nil, "", fmt.Errorf("failed to read automation grant secret: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(stored.Value), []byte(hashAPIKey(secret))) != 1 {
		return nil, GrantRejectSecret, ErrInvalidGrantCredential
	}
	return grant, "", nil
}

func parseGrantCredential(credential string) (id, secret string, ok bool) {
	rest, found := strings.CutPrefix(credential, automationGrantCredentialPrefix)
	if !found {
		return "", "", false
	}
	// The id is hex, so the first underscore ends it; the base64url secret may
	// itself contain underscores.
	id, secret, found = strings.Cut(rest, "_")
	if !found || id == "" || secret == "" {
		return "", "", false
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", "", false
	}
	return id, secret, true
}

// List returns the grants of the given tenants, ordered by creation time then id.
// The caller resolves the subtree (a tenant and its ParentID descendants, e.g.
// Server.tenantSubtreeIDs) so containment never depends on the shape of a tenant id.
func (s *AutomationGrantStore) List(ctx context.Context, subtreeTenantIDs []string) ([]*AutomationGrant, error) {
	if len(subtreeTenantIDs) == 0 {
		return nil, nil
	}
	inScope := make(map[string]struct{}, len(subtreeTenantIDs))
	for _, id := range subtreeTenantIDs {
		inScope[id] = struct{}{}
	}
	entries, err := s.configs.ListConfigs(ctx, &cfgconfig.ConfigFilter{Namespace: automationGrantConfigNamespace})
	if err != nil {
		return nil, fmt.Errorf("failed to list automation grants: %w", err)
	}
	var grants []*AutomationGrant
	for _, e := range entries {
		g, err := decodeGrant(e)
		if err != nil {
			return nil, err
		}
		if _, ok := inScope[g.TenantID]; ok {
			grants = append(grants, g)
		}
	}
	sort.Slice(grants, func(i, j int) bool {
		if !grants[i].CreatedAt.Equal(grants[j].CreatedAt) {
			return grants[i].CreatedAt.Before(grants[j].CreatedAt)
		}
		return grants[i].ID < grants[j].ID
	})
	return grants, nil
}

// Revoke marks a grant revoked and deletes its secret hash. Revoking an already
// revoked grant keeps the original revocation record.
func (s *AutomationGrantStore) Revoke(ctx context.Context, tenantID, id, revokedBy string) (*AutomationGrant, error) {
	grant, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if !grant.Revoked() {
		at := s.now().UTC()
		grant.RevokedAt = &at
		grant.RevokedBy = revokedBy
		if err := s.writeGrant(ctx, grant); err != nil {
			return nil, err
		}
	}
	if err := s.deleteSecret(ctx, tenantID, id); err != nil && !errors.Is(err, secretsif.ErrSecretNotFound) {
		return nil, fmt.Errorf("failed to delete automation grant secret: %w", err)
	}
	return grant, nil
}
