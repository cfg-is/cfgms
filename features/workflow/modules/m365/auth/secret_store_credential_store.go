// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// SecretStoreCredentialStore implements CredentialStore via pkg/secrets.
type SecretStoreCredentialStore struct {
	store secretsif.SecretStore
}

// NewSecretStoreCredentialStore creates a credential store backed by a SecretStore.
func NewSecretStoreCredentialStore(store secretsif.SecretStore) *SecretStoreCredentialStore {
	return &SecretStoreCredentialStore{store: store}
}

func sanitizeSegment(s string) string {
	return strings.ReplaceAll(s, "/", "_")
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
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}
	return s.store.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:       tokenKey(tenantID),
		Value:     string(data),
		TenantID:  "m365",
		CreatedBy: "m365-auth",
	})
}

func (s *SecretStoreCredentialStore) GetToken(tenantID string) (*AccessToken, error) {
	secret, err := s.store.GetSecret(context.Background(), tokenKey(tenantID))
	if err != nil {
		if errors.Is(err, secretsif.ErrSecretNotFound) {
			return nil, fmt.Errorf("no token for tenant %s: %w", tenantID, secretsif.ErrSecretNotFound)
		}
		return nil, fmt.Errorf("get token: %w", err)
	}
	var token AccessToken
	if err := json.Unmarshal([]byte(secret.Value), &token); err != nil {
		return nil, fmt.Errorf("unmarshal token: %w", err)
	}
	return &token, nil
}

func (s *SecretStoreCredentialStore) DeleteToken(tenantID string) error {
	err := s.store.DeleteSecret(context.Background(), tokenKey(tenantID))
	if err != nil && !isNotFoundError(err) {
		return fmt.Errorf("delete token: %w", err)
	}
	return nil
}

func (s *SecretStoreCredentialStore) StoreConfig(tenantID string, config *OAuth2Config) error {
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return s.store.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:       configKey(tenantID),
		Value:     string(data),
		TenantID:  "m365",
		CreatedBy: "m365-auth",
	})
}

func (s *SecretStoreCredentialStore) GetConfig(tenantID string) (*OAuth2Config, error) {
	secret, err := s.store.GetSecret(context.Background(), configKey(tenantID))
	if err != nil {
		if errors.Is(err, secretsif.ErrSecretNotFound) {
			return nil, fmt.Errorf("no config for tenant %s: %w", tenantID, secretsif.ErrSecretNotFound)
		}
		return nil, fmt.Errorf("get config: %w", err)
	}
	var cfg OAuth2Config
	if err := json.Unmarshal([]byte(secret.Value), &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return &cfg, nil
}

func (s *SecretStoreCredentialStore) StoreDelegatedToken(tenantID, userID string, token *AccessToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("marshal delegated token: %w", err)
	}
	return s.store.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:       delegatedKey(tenantID, userID),
		Value:     string(data),
		TenantID:  "m365",
		CreatedBy: "m365-auth",
	})
}

func (s *SecretStoreCredentialStore) GetDelegatedToken(tenantID, userID string) (*AccessToken, error) {
	secret, err := s.store.GetSecret(context.Background(), delegatedKey(tenantID, userID))
	if err != nil {
		if errors.Is(err, secretsif.ErrSecretNotFound) {
			return nil, fmt.Errorf("no delegated token for user %s in tenant %s: %w", userID, tenantID, secretsif.ErrSecretNotFound)
		}
		return nil, fmt.Errorf("get delegated token: %w", err)
	}
	var token AccessToken
	if err := json.Unmarshal([]byte(secret.Value), &token); err != nil {
		return nil, fmt.Errorf("unmarshal delegated token: %w", err)
	}
	return &token, nil
}

func (s *SecretStoreCredentialStore) DeleteDelegatedToken(tenantID, userID string) error {
	err := s.store.DeleteSecret(context.Background(), delegatedKey(tenantID, userID))
	if err != nil && !isNotFoundError(err) {
		return fmt.Errorf("delete delegated token: %w", err)
	}
	return nil
}

func (s *SecretStoreCredentialStore) StoreUserContext(tenantID, userID string, uctx *UserContext) error {
	data, err := json.Marshal(uctx)
	if err != nil {
		return fmt.Errorf("marshal user context: %w", err)
	}
	return s.store.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:       userContextKey(tenantID, userID),
		Value:     string(data),
		TenantID:  "m365",
		CreatedBy: "m365-auth",
	})
}

func (s *SecretStoreCredentialStore) GetUserContext(tenantID, userID string) (*UserContext, error) {
	secret, err := s.store.GetSecret(context.Background(), userContextKey(tenantID, userID))
	if err != nil {
		if errors.Is(err, secretsif.ErrSecretNotFound) {
			return nil, fmt.Errorf("no user context for user %s in tenant %s: %w", userID, tenantID, secretsif.ErrSecretNotFound)
		}
		return nil, fmt.Errorf("get user context: %w", err)
	}
	var uctx UserContext
	if err := json.Unmarshal([]byte(secret.Value), &uctx); err != nil {
		return nil, fmt.Errorf("unmarshal user context: %w", err)
	}
	return &uctx, nil
}

func (s *SecretStoreCredentialStore) DeleteUserContext(tenantID, userID string) error {
	err := s.store.DeleteSecret(context.Background(), userContextKey(tenantID, userID))
	if err != nil && !isNotFoundError(err) {
		return fmt.Errorf("delete user context: %w", err)
	}
	return nil
}

func (s *SecretStoreCredentialStore) IsAvailable() bool {
	return s.store.HealthCheck(context.Background()) == nil
}
