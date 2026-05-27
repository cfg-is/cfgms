// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package saas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// isNotFoundError matches the steward provider's "not found" signal, which is not
// always wrapped as secretsif.ErrSecretNotFound in DeleteSecret responses.
func isNotFoundError(err error) bool {
	if errors.Is(err, secretsif.ErrSecretNotFound) {
		return true
	}
	return strings.Contains(err.Error(), "not found")
}

// SecretStoreCredentialStore implements auth.CredentialStore backed by a secretsif.SecretStore.
// All SecretRequests set TenantID to the tenantID argument so SOPS and other multi-tenant
// backends always receive a non-empty TenantID.
type SecretStoreCredentialStore struct {
	secretStore secretsif.SecretStore
}

// NewSecretStoreCredentialStore returns an auth.CredentialStore backed by the given SecretStore.
func NewSecretStoreCredentialStore(secretStore secretsif.SecretStore) *SecretStoreCredentialStore {
	return &SecretStoreCredentialStore{secretStore: secretStore}
}

// StoreToken stores an access token keyed by tenantID.
func (s *SecretStoreCredentialStore) StoreToken(tenantID string, token *auth.AccessToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token for tenant %s: %w", tenantID, err)
	}
	return s.secretStore.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:      "m365/" + tenantID + "/token",
		Value:    string(data),
		TenantID: tenantID,
	})
}

// GetToken retrieves an access token keyed by tenantID.
func (s *SecretStoreCredentialStore) GetToken(tenantID string) (*auth.AccessToken, error) {
	secret, err := s.secretStore.GetSecret(context.Background(), "m365/"+tenantID+"/token")
	if err != nil {
		return nil, fmt.Errorf("token not found for tenant %s: %w", tenantID, err)
	}
	var token auth.AccessToken
	if err := json.Unmarshal([]byte(secret.Value), &token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token for tenant %s: %w", tenantID, err)
	}
	return &token, nil
}

// DeleteToken removes the access token for the given tenantID.
func (s *SecretStoreCredentialStore) DeleteToken(tenantID string) error {
	err := s.secretStore.DeleteSecret(context.Background(), "m365/"+tenantID+"/token")
	if err != nil && !isNotFoundError(err) {
		return err
	}
	return nil
}

// StoreDelegatedToken stores a delegated access token for a user within a tenant.
func (s *SecretStoreCredentialStore) StoreDelegatedToken(tenantID, userID string, token *auth.AccessToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal delegated token for tenant %s user %s: %w", tenantID, userID, err)
	}
	return s.secretStore.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:      "m365/" + tenantID + "/delegated/" + userID,
		Value:    string(data),
		TenantID: tenantID,
	})
}

// GetDelegatedToken retrieves a delegated access token for a user within a tenant.
func (s *SecretStoreCredentialStore) GetDelegatedToken(tenantID, userID string) (*auth.AccessToken, error) {
	secret, err := s.secretStore.GetSecret(context.Background(), "m365/"+tenantID+"/delegated/"+userID)
	if err != nil {
		return nil, fmt.Errorf("delegated token not found for tenant %s user %s: %w", tenantID, userID, err)
	}
	var token auth.AccessToken
	if err := json.Unmarshal([]byte(secret.Value), &token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal delegated token for tenant %s user %s: %w", tenantID, userID, err)
	}
	return &token, nil
}

// DeleteDelegatedToken removes the delegated access token for a user within a tenant.
func (s *SecretStoreCredentialStore) DeleteDelegatedToken(tenantID, userID string) error {
	err := s.secretStore.DeleteSecret(context.Background(), "m365/"+tenantID+"/delegated/"+userID)
	if err != nil && !isNotFoundError(err) {
		return err
	}
	return nil
}

// StoreUserContext stores user context for a user within a tenant.
func (s *SecretStoreCredentialStore) StoreUserContext(tenantID, userID string, userCtx *auth.UserContext) error {
	data, err := json.Marshal(userCtx)
	if err != nil {
		return fmt.Errorf("failed to marshal user context for tenant %s user %s: %w", tenantID, userID, err)
	}
	return s.secretStore.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:      "m365/" + tenantID + "/users/" + userID + "/context",
		Value:    string(data),
		TenantID: tenantID,
	})
}

// GetUserContext retrieves user context for a user within a tenant.
func (s *SecretStoreCredentialStore) GetUserContext(tenantID, userID string) (*auth.UserContext, error) {
	secret, err := s.secretStore.GetSecret(context.Background(), "m365/"+tenantID+"/users/"+userID+"/context")
	if err != nil {
		return nil, fmt.Errorf("user context not found for tenant %s user %s: %w", tenantID, userID, err)
	}
	var userCtx auth.UserContext
	if err := json.Unmarshal([]byte(secret.Value), &userCtx); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user context for tenant %s user %s: %w", tenantID, userID, err)
	}
	return &userCtx, nil
}

// DeleteUserContext removes user context for a user within a tenant.
func (s *SecretStoreCredentialStore) DeleteUserContext(tenantID, userID string) error {
	err := s.secretStore.DeleteSecret(context.Background(), "m365/"+tenantID+"/users/"+userID+"/context")
	if err != nil && !isNotFoundError(err) {
		return err
	}
	return nil
}

// StoreConfig stores OAuth2 configuration for a tenant.
func (s *SecretStoreCredentialStore) StoreConfig(tenantID string, config *auth.OAuth2Config) error {
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config for tenant %s: %w", tenantID, err)
	}
	return s.secretStore.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:      "m365/" + tenantID + "/config",
		Value:    string(data),
		TenantID: tenantID,
	})
}

// GetConfig retrieves OAuth2 configuration for a tenant.
func (s *SecretStoreCredentialStore) GetConfig(tenantID string) (*auth.OAuth2Config, error) {
	secret, err := s.secretStore.GetSecret(context.Background(), "m365/"+tenantID+"/config")
	if err != nil {
		return nil, fmt.Errorf("config not found for tenant %s: %w", tenantID, err)
	}
	var config auth.OAuth2Config
	if err := json.Unmarshal([]byte(secret.Value), &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config for tenant %s: %w", tenantID, err)
	}
	return &config, nil
}

// IsAvailable checks if the underlying secret store is healthy.
func (s *SecretStoreCredentialStore) IsAvailable() bool {
	return s.secretStore.HealthCheck(context.Background()) == nil
}
