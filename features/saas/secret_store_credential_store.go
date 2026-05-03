// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package saas

import (
	"context"
	"encoding/json"
	"fmt"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// SecretStoreCredentialStore implements CredentialStore backed by a secretsif.SecretStore.
// All SecretRequests set TenantID="saas" (fixed) so sops and other multi-tenant backends
// always receive a non-empty TenantID.
type SecretStoreCredentialStore struct {
	secretStore secretsif.SecretStore
}

// NewSecretStoreCredentialStore returns a CredentialStore backed by the given SecretStore.
func NewSecretStoreCredentialStore(secretStore secretsif.SecretStore) *SecretStoreCredentialStore {
	return &SecretStoreCredentialStore{secretStore: secretStore}
}

// StoreClientSecret stores a client secret for the given provider.
func (s *SecretStoreCredentialStore) StoreClientSecret(provider, clientSecret string) error {
	return s.secretStore.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:      "saas/" + provider + "/client_secret",
		Value:    clientSecret,
		TenantID: "saas",
	})
}

// GetClientSecret retrieves a client secret for the given provider.
func (s *SecretStoreCredentialStore) GetClientSecret(provider string) (string, error) {
	secret, err := s.secretStore.GetSecret(context.Background(), "saas/"+provider+"/client_secret")
	if err != nil {
		return "", fmt.Errorf("client secret not found for provider %s: %w", provider, err)
	}
	return secret.Value, nil
}

// StoreTokenSet JSON-marshals tokens and stores them for the given provider.
func (s *SecretStoreCredentialStore) StoreTokenSet(provider string, tokens *TokenSet) error {
	data, err := json.Marshal(tokens)
	if err != nil {
		return fmt.Errorf("failed to marshal token set for provider %s: %w", provider, err)
	}
	return s.secretStore.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:      "saas/" + provider + "/token_set",
		Value:    string(data),
		TenantID: "saas",
	})
}

// GetTokenSet retrieves and unmarshals the token set for the given provider.
func (s *SecretStoreCredentialStore) GetTokenSet(provider string) (*TokenSet, error) {
	secret, err := s.secretStore.GetSecret(context.Background(), "saas/"+provider+"/token_set")
	if err != nil {
		return nil, fmt.Errorf("token set not found for provider %s: %w", provider, err)
	}
	var tokenSet TokenSet
	if err := json.Unmarshal([]byte(secret.Value), &tokenSet); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token set for provider %s: %w", provider, err)
	}
	return &tokenSet, nil
}

// DeleteTokenSet removes the token set for the given provider.
func (s *SecretStoreCredentialStore) DeleteTokenSet(provider string) error {
	return s.secretStore.DeleteSecret(context.Background(), "saas/"+provider+"/token_set")
}

// IsAvailable checks if the underlying secret store is healthy.
func (s *SecretStoreCredentialStore) IsAvailable() bool {
	return s.secretStore.HealthCheck(context.Background()) == nil
}
