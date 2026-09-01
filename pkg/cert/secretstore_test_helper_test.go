// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"fmt"
	"sync"
	"time"

	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// inMemSecretStore is a minimal thread-safe in-memory SecretStore for unit tests.
// It exercises the real SecretStore interface without requiring a running OpenBao instance.
type inMemSecretStore struct {
	mu       sync.RWMutex
	secrets  map[string]string
	versions map[string]int
}

func newInMemSecretStore() *inMemSecretStore {
	return &inMemSecretStore{secrets: make(map[string]string)}
}

func (s *inMemSecretStore) StoreSecret(_ context.Context, req *secretsinterfaces.SecretRequest) error {
	if req.TenantID == "" {
		return fmt.Errorf("TenantID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[req.TenantID+"/"+req.Key] = req.Value
	return nil
}

func (s *inMemSecretStore) CompareAndSwapSecret(_ context.Context, key string, expectedVersion int, req *secretsinterfaces.SecretRequest) (int, bool, error) {
	if req.TenantID == "" {
		return 0, false, fmt.Errorf("TenantID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.versions == nil {
		s.versions = make(map[string]int)
	}
	if s.versions[key] != expectedVersion {
		return 0, false, nil
	}
	s.secrets[req.TenantID+"/"+req.Key] = req.Value
	s.versions[key]++
	return s.versions[key], true, nil
}

func (s *inMemSecretStore) GetSecret(_ context.Context, key string) (*secretsinterfaces.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.secrets[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", secretsinterfaces.ErrSecretNotFound, key)
	}
	return &secretsinterfaces.Secret{Key: key, Value: val}, nil
}

func (s *inMemSecretStore) DeleteSecret(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.secrets, key)
	return nil
}

func (s *inMemSecretStore) ListSecrets(_ context.Context, _ *secretsinterfaces.SecretFilter) ([]*secretsinterfaces.SecretMetadata, error) {
	return nil, nil
}

func (s *inMemSecretStore) GetSecrets(ctx context.Context, keys []string) (map[string]*secretsinterfaces.Secret, error) {
	result := make(map[string]*secretsinterfaces.Secret, len(keys))
	for _, k := range keys {
		sec, err := s.GetSecret(ctx, k)
		if err != nil {
			continue
		}
		result[k] = sec
	}
	return result, nil
}

func (s *inMemSecretStore) StoreSecrets(ctx context.Context, secrets map[string]*secretsinterfaces.SecretRequest) error {
	for _, req := range secrets {
		if err := s.StoreSecret(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

func (s *inMemSecretStore) GetSecretVersion(_ context.Context, key string, _ int) (*secretsinterfaces.Secret, error) {
	return s.GetSecret(context.Background(), key)
}

func (s *inMemSecretStore) ListSecretVersions(_ context.Context, _ string) ([]*secretsinterfaces.SecretVersion, error) {
	return nil, nil
}

func (s *inMemSecretStore) GetSecretMetadata(_ context.Context, key string) (*secretsinterfaces.SecretMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.secrets[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", secretsinterfaces.ErrSecretNotFound, key)
	}
	now := time.Now()
	return &secretsinterfaces.SecretMetadata{Key: key, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *inMemSecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}

func (s *inMemSecretStore) RotateSecret(ctx context.Context, key string, newValue string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[key] = newValue
	return nil
}

func (s *inMemSecretStore) ExpireSecret(ctx context.Context, key string) error {
	return s.DeleteSecret(ctx, key)
}

func (s *inMemSecretStore) HealthCheck(_ context.Context) error { return nil }
func (s *inMemSecretStore) Close() error                        { return nil }

var _ secretsinterfaces.SecretStore = (*inMemSecretStore)(nil)
