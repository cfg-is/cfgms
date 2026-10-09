// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package testutil

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// MemSecretStore is a minimal thread-safe in-memory SecretStore for unit tests.
// It exercises the real SecretStore interface without requiring a running OpenBao instance.
type MemSecretStore struct {
	mu       sync.RWMutex
	secrets  map[string]string
	versions map[string]int
}

func NewMemSecretStore() *MemSecretStore {
	return &MemSecretStore{secrets: make(map[string]string), versions: make(map[string]int)}
}

// StoreSecret bumps the stored version like a real KV v2 backend does, so a
// secret written through this path is visible to a later create-if-absent
// compare-and-swap (expectedVersion 0) as already claimed.
func (s *MemSecretStore) StoreSecret(_ context.Context, req *secretsinterfaces.SecretRequest) error {
	if req.TenantID == "" {
		return fmt.Errorf("TenantID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[req.TenantID+"/"+req.Key] = req.Value
	s.versions[req.TenantID+"/"+req.Key]++
	return nil
}

func (s *MemSecretStore) CompareAndSwapSecret(_ context.Context, key string, expectedVersion int, req *secretsinterfaces.SecretRequest) (int, bool, error) {
	if req.TenantID == "" {
		return 0, false, fmt.Errorf("TenantID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.versions[key] != expectedVersion {
		return 0, false, nil
	}
	s.secrets[req.TenantID+"/"+req.Key] = req.Value
	s.versions[key]++
	return s.versions[key], true, nil
}

func (s *MemSecretStore) GetSecret(_ context.Context, key string) (*secretsinterfaces.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.secrets[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", secretsinterfaces.ErrSecretNotFound, key)
	}
	return &secretsinterfaces.Secret{Key: key, Value: val}, nil
}

func (s *MemSecretStore) DeleteSecret(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.secrets, key)
	delete(s.versions, key)
	return nil
}

// ListSecrets returns the direct children of filter.TenantID (a path prefix), the
// way the OpenBao provider lists a metadata directory. Keys are reported without
// the first path segment, as that provider reports them.
func (s *MemSecretStore) ListSecrets(_ context.Context, filter *secretsinterfaces.SecretFilter) ([]*secretsinterfaces.SecretMetadata, error) {
	if filter == nil || filter.TenantID == "" {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*secretsinterfaces.SecretMetadata
	prefix := filter.TenantID + "/"
	for k := range s.secrets {
		rest, ok := strings.CutPrefix(k, prefix)
		if !ok || strings.Contains(rest, "/") {
			continue
		}
		tenant, key, _ := strings.Cut(k, "/")
		out = append(out, &secretsinterfaces.SecretMetadata{Key: key, TenantID: tenant, Version: s.versions[k]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// CompareAndSwapIsClusterAtomic lets the signing key store accept this store: the
// compare-and-swap above is atomic under the store's mutex, which is the property
// the interface asks for within this single in-process "cluster".
func (s *MemSecretStore) CompareAndSwapIsClusterAtomic() bool { return true }

func (s *MemSecretStore) GetSecrets(ctx context.Context, keys []string) (map[string]*secretsinterfaces.Secret, error) {
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

func (s *MemSecretStore) StoreSecrets(ctx context.Context, secrets map[string]*secretsinterfaces.SecretRequest) error {
	for _, req := range secrets {
		if err := s.StoreSecret(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

func (s *MemSecretStore) GetSecretVersion(_ context.Context, key string, _ int) (*secretsinterfaces.Secret, error) {
	return s.GetSecret(context.Background(), key)
}

func (s *MemSecretStore) ListSecretVersions(_ context.Context, _ string) ([]*secretsinterfaces.SecretVersion, error) {
	return nil, nil
}

func (s *MemSecretStore) GetSecretMetadata(_ context.Context, key string) (*secretsinterfaces.SecretMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.secrets[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", secretsinterfaces.ErrSecretNotFound, key)
	}
	now := time.Now()
	return &secretsinterfaces.SecretMetadata{Key: key, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *MemSecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}

func (s *MemSecretStore) RotateSecret(ctx context.Context, key string, newValue string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[key] = newValue
	return nil
}

func (s *MemSecretStore) ExpireSecret(ctx context.Context, key string) error {
	return s.DeleteSecret(ctx, key)
}

func (s *MemSecretStore) HealthCheck(_ context.Context) error { return nil }
func (s *MemSecretStore) Close() error                        { return nil }

var _ secretsinterfaces.SecretStore = (*MemSecretStore)(nil)
