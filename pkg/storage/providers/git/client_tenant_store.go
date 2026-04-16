// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package git implements production-ready git-based storage provider for CFGMS
package git

import (
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// MVP: Simple in-memory storage within the git provider.
// Future: implement proper git file storage with commits.
type memoryStorage struct {
	clients  map[string]*interfaces.ClientTenant
	requests map[string]*interfaces.AdminConsentRequest
	mutex    sync.RWMutex
}

func newMemoryStorage() *memoryStorage {
	return &memoryStorage{
		clients:  make(map[string]*interfaces.ClientTenant),
		requests: make(map[string]*interfaces.AdminConsentRequest),
	}
}

// GitClientTenantStore implements ClientTenantStore using git for persistence.
//
// MVP Implementation Note:
// This is a minimal implementation to unblock the current sprint.
// Full implementation will be done in Epic 5 with proper JSON file storage,
// remote repository sync, Mozilla SOPS integration, and performance optimization.
// For now, in-memory storage is used within the git provider to satisfy the interface.
type GitClientTenantStore struct {
	repoPath  string
	remoteURL string         // MVP: not used, for future implementation
	storage   *memoryStorage // Per-instance storage to avoid test conflicts
}

// NewGitClientTenantStore creates a new git-based client tenant store
func NewGitClientTenantStore(repoPath, remoteURL string) (*GitClientTenantStore, error) {
	store := &GitClientTenantStore{
		repoPath:  repoPath,
		remoteURL: remoteURL,
		storage:   newMemoryStorage(),
	}

	if err := initializeGitRepo(repoPath); err != nil {
		return nil, fmt.Errorf("failed to initialize git repository: %w", err)
	}

	return store, nil
}

func (s *GitClientTenantStore) StoreClientTenant(client *interfaces.ClientTenant) error {
	s.storage.mutex.Lock()
	defer s.storage.mutex.Unlock()

	if client.ID == "" {
		client.ID = client.TenantID
	}
	if client.CreatedAt.IsZero() {
		client.CreatedAt = time.Now()
	}
	client.UpdatedAt = time.Now()

	s.storage.clients[client.TenantID] = client
	return nil
}

func (s *GitClientTenantStore) GetClientTenant(tenantID string) (*interfaces.ClientTenant, error) {
	s.storage.mutex.RLock()
	defer s.storage.mutex.RUnlock()

	client, exists := s.storage.clients[tenantID]
	if !exists {
		return nil, fmt.Errorf("client tenant not found: %s", tenantID)
	}
	return client, nil
}

func (s *GitClientTenantStore) GetClientTenantByIdentifier(clientIdentifier string) (*interfaces.ClientTenant, error) {
	s.storage.mutex.RLock()
	defer s.storage.mutex.RUnlock()

	for _, client := range s.storage.clients {
		if client.ClientIdentifier == clientIdentifier {
			return client, nil
		}
	}
	return nil, fmt.Errorf("client tenant not found by identifier: %s", clientIdentifier)
}

func (s *GitClientTenantStore) ListClientTenants(status interfaces.ClientTenantStatus) ([]*interfaces.ClientTenant, error) {
	s.storage.mutex.RLock()
	defer s.storage.mutex.RUnlock()

	var result []*interfaces.ClientTenant
	for _, client := range s.storage.clients {
		if status == "" || client.Status == status {
			result = append(result, client)
		}
	}
	return result, nil
}

func (s *GitClientTenantStore) UpdateClientTenantStatus(tenantID string, status interfaces.ClientTenantStatus) error {
	s.storage.mutex.Lock()
	defer s.storage.mutex.Unlock()

	client, exists := s.storage.clients[tenantID]
	if !exists {
		return fmt.Errorf("client tenant not found: %s", tenantID)
	}

	client.Status = status
	client.UpdatedAt = time.Now()
	return nil
}

func (s *GitClientTenantStore) DeleteClientTenant(tenantID string) error {
	s.storage.mutex.Lock()
	defer s.storage.mutex.Unlock()

	delete(s.storage.clients, tenantID)
	return nil
}

func (s *GitClientTenantStore) StoreAdminConsentRequest(request *interfaces.AdminConsentRequest) error {
	s.storage.mutex.Lock()
	defer s.storage.mutex.Unlock()

	if request.CreatedAt.IsZero() {
		request.CreatedAt = time.Now()
	}

	s.storage.requests[request.State] = request
	return nil
}

func (s *GitClientTenantStore) GetAdminConsentRequest(state string) (*interfaces.AdminConsentRequest, error) {
	s.storage.mutex.RLock()
	defer s.storage.mutex.RUnlock()

	request, exists := s.storage.requests[state]
	if !exists {
		return nil, fmt.Errorf("admin consent request not found: %s", state)
	}

	if time.Now().After(request.ExpiresAt) {
		return nil, fmt.Errorf("admin consent request expired: %s", state)
	}

	return request, nil
}

func (s *GitClientTenantStore) DeleteAdminConsentRequest(state string) error {
	s.storage.mutex.Lock()
	defer s.storage.mutex.Unlock()

	delete(s.storage.requests, state)
	return nil
}

// Close is a no-op for the git-based client tenant store (no persistent connections to release).
func (s *GitClientTenantStore) Close() error {
	return nil
}
