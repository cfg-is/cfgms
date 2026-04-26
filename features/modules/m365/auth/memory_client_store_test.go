// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package auth

import (
	"fmt"
	"sync"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion that MemoryClientTenantStore satisfies the canonical
// business.ClientTenantStore contract.
var _ business.ClientTenantStore = (*MemoryClientTenantStore)(nil)

// MemoryClientTenantStore provides an in-memory implementation of business.ClientTenantStore
// for use in tests only. For production deployments, use StorageClientTenantStoreAdapter
// with pkg/storage providers.
type MemoryClientTenantStore struct {
	// Client tenant storage
	clientTenants      map[string]*business.ClientTenant // tenantID -> ClientTenant
	clientTenantsByID  map[string]*business.ClientTenant // clientIdentifier -> ClientTenant
	clientTenantsMutex sync.RWMutex

	// Admin consent request storage
	adminConsentRequests map[string]*business.AdminConsentRequest // state -> AdminConsentRequest
	consentRequestsMutex sync.RWMutex

	// Cleanup goroutine control
	stopCleanup chan struct{}
	stopOnce    sync.Once
}

// NewMemoryClientTenantStore creates a new in-memory client tenant store
func NewMemoryClientTenantStore() *MemoryClientTenantStore {
	store := &MemoryClientTenantStore{
		clientTenants:        make(map[string]*business.ClientTenant),
		clientTenantsByID:    make(map[string]*business.ClientTenant),
		adminConsentRequests: make(map[string]*business.AdminConsentRequest),
		stopCleanup:          make(chan struct{}),
	}

	// Start cleanup goroutine for expired requests
	go store.cleanupExpiredRequests()

	return store
}

// Client tenant management

// StoreClientTenant stores a client tenant
func (s *MemoryClientTenantStore) StoreClientTenant(client *business.ClientTenant) error {
	s.clientTenantsMutex.Lock()
	defer s.clientTenantsMutex.Unlock()

	// Update timestamp
	client.UpdatedAt = time.Now()

	// Store by tenant ID and client identifier
	s.clientTenants[client.TenantID] = client
	s.clientTenantsByID[client.ClientIdentifier] = client

	return nil
}

// GetClientTenant retrieves a client tenant by tenant ID
func (s *MemoryClientTenantStore) GetClientTenant(tenantID string) (*business.ClientTenant, error) {
	s.clientTenantsMutex.RLock()
	defer s.clientTenantsMutex.RUnlock()

	client, exists := s.clientTenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("client tenant not found: %s", tenantID)
	}

	// Return a copy to prevent external modification
	clientCopy := *client
	return &clientCopy, nil
}

// GetClientTenantByIdentifier retrieves a client tenant by client identifier
func (s *MemoryClientTenantStore) GetClientTenantByIdentifier(clientIdentifier string) (*business.ClientTenant, error) {
	s.clientTenantsMutex.RLock()
	defer s.clientTenantsMutex.RUnlock()

	client, exists := s.clientTenantsByID[clientIdentifier]
	if !exists {
		return nil, fmt.Errorf("client tenant not found by identifier: %s", clientIdentifier)
	}

	// Return a copy to prevent external modification
	clientCopy := *client
	return &clientCopy, nil
}

// ListClientTenants returns all client tenants, optionally filtered by status
func (s *MemoryClientTenantStore) ListClientTenants(status business.ClientTenantStatus) ([]*business.ClientTenant, error) {
	s.clientTenantsMutex.RLock()
	defer s.clientTenantsMutex.RUnlock()

	var clients []*business.ClientTenant

	for _, client := range s.clientTenants {
		// Filter by status if specified
		if status != "" && client.Status != status {
			continue
		}

		// Return a copy to prevent external modification
		clientCopy := *client
		clients = append(clients, &clientCopy)
	}

	return clients, nil
}

// UpdateClientTenantStatus updates the status of a client tenant
func (s *MemoryClientTenantStore) UpdateClientTenantStatus(tenantID string, status business.ClientTenantStatus) error {
	s.clientTenantsMutex.Lock()
	defer s.clientTenantsMutex.Unlock()

	client, exists := s.clientTenants[tenantID]
	if !exists {
		return fmt.Errorf("client tenant not found: %s", tenantID)
	}

	// Update status and timestamp
	client.Status = status
	client.UpdatedAt = time.Now()

	return nil
}

// DeleteClientTenant removes a client tenant
func (s *MemoryClientTenantStore) DeleteClientTenant(tenantID string) error {
	s.clientTenantsMutex.Lock()
	defer s.clientTenantsMutex.Unlock()

	client, exists := s.clientTenants[tenantID]
	if !exists {
		return fmt.Errorf("client tenant not found: %s", tenantID)
	}

	// Remove from both maps
	delete(s.clientTenants, tenantID)
	delete(s.clientTenantsByID, client.ClientIdentifier)

	return nil
}

// Admin consent request management

// StoreAdminConsentRequest stores an admin consent request
func (s *MemoryClientTenantStore) StoreAdminConsentRequest(request *business.AdminConsentRequest) error {
	s.consentRequestsMutex.Lock()
	defer s.consentRequestsMutex.Unlock()

	s.adminConsentRequests[request.State] = request
	return nil
}

// GetAdminConsentRequest retrieves an admin consent request by state
func (s *MemoryClientTenantStore) GetAdminConsentRequest(state string) (*business.AdminConsentRequest, error) {
	s.consentRequestsMutex.RLock()
	defer s.consentRequestsMutex.RUnlock()

	request, exists := s.adminConsentRequests[state]
	if !exists {
		return nil, fmt.Errorf("admin consent request not found: %s", state)
	}

	// Check if request has expired
	if time.Now().After(request.ExpiresAt) {
		return nil, fmt.Errorf("admin consent request expired: %s", state)
	}

	// Return a copy to prevent external modification
	requestCopy := *request
	return &requestCopy, nil
}

// DeleteAdminConsentRequest removes an admin consent request
func (s *MemoryClientTenantStore) DeleteAdminConsentRequest(state string) error {
	s.consentRequestsMutex.Lock()
	defer s.consentRequestsMutex.Unlock()

	delete(s.adminConsentRequests, state)
	return nil
}

// Close stops the background cleanup goroutine and releases any held resources.
// Required by business.ClientTenantStore — memory-only implementation has no
// OS handles to release, but we must terminate the cleanup goroutine so test
// binaries can exit cleanly.
func (s *MemoryClientTenantStore) Close() error {
	s.stopOnce.Do(func() {
		close(s.stopCleanup)
	})
	return nil
}

// Utility methods

// GetStats returns statistics about stored data
func (s *MemoryClientTenantStore) GetStats() map[string]interface{} {
	s.clientTenantsMutex.RLock()
	s.consentRequestsMutex.RLock()
	defer s.clientTenantsMutex.RUnlock()
	defer s.consentRequestsMutex.RUnlock()

	// Count by status
	statusCounts := make(map[business.ClientTenantStatus]int)
	for _, client := range s.clientTenants {
		statusCounts[client.Status]++
	}

	return map[string]interface{}{
		"total_clients":            len(s.clientTenants),
		"pending_consent_requests": len(s.adminConsentRequests),
		"clients_by_status":        statusCounts,
		"last_updated":             time.Now(),
	}
}

// CleanupExpiredRequests removes expired admin consent requests
func (s *MemoryClientTenantStore) CleanupExpiredRequests() int {
	s.consentRequestsMutex.Lock()
	defer s.consentRequestsMutex.Unlock()

	now := time.Now()
	expiredCount := 0

	for state, request := range s.adminConsentRequests {
		if now.After(request.ExpiresAt) {
			delete(s.adminConsentRequests, state)
			expiredCount++
		}
	}

	return expiredCount
}

// Background cleanup goroutine
func (s *MemoryClientTenantStore) cleanupExpiredRequests() {
	ticker := time.NewTicker(5 * time.Minute) // Cleanup every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.CleanupExpiredRequests()
		case <-s.stopCleanup:
			return
		}
	}
}

// GetClientTenantsByStatus returns clients filtered by status with additional filtering options
func (s *MemoryClientTenantStore) GetClientTenantsByStatus(status business.ClientTenantStatus, limit int) ([]*business.ClientTenant, error) {
	s.clientTenantsMutex.RLock()
	defer s.clientTenantsMutex.RUnlock()

	var clients []*business.ClientTenant
	count := 0

	for _, client := range s.clientTenants {
		if status != "" && client.Status != status {
			continue
		}

		// Return a copy to prevent external modification
		clientCopy := *client
		clients = append(clients, &clientCopy)

		count++
		if limit > 0 && count >= limit {
			break
		}
	}

	return clients, nil
}

// UpdateClientTenantMetadata updates metadata for a client tenant
func (s *MemoryClientTenantStore) UpdateClientTenantMetadata(tenantID string, metadata map[string]interface{}) error {
	s.clientTenantsMutex.Lock()
	defer s.clientTenantsMutex.Unlock()

	client, exists := s.clientTenants[tenantID]
	if !exists {
		return fmt.Errorf("client tenant not found: %s", tenantID)
	}

	// Initialize metadata if nil
	if client.Metadata == nil {
		client.Metadata = make(map[string]interface{})
	}

	// Merge metadata
	for key, value := range metadata {
		client.Metadata[key] = value
	}

	client.UpdatedAt = time.Now()

	return nil
}

// Search functionality for development/debugging
func (s *MemoryClientTenantStore) SearchClientTenants(query string) ([]*business.ClientTenant, error) {
	s.clientTenantsMutex.RLock()
	defer s.clientTenantsMutex.RUnlock()

	var results []*business.ClientTenant

	for _, client := range s.clientTenants {
		// Simple search in tenant name, domain name, and client identifier
		if containsIgnoreCase(client.TenantName, query) ||
			containsIgnoreCase(client.DomainName, query) ||
			containsIgnoreCase(client.ClientIdentifier, query) ||
			containsIgnoreCase(client.AdminEmail, query) {

			clientCopy := *client
			results = append(results, &clientCopy)
		}
	}

	return results, nil
}

// Helper function for case-insensitive string search
func containsIgnoreCase(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}

	sLower := stringToLower(s)
	substrLower := stringToLower(substr)

	for i := 0; i <= len(sLower)-len(substrLower); i++ {
		if sLower[i:i+len(substrLower)] == substrLower {
			return true
		}
	}
	return false
}

// Simple lowercase conversion (basic implementation)
func stringToLower(s string) string {
	// ASCII-only lowercase; sufficient for the identifiers this store searches.
	result := make([]byte, len(s))
	for i, r := range []byte(s) {
		if r >= 'A' && r <= 'Z' {
			result[i] = r + 32
		} else {
			result[i] = r
		}
	}
	return string(result)
}
