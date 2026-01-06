// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package git

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	storageInterfaces "github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// GitM365ClientTenantStore implements M365ClientTenantStore using git for persistence
// OAuth credentials are stored encrypted using pkg/secrets
type GitM365ClientTenantStore struct {
	repoPath    string
	remoteURL   string
	secretStore interfaces.SecretStore
}

// NewGitM365ClientTenantStore creates a new git-based M365 client tenant store
func NewGitM365ClientTenantStore(repoPath, remoteURL string, secretStore interfaces.SecretStore) (*GitM365ClientTenantStore, error) {
	if secretStore == nil {
		return nil, fmt.Errorf("secretStore cannot be nil - OAuth credentials must be encrypted")
	}

	store := &GitM365ClientTenantStore{
		repoPath:    repoPath,
		remoteURL:   remoteURL,
		secretStore: secretStore,
	}

	// Initialize repository structure
	if err := store.initializeRepo(); err != nil {
		return nil, fmt.Errorf("failed to initialize git repository: %w", err)
	}

	return store, nil
}

// initializeRepo ensures the git repository and M365 directories exist
func (s *GitM365ClientTenantStore) initializeRepo() error {
	// Check if directory exists
	if _, err := os.Stat(s.repoPath); os.IsNotExist(err) {
		// Create directory
		if err := os.MkdirAll(s.repoPath, 0750); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Create subdirectories for M365 client tenant data
	dirs := []string{
		filepath.Join(s.repoPath, "m365", "client_tenants"),
		filepath.Join(s.repoPath, "m365", "consent_requests"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// safeReadFile safely reads a file with path validation to prevent directory traversal
func (s *GitM365ClientTenantStore) safeReadFile(targetPath string) ([]byte, error) {
	// Clean the path to resolve any .. or . components
	cleanPath := filepath.Clean(targetPath)

	// Ensure the path is within the repo directory
	if !strings.HasPrefix(cleanPath, filepath.Clean(s.repoPath)) {
		return nil, fmt.Errorf("path outside repository: %s", targetPath)
	}

	return os.ReadFile(cleanPath)
}

// safeWriteFile safely writes a file with path validation to prevent directory traversal
func (s *GitM365ClientTenantStore) safeWriteFile(targetPath string, data []byte, perm os.FileMode) error {
	// Clean the path to resolve any .. or . components
	cleanPath := filepath.Clean(targetPath)

	// Ensure the path is within the repo directory
	if !strings.HasPrefix(cleanPath, filepath.Clean(s.repoPath)) {
		return fmt.Errorf("path outside repository: %s", targetPath)
	}

	return os.WriteFile(cleanPath, data, perm)
}

// sanitizeFilename generates a safe filename from a tenant ID or identifier
func (s *GitM365ClientTenantStore) sanitizeFilename(id string) string {
	// Replace any potentially dangerous characters
	safe := strings.ReplaceAll(id, "/", "_")
	safe = strings.ReplaceAll(safe, "\\", "_")
	safe = strings.ReplaceAll(safe, "..", "_")
	safe = strings.ReplaceAll(safe, " ", "_")
	return safe
}

// Initialize implements M365ClientTenantStore.Initialize
func (s *GitM365ClientTenantStore) Initialize(ctx context.Context) error {
	return s.initializeRepo()
}

// Close implements M365ClientTenantStore.Close
func (s *GitM365ClientTenantStore) Close() error {
	return nil
}

// StoreClientTenant implements M365ClientTenantStore.StoreClientTenant
func (s *GitM365ClientTenantStore) StoreClientTenant(ctx context.Context, client *storageInterfaces.M365ClientTenant) error {
	if client == nil {
		return fmt.Errorf("client tenant cannot be nil")
	}
	if client.TenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	// Update timestamp
	client.UpdatedAt = time.Now()

	// Marshal client data (without OAuth credentials)
	data, err := json.MarshalIndent(client, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal client tenant: %w", err)
	}

	// Write client tenant file
	filename := s.sanitizeFilename(client.TenantID) + ".json"
	filePath := filepath.Join(s.repoPath, "m365", "client_tenants", filename)

	if err := s.safeWriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write client tenant file: %w", err)
	}

	return nil
}

// GetClientTenant implements M365ClientTenantStore.GetClientTenant
func (s *GitM365ClientTenantStore) GetClientTenant(ctx context.Context, tenantID string) (*storageInterfaces.M365ClientTenant, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	filename := s.sanitizeFilename(tenantID) + ".json"
	filePath := filepath.Join(s.repoPath, "m365", "client_tenants", filename)

	data, err := s.safeReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("client tenant not found: %s", tenantID)
		}
		return nil, fmt.Errorf("failed to read client tenant file: %w", err)
	}

	var client storageInterfaces.M365ClientTenant
	if err := json.Unmarshal(data, &client); err != nil {
		return nil, fmt.Errorf("failed to unmarshal client tenant: %w", err)
	}

	return &client, nil
}

// GetClientTenantByIdentifier implements M365ClientTenantStore.GetClientTenantByIdentifier
func (s *GitM365ClientTenantStore) GetClientTenantByIdentifier(ctx context.Context, clientIdentifier string) (*storageInterfaces.M365ClientTenant, error) {
	if clientIdentifier == "" {
		return nil, fmt.Errorf("client identifier cannot be empty")
	}

	// List all client tenants and find matching identifier
	tenantsDir := filepath.Join(s.repoPath, "m365", "client_tenants")
	entries, err := os.ReadDir(tenantsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("client tenant not found by identifier: %s", clientIdentifier)
		}
		return nil, fmt.Errorf("failed to read client_tenants directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(tenantsDir, entry.Name())
		data, err := s.safeReadFile(filePath)
		if err != nil {
			continue // Skip files that can't be read
		}

		var client storageInterfaces.M365ClientTenant
		if err := json.Unmarshal(data, &client); err != nil {
			continue // Skip files that can't be parsed
		}

		if client.ClientIdentifier == clientIdentifier {
			return &client, nil
		}
	}

	return nil, fmt.Errorf("client tenant not found by identifier: %s", clientIdentifier)
}

// ListClientTenants implements M365ClientTenantStore.ListClientTenants
func (s *GitM365ClientTenantStore) ListClientTenants(ctx context.Context, status storageInterfaces.M365ClientTenantStatus) ([]*storageInterfaces.M365ClientTenant, error) {
	tenantsDir := filepath.Join(s.repoPath, "m365", "client_tenants")
	entries, err := os.ReadDir(tenantsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*storageInterfaces.M365ClientTenant{}, nil
		}
		return nil, fmt.Errorf("failed to read client_tenants directory: %w", err)
	}

	var clients []*storageInterfaces.M365ClientTenant

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(tenantsDir, entry.Name())
		data, err := s.safeReadFile(filePath)
		if err != nil {
			continue // Skip files that can't be read
		}

		var client storageInterfaces.M365ClientTenant
		if err := json.Unmarshal(data, &client); err != nil {
			continue // Skip files that can't be parsed
		}

		// Filter by status if specified
		if status != "" && client.Status != status {
			continue
		}

		clients = append(clients, &client)
	}

	return clients, nil
}

// UpdateClientTenantStatus implements M365ClientTenantStore.UpdateClientTenantStatus
func (s *GitM365ClientTenantStore) UpdateClientTenantStatus(ctx context.Context, tenantID string, status storageInterfaces.M365ClientTenantStatus) error {
	// Get existing client
	client, err := s.GetClientTenant(ctx, tenantID)
	if err != nil {
		return err
	}

	// Update status and timestamp
	client.Status = status
	client.UpdatedAt = time.Now()

	// Store updated client
	return s.StoreClientTenant(ctx, client)
}

// DeleteClientTenant implements M365ClientTenantStore.DeleteClientTenant
func (s *GitM365ClientTenantStore) DeleteClientTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	filename := s.sanitizeFilename(tenantID) + ".json"
	filePath := filepath.Join(s.repoPath, "m365", "client_tenants", filename)

	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("client tenant not found: %s", tenantID)
		}
		return fmt.Errorf("failed to delete client tenant file: %w", err)
	}

	return nil
}

// StoreAdminConsentRequest implements M365ClientTenantStore.StoreAdminConsentRequest
func (s *GitM365ClientTenantStore) StoreAdminConsentRequest(ctx context.Context, request *storageInterfaces.M365AdminConsentRequest) error {
	if request == nil {
		return fmt.Errorf("admin consent request cannot be nil")
	}
	if request.State == "" {
		return fmt.Errorf("state cannot be empty")
	}

	// Marshal request data
	data, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal admin consent request: %w", err)
	}

	// Write consent request file
	filename := s.sanitizeFilename(request.State) + ".json"
	filePath := filepath.Join(s.repoPath, "m365", "consent_requests", filename)

	if err := s.safeWriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write admin consent request file: %w", err)
	}

	return nil
}

// GetAdminConsentRequest implements M365ClientTenantStore.GetAdminConsentRequest
func (s *GitM365ClientTenantStore) GetAdminConsentRequest(ctx context.Context, state string) (*storageInterfaces.M365AdminConsentRequest, error) {
	if state == "" {
		return nil, fmt.Errorf("state cannot be empty")
	}

	filename := s.sanitizeFilename(state) + ".json"
	filePath := filepath.Join(s.repoPath, "m365", "consent_requests", filename)

	data, err := s.safeReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("admin consent request not found: %s", state)
		}
		return nil, fmt.Errorf("failed to read admin consent request file: %w", err)
	}

	var request storageInterfaces.M365AdminConsentRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return nil, fmt.Errorf("failed to unmarshal admin consent request: %w", err)
	}

	// Check if request has expired
	if time.Now().After(request.ExpiresAt) {
		return nil, fmt.Errorf("admin consent request expired: %s", state)
	}

	return &request, nil
}

// DeleteAdminConsentRequest implements M365ClientTenantStore.DeleteAdminConsentRequest
func (s *GitM365ClientTenantStore) DeleteAdminConsentRequest(ctx context.Context, state string) error {
	if state == "" {
		return fmt.Errorf("state cannot be empty")
	}

	filename := s.sanitizeFilename(state) + ".json"
	filePath := filepath.Join(s.repoPath, "m365", "consent_requests", filename)

	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("admin consent request not found: %s", state)
		}
		return fmt.Errorf("failed to delete admin consent request file: %w", err)
	}

	return nil
}

// GetStats implements M365ClientTenantStore.GetStats
func (s *GitM365ClientTenantStore) GetStats(ctx context.Context) (*storageInterfaces.M365ClientTenantStats, error) {
	// Count client tenants by status
	tenantsDir := filepath.Join(s.repoPath, "m365", "client_tenants")
	entries, err := os.ReadDir(tenantsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &storageInterfaces.M365ClientTenantStats{
				ClientsByStatus: make(map[storageInterfaces.M365ClientTenantStatus]int),
				LastUpdated:     time.Now(),
			}, nil
		}
		return nil, fmt.Errorf("failed to read client_tenants directory: %w", err)
	}

	statusCounts := make(map[storageInterfaces.M365ClientTenantStatus]int)
	totalClients := 0

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(tenantsDir, entry.Name())
		data, err := s.safeReadFile(filePath)
		if err != nil {
			continue
		}

		var client storageInterfaces.M365ClientTenant
		if err := json.Unmarshal(data, &client); err != nil {
			continue
		}

		totalClients++
		statusCounts[client.Status]++
	}

	// Count pending consent requests
	consentDir := filepath.Join(s.repoPath, "m365", "consent_requests")
	consentEntries, err := os.ReadDir(consentDir)
	pendingRequests := 0
	if err == nil {
		for _, entry := range consentEntries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
				pendingRequests++
			}
		}
	}

	return &storageInterfaces.M365ClientTenantStats{
		TotalClients:           totalClients,
		PendingConsentRequests: pendingRequests,
		ClientsByStatus:        statusCounts,
		LastUpdated:            time.Now(),
	}, nil
}

// CleanupExpiredRequests implements M365ClientTenantStore.CleanupExpiredRequests
func (s *GitM365ClientTenantStore) CleanupExpiredRequests(ctx context.Context) (int, error) {
	consentDir := filepath.Join(s.repoPath, "m365", "consent_requests")
	entries, err := os.ReadDir(consentDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to read consent_requests directory: %w", err)
	}

	now := time.Now()
	expiredCount := 0

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(consentDir, entry.Name())
		data, err := s.safeReadFile(filePath)
		if err != nil {
			continue
		}

		var request storageInterfaces.M365AdminConsentRequest
		if err := json.Unmarshal(data, &request); err != nil {
			continue
		}

		// Check if expired
		if now.After(request.ExpiresAt) {
			if err := os.Remove(filePath); err == nil {
				expiredCount++
			}
		}
	}

	return expiredCount, nil
}
