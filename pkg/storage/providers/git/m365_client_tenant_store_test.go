// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package git

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	secretsInterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockSecretStore is a test implementation of SecretStore
type MockSecretStore struct{}

func (m *MockSecretStore) StoreSecret(ctx context.Context, req *secretsInterfaces.SecretRequest) error {
	return nil
}

func (m *MockSecretStore) GetSecret(ctx context.Context, key string) (*secretsInterfaces.Secret, error) {
	return &secretsInterfaces.Secret{Key: key, Value: "test-value"}, nil
}

func (m *MockSecretStore) DeleteSecret(ctx context.Context, key string) error {
	return nil
}

func (m *MockSecretStore) ListSecrets(ctx context.Context, filter *secretsInterfaces.SecretFilter) ([]*secretsInterfaces.SecretMetadata, error) {
	return nil, nil
}

func (m *MockSecretStore) GetSecrets(ctx context.Context, keys []string) (map[string]*secretsInterfaces.Secret, error) {
	return nil, nil
}

func (m *MockSecretStore) StoreSecrets(ctx context.Context, secrets map[string]*secretsInterfaces.SecretRequest) error {
	return nil
}

func (m *MockSecretStore) GetSecretVersion(ctx context.Context, key string, version int) (*secretsInterfaces.Secret, error) {
	return nil, nil
}

func (m *MockSecretStore) ListSecretVersions(ctx context.Context, key string) ([]*secretsInterfaces.SecretVersion, error) {
	return nil, nil
}

func (m *MockSecretStore) GetSecretMetadata(ctx context.Context, key string) (*secretsInterfaces.SecretMetadata, error) {
	return nil, nil
}

func (m *MockSecretStore) UpdateSecretMetadata(ctx context.Context, key string, metadata map[string]string) error {
	return nil
}

func (m *MockSecretStore) RotateSecret(ctx context.Context, key string, newValue string) error {
	return nil
}

func (m *MockSecretStore) ExpireSecret(ctx context.Context, key string) error {
	return nil
}

func (m *MockSecretStore) HealthCheck(ctx context.Context) error {
	return nil
}

func (m *MockSecretStore) Close() error {
	return nil
}

func TestGitM365ClientTenantStore_NewStore(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	secretStore := &MockSecretStore{}

	store, err := NewGitM365ClientTenantStore(tempDir, "", secretStore)
	require.NoError(t, err)
	require.NotNil(t, store)

	// Verify directories were created
	assert.DirExists(t, filepath.Join(tempDir, "m365", "client_tenants"))
	assert.DirExists(t, filepath.Join(tempDir, "m365", "consent_requests"))

	err = store.Close()
	assert.NoError(t, err)
}

func TestGitM365ClientTenantStore_NewStore_RequiresSecretStore(t *testing.T) {
	tempDir := t.TempDir()

	// Should fail without secret store
	_, err := NewGitM365ClientTenantStore(tempDir, "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secretStore cannot be nil")
}

func TestGitM365ClientTenantStore_ClientTenant_CRUD(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()
	secretStore := &MockSecretStore{}

	store, err := NewGitM365ClientTenantStore(tempDir, "", secretStore)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Test data
	client := &interfaces.M365ClientTenant{
		ID:               "test-id-1",
		TenantID:         "tenant-123",
		TenantName:       "Test Client Corp",
		DomainName:       "testclient.com",
		AdminEmail:       "admin@testclient.com",
		ConsentedAt:      time.Now().UTC().Truncate(time.Second),
		Status:           interfaces.M365ClientTenantStatusActive,
		ClientIdentifier: "client-abc123",
		Metadata: map[string]interface{}{
			"region": "us-east-1",
			"tier":   "premium",
		},
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
	}

	// Test Create
	err = store.StoreClientTenant(ctx, client)
	require.NoError(t, err)

	// Test Read by TenantID
	retrieved, err := store.GetClientTenant(ctx, client.TenantID)
	require.NoError(t, err)
	assert.Equal(t, client.ID, retrieved.ID)
	assert.Equal(t, client.TenantID, retrieved.TenantID)
	assert.Equal(t, client.TenantName, retrieved.TenantName)
	assert.Equal(t, client.DomainName, retrieved.DomainName)
	assert.Equal(t, client.AdminEmail, retrieved.AdminEmail)
	assert.Equal(t, client.Status, retrieved.Status)
	assert.Equal(t, client.ClientIdentifier, retrieved.ClientIdentifier)
	assert.Equal(t, client.Metadata["region"], retrieved.Metadata["region"])

	// Test Read by ClientIdentifier
	retrievedByID, err := store.GetClientTenantByIdentifier(ctx, client.ClientIdentifier)
	require.NoError(t, err)
	assert.Equal(t, client.TenantID, retrievedByID.TenantID)

	// Test Update
	client.TenantName = "Updated Client Corp"
	client.Status = interfaces.M365ClientTenantStatusSuspended
	err = store.StoreClientTenant(ctx, client)
	require.NoError(t, err)

	updated, err := store.GetClientTenant(ctx, client.TenantID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Client Corp", updated.TenantName)
	assert.Equal(t, interfaces.M365ClientTenantStatusSuspended, updated.Status)

	// Test Delete
	err = store.DeleteClientTenant(ctx, client.TenantID)
	require.NoError(t, err)

	// Verify deletion
	_, err = store.GetClientTenant(ctx, client.TenantID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGitM365ClientTenantStore_ListClientTenants(t *testing.T) {
	tempDir := t.TempDir()
	secretStore := &MockSecretStore{}

	store, err := NewGitM365ClientTenantStore(tempDir, "", secretStore)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create multiple clients with different statuses
	clients := []*interfaces.M365ClientTenant{
		{
			ID:               "id-1",
			TenantID:         "tenant-1",
			TenantName:       "Client 1",
			ClientIdentifier: "client-1",
			Status:           interfaces.M365ClientTenantStatusActive,
			ConsentedAt:      time.Now(),
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		},
		{
			ID:               "id-2",
			TenantID:         "tenant-2",
			TenantName:       "Client 2",
			ClientIdentifier: "client-2",
			Status:           interfaces.M365ClientTenantStatusActive,
			ConsentedAt:      time.Now(),
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		},
		{
			ID:               "id-3",
			TenantID:         "tenant-3",
			TenantName:       "Client 3",
			ClientIdentifier: "client-3",
			Status:           interfaces.M365ClientTenantStatusSuspended,
			ConsentedAt:      time.Now(),
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		},
	}

	for _, client := range clients {
		err := store.StoreClientTenant(ctx, client)
		require.NoError(t, err)
	}

	// List all clients
	allClients, err := store.ListClientTenants(ctx, "")
	require.NoError(t, err)
	assert.Len(t, allClients, 3)

	// List active clients only
	activeClients, err := store.ListClientTenants(ctx, interfaces.M365ClientTenantStatusActive)
	require.NoError(t, err)
	assert.Len(t, activeClients, 2)

	// List suspended clients only
	suspendedClients, err := store.ListClientTenants(ctx, interfaces.M365ClientTenantStatusSuspended)
	require.NoError(t, err)
	assert.Len(t, suspendedClients, 1)
}

func TestGitM365ClientTenantStore_UpdateClientTenantStatus(t *testing.T) {
	tempDir := t.TempDir()
	secretStore := &MockSecretStore{}

	store, err := NewGitM365ClientTenantStore(tempDir, "", secretStore)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	client := &interfaces.M365ClientTenant{
		ID:               "id-1",
		TenantID:         "tenant-1",
		TenantName:       "Test Client",
		ClientIdentifier: "client-1",
		Status:           interfaces.M365ClientTenantStatusPending,
		ConsentedAt:      time.Now(),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	err = store.StoreClientTenant(ctx, client)
	require.NoError(t, err)

	// Update status
	err = store.UpdateClientTenantStatus(ctx, client.TenantID, interfaces.M365ClientTenantStatusActive)
	require.NoError(t, err)

	// Verify status was updated
	updated, err := store.GetClientTenant(ctx, client.TenantID)
	require.NoError(t, err)
	assert.Equal(t, interfaces.M365ClientTenantStatusActive, updated.Status)
}

func TestGitM365ClientTenantStore_AdminConsentRequest_CRUD(t *testing.T) {
	tempDir := t.TempDir()
	secretStore := &MockSecretStore{}

	store, err := NewGitM365ClientTenantStore(tempDir, "", secretStore)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Test data
	request := &interfaces.M365AdminConsentRequest{
		ClientIdentifier: "client-123",
		ClientName:       "Test Client",
		RequestedBy:      "admin@msp.com",
		State:            "state-abc123",
		ExpiresAt:        time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second),
		Metadata: map[string]interface{}{
			"ip_address": "192.168.1.1",
		},
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}

	// Test Create
	err = store.StoreAdminConsentRequest(ctx, request)
	require.NoError(t, err)

	// Test Read
	retrieved, err := store.GetAdminConsentRequest(ctx, request.State)
	require.NoError(t, err)
	assert.Equal(t, request.ClientIdentifier, retrieved.ClientIdentifier)
	assert.Equal(t, request.ClientName, retrieved.ClientName)
	assert.Equal(t, request.RequestedBy, retrieved.RequestedBy)
	assert.Equal(t, request.State, retrieved.State)

	// Test Delete
	err = store.DeleteAdminConsentRequest(ctx, request.State)
	require.NoError(t, err)

	// Verify deletion
	_, err = store.GetAdminConsentRequest(ctx, request.State)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGitM365ClientTenantStore_GetAdminConsentRequest_Expired(t *testing.T) {
	tempDir := t.TempDir()
	secretStore := &MockSecretStore{}

	store, err := NewGitM365ClientTenantStore(tempDir, "", secretStore)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create expired request
	request := &interfaces.M365AdminConsentRequest{
		ClientIdentifier: "client-123",
		ClientName:       "Test Client",
		RequestedBy:      "admin@msp.com",
		State:            "state-expired",
		ExpiresAt:        time.Now().Add(-1 * time.Hour), // Already expired
		CreatedAt:        time.Now(),
	}

	err = store.StoreAdminConsentRequest(ctx, request)
	require.NoError(t, err)

	// Try to retrieve expired request
	_, err = store.GetAdminConsentRequest(ctx, request.State)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestGitM365ClientTenantStore_CleanupExpiredRequests(t *testing.T) {
	tempDir := t.TempDir()
	secretStore := &MockSecretStore{}

	store, err := NewGitM365ClientTenantStore(tempDir, "", secretStore)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create expired and valid requests
	expiredRequest := &interfaces.M365AdminConsentRequest{
		ClientIdentifier: "client-1",
		ClientName:       "Expired Client",
		RequestedBy:      "admin@msp.com",
		State:            "state-expired",
		ExpiresAt:        time.Now().Add(-1 * time.Hour),
		CreatedAt:        time.Now(),
	}

	validRequest := &interfaces.M365AdminConsentRequest{
		ClientIdentifier: "client-2",
		ClientName:       "Valid Client",
		RequestedBy:      "admin@msp.com",
		State:            "state-valid",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		CreatedAt:        time.Now(),
	}

	err = store.StoreAdminConsentRequest(ctx, expiredRequest)
	require.NoError(t, err)
	err = store.StoreAdminConsentRequest(ctx, validRequest)
	require.NoError(t, err)

	// Cleanup expired requests
	count, err := store.CleanupExpiredRequests(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify expired request was deleted
	_, err = store.GetAdminConsentRequest(ctx, expiredRequest.State)
	assert.Error(t, err)

	// Verify valid request still exists
	_, err = store.GetAdminConsentRequest(ctx, validRequest.State)
	assert.NoError(t, err)
}

func TestGitM365ClientTenantStore_GetStats(t *testing.T) {
	tempDir := t.TempDir()
	secretStore := &MockSecretStore{}

	store, err := NewGitM365ClientTenantStore(tempDir, "", secretStore)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create test data
	clients := []*interfaces.M365ClientTenant{
		{
			ID:               "id-1",
			TenantID:         "tenant-1",
			TenantName:       "Client 1",
			ClientIdentifier: "client-1",
			Status:           interfaces.M365ClientTenantStatusActive,
			ConsentedAt:      time.Now(),
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		},
		{
			ID:               "id-2",
			TenantID:         "tenant-2",
			TenantName:       "Client 2",
			ClientIdentifier: "client-2",
			Status:           interfaces.M365ClientTenantStatusSuspended,
			ConsentedAt:      time.Now(),
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		},
	}

	for _, client := range clients {
		err := store.StoreClientTenant(ctx, client)
		require.NoError(t, err)
	}

	// Create pending consent request
	request := &interfaces.M365AdminConsentRequest{
		ClientIdentifier: "client-3",
		ClientName:       "Pending Client",
		RequestedBy:      "admin@msp.com",
		State:            "state-pending",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		CreatedAt:        time.Now(),
	}
	err = store.StoreAdminConsentRequest(ctx, request)
	require.NoError(t, err)

	// Get stats
	stats, err := store.GetStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, stats.TotalClients)
	assert.Equal(t, 1, stats.PendingConsentRequests)
	assert.Equal(t, 1, stats.ClientsByStatus[interfaces.M365ClientTenantStatusActive])
	assert.Equal(t, 1, stats.ClientsByStatus[interfaces.M365ClientTenantStatusSuspended])
}

func TestGitM365ClientTenantStore_PathTraversalPrevention(t *testing.T) {
	tempDir := t.TempDir()
	secretStore := &MockSecretStore{}

	store, err := NewGitM365ClientTenantStore(tempDir, "", secretStore)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Try to create client with path traversal in tenant ID
	maliciousClient := &interfaces.M365ClientTenant{
		ID:               "evil-id",
		TenantID:         "../../../etc/passwd",
		TenantName:       "Evil Client",
		ClientIdentifier: "evil-client",
		Status:           interfaces.M365ClientTenantStatusActive,
		ConsentedAt:      time.Now(),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	err = store.StoreClientTenant(ctx, maliciousClient)
	require.NoError(t, err)

	// Verify it was sanitized and stored safely within the repo
	retrieved, err := store.GetClientTenant(ctx, maliciousClient.TenantID)
	require.NoError(t, err)
	assert.Equal(t, maliciousClient.TenantID, retrieved.TenantID)

	// Verify no files were created outside the repository
	// The sanitized filename should be stored within the repo
	filename := store.sanitizeFilename(maliciousClient.TenantID) + ".json"
	expectedPath := filepath.Join(tempDir, "m365", "client_tenants", filename)
	assert.FileExists(t, expectedPath)

	// Verify nothing was created outside tempDir
	parentDir := filepath.Dir(tempDir)
	etcPasswdPath := filepath.Join(parentDir, "etc", "passwd")
	assert.NoFileExists(t, etcPasswdPath)
}

func TestGitM365ClientTenantStore_Initialize(t *testing.T) {
	tempDir := t.TempDir()
	secretStore := &MockSecretStore{}

	store, err := NewGitM365ClientTenantStore(tempDir, "", secretStore)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Test Initialize
	err = store.Initialize(ctx)
	require.NoError(t, err)

	// Verify directories exist
	assert.DirExists(t, filepath.Join(tempDir, "m365", "client_tenants"))
	assert.DirExists(t, filepath.Join(tempDir, "m365", "consent_requests"))
}

func TestGitM365ClientTenantStore_DataPersistence(t *testing.T) {
	tempDir := t.TempDir()
	secretStore := &MockSecretStore{}

	ctx := context.Background()

	// Create store and add data
	{
		store, err := NewGitM365ClientTenantStore(tempDir, "", secretStore)
		require.NoError(t, err)

		client := &interfaces.M365ClientTenant{
			ID:               "persistent-id",
			TenantID:         "persistent-tenant",
			TenantName:       "Persistent Client",
			ClientIdentifier: "persistent-client",
			Status:           interfaces.M365ClientTenantStatusActive,
			ConsentedAt:      time.Now(),
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		}

		err = store.StoreClientTenant(ctx, client)
		require.NoError(t, err)

		err = store.Close()
		require.NoError(t, err)
	}

	// Recreate store and verify data persisted
	{
		store, err := NewGitM365ClientTenantStore(tempDir, "", secretStore)
		require.NoError(t, err)
		defer store.Close()

		retrieved, err := store.GetClientTenant(ctx, "persistent-tenant")
		require.NoError(t, err)
		assert.Equal(t, "Persistent Client", retrieved.TenantName)
		assert.Equal(t, "persistent-client", retrieved.ClientIdentifier)
	}
}
