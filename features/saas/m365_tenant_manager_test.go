// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package saas

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/tenant"
)

// Mock implementations

type mockTenantStore struct {
	tenants map[string]*tenant.Tenant
}

func newMockTenantStore() *mockTenantStore {
	return &mockTenantStore{
		tenants: make(map[string]*tenant.Tenant),
	}
}

func (m *mockTenantStore) CreateTenant(ctx context.Context, t *tenant.Tenant) error {
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()
	m.tenants[t.ID] = t
	return nil
}

func (m *mockTenantStore) GetTenant(ctx context.Context, tenantID string) (*tenant.Tenant, error) {
	t, exists := m.tenants[tenantID]
	if !exists {
		return nil, tenant.ErrTenantNotFound
	}
	return t, nil
}

func (m *mockTenantStore) UpdateTenant(ctx context.Context, t *tenant.Tenant) error {
	if _, exists := m.tenants[t.ID]; !exists {
		return tenant.ErrTenantNotFound
	}
	t.UpdatedAt = time.Now()
	m.tenants[t.ID] = t
	return nil
}

func (m *mockTenantStore) DeleteTenant(ctx context.Context, tenantID string) error {
	delete(m.tenants, tenantID)
	return nil
}

func (m *mockTenantStore) ListTenants(ctx context.Context, filter *tenant.TenantFilter) ([]*tenant.Tenant, error) {
	var result []*tenant.Tenant
	for _, t := range m.tenants {
		if filter != nil {
			if filter.Status != "" && t.Status != filter.Status {
				continue
			}
			if filter.ParentID != "" && t.ParentID != filter.ParentID {
				continue
			}
		}
		result = append(result, t)
	}
	return result, nil
}

func (m *mockTenantStore) GetTenantHierarchy(ctx context.Context, tenantID string) (*tenant.TenantHierarchy, error) {
	return &tenant.TenantHierarchy{
		TenantID: tenantID,
		Path:     []string{tenantID},
		Depth:    0,
		Children: []string{},
	}, nil
}

func (m *mockTenantStore) GetChildTenants(ctx context.Context, parentID string) ([]*tenant.Tenant, error) {
	var children []*tenant.Tenant
	for _, t := range m.tenants {
		if t.ParentID == parentID {
			children = append(children, t)
		}
	}
	return children, nil
}

func (m *mockTenantStore) GetTenantPath(ctx context.Context, tenantID string) ([]string, error) {
	return []string{tenantID}, nil
}

func (m *mockTenantStore) IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error) {
	return false, nil
}

type mockCredentialStore struct{}

func (m *mockCredentialStore) StoreTokenSet(provider string, tokens *TokenSet) error {
	return nil
}

func (m *mockCredentialStore) GetTokenSet(provider string) (*TokenSet, error) {
	return &TokenSet{
		AccessToken:  "mock-token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		RefreshToken: "mock-refresh",
	}, nil
}

func (m *mockCredentialStore) DeleteTokenSet(provider string) error {
	return nil
}

func (m *mockCredentialStore) StoreClientSecret(provider, clientSecret string) error {
	return nil
}

func (m *mockCredentialStore) GetClientSecret(provider string) (string, error) {
	return "mock-secret", nil
}

func (m *mockCredentialStore) IsAvailable() bool {
	return true
}

// Test setup helper
func setupTestManager(t *testing.T) (*M365TenantManager, *mockTenantStore, context.Context) {
	ctx := context.Background()

	// Create mock tenant store
	mockStore := newMockTenantStore()

	// Create CFGMS tenant manager without RBAC for these tests
	// (M365 integration tests don't need full RBAC setup)
	cfgmsTenantManager := tenant.NewManager(mockStore, nil)

	// Create mock credential store
	mockCredStore := &mockCredentialStore{}

	// Create M365 provider
	httpClient := &http.Client{Timeout: 30 * time.Second}
	m365Provider := NewMicrosoftMultiTenantProvider(mockCredStore, httpClient)

	// Create admin consent flow (can be nil for basic tests)
	var adminConsentFlow *auth.AdminConsentFlow

	// Create GDAP provider (can be nil for basic tests)
	var gdapProvider GDAPProvider

	// Create M365 tenant manager
	manager := NewM365TenantManager(
		cfgmsTenantManager,
		m365Provider,
		adminConsentFlow,
		gdapProvider,
	)

	return manager, mockStore, ctx
}

// Tests

func TestNewM365TenantManager(t *testing.T) {
	manager, _, _ := setupTestManager(t)

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.cfgmsTenantManager)
	assert.NotNil(t, manager.m365Provider)
	assert.NotNil(t, manager.httpClient)
}

func TestM365TenantMetadata_MarshalUnmarshal(t *testing.T) {
	// Test that M365TenantMetadata can be marshaled and unmarshaled correctly
	original := &tenant.M365TenantMetadata{
		M365TenantID:       "test-tenant-id",
		PrimaryDomain:      "contoso.com",
		TokenExpiresAt:     time.Now().Add(1 * time.Hour),
		ConsentedAt:        time.Now(),
		AdminEmail:         "admin@contoso.com",
		GDAPRelationshipID: "gdap-rel-123",
		LastHealthCheck:    time.Now(),
		HealthStatus:       tenant.HealthStatusHealthy,
		HealthDetails:      "",
		CountryCode:        "US",
		TenantType:         "AAD",
		DiscoveredAt:       time.Now(),
		DiscoveryMethod:    "admin_consent",
	}

	// Marshal
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal
	var unmarshaled tenant.M365TenantMetadata
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.M365TenantID, unmarshaled.M365TenantID)
	assert.Equal(t, original.PrimaryDomain, unmarshaled.PrimaryDomain)
	assert.Equal(t, original.AdminEmail, unmarshaled.AdminEmail)
	assert.Equal(t, original.HealthStatus, unmarshaled.HealthStatus)
	assert.Equal(t, original.DiscoveryMethod, unmarshaled.DiscoveryMethod)
}

func TestCreateCFGMSTenant(t *testing.T) {
	manager, mockStore, ctx := setupTestManager(t)

	m365Tenant := &TenantInfo{
		TenantID:    "m365-tenant-123",
		DisplayName: "Contoso-Ltd",
		Domain:      "contoso.com",
		CountryCode: "US",
		TenantType:  "AAD",
		HasAccess:   true,
	}

	err := manager.createCFGMSTenant(ctx, m365Tenant, "admin_consent", time.Now())
	require.NoError(t, err)

	// Verify tenant was created
	tenants, err := mockStore.ListTenants(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, tenants, 1)

	createdTenant := tenants[0]
	assert.Equal(t, "Contoso-Ltd", createdTenant.Name)
	assert.Contains(t, createdTenant.Metadata, "m365_metadata")
	assert.Equal(t, "m365", createdTenant.Metadata["tenant_type"])

	// Verify M365 metadata
	metadata, err := manager.getM365Metadata(createdTenant)
	require.NoError(t, err)
	assert.Equal(t, "m365-tenant-123", metadata.M365TenantID)
	assert.Equal(t, "contoso.com", metadata.PrimaryDomain)
	assert.Equal(t, "US", metadata.CountryCode)
	assert.Equal(t, "admin_consent", metadata.DiscoveryMethod)
}

func TestGetM365Metadata(t *testing.T) {
	manager, _, _ := setupTestManager(t)

	// Create tenant with M365 metadata
	m365Metadata := &tenant.M365TenantMetadata{
		M365TenantID:    "test-tenant",
		PrimaryDomain:   "test.com",
		HealthStatus:    tenant.HealthStatusHealthy,
		DiscoveryMethod: "admin_consent",
	}

	metadataJSON, err := json.Marshal(m365Metadata)
	require.NoError(t, err)

	cfgmsTenant := &tenant.Tenant{
		ID:   "cfgms-123",
		Name: "Test-Tenant",
		Metadata: map[string]string{
			"m365_metadata": string(metadataJSON),
			"tenant_type":   "m365",
		},
	}

	// Get metadata
	retrieved, err := manager.getM365Metadata(cfgmsTenant)
	require.NoError(t, err)
	assert.Equal(t, "test-tenant", retrieved.M365TenantID)
	assert.Equal(t, "test.com", retrieved.PrimaryDomain)
	assert.Equal(t, tenant.HealthStatusHealthy, retrieved.HealthStatus)
}

func TestGetM365Metadata_NotFound(t *testing.T) {
	manager, _, _ := setupTestManager(t)

	cfgmsTenant := &tenant.Tenant{
		ID:       "cfgms-123",
		Name:     "Test Tenant",
		Metadata: map[string]string{},
	}

	_, err := manager.getM365Metadata(cfgmsTenant)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "M365 metadata not found")
}

func TestCheckTokenValidity(t *testing.T) {
	manager, _, ctx := setupTestManager(t)

	tests := []struct {
		name           string
		tokenExpiresAt time.Time
		expectedStatus tenant.HealthStatus
		expectedMsg    string
	}{
		{
			name:           "Valid token",
			tokenExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 days
			expectedStatus: tenant.HealthStatusHealthy,
			expectedMsg:    "Token valid until",
		},
		{
			name:           "Token expiring soon",
			tokenExpiresAt: time.Now().Add(3 * 24 * time.Hour), // 3 days
			expectedStatus: tenant.HealthStatusDegraded,
			expectedMsg:    "Token expires soon",
		},
		{
			name:           "Expired token",
			tokenExpiresAt: time.Now().Add(-1 * time.Hour),
			expectedStatus: tenant.HealthStatusUnhealthy,
			expectedMsg:    "Token expired",
		},
		{
			name:           "No expiration set",
			tokenExpiresAt: time.Time{},
			expectedStatus: tenant.HealthStatusUnknown,
			expectedMsg:    "Token expiration time not set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := &tenant.M365TenantMetadata{
				TokenExpiresAt: tt.tokenExpiresAt,
			}

			result := manager.checkTokenValidity(ctx, metadata)
			assert.Equal(t, tt.expectedStatus, result.Status)
			assert.Contains(t, result.Message, tt.expectedMsg)
		})
	}
}

func TestCalculateOverallHealth(t *testing.T) {
	manager, _, _ := setupTestManager(t)

	tests := []struct {
		name           string
		checks         map[string]HealthCheckResult
		expectedStatus tenant.HealthStatus
	}{
		{
			name: "All healthy",
			checks: map[string]HealthCheckResult{
				"token": {Status: tenant.HealthStatusHealthy},
				"api":   {Status: tenant.HealthStatusHealthy},
			},
			expectedStatus: tenant.HealthStatusHealthy,
		},
		{
			name: "One degraded",
			checks: map[string]HealthCheckResult{
				"token": {Status: tenant.HealthStatusHealthy},
				"api":   {Status: tenant.HealthStatusDegraded},
			},
			expectedStatus: tenant.HealthStatusDegraded,
		},
		{
			name: "One unhealthy",
			checks: map[string]HealthCheckResult{
				"token": {Status: tenant.HealthStatusHealthy},
				"api":   {Status: tenant.HealthStatusUnhealthy},
			},
			expectedStatus: tenant.HealthStatusUnhealthy,
		},
		{
			name: "Mixed degraded and unhealthy",
			checks: map[string]HealthCheckResult{
				"token": {Status: tenant.HealthStatusDegraded},
				"api":   {Status: tenant.HealthStatusUnhealthy},
			},
			expectedStatus: tenant.HealthStatusUnhealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := manager.calculateOverallHealth(tt.checks)
			assert.Equal(t, tt.expectedStatus, status)
		})
	}
}

func TestGenerateHealthDetails(t *testing.T) {
	manager, _, _ := setupTestManager(t)

	checks := map[string]HealthCheckResult{
		"token": {
			Name:    "token_validity",
			Status:  tenant.HealthStatusDegraded,
			Message: "Token expires soon",
		},
		"api": {
			Name:    "graph_api",
			Status:  tenant.HealthStatusUnhealthy,
			Message: "Connection failed",
		},
		"gdap": {
			Name:    "gdap_relationship",
			Status:  tenant.HealthStatusHealthy,
			Message: "Active",
		},
	}

	details := manager.generateHealthDetails(checks)

	// Should contain unhealthy and degraded, but not healthy
	assert.Contains(t, details, "token_validity")
	assert.Contains(t, details, "Token expires soon")
	assert.Contains(t, details, "graph_api")
	assert.Contains(t, details, "Connection failed")
	assert.NotContains(t, details, "Active") // Healthy check should not be in details
}

func TestListM365Tenants(t *testing.T) {
	manager, mockStore, ctx := setupTestManager(t)

	// Create M365 tenant
	m365Metadata := &tenant.M365TenantMetadata{
		M365TenantID:  "m365-1",
		PrimaryDomain: "test.com",
	}
	metadataJSON, _ := json.Marshal(m365Metadata)

	m365Tenant := &tenant.Tenant{
		ID:   "tenant-1",
		Name: "M365-Tenant",
		Metadata: map[string]string{
			"m365_metadata": string(metadataJSON),
			"tenant_type":   "m365",
		},
	}

	// Create non-M365 tenant
	regularTenant := &tenant.Tenant{
		ID:       "tenant-2",
		Name:     "Regular-Tenant",
		Metadata: map[string]string{},
	}

	// Add both to store
	require.NoError(t, mockStore.CreateTenant(ctx, m365Tenant))
	require.NoError(t, mockStore.CreateTenant(ctx, regularTenant))

	// List M365 tenants
	m365Tenants, err := manager.listM365Tenants(ctx)
	require.NoError(t, err)

	// Should only return M365 tenant
	assert.Len(t, m365Tenants, 1)
	assert.Equal(t, "tenant-1", m365Tenants[0].ID)
}

func TestGetTenantByM365ID(t *testing.T) {
	manager, mockStore, ctx := setupTestManager(t)

	// Create M365 tenant
	m365Metadata := &tenant.M365TenantMetadata{
		M365TenantID:  "m365-target",
		PrimaryDomain: "target.com",
	}
	metadataJSON, _ := json.Marshal(m365Metadata)

	targetTenant := &tenant.Tenant{
		ID:   "cfgms-target",
		Name: "Target-Tenant",
		Metadata: map[string]string{
			"m365_metadata": string(metadataJSON),
			"tenant_type":   "m365",
		},
	}

	require.NoError(t, mockStore.CreateTenant(ctx, targetTenant))

	// Find by M365 ID
	found, err := manager.getTenantByM365ID(ctx, "m365-target")
	require.NoError(t, err)
	assert.Equal(t, "cfgms-target", found.ID)
	assert.Equal(t, "Target-Tenant", found.Name)

	// Try to find non-existent
	_, err = manager.getTenantByM365ID(ctx, "non-existent")
	assert.Error(t, err)
}

func TestUpdateTenantMetadata(t *testing.T) {
	manager, mockStore, ctx := setupTestManager(t)

	// Create existing tenant
	originalMetadata := &tenant.M365TenantMetadata{
		M365TenantID:    "m365-123",
		PrimaryDomain:   "old-domain.com",
		DiscoveryMethod: "manual",
	}
	metadataJSON, _ := json.Marshal(originalMetadata)

	existingTenant := &tenant.Tenant{
		ID:   "tenant-1",
		Name: "Test-Tenant",
		Metadata: map[string]string{
			"m365_metadata": string(metadataJSON),
			"tenant_type":   "m365",
		},
		Status: tenant.TenantStatusActive,
	}

	require.NoError(t, mockStore.CreateTenant(ctx, existingTenant))

	// Update metadata
	newM365Info := &TenantInfo{
		TenantID:    "m365-123",
		DisplayName: "Test-Tenant",
		Domain:      "new-domain.com",
		CountryCode: "GB",
	}

	discoveryTime := time.Now()
	err := manager.updateTenantMetadata(ctx, existingTenant, newM365Info, "admin_consent", discoveryTime)
	require.NoError(t, err)

	// Retrieve and verify
	updated, err := mockStore.GetTenant(ctx, "tenant-1")
	require.NoError(t, err)

	updatedMetadata, err := manager.getM365Metadata(updated)
	require.NoError(t, err)

	assert.Equal(t, "new-domain.com", updatedMetadata.PrimaryDomain)
	assert.Equal(t, "GB", updatedMetadata.CountryCode)
	assert.Equal(t, "admin_consent", updatedMetadata.DiscoveryMethod)
	assert.Equal(t, discoveryTime.Unix(), updatedMetadata.DiscoveredAt.Unix())
}

func TestHealthStatus_Constants(t *testing.T) {
	// Verify health status constants are defined
	assert.Equal(t, tenant.HealthStatus("healthy"), tenant.HealthStatusHealthy)
	assert.Equal(t, tenant.HealthStatus("degraded"), tenant.HealthStatusDegraded)
	assert.Equal(t, tenant.HealthStatus("unhealthy"), tenant.HealthStatusUnhealthy)
	assert.Equal(t, tenant.HealthStatus("unknown"), tenant.HealthStatusUnknown)
}

// countingTenantStore wraps mockTenantStore and records ListTenants call count.
type countingTenantStore struct {
	*mockTenantStore
	listTenantsCallCount int
}

func (c *countingTenantStore) ListTenants(ctx context.Context, filter *tenant.TenantFilter) ([]*tenant.Tenant, error) {
	c.listTenantsCallCount++
	return c.mockTenantStore.ListTenants(ctx, filter)
}

func setupTestManagerWithCountingStore(t *testing.T) (*M365TenantManager, *countingTenantStore, context.Context) {
	t.Helper()
	ctx := context.Background()
	counting := &countingTenantStore{mockTenantStore: newMockTenantStore()}
	cfgmsTenantManager := tenant.NewManager(counting, nil)
	m365Provider := NewMicrosoftMultiTenantProvider(&mockCredentialStore{}, &http.Client{Timeout: 30 * time.Second})
	manager := NewM365TenantManager(cfgmsTenantManager, m365Provider, nil, nil)
	return manager, counting, ctx
}

func TestM365TenantManager_GetTenantByM365ID_Index(t *testing.T) {
	manager, counting, ctx := setupTestManagerWithCountingStore(t)

	const n = 5

	// Seed N tenants with distinct M365 IDs directly into the counting store.
	for i := range n {
		meta := &tenant.M365TenantMetadata{
			M365TenantID:  fmt.Sprintf("m365-idx-%d", i),
			PrimaryDomain: fmt.Sprintf("tenant%d.example.com", i),
		}
		metaJSON, err := json.Marshal(meta)
		require.NoError(t, err)
		require.NoError(t, counting.CreateTenant(ctx, &tenant.Tenant{
			ID:   fmt.Sprintf("cfgms-idx-%d", i),
			Name: fmt.Sprintf("Tenant-%d", i),
			Metadata: map[string]string{
				"m365_metadata": string(metaJSON),
				"tenant_type":   "m365",
			},
		}))
	}

	// CreateTenant does not call ListTenants; reset to isolate the lookup phase.
	counting.listTenantsCallCount = 0

	// N lookups for N distinct IDs — all reads, no writes between them.
	for i := range n {
		found, err := manager.getTenantByM365ID(ctx, fmt.Sprintf("m365-idx-%d", i))
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("cfgms-idx-%d", i), found.ID)
	}

	// Index must be populated on the first call and reused for all subsequent ones.
	assert.Equal(t, 1, counting.listTenantsCallCount,
		"ListTenants should be called exactly once across %d getTenantByM365ID calls", n)
}

// mockGDAPProvider is a test-local GDAP implementation for benchmark setup.
type mockGDAPProvider struct {
	relationships []GDAPRelationship
}

func (m *mockGDAPProvider) DiscoverGDAPCustomers(_ context.Context) ([]GDAPRelationship, error) {
	return m.relationships, nil
}

func (m *mockGDAPProvider) ValidateGDAPAccess(_ context.Context, customerTenantID string, _ []string) (*GDAPRelationship, error) {
	for i := range m.relationships {
		if m.relationships[i].CustomerTenantID == customerTenantID {
			return &m.relationships[i], nil
		}
	}
	return nil, fmt.Errorf("relationship not found")
}

func BenchmarkM365TenantManager_DiscoverAndSyncTenants(b *testing.B) {
	ctx := context.Background()
	const n = 100

	relationships := make([]GDAPRelationship, n)
	for i := range n {
		relationships[i] = GDAPRelationship{
			RelationshipID:   fmt.Sprintf("rel-%d", i),
			CustomerTenantID: fmt.Sprintf("m365-bench-%d", i),
			CustomerName:     fmt.Sprintf("Bench Tenant %d", i),
			Status:           "active",
			ExpiresAt:        time.Now().Add(365 * 24 * time.Hour),
		}
	}

	for range b.N {
		b.StopTimer()

		mockStore := newMockTenantStore()
		cfgmsTenantManager := tenant.NewManager(mockStore, nil)
		m365Provider := NewMicrosoftMultiTenantProvider(&mockCredentialStore{}, &http.Client{Timeout: 30 * time.Second})
		gdap := &mockGDAPProvider{relationships: relationships}
		manager := NewM365TenantManager(cfgmsTenantManager, m365Provider, nil, gdap)

		// Pre-seed 100 M365 tenants so all sync iterations hit the update path.
		for i := range n {
			meta := &tenant.M365TenantMetadata{
				M365TenantID:    fmt.Sprintf("m365-bench-%d", i),
				PrimaryDomain:   fmt.Sprintf("bench%d.example.com", i),
				DiscoveryMethod: "gdap",
				HealthStatus:    tenant.HealthStatusUnknown,
			}
			metaJSON, _ := json.Marshal(meta)
			_ = mockStore.CreateTenant(ctx, &tenant.Tenant{
				ID:   fmt.Sprintf("cfgms-bench-%d", i),
				Name: fmt.Sprintf("Bench-Tenant-%d", i),
				Metadata: map[string]string{
					"m365_metadata": string(metaJSON),
					"tenant_type":   "m365",
				},
			})
		}

		b.StartTimer()
		result, err := manager.DiscoverAndSyncTenants(ctx, "gdap")
		b.StopTimer()

		if err != nil {
			b.Fatalf("DiscoverAndSyncTenants failed: %v", err)
		}
		if result.Metadata["synced_count"] != n {
			b.Fatalf("expected %d synced, got %v", n, result.Metadata["synced_count"])
		}
	}
}
