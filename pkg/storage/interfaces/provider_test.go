package interfaces

import (
	"context"
	"testing"
	"time"
)

// MockStorageProvider implements StorageProvider for testing
type MockStorageProvider struct {
	name         string
	description  string
	version      string
	available    bool
	availableErr error
	capabilities ProviderCapabilities
}

func NewMockStorageProvider() *MockStorageProvider {
	return &MockStorageProvider{
		name:        "mock",
		description: "Mock storage provider for testing",
		version:     "1.0.0",
		available:   true,
		capabilities: ProviderCapabilities{
			SupportsTransactions:   true,
			SupportsVersioning:     true,
			SupportsFullTextSearch: false,
			SupportsEncryption:     true,
			SupportsCompression:    false,
			SupportsReplication:    false,
			SupportsSharding:       false,
			MaxBatchSize:          100,
			MaxConfigSize:         1024 * 1024, // 1MB
			MaxAuditRetentionDays: 365,
		},
	}
}

func (m *MockStorageProvider) Name() string {
	return m.name
}

func (m *MockStorageProvider) Description() string {
	return m.description
}

func (m *MockStorageProvider) GetVersion() string {
	return m.version
}

func (m *MockStorageProvider) Available() (bool, error) {
	return m.available, m.availableErr
}

func (m *MockStorageProvider) GetCapabilities() ProviderCapabilities {
	return m.capabilities
}

func (m *MockStorageProvider) CreateClientTenantStore(config map[string]interface{}) (ClientTenantStore, error) {
	return &MockClientTenantStore{}, nil
}

func (m *MockStorageProvider) CreateConfigStore(config map[string]interface{}) (ConfigStore, error) {
	return &MockConfigStore{}, nil
}

func (m *MockStorageProvider) CreateAuditStore(config map[string]interface{}) (AuditStore, error) {
	return &MockAuditStore{}, nil
}

// Mock implementations of store interfaces
type MockClientTenantStore struct{}

func (m *MockClientTenantStore) StoreClientTenant(client *ClientTenant) error              { return nil }
func (m *MockClientTenantStore) GetClientTenant(tenantID string) (*ClientTenant, error)   { return nil, ErrTenantNotFound }
func (m *MockClientTenantStore) GetClientTenantByIdentifier(clientIdentifier string) (*ClientTenant, error) { return nil, ErrTenantNotFound }
func (m *MockClientTenantStore) ListClientTenants(status ClientTenantStatus) ([]*ClientTenant, error) { return nil, nil }
func (m *MockClientTenantStore) UpdateClientTenantStatus(tenantID string, status ClientTenantStatus) error { return nil }
func (m *MockClientTenantStore) DeleteClientTenant(tenantID string) error                 { return nil }
func (m *MockClientTenantStore) StoreAdminConsentRequest(request *AdminConsentRequest) error { return nil }
func (m *MockClientTenantStore) GetAdminConsentRequest(state string) (*AdminConsentRequest, error) { return nil, ErrTenantNotFound }
func (m *MockClientTenantStore) DeleteAdminConsentRequest(state string) error             { return nil }

type MockConfigStore struct{}

func (m *MockConfigStore) StoreConfig(ctx context.Context, config *ConfigEntry) error         { return nil }
func (m *MockConfigStore) GetConfig(ctx context.Context, key *ConfigKey) (*ConfigEntry, error) { return nil, ErrConfigNotFound }
func (m *MockConfigStore) DeleteConfig(ctx context.Context, key *ConfigKey) error             { return nil }
func (m *MockConfigStore) ListConfigs(ctx context.Context, filter *ConfigFilter) ([]*ConfigEntry, error) { return nil, nil }
func (m *MockConfigStore) GetConfigHistory(ctx context.Context, key *ConfigKey, limit int) ([]*ConfigEntry, error) { return nil, nil }
func (m *MockConfigStore) GetConfigVersion(ctx context.Context, key *ConfigKey, version int64) (*ConfigEntry, error) { return nil, ErrConfigNotFound }
func (m *MockConfigStore) StoreConfigBatch(ctx context.Context, configs []*ConfigEntry) error { return nil }
func (m *MockConfigStore) DeleteConfigBatch(ctx context.Context, keys []*ConfigKey) error      { return nil }
func (m *MockConfigStore) ResolveConfigWithInheritance(ctx context.Context, key *ConfigKey) (*ConfigEntry, error) { return nil, ErrConfigNotFound }
func (m *MockConfigStore) ValidateConfig(ctx context.Context, config *ConfigEntry) error      { return nil }
func (m *MockConfigStore) GetConfigStats(ctx context.Context) (*ConfigStats, error)           { return &ConfigStats{}, nil }

type MockAuditStore struct{}

func (m *MockAuditStore) StoreAuditEntry(ctx context.Context, entry *AuditEntry) error        { return nil }
func (m *MockAuditStore) GetAuditEntry(ctx context.Context, id string) (*AuditEntry, error)   { return nil, ErrAuditNotFound }
func (m *MockAuditStore) ListAuditEntries(ctx context.Context, filter *AuditFilter) ([]*AuditEntry, error) { return nil, nil }
func (m *MockAuditStore) StoreAuditBatch(ctx context.Context, entries []*AuditEntry) error    { return nil }
func (m *MockAuditStore) GetAuditsByUser(ctx context.Context, userID string, timeRange *TimeRange) ([]*AuditEntry, error) { return nil, nil }
func (m *MockAuditStore) GetAuditsByResource(ctx context.Context, resourceType, resourceID string, timeRange *TimeRange) ([]*AuditEntry, error) { return nil, nil }
func (m *MockAuditStore) GetAuditsByAction(ctx context.Context, action string, timeRange *TimeRange) ([]*AuditEntry, error) { return nil, nil }
func (m *MockAuditStore) GetFailedActions(ctx context.Context, timeRange *TimeRange, limit int) ([]*AuditEntry, error) { return nil, nil }
func (m *MockAuditStore) GetSuspiciousActivity(ctx context.Context, tenantID string, timeRange *TimeRange) ([]*AuditEntry, error) { return nil, nil }
func (m *MockAuditStore) GetAuditStats(ctx context.Context) (*AuditStats, error)              { return &AuditStats{}, nil }
func (m *MockAuditStore) ArchiveAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) { return 0, nil }
func (m *MockAuditStore) PurgeAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) { return 0, nil }

// Test provider registration
func TestRegisterStorageProvider(t *testing.T) {
	// Clear registry for test
	originalProviders := make(map[string]StorageProvider)
	globalRegistry.mutex.RLock()
	for name, provider := range globalRegistry.providers {
		originalProviders[name] = provider
	}
	globalRegistry.mutex.RUnlock()
	
	// Clear registry
	globalRegistry.mutex.Lock()
	globalRegistry.providers = make(map[string]StorageProvider)
	globalRegistry.mutex.Unlock()
	
	defer func() {
		// Restore original providers
		globalRegistry.mutex.Lock()
		globalRegistry.providers = originalProviders
		globalRegistry.mutex.Unlock()
	}()
	
	provider := NewMockStorageProvider()
	RegisterStorageProvider(provider)
	
	// Verify registration
	names := GetRegisteredProviderNames()
	if len(names) != 1 || names[0] != "mock" {
		t.Errorf("Expected provider 'mock' to be registered, got: %v", names)
	}
	
	// Test getting the provider
	retrieved, err := GetStorageProvider("mock")
	if err != nil {
		t.Errorf("Failed to get registered provider: %v", err)
	}
	
	if retrieved.Name() != "mock" {
		t.Errorf("Expected provider name 'mock', got: %s", retrieved.Name())
	}
}

func TestRegisterStorageProviderWithValidation(t *testing.T) {
	// Clear registry for test
	originalProviders := make(map[string]StorageProvider)
	globalRegistry.mutex.RLock()
	for name, provider := range globalRegistry.providers {
		originalProviders[name] = provider
	}
	globalRegistry.mutex.RUnlock()
	
	// Clear registry
	globalRegistry.mutex.Lock()
	globalRegistry.providers = make(map[string]StorageProvider)
	globalRegistry.mutex.Unlock()
	
	defer func() {
		// Restore original providers
		globalRegistry.mutex.Lock()
		globalRegistry.providers = originalProviders
		globalRegistry.mutex.Unlock()
	}()
	
	provider := NewMockStorageProvider()
	testConfig := map[string]interface{}{
		"test": "config",
	}
	
	err := RegisterStorageProviderWithValidation(provider, testConfig)
	if err != nil {
		t.Errorf("Failed to register provider with validation: %v", err)
	}
	
	// Verify registration
	names := GetRegisteredProviderNames()
	if len(names) != 1 || names[0] != "mock" {
		t.Errorf("Expected provider 'mock' to be registered, got: %v", names)
	}
}

func TestValidateProvider(t *testing.T) {
	tests := []struct {
		name        string
		provider    *MockStorageProvider
		expectError bool
	}{
		{
			name:        "valid provider",
			provider:    NewMockStorageProvider(),
			expectError: false,
		},
		{
			name: "empty name",
			provider: &MockStorageProvider{
				name:        "",
				description: "test",
				version:     "1.0.0",
				available:   true,
			},
			expectError: true,
		},
		{
			name: "empty description",
			provider: &MockStorageProvider{
				name:        "test",
				description: "",
				version:     "1.0.0",
				available:   true,
			},
			expectError: true,
		},
		{
			name: "empty version",
			provider: &MockStorageProvider{
				name:        "test",
				description: "test",
				version:     "",
				available:   true,
			},
			expectError: true,
		},
		{
			name: "negative batch size",
			provider: &MockStorageProvider{
				name:        "test",
				description: "test",
				version:     "1.0.0",
				available:   true,
				capabilities: ProviderCapabilities{
					MaxBatchSize: -1,
				},
			},
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProvider(tt.provider)
			if tt.expectError && err == nil {
				t.Errorf("Expected validation error, got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no validation error, got: %v", err)
			}
		})
	}
}

func TestCreateAllStoresFromConfig(t *testing.T) {
	// Clear registry for test
	originalProviders := make(map[string]StorageProvider)
	globalRegistry.mutex.RLock()
	for name, provider := range globalRegistry.providers {
		originalProviders[name] = provider
	}
	globalRegistry.mutex.RUnlock()
	
	// Clear registry
	globalRegistry.mutex.Lock()
	globalRegistry.providers = make(map[string]StorageProvider)
	globalRegistry.mutex.Unlock()
	
	defer func() {
		// Restore original providers
		globalRegistry.mutex.Lock()
		globalRegistry.providers = originalProviders
		globalRegistry.mutex.Unlock()
	}()
	
	// Register mock provider
	provider := NewMockStorageProvider()
	RegisterStorageProvider(provider)
	
	config := map[string]interface{}{
		"test": "config",
	}
	
	manager, err := CreateAllStoresFromConfig("mock", config)
	if err != nil {
		t.Errorf("Failed to create storage manager: %v", err)
	}
	
	if manager.GetProviderName() != "mock" {
		t.Errorf("Expected provider name 'mock', got: %s", manager.GetProviderName())
	}
	
	if manager.GetClientTenantStore() == nil {
		t.Errorf("ClientTenantStore should not be nil")
	}
	
	if manager.GetConfigStore() == nil {
		t.Errorf("ConfigStore should not be nil")
	}
	
	if manager.GetAuditStore() == nil {
		t.Errorf("AuditStore should not be nil")
	}
}

func TestConfigKeyString(t *testing.T) {
	tests := []struct {
		name     string
		key      *ConfigKey
		expected string
	}{
		{
			name: "with scope",
			key: &ConfigKey{
				TenantID:  "tenant1",
				Namespace: "templates",
				Name:      "firewall",
				Scope:     "device1",
			},
			expected: "tenant1/templates/firewall@device1",
		},
		{
			name: "without scope",
			key: &ConfigKey{
				TenantID:  "tenant1",
				Namespace: "certificates",
				Name:      "root-ca",
			},
			expected: "tenant1/certificates/root-ca",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.key.String()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestListProvidersV2(t *testing.T) {
	// Clear registry for test
	originalProviders := make(map[string]StorageProvider)
	globalRegistry.mutex.RLock()
	for name, provider := range globalRegistry.providers {
		originalProviders[name] = provider
	}
	globalRegistry.mutex.RUnlock()
	
	// Clear registry
	globalRegistry.mutex.Lock()
	globalRegistry.providers = make(map[string]StorageProvider)
	globalRegistry.mutex.Unlock()
	
	defer func() {
		// Restore original providers
		globalRegistry.mutex.Lock()
		globalRegistry.providers = originalProviders
		globalRegistry.mutex.Unlock()
	}()
	
	// Register mock provider
	provider := NewMockStorageProvider()
	RegisterStorageProvider(provider)
	
	providers := ListProvidersV2()
	if len(providers) != 1 {
		t.Errorf("Expected 1 provider, got %d", len(providers))
	}
	
	if providers[0].Name != "mock" {
		t.Errorf("Expected provider name 'mock', got: %s", providers[0].Name)
	}
	
	if providers[0].Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got: %s", providers[0].Version)
	}
	
	if !providers[0].Capabilities.SupportsTransactions {
		t.Errorf("Expected provider to support transactions")
	}
}

func TestUnregisterStorageProvider(t *testing.T) {
	// Clear registry for test
	originalProviders := make(map[string]StorageProvider)
	globalRegistry.mutex.RLock()
	for name, provider := range globalRegistry.providers {
		originalProviders[name] = provider
	}
	globalRegistry.mutex.RUnlock()
	
	// Clear registry
	globalRegistry.mutex.Lock()
	globalRegistry.providers = make(map[string]StorageProvider)
	globalRegistry.mutex.Unlock()
	
	defer func() {
		// Restore original providers
		globalRegistry.mutex.Lock()
		globalRegistry.providers = originalProviders
		globalRegistry.mutex.Unlock()
	}()
	
	// Register mock provider
	provider := NewMockStorageProvider()
	RegisterStorageProvider(provider)
	
	// Verify it's registered
	names := GetRegisteredProviderNames()
	if len(names) != 1 {
		t.Errorf("Expected 1 provider, got %d", len(names))
	}
	
	// Unregister it
	success := UnregisterStorageProvider("mock")
	if !success {
		t.Errorf("Failed to unregister provider")
	}
	
	// Verify it's gone
	names = GetRegisteredProviderNames()
	if len(names) != 0 {
		t.Errorf("Expected 0 providers after unregistration, got %d", len(names))
	}
	
	// Try to unregister non-existent provider
	success = UnregisterStorageProvider("nonexistent")
	if success {
		t.Errorf("Should not succeed unregistering non-existent provider")
	}
}