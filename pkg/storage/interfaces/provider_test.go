// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
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
			MaxBatchSize:           100,
			MaxConfigSize:          1024 * 1024, // 1MB
			MaxAuditRetentionDays:  365,
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

func (m *MockStorageProvider) CreateClientTenantStore(_ map[string]interface{}) (business.ClientTenantStore, error) {
	return &MockClientTenantStore{}, nil
}

func (m *MockStorageProvider) CreateConfigStore(_ map[string]interface{}) (cfgconfig.ConfigStore, error) {
	return &MockConfigStore{}, nil
}

func (m *MockStorageProvider) CreateAuditStore(_ map[string]interface{}) (business.AuditStore, error) {
	return &MockAuditStore{}, nil
}

func (m *MockStorageProvider) CreateRBACStore(_ map[string]interface{}) (business.RBACStore, error) {
	return &MockRBACStore{}, nil
}

func (m *MockStorageProvider) CreateTenantStore(_ map[string]interface{}) (business.TenantStore, error) {
	return &MockTenantStore{}, nil
}

func (m *MockStorageProvider) CreateRegistrationTokenStore(_ map[string]interface{}) (business.RegistrationTokenStore, error) {
	return &MockRegistrationTokenStore{}, nil
}

func (m *MockStorageProvider) CreateSessionStore(_ map[string]interface{}) (business.SessionStore, error) {
	return nil, business.ErrNotSupported
}

func (m *MockStorageProvider) CreateStewardStore(_ map[string]interface{}) (business.StewardStore, error) {
	return nil, business.ErrNotSupported
}

func (m *MockStorageProvider) CreateCommandStore(_ map[string]interface{}) (business.CommandStore, error) {
	return nil, business.ErrNotSupported
}

// Mock implementations of store interfaces
type MockClientTenantStore struct{}

func (m *MockClientTenantStore) StoreClientTenant(_ *business.ClientTenant) error { return nil }
func (m *MockClientTenantStore) GetClientTenant(_ string) (*business.ClientTenant, error) {
	return nil, business.ErrTenantNotFound
}
func (m *MockClientTenantStore) GetClientTenantByIdentifier(_ string) (*business.ClientTenant, error) {
	return nil, business.ErrTenantNotFound
}
func (m *MockClientTenantStore) ListClientTenants(_ business.ClientTenantStatus) ([]*business.ClientTenant, error) {
	return nil, nil
}
func (m *MockClientTenantStore) UpdateClientTenantStatus(_ string, _ business.ClientTenantStatus) error {
	return nil
}
func (m *MockClientTenantStore) DeleteClientTenant(_ string) error { return nil }
func (m *MockClientTenantStore) StoreAdminConsentRequest(_ *business.AdminConsentRequest) error {
	return nil
}
func (m *MockClientTenantStore) GetAdminConsentRequest(_ string) (*business.AdminConsentRequest, error) {
	return nil, business.ErrTenantNotFound
}
func (m *MockClientTenantStore) DeleteAdminConsentRequest(_ string) error { return nil }
func (m *MockClientTenantStore) Close() error                             { return nil }

type MockConfigStore struct{}

func (m *MockConfigStore) StoreConfig(_ context.Context, _ *cfgconfig.ConfigEntry) error {
	return nil
}
func (m *MockConfigStore) GetConfig(_ context.Context, _ *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	return nil, cfgconfig.ErrConfigNotFound
}
func (m *MockConfigStore) DeleteConfig(_ context.Context, _ *cfgconfig.ConfigKey) error { return nil }
func (m *MockConfigStore) ListConfigs(_ context.Context, _ *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	return nil, nil
}
func (m *MockConfigStore) GetConfigHistory(_ context.Context, _ *cfgconfig.ConfigKey, _ int) ([]*cfgconfig.ConfigEntry, error) {
	return nil, nil
}
func (m *MockConfigStore) GetConfigVersion(_ context.Context, _ *cfgconfig.ConfigKey, _ int64) (*cfgconfig.ConfigEntry, error) {
	return nil, cfgconfig.ErrConfigNotFound
}
func (m *MockConfigStore) StoreConfigBatch(_ context.Context, _ []*cfgconfig.ConfigEntry) error {
	return nil
}
func (m *MockConfigStore) DeleteConfigBatch(_ context.Context, _ []*cfgconfig.ConfigKey) error {
	return nil
}
func (m *MockConfigStore) ResolveConfigWithInheritance(_ context.Context, _ *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	return nil, cfgconfig.ErrConfigNotFound
}
func (m *MockConfigStore) ValidateConfig(_ context.Context, _ *cfgconfig.ConfigEntry) error {
	return nil
}
func (m *MockConfigStore) GetConfigStats(_ context.Context) (*cfgconfig.ConfigStats, error) {
	return &cfgconfig.ConfigStats{}, nil
}

type MockAuditStore struct{}

func (m *MockAuditStore) StoreAuditEntry(_ context.Context, _ *business.AuditEntry) error {
	return nil
}
func (m *MockAuditStore) GetAuditEntry(_ context.Context, _ string) (*business.AuditEntry, error) {
	return nil, business.ErrAuditNotFound
}
func (m *MockAuditStore) ListAuditEntries(_ context.Context, _ *business.AuditFilter) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (m *MockAuditStore) StoreAuditBatch(_ context.Context, _ []*business.AuditEntry) error {
	return nil
}
func (m *MockAuditStore) GetAuditsByUser(_ context.Context, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (m *MockAuditStore) GetAuditsByResource(_ context.Context, _, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (m *MockAuditStore) GetAuditsByAction(_ context.Context, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (m *MockAuditStore) GetFailedActions(_ context.Context, _ *business.TimeRange, _ int) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (m *MockAuditStore) GetSuspiciousActivity(_ context.Context, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (m *MockAuditStore) GetAuditStats(_ context.Context) (*business.AuditStats, error) {
	return &business.AuditStats{}, nil
}
func (m *MockAuditStore) ArchiveAuditEntries(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (m *MockAuditStore) PurgeAuditEntries(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (m *MockAuditStore) Close() error { return nil }

type MockRBACStore struct{}

func (m *MockRBACStore) StorePermission(_ context.Context, _ *common.Permission) error {
	return nil
}
func (m *MockRBACStore) GetPermission(_ context.Context, _ string) (*common.Permission, error) {
	return nil, fmt.Errorf("permission not found")
}
func (m *MockRBACStore) ListPermissions(_ context.Context, _ string) ([]*common.Permission, error) {
	return nil, nil
}
func (m *MockRBACStore) UpdatePermission(_ context.Context, _ *common.Permission) error {
	return nil
}
func (m *MockRBACStore) DeletePermission(_ context.Context, _ string) error { return nil }
func (m *MockRBACStore) StoreRole(_ context.Context, _ *common.Role) error  { return nil }
func (m *MockRBACStore) GetRole(_ context.Context, _ string) (*common.Role, error) {
	return nil, fmt.Errorf("role not found")
}
func (m *MockRBACStore) ListRoles(_ context.Context, _ string) ([]*common.Role, error) {
	return nil, nil
}
func (m *MockRBACStore) UpdateRole(_ context.Context, _ *common.Role) error      { return nil }
func (m *MockRBACStore) DeleteRole(_ context.Context, _ string) error            { return nil }
func (m *MockRBACStore) StoreSubject(_ context.Context, _ *common.Subject) error { return nil }
func (m *MockRBACStore) GetSubject(_ context.Context, _ string) (*common.Subject, error) {
	return nil, fmt.Errorf("subject not found")
}
func (m *MockRBACStore) ListSubjects(_ context.Context, _ string, _ common.SubjectType) ([]*common.Subject, error) {
	return nil, nil
}
func (m *MockRBACStore) UpdateSubject(_ context.Context, _ *common.Subject) error { return nil }
func (m *MockRBACStore) DeleteSubject(_ context.Context, _ string) error          { return nil }
func (m *MockRBACStore) StoreRoleAssignment(_ context.Context, _ *common.RoleAssignment) error {
	return nil
}
func (m *MockRBACStore) GetRoleAssignment(_ context.Context, _ string) (*common.RoleAssignment, error) {
	return nil, fmt.Errorf("assignment not found")
}
func (m *MockRBACStore) ListRoleAssignments(_ context.Context, _, _, _ string) ([]*common.RoleAssignment, error) {
	return nil, nil
}
func (m *MockRBACStore) DeleteRoleAssignment(_ context.Context, _, _, _ string) error {
	return nil
}
func (m *MockRBACStore) StoreBulkPermissions(_ context.Context, _ []*common.Permission) error {
	return nil
}
func (m *MockRBACStore) StoreBulkRoles(_ context.Context, _ []*common.Role) error { return nil }
func (m *MockRBACStore) StoreBulkSubjects(_ context.Context, _ []*common.Subject) error {
	return nil
}
func (m *MockRBACStore) GetSubjectRoles(_ context.Context, _, _ string) ([]*common.Role, error) {
	return nil, nil
}
func (m *MockRBACStore) GetRolePermissions(_ context.Context, _ string) ([]*common.Permission, error) {
	return nil, nil
}
func (m *MockRBACStore) GetSubjectAssignments(_ context.Context, _, _ string) ([]*common.RoleAssignment, error) {
	return nil, nil
}
func (m *MockRBACStore) Initialize(_ context.Context) error { return nil }
func (m *MockRBACStore) Close() error                       { return nil }

// MockTenantStore implements business.TenantStore for testing
type MockTenantStore struct{}

func (m *MockTenantStore) CreateTenant(_ context.Context, _ *business.TenantData) error { return nil }
func (m *MockTenantStore) GetTenant(_ context.Context, tenantID string) (*business.TenantData, error) {
	return &business.TenantData{ID: tenantID, Name: "Test Tenant"}, nil
}
func (m *MockTenantStore) UpdateTenant(_ context.Context, _ *business.TenantData) error { return nil }
func (m *MockTenantStore) DeleteTenant(_ context.Context, _ string) error               { return nil }
func (m *MockTenantStore) ListTenants(_ context.Context, _ *business.TenantFilter) ([]*business.TenantData, error) {
	return nil, nil
}
func (m *MockTenantStore) GetTenantHierarchy(_ context.Context, tenantID string) (*business.TenantHierarchy, error) {
	return &business.TenantHierarchy{TenantID: tenantID}, nil
}
func (m *MockTenantStore) GetChildTenants(_ context.Context, _ string) ([]*business.TenantData, error) {
	return nil, nil
}
func (m *MockTenantStore) GetTenantPath(_ context.Context, tenantID string) ([]string, error) {
	return []string{tenantID}, nil
}
func (m *MockTenantStore) IsTenantAncestor(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}
func (m *MockTenantStore) Initialize(_ context.Context) error { return nil }
func (m *MockTenantStore) Close() error                       { return nil }

// MockRegistrationTokenStore implements business.RegistrationTokenStore for testing
type MockRegistrationTokenStore struct{}

func (m *MockRegistrationTokenStore) SaveToken(_ context.Context, _ *business.RegistrationTokenData) error {
	return nil
}
func (m *MockRegistrationTokenStore) GetToken(_ context.Context, _ string) (*business.RegistrationTokenData, error) {
	return nil, fmt.Errorf("token not found")
}
func (m *MockRegistrationTokenStore) UpdateToken(_ context.Context, _ *business.RegistrationTokenData) error {
	return nil
}
func (m *MockRegistrationTokenStore) DeleteToken(_ context.Context, _ string) error {
	return nil
}
func (m *MockRegistrationTokenStore) ListTokens(_ context.Context, _ *business.RegistrationTokenFilter) ([]*business.RegistrationTokenData, error) {
	return nil, nil
}
func (m *MockRegistrationTokenStore) Initialize(_ context.Context) error { return nil }
func (m *MockRegistrationTokenStore) Close() error                       { return nil }

// MockStewardStore implements business.StewardStore for testing
type MockStewardStore struct{}

func (m *MockStewardStore) RegisterSteward(_ context.Context, _ *business.StewardRecord) error {
	return nil
}
func (m *MockStewardStore) UpdateHeartbeat(_ context.Context, _ string) error { return nil }
func (m *MockStewardStore) GetSteward(_ context.Context, _ string) (*business.StewardRecord, error) {
	return nil, business.ErrStewardNotFound
}
func (m *MockStewardStore) ListStewards(_ context.Context) ([]*business.StewardRecord, error) {
	return nil, nil
}
func (m *MockStewardStore) ListStewardsByStatus(_ context.Context, _ business.StewardStatus) ([]*business.StewardRecord, error) {
	return nil, nil
}
func (m *MockStewardStore) UpdateStewardStatus(_ context.Context, _ string, _ business.StewardStatus) error {
	return nil
}
func (m *MockStewardStore) DeregisterSteward(_ context.Context, _ string) error { return nil }
func (m *MockStewardStore) GetStewardsSeen(_ context.Context, _ time.Time) ([]*business.StewardRecord, error) {
	return nil, nil
}
func (m *MockStewardStore) HealthCheck(_ context.Context) error { return nil }
func (m *MockStewardStore) Initialize(_ context.Context) error  { return nil }
func (m *MockStewardStore) Close() error                        { return nil }

// MockSessionStore implements business.SessionStore for testing
type MockSessionStore struct{}

func (m *MockSessionStore) CreateSession(_ context.Context, _ *business.Session) error { return nil }
func (m *MockSessionStore) GetSession(_ context.Context, _ string) (*business.Session, error) {
	return nil, fmt.Errorf("not found")
}
func (m *MockSessionStore) UpdateSession(_ context.Context, _ string, _ *business.Session) error {
	return nil
}
func (m *MockSessionStore) DeleteSession(_ context.Context, _ string) error { return nil }
func (m *MockSessionStore) ListSessions(_ context.Context, _ *business.SessionFilter) ([]*business.Session, error) {
	return nil, nil
}
func (m *MockSessionStore) SetSessionTTL(_ context.Context, _ string, _ time.Duration) error {
	return nil
}
func (m *MockSessionStore) CleanupExpiredSessions(_ context.Context) (int, error) { return 0, nil }
func (m *MockSessionStore) GetSessionsByUser(_ context.Context, _ string) ([]*business.Session, error) {
	return nil, nil
}
func (m *MockSessionStore) GetSessionsByTenant(_ context.Context, _ string) ([]*business.Session, error) {
	return nil, nil
}
func (m *MockSessionStore) GetSessionsByType(_ context.Context, _ business.SessionType) ([]*business.Session, error) {
	return nil, nil
}
func (m *MockSessionStore) GetActiveSessionsCount(_ context.Context) (int64, error) { return 0, nil }
func (m *MockSessionStore) HealthCheck(_ context.Context) error                     { return nil }
func (m *MockSessionStore) GetStats(_ context.Context) (*business.RuntimeStoreStats, error) {
	return &business.RuntimeStoreStats{}, nil
}
func (m *MockSessionStore) Initialize(_ context.Context) error { return nil }
func (m *MockSessionStore) Close() error                       { return nil }

// MockCommandStore implements business.CommandStore for testing
type MockCommandStore struct{}

func (m *MockCommandStore) CreateCommandRecord(_ context.Context, _ *business.CommandRecord) error {
	return nil
}
func (m *MockCommandStore) UpdateCommandStatus(_ context.Context, _ string, _ business.CommandStatus, _ map[string]interface{}, _ string) error {
	return nil
}
func (m *MockCommandStore) GetCommandRecord(_ context.Context, _ string) (*business.CommandRecord, error) {
	return nil, fmt.Errorf("not found")
}
func (m *MockCommandStore) ListCommandRecords(_ context.Context, _ *business.CommandFilter) ([]*business.CommandRecord, error) {
	return nil, nil
}
func (m *MockCommandStore) ListCommandsByDevice(_ context.Context, _ string) ([]*business.CommandRecord, error) {
	return nil, nil
}
func (m *MockCommandStore) ListCommandsByStatus(_ context.Context, _ business.CommandStatus) ([]*business.CommandRecord, error) {
	return nil, nil
}
func (m *MockCommandStore) GetCommandAuditTrail(_ context.Context, _ string) ([]*business.CommandTransition, error) {
	return nil, nil
}
func (m *MockCommandStore) PurgeExpiredRecords(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (m *MockCommandStore) HealthCheck(_ context.Context) error { return nil }
func (m *MockCommandStore) Close() error                        { return nil }

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
		key      *cfgconfig.ConfigKey
		expected string
	}{
		{
			name: "with scope",
			key: &cfgconfig.ConfigKey{
				TenantID:  "tenant1",
				Namespace: "templates",
				Name:      "firewall",
				Scope:     "device1",
			},
			expected: "tenant1/templates/firewall@device1",
		},
		{
			name: "without scope",
			key: &cfgconfig.ConfigKey{
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

func TestNewStorageManagerFromStores(t *testing.T) {
	t.Run("composite provider name and nil provider", func(t *testing.T) {
		sm := NewStorageManagerFromStores(
			&MockConfigStore{}, &MockAuditStore{}, &MockRBACStore{},
			&MockTenantStore{}, &MockClientTenantStore{}, &MockRegistrationTokenStore{},
			nil, nil, nil,
		)

		if sm.GetProviderName() != "composite" {
			t.Errorf("expected providerName %q, got %q", "composite", sm.GetProviderName())
		}
		if sm.GetProvider() != nil {
			t.Errorf("expected nil provider for composite manager, got non-nil")
		}
	})

	t.Run("GetCapabilities returns zero value without panic", func(t *testing.T) {
		sm := NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil)
		caps := sm.GetCapabilities()
		// Zero value - no field should be set
		if caps.SupportsTransactions || caps.SupportsVersioning || caps.MaxBatchSize != 0 {
			t.Errorf("expected zero-value ProviderCapabilities, got %+v", caps)
		}
	})

	t.Run("GetVersion returns composite without panic", func(t *testing.T) {
		sm := NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil)
		if sm.GetVersion() != "composite" {
			t.Errorf("expected version %q, got %q", "composite", sm.GetVersion())
		}
	})

	t.Run("GetProvider returns nil without panic", func(t *testing.T) {
		sm := NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil)
		if sm.GetProvider() != nil {
			t.Errorf("expected nil from GetProvider on composite manager")
		}
	})

	t.Run("all store parameters accepted and retrievable", func(t *testing.T) {
		configStore := &MockConfigStore{}
		auditStore := &MockAuditStore{}
		rbacStore := &MockRBACStore{}
		tenantStore := &MockTenantStore{}
		clientTenantStore := &MockClientTenantStore{}
		registrationTokenStore := &MockRegistrationTokenStore{}

		sm := NewStorageManagerFromStores(
			configStore, auditStore, rbacStore,
			tenantStore, clientTenantStore, registrationTokenStore,
			nil, nil, nil,
		)

		if sm.GetConfigStore() != configStore {
			t.Errorf("ConfigStore mismatch")
		}
		if sm.GetAuditStore() != auditStore {
			t.Errorf("AuditStore mismatch")
		}
		if sm.GetRBACStore() != rbacStore {
			t.Errorf("RBACStore mismatch")
		}
		if sm.GetTenantStore() != tenantStore {
			t.Errorf("TenantStore mismatch")
		}
		if sm.GetClientTenantStore() != clientTenantStore {
			t.Errorf("ClientTenantStore mismatch")
		}
		if sm.GetRegistrationTokenStore() != registrationTokenStore {
			t.Errorf("RegistrationTokenStore mismatch")
		}
		if sm.GetSessionStore() != nil {
			t.Errorf("SessionStore should be nil")
		}
		if sm.GetStewardStore() != nil {
			t.Errorf("StewardStore should be nil")
		}
		if sm.GetCommandStore() != nil {
			t.Errorf("CommandStore should be nil")
		}
	})

	t.Run("nil values allowed for all stores", func(t *testing.T) {
		sm := NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil)
		// Should not panic
		if sm.GetConfigStore() != nil {
			t.Errorf("expected nil ConfigStore")
		}
		if sm.GetAuditStore() != nil {
			t.Errorf("expected nil AuditStore")
		}
	})
}

func TestCreateOSSStorageManager(t *testing.T) {
	// Register flatfile and sqlite providers for this test
	// We use the mock provider approach since the real providers require CGo (sqlite) / filesystem
	// and are exercised by their own provider-level integration tests.

	// Save registry state
	originalProviders := make(map[string]StorageProvider)
	globalRegistry.mutex.RLock()
	for name, provider := range globalRegistry.providers {
		originalProviders[name] = provider
	}
	globalRegistry.mutex.RUnlock()

	globalRegistry.mutex.Lock()
	globalRegistry.providers = make(map[string]StorageProvider)
	globalRegistry.mutex.Unlock()

	defer func() {
		globalRegistry.mutex.Lock()
		globalRegistry.providers = originalProviders
		globalRegistry.mutex.Unlock()
	}()

	t.Run("error when flatfile provider not registered", func(t *testing.T) {
		_, err := CreateOSSStorageManager(t.TempDir(), t.TempDir()+"/test.db")
		if err == nil {
			t.Fatal("expected error when flatfile provider not registered")
		}
	})

	t.Run("error when sqlite provider not registered", func(t *testing.T) {
		// Register only flatfile
		ffMock := &MockOSSProvider{providerName: "flatfile"}
		globalRegistry.mutex.Lock()
		globalRegistry.providers["flatfile"] = ffMock
		globalRegistry.mutex.Unlock()

		_, err := CreateOSSStorageManager(t.TempDir(), t.TempDir()+"/test.db")
		if err == nil {
			t.Fatal("expected error when sqlite provider not registered")
		}

		globalRegistry.mutex.Lock()
		delete(globalRegistry.providers, "flatfile")
		globalRegistry.mutex.Unlock()
	})

	t.Run("creates composite manager with correct providerName", func(t *testing.T) {
		ffMock := &MockOSSProvider{providerName: "flatfile"}
		sqMock := &MockOSSProvider{providerName: "sqlite"}

		globalRegistry.mutex.Lock()
		globalRegistry.providers["flatfile"] = ffMock
		globalRegistry.providers["sqlite"] = sqMock
		globalRegistry.mutex.Unlock()

		sm, err := CreateOSSStorageManager(t.TempDir(), t.TempDir()+"/test.db")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if sm.GetProviderName() != "composite" {
			t.Errorf("expected providerName %q, got %q", "composite", sm.GetProviderName())
		}
		if sm.GetProvider() != nil {
			t.Errorf("expected nil provider")
		}

		// Config/Audit/Steward come from flatfile
		if sm.GetConfigStore() == nil {
			t.Errorf("ConfigStore should not be nil")
		}
		if sm.GetAuditStore() == nil {
			t.Errorf("AuditStore should not be nil")
		}
		if sm.GetStewardStore() == nil {
			t.Errorf("StewardStore should not be nil")
		}

		// Business stores come from sqlite
		if sm.GetRBACStore() == nil {
			t.Errorf("RBACStore should not be nil")
		}
		if sm.GetTenantStore() == nil {
			t.Errorf("TenantStore should not be nil")
		}
		if sm.GetClientTenantStore() == nil {
			t.Errorf("ClientTenantStore should not be nil")
		}
		if sm.GetRegistrationTokenStore() == nil {
			t.Errorf("RegistrationTokenStore should not be nil")
		}

		globalRegistry.mutex.Lock()
		delete(globalRegistry.providers, "flatfile")
		delete(globalRegistry.providers, "sqlite")
		globalRegistry.mutex.Unlock()
	})
}

// MockOSSProvider is a minimal StorageProvider for testing OSS factory wiring.
// Unlike MockStorageProvider, it always returns non-nil stores for all supported methods.
type MockOSSProvider struct {
	providerName string
}

func (m *MockOSSProvider) Name() string        { return m.providerName }
func (m *MockOSSProvider) Description() string { return "mock oss provider for testing" }
func (m *MockOSSProvider) GetVersion() string  { return "1.0.0" }
func (m *MockOSSProvider) Available() (bool, error) {
	return true, nil
}
func (m *MockOSSProvider) GetCapabilities() ProviderCapabilities { return ProviderCapabilities{} }

func (m *MockOSSProvider) CreateConfigStore(_ map[string]interface{}) (cfgconfig.ConfigStore, error) {
	return &MockConfigStore{}, nil
}
func (m *MockOSSProvider) CreateAuditStore(_ map[string]interface{}) (business.AuditStore, error) {
	return &MockAuditStore{}, nil
}
func (m *MockOSSProvider) CreateStewardStore(_ map[string]interface{}) (business.StewardStore, error) {
	return &MockStewardStore{}, nil
}
func (m *MockOSSProvider) CreateRBACStore(_ map[string]interface{}) (business.RBACStore, error) {
	return &MockRBACStore{}, nil
}
func (m *MockOSSProvider) CreateTenantStore(_ map[string]interface{}) (business.TenantStore, error) {
	return &MockTenantStore{}, nil
}
func (m *MockOSSProvider) CreateClientTenantStore(_ map[string]interface{}) (business.ClientTenantStore, error) {
	return &MockClientTenantStore{}, nil
}
func (m *MockOSSProvider) CreateRegistrationTokenStore(_ map[string]interface{}) (business.RegistrationTokenStore, error) {
	return &MockRegistrationTokenStore{}, nil
}
func (m *MockOSSProvider) CreateSessionStore(_ map[string]interface{}) (business.SessionStore, error) {
	return &MockSessionStore{}, nil
}
func (m *MockOSSProvider) CreateCommandStore(_ map[string]interface{}) (business.CommandStore, error) {
	return &MockCommandStore{}, nil
}

// MockOSSProviderWithError is an interface stub that returns an error from a designated Create* method.
// It is used to test that CreateOSSStorageManager propagates store-creation errors correctly.
// Real providers cannot be used here because pkg/storage/providers/* imports this package
// (pkg/storage/interfaces), which would create an import cycle.
type MockOSSProviderWithError struct {
	providerName string
	failMethod   string // name of the Create* method that should fail
}

func (m *MockOSSProviderWithError) Name() string             { return m.providerName }
func (m *MockOSSProviderWithError) Description() string      { return "error mock" }
func (m *MockOSSProviderWithError) GetVersion() string       { return "1.0.0" }
func (m *MockOSSProviderWithError) Available() (bool, error) { return true, nil }
func (m *MockOSSProviderWithError) GetCapabilities() ProviderCapabilities {
	return ProviderCapabilities{}
}

func (m *MockOSSProviderWithError) mayFail(method string) error {
	if m.failMethod == method {
		return fmt.Errorf("injected %s failure", method)
	}
	return nil
}

func (m *MockOSSProviderWithError) CreateConfigStore(_ map[string]interface{}) (cfgconfig.ConfigStore, error) {
	if err := m.mayFail("CreateConfigStore"); err != nil {
		return nil, err
	}
	return &MockConfigStore{}, nil
}
func (m *MockOSSProviderWithError) CreateAuditStore(_ map[string]interface{}) (business.AuditStore, error) {
	if err := m.mayFail("CreateAuditStore"); err != nil {
		return nil, err
	}
	return &MockAuditStore{}, nil
}
func (m *MockOSSProviderWithError) CreateStewardStore(_ map[string]interface{}) (business.StewardStore, error) {
	if err := m.mayFail("CreateStewardStore"); err != nil {
		return nil, err
	}
	return &MockStewardStore{}, nil
}
func (m *MockOSSProviderWithError) CreateRBACStore(_ map[string]interface{}) (business.RBACStore, error) {
	if err := m.mayFail("CreateRBACStore"); err != nil {
		return nil, err
	}
	return &MockRBACStore{}, nil
}
func (m *MockOSSProviderWithError) CreateTenantStore(_ map[string]interface{}) (business.TenantStore, error) {
	if err := m.mayFail("CreateTenantStore"); err != nil {
		return nil, err
	}
	return &MockTenantStore{}, nil
}
func (m *MockOSSProviderWithError) CreateClientTenantStore(_ map[string]interface{}) (business.ClientTenantStore, error) {
	if err := m.mayFail("CreateClientTenantStore"); err != nil {
		return nil, err
	}
	return &MockClientTenantStore{}, nil
}
func (m *MockOSSProviderWithError) CreateRegistrationTokenStore(_ map[string]interface{}) (business.RegistrationTokenStore, error) {
	if err := m.mayFail("CreateRegistrationTokenStore"); err != nil {
		return nil, err
	}
	return &MockRegistrationTokenStore{}, nil
}
func (m *MockOSSProviderWithError) CreateSessionStore(_ map[string]interface{}) (business.SessionStore, error) {
	if err := m.mayFail("CreateSessionStore"); err != nil {
		return nil, err
	}
	return &MockSessionStore{}, nil
}
func (m *MockOSSProviderWithError) CreateCommandStore(_ map[string]interface{}) (business.CommandStore, error) {
	if err := m.mayFail("CreateCommandStore"); err != nil {
		return nil, err
	}
	return &MockCommandStore{}, nil
}

func TestCreateOSSStorageManager_StoreCreationErrors(t *testing.T) {
	// Save and clear registry
	originalProviders := make(map[string]StorageProvider)
	globalRegistry.mutex.RLock()
	for name, provider := range globalRegistry.providers {
		originalProviders[name] = provider
	}
	globalRegistry.mutex.RUnlock()

	globalRegistry.mutex.Lock()
	globalRegistry.providers = make(map[string]StorageProvider)
	globalRegistry.mutex.Unlock()

	defer func() {
		globalRegistry.mutex.Lock()
		globalRegistry.providers = originalProviders
		globalRegistry.mutex.Unlock()
	}()

	// Each subtest injects an error from one of the flatfile Create* methods
	// to verify CreateOSSStorageManager propagates all store-creation errors.
	flatfileFailures := []string{
		"CreateConfigStore",
		"CreateAuditStore",
		"CreateStewardStore",
	}
	sqliteFailures := []string{
		"CreateRBACStore",
		"CreateTenantStore",
		"CreateClientTenantStore",
		"CreateRegistrationTokenStore",
		"CreateSessionStore",
		"CreateCommandStore",
	}

	for _, failMethod := range flatfileFailures {
		failMethod := failMethod
		t.Run("flatfile_"+failMethod+"_returns_error", func(t *testing.T) {
			globalRegistry.mutex.Lock()
			globalRegistry.providers = map[string]StorageProvider{
				"flatfile": &MockOSSProviderWithError{providerName: "flatfile", failMethod: failMethod},
				"sqlite":   &MockOSSProvider{providerName: "sqlite"},
			}
			globalRegistry.mutex.Unlock()

			_, err := CreateOSSStorageManager(t.TempDir(), t.TempDir()+"/test.db")
			if err == nil {
				t.Errorf("expected error when flatfile %s fails, got nil", failMethod)
			}
		})
	}

	for _, failMethod := range sqliteFailures {
		failMethod := failMethod
		t.Run("sqlite_"+failMethod+"_returns_error", func(t *testing.T) {
			globalRegistry.mutex.Lock()
			globalRegistry.providers = map[string]StorageProvider{
				"flatfile": &MockOSSProvider{providerName: "flatfile"},
				"sqlite":   &MockOSSProviderWithError{providerName: "sqlite", failMethod: failMethod},
			}
			globalRegistry.mutex.Unlock()

			_, err := CreateOSSStorageManager(t.TempDir(), t.TempDir()+"/test.db")
			if err == nil {
				t.Errorf("expected error when sqlite %s fails, got nil", failMethod)
			}
		})
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
