// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
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

func (m *MockStorageProvider) CreateClientTenantStore(config map[string]interface{}) (ClientTenantStore, error) {
	return &MockClientTenantStore{}, nil
}

func (m *MockStorageProvider) CreateConfigStore(config map[string]interface{}) (ConfigStore, error) {
	return &MockConfigStore{}, nil
}

func (m *MockStorageProvider) CreateAuditStore(config map[string]interface{}) (AuditStore, error) {
	return &MockAuditStore{}, nil
}

func (m *MockStorageProvider) CreateRBACStore(config map[string]interface{}) (RBACStore, error) {
	return &MockRBACStore{}, nil
}

func (m *MockStorageProvider) CreateRuntimeStore(config map[string]interface{}) (RuntimeStore, error) {
	return &MockRuntimeStore{}, nil
}

func (m *MockStorageProvider) CreateTenantStore(config map[string]interface{}) (TenantStore, error) {
	return &MockTenantStore{}, nil
}

func (m *MockStorageProvider) CreateRegistrationTokenStore(config map[string]interface{}) (RegistrationTokenStore, error) {
	return &MockRegistrationTokenStore{}, nil
}

func (m *MockStorageProvider) CreateSessionStore(config map[string]interface{}) (SessionStore, error) {
	return nil, ErrNotSupported
}

func (m *MockStorageProvider) CreateStewardStore(config map[string]interface{}) (StewardStore, error) {
	return nil, ErrNotSupported
}

func (m *MockStorageProvider) CreateCommandStore(config map[string]interface{}) (CommandStore, error) {
	return nil, ErrNotSupported
}

// Mock implementations of store interfaces
type MockClientTenantStore struct{}

func (m *MockClientTenantStore) StoreClientTenant(client *ClientTenant) error { return nil }
func (m *MockClientTenantStore) GetClientTenant(tenantID string) (*ClientTenant, error) {
	return nil, ErrTenantNotFound
}
func (m *MockClientTenantStore) GetClientTenantByIdentifier(clientIdentifier string) (*ClientTenant, error) {
	return nil, ErrTenantNotFound
}
func (m *MockClientTenantStore) ListClientTenants(status ClientTenantStatus) ([]*ClientTenant, error) {
	return nil, nil
}
func (m *MockClientTenantStore) UpdateClientTenantStatus(tenantID string, status ClientTenantStatus) error {
	return nil
}
func (m *MockClientTenantStore) DeleteClientTenant(tenantID string) error { return nil }
func (m *MockClientTenantStore) StoreAdminConsentRequest(request *AdminConsentRequest) error {
	return nil
}
func (m *MockClientTenantStore) GetAdminConsentRequest(state string) (*AdminConsentRequest, error) {
	return nil, ErrTenantNotFound
}
func (m *MockClientTenantStore) DeleteAdminConsentRequest(state string) error { return nil }
func (m *MockClientTenantStore) Close() error                                 { return nil }

type MockConfigStore struct{}

func (m *MockConfigStore) StoreConfig(ctx context.Context, config *ConfigEntry) error { return nil }
func (m *MockConfigStore) GetConfig(ctx context.Context, key *ConfigKey) (*ConfigEntry, error) {
	return nil, ErrConfigNotFound
}
func (m *MockConfigStore) DeleteConfig(ctx context.Context, key *ConfigKey) error { return nil }
func (m *MockConfigStore) ListConfigs(ctx context.Context, filter *ConfigFilter) ([]*ConfigEntry, error) {
	return nil, nil
}
func (m *MockConfigStore) GetConfigHistory(ctx context.Context, key *ConfigKey, limit int) ([]*ConfigEntry, error) {
	return nil, nil
}
func (m *MockConfigStore) GetConfigVersion(ctx context.Context, key *ConfigKey, version int64) (*ConfigEntry, error) {
	return nil, ErrConfigNotFound
}
func (m *MockConfigStore) StoreConfigBatch(ctx context.Context, configs []*ConfigEntry) error {
	return nil
}
func (m *MockConfigStore) DeleteConfigBatch(ctx context.Context, keys []*ConfigKey) error { return nil }
func (m *MockConfigStore) ResolveConfigWithInheritance(ctx context.Context, key *ConfigKey) (*ConfigEntry, error) {
	return nil, ErrConfigNotFound
}
func (m *MockConfigStore) ValidateConfig(ctx context.Context, config *ConfigEntry) error { return nil }
func (m *MockConfigStore) GetConfigStats(ctx context.Context) (*ConfigStats, error) {
	return &ConfigStats{}, nil
}

type MockAuditStore struct{}

func (m *MockAuditStore) StoreAuditEntry(ctx context.Context, entry *AuditEntry) error { return nil }
func (m *MockAuditStore) GetAuditEntry(ctx context.Context, id string) (*AuditEntry, error) {
	return nil, ErrAuditNotFound
}
func (m *MockAuditStore) ListAuditEntries(ctx context.Context, filter *AuditFilter) ([]*AuditEntry, error) {
	return nil, nil
}
func (m *MockAuditStore) StoreAuditBatch(ctx context.Context, entries []*AuditEntry) error {
	return nil
}
func (m *MockAuditStore) GetAuditsByUser(ctx context.Context, userID string, timeRange *TimeRange) ([]*AuditEntry, error) {
	return nil, nil
}
func (m *MockAuditStore) GetAuditsByResource(ctx context.Context, resourceType, resourceID string, timeRange *TimeRange) ([]*AuditEntry, error) {
	return nil, nil
}
func (m *MockAuditStore) GetAuditsByAction(ctx context.Context, action string, timeRange *TimeRange) ([]*AuditEntry, error) {
	return nil, nil
}
func (m *MockAuditStore) GetFailedActions(ctx context.Context, timeRange *TimeRange, limit int) ([]*AuditEntry, error) {
	return nil, nil
}
func (m *MockAuditStore) GetSuspiciousActivity(ctx context.Context, tenantID string, timeRange *TimeRange) ([]*AuditEntry, error) {
	return nil, nil
}
func (m *MockAuditStore) GetAuditStats(ctx context.Context) (*AuditStats, error) {
	return &AuditStats{}, nil
}
func (m *MockAuditStore) ArchiveAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) {
	return 0, nil
}
func (m *MockAuditStore) PurgeAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) {
	return 0, nil
}
func (m *MockAuditStore) Close() error { return nil }

type MockRBACStore struct{}

func (m *MockRBACStore) StorePermission(ctx context.Context, permission *common.Permission) error {
	return nil
}
func (m *MockRBACStore) GetPermission(ctx context.Context, id string) (*common.Permission, error) {
	return nil, fmt.Errorf("permission not found")
}
func (m *MockRBACStore) ListPermissions(ctx context.Context, resourceType string) ([]*common.Permission, error) {
	return nil, nil
}
func (m *MockRBACStore) UpdatePermission(ctx context.Context, permission *common.Permission) error {
	return nil
}
func (m *MockRBACStore) DeletePermission(ctx context.Context, id string) error  { return nil }
func (m *MockRBACStore) StoreRole(ctx context.Context, role *common.Role) error { return nil }
func (m *MockRBACStore) GetRole(ctx context.Context, id string) (*common.Role, error) {
	return nil, fmt.Errorf("role not found")
}
func (m *MockRBACStore) ListRoles(ctx context.Context, tenantID string) ([]*common.Role, error) {
	return nil, nil
}
func (m *MockRBACStore) UpdateRole(ctx context.Context, role *common.Role) error         { return nil }
func (m *MockRBACStore) DeleteRole(ctx context.Context, id string) error                 { return nil }
func (m *MockRBACStore) StoreSubject(ctx context.Context, subject *common.Subject) error { return nil }
func (m *MockRBACStore) GetSubject(ctx context.Context, id string) (*common.Subject, error) {
	return nil, fmt.Errorf("subject not found")
}
func (m *MockRBACStore) ListSubjects(ctx context.Context, tenantID string, subjectType common.SubjectType) ([]*common.Subject, error) {
	return nil, nil
}
func (m *MockRBACStore) UpdateSubject(ctx context.Context, subject *common.Subject) error { return nil }
func (m *MockRBACStore) DeleteSubject(ctx context.Context, id string) error               { return nil }
func (m *MockRBACStore) StoreRoleAssignment(ctx context.Context, assignment *common.RoleAssignment) error {
	return nil
}
func (m *MockRBACStore) GetRoleAssignment(ctx context.Context, id string) (*common.RoleAssignment, error) {
	return nil, fmt.Errorf("assignment not found")
}
func (m *MockRBACStore) ListRoleAssignments(ctx context.Context, subjectID, roleID, tenantID string) ([]*common.RoleAssignment, error) {
	return nil, nil
}
func (m *MockRBACStore) DeleteRoleAssignment(ctx context.Context, subjectID, roleID, tenantID string) error {
	return nil
}
func (m *MockRBACStore) StoreBulkPermissions(ctx context.Context, permissions []*common.Permission) error {
	return nil
}
func (m *MockRBACStore) StoreBulkRoles(ctx context.Context, roles []*common.Role) error { return nil }
func (m *MockRBACStore) StoreBulkSubjects(ctx context.Context, subjects []*common.Subject) error {
	return nil
}
func (m *MockRBACStore) GetSubjectRoles(ctx context.Context, subjectID, tenantID string) ([]*common.Role, error) {
	return nil, nil
}
func (m *MockRBACStore) GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error) {
	return nil, nil
}
func (m *MockRBACStore) GetSubjectAssignments(ctx context.Context, subjectID, tenantID string) ([]*common.RoleAssignment, error) {
	return nil, nil
}
func (m *MockRBACStore) Initialize(ctx context.Context) error { return nil }
func (m *MockRBACStore) Close() error                         { return nil }

type MockRuntimeStore struct{}

// Session Management
func (m *MockRuntimeStore) CreateSession(ctx context.Context, session *Session) error { return nil }
func (m *MockRuntimeStore) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	return &Session{SessionID: sessionID}, nil
}
func (m *MockRuntimeStore) UpdateSession(ctx context.Context, sessionID string, session *Session) error {
	return nil
}
func (m *MockRuntimeStore) DeleteSession(ctx context.Context, sessionID string) error { return nil }
func (m *MockRuntimeStore) ListSessions(ctx context.Context, filters *SessionFilter) ([]*Session, error) {
	return nil, nil
}

// Session Lifecycle Management
func (m *MockRuntimeStore) SetSessionTTL(ctx context.Context, sessionID string, ttl time.Duration) error {
	return nil
}
func (m *MockRuntimeStore) CleanupExpiredSessions(ctx context.Context) (int, error) { return 0, nil }
func (m *MockRuntimeStore) ListExpiredSessions(ctx context.Context, cutoff time.Time) ([]string, error) {
	return nil, nil
}

// Runtime State Management
func (m *MockRuntimeStore) SetRuntimeState(ctx context.Context, key string, value interface{}) error {
	return nil
}
func (m *MockRuntimeStore) GetRuntimeState(ctx context.Context, key string) (interface{}, error) {
	return nil, fmt.Errorf("not found")
}
func (m *MockRuntimeStore) DeleteRuntimeState(ctx context.Context, key string) error { return nil }
func (m *MockRuntimeStore) ListRuntimeKeys(ctx context.Context, prefix string) ([]string, error) {
	return nil, nil
}

// Batch Operations
func (m *MockRuntimeStore) CreateSessionsBatch(ctx context.Context, sessions []*Session) error {
	return nil
}
func (m *MockRuntimeStore) DeleteSessionsBatch(ctx context.Context, sessionIDs []string) error {
	return nil
}

// Session Queries
func (m *MockRuntimeStore) GetSessionsByUser(ctx context.Context, userID string) ([]*Session, error) {
	return nil, nil
}
func (m *MockRuntimeStore) GetSessionsByTenant(ctx context.Context, tenantID string) ([]*Session, error) {
	return nil, nil
}
func (m *MockRuntimeStore) GetSessionsByType(ctx context.Context, sessionType SessionType) ([]*Session, error) {
	return nil, nil
}
func (m *MockRuntimeStore) GetActiveSessionsCount(ctx context.Context) (int64, error) { return 0, nil }

// Health and Maintenance
func (m *MockRuntimeStore) HealthCheck(ctx context.Context) error { return nil }
func (m *MockRuntimeStore) GetStats(ctx context.Context) (*RuntimeStoreStats, error) {
	return &RuntimeStoreStats{}, nil
}
func (m *MockRuntimeStore) Vacuum(ctx context.Context) error { return nil }

// MockTenantStore implements TenantStore for testing
type MockTenantStore struct{}

func (m *MockTenantStore) CreateTenant(ctx context.Context, tenant *TenantData) error { return nil }
func (m *MockTenantStore) GetTenant(ctx context.Context, tenantID string) (*TenantData, error) {
	return &TenantData{ID: tenantID, Name: "Test Tenant"}, nil
}
func (m *MockTenantStore) UpdateTenant(ctx context.Context, tenant *TenantData) error { return nil }
func (m *MockTenantStore) DeleteTenant(ctx context.Context, tenantID string) error    { return nil }
func (m *MockTenantStore) ListTenants(ctx context.Context, filter *TenantFilter) ([]*TenantData, error) {
	return nil, nil
}
func (m *MockTenantStore) GetTenantHierarchy(ctx context.Context, tenantID string) (*TenantHierarchy, error) {
	return &TenantHierarchy{TenantID: tenantID}, nil
}
func (m *MockTenantStore) GetChildTenants(ctx context.Context, parentID string) ([]*TenantData, error) {
	return nil, nil
}
func (m *MockTenantStore) GetTenantPath(ctx context.Context, tenantID string) ([]string, error) {
	return []string{tenantID}, nil
}
func (m *MockTenantStore) IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error) {
	return false, nil
}
func (m *MockTenantStore) Initialize(ctx context.Context) error { return nil }
func (m *MockTenantStore) Close() error                         { return nil }

// MockRegistrationTokenStore implements RegistrationTokenStore for testing
type MockRegistrationTokenStore struct{}

func (m *MockRegistrationTokenStore) SaveToken(ctx context.Context, token *RegistrationTokenData) error {
	return nil
}
func (m *MockRegistrationTokenStore) GetToken(ctx context.Context, tokenStr string) (*RegistrationTokenData, error) {
	return nil, fmt.Errorf("token not found")
}
func (m *MockRegistrationTokenStore) UpdateToken(ctx context.Context, token *RegistrationTokenData) error {
	return nil
}
func (m *MockRegistrationTokenStore) DeleteToken(ctx context.Context, tokenStr string) error {
	return nil
}
func (m *MockRegistrationTokenStore) ListTokens(ctx context.Context, filter *RegistrationTokenFilter) ([]*RegistrationTokenData, error) {
	return nil, nil
}
func (m *MockRegistrationTokenStore) Initialize(ctx context.Context) error { return nil }
func (m *MockRegistrationTokenStore) Close() error                         { return nil }

// MockStewardStore implements StewardStore for testing
type MockStewardStore struct{}

func (m *MockStewardStore) RegisterSteward(_ context.Context, _ *StewardRecord) error { return nil }
func (m *MockStewardStore) UpdateHeartbeat(_ context.Context, _ string) error         { return nil }
func (m *MockStewardStore) GetSteward(_ context.Context, _ string) (*StewardRecord, error) {
	return nil, ErrStewardNotFound
}
func (m *MockStewardStore) ListStewards(_ context.Context) ([]*StewardRecord, error) {
	return nil, nil
}
func (m *MockStewardStore) ListStewardsByStatus(_ context.Context, _ StewardStatus) ([]*StewardRecord, error) {
	return nil, nil
}
func (m *MockStewardStore) UpdateStewardStatus(_ context.Context, _ string, _ StewardStatus) error {
	return nil
}
func (m *MockStewardStore) DeregisterSteward(_ context.Context, _ string) error { return nil }
func (m *MockStewardStore) GetStewardsSeen(_ context.Context, _ time.Time) ([]*StewardRecord, error) {
	return nil, nil
}
func (m *MockStewardStore) HealthCheck(_ context.Context) error  { return nil }
func (m *MockStewardStore) Initialize(_ context.Context) error   { return nil }
func (m *MockStewardStore) Close() error                         { return nil }

// MockSessionStore implements SessionStore for testing
type MockSessionStore struct{}

func (m *MockSessionStore) CreateSession(_ context.Context, _ *Session) error { return nil }
func (m *MockSessionStore) GetSession(_ context.Context, _ string) (*Session, error) {
	return nil, fmt.Errorf("not found")
}
func (m *MockSessionStore) UpdateSession(_ context.Context, _ string, _ *Session) error {
	return nil
}
func (m *MockSessionStore) DeleteSession(_ context.Context, _ string) error { return nil }
func (m *MockSessionStore) ListSessions(_ context.Context, _ *SessionFilter) ([]*Session, error) {
	return nil, nil
}
func (m *MockSessionStore) SetSessionTTL(_ context.Context, _ string, _ time.Duration) error {
	return nil
}
func (m *MockSessionStore) CleanupExpiredSessions(_ context.Context) (int, error) { return 0, nil }
func (m *MockSessionStore) GetSessionsByUser(_ context.Context, _ string) ([]*Session, error) {
	return nil, nil
}
func (m *MockSessionStore) GetSessionsByTenant(_ context.Context, _ string) ([]*Session, error) {
	return nil, nil
}
func (m *MockSessionStore) GetSessionsByType(_ context.Context, _ SessionType) ([]*Session, error) {
	return nil, nil
}
func (m *MockSessionStore) GetActiveSessionsCount(_ context.Context) (int64, error) { return 0, nil }
func (m *MockSessionStore) HealthCheck(_ context.Context) error                     { return nil }
func (m *MockSessionStore) GetStats(_ context.Context) (*RuntimeStoreStats, error) {
	return &RuntimeStoreStats{}, nil
}
func (m *MockSessionStore) Initialize(_ context.Context) error { return nil }
func (m *MockSessionStore) Close() error                       { return nil }

// MockCommandStore implements CommandStore for testing
type MockCommandStore struct{}

func (m *MockCommandStore) CreateCommandRecord(_ context.Context, _ *CommandRecord) error {
	return nil
}
func (m *MockCommandStore) UpdateCommandStatus(_ context.Context, _ string, _ CommandStatus, _ map[string]interface{}, _ string) error {
	return nil
}
func (m *MockCommandStore) GetCommandRecord(_ context.Context, _ string) (*CommandRecord, error) {
	return nil, fmt.Errorf("not found")
}
func (m *MockCommandStore) ListCommandRecords(_ context.Context, _ *CommandFilter) ([]*CommandRecord, error) {
	return nil, nil
}
func (m *MockCommandStore) ListCommandsByDevice(_ context.Context, _ string) ([]*CommandRecord, error) {
	return nil, nil
}
func (m *MockCommandStore) ListCommandsByStatus(_ context.Context, _ CommandStatus) ([]*CommandRecord, error) {
	return nil, nil
}
func (m *MockCommandStore) GetCommandAuditTrail(_ context.Context, _ string) ([]*CommandTransition, error) {
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

func TestNewStorageManagerFromStores(t *testing.T) {
	t.Run("composite provider name and nil provider", func(t *testing.T) {
		sm := NewStorageManagerFromStores(
			&MockConfigStore{}, &MockAuditStore{}, &MockRBACStore{}, nil,
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
		sm := NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		caps := sm.GetCapabilities()
		// Zero value — no field should be set
		if caps.SupportsTransactions || caps.SupportsVersioning || caps.MaxBatchSize != 0 {
			t.Errorf("expected zero-value ProviderCapabilities, got %+v", caps)
		}
	})

	t.Run("GetVersion returns composite without panic", func(t *testing.T) {
		sm := NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		if sm.GetVersion() != "composite" {
			t.Errorf("expected version %q, got %q", "composite", sm.GetVersion())
		}
	})

	t.Run("GetProvider returns nil without panic", func(t *testing.T) {
		sm := NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		if sm.GetProvider() != nil {
			t.Errorf("expected nil from GetProvider on composite manager")
		}
	})

	t.Run("all 10 store parameters accepted and retrievable", func(t *testing.T) {
		configStore := &MockConfigStore{}
		auditStore := &MockAuditStore{}
		rbacStore := &MockRBACStore{}
		runtimeStore := &MockRuntimeStore{}
		tenantStore := &MockTenantStore{}
		clientTenantStore := &MockClientTenantStore{}
		registrationTokenStore := &MockRegistrationTokenStore{}

		sm := NewStorageManagerFromStores(
			configStore, auditStore, rbacStore, runtimeStore,
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
		sm := NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
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

		// RuntimeStore is always nil (being retired per ADR-003)
		if sm.GetRuntimeStore() != nil {
			t.Errorf("RuntimeStore should be nil in OSS composite manager")
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

func (m *MockOSSProvider) CreateConfigStore(_ map[string]interface{}) (ConfigStore, error) {
	return &MockConfigStore{}, nil
}
func (m *MockOSSProvider) CreateAuditStore(_ map[string]interface{}) (AuditStore, error) {
	return &MockAuditStore{}, nil
}
func (m *MockOSSProvider) CreateStewardStore(_ map[string]interface{}) (StewardStore, error) {
	return &MockStewardStore{}, nil
}
func (m *MockOSSProvider) CreateRBACStore(_ map[string]interface{}) (RBACStore, error) {
	return &MockRBACStore{}, nil
}
func (m *MockOSSProvider) CreateTenantStore(_ map[string]interface{}) (TenantStore, error) {
	return &MockTenantStore{}, nil
}
func (m *MockOSSProvider) CreateClientTenantStore(_ map[string]interface{}) (ClientTenantStore, error) {
	return &MockClientTenantStore{}, nil
}
func (m *MockOSSProvider) CreateRegistrationTokenStore(_ map[string]interface{}) (RegistrationTokenStore, error) {
	return &MockRegistrationTokenStore{}, nil
}
func (m *MockOSSProvider) CreateSessionStore(_ map[string]interface{}) (SessionStore, error) {
	return &MockSessionStore{}, nil
}
func (m *MockOSSProvider) CreateCommandStore(_ map[string]interface{}) (CommandStore, error) {
	return &MockCommandStore{}, nil
}
func (m *MockOSSProvider) CreateRuntimeStore(_ map[string]interface{}) (RuntimeStore, error) {
	return nil, ErrNotSupported
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
