// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces provides tests for hybrid storage management
package interfaces

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
)

func TestHybridStorageConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  HybridStorageConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid hybrid config",
			config: HybridStorageConfig{
				Operational: StorageBackendConfig{
					Provider: "mock",
					Config:   map[string]interface{}{"test": true},
				},
				Configuration: StorageBackendConfig{
					Provider: "mock",
					Config:   map[string]interface{}{"test": true},
				},
			},
			wantErr: false,
		},
		{
			name: "missing operational provider",
			config: HybridStorageConfig{
				Configuration: StorageBackendConfig{
					Provider: "mock",
					Config:   map[string]interface{}{"test": true},
				},
			},
			wantErr: true,
			errMsg:  "operational storage provider is required",
		},
		{
			name: "missing configuration provider",
			config: HybridStorageConfig{
				Operational: StorageBackendConfig{
					Provider: "mock",
					Config:   map[string]interface{}{"test": true},
				},
			},
			wantErr: true,
			errMsg:  "configuration storage provider is required",
		},
		{
			name: "invalid operational provider",
			config: HybridStorageConfig{
				Operational: StorageBackendConfig{
					Provider: "nonexistent",
					Config:   map[string]interface{}{},
				},
				Configuration: StorageBackendConfig{
					Provider: "mock",
					Config:   map[string]interface{}{"test": true},
				},
			},
			wantErr: true,
			errMsg:  "operational storage provider 'nonexistent' not available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Register mock provider for valid tests
			if !tt.wantErr || tt.name == "invalid operational provider" {
				RegisterStorageProvider(&mockProvider{})
			}

			err := ValidateHybridConfig(tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHybridStorageManager_Creation(t *testing.T) {
	// Register mock provider
	RegisterStorageProvider(&mockProvider{})
	defer UnregisterStorageProvider("mock")

	config := HybridStorageConfig{
		Operational: StorageBackendConfig{
			Provider: "mock",
			Config:   map[string]interface{}{"test": "operational"},
		},
		Configuration: StorageBackendConfig{
			Provider: "mock",
			Config:   map[string]interface{}{"test": "configuration"},
		},
	}

	manager, err := NewHybridStorageManager(config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Test interface access
	assert.NotNil(t, manager.GetClientTenantStore())
	assert.NotNil(t, manager.GetAuditStore())
	assert.NotNil(t, manager.GetConfigStore())

	// Test provider access
	assert.NotNil(t, manager.GetOperationalProvider())
	assert.NotNil(t, manager.GetConfigurationProvider())
	assert.Equal(t, "mock", manager.GetOperationalProvider().Name())
	assert.Equal(t, "mock", manager.GetConfigurationProvider().Name())

	// Test capabilities
	opCaps := manager.GetOperationalCapabilities()
	cfgCaps := manager.GetConfigurationCapabilities()
	assert.NotNil(t, opCaps)
	assert.NotNil(t, cfgCaps)

	// Test backend info
	info := manager.GetBackendInfo()
	assert.Equal(t, "mock", info.Operational.Provider)
	assert.Equal(t, "mock", info.Configuration.Provider)
	assert.Equal(t, "1.0.0", info.Operational.Version)
	assert.Equal(t, "1.0.0", info.Configuration.Version)
}

func TestCreateHybridStorageFromConfig(t *testing.T) {
	// Register mock provider
	RegisterStorageProvider(&mockProvider{})
	defer UnregisterStorageProvider("mock")

	config := HybridStorageConfig{
		Operational: StorageBackendConfig{
			Provider: "mock",
			Config:   map[string]interface{}{"test": true},
		},
		Configuration: StorageBackendConfig{
			Provider: "mock",
			Config:   map[string]interface{}{"test": true},
		},
	}

	manager, err := CreateHybridStorageFromConfig(config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Verify all storage interfaces are available
	assert.NotNil(t, manager.GetClientTenantStore())
	assert.NotNil(t, manager.GetAuditStore())
	assert.NotNil(t, manager.GetConfigStore())
}

func TestCreateHybridStorageManagerFromConfig(t *testing.T) {
	// Register mock provider
	RegisterStorageProvider(&mockProvider{})
	defer UnregisterStorageProvider("mock")

	config := HybridStorageConfig{
		Operational: StorageBackendConfig{
			Provider: "mock",
			Config:   map[string]interface{}{"test": true},
		},
		Configuration: StorageBackendConfig{
			Provider: "mock",
			Config:   map[string]interface{}{"test": true},
		},
	}

	manager, err := CreateHybridStorageManagerFromConfig(config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Test that it returns the same type as the direct function
	directManager, err := CreateHybridStorageFromConfig(config)
	require.NoError(t, err)

	assert.Equal(t, manager.GetOperationalProvider().Name(), directManager.GetOperationalProvider().Name())
	assert.Equal(t, manager.GetConfigurationProvider().Name(), directManager.GetConfigurationProvider().Name())
}

func TestGetRecommendedHybridConfig(t *testing.T) {
	config := GetRecommendedHybridConfig()

	// Verify structure
	assert.Equal(t, "database", config.Operational.Provider)
	assert.Equal(t, "git", config.Configuration.Provider)

	// Verify operational config has database-specific settings
	opConfig := config.Operational.Config
	assert.Contains(t, opConfig, "host")
	assert.Contains(t, opConfig, "port")
	assert.Contains(t, opConfig, "database")
	assert.Contains(t, opConfig, "max_open_connections")

	// Verify configuration config has git-specific settings
	cfgConfig := config.Configuration.Config
	assert.Contains(t, cfgConfig, "repository_path")
	assert.Contains(t, cfgConfig, "remote_url")
	assert.Contains(t, cfgConfig, "branch")
}

func TestPlanHybridMigration(t *testing.T) {
	tests := []struct {
		name            string
		currentProvider string
		currentConfig   map[string]interface{}
		expectedOp      string
		expectedCfg     string
	}{
		{
			name:            "migrate from database to hybrid",
			currentProvider: "database",
			currentConfig: map[string]interface{}{
				"host":     "localhost",
				"database": "cfgms",
			},
			expectedOp:  "database", // Keep existing database for operational
			expectedCfg: "git",      // Add git for configuration
		},
		{
			name:            "migrate from git to hybrid",
			currentProvider: "git",
			currentConfig: map[string]interface{}{
				"repository_path": "/data/cfgms",
				"remote_url":      "git@github.com:org/repo.git",
			},
			expectedOp:  "database", // Add database for operational
			expectedCfg: "git",      // Keep existing git for configuration
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := PlanHybridMigration(tt.currentProvider, tt.currentConfig)

			assert.Equal(t, tt.currentProvider, strategy.SourceProvider)
			assert.Equal(t, tt.currentConfig, strategy.SourceConfig)
			assert.True(t, strategy.MigrateData)
			assert.True(t, strategy.BackupFirst)

			assert.Equal(t, tt.expectedOp, strategy.TargetConfig.Operational.Provider)
			assert.Equal(t, tt.expectedCfg, strategy.TargetConfig.Configuration.Provider)

			// Verify config preservation
			switch tt.currentProvider {
			case "database":
				assert.Equal(t, tt.currentConfig, strategy.TargetConfig.Operational.Config)
			case "git":
				assert.Equal(t, tt.currentConfig, strategy.TargetConfig.Configuration.Config)
			}
		})
	}
}

func TestHybridBackendInfo(t *testing.T) {
	// Register mock provider
	RegisterStorageProvider(&mockProvider{})
	defer UnregisterStorageProvider("mock")

	config := HybridStorageConfig{
		Operational: StorageBackendConfig{
			Provider: "mock",
			Config:   map[string]interface{}{"test": "operational"},
		},
		Configuration: StorageBackendConfig{
			Provider: "mock",
			Config:   map[string]interface{}{"test": "configuration"},
		},
	}

	manager, err := NewHybridStorageManager(config)
	require.NoError(t, err)

	info := manager.GetBackendInfo()

	// Verify operational backend info
	assert.Equal(t, "mock", info.Operational.Provider)
	assert.Equal(t, "Mock storage provider for testing", info.Operational.Description)
	assert.Equal(t, "1.0.0", info.Operational.Version)
	assert.NotNil(t, info.Operational.Capabilities)

	// Verify configuration backend info
	assert.Equal(t, "mock", info.Configuration.Provider)
	assert.Equal(t, "Mock storage provider for testing", info.Configuration.Description)
	assert.Equal(t, "1.0.0", info.Configuration.Version)
	assert.NotNil(t, info.Configuration.Capabilities)
}

// mockProvider implements StorageProvider for testing
type mockProvider struct{}

func (p *mockProvider) Name() string {
	return "mock"
}

func (p *mockProvider) Description() string {
	return "Mock storage provider for testing"
}

func (p *mockProvider) Available() (bool, error) {
	return true, nil
}

func (p *mockProvider) CreateClientTenantStore(config map[string]interface{}) (ClientTenantStore, error) {
	return &mockClientTenantStore{}, nil
}

func (p *mockProvider) CreateConfigStore(config map[string]interface{}) (ConfigStore, error) {
	return &mockConfigStore{}, nil
}

func (p *mockProvider) CreateAuditStore(config map[string]interface{}) (AuditStore, error) {
	return &mockAuditStore{}, nil
}

func (p *mockProvider) CreateRBACStore(config map[string]interface{}) (RBACStore, error) {
	return &mockRBACStore{}, nil
}

func (p *mockProvider) CreateRuntimeStore(config map[string]interface{}) (RuntimeStore, error) {
	return &mockRuntimeStore{}, nil
}

func (p *mockProvider) CreateTenantStore(config map[string]interface{}) (TenantStore, error) {
	return &mockTenantStore{}, nil
}

func (p *mockProvider) CreateRegistrationTokenStore(config map[string]interface{}) (RegistrationTokenStore, error) {
	return &mockRegistrationTokenStore{}, nil
}

func (p *mockProvider) CreateSessionStore(config map[string]interface{}) (SessionStore, error) {
	return nil, ErrNotSupported
}

func (p *mockProvider) CreateStewardStore(config map[string]interface{}) (StewardStore, error) {
	return nil, ErrNotSupported
}

func (p *mockProvider) GetCapabilities() ProviderCapabilities {
	return ProviderCapabilities{
		SupportsTransactions:   true,
		SupportsVersioning:     true,
		SupportsFullTextSearch: false,
		SupportsEncryption:     false,
		SupportsCompression:    false,
		SupportsReplication:    false,
		SupportsSharding:       false,
		MaxBatchSize:           100,
		MaxConfigSize:          1024 * 1024, // 1MB
		MaxAuditRetentionDays:  90,
	}
}

func (p *mockProvider) GetVersion() string {
	return "1.0.0"
}

// Mock store implementations
type mockClientTenantStore struct{}

func (s *mockClientTenantStore) StoreClientTenant(client *ClientTenant) error {
	return nil
}

func (s *mockClientTenantStore) GetClientTenant(tenantID string) (*ClientTenant, error) {
	return &ClientTenant{ID: tenantID, TenantName: "Mock Tenant"}, nil
}

func (s *mockClientTenantStore) GetClientTenantByIdentifier(clientIdentifier string) (*ClientTenant, error) {
	return &ClientTenant{ID: "mock-id", ClientIdentifier: clientIdentifier}, nil
}

func (s *mockClientTenantStore) ListClientTenants(status ClientTenantStatus) ([]*ClientTenant, error) {
	return []*ClientTenant{{ID: "test", TenantName: "Test Tenant"}}, nil
}

func (s *mockClientTenantStore) UpdateClientTenantStatus(tenantID string, status ClientTenantStatus) error {
	return nil
}

func (s *mockClientTenantStore) DeleteClientTenant(tenantID string) error {
	return nil
}

func (s *mockClientTenantStore) StoreAdminConsentRequest(request *AdminConsentRequest) error {
	return nil
}

func (s *mockClientTenantStore) GetAdminConsentRequest(state string) (*AdminConsentRequest, error) {
	return &AdminConsentRequest{State: state}, nil
}

func (s *mockClientTenantStore) DeleteAdminConsentRequest(state string) error {
	return nil
}

func (s *mockClientTenantStore) Close() error {
	return nil
}

type mockConfigStore struct{}

func (s *mockConfigStore) StoreConfig(ctx context.Context, config *ConfigEntry) error {
	return nil
}

func (s *mockConfigStore) GetConfig(ctx context.Context, key *ConfigKey) (*ConfigEntry, error) {
	return &ConfigEntry{Key: key, Data: []byte("mock-data"), Format: ConfigFormatYAML}, nil
}

func (s *mockConfigStore) DeleteConfig(ctx context.Context, key *ConfigKey) error {
	return nil
}

func (s *mockConfigStore) ListConfigs(ctx context.Context, filter *ConfigFilter) ([]*ConfigEntry, error) {
	return []*ConfigEntry{{Key: &ConfigKey{TenantID: "test", Name: "test"}, Data: []byte("mock"), Format: ConfigFormatYAML}}, nil
}

func (s *mockConfigStore) GetConfigHistory(ctx context.Context, key *ConfigKey, limit int) ([]*ConfigEntry, error) {
	return []*ConfigEntry{{Key: key, Data: []byte("mock-history"), Format: ConfigFormatYAML}}, nil
}

func (s *mockConfigStore) GetConfigVersion(ctx context.Context, key *ConfigKey, version int64) (*ConfigEntry, error) {
	return &ConfigEntry{Key: key, Data: []byte("mock-version"), Format: ConfigFormatYAML, Version: version}, nil
}

func (s *mockConfigStore) StoreConfigBatch(ctx context.Context, configs []*ConfigEntry) error {
	return nil
}

func (s *mockConfigStore) DeleteConfigBatch(ctx context.Context, keys []*ConfigKey) error {
	return nil
}

func (s *mockConfigStore) ResolveConfigWithInheritance(ctx context.Context, key *ConfigKey) (*ConfigEntry, error) {
	return &ConfigEntry{Key: key, Data: []byte("mock-inherited"), Format: ConfigFormatYAML}, nil
}

func (s *mockConfigStore) ValidateConfig(ctx context.Context, config *ConfigEntry) error {
	return nil
}

func (s *mockConfigStore) GetConfigStats(ctx context.Context) (*ConfigStats, error) {
	return &ConfigStats{
		TotalConfigs:       1,
		TotalSize:          100,
		ConfigsByTenant:    map[string]int64{"test": 1},
		ConfigsByFormat:    map[string]int64{"yaml": 1},
		ConfigsByNamespace: map[string]int64{"default": 1},
		AverageSize:        100,
	}, nil
}

type mockAuditStore struct{}

func (s *mockAuditStore) StoreAuditEntry(ctx context.Context, entry *AuditEntry) error {
	return nil
}

func (s *mockAuditStore) GetAuditEntry(ctx context.Context, id string) (*AuditEntry, error) {
	return &AuditEntry{ID: id, Action: "mock-action"}, nil
}

func (s *mockAuditStore) ListAuditEntries(ctx context.Context, filter *AuditFilter) ([]*AuditEntry, error) {
	return []*AuditEntry{{ID: "test", Action: "mock-action"}}, nil
}

func (s *mockAuditStore) StoreAuditBatch(ctx context.Context, entries []*AuditEntry) error {
	return nil
}

func (s *mockAuditStore) GetAuditsByUser(ctx context.Context, userID string, timeRange *TimeRange) ([]*AuditEntry, error) {
	return []*AuditEntry{{ID: "test", UserID: userID, Action: "mock-user-action"}}, nil
}

func (s *mockAuditStore) GetAuditsByResource(ctx context.Context, resourceType, resourceID string, timeRange *TimeRange) ([]*AuditEntry, error) {
	return []*AuditEntry{{ID: "test", ResourceType: resourceType, ResourceID: resourceID, Action: "mock-resource-action"}}, nil
}

func (s *mockAuditStore) GetAuditsByAction(ctx context.Context, action string, timeRange *TimeRange) ([]*AuditEntry, error) {
	return []*AuditEntry{{ID: "test", Action: action}}, nil
}

func (s *mockAuditStore) GetFailedActions(ctx context.Context, timeRange *TimeRange, limit int) ([]*AuditEntry, error) {
	return []*AuditEntry{}, nil
}

func (s *mockAuditStore) GetSuspiciousActivity(ctx context.Context, tenantID string, timeRange *TimeRange) ([]*AuditEntry, error) {
	return []*AuditEntry{}, nil
}

func (s *mockAuditStore) GetAuditStats(ctx context.Context) (*AuditStats, error) {
	return &AuditStats{
		TotalEntries:      1,
		TotalSize:         100,
		EntriesByTenant:   map[string]int64{"test": 1},
		EntriesByType:     map[string]int64{"system_event": 1},
		EntriesByResult:   map[string]int64{"success": 1},
		EntriesBySeverity: map[string]int64{"low": 1},
		EntriesLast24h:    1,
		EntriesLast7d:     1,
		EntriesLast30d:    1,
		AverageSize:       100,
	}, nil
}

func (s *mockAuditStore) ArchiveAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) {
	return 0, nil
}

func (s *mockAuditStore) PurgeAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) {
	return 0, nil
}

func (s *mockAuditStore) Close() error {
	return nil
}

type mockRBACStore struct{}

func (s *mockRBACStore) StorePermission(ctx context.Context, permission *common.Permission) error {
	return nil
}
func (s *mockRBACStore) GetPermission(ctx context.Context, id string) (*common.Permission, error) {
	return nil, nil
}
func (s *mockRBACStore) ListPermissions(ctx context.Context, resourceType string) ([]*common.Permission, error) {
	return nil, nil
}
func (s *mockRBACStore) UpdatePermission(ctx context.Context, permission *common.Permission) error {
	return nil
}
func (s *mockRBACStore) DeletePermission(ctx context.Context, id string) error  { return nil }
func (s *mockRBACStore) StoreRole(ctx context.Context, role *common.Role) error { return nil }
func (s *mockRBACStore) GetRole(ctx context.Context, id string) (*common.Role, error) {
	return nil, nil
}
func (s *mockRBACStore) ListRoles(ctx context.Context, tenantID string) ([]*common.Role, error) {
	return nil, nil
}
func (s *mockRBACStore) UpdateRole(ctx context.Context, role *common.Role) error         { return nil }
func (s *mockRBACStore) DeleteRole(ctx context.Context, id string) error                 { return nil }
func (s *mockRBACStore) StoreSubject(ctx context.Context, subject *common.Subject) error { return nil }
func (s *mockRBACStore) GetSubject(ctx context.Context, id string) (*common.Subject, error) {
	return nil, nil
}
func (s *mockRBACStore) ListSubjects(ctx context.Context, tenantID string, subjectType common.SubjectType) ([]*common.Subject, error) {
	return nil, nil
}
func (s *mockRBACStore) UpdateSubject(ctx context.Context, subject *common.Subject) error { return nil }
func (s *mockRBACStore) DeleteSubject(ctx context.Context, id string) error               { return nil }
func (s *mockRBACStore) StoreRoleAssignment(ctx context.Context, assignment *common.RoleAssignment) error {
	return nil
}
func (s *mockRBACStore) GetRoleAssignment(ctx context.Context, id string) (*common.RoleAssignment, error) {
	return nil, nil
}
func (s *mockRBACStore) ListRoleAssignments(ctx context.Context, subjectID, roleID, tenantID string) ([]*common.RoleAssignment, error) {
	return nil, nil
}
func (s *mockRBACStore) DeleteRoleAssignment(ctx context.Context, subjectID, roleID, tenantID string) error {
	return nil
}
func (s *mockRBACStore) StoreBulkPermissions(ctx context.Context, permissions []*common.Permission) error {
	return nil
}
func (s *mockRBACStore) StoreBulkRoles(ctx context.Context, roles []*common.Role) error { return nil }
func (s *mockRBACStore) StoreBulkSubjects(ctx context.Context, subjects []*common.Subject) error {
	return nil
}
func (s *mockRBACStore) GetSubjectRoles(ctx context.Context, subjectID, tenantID string) ([]*common.Role, error) {
	return nil, nil
}
func (s *mockRBACStore) GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error) {
	return nil, nil
}
func (s *mockRBACStore) GetSubjectAssignments(ctx context.Context, subjectID, tenantID string) ([]*common.RoleAssignment, error) {
	return nil, nil
}
func (s *mockRBACStore) Initialize(ctx context.Context) error { return nil }
func (s *mockRBACStore) Close() error                         { return nil }

type mockRuntimeStore struct{}

// Session Management
func (s *mockRuntimeStore) CreateSession(ctx context.Context, session *Session) error { return nil }
func (s *mockRuntimeStore) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	return &Session{SessionID: sessionID}, nil
}
func (s *mockRuntimeStore) UpdateSession(ctx context.Context, sessionID string, session *Session) error {
	return nil
}
func (s *mockRuntimeStore) DeleteSession(ctx context.Context, sessionID string) error { return nil }
func (s *mockRuntimeStore) ListSessions(ctx context.Context, filters *SessionFilter) ([]*Session, error) {
	return nil, nil
}

// Session Lifecycle Management
func (s *mockRuntimeStore) SetSessionTTL(ctx context.Context, sessionID string, ttl time.Duration) error {
	return nil
}
func (s *mockRuntimeStore) CleanupExpiredSessions(ctx context.Context) (int, error) { return 0, nil }
func (s *mockRuntimeStore) ListExpiredSessions(ctx context.Context, cutoff time.Time) ([]string, error) {
	return nil, nil
}

// Runtime State Management
func (s *mockRuntimeStore) SetRuntimeState(ctx context.Context, key string, value interface{}) error {
	return nil
}
func (s *mockRuntimeStore) GetRuntimeState(ctx context.Context, key string) (interface{}, error) {
	return nil, fmt.Errorf("not found")
}
func (s *mockRuntimeStore) DeleteRuntimeState(ctx context.Context, key string) error { return nil }
func (s *mockRuntimeStore) ListRuntimeKeys(ctx context.Context, prefix string) ([]string, error) {
	return nil, nil
}

// Batch Operations
func (s *mockRuntimeStore) CreateSessionsBatch(ctx context.Context, sessions []*Session) error {
	return nil
}
func (s *mockRuntimeStore) DeleteSessionsBatch(ctx context.Context, sessionIDs []string) error {
	return nil
}

// Session Queries
func (s *mockRuntimeStore) GetSessionsByUser(ctx context.Context, userID string) ([]*Session, error) {
	return nil, nil
}
func (s *mockRuntimeStore) GetSessionsByTenant(ctx context.Context, tenantID string) ([]*Session, error) {
	return nil, nil
}
func (s *mockRuntimeStore) GetSessionsByType(ctx context.Context, sessionType SessionType) ([]*Session, error) {
	return nil, nil
}
func (s *mockRuntimeStore) GetActiveSessionsCount(ctx context.Context) (int64, error) { return 0, nil }

// Health and Maintenance
func (s *mockRuntimeStore) HealthCheck(ctx context.Context) error { return nil }
func (s *mockRuntimeStore) GetStats(ctx context.Context) (*RuntimeStoreStats, error) {
	return &RuntimeStoreStats{}, nil
}
func (s *mockRuntimeStore) Vacuum(ctx context.Context) error { return nil }

// mockTenantStore implements TenantStore for testing
type mockTenantStore struct{}

func (s *mockTenantStore) CreateTenant(ctx context.Context, tenant *TenantData) error { return nil }
func (s *mockTenantStore) GetTenant(ctx context.Context, tenantID string) (*TenantData, error) {
	return &TenantData{ID: tenantID, Name: "Test Tenant"}, nil
}
func (s *mockTenantStore) UpdateTenant(ctx context.Context, tenant *TenantData) error { return nil }
func (s *mockTenantStore) DeleteTenant(ctx context.Context, tenantID string) error    { return nil }
func (s *mockTenantStore) ListTenants(ctx context.Context, filter *TenantFilter) ([]*TenantData, error) {
	return nil, nil
}
func (s *mockTenantStore) GetTenantHierarchy(ctx context.Context, tenantID string) (*TenantHierarchy, error) {
	return &TenantHierarchy{TenantID: tenantID}, nil
}
func (s *mockTenantStore) GetChildTenants(ctx context.Context, parentID string) ([]*TenantData, error) {
	return nil, nil
}
func (s *mockTenantStore) GetTenantPath(ctx context.Context, tenantID string) ([]string, error) {
	return []string{tenantID}, nil
}
func (s *mockTenantStore) IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error) {
	return false, nil
}
func (s *mockTenantStore) Initialize(ctx context.Context) error { return nil }
func (s *mockTenantStore) Close() error                         { return nil }

// mockRegistrationTokenStore implements RegistrationTokenStore for testing
type mockRegistrationTokenStore struct{}

func (s *mockRegistrationTokenStore) SaveToken(ctx context.Context, token *RegistrationTokenData) error {
	return nil
}
func (s *mockRegistrationTokenStore) GetToken(ctx context.Context, tokenStr string) (*RegistrationTokenData, error) {
	return &RegistrationTokenData{Token: tokenStr, TenantID: "test-tenant"}, nil
}
func (s *mockRegistrationTokenStore) UpdateToken(ctx context.Context, token *RegistrationTokenData) error {
	return nil
}
func (s *mockRegistrationTokenStore) DeleteToken(ctx context.Context, tokenStr string) error {
	return nil
}
func (s *mockRegistrationTokenStore) ListTokens(ctx context.Context, filter *RegistrationTokenFilter) ([]*RegistrationTokenData, error) {
	return nil, nil
}
func (s *mockRegistrationTokenStore) Initialize(ctx context.Context) error { return nil }
func (s *mockRegistrationTokenStore) Close() error                         { return nil }
