// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces provides tests for hybrid storage management
package interfaces

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
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
	assert.Equal(t, "flatfile", config.Configuration.Provider)

	// Verify operational config has database-specific settings
	opConfig := config.Operational.Config
	assert.Contains(t, opConfig, "host")
	assert.Contains(t, opConfig, "port")
	assert.Contains(t, opConfig, "database")
	assert.Contains(t, opConfig, "max_open_connections")

	// Verify configuration config has flatfile-specific settings
	cfgConfig := config.Configuration.Config
	assert.Contains(t, cfgConfig, "root")
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
			expectedCfg: "flatfile", // Add flatfile for configuration
		},
		{
			name:            "migrate from git to hybrid",
			currentProvider: "git",
			currentConfig: map[string]interface{}{
				"repository_path": "/data/cfgms",
				"remote_url":      "git@github.com:org/repo.git",
			},
			expectedOp:  "database", // Add database for operational
			expectedCfg: "flatfile", // Migrate git to flatfile
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

			// Verify config preservation for database case
			if tt.currentProvider == "database" {
				assert.Equal(t, tt.currentConfig, strategy.TargetConfig.Operational.Config)
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

// mockProvider implements StorageProvider for testing HybridStorageManager wiring logic.
//
// Architecture note: This test file is in package "interfaces" (same package as the
// tested code) to access package-internal registration helpers. Adding real provider
// imports (flatfile, sqlite) here would create a circular dependency:
//
//	interfaces_test -> pkg/storage/providers/flatfile -> pkg/storage/interfaces
//
// The mock is therefore the only viable option for unit-testing HybridStorageManager
// wiring within this package. End-to-end hybrid storage behaviour is tested via
// integration tests that use real providers.
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

func (p *mockProvider) CreateClientTenantStore(_ map[string]interface{}) (business.ClientTenantStore, error) {
	return &mockClientTenantStore{}, nil
}

func (p *mockProvider) CreateConfigStore(_ map[string]interface{}) (cfgconfig.ConfigStore, error) {
	return &mockConfigStore{}, nil
}

func (p *mockProvider) CreateAuditStore(_ map[string]interface{}) (business.AuditStore, error) {
	return &mockAuditStore{}, nil
}

func (p *mockProvider) CreateRBACStore(_ map[string]interface{}) (business.RBACStore, error) {
	return &mockRBACStore{}, nil
}

func (p *mockProvider) CreateTenantStore(_ map[string]interface{}) (business.TenantStore, error) {
	return &mockTenantStore{}, nil
}

func (p *mockProvider) CreateRegistrationTokenStore(_ map[string]interface{}) (business.RegistrationTokenStore, error) {
	return &mockRegistrationTokenStore{}, nil
}

func (p *mockProvider) CreateSessionStore(_ map[string]interface{}) (business.SessionStore, error) {
	return nil, business.ErrNotSupported
}

func (p *mockProvider) CreateStewardStore(_ map[string]interface{}) (business.StewardStore, error) {
	return nil, business.ErrNotSupported
}

func (p *mockProvider) CreateCommandStore(_ map[string]interface{}) (business.CommandStore, error) {
	return nil, business.ErrNotSupported
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

func (s *mockClientTenantStore) StoreClientTenant(_ *business.ClientTenant) error {
	return nil
}

func (s *mockClientTenantStore) GetClientTenant(tenantID string) (*business.ClientTenant, error) {
	return &business.ClientTenant{ID: tenantID, TenantName: "Mock Tenant"}, nil
}

func (s *mockClientTenantStore) GetClientTenantByIdentifier(clientIdentifier string) (*business.ClientTenant, error) {
	return &business.ClientTenant{ID: "mock-id", ClientIdentifier: clientIdentifier}, nil
}

func (s *mockClientTenantStore) ListClientTenants(_ business.ClientTenantStatus) ([]*business.ClientTenant, error) {
	return []*business.ClientTenant{{ID: "test", TenantName: "Test Tenant"}}, nil
}

func (s *mockClientTenantStore) UpdateClientTenantStatus(_ string, _ business.ClientTenantStatus) error {
	return nil
}

func (s *mockClientTenantStore) DeleteClientTenant(_ string) error {
	return nil
}

func (s *mockClientTenantStore) StoreAdminConsentRequest(_ *business.AdminConsentRequest) error {
	return nil
}

func (s *mockClientTenantStore) GetAdminConsentRequest(state string) (*business.AdminConsentRequest, error) {
	return &business.AdminConsentRequest{State: state}, nil
}

func (s *mockClientTenantStore) DeleteAdminConsentRequest(_ string) error {
	return nil
}

func (s *mockClientTenantStore) Close() error {
	return nil
}

type mockConfigStore struct{}

func (s *mockConfigStore) StoreConfig(_ context.Context, _ *cfgconfig.ConfigEntry) error {
	return nil
}

func (s *mockConfigStore) GetConfig(_ context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	return &cfgconfig.ConfigEntry{Key: key, Data: []byte("mock-data"), Format: cfgconfig.ConfigFormatYAML}, nil
}

func (s *mockConfigStore) DeleteConfig(_ context.Context, _ *cfgconfig.ConfigKey) error {
	return nil
}

func (s *mockConfigStore) ListConfigs(_ context.Context, _ *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	return []*cfgconfig.ConfigEntry{{Key: &cfgconfig.ConfigKey{TenantID: "test", Name: "test"}, Data: []byte("mock"), Format: cfgconfig.ConfigFormatYAML}}, nil
}

func (s *mockConfigStore) GetConfigHistory(_ context.Context, key *cfgconfig.ConfigKey, _ int) ([]*cfgconfig.ConfigEntry, error) {
	return []*cfgconfig.ConfigEntry{{Key: key, Data: []byte("mock-history"), Format: cfgconfig.ConfigFormatYAML}}, nil
}

func (s *mockConfigStore) GetConfigVersion(_ context.Context, key *cfgconfig.ConfigKey, version int64) (*cfgconfig.ConfigEntry, error) {
	return &cfgconfig.ConfigEntry{Key: key, Data: []byte("mock-version"), Format: cfgconfig.ConfigFormatYAML, Version: version}, nil
}

func (s *mockConfigStore) StoreConfigBatch(_ context.Context, _ []*cfgconfig.ConfigEntry) error {
	return nil
}

func (s *mockConfigStore) DeleteConfigBatch(_ context.Context, _ []*cfgconfig.ConfigKey) error {
	return nil
}

func (s *mockConfigStore) ResolveConfigWithInheritance(_ context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	return &cfgconfig.ConfigEntry{Key: key, Data: []byte("mock-inherited"), Format: cfgconfig.ConfigFormatYAML}, nil
}

func (s *mockConfigStore) ValidateConfig(_ context.Context, _ *cfgconfig.ConfigEntry) error {
	return nil
}

func (s *mockConfigStore) GetConfigStats(_ context.Context) (*cfgconfig.ConfigStats, error) {
	return &cfgconfig.ConfigStats{
		TotalConfigs:       1,
		TotalSize:          100,
		ConfigsByTenant:    map[string]int64{"test": 1},
		ConfigsByFormat:    map[string]int64{"yaml": 1},
		ConfigsByNamespace: map[string]int64{"default": 1},
		AverageSize:        100,
	}, nil
}

type mockAuditStore struct{}

func (s *mockAuditStore) StoreAuditEntry(_ context.Context, _ *business.AuditEntry) error {
	return nil
}

func (s *mockAuditStore) GetAuditEntry(_ context.Context, id string) (*business.AuditEntry, error) {
	return &business.AuditEntry{ID: id, Action: "mock-action"}, nil
}

func (s *mockAuditStore) ListAuditEntries(_ context.Context, _ *business.AuditFilter) ([]*business.AuditEntry, error) {
	return []*business.AuditEntry{{ID: "test", Action: "mock-action"}}, nil
}

func (s *mockAuditStore) StoreAuditBatch(_ context.Context, _ []*business.AuditEntry) error {
	return nil
}

func (s *mockAuditStore) GetAuditsByUser(_ context.Context, userID string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return []*business.AuditEntry{{ID: "test", UserID: userID, Action: "mock-user-action"}}, nil
}

func (s *mockAuditStore) GetAuditsByResource(_ context.Context, resourceType, resourceID string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return []*business.AuditEntry{{ID: "test", ResourceType: resourceType, ResourceID: resourceID, Action: "mock-resource-action"}}, nil
}

func (s *mockAuditStore) GetAuditsByAction(_ context.Context, action string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return []*business.AuditEntry{{ID: "test", Action: action}}, nil
}

func (s *mockAuditStore) GetFailedActions(_ context.Context, _ *business.TimeRange, _ int) ([]*business.AuditEntry, error) {
	return []*business.AuditEntry{}, nil
}

func (s *mockAuditStore) GetSuspiciousActivity(_ context.Context, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return []*business.AuditEntry{}, nil
}

func (s *mockAuditStore) GetAuditStats(_ context.Context) (*business.AuditStats, error) {
	return &business.AuditStats{
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

func (s *mockAuditStore) ArchiveAuditEntries(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (s *mockAuditStore) PurgeAuditEntries(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (s *mockAuditStore) Close() error {
	return nil
}

type mockRBACStore struct{}

func (s *mockRBACStore) StorePermission(_ context.Context, _ *common.Permission) error {
	return nil
}
func (s *mockRBACStore) GetPermission(_ context.Context, _ string) (*common.Permission, error) {
	return nil, nil
}
func (s *mockRBACStore) ListPermissions(_ context.Context, _ string) ([]*common.Permission, error) {
	return nil, nil
}
func (s *mockRBACStore) UpdatePermission(_ context.Context, _ *common.Permission) error {
	return nil
}
func (s *mockRBACStore) DeletePermission(_ context.Context, _ string) error { return nil }
func (s *mockRBACStore) StoreRole(_ context.Context, _ *common.Role) error  { return nil }
func (s *mockRBACStore) GetRole(_ context.Context, _ string) (*common.Role, error) {
	return nil, nil
}
func (s *mockRBACStore) ListRoles(_ context.Context, _ string) ([]*common.Role, error) {
	return nil, nil
}
func (s *mockRBACStore) UpdateRole(_ context.Context, _ *common.Role) error      { return nil }
func (s *mockRBACStore) DeleteRole(_ context.Context, _ string) error            { return nil }
func (s *mockRBACStore) StoreSubject(_ context.Context, _ *common.Subject) error { return nil }
func (s *mockRBACStore) GetSubject(_ context.Context, _ string) (*common.Subject, error) {
	return nil, nil
}
func (s *mockRBACStore) ListSubjects(_ context.Context, _ string, _ common.SubjectType) ([]*common.Subject, error) {
	return nil, nil
}
func (s *mockRBACStore) UpdateSubject(_ context.Context, _ *common.Subject) error { return nil }
func (s *mockRBACStore) DeleteSubject(_ context.Context, _ string) error          { return nil }
func (s *mockRBACStore) StoreRoleAssignment(_ context.Context, _ *common.RoleAssignment) error {
	return nil
}
func (s *mockRBACStore) GetRoleAssignment(_ context.Context, _ string) (*common.RoleAssignment, error) {
	return nil, nil
}
func (s *mockRBACStore) ListRoleAssignments(_ context.Context, _, _, _ string) ([]*common.RoleAssignment, error) {
	return nil, nil
}
func (s *mockRBACStore) DeleteRoleAssignment(_ context.Context, _, _, _ string) error {
	return nil
}
func (s *mockRBACStore) StoreBulkPermissions(_ context.Context, _ []*common.Permission) error {
	return nil
}
func (s *mockRBACStore) StoreBulkRoles(_ context.Context, _ []*common.Role) error { return nil }
func (s *mockRBACStore) StoreBulkSubjects(_ context.Context, _ []*common.Subject) error {
	return nil
}
func (s *mockRBACStore) GetSubjectRoles(_ context.Context, _, _ string) ([]*common.Role, error) {
	return nil, nil
}
func (s *mockRBACStore) GetRolePermissions(_ context.Context, _ string) ([]*common.Permission, error) {
	return nil, nil
}
func (s *mockRBACStore) GetSubjectAssignments(_ context.Context, _, _ string) ([]*common.RoleAssignment, error) {
	return nil, nil
}
func (s *mockRBACStore) Initialize(_ context.Context) error { return nil }
func (s *mockRBACStore) Close() error                       { return nil }

// mockTenantStore implements business.TenantStore for testing
type mockTenantStore struct{}

func (s *mockTenantStore) CreateTenant(_ context.Context, _ *business.TenantData) error { return nil }
func (s *mockTenantStore) GetTenant(_ context.Context, tenantID string) (*business.TenantData, error) {
	return &business.TenantData{ID: tenantID, Name: "Test Tenant"}, nil
}
func (s *mockTenantStore) UpdateTenant(_ context.Context, _ *business.TenantData) error { return nil }
func (s *mockTenantStore) DeleteTenant(_ context.Context, _ string) error               { return nil }
func (s *mockTenantStore) ListTenants(_ context.Context, _ *business.TenantFilter) ([]*business.TenantData, error) {
	return nil, nil
}
func (s *mockTenantStore) GetTenantHierarchy(_ context.Context, tenantID string) (*business.TenantHierarchy, error) {
	return &business.TenantHierarchy{TenantID: tenantID}, nil
}
func (s *mockTenantStore) GetChildTenants(_ context.Context, _ string) ([]*business.TenantData, error) {
	return nil, nil
}
func (s *mockTenantStore) GetTenantPath(_ context.Context, tenantID string) ([]string, error) {
	return []string{tenantID}, nil
}
func (s *mockTenantStore) IsTenantAncestor(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}
func (s *mockTenantStore) Initialize(_ context.Context) error { return nil }
func (s *mockTenantStore) Close() error                       { return nil }

// mockRegistrationTokenStore implements business.RegistrationTokenStore for testing
type mockRegistrationTokenStore struct{}

func (s *mockRegistrationTokenStore) SaveToken(_ context.Context, _ *business.RegistrationTokenData) error {
	return nil
}
func (s *mockRegistrationTokenStore) GetToken(_ context.Context, tokenStr string) (*business.RegistrationTokenData, error) {
	return &business.RegistrationTokenData{Token: tokenStr, TenantID: "test-tenant"}, nil
}
func (s *mockRegistrationTokenStore) UpdateToken(_ context.Context, _ *business.RegistrationTokenData) error {
	return nil
}
func (s *mockRegistrationTokenStore) DeleteToken(_ context.Context, _ string) error {
	return nil
}
func (s *mockRegistrationTokenStore) ListTokens(_ context.Context, _ *business.RegistrationTokenFilter) ([]*business.RegistrationTokenData, error) {
	return nil, nil
}
func (s *mockRegistrationTokenStore) Initialize(_ context.Context) error { return nil }
func (s *mockRegistrationTokenStore) Close() error                       { return nil }
