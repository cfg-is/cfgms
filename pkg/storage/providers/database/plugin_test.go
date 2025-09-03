// Package database provides tests for PostgreSQL storage provider
package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "github.com/lib/pq" // PostgreSQL driver
)

// Test database configuration - requires PostgreSQL instance for full tests
var testDBConfig = map[string]interface{}{
	"host":     "localhost",
	"port":     5432,
	"database": "cfgms_test",
	"username": "cfgms_test",
	"password": "cfgms_test",
	"sslmode":  "disable",
}

// getTestDB returns a test database connection or skips if not available
func getTestDB(t *testing.T) *sql.DB {
	if testing.Short() {
		t.Skip("Skipping database tests in short mode")
	}
	
	// Check if test database is available
	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		testDBConfig["host"], testDBConfig["port"], testDBConfig["database"],
		testDBConfig["username"], testDBConfig["password"], testDBConfig["sslmode"])
	
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skip("PostgreSQL test database not available:", err)
	}
	
	if err := db.Ping(); err != nil {
		db.Close()
		t.Skip("PostgreSQL test database not reachable:", err)
	}
	
	return db
}

// setupTestDatabase creates a clean test database
func setupTestDatabase(t *testing.T) *sql.DB {
	db := getTestDB(t)
	
	// Clean up any existing tables
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	
	if err := schemas.DropAllTables(ctx, db); err != nil {
		// Ignore errors on cleanup
		_ = err
	}
	
	return db
}

func TestDatabaseProvider_Basic(t *testing.T) {
	provider := &DatabaseProvider{}
	
	// Test basic provider information
	assert.Equal(t, "database", provider.Name())
	assert.Contains(t, provider.Description(), "PostgreSQL")
	assert.NotEmpty(t, provider.GetVersion())
	
	capabilities := provider.GetCapabilities()
	assert.True(t, capabilities.SupportsTransactions)
	assert.True(t, capabilities.SupportsVersioning)
	assert.True(t, capabilities.SupportsFullTextSearch)
	assert.True(t, capabilities.SupportsReplication)
	assert.True(t, capabilities.SupportsSharding)
	assert.Greater(t, capabilities.MaxBatchSize, 0)
	assert.Greater(t, capabilities.MaxConfigSize, 0)
	assert.Greater(t, capabilities.MaxAuditRetentionDays, 0)
	
	// Test availability
	available, err := provider.Available()
	assert.True(t, available)
	assert.NoError(t, err)
}

func TestDatabaseProvider_CreateClientTenantStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}
	
	db := setupTestDatabase(t)
	defer db.Close()
	
	provider := &DatabaseProvider{}
	
	// Test creating client tenant store
	store, err := provider.CreateClientTenantStore(testDBConfig)
	require.NoError(t, err)
	require.NotNil(t, store)
	
	// Verify store implements interface
	_, ok := store.(interfaces.ClientTenantStore)
	assert.True(t, ok)
	
	// Clean up
	if dbStore, ok := store.(*DatabaseClientTenantStore); ok {
		dbStore.Close()
	}
}

func TestDatabaseProvider_CreateConfigStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}
	
	db := setupTestDatabase(t)
	defer db.Close()
	
	provider := &DatabaseProvider{}
	
	// Test creating config store
	store, err := provider.CreateConfigStore(testDBConfig)
	require.NoError(t, err)
	require.NotNil(t, store)
	
	// Verify store implements interface
	_, ok := store.(interfaces.ConfigStore)
	assert.True(t, ok)
	
	// Clean up
	if dbStore, ok := store.(*DatabaseConfigStore); ok {
		dbStore.Close()
	}
}

func TestDatabaseProvider_CreateAuditStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}
	
	db := setupTestDatabase(t)
	defer db.Close()
	
	provider := &DatabaseProvider{}
	
	// Test creating audit store
	store, err := provider.CreateAuditStore(testDBConfig)
	require.NoError(t, err)
	require.NotNil(t, store)
	
	// Verify store implements interface
	_, ok := store.(interfaces.AuditStore)
	assert.True(t, ok)
	
	// Clean up
	if dbStore, ok := store.(*DatabaseAuditStore); ok {
		dbStore.Close()
	}
}

func TestDatabaseProvider_DSNGeneration(t *testing.T) {
	provider := &DatabaseProvider{}
	
	tests := []struct {
		name     string
		config   map[string]interface{}
		expected string
		wantErr  bool
	}{
		{
			name: "Complete DSN provided",
			config: map[string]interface{}{
				"dsn": "postgres://user:pass@localhost/dbname?sslmode=require",
			},
			expected: "postgres://user:pass@localhost/dbname?sslmode=require",
			wantErr:  false,
		},
		{
			name: "Individual components",
			config: map[string]interface{}{
				"host":     "localhost",
				"port":     5432,
				"database": "cfgms",
				"username": "user",
				"password": "pass",
				"sslmode":  "require",
			},
			expected: "host=localhost port=5432 dbname=cfgms user=user password=pass sslmode=require",
			wantErr:  false,
		},
		{
			name: "Missing password",
			config: map[string]interface{}{
				"host":     "localhost",
				"username": "user",
			},
			expected: "",
			wantErr:  true,
		},
		{
			name: "With defaults",
			config: map[string]interface{}{
				"password": "testpass",
			},
			expected: "host=localhost port=5432 dbname=cfgms user=cfgms password=testpass sslmode=require",
			wantErr:  false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dsn, err := provider.getDSN(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, dsn)
		})
	}
}

func TestDatabaseSchemas_CreateTables(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}
	
	db := setupTestDatabase(t)
	defer db.Close()
	
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	
	// Test creating all tables
	err := schemas.CreateAllTables(ctx, db)
	require.NoError(t, err)
	
	// Verify tables exist
	tables := []string{
		"client_tenants",
		"admin_consent_requests",
		"configs",
		"config_history",
		"audit_entries",
		"storage_health",
	}
	
	for _, table := range tables {
		var exists bool
		query := `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`
		err := db.QueryRowContext(ctx, query, table).Scan(&exists)
		require.NoError(t, err)
		assert.True(t, exists, "Table %s should exist", table)
	}
	
	// Verify materialized view exists
	var viewExists bool
	viewQuery := `SELECT EXISTS (SELECT 1 FROM information_schema.views WHERE table_name = 'audit_stats')`
	err = db.QueryRowContext(ctx, viewQuery).Scan(&viewExists)
	require.NoError(t, err)
	assert.True(t, viewExists, "Materialized view audit_stats should exist")
}

func TestDatabaseClientTenantStore_CRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}
	
	db := setupTestDatabase(t)
	defer db.Close()
	
	store, err := NewDatabaseClientTenantStore("", testDBConfig)
	require.NoError(t, err)
	defer store.Close()
	
	// Create a test client tenant
	tenant := &interfaces.ClientTenant{
		TenantID:         "test-tenant-123",
		TenantName:       "Test Organization",
		DomainName:       "test.com",
		AdminEmail:       "admin@test.com",
		ConsentedAt:      time.Now(),
		Status:           interfaces.ClientTenantStatusActive,
		ClientIdentifier: "client-123",
		Metadata: map[string]interface{}{
			"region": "us-east-1",
			"plan":   "enterprise",
		},
	}
	
	// Test Store
	err = store.StoreClientTenant(tenant)
	require.NoError(t, err)
	
	// Test Get by tenant ID
	retrieved, err := store.GetClientTenant("test-tenant-123")
	require.NoError(t, err)
	assert.Equal(t, tenant.TenantID, retrieved.TenantID)
	assert.Equal(t, tenant.TenantName, retrieved.TenantName)
	assert.Equal(t, tenant.Status, retrieved.Status)
	assert.Equal(t, tenant.Metadata["region"], retrieved.Metadata["region"])
	
	// Test Get by client identifier
	byIdentifier, err := store.GetClientTenantByIdentifier("client-123")
	require.NoError(t, err)
	assert.Equal(t, tenant.TenantID, byIdentifier.TenantID)
	
	// Test List all tenants
	allTenants, err := store.ListClientTenants("")
	require.NoError(t, err)
	assert.Len(t, allTenants, 1)
	
	// Test List by status
	activeTenants, err := store.ListClientTenants(interfaces.ClientTenantStatusActive)
	require.NoError(t, err)
	assert.Len(t, activeTenants, 1)
	
	pendingTenants, err := store.ListClientTenants(interfaces.ClientTenantStatusPending)
	require.NoError(t, err)
	assert.Len(t, pendingTenants, 0)
	
	// Test Update status
	err = store.UpdateClientTenantStatus("test-tenant-123", interfaces.ClientTenantStatusSuspended)
	require.NoError(t, err)
	
	updated, err := store.GetClientTenant("test-tenant-123")
	require.NoError(t, err)
	assert.Equal(t, interfaces.ClientTenantStatusSuspended, updated.Status)
	
	// Test Delete
	err = store.DeleteClientTenant("test-tenant-123")
	require.NoError(t, err)
	
	_, err = store.GetClientTenant("test-tenant-123")
	assert.Error(t, err)
}

func TestDatabaseClientTenantStore_AdminConsent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}
	
	db := setupTestDatabase(t)
	defer db.Close()
	
	store, err := NewDatabaseClientTenantStore("", testDBConfig)
	require.NoError(t, err)
	defer store.Close()
	
	// Create a test admin consent request
	request := &interfaces.AdminConsentRequest{
		ClientIdentifier: "client-456",
		ClientName:       "Test Client",
		RequestedBy:      "admin@msp.com",
		State:            "test-state-789",
		ExpiresAt:        time.Now().Add(1 * time.Hour),
		Metadata: map[string]interface{}{
			"flow": "delegated",
		},
	}
	
	// Test Store
	err = store.StoreAdminConsentRequest(request)
	require.NoError(t, err)
	
	// Test Get
	retrieved, err := store.GetAdminConsentRequest("test-state-789")
	require.NoError(t, err)
	assert.Equal(t, request.ClientIdentifier, retrieved.ClientIdentifier)
	assert.Equal(t, request.State, retrieved.State)
	assert.Equal(t, request.Metadata["flow"], retrieved.Metadata["flow"])
	
	// Test Delete
	err = store.DeleteAdminConsentRequest("test-state-789")
	require.NoError(t, err)
	
	_, err = store.GetAdminConsentRequest("test-state-789")
	assert.Error(t, err)
}

func TestDatabaseProvider_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}
	
	// Skip if DATABASE_URL is not set (CI/CD environments)
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}
	
	db := setupTestDatabase(t)
	defer db.Close()
	
	// Test provider registration
	providerNames := interfaces.GetRegisteredProviderNames()
	assert.Contains(t, providerNames, "database")
	
	// Test getting the provider
	provider, err := interfaces.GetStorageProvider("database")
	require.NoError(t, err)
	assert.NotNil(t, provider)
	
	// Test creating storage manager
	storageManager, err := interfaces.CreateAllStoresFromConfig("database", testDBConfig)
	require.NoError(t, err)
	require.NotNil(t, storageManager)
	
	assert.Equal(t, "database", storageManager.GetProviderName())
	assert.NotNil(t, storageManager.GetClientTenantStore())
	assert.NotNil(t, storageManager.GetConfigStore())
	assert.NotNil(t, storageManager.GetAuditStore())
	
	capabilities := storageManager.GetCapabilities()
	assert.True(t, capabilities.SupportsTransactions)
}

func TestDatabaseProvider_ErrorHandling(t *testing.T) {
	provider := &DatabaseProvider{}
	
	// Test invalid DSN
	invalidConfig := map[string]interface{}{
		"dsn": "invalid://connection/string",
	}
	
	_, err := provider.CreateClientTenantStore(invalidConfig)
	assert.Error(t, err)
	
	_, err = provider.CreateConfigStore(invalidConfig)
	assert.Error(t, err)
	
	_, err = provider.CreateAuditStore(invalidConfig)
	assert.Error(t, err)
	
	// Test missing password
	missingPasswordConfig := map[string]interface{}{
		"host":     "localhost",
		"username": "test",
	}
	
	_, err = provider.CreateClientTenantStore(missingPasswordConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password is required")
}

func TestUtilityFunctions(t *testing.T) {
	// Test getStringFromConfig
	config := map[string]interface{}{
		"string_val":  "test",
		"int_val":     123,
		"missing_val": nil,
	}
	
	assert.Equal(t, "test", getStringFromConfig(config, "string_val", "default"))
	assert.Equal(t, "default", getStringFromConfig(config, "missing_val", "default"))
	assert.Equal(t, "default", getStringFromConfig(config, "nonexistent", "default"))
	
	// Test getIntFromConfig
	assert.Equal(t, 123, getIntFromConfig(config, "int_val", 0))
	assert.Equal(t, 456, getIntFromConfig(config, "missing_val", 456))
	
	// Test getBoolFromConfig
	boolConfig := map[string]interface{}{
		"bool_val": true,
	}
	assert.True(t, getBoolFromConfig(boolConfig, "bool_val", false))
	assert.False(t, getBoolFromConfig(boolConfig, "missing_val", false))
}

// Benchmarks for performance testing

func BenchmarkDatabaseProvider_CreateStores(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}
	
	provider := &DatabaseProvider{}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store, err := provider.CreateClientTenantStore(testDBConfig)
		if err == nil && store != nil {
			if dbStore, ok := store.(*DatabaseClientTenantStore); ok {
				dbStore.Close()
			}
		}
	}
}

// Helper function to check if PostgreSQL is available for tests
// Note: Cannot use testing.Short() in init() as it's called before flag parsing