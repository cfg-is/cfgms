// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides tests for PostgreSQL storage provider
package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/testutil"
)

func TestDatabaseProvider_ClusterCapable_True(t *testing.T) {
	p := &DatabaseProvider{}
	assert.True(t, p.ClusterCapable(), "DatabaseProvider must be cluster-capable (Postgres supports shared state across controller nodes)")
}

// getTestConfig returns test database configuration using environment variables or defaults
func getTestConfig() map[string]interface{} {
	password := testutil.GetTestDBPassword()

	port := 5432
	if portStr := os.Getenv("CFGMS_TEST_DB_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	return map[string]interface{}{
		"host":     "localhost",
		"port":     port,
		"database": "cfgms_test",
		"username": "cfgms_test",
		"password": password,
		"sslmode":  "disable",
		// The database session store refuses to start without an HMAC key, by
		// design — a session token signed with a predictable key is forgeable. The
		// key is generated per run rather than written here as a constant: a
		// checked-in key is a hardcoded secret regardless of it being "only a test",
		// and the store cannot tell the difference. This omission was invisible
		// until Issue #3872 first ran this package against a real Postgres.
		"session_hmac_key": newTestSessionHMACKey(),
	}
}

// newTestSessionHMACKey returns a fresh 32-byte random key, hex-encoded. It panics
// rather than returning an error: a test config that silently degrades to a weak or
// empty key would let the session store's own guard pass for the wrong reason.
func newTestSessionHMACKey() string {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Sprintf("generating test session HMAC key: %v", err))
	}
	return hex.EncodeToString(key)
}

// getTestDB returns a test database connection or skips if not available
func getTestDB(t *testing.T) *sql.DB {
	if testing.Short() {
		t.Skip("Skipping database tests in short mode")
	}

	// Get fresh config each time to pick up environment variables
	testDBConfig := getTestConfig()

	// Check if test database is available
	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		testDBConfig["host"], testDBConfig["port"], testDBConfig["database"],
		testDBConfig["username"], testDBConfig["password"], testDBConfig["sslmode"])

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skip("PostgreSQL test database not available:", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
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

	// Every statement in DropAllTables uses IF EXISTS, so an absent table is not
	// an error. Any failure here (locks, permissions, lost connection) leaves the
	// database dirty and makes every later test fail with a misleading
	// "already exists"; surface it as the real root cause instead.
	require.NoError(t, schemas.DropAllTables(ctx, db), "failed to drop existing test tables")

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
	defer func() { _ = db.Close() }()

	provider := &DatabaseProvider{}
	t.Cleanup(func() { _ = provider.Close() })

	// Test creating client tenant store
	store, err := provider.CreateClientTenantStore(getTestConfig())
	require.NoError(t, err)
	require.NotNil(t, store)

	// Verify store is not nil - interface compliance verified at compile time
	assert.NotNil(t, store)
}

func TestDatabaseProvider_CreateConfigStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	provider := &DatabaseProvider{}
	t.Cleanup(func() { _ = provider.Close() })

	// Test creating config store
	store, err := provider.CreateConfigStore(getTestConfig())
	require.NoError(t, err)
	require.NotNil(t, store)

	// Verify store is not nil - interface compliance verified at compile time
	assert.NotNil(t, store)
}

func TestDatabaseProvider_CreateAuditStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	provider := &DatabaseProvider{}
	t.Cleanup(func() { _ = provider.Close() })

	// Test creating audit store
	store, err := provider.CreateAuditStore(getTestConfig())
	require.NoError(t, err)
	require.NotNil(t, store)

	// Verify store is not nil - interface compliance verified at compile time
	assert.NotNil(t, store)
}

// TestDatabaseProvider_CreatePendingRegistrationStore verifies that the provider
// returns a working Postgres-backed store instead of ErrNotSupported (Issue #3401).
// A working store means GET /api/v1/registration/pending returns 200, not 503 —
// the handler guards on a nil pendingStore, which only arises when the constructor
// returns ErrNotSupported.
func TestDatabaseProvider_CreatePendingRegistrationStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	provider := &DatabaseProvider{}
	t.Cleanup(func() { _ = provider.Close() })

	store, err := provider.CreatePendingRegistrationStore(getTestConfig())
	require.NoError(t, err, "CreatePendingRegistrationStore must not return ErrNotSupported")
	require.NotNil(t, store, "CreatePendingRegistrationStore must return a non-nil store")

	// Confirm the store is functional: ListPending on an empty table returns
	// without error — the same path a cluster-mode controller takes when the
	// endpoint is first hit. ListPending accumulates rows with append, so an
	// empty table yields a nil slice; assert.Empty accepts both nil and empty.
	entries, err := store.ListPending(context.Background(), "")
	require.NoError(t, err)
	assert.Empty(t, entries)
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
	defer func() { _ = db.Close() }()

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
		"cfgms_ip_trust_ranges",
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
	viewQuery := `SELECT EXISTS (SELECT 1 FROM pg_matviews WHERE matviewname = 'audit_stats')`
	err = db.QueryRowContext(ctx, viewQuery).Scan(&viewExists)
	require.NoError(t, err)
	assert.True(t, viewExists, "Materialized view audit_stats should exist")
}

func TestDatabaseClientTenantStore_CRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	store, err := NewDatabaseClientTenantStore(db, getTestConfig())
	require.NoError(t, err)

	// Create a test client tenant
	tenant := &business.ClientTenant{
		TenantID:         "test-tenant-123",
		TenantName:       "Test Organization",
		DomainName:       "test.com",
		AdminEmail:       "admin@test.com",
		ConsentedAt:      time.Now(),
		Status:           business.ClientTenantStatusActive,
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
	activeTenants, err := store.ListClientTenants(business.ClientTenantStatusActive)
	require.NoError(t, err)
	assert.Len(t, activeTenants, 1)

	pendingTenants, err := store.ListClientTenants(business.ClientTenantStatusPending)
	require.NoError(t, err)
	assert.Len(t, pendingTenants, 0)

	// Test Update status
	err = store.UpdateClientTenantStatus("test-tenant-123", business.ClientTenantStatusSuspended)
	require.NoError(t, err)

	updated, err := store.GetClientTenant("test-tenant-123")
	require.NoError(t, err)
	assert.Equal(t, business.ClientTenantStatusSuspended, updated.Status)

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
	defer func() { _ = db.Close() }()

	store, err := NewDatabaseClientTenantStore(db, getTestConfig())
	require.NoError(t, err)

	// Create a test admin consent request
	request := &business.AdminConsentRequest{
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

func TestDatabaseProvider_ErrorHandling(t *testing.T) {
	provider := &DatabaseProvider{}
	t.Cleanup(func() { _ = provider.Close() })

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

	_, err = provider.CreatePendingRegistrationStore(invalidConfig)
	assert.Error(t, err, "CreatePendingRegistrationStore must propagate DSN errors")

	_, err = provider.CreateTriggerStore(invalidConfig)
	assert.Error(t, err, "CreateTriggerStore must propagate DSN errors")

	_, err = provider.CreatePushStore(invalidConfig)
	assert.Error(t, err, "CreatePushStore must propagate DSN errors")

	// Test missing password
	missingPasswordConfig := map[string]interface{}{
		"host":     "localhost",
		"username": "test",
	}

	_, err = provider.CreateClientTenantStore(missingPasswordConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password is required")

	_, err = provider.CreatePendingRegistrationStore(missingPasswordConfig)
	assert.Error(t, err, "CreatePendingRegistrationStore must propagate missing-password errors")
	assert.Contains(t, err.Error(), "password is required")

	_, err = provider.CreateTriggerStore(missingPasswordConfig)
	assert.Error(t, err, "CreateTriggerStore must propagate missing-password errors")
	assert.Contains(t, err.Error(), "password is required")

	_, err = provider.CreatePushStore(missingPasswordConfig)
	assert.Error(t, err, "CreatePushStore must propagate missing-password errors")
	assert.Contains(t, err.Error(), "password is required")
}

// TestDatabaseProvider_SharedPool_Identity is the [REQUIRED TEST] for Issue #3758
// / ADR-031 Decision 6: every store created from one DatabaseProvider instance
// must share the exact same underlying *sql.DB — not merely behave the same way.
// Pointer identity (assert.Same) is the only assertion that actually proves a
// single shared pool rather than N independently-opened pools that happen to
// point at the same database.
func TestDatabaseProvider_SharedPool_Identity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	provider := &DatabaseProvider{}
	t.Cleanup(func() { _ = provider.Close() })

	config := getTestConfig()
	config["session_hmac_key"] = "test-hmac-key-for-shared-pool-identity-test-32b"

	clientTenantStore, err := provider.CreateClientTenantStore(config)
	require.NoError(t, err)
	configStore, err := provider.CreateConfigStore(config)
	require.NoError(t, err)
	auditStore, err := provider.CreateAuditStore(config)
	require.NoError(t, err)
	rbacStore, err := provider.CreateRBACStore(config)
	require.NoError(t, err)
	tenantStore, err := provider.CreateTenantStore(config)
	require.NoError(t, err)
	sessionStore, err := provider.CreateSessionStore(config)
	require.NoError(t, err)
	caseStore, err := provider.CreateCaseStore(config)
	require.NoError(t, err)
	nonceStore, err := provider.CreateNonceStore(config)
	require.NoError(t, err)
	leaseStore, err := provider.CreateLeaseStore(config)
	require.NoError(t, err)

	pool, err := provider.sharedPool(config)
	require.NoError(t, err)
	require.NotNil(t, pool)

	assert.Same(t, pool, clientTenantStore.(*DatabaseClientTenantStore).db, "ClientTenantStore must share the provider's pool")
	assert.Same(t, pool, configStore.(*DatabaseConfigStore).db, "ConfigStore must share the provider's pool")
	assert.Same(t, pool, auditStore.(*DatabaseAuditStore).db, "AuditStore must share the provider's pool")
	assert.Same(t, pool, rbacStore.(*DatabaseRBACStore).db, "RBACStore must share the provider's pool")
	assert.Same(t, pool, tenantStore.(*DatabaseTenantStore).db, "TenantStore must share the provider's pool")
	assert.Same(t, pool, sessionStore.(*DatabaseSessionStore).db, "SessionStore must share the provider's pool")
	assert.Same(t, pool, caseStore.(*DatabaseCaseStore).db, "CaseStore must share the provider's pool")
	assert.Same(t, pool, nonceStore.(*DatabaseNonceStore).db, "NonceStore must share the provider's pool")
	assert.Same(t, pool, leaseStore.(*DatabaseLeaseStore).db, "LeaseStore must share the provider's pool")
}

// TestDatabaseProvider_SharedPool_DivergentDSNDoesNotReusePool covers the
// singleton footgun: interfaces.RegisterStorageProvider registers ONE
// DatabaseProvider for the process, and GetStorageProvider hands that same
// pointer to every consumer, so two operator-set connection strings
// (storage.cluster.postgres_dsn via CreateClusterStorageManager, storage.config.dsn
// via the SOPS secret store, and the separate operational/configuration maps of
// NewHybridStorageManager) reach the same instance. A caller asking for DSN B
// must never be handed the pool opened for DSN A — that silently redirects its
// writes to another database under another set of credentials and sslmode.
//
// No live PostgreSQL is needed: sql.Open does not dial, so the pre-seeded entry
// is a real *sql.DB handle, and the divergent DSN's open attempt fails fast
// against a closed port instead of being answered from the cache.
func TestDatabaseProvider_SharedPool_DivergentDSNDoesNotReusePool(t *testing.T) {
	provider := &DatabaseProvider{}
	t.Cleanup(func() { _ = provider.Close() })

	const firstDSN = "host=127.0.0.1 port=1 dbname=cluster_db user=cluster_user password=cluster-secret sslmode=disable"

	// Seed the provider as if CreateClusterStorageManager had already opened a
	// pool for firstDSN (sql.Open is lazy, so no server is contacted).
	seeded, err := sql.Open("postgres", firstDSN)
	require.NoError(t, err)
	provider.poolMu.Lock()
	provider.pools = map[string]*sql.DB{firstDSN: seeded}
	provider.poolMu.Unlock()

	// The same DSN keeps sharing the one pool (ADR-031 Decision 6).
	same, err := provider.sharedPool(map[string]interface{}{"dsn": firstDSN})
	require.NoError(t, err)
	assert.Same(t, seeded, same, "an identical DSN must reuse the already-open pool")

	// A different target database, credentials and sslmode must NOT be answered
	// from the existing pool.
	const secondDSN = "host=127.0.0.1 port=1 dbname=secrets_db user=secrets_user password=secrets-secret sslmode=require"
	other, err := provider.sharedPool(map[string]interface{}{"dsn": secondDSN})
	require.Error(t, err, "a divergent DSN must not silently reuse another DSN's pool")
	assert.Nil(t, other)
	assert.NotContains(t, err.Error(), "secrets-secret", "error must not disclose credentials")
	assert.NotContains(t, err.Error(), "cluster-secret", "error must not disclose credentials")

	// The divergent call must not have replaced or evicted the existing pool.
	still, err := provider.sharedPool(map[string]interface{}{"dsn": firstDSN})
	require.NoError(t, err)
	assert.Same(t, seeded, still, "a failed open for another DSN must leave the existing pool intact")
}

// TestDatabaseProvider_SharedPool_ComponentConfigDivergenceIsNotReused proves the
// same fail-safe for configs built from individual host/database/username/password/
// sslmode keys rather than a literal "dsn" string — the shape
// NewHybridStorageManager passes for its operational and configuration backends.
func TestDatabaseProvider_SharedPool_ComponentConfigDivergenceIsNotReused(t *testing.T) {
	provider := &DatabaseProvider{}
	t.Cleanup(func() { _ = provider.Close() })

	operational := map[string]interface{}{
		"host": "127.0.0.1", "port": 1, "database": "operational_db",
		"username": "op_user", "password": "op-secret", "sslmode": "disable",
	}
	configuration := map[string]interface{}{
		"host": "127.0.0.1", "port": 1, "database": "configuration_db",
		"username": "cfg_user", "password": "cfg-secret", "sslmode": "require",
	}

	operationalDSN, err := provider.getDSN(operational)
	require.NoError(t, err)
	configurationDSN, err := provider.getDSN(configuration)
	require.NoError(t, err)
	require.NotEqual(t, operationalDSN, configurationDSN)

	seeded, err := sql.Open("postgres", operationalDSN)
	require.NoError(t, err)
	provider.poolMu.Lock()
	provider.pools = map[string]*sql.DB{operationalDSN: seeded}
	provider.poolMu.Unlock()

	store, err := provider.CreateConfigStore(configuration)
	require.Error(t, err, "the configuration backend must not be handed the operational backend's pool")
	assert.Nil(t, store)
	assert.NotContains(t, err.Error(), "cfg-secret", "error must not disclose credentials")
	assert.NotContains(t, err.Error(), "op-secret", "error must not disclose credentials")
}

// TestDatabaseProvider_Close_ClosesEveryPool proves Close releases all pools the
// provider opened, not just one, and stays idempotent.
func TestDatabaseProvider_Close_ClosesEveryPool(t *testing.T) {
	provider := &DatabaseProvider{}

	first, err := sql.Open("postgres", "host=127.0.0.1 port=1 dbname=a user=u password=p sslmode=disable")
	require.NoError(t, err)
	second, err := sql.Open("postgres", "host=127.0.0.1 port=1 dbname=b user=u password=p sslmode=disable")
	require.NoError(t, err)

	provider.poolMu.Lock()
	provider.pools = map[string]*sql.DB{
		"host=127.0.0.1 port=1 dbname=a user=u password=p sslmode=disable": first,
		"host=127.0.0.1 port=1 dbname=b user=u password=p sslmode=disable": second,
	}
	provider.poolMu.Unlock()

	require.NoError(t, provider.Close())
	require.NoError(t, provider.Close(), "Close must be idempotent")

	// A closed *sql.DB reports "sql: database is closed" for any use; an open one
	// pointed at a dead port would report a dial error instead, so this
	// distinguishes "closed" from "unreachable".
	assert.EqualError(t, first.Ping(), "sql: database is closed", "first pool must be closed")
	assert.EqualError(t, second.Ping(), "sql: database is closed", "second pool must be closed")
}

// TestDatabaseProvider_SharedPool_OpensOnce proves sharedPool itself opens the
// underlying connection exactly once per DSN: a second call carrying different
// pool-sizing values but the same connection string returns the same pool
// rather than opening a second one.
func TestDatabaseProvider_SharedPool_OpensOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	provider := &DatabaseProvider{}
	t.Cleanup(func() { _ = provider.Close() })

	pool1, err := provider.sharedPool(getTestConfig())
	require.NoError(t, err)

	// A second call, even with a config carrying different pool-sizing values,
	// must reuse the already-open pool rather than opening a new one.
	secondConfig := getTestConfig()
	secondConfig["max_open_connections"] = 5
	pool2, err := provider.sharedPool(secondConfig)
	require.NoError(t, err)

	assert.Same(t, pool1, pool2, "a second sharedPool call must reuse the already-open pool")
}

// TestDatabaseProvider_SharedPool_ConcurrentCreateIsRaceFree exercises the
// poolMu-guarded lazy-open path from many goroutines at once, proving the
// provider never opens more than one pool under concurrent CreateXStore calls
// (the shape every real caller — CreateClusterStorageManager,
// NewHybridStorageManager — uses when wiring up a controller node).
func TestDatabaseProvider_SharedPool_ConcurrentCreateIsRaceFree(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	provider := &DatabaseProvider{}
	t.Cleanup(func() { _ = provider.Close() })

	config := getTestConfig()

	const concurrency = 10
	pools := make([]*sql.DB, concurrency)
	errs := make([]error, concurrency)

	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(i int) {
			defer wg.Done()
			pools[i], errs[i] = provider.sharedPool(config)
		}(i)
	}
	wg.Wait()

	for i := 0; i < concurrency; i++ {
		require.NoError(t, errs[i])
		assert.Same(t, pools[0], pools[i], "every concurrent caller must observe the same shared pool")
	}
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
	b.Cleanup(func() { _ = provider.Close() })

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = provider.CreateClientTenantStore(getTestConfig())
	}
}

// Helper function to check if PostgreSQL is available for tests
// Note: Cannot use testing.Short() in init() as it's called before flag parsing
