// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements production-ready PostgreSQL storage provider for CFGMS
// Provides database-based storage with ACID transactions, connection pooling, and performance optimization
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// DatabaseProvider implements the StorageProvider interface using PostgreSQL for persistence.
//
// CreateXStore methods that resolve to the same connection string share a single
// underlying *sql.DB connection pool (ADR-031 Decision 6), replacing the earlier
// design where every store opened and sized its own pool. A pool is opened lazily
// on the first CreateXStore call for a given DSN and sized from that call's config;
// later calls resolving to the same DSN reuse it regardless of their own config's
// pool-sizing settings.
//
// Pools are keyed by resolved DSN rather than one-per-provider because the
// provider registry hands the same DatabaseProvider instance to every consumer
// in the process (see RegisterStorageProvider/GetStorageProvider), and distinct
// operator-set connection strings do reach it — storage.cluster.postgres_dsn via
// CreateClusterStorageManager, storage.config.dsn via the SOPS secret store, and
// the separate operational/configuration maps of NewHybridStorageManager. Reusing
// a pool opened from one DSN for a caller that asked for another would silently
// discard that caller's target database, credentials and sslmode, so a divergent
// DSN always gets its own pool.
type DatabaseProvider struct {
	poolMu sync.Mutex
	// pools maps a resolved DSN to the pool opened for it. Never reuse an entry
	// for a DSN that is not byte-identical to its key.
	pools map[string]*sql.DB
}

// Compile-time assertions. The optional store-creator extensions are wired by
// CreateClusterStorageManager through a type assertion, so a missing method is
// not a compile error at the call site — it silently leaves the store nil and
// the dependent endpoints answering 503 (Issue #3755, and #3401 before it).
// These assertions turn that class of regression back into a build failure.
var (
	_ interfaces.StorageProvider            = (*DatabaseProvider)(nil)
	_ interfaces.NonceStoreCreator          = (*DatabaseProvider)(nil)
	_ interfaces.LeaseStoreCreator          = (*DatabaseProvider)(nil)
	_ interfaces.RoutingStoreCreator        = (*DatabaseProvider)(nil)
	_ interfaces.CertRevocationStoreCreator = (*DatabaseProvider)(nil)
	_ interfaces.SigningCursorStoreCreator  = (*DatabaseProvider)(nil)
)

// Name returns the provider name
func (p *DatabaseProvider) Name() string {
	return "database"
}

// Description returns a human-readable description
func (p *DatabaseProvider) Description() string {
	return "Production PostgreSQL storage with ACID transactions, connection pooling, and performance optimization"
}

// GetVersion returns the provider version
func (p *DatabaseProvider) GetVersion() string {
	return "1.0.0"
}

// GetCapabilities returns the provider's capabilities
func (p *DatabaseProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{
		SupportsTransactions:   true,             // Full ACID transaction support
		SupportsVersioning:     true,             // Version tracking in database
		SupportsFullTextSearch: true,             // PostgreSQL full-text search
		SupportsEncryption:     false,            // Database-level encryption (TDE)
		SupportsCompression:    false,            // Database-level compression
		SupportsReplication:    true,             // PostgreSQL replication
		SupportsSharding:       true,             // Database partitioning/sharding
		MaxBatchSize:           1000,             // Optimal batch size for PostgreSQL
		MaxConfigSize:          50 * 1024 * 1024, // 50MB per config (PostgreSQL TOAST)
		MaxAuditRetentionDays:  7300,             // 20 years with database partitioning
	}
}

// ClusterCapable returns true if this provider can serve as shared state across
// multiple CFGMS controller nodes in cluster mode.
func (p *DatabaseProvider) ClusterCapable() bool { return true }

// Available checks if PostgreSQL is available and accessible
func (p *DatabaseProvider) Available() (bool, error) {
	// Assumes PostgreSQL driver is available; live connection ping is deferred.
	return true, nil
}

// CreateClientTenantStore creates a database-based client tenant store
func (p *DatabaseProvider) CreateClientTenantStore(config map[string]interface{}) (business.ClientTenantStore, error) {
	// Get the provider's shared connection pool
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	// Create the database client tenant store
	store, err := NewDatabaseClientTenantStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database client tenant store: %w", err)
	}

	return store, nil
}

// CreateConfigStore creates a database-based configuration store
func (p *DatabaseProvider) CreateConfigStore(config map[string]interface{}) (cfgconfig.ConfigStore, error) {
	// Get the provider's shared connection pool
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	// Create the database config store
	store, err := NewDatabaseConfigStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database config store: %w", err)
	}

	return store, nil
}

// CreateAuditStore creates a database-based audit store
func (p *DatabaseProvider) CreateAuditStore(config map[string]interface{}) (business.AuditStore, error) {
	// Get the provider's shared connection pool
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	// Create the database audit store
	store, err := NewDatabaseAuditStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database audit store: %w", err)
	}

	return store, nil
}

func (p *DatabaseProvider) CreateRBACStore(config map[string]interface{}) (business.RBACStore, error) {
	// Get the provider's shared connection pool
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	// Create the database RBAC store
	store, err := NewDatabaseRBACStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database RBAC store: %w", err)
	}

	return store, nil
}

func (p *DatabaseProvider) CreateTenantStore(config map[string]interface{}) (business.TenantStore, error) {
	// Get the provider's shared connection pool
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	// Create the database tenant store
	store, err := NewDatabaseTenantStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database tenant store: %w", err)
	}

	return store, nil
}

// CreateSessionStore creates a PostgreSQL-backed SessionStore.
// Bearer tokens are stored as HMAC-SHA256 hashes; plaintext tokens are never written to the DB.
// RLS is enforced by setting app.current_tenant per transaction in the store layer.
func (p *DatabaseProvider) CreateSessionStore(config map[string]interface{}) (business.SessionStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseSessionStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database session store: %w", err)
	}
	return store, nil
}

// CreateSessionTokenStore creates a PostgreSQL-backed pkg/session.Store for use by
// session.Manager in cluster mode (Issue #2775). The store keys on the pre-hashed
// SHA-256 hex token hash provided by session.Manager — the raw token is never stored.
// config["dsn"] or the individual host/port/database/username/password/sslmode keys
// are used to open the connection, matching the convention of CreateSessionStore.
func (p *DatabaseProvider) CreateSessionTokenStore(config map[string]interface{}) (*DatabaseSessionTokenStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseSessionTokenStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database session token store: %w", err)
	}
	return store, nil
}

// CreateStewardStore creates a PostgreSQL-backed StewardStore with tenant-scoped RLS.
func (p *DatabaseProvider) CreateStewardStore(config map[string]interface{}) (business.StewardStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseStewardStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database steward store: %w", err)
	}
	return store, nil
}

// CreateCommandStore creates a PostgreSQL-backed CommandStore with tenant-scoped RLS.
func (p *DatabaseProvider) CreateCommandStore(config map[string]interface{}) (business.CommandStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseCommandStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database command store: %w", err)
	}
	return store, nil
}

// CreateTriggerStore creates a PostgreSQL-backed TriggerStore (Issue #3402).
func (p *DatabaseProvider) CreateTriggerStore(config map[string]interface{}) (business.TriggerStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseTriggerStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database trigger store: %w", err)
	}
	return store, nil
}

// CreatePushStore creates a PostgreSQL-backed PushStore (Issue #3402).
// The push store gives resumePendingPushes a durable record to read in cluster
// mode, enabling failover replay of in-flight configuration pushes.
func (p *DatabaseProvider) CreatePushStore(config map[string]interface{}) (business.PushStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabasePushStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database push store: %w", err)
	}
	return store, nil
}

// CreatePendingRegistrationStore creates a PostgreSQL-backed PendingRegistrationStore (Issue #3401).
func (p *DatabaseProvider) CreatePendingRegistrationStore(config map[string]interface{}) (business.PendingRegistrationStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabasePendingRegistrationStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database pending registration store: %w", err)
	}
	return store, nil
}

// CreateRefreshPolicyStore creates a PostgreSQL-backed RefreshPolicyStore (Issue #2329).
func (p *DatabaseProvider) CreateRefreshPolicyStore(config map[string]interface{}) (business.RefreshPolicyStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseRefreshPolicyStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database refresh policy store: %w", err)
	}
	return store, nil
}

// CreateAssurancePolicyStore creates a PostgreSQL-backed AssurancePolicyStore (Issue #2845).
func (p *DatabaseProvider) CreateAssurancePolicyStore(config map[string]interface{}) (business.AssurancePolicyStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseAssurancePolicyStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database assurance policy store: %w", err)
	}
	return store, nil
}

// CreateTenantCrossingStore creates a PostgreSQL-backed TenantCrossingStore (ADR-025 Decision 2).
func (p *DatabaseProvider) CreateTenantCrossingStore(config map[string]interface{}) (business.TenantCrossingStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseTenantCrossingStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database tenant crossing store: %w", err)
	}
	return store, nil
}

// CreateCaseStore creates a PostgreSQL-backed CaseStore (ADR-022 §8, Issue #3602).
func (p *DatabaseProvider) CreateCaseStore(config map[string]interface{}) (business.CaseStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseCaseStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database case store: %w", err)
	}
	return store, nil
}

// CreateNonceStore creates a PostgreSQL-backed NonceStore (Issue #3755, ADR-031
// amendment to ADR-011). Implements interfaces.NonceStoreCreator, which is what
// CreateClusterStorageManager type-asserts on to wire the durable nonce store:
// without this method the cluster (multi-node Postgres) deployment runs with a
// nil nonce store and every registration-refresh endpoint answers 503.
func (p *DatabaseProvider) CreateNonceStore(config map[string]interface{}) (business.NonceStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseNonceStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database nonce store: %w", err)
	}
	return store, nil
}

// CreateLeaseStore creates a PostgreSQL-backed LeaseStore — the fenced,
// quorum-equivalent singleton-claim primitive (ADR-031 Decision 5, Issue #3756).
// Implements interfaces.LeaseStoreCreator.
func (p *DatabaseProvider) CreateLeaseStore(config map[string]interface{}) (business.LeaseStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseLeaseStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database lease store: %w", err)
	}
	return store, nil
}

// CreateRoutingStore creates a PostgreSQL-backed RoutingStore — the shared
// steward-routing table (ADR-031 Decision 3, Issue #3764).
// Implements interfaces.RoutingStoreCreator.
func (p *DatabaseProvider) CreateRoutingStore(config map[string]interface{}) (business.RoutingStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseRoutingStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database routing store: %w", err)
	}
	return store, nil
}

// CreateCertRevocationStore creates a PostgreSQL-backed CertRevocationStore
// (ADR-031 Decision 1, Issue #3852: pkg/cert's revocation list must be
// cluster-visible). Implements interfaces.CertRevocationStoreCreator.
func (p *DatabaseProvider) CreateCertRevocationStore(config map[string]interface{}) (certinterfaces.RevocationStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseCertRevocationStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database cert revocation store: %w", err)
	}
	return store, nil
}

// CreateSigningCursorStore creates a PostgreSQL-backed SigningCursorStore
// (ADR-031 Decision 1, Issue #3852: the config-signing rotation cursor must
// be cluster-visible). Implements interfaces.SigningCursorStoreCreator.
func (p *DatabaseProvider) CreateSigningCursorStore(config map[string]interface{}) (certinterfaces.SigningCursorStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseSigningCursorStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database signing cursor store: %w", err)
	}
	return store, nil
}

// CreatePendingRefreshStore creates a PostgreSQL-backed PendingRefreshStore (Issue #2329).
func (p *DatabaseProvider) CreatePendingRefreshStore(config map[string]interface{}) (business.PendingRefreshStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabasePendingRefreshStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database pending refresh store: %w", err)
	}
	return store, nil
}

// CreateIPTrustStore creates a PostgreSQL-backed IPTrustStore.
func (p *DatabaseProvider) CreateIPTrustStore(config map[string]interface{}) (business.IPTrustStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseIPTrustStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database ip trust store: %w", err)
	}
	return store, nil
}

// CreateAlertStore creates a PostgreSQL-backed AlertStore.
func (p *DatabaseProvider) CreateAlertStore(config map[string]interface{}) (business.AlertStore, error) {
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}
	store, err := NewDatabaseAlertStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database alert store: %w", err)
	}
	return store, nil
}

func (p *DatabaseProvider) CreateRegistrationTokenStore(config map[string]interface{}) (business.RegistrationTokenStore, error) {
	// Get the provider's shared connection pool
	db, err := p.sharedPool(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	// Create the database registration token store
	store, err := NewDatabaseRegistrationTokenStore(db, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database registration token store: %w", err)
	}

	return store, nil
}

// getDSN extracts and validates the database connection string from configuration
func (p *DatabaseProvider) getDSN(config map[string]interface{}) (string, error) {
	// First, try to get a complete DSN
	if dsn, ok := config["dsn"].(string); ok && dsn != "" {
		return dsn, nil
	}

	// Otherwise, build DSN from individual components
	host := getStringFromConfig(config, "host", "localhost")
	port := getIntFromConfig(config, "port", 5432)
	database := getStringFromConfig(config, "database", "cfgms")
	username := getStringFromConfig(config, "username", "cfgms")
	password := getStringFromConfig(config, "password", "")
	sslmode := getStringFromConfig(config, "sslmode", "require")

	if password == "" {
		return "", fmt.Errorf("database password is required")
	}

	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		host, port, database, username, password, sslmode)

	return dsn, nil
}

// sharedPool returns the *sql.DB for the connection string config resolves to,
// opening and sizing it on the first call for that DSN (ADR-031 Decision 6).
// The DSN is resolved before the cache is consulted: a config that resolves to
// a DSN no pool has been opened for gets its own pool rather than the pool of
// some earlier, unrelated caller. Pool-sizing keys (max_open_connections,
// max_idle_connections, connection_max_lifetime_minutes) are honoured only on
// the call that opens a given DSN's pool; later calls for the same DSN reuse it.
func (p *DatabaseProvider) sharedPool(config map[string]interface{}) (*sql.DB, error) {
	dsn, err := p.getDSN(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	p.poolMu.Lock()
	defer p.poolMu.Unlock()

	if existing, ok := p.pools[dsn]; ok {
		return existing, nil
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	maxOpenConns := getIntFromConfig(config, "max_open_connections", 25)
	maxIdleConns := getIntFromConfig(config, "max_idle_connections", 5)
	connMaxLifetime := time.Duration(getIntFromConfig(config, "connection_max_lifetime_minutes", 30)) * time.Minute

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	if p.pools == nil {
		p.pools = make(map[string]*sql.DB, 1)
	}
	p.pools[dsn] = db
	return db, nil
}

// Close releases every connection pool the provider opened. Safe to call when
// no pool was ever opened, and safe to call more than once. Stores created by
// this provider do not close their pool from their own Close methods — the
// provider that opened it is the only owner that closes it.
func (p *DatabaseProvider) Close() error {
	p.poolMu.Lock()
	defer p.poolMu.Unlock()

	var errs []error
	for dsn, db := range p.pools {
		if err := db.Close(); err != nil {
			// The DSN carries credentials, so it is never included in the error.
			errs = append(errs, err)
		}
		delete(p.pools, dsn)
	}
	p.pools = nil
	return errors.Join(errs...)
}

// Helper functions for configuration extraction
func getStringFromConfig(config map[string]interface{}, key, defaultValue string) string {
	if val, ok := config[key].(string); ok {
		return val
	}
	return defaultValue
}

func getIntFromConfig(config map[string]interface{}, key string, defaultValue int) int {
	if val, ok := config[key].(int); ok {
		return val
	}
	if val, ok := config[key].(float64); ok {
		return int(val)
	}
	return defaultValue
}

func getBoolFromConfig(config map[string]interface{}, key string, defaultValue bool) bool {
	if val, ok := config[key].(bool); ok {
		return val
	}
	return defaultValue
}

// Auto-register this provider (Salt-style)
func init() {
	interfaces.RegisterStorageProvider(&DatabaseProvider{})
}

// DatabaseClientTenantStore implements ClientTenantStore using PostgreSQL for persistence
type DatabaseClientTenantStore struct {
	db      *sql.DB
	config  map[string]interface{}
	mutex   sync.RWMutex
	schemas DatabaseSchemas
}

// NewDatabaseClientTenantStore creates a new PostgreSQL-based client tenant
// store backed by the shared connection pool db (owned by DatabaseProvider).
func NewDatabaseClientTenantStore(db *sql.DB, config map[string]interface{}) (*DatabaseClientTenantStore, error) {
	store := &DatabaseClientTenantStore{
		db:      db,
		config:  config,
		schemas: NewDatabaseSchemas(),
	}

	// Initialize database schema
	if err := store.initializeSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	return store, nil
}

// initializeSchema creates the necessary database tables and indexes
func (s *DatabaseClientTenantStore) initializeSchema() error {
	ctx := context.Background()

	// Use PostgreSQL advisory lock to prevent concurrent schema initialization
	// Lock ID: 24681357 (different from other store locks)
	const schemaLockID = 24681357

	// Acquire advisory lock - will wait if another instance is initializing
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", schemaLockID); err != nil {
		return fmt.Errorf("failed to acquire client tenant schema initialization lock: %w", err)
	}

	// Ensure we release the lock when done
	defer func() {
		if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", schemaLockID); err != nil {
			// Log but don't fail - lock will be released when connection closes
			// This is non-critical since PostgreSQL will release advisory locks when connection closes
			_ = err // Explicitly ignore error to satisfy linter
		}
	}()

	// Create client tenants table
	if err := s.schemas.CreateClientTenantsTable(ctx, s.db); err != nil {
		return fmt.Errorf("failed to create client_tenants table: %w", err)
	}

	// Create admin consent requests table
	if err := s.schemas.CreateAdminConsentRequestsTable(ctx, s.db); err != nil {
		return fmt.Errorf("failed to create admin_consent_requests table: %w", err)
	}

	return nil
}

// StoreClientTenant stores a client tenant in the database
func (s *DatabaseClientTenantStore) StoreClientTenant(client *business.ClientTenant) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	ctx := context.Background()

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Set timestamps
	now := time.Now()
	if client.CreatedAt.IsZero() {
		client.CreatedAt = now
	}
	client.UpdatedAt = now

	// Use tenant_id as ID if not set
	if client.ID == "" {
		client.ID = client.TenantID
	}

	// Insert or update client tenant
	query := `
		INSERT INTO client_tenants (id, tenant_id, tenant_name, domain_name, admin_email, consented_at, status, client_identifier, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id) DO UPDATE SET
			tenant_name = EXCLUDED.tenant_name,
			domain_name = EXCLUDED.domain_name,
			admin_email = EXCLUDED.admin_email,
			consented_at = EXCLUDED.consented_at,
			status = EXCLUDED.status,
			client_identifier = EXCLUDED.client_identifier,
			metadata = EXCLUDED.metadata,
			updated_at = EXCLUDED.updated_at
	`

	metadataJSON, err := serializeMetadata(client.Metadata)
	if err != nil {
		return fmt.Errorf("failed to serialize metadata: %w", err)
	}

	_, err = tx.ExecContext(ctx, query,
		client.ID,
		client.TenantID,
		client.TenantName,
		client.DomainName,
		client.AdminEmail,
		client.ConsentedAt,
		string(client.Status),
		client.ClientIdentifier,
		metadataJSON,
		client.CreatedAt,
		client.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to store client tenant: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetClientTenant retrieves a client tenant by tenant ID
func (s *DatabaseClientTenantStore) GetClientTenant(tenantID string) (*business.ClientTenant, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	ctx := context.Background()

	query := `
		SELECT id, tenant_id, tenant_name, domain_name, admin_email, consented_at, status, client_identifier, metadata, created_at, updated_at
		FROM client_tenants
		WHERE tenant_id = $1
	`

	row := s.db.QueryRowContext(ctx, query, tenantID)

	client := &business.ClientTenant{}
	var statusStr string
	var metadataJSON []byte

	err := row.Scan(
		&client.ID,
		&client.TenantID,
		&client.TenantName,
		&client.DomainName,
		&client.AdminEmail,
		&client.ConsentedAt,
		&statusStr,
		&client.ClientIdentifier,
		&metadataJSON,
		&client.CreatedAt,
		&client.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("client tenant not found: %s", tenantID)
		}
		return nil, fmt.Errorf("failed to get client tenant: %w", err)
	}

	client.Status = business.ClientTenantStatus(statusStr)

	if len(metadataJSON) > 0 {
		metadata, err := deserializeMetadata(metadataJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize metadata: %w", err)
		}
		client.Metadata = metadata
	}

	return client, nil
}

// GetClientTenantByIdentifier retrieves a client tenant by client identifier
func (s *DatabaseClientTenantStore) GetClientTenantByIdentifier(clientIdentifier string) (*business.ClientTenant, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	ctx := context.Background()

	query := `
		SELECT id, tenant_id, tenant_name, domain_name, admin_email, consented_at, status, client_identifier, metadata, created_at, updated_at
		FROM client_tenants
		WHERE client_identifier = $1
	`

	row := s.db.QueryRowContext(ctx, query, clientIdentifier)

	client := &business.ClientTenant{}
	var statusStr string
	var metadataJSON []byte

	err := row.Scan(
		&client.ID,
		&client.TenantID,
		&client.TenantName,
		&client.DomainName,
		&client.AdminEmail,
		&client.ConsentedAt,
		&statusStr,
		&client.ClientIdentifier,
		&metadataJSON,
		&client.CreatedAt,
		&client.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("client tenant not found by identifier: %s", clientIdentifier)
		}
		return nil, fmt.Errorf("failed to get client tenant by identifier: %w", err)
	}

	client.Status = business.ClientTenantStatus(statusStr)

	if len(metadataJSON) > 0 {
		metadata, err := deserializeMetadata(metadataJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize metadata: %w", err)
		}
		client.Metadata = metadata
	}

	return client, nil
}

// ListClientTenants lists client tenants by status
func (s *DatabaseClientTenantStore) ListClientTenants(status business.ClientTenantStatus) ([]*business.ClientTenant, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	ctx := context.Background()

	var query string
	var args []interface{}

	if status == "" {
		query = `
			SELECT id, tenant_id, tenant_name, domain_name, admin_email, consented_at, status, client_identifier, metadata, created_at, updated_at
			FROM client_tenants
			ORDER BY created_at DESC
		`
	} else {
		query = `
			SELECT id, tenant_id, tenant_name, domain_name, admin_email, consented_at, status, client_identifier, metadata, created_at, updated_at
			FROM client_tenants
			WHERE status = $1
			ORDER BY created_at DESC
		`
		args = []interface{}{string(status)}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list client tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var clients []*business.ClientTenant

	for rows.Next() {
		client := &business.ClientTenant{}
		var statusStr string
		var metadataJSON []byte

		err := rows.Scan(
			&client.ID,
			&client.TenantID,
			&client.TenantName,
			&client.DomainName,
			&client.AdminEmail,
			&client.ConsentedAt,
			&statusStr,
			&client.ClientIdentifier,
			&metadataJSON,
			&client.CreatedAt,
			&client.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan client tenant: %w", err)
		}

		client.Status = business.ClientTenantStatus(statusStr)

		if len(metadataJSON) > 0 {
			metadata, err := deserializeMetadata(metadataJSON)
			if err != nil {
				return nil, fmt.Errorf("failed to deserialize metadata: %w", err)
			}
			client.Metadata = metadata
		}

		clients = append(clients, client)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating client tenants: %w", err)
	}

	return clients, nil
}

// UpdateClientTenantStatus updates the status of a client tenant
func (s *DatabaseClientTenantStore) UpdateClientTenantStatus(tenantID string, status business.ClientTenantStatus) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	ctx := context.Background()

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `
		UPDATE client_tenants
		SET status = $1, updated_at = $2
		WHERE tenant_id = $3
	`

	result, err := tx.ExecContext(ctx, query, string(status), time.Now(), tenantID)
	if err != nil {
		return fmt.Errorf("failed to update client tenant status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("client tenant not found: %s", tenantID)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DeleteClientTenant deletes a client tenant
func (s *DatabaseClientTenantStore) DeleteClientTenant(tenantID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	ctx := context.Background()

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `DELETE FROM client_tenants WHERE tenant_id = $1`

	_, err = tx.ExecContext(ctx, query, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete client tenant: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// StoreAdminConsentRequest stores an admin consent request
func (s *DatabaseClientTenantStore) StoreAdminConsentRequest(request *business.AdminConsentRequest) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	ctx := context.Background()

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Set created timestamp
	if request.CreatedAt.IsZero() {
		request.CreatedAt = time.Now()
	}

	query := `
		INSERT INTO admin_consent_requests (client_identifier, client_name, requested_by, state, expires_at, created_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (state) DO UPDATE SET
			client_identifier = EXCLUDED.client_identifier,
			client_name = EXCLUDED.client_name,
			requested_by = EXCLUDED.requested_by,
			expires_at = EXCLUDED.expires_at,
			metadata = EXCLUDED.metadata
	`

	metadataJSON, err := serializeMetadata(request.Metadata)
	if err != nil {
		return fmt.Errorf("failed to serialize metadata: %w", err)
	}

	_, err = tx.ExecContext(ctx, query,
		request.ClientIdentifier,
		request.ClientName,
		request.RequestedBy,
		request.State,
		request.ExpiresAt,
		request.CreatedAt,
		metadataJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to store admin consent request: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetAdminConsentRequest retrieves an admin consent request by state
func (s *DatabaseClientTenantStore) GetAdminConsentRequest(state string) (*business.AdminConsentRequest, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	ctx := context.Background()

	query := `
		SELECT client_identifier, client_name, requested_by, state, expires_at, created_at, metadata
		FROM admin_consent_requests
		WHERE state = $1
	`

	row := s.db.QueryRowContext(ctx, query, state)

	request := &business.AdminConsentRequest{}
	var metadataJSON []byte

	err := row.Scan(
		&request.ClientIdentifier,
		&request.ClientName,
		&request.RequestedBy,
		&request.State,
		&request.ExpiresAt,
		&request.CreatedAt,
		&metadataJSON,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("admin consent request not found: %s", state)
		}
		return nil, fmt.Errorf("failed to get admin consent request: %w", err)
	}

	// Check if expired
	if time.Now().After(request.ExpiresAt) {
		return nil, fmt.Errorf("admin consent request expired: %s", state)
	}

	if len(metadataJSON) > 0 {
		metadata, err := deserializeMetadata(metadataJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize metadata: %w", err)
		}
		request.Metadata = metadata
	}

	return request, nil
}

// DeleteAdminConsentRequest deletes an admin consent request
func (s *DatabaseClientTenantStore) DeleteAdminConsentRequest(state string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	ctx := context.Background()

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `DELETE FROM admin_consent_requests WHERE state = $1`

	_, err = tx.ExecContext(ctx, query, state)
	if err != nil {
		return fmt.Errorf("failed to delete admin consent request: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// Close is a no-op: the underlying connection pool is owned and closed by
// DatabaseProvider, not by individual stores (ADR-031 Decision 6).
func (s *DatabaseClientTenantStore) Close() error {
	return nil
}
