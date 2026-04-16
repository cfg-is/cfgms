// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package database implements production-ready PostgreSQL storage provider for CFGMS
// Provides database-based storage with ACID transactions, connection pooling, and performance optimization
package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// DatabaseProvider implements the StorageProvider interface using PostgreSQL for persistence
type DatabaseProvider struct{}

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

// Available checks if PostgreSQL is available and accessible
func (p *DatabaseProvider) Available() (bool, error) {
	// For production use, this would ping a test database connection
	// For now, we assume PostgreSQL driver availability
	return true, nil
}

// CreateClientTenantStore creates a database-based client tenant store
func (p *DatabaseProvider) CreateClientTenantStore(config map[string]interface{}) (interfaces.ClientTenantStore, error) {
	// Get database connection string from config
	dsn, err := p.getDSN(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	// Create the database client tenant store
	store, err := NewDatabaseClientTenantStore(dsn, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database client tenant store: %w", err)
	}

	return store, nil
}

// CreateConfigStore creates a database-based configuration store
func (p *DatabaseProvider) CreateConfigStore(config map[string]interface{}) (interfaces.ConfigStore, error) {
	// Get database connection string from config
	dsn, err := p.getDSN(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	// Create the database config store
	store, err := NewDatabaseConfigStore(dsn, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database config store: %w", err)
	}

	return store, nil
}

// CreateAuditStore creates a database-based audit store
func (p *DatabaseProvider) CreateAuditStore(config map[string]interface{}) (interfaces.AuditStore, error) {
	// Get database connection string from config
	dsn, err := p.getDSN(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	// Create the database audit store
	store, err := NewDatabaseAuditStore(dsn, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database audit store: %w", err)
	}

	return store, nil
}

// CreateRBACStore creates a database-based RBAC store
func (p *DatabaseProvider) CreateRuntimeStore(config map[string]interface{}) (interfaces.RuntimeStore, error) {
	dsn, err := p.getDSN(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		if err := db.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	store := &DatabaseRuntimeStore{
		db:             db,
		tableName:      p.getTableName(config, "runtime_sessions"),
		stateTableName: p.getTableName(config, "runtime_state"),
	}

	// Create tables if they don't exist
	if err := store.createTables(); err != nil {
		if err := db.Close(); err != nil {
			// Could add logging here if needed
			_ = err
		}
		return nil, fmt.Errorf("failed to create runtime tables: %w", err)
	}

	return store, nil
}

func (p *DatabaseProvider) CreateRBACStore(config map[string]interface{}) (interfaces.RBACStore, error) {
	// Get database connection string from config
	dsn, err := p.getDSN(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	// Create the database RBAC store
	store, err := NewDatabaseRBACStore(dsn, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database RBAC store: %w", err)
	}

	return store, nil
}

func (p *DatabaseProvider) CreateTenantStore(config map[string]interface{}) (interfaces.TenantStore, error) {
	// Get database connection string from config
	dsn, err := p.getDSN(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	// Create the database tenant store
	store, err := NewDatabaseTenantStore(dsn, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database tenant store: %w", err)
	}

	return store, nil
}

// CreateSessionStore is not supported by the database provider in this release.
// The database provider exposes session data via CreateRuntimeStore.
// Use the SQLite provider for SessionStore, or extend this provider in a future story.
func (p *DatabaseProvider) CreateSessionStore(config map[string]interface{}) (interfaces.SessionStore, error) {
	return nil, interfaces.ErrNotSupported
}

// CreateStewardStore is not supported by the database provider.
// StewardStore is implemented by the flat-file and SQLite providers (Issue #663).
func (p *DatabaseProvider) CreateStewardStore(config map[string]interface{}) (interfaces.StewardStore, error) {
	return nil, interfaces.ErrNotSupported
}

func (p *DatabaseProvider) CreateRegistrationTokenStore(config map[string]interface{}) (interfaces.RegistrationTokenStore, error) {
	// Get database connection string from config
	dsn, err := p.getDSN(config)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	// Create the database registration token store
	store, err := NewDatabaseRegistrationTokenStore(dsn, config)
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

// getTableName returns the table name for the given key, with optional prefix
func (p *DatabaseProvider) getTableName(config map[string]interface{}, defaultName string) string {
	// Check for table prefix
	prefix := getStringFromConfig(config, "table_prefix", "cfgms_")

	// Check for custom table name
	tableKey := defaultName + "_table"
	if customName, ok := config[tableKey].(string); ok && customName != "" {
		return p.validateTableName(prefix + customName)
	}

	return p.validateTableName(prefix + defaultName)
}

// validateTableName validates and sanitizes table names to prevent SQL injection
func (p *DatabaseProvider) validateTableName(tableName string) string {
	// Only allow alphanumeric characters and underscores
	// This prevents SQL injection in table names
	var sanitized strings.Builder
	for _, r := range tableName {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			sanitized.WriteRune(r)
		}
	}

	result := sanitized.String()
	if result == "" {
		return "cfgms_default" // fallback to safe default
	}

	return result
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

// NewDatabaseClientTenantStore creates a new PostgreSQL-based client tenant store
func NewDatabaseClientTenantStore(dsn string, config map[string]interface{}) (*DatabaseClientTenantStore, error) {
	// Open database connection with connection pooling
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool
	maxOpenConns := getIntFromConfig(config, "max_open_connections", 25)
	maxIdleConns := getIntFromConfig(config, "max_idle_connections", 5)
	connMaxLifetime := time.Duration(getIntFromConfig(config, "connection_max_lifetime_minutes", 30)) * time.Minute

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)

	// Test connection
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	store := &DatabaseClientTenantStore{
		db:      db,
		config:  config,
		schemas: NewDatabaseSchemas(),
	}

	// Initialize database schema
	if err := store.initializeSchema(); err != nil {
		_ = db.Close()
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
func (s *DatabaseClientTenantStore) StoreClientTenant(client *interfaces.ClientTenant) error {
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
func (s *DatabaseClientTenantStore) GetClientTenant(tenantID string) (*interfaces.ClientTenant, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	ctx := context.Background()

	query := `
		SELECT id, tenant_id, tenant_name, domain_name, admin_email, consented_at, status, client_identifier, metadata, created_at, updated_at
		FROM client_tenants
		WHERE tenant_id = $1
	`

	row := s.db.QueryRowContext(ctx, query, tenantID)

	client := &interfaces.ClientTenant{}
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

	client.Status = interfaces.ClientTenantStatus(statusStr)

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
func (s *DatabaseClientTenantStore) GetClientTenantByIdentifier(clientIdentifier string) (*interfaces.ClientTenant, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	ctx := context.Background()

	query := `
		SELECT id, tenant_id, tenant_name, domain_name, admin_email, consented_at, status, client_identifier, metadata, created_at, updated_at
		FROM client_tenants
		WHERE client_identifier = $1
	`

	row := s.db.QueryRowContext(ctx, query, clientIdentifier)

	client := &interfaces.ClientTenant{}
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

	client.Status = interfaces.ClientTenantStatus(statusStr)

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
func (s *DatabaseClientTenantStore) ListClientTenants(status interfaces.ClientTenantStatus) ([]*interfaces.ClientTenant, error) {
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

	var clients []*interfaces.ClientTenant

	for rows.Next() {
		client := &interfaces.ClientTenant{}
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

		client.Status = interfaces.ClientTenantStatus(statusStr)

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
func (s *DatabaseClientTenantStore) UpdateClientTenantStatus(tenantID string, status interfaces.ClientTenantStatus) error {
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
func (s *DatabaseClientTenantStore) StoreAdminConsentRequest(request *interfaces.AdminConsentRequest) error {
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
func (s *DatabaseClientTenantStore) GetAdminConsentRequest(state string) (*interfaces.AdminConsentRequest, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	ctx := context.Background()

	query := `
		SELECT client_identifier, client_name, requested_by, state, expires_at, created_at, metadata
		FROM admin_consent_requests
		WHERE state = $1
	`

	row := s.db.QueryRowContext(ctx, query, state)

	request := &interfaces.AdminConsentRequest{}
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

// Close closes the database connection
func (s *DatabaseClientTenantStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
