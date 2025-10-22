// Package database implements ConfigStore interface using PostgreSQL
package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/lib/pq"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// DatabaseConfigStore implements ConfigStore using PostgreSQL for persistence
type DatabaseConfigStore struct {
	db      *sql.DB
	config  map[string]interface{}
	mutex   sync.RWMutex
	schemas DatabaseSchemas
}

// NewDatabaseConfigStore creates a new PostgreSQL-based configuration store
func NewDatabaseConfigStore(dsn string, config map[string]interface{}) (*DatabaseConfigStore, error) {
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

	store := &DatabaseConfigStore{
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

// initializeSchema creates the necessary database tables and indexes for configuration storage
func (s *DatabaseConfigStore) initializeSchema() error {
	ctx := context.Background()

	// Use PostgreSQL advisory lock to prevent concurrent schema initialization
	// Lock ID: 12345678 (arbitrary but consistent)
	const schemaLockID = 12345678

	// Acquire advisory lock - will wait if another instance is initializing
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", schemaLockID); err != nil {
		return fmt.Errorf("failed to acquire schema initialization lock: %w", err)
	}

	// Ensure we release the lock when done
	defer func() {
		if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", schemaLockID); err != nil {
			// Log but don't fail - lock will be released when connection closes
			// This is non-critical since PostgreSQL will release advisory locks when connection closes
			_ = err // Explicitly ignore error to satisfy linter
		}
	}()

	// Create configs table
	if err := s.schemas.CreateConfigsTable(ctx, s.db); err != nil {
		return fmt.Errorf("failed to create configs table: %w", err)
	}

	// Create config history table for versioning
	if err := s.schemas.CreateConfigHistoryTable(ctx, s.db); err != nil {
		return fmt.Errorf("failed to create config_history table: %w", err)
	}

	return nil
}

// StoreConfig stores a configuration entry in the database with versioning and history tracking
func (s *DatabaseConfigStore) StoreConfig(ctx context.Context, config *interfaces.ConfigEntry) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Validate required fields
	if err := s.validateConfigEntry(config); err != nil {
		return err
	}

	// Begin transaction for atomic operations
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Set metadata
	now := time.Now()
	if config.CreatedAt.IsZero() {
		config.CreatedAt = now
	}
	config.UpdatedAt = now
	config.Format = interfaces.ConfigFormatYAML

	// Calculate checksum
	hasher := sha256.New()
	hasher.Write(config.Data)
	config.Checksum = hex.EncodeToString(hasher.Sum(nil))

	// Check if configuration already exists to determine version and operation
	existingConfig, err := s.getConfigInternal(ctx, tx, config.Key)
	isUpdate := err == nil && existingConfig != nil

	if isUpdate {
		config.Version = existingConfig.Version + 1
	} else {
		config.Version = 1
	}

	// Serialize metadata and tags
	metadataJSON, err := serializeMetadata(config.Metadata)
	if err != nil {
		return fmt.Errorf("failed to serialize metadata: %w", err)
	}

	// Insert or update configuration
	query := `
		INSERT INTO configs (tenant_id, namespace, name, scope, version, format, data, checksum, metadata, tags, source, created_at, updated_at, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (tenant_id, namespace, name, scope) DO UPDATE SET
			version = EXCLUDED.version,
			format = EXCLUDED.format,
			data = EXCLUDED.data,
			checksum = EXCLUDED.checksum,
			metadata = EXCLUDED.metadata,
			tags = EXCLUDED.tags,
			source = EXCLUDED.source,
			updated_at = EXCLUDED.updated_at,
			updated_by = EXCLUDED.updated_by
		RETURNING id
	`

	var configID int
	err = tx.QueryRowContext(ctx, query,
		config.Key.TenantID,
		config.Key.Namespace,
		config.Key.Name,
		config.Key.Scope,
		config.Version,
		string(config.Format),
		string(config.Data),
		config.Checksum,
		metadataJSON,
		pq.Array(config.Tags),
		config.Source,
		config.CreatedAt,
		config.UpdatedAt,
		config.CreatedBy,
		config.UpdatedBy,
	).Scan(&configID)

	if err != nil {
		return fmt.Errorf("failed to store configuration: %w", err)
	}

	// Store history entry for audit trail
	operation := "create"
	if isUpdate {
		operation = "update"
	}

	historyQuery := `
		INSERT INTO config_history (config_id, tenant_id, namespace, name, scope, version, format, data, checksum, metadata, tags, source, created_at, created_by, operation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	_, err = tx.ExecContext(ctx, historyQuery,
		configID,
		config.Key.TenantID,
		config.Key.Namespace,
		config.Key.Name,
		config.Key.Scope,
		config.Version,
		string(config.Format),
		string(config.Data),
		config.Checksum,
		metadataJSON,
		pq.Array(config.Tags),
		config.Source,
		config.CreatedAt,
		config.CreatedBy,
		operation,
	)

	if err != nil {
		return fmt.Errorf("failed to store configuration history: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetConfig retrieves a configuration entry from the database
func (s *DatabaseConfigStore) GetConfig(ctx context.Context, key *interfaces.ConfigKey) (*interfaces.ConfigEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.getConfigInternal(ctx, s.db, key)
}

// getConfigInternal retrieves a configuration entry (can be used within transactions)
func (s *DatabaseConfigStore) getConfigInternal(ctx context.Context, querier interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}, key *interfaces.ConfigKey) (*interfaces.ConfigEntry, error) {
	query := `
		SELECT tenant_id, namespace, name, scope, version, format, data, checksum, metadata, tags, source, created_at, updated_at, created_by, updated_by
		FROM configs
		WHERE tenant_id = $1 AND namespace = $2 AND name = $3 AND scope = $4
	`

	row := querier.QueryRowContext(ctx, query, key.TenantID, key.Namespace, key.Name, key.Scope)

	config := &interfaces.ConfigEntry{
		Key: &interfaces.ConfigKey{},
	}
	var formatStr string
	var metadataJSON []byte
	var tags pq.StringArray

	err := row.Scan(
		&config.Key.TenantID,
		&config.Key.Namespace,
		&config.Key.Name,
		&config.Key.Scope,
		&config.Version,
		&formatStr,
		&config.Data,
		&config.Checksum,
		&metadataJSON,
		&tags,
		&config.Source,
		&config.CreatedAt,
		&config.UpdatedAt,
		&config.CreatedBy,
		&config.UpdatedBy,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, interfaces.ErrConfigNotFound
		}
		return nil, fmt.Errorf("failed to get configuration: %w", err)
	}

	config.Format = interfaces.ConfigFormat(formatStr)
	config.Tags = []string(tags)

	if len(metadataJSON) > 0 {
		metadata, err := deserializeMetadata(metadataJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize metadata: %w", err)
		}
		config.Metadata = metadata
	}

	return config, nil
}

// DeleteConfig removes a configuration entry from the database
func (s *DatabaseConfigStore) DeleteConfig(ctx context.Context, key *interfaces.ConfigKey) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Get the configuration before deletion for history
	existingConfig, err := s.getConfigInternal(ctx, tx, key)
	if err != nil {
		return err // Will return ErrConfigNotFound if not found
	}

	// Delete the configuration
	query := `DELETE FROM configs WHERE tenant_id = $1 AND namespace = $2 AND name = $3 AND scope = $4`

	result, err := tx.ExecContext(ctx, query, key.TenantID, key.Namespace, key.Name, key.Scope)
	if err != nil {
		return fmt.Errorf("failed to delete configuration: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return interfaces.ErrConfigNotFound
	}

	// Store deletion in history
	historyQuery := `
		INSERT INTO config_history (config_id, tenant_id, namespace, name, scope, version, format, data, checksum, metadata, tags, source, created_at, created_by, operation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	metadataJSON, _ := serializeMetadata(existingConfig.Metadata)

	_, err = tx.ExecContext(ctx, historyQuery,
		-1, // Special ID for deleted configs
		existingConfig.Key.TenantID,
		existingConfig.Key.Namespace,
		existingConfig.Key.Name,
		existingConfig.Key.Scope,
		existingConfig.Version,
		string(existingConfig.Format),
		string(existingConfig.Data),
		existingConfig.Checksum,
		metadataJSON,
		pq.Array(existingConfig.Tags),
		existingConfig.Source,
		time.Now(),
		"", // Could be set to user who performed deletion
		"delete",
	)

	if err != nil {
		return fmt.Errorf("failed to store deletion history: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ListConfigs lists configuration entries matching the filter with optimized database queries
func (s *DatabaseConfigStore) ListConfigs(ctx context.Context, filter *interfaces.ConfigFilter) ([]*interfaces.ConfigEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Build query with filters
	baseQuery := `
		SELECT tenant_id, namespace, name, scope, version, format, data, checksum, metadata, tags, source, created_at, updated_at, created_by, updated_by
		FROM configs
	`

	var args []interface{}
	whereClause, args := buildConfigFilterQuery(filter, args)
	orderClause := buildConfigOrderByClause(filter)
	limitClause := buildConfigLimitOffsetClause(filter)

	query := baseQuery + " " + whereClause + " " + orderClause + limitClause

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list configurations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var configs []*interfaces.ConfigEntry

	for rows.Next() {
		config := &interfaces.ConfigEntry{
			Key: &interfaces.ConfigKey{},
		}
		var formatStr string
		var metadataJSON []byte
		var tags pq.StringArray

		err := rows.Scan(
			&config.Key.TenantID,
			&config.Key.Namespace,
			&config.Key.Name,
			&config.Key.Scope,
			&config.Version,
			&formatStr,
			&config.Data,
			&config.Checksum,
			&metadataJSON,
			&tags,
			&config.Source,
			&config.CreatedAt,
			&config.UpdatedAt,
			&config.CreatedBy,
			&config.UpdatedBy,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan configuration: %w", err)
		}

		config.Format = interfaces.ConfigFormat(formatStr)
		config.Tags = []string(tags)

		if len(metadataJSON) > 0 {
			metadata, err := deserializeMetadata(metadataJSON)
			if err != nil {
				return nil, fmt.Errorf("failed to deserialize metadata: %w", err)
			}
			config.Metadata = metadata
		}

		configs = append(configs, config)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating configurations: %w", err)
	}

	return configs, nil
}

// GetConfigHistory gets version history for a configuration using the history table
func (s *DatabaseConfigStore) GetConfigHistory(ctx context.Context, key *interfaces.ConfigKey, limit int) ([]*interfaces.ConfigEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT tenant_id, namespace, name, scope, version, format, data, checksum, metadata, tags, source, created_at, created_by
		FROM config_history
		WHERE tenant_id = $1 AND namespace = $2 AND name = $3 AND scope = $4
		ORDER BY version DESC
		LIMIT $5
	`

	rows, err := s.db.QueryContext(ctx, query, key.TenantID, key.Namespace, key.Name, key.Scope, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get configuration history: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var configs []*interfaces.ConfigEntry

	for rows.Next() {
		config := &interfaces.ConfigEntry{
			Key: &interfaces.ConfigKey{},
		}
		var formatStr string
		var metadataJSON []byte
		var tags pq.StringArray

		err := rows.Scan(
			&config.Key.TenantID,
			&config.Key.Namespace,
			&config.Key.Name,
			&config.Key.Scope,
			&config.Version,
			&formatStr,
			&config.Data,
			&config.Checksum,
			&metadataJSON,
			&tags,
			&config.Source,
			&config.CreatedAt,
			&config.CreatedBy,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan configuration history: %w", err)
		}

		config.Format = interfaces.ConfigFormat(formatStr)
		config.Tags = []string(tags)

		if len(metadataJSON) > 0 {
			metadata, err := deserializeMetadata(metadataJSON)
			if err != nil {
				return nil, fmt.Errorf("failed to deserialize metadata: %w", err)
			}
			config.Metadata = metadata
		}

		configs = append(configs, config)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating configuration history: %w", err)
	}

	return configs, nil
}

// GetConfigVersion gets a specific version of a configuration
func (s *DatabaseConfigStore) GetConfigVersion(ctx context.Context, key *interfaces.ConfigKey, version int64) (*interfaces.ConfigEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT tenant_id, namespace, name, scope, version, format, data, checksum, metadata, tags, source, created_at, created_by
		FROM config_history
		WHERE tenant_id = $1 AND namespace = $2 AND name = $3 AND scope = $4 AND version = $5
	`

	row := s.db.QueryRowContext(ctx, query, key.TenantID, key.Namespace, key.Name, key.Scope, version)

	config := &interfaces.ConfigEntry{
		Key: &interfaces.ConfigKey{},
	}
	var formatStr string
	var metadataJSON []byte
	var tags pq.StringArray

	err := row.Scan(
		&config.Key.TenantID,
		&config.Key.Namespace,
		&config.Key.Name,
		&config.Key.Scope,
		&config.Version,
		&formatStr,
		&config.Data,
		&config.Checksum,
		&metadataJSON,
		&tags,
		&config.Source,
		&config.CreatedAt,
		&config.CreatedBy,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, interfaces.ErrConfigNotFound
		}
		return nil, fmt.Errorf("failed to get configuration version: %w", err)
	}

	config.Format = interfaces.ConfigFormat(formatStr)
	config.Tags = []string(tags)

	if len(metadataJSON) > 0 {
		metadata, err := deserializeMetadata(metadataJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize metadata: %w", err)
		}
		config.Metadata = metadata
	}

	return config, nil
}

// StoreConfigBatch stores multiple configurations in a single transaction for performance
func (s *DatabaseConfigStore) StoreConfigBatch(ctx context.Context, configs []*interfaces.ConfigEntry) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Begin transaction for atomic batch operation
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Store each configuration
	for _, config := range configs {
		if err := s.storeConfigInTransaction(ctx, tx, config); err != nil {
			return fmt.Errorf("failed to store configuration %s: %w", config.Key.String(), err)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	return nil
}

// DeleteConfigBatch deletes multiple configurations in a single transaction
func (s *DatabaseConfigStore) DeleteConfigBatch(ctx context.Context, keys []*interfaces.ConfigKey) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Begin transaction for atomic batch operation
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Delete each configuration
	for _, key := range keys {
		if err := s.deleteConfigInTransaction(ctx, tx, key); err != nil {
			return fmt.Errorf("failed to delete configuration %s: %w", key.String(), err)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch deletion transaction: %w", err)
	}

	return nil
}

// ResolveConfigWithInheritance resolves configuration with inheritance (not implemented yet)
func (s *DatabaseConfigStore) ResolveConfigWithInheritance(ctx context.Context, key *interfaces.ConfigKey) (*interfaces.ConfigEntry, error) {
	// For now, just return the config without inheritance resolution
	// Future implementation would handle hierarchical inheritance
	return s.GetConfig(ctx, key)
}

// ValidateConfig validates a configuration entry
func (s *DatabaseConfigStore) ValidateConfig(ctx context.Context, config *interfaces.ConfigEntry) error {
	return s.validateConfigEntry(config)
}

// GetConfigStats returns statistics about stored configurations using optimized queries
func (s *DatabaseConfigStore) GetConfigStats(ctx context.Context) (*interfaces.ConfigStats, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	stats := &interfaces.ConfigStats{
		ConfigsByTenant:    make(map[string]int64),
		ConfigsByFormat:    make(map[string]int64),
		ConfigsByNamespace: make(map[string]int64),
		LastUpdated:        time.Now(),
	}

	// Get overall statistics
	overallQuery := `
		SELECT 
			COUNT(*) as total_configs,
			COALESCE(SUM(LENGTH(data)), 0) as total_size,
			COALESCE(ROUND(AVG(LENGTH(data))), 0) as average_size,
			MIN(created_at) as oldest_config,
			MAX(updated_at) as newest_config
		FROM configs
	`

	row := s.db.QueryRowContext(ctx, overallQuery)
	err := row.Scan(&stats.TotalConfigs, &stats.TotalSize, &stats.AverageSize, &stats.OldestConfig, &stats.NewestConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get overall statistics: %w", err)
	}

	// Get statistics by tenant
	tenantQuery := `SELECT tenant_id, COUNT(*) FROM configs GROUP BY tenant_id`
	rows, err := s.db.QueryContext(ctx, tenantQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant statistics: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var tenantID string
		var count int64
		if err := rows.Scan(&tenantID, &count); err != nil {
			return nil, fmt.Errorf("failed to scan tenant statistics: %w", err)
		}
		stats.ConfigsByTenant[tenantID] = count
	}

	// Get statistics by format
	formatQuery := `SELECT format, COUNT(*) FROM configs GROUP BY format`
	rows, err = s.db.QueryContext(ctx, formatQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get format statistics: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var format string
		var count int64
		if err := rows.Scan(&format, &count); err != nil {
			return nil, fmt.Errorf("failed to scan format statistics: %w", err)
		}
		stats.ConfigsByFormat[format] = count
	}

	// Get statistics by namespace
	namespaceQuery := `SELECT namespace, COUNT(*) FROM configs GROUP BY namespace`
	rows, err = s.db.QueryContext(ctx, namespaceQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace statistics: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var namespace string
		var count int64
		if err := rows.Scan(&namespace, &count); err != nil {
			return nil, fmt.Errorf("failed to scan namespace statistics: %w", err)
		}
		stats.ConfigsByNamespace[namespace] = count
	}

	return stats, nil
}

// Helper methods

// validateConfigEntry validates a configuration entry
func (s *DatabaseConfigStore) validateConfigEntry(config *interfaces.ConfigEntry) error {
	if config.Key == nil {
		return interfaces.ErrNameRequired
	}
	if config.Key.TenantID == "" {
		return interfaces.ErrTenantRequired
	}
	if config.Key.Namespace == "" {
		return interfaces.ErrNamespaceRequired
	}
	if config.Key.Name == "" {
		return interfaces.ErrNameRequired
	}
	if len(config.Data) == 0 {
		return fmt.Errorf("configuration data cannot be empty")
	}

	return nil
}

// storeConfigInTransaction stores a config within an existing transaction
func (s *DatabaseConfigStore) storeConfigInTransaction(ctx context.Context, tx *sql.Tx, config *interfaces.ConfigEntry) error {
	// Validate configuration
	if err := s.validateConfigEntry(config); err != nil {
		return err
	}

	// Set metadata
	now := time.Now()
	if config.CreatedAt.IsZero() {
		config.CreatedAt = now
	}
	config.UpdatedAt = now
	config.Format = interfaces.ConfigFormatYAML

	// Calculate checksum
	hasher := sha256.New()
	hasher.Write(config.Data)
	config.Checksum = hex.EncodeToString(hasher.Sum(nil))

	// Check if configuration already exists
	existingConfig, err := s.getConfigInternal(ctx, tx, config.Key)
	isUpdate := err == nil && existingConfig != nil

	if isUpdate {
		config.Version = existingConfig.Version + 1
	} else {
		config.Version = 1
	}

	// Serialize metadata
	metadataJSON, err := serializeMetadata(config.Metadata)
	if err != nil {
		return fmt.Errorf("failed to serialize metadata: %w", err)
	}

	// Insert or update configuration
	query := `
		INSERT INTO configs (tenant_id, namespace, name, scope, version, format, data, checksum, metadata, tags, source, created_at, updated_at, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (tenant_id, namespace, name, scope) DO UPDATE SET
			version = EXCLUDED.version,
			format = EXCLUDED.format,
			data = EXCLUDED.data,
			checksum = EXCLUDED.checksum,
			metadata = EXCLUDED.metadata,
			tags = EXCLUDED.tags,
			source = EXCLUDED.source,
			updated_at = EXCLUDED.updated_at,
			updated_by = EXCLUDED.updated_by
		RETURNING id
	`

	var configID int
	err = tx.QueryRowContext(ctx, query,
		config.Key.TenantID,
		config.Key.Namespace,
		config.Key.Name,
		config.Key.Scope,
		config.Version,
		string(config.Format),
		string(config.Data),
		config.Checksum,
		metadataJSON,
		pq.Array(config.Tags),
		config.Source,
		config.CreatedAt,
		config.UpdatedAt,
		config.CreatedBy,
		config.UpdatedBy,
	).Scan(&configID)

	if err != nil {
		return fmt.Errorf("failed to store configuration: %w", err)
	}

	// Store history entry
	operation := "create"
	if isUpdate {
		operation = "update"
	}

	historyQuery := `
		INSERT INTO config_history (config_id, tenant_id, namespace, name, scope, version, format, data, checksum, metadata, tags, source, created_at, created_by, operation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	_, err = tx.ExecContext(ctx, historyQuery,
		configID,
		config.Key.TenantID,
		config.Key.Namespace,
		config.Key.Name,
		config.Key.Scope,
		config.Version,
		string(config.Format),
		string(config.Data),
		config.Checksum,
		metadataJSON,
		pq.Array(config.Tags),
		config.Source,
		config.CreatedAt,
		config.CreatedBy,
		operation,
	)

	if err != nil {
		return fmt.Errorf("failed to store configuration history: %w", err)
	}

	return nil
}

// deleteConfigInTransaction deletes a config within an existing transaction
func (s *DatabaseConfigStore) deleteConfigInTransaction(ctx context.Context, tx *sql.Tx, key *interfaces.ConfigKey) error {
	// Get the configuration before deletion for history
	existingConfig, err := s.getConfigInternal(ctx, tx, key)
	if err != nil {
		return err // Will return ErrConfigNotFound if not found
	}

	// Delete the configuration
	query := `DELETE FROM configs WHERE tenant_id = $1 AND namespace = $2 AND name = $3 AND scope = $4`

	result, err := tx.ExecContext(ctx, query, key.TenantID, key.Namespace, key.Name, key.Scope)
	if err != nil {
		return fmt.Errorf("failed to delete configuration: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return interfaces.ErrConfigNotFound
	}

	// Store deletion in history
	historyQuery := `
		INSERT INTO config_history (config_id, tenant_id, namespace, name, scope, version, format, data, checksum, metadata, tags, source, created_at, created_by, operation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	metadataJSON, _ := serializeMetadata(existingConfig.Metadata)

	_, err = tx.ExecContext(ctx, historyQuery,
		-1, // Special ID for deleted configs
		existingConfig.Key.TenantID,
		existingConfig.Key.Namespace,
		existingConfig.Key.Name,
		existingConfig.Key.Scope,
		existingConfig.Version,
		string(existingConfig.Format),
		string(existingConfig.Data),
		existingConfig.Checksum,
		metadataJSON,
		pq.Array(existingConfig.Tags),
		existingConfig.Source,
		time.Now(),
		"", // Could be set to user who performed deletion
		"delete",
	)

	if err != nil {
		return fmt.Errorf("failed to store deletion history: %w", err)
	}

	return nil
}

// Close closes the database connection
func (s *DatabaseConfigStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
