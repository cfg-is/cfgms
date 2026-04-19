// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// DatabaseTenantStore implements TenantStore using PostgreSQL for persistence
type DatabaseTenantStore struct {
	db      *sql.DB
	config  map[string]interface{}
	mutex   sync.RWMutex
	schemas DatabaseSchemas
}

// NewDatabaseTenantStore creates a new PostgreSQL-based tenant store
func NewDatabaseTenantStore(dsn string, config map[string]interface{}) (*DatabaseTenantStore, error) {
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

	store := &DatabaseTenantStore{
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

// initializeSchema creates the necessary database tables and indexes for tenants
func (s *DatabaseTenantStore) initializeSchema() error {
	ctx := context.Background()

	// Use PostgreSQL advisory lock to prevent concurrent schema initialization
	// Lock ID: 13579247 (different from RBAC's 13579246)
	const schemaLockID = 13579247

	// Acquire advisory lock - will wait if another instance is initializing
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", schemaLockID); err != nil {
		return fmt.Errorf("failed to acquire tenant schema initialization lock: %w", err)
	}

	// Ensure we release the lock when done
	defer func() {
		if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", schemaLockID); err != nil {
			// Log but don't fail - lock will be released when connection closes
			_ = err
		}
	}()

	// Create tenant tables
	if err := s.schemas.CreateTenantTables(ctx, s.db); err != nil {
		return fmt.Errorf("failed to create tenant tables: %w", err)
	}

	return nil
}

// Initialize implements TenantStore.Initialize
func (s *DatabaseTenantStore) Initialize(ctx context.Context) error {
	return s.initializeSchema()
}

// Close implements TenantStore.Close
func (s *DatabaseTenantStore) Close() error {
	return s.db.Close()
}

// CreateTenant implements TenantStore.CreateTenant
func (s *DatabaseTenantStore) CreateTenant(ctx context.Context, tenant *business.TenantData) error {
	if tenant == nil {
		return fmt.Errorf("tenant cannot be nil")
	}
	if tenant.ID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Serialize metadata to JSON
	metadataJSON, err := json.Marshal(tenant.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO cfgms_tenants (id, name, description, parent_id, metadata, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err = s.db.ExecContext(ctx, query,
		tenant.ID,
		tenant.Name,
		tenant.Description,
		nullStringOrEmpty(tenant.ParentID),
		metadataJSON,
		string(tenant.Status),
		tenant.CreatedAt,
		tenant.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	return nil
}

// GetTenant implements TenantStore.GetTenant
func (s *DatabaseTenantStore) GetTenant(ctx context.Context, tenantID string) (*business.TenantData, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT id, name, description, parent_id, metadata, status, created_at, updated_at
		FROM cfgms_tenants
		WHERE id = $1
	`

	var tenant business.TenantData
	var parentID sql.NullString
	var metadataJSON []byte

	err := s.db.QueryRowContext(ctx, query, tenantID).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.Description,
		&parentID,
		&metadataJSON,
		&tenant.Status,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("tenant %s not found", tenantID)
		}
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	tenant.ParentID = parentID.String

	if err := json.Unmarshal(metadataJSON, &tenant.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &tenant, nil
}

// UpdateTenant implements TenantStore.UpdateTenant
func (s *DatabaseTenantStore) UpdateTenant(ctx context.Context, tenant *business.TenantData) error {
	if tenant == nil {
		return fmt.Errorf("tenant cannot be nil")
	}
	if tenant.ID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Serialize metadata to JSON
	metadataJSON, err := json.Marshal(tenant.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		UPDATE cfgms_tenants
		SET name = $2, description = $3, parent_id = $4, metadata = $5, status = $6, updated_at = $7
		WHERE id = $1
	`

	result, err := s.db.ExecContext(ctx, query,
		tenant.ID,
		tenant.Name,
		tenant.Description,
		nullStringOrEmpty(tenant.ParentID),
		metadataJSON,
		string(tenant.Status),
		tenant.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("tenant %s not found", tenant.ID)
	}

	return nil
}

// DeleteTenant implements TenantStore.DeleteTenant
func (s *DatabaseTenantStore) DeleteTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	query := `DELETE FROM cfgms_tenants WHERE id = $1`

	result, err := s.db.ExecContext(ctx, query, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("tenant %s not found", tenantID)
	}

	return nil
}

// ListTenants implements TenantStore.ListTenants
func (s *DatabaseTenantStore) ListTenants(ctx context.Context, filter *business.TenantFilter) ([]*business.TenantData, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT id, name, description, parent_id, metadata, status, created_at, updated_at
		FROM cfgms_tenants
		WHERE 1=1
	`
	args := []interface{}{}
	argCount := 1

	// Apply filters
	if filter != nil {
		if filter.ParentID != "" {
			query += fmt.Sprintf(" AND parent_id = $%d", argCount)
			args = append(args, filter.ParentID)
			argCount++
		}
		if filter.Status != "" {
			query += fmt.Sprintf(" AND status = $%d", argCount)
			args = append(args, string(filter.Status))
			argCount++
		}
		if filter.Name != "" {
			query += fmt.Sprintf(" AND name ILIKE $%d", argCount)
			args = append(args, "%"+filter.Name+"%")
			// argCount not incremented as it's the last filter condition
		}
	}

	query += " ORDER BY created_at DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tenants []*business.TenantData
	for rows.Next() {
		var tenant business.TenantData
		var parentID sql.NullString
		var metadataJSON []byte

		err := rows.Scan(
			&tenant.ID,
			&tenant.Name,
			&tenant.Description,
			&parentID,
			&metadataJSON,
			&tenant.Status,
			&tenant.CreatedAt,
			&tenant.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan tenant row: %w", err)
		}

		tenant.ParentID = parentID.String

		if err := json.Unmarshal(metadataJSON, &tenant.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		tenants = append(tenants, &tenant)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating tenant rows: %w", err)
	}

	return tenants, nil
}

// GetTenantHierarchy implements TenantStore.GetTenantHierarchy
func (s *DatabaseTenantStore) GetTenantHierarchy(ctx context.Context, tenantID string) (*business.TenantHierarchy, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	// Get path from root to tenant
	path, err := s.GetTenantPath(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant path: %w", err)
	}

	// Get direct children
	children, err := s.GetChildTenants(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get child tenants: %w", err)
	}

	childIDs := make([]string, len(children))
	for i, child := range children {
		childIDs[i] = child.ID
	}

	return &business.TenantHierarchy{
		TenantID: tenantID,
		Path:     path,
		Depth:    len(path) - 1,
		Children: childIDs,
	}, nil
}

// GetChildTenants implements TenantStore.GetChildTenants
func (s *DatabaseTenantStore) GetChildTenants(ctx context.Context, parentID string) ([]*business.TenantData, error) {
	filter := &business.TenantFilter{
		ParentID: parentID,
	}
	return s.ListTenants(ctx, filter)
}

// GetTenantPath implements TenantStore.GetTenantPath
func (s *DatabaseTenantStore) GetTenantPath(ctx context.Context, tenantID string) ([]string, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	var path []string
	currentID := tenantID

	// Walk up the parent chain
	for currentID != "" {
		tenant, err := s.GetTenant(ctx, currentID)
		if err != nil {
			return nil, fmt.Errorf("failed to get tenant %s: %w", currentID, err)
		}

		// Prepend to path (building from child to root)
		path = append([]string{currentID}, path...)

		currentID = tenant.ParentID

		// Prevent infinite loops
		if len(path) > 100 {
			return nil, fmt.Errorf("tenant hierarchy depth exceeded (possible circular reference)")
		}
	}

	return path, nil
}

// IsTenantAncestor implements TenantStore.IsTenantAncestor
func (s *DatabaseTenantStore) IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error) {
	if ancestorID == "" || descendantID == "" {
		return false, fmt.Errorf("ancestor and descendant IDs cannot be empty")
	}

	// Get the path from descendant to root
	path, err := s.GetTenantPath(ctx, descendantID)
	if err != nil {
		return false, fmt.Errorf("failed to get tenant path: %w", err)
	}

	// Check if ancestorID is in the path
	for _, id := range path {
		if id == ancestorID {
			return true, nil
		}
	}

	return false, nil
}

// nullStringOrEmpty returns a sql.NullString that's NULL if the input is empty
func nullStringOrEmpty(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}
