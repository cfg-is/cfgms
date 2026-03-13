// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// ErrCrossTenantAccessDenied is returned when attempting to access a resource from a different tenant
var ErrCrossTenantAccessDenied = errors.New("cross-tenant access denied")

// DatabaseRBACStore implements RBACStore using PostgreSQL for persistence
type DatabaseRBACStore struct {
	db      *sql.DB
	config  map[string]interface{}
	mutex   sync.RWMutex
	schemas DatabaseSchemas
}

// NewDatabaseRBACStore creates a new PostgreSQL-based RBAC store
func NewDatabaseRBACStore(dsn string, config map[string]interface{}) (*DatabaseRBACStore, error) {
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

	store := &DatabaseRBACStore{
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

// initializeSchema creates the necessary database tables and indexes for RBAC
func (s *DatabaseRBACStore) initializeSchema() error {
	ctx := context.Background()

	// Use PostgreSQL advisory lock to prevent concurrent schema initialization
	// Lock ID: 13579246 (different from other store locks)
	const schemaLockID = 13579246

	// Acquire advisory lock - will wait if another instance is initializing
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", schemaLockID); err != nil {
		return fmt.Errorf("failed to acquire RBAC schema initialization lock: %w", err)
	}

	// Ensure we release the lock when done
	defer func() {
		if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", schemaLockID); err != nil {
			// Log but don't fail - lock will be released when connection closes
			// This is non-critical since PostgreSQL will release advisory locks when connection closes
			_ = err // Explicitly ignore error to satisfy linter
		}
	}()

	// Create RBAC tables
	if err := s.schemas.CreateRBACTables(ctx, s.db); err != nil {
		return fmt.Errorf("failed to create RBAC tables: %w", err)
	}

	return nil
}

// Initialize implements RBACStore.Initialize
func (s *DatabaseRBACStore) Initialize(ctx context.Context) error {
	return s.initializeSchema()
}

// Close implements RBACStore.Close
func (s *DatabaseRBACStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// H-TENANT-1: Tenant boundary validation helper (security audit finding)
// validateTenantAccess checks if the authenticated tenant matches the resource's tenant
// System roles are allowed to bypass tenant validation
func (s *DatabaseRBACStore) validateTenantAccess(ctx context.Context, resourceTenantID string, isSystemResource bool) error {
	// System resources (is_system_role=true, etc.) can be accessed by any tenant
	if isSystemResource {
		return nil
	}

	// Extract authenticated tenant ID from context
	authTenantIDValue := ctx.Value("tenant_id")
	if authTenantIDValue == nil {
		// If no tenant_id in context, allow operation (backwards compatibility)
		// This supports operations from internal system components
		return nil
	}

	authTenantID, ok := authTenantIDValue.(string)
	if !ok {
		return fmt.Errorf("invalid tenant_id type in context")
	}

	// H-TENANT-1: Block cross-tenant access (security audit finding)
	if authTenantID != resourceTenantID {
		return fmt.Errorf("%w: authenticated tenant=%s, resource tenant=%s",
			ErrCrossTenantAccessDenied, authTenantID, resourceTenantID)
	}

	return nil
}

// M-TENANT-1: RLS helper functions
// These functions will be used when integrating RLS into database operations.
// Currently unused but documented in migrations/003_enable_rls.sql
// Example usage:
//
//	err := s.withTenantContext(ctx, tenantID, func(ctx context.Context, tx *sql.Tx) error {
//	    // Perform database operations with RLS enforced
//	    return nil
//	})
