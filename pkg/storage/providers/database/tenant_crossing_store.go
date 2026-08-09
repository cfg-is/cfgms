// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements TenantCrossingStore using PostgreSQL (ADR-025 Decision 2).
package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.TenantCrossingStore = (*DatabaseTenantCrossingStore)(nil)

// DatabaseTenantCrossingStore implements business.TenantCrossingStore using PostgreSQL.
type DatabaseTenantCrossingStore struct {
	db *sql.DB
}

// NewDatabaseTenantCrossingStore opens a pooled Postgres connection, initialises the
// schema, and returns a ready-to-use TenantCrossingStore.
func NewDatabaseTenantCrossingStore(dsn string, config map[string]interface{}) (*DatabaseTenantCrossingStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("database: failed to open tenant crossing store connection: %w", err)
	}
	db.SetMaxOpenConns(getIntFromConfig(config, "max_open_connections", 25))
	db.SetMaxIdleConns(getIntFromConfig(config, "max_idle_connections", 5))
	db.SetConnMaxLifetime(time.Duration(getIntFromConfig(config, "connection_max_lifetime_minutes", 30)) * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to ping tenant crossing store: %w", err)
	}
	store := &DatabaseTenantCrossingStore{db: db}
	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to initialise tenant crossing schema: %w", err)
	}
	return store, nil
}

func (s *DatabaseTenantCrossingStore) initSchema() error {
	ctx := context.Background()
	const lockID = 71934862 // advisory lock ID unique to tenant_crossings schema
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("database: failed to acquire tenant crossing schema lock: %w", err)
	}
	defer func() { _, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID) }()
	return NewDatabaseSchemas().CreateTenantCrossingsTable(ctx, s.db)
}

// Initialize is a no-op: the schema is created in NewDatabaseTenantCrossingStore.
func (s *DatabaseTenantCrossingStore) Initialize(ctx context.Context) error { return nil }

// Close releases the database connection.
func (s *DatabaseTenantCrossingStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// CreateTenantCrossing persists a new grant or break-glass record.
func (s *DatabaseTenantCrossingStore) CreateTenantCrossing(ctx context.Context, c *business.TenantCrossing) error {
	if c == nil {
		return fmt.Errorf("database: tenant crossing cannot be nil")
	}
	if c.ID == "" || c.TenantID == "" || c.PrincipalID == "" {
		return fmt.Errorf("database: tenant crossing ID, tenant ID, and principal ID are required")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tenant_crossings (id, tenant_id, principal_id, kind, granted_by, justification, created_at, expires_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.ID, c.TenantID, c.PrincipalID, string(c.Kind), c.GrantedBy, c.Justification,
		c.CreatedAt, c.ExpiresAt, c.RevokedAt,
	)
	if err != nil {
		return fmt.Errorf("database: failed to create tenant crossing %s: %w", c.ID, err)
	}
	return nil
}

// GetTenantCrossing retrieves a crossing by ID.
func (s *DatabaseTenantCrossingStore) GetTenantCrossing(ctx context.Context, id string) (*business.TenantCrossing, error) {
	if id == "" {
		return nil, fmt.Errorf("database: tenant crossing ID cannot be empty")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, principal_id, kind, granted_by, justification, created_at, expires_at, revoked_at
		FROM tenant_crossings WHERE id = $1`, id)
	return scanDatabaseTenantCrossing(row)
}

// ListTenantCrossings returns every crossing scoped to tenantID, newest first.
func (s *DatabaseTenantCrossingStore) ListTenantCrossings(ctx context.Context, tenantID string) ([]*business.TenantCrossing, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("database: tenant ID cannot be empty")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, principal_id, kind, granted_by, justification, created_at, expires_at, revoked_at
		FROM tenant_crossings WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("database: failed to list tenant crossings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*business.TenantCrossing
	for rows.Next() {
		c, err := scanDatabaseTenantCrossingRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// HasActiveTenantCrossing reports whether principalID currently holds a non-expired,
// non-revoked crossing for exactly tenantID.
func (s *DatabaseTenantCrossingStore) HasActiveTenantCrossing(ctx context.Context, principalID, tenantID string) (bool, error) {
	if principalID == "" || tenantID == "" {
		return false, fmt.Errorf("database: principal ID and tenant ID cannot be empty")
	}
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(1) FROM tenant_crossings
		WHERE principal_id = $1 AND tenant_id = $2 AND revoked_at IS NULL AND expires_at > now()`,
		principalID, tenantID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("database: failed to check active tenant crossing: %w", err)
	}
	return count > 0, nil
}

// RevokeTenantCrossing marks a crossing revoked immediately, regardless of ExpiresAt.
func (s *DatabaseTenantCrossingStore) RevokeTenantCrossing(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("database: tenant crossing ID cannot be empty")
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE tenant_crossings SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("database: failed to revoke tenant crossing %s: %w", id, err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("database: failed to get rows affected: %w", err)
	}
	if n == 0 {
		// Either the ID doesn't exist, or it does but was already revoked — confirm which.
		if _, getErr := s.GetTenantCrossing(ctx, id); getErr != nil {
			return getErr
		}
		return nil // already revoked: idempotent
	}
	return nil
}

func scanDatabaseTenantCrossing(row *sql.Row) (*business.TenantCrossing, error) {
	var c business.TenantCrossing
	var kind string
	var revokedAt sql.NullTime
	err := row.Scan(&c.ID, &c.TenantID, &c.PrincipalID, &kind, &c.GrantedBy, &c.Justification, &c.CreatedAt, &c.ExpiresAt, &revokedAt)
	if err == sql.ErrNoRows {
		return nil, business.ErrTenantCrossingNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to scan tenant crossing: %w", err)
	}
	c.Kind = business.TenantCrossingKind(kind)
	if revokedAt.Valid {
		t := revokedAt.Time
		c.RevokedAt = &t
	}
	return &c, nil
}

func scanDatabaseTenantCrossingRow(rows *sql.Rows) (*business.TenantCrossing, error) {
	var c business.TenantCrossing
	var kind string
	var revokedAt sql.NullTime
	if err := rows.Scan(&c.ID, &c.TenantID, &c.PrincipalID, &kind, &c.GrantedBy, &c.Justification, &c.CreatedAt, &c.ExpiresAt, &revokedAt); err != nil {
		return nil, fmt.Errorf("database: failed to scan tenant crossing row: %w", err)
	}
	c.Kind = business.TenantCrossingKind(kind)
	if revokedAt.Valid {
		t := revokedAt.Time
		c.RevokedAt = &t
	}
	return &c, nil
}
