// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements RefreshPolicyStore using PostgreSQL (Issue #2329).
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
var _ business.RefreshPolicyStore = (*DatabaseRefreshPolicyStore)(nil)

// DatabaseRefreshPolicyStore implements business.RefreshPolicyStore using PostgreSQL.
type DatabaseRefreshPolicyStore struct {
	db *sql.DB
}

// NewDatabaseRefreshPolicyStore opens a pooled Postgres connection, initialises
// the schema, and returns a ready-to-use RefreshPolicyStore.
func NewDatabaseRefreshPolicyStore(dsn string, config map[string]interface{}) (*DatabaseRefreshPolicyStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("database: failed to open refresh policy store connection: %w", err)
	}
	db.SetMaxOpenConns(getIntFromConfig(config, "max_open_connections", 25))
	db.SetMaxIdleConns(getIntFromConfig(config, "max_idle_connections", 5))
	db.SetConnMaxLifetime(time.Duration(getIntFromConfig(config, "connection_max_lifetime_minutes", 30)) * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to ping refresh policy store: %w", err)
	}
	store := &DatabaseRefreshPolicyStore{db: db}
	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to initialise refresh policy schema: %w", err)
	}
	return store, nil
}

func (s *DatabaseRefreshPolicyStore) initSchema() error {
	ctx := context.Background()
	const lockID = 53781294 // advisory lock ID unique to refresh_policies schema
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("database: failed to acquire refresh policy schema lock: %w", err)
	}
	defer func() { _, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID) }()
	return NewDatabaseSchemas().CreateRefreshPoliciesTable(ctx, s.db)
}

// Close releases the database connection.
func (s *DatabaseRefreshPolicyStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// GetPolicy returns the refresh policy for the given tenant. When no record
// exists it returns a default policy of {Mode: "require_approval",
// MaxDormancyDays: nil} without error (ADR-010 §4).
func (s *DatabaseRefreshPolicyStore) GetPolicy(ctx context.Context, tenantID string) (*business.RefreshPolicy, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT tenant_id, mode, max_dormancy_days
		FROM refresh_policies WHERE tenant_id = $1`, tenantID)

	p := &business.RefreshPolicy{}
	var maxDormancy sql.NullInt64
	err := row.Scan(&p.TenantID, &p.Mode, &maxDormancy)
	if err == sql.ErrNoRows {
		return &business.RefreshPolicy{
			TenantID:        tenantID,
			Mode:            "require_approval",
			MaxDormancyDays: nil,
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to get refresh policy for tenant %s: %w", tenantID, err)
	}
	if maxDormancy.Valid {
		v := int(maxDormancy.Int64)
		p.MaxDormancyDays = &v
	}
	return p, nil
}

// SetPolicy creates or replaces the refresh policy for the tenant identified by
// policy.TenantID using upsert semantics.
func (s *DatabaseRefreshPolicyStore) SetPolicy(ctx context.Context, policy *business.RefreshPolicy) error {
	if policy == nil {
		return fmt.Errorf("database: policy cannot be nil")
	}
	if policy.TenantID == "" {
		return fmt.Errorf("database: policy tenant_id cannot be empty")
	}

	var maxDormancy interface{}
	if policy.MaxDormancyDays != nil {
		maxDormancy = *policy.MaxDormancyDays
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO refresh_policies (tenant_id, mode, max_dormancy_days)
		VALUES ($1, $2, $3)
		ON CONFLICT(tenant_id) DO UPDATE SET
			mode              = EXCLUDED.mode,
			max_dormancy_days = EXCLUDED.max_dormancy_days`,
		policy.TenantID,
		policy.Mode,
		maxDormancy,
	)
	if err != nil {
		return fmt.Errorf("database: failed to set refresh policy for tenant %s: %w", policy.TenantID, err)
	}
	return nil
}
