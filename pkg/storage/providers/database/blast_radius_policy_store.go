// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements BlastRadiusPolicyStore using PostgreSQL (Issue #3698).
package database

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.BlastRadiusPolicyStore = (*DatabaseBlastRadiusPolicyStore)(nil)

// DatabaseBlastRadiusPolicyStore implements business.BlastRadiusPolicyStore using PostgreSQL.
type DatabaseBlastRadiusPolicyStore struct {
	db *sql.DB
}

// NewDatabaseBlastRadiusPolicyStore opens a pooled Postgres connection, initialises
// the schema, and returns a ready-to-use BlastRadiusPolicyStore.
func NewDatabaseBlastRadiusPolicyStore(db *sql.DB, config map[string]interface{}) (*DatabaseBlastRadiusPolicyStore, error) {
	store := &DatabaseBlastRadiusPolicyStore{db: db}
	if err := store.initSchema(); err != nil {
		return nil, fmt.Errorf("database: failed to initialise blast radius policy schema: %w", err)
	}
	return store, nil
}

func (s *DatabaseBlastRadiusPolicyStore) initSchema() error {
	ctx := context.Background()
	const lockID = 53781296 // advisory lock ID unique to blast_radius_policy_overrides schema
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("database: failed to acquire blast radius policy schema lock: %w", err)
	}
	defer func() { _, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID) }()
	return NewDatabaseSchemas().CreateBlastRadiusPolicyOverridesTable(ctx, s.db)
}

// Close releases the database connection.
// Close is a no-op: the underlying connection pool is owned and closed by
// DatabaseProvider, not by individual stores (ADR-031 Decision 6).
func (s *DatabaseBlastRadiusPolicyStore) Close() error {
	return nil
}

// GetPolicy returns the blast-radius override for the given tenant. When no row
// exists, it returns {TenantID: tenantID, MaxTargets: nil} without error — "no
// override" and "no data" are equivalent (Issue #3698).
func (s *DatabaseBlastRadiusPolicyStore) GetPolicy(ctx context.Context, tenantID string) (*business.BlastRadiusPolicy, error) {
	var maxTargets sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT max_targets
		FROM blast_radius_policy_overrides
		WHERE tenant_id = $1`, tenantID).Scan(&maxTargets)
	if err == sql.ErrNoRows {
		return &business.BlastRadiusPolicy{TenantID: tenantID, MaxTargets: nil}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to get blast radius policy for tenant %s: %w", tenantID, err)
	}

	policy := &business.BlastRadiusPolicy{TenantID: tenantID}
	if maxTargets.Valid {
		v := int(maxTargets.Int64)
		policy.MaxTargets = &v
	}
	return policy, nil
}

// SetPolicy replaces the tenant's MaxTargets override (upsert semantics).
func (s *DatabaseBlastRadiusPolicyStore) SetPolicy(ctx context.Context, policy *business.BlastRadiusPolicy) error {
	if policy == nil {
		return fmt.Errorf("database: blast radius policy cannot be nil")
	}
	if policy.TenantID == "" {
		return fmt.Errorf("database: blast radius policy tenant_id cannot be empty")
	}

	var maxTargets interface{}
	if policy.MaxTargets != nil {
		maxTargets = *policy.MaxTargets
	}

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO blast_radius_policy_overrides (tenant_id, max_targets)
		VALUES ($1, $2)
		ON CONFLICT (tenant_id) DO UPDATE SET max_targets = EXCLUDED.max_targets`,
		policy.TenantID, maxTargets,
	); err != nil {
		return fmt.Errorf("database: failed to upsert blast radius policy for tenant %s: %w", policy.TenantID, err)
	}
	return nil
}
