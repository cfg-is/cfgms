// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements AssurancePolicyStore using PostgreSQL (Issue #2845).
package database

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.AssurancePolicyStore = (*DatabaseAssurancePolicyStore)(nil)

// DatabaseAssurancePolicyStore implements business.AssurancePolicyStore using PostgreSQL.
type DatabaseAssurancePolicyStore struct {
	db *sql.DB
}

// NewDatabaseAssurancePolicyStore opens a pooled Postgres connection, initialises
// the schema, and returns a ready-to-use AssurancePolicyStore.
func NewDatabaseAssurancePolicyStore(db *sql.DB, config map[string]interface{}) (*DatabaseAssurancePolicyStore, error) {
	store := &DatabaseAssurancePolicyStore{db: db}
	if err := store.initSchema(); err != nil {
		return nil, fmt.Errorf("database: failed to initialise assurance policy schema: %w", err)
	}
	return store, nil

}

func (s *DatabaseAssurancePolicyStore) initSchema() error {
	ctx := context.Background()
	const lockID = 53781295 // advisory lock ID unique to assurance_policy_overrides schema
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("database: failed to acquire assurance policy schema lock: %w", err)
	}
	defer func() { _, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID) }()
	return NewDatabaseSchemas().CreateAssurancePolicyOverridesTable(ctx, s.db)
}

// Close releases the database connection.
// Close is a no-op: the underlying connection pool is owned and closed by
// DatabaseProvider, not by individual stores (ADR-031 Decision 6).
func (s *DatabaseAssurancePolicyStore) Close() error {
	return nil
}

// GetPolicy returns the assurance-policy overrides for the given tenant. When no
// rows exist for the tenant, it returns {TenantID: tenantID, Overrides: nil}
// without error — "no override" and "no data" are equivalent (ADR-021, Issue #2845).
func (s *DatabaseAssurancePolicyStore) GetPolicy(ctx context.Context, tenantID string) (*business.AssurancePolicy, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT permission_id, min_override, require_user_presence
		FROM assurance_policy_overrides
		WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("database: failed to get assurance policy for tenant %s: %w", tenantID, err)
	}
	defer func() { _ = rows.Close() }()

	var overrides []business.AssurancePolicyOverride
	for rows.Next() {
		var o business.AssurancePolicyOverride
		var minOverride sql.NullInt64
		if err := rows.Scan(&o.PermissionID, &minOverride, &o.RequireUserPresence); err != nil {
			return nil, fmt.Errorf("database: failed to scan assurance policy row for tenant %s: %w", tenantID, err)
		}
		if minOverride.Valid {
			v := int(minOverride.Int64)
			o.MinOverride = &v
		}
		overrides = append(overrides, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("database: failed to iterate assurance policy rows for tenant %s: %w", tenantID, err)
	}

	return &business.AssurancePolicy{TenantID: tenantID, Overrides: overrides}, nil
}

// SetPolicy replaces the tenant's full assurance-policy override set in one
// transaction (delete all existing rows for the tenant, then insert the new set).
func (s *DatabaseAssurancePolicyStore) SetPolicy(ctx context.Context, policy *business.AssurancePolicy) error {
	if policy == nil {
		return fmt.Errorf("database: assurance policy cannot be nil")
	}
	if policy.TenantID == "" {
		return fmt.Errorf("database: assurance policy tenant_id cannot be empty")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: failed to begin assurance policy transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM assurance_policy_overrides WHERE tenant_id = $1`,
		policy.TenantID,
	); err != nil {
		return fmt.Errorf("database: failed to delete existing assurance policy overrides for tenant %s: %w", policy.TenantID, err)
	}

	for _, o := range policy.Overrides {
		var minOverride interface{}
		if o.MinOverride != nil {
			minOverride = *o.MinOverride
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO assurance_policy_overrides (tenant_id, permission_id, min_override, require_user_presence)
			VALUES ($1, $2, $3, $4)`,
			policy.TenantID, o.PermissionID, minOverride, o.RequireUserPresence,
		); err != nil {
			return fmt.Errorf("database: failed to insert assurance policy override for tenant %s permission %s: %w",
				policy.TenantID, o.PermissionID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("database: failed to commit assurance policy transaction for tenant %s: %w", policy.TenantID, err)
	}
	return nil
}
