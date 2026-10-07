// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite implements AssurancePolicyStore using the assurance_policy_overrides
// table (ADR-021, Issue #2845).
package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.AssurancePolicyStore = (*SQLiteAssurancePolicyStore)(nil)

// SQLiteAssurancePolicyStore implements business.AssurancePolicyStore using a
// SQLite database backed by the assurance_policy_overrides table.
type SQLiteAssurancePolicyStore struct {
	db *sql.DB
}

// Close closes the underlying database connection.
func (s *SQLiteAssurancePolicyStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// GetPolicy returns the assurance-policy overrides for the given tenant. When no
// rows exist, it returns {TenantID: tenantID, Overrides: nil} without error —
// "no override" and "no data" are equivalent (ADR-021, Issue #2845).
func (s *SQLiteAssurancePolicyStore) GetPolicy(ctx context.Context, tenantID string) (*business.AssurancePolicy, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT permission_id, min_override, require_user_presence
		FROM assurance_policy_overrides
		WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to get assurance policy for tenant %s: %w", tenantID, err)
	}
	defer func() { _ = rows.Close() }()

	var overrides []business.AssurancePolicyOverride
	for rows.Next() {
		var o business.AssurancePolicyOverride
		var minOverride sql.NullInt64
		if err := rows.Scan(&o.PermissionID, &minOverride, &o.RequireUserPresence); err != nil {
			return nil, fmt.Errorf("sqlite: failed to scan assurance policy row for tenant %s: %w", tenantID, err)
		}
		if minOverride.Valid {
			v := int(minOverride.Int64)
			o.MinOverride = &v
		}
		overrides = append(overrides, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: failed to iterate assurance policy rows for tenant %s: %w", tenantID, err)
	}

	return &business.AssurancePolicy{TenantID: tenantID, Overrides: overrides}, nil
}

// SetPolicy replaces the tenant's full assurance-policy override set in one
// transaction (delete all existing rows for the tenant, then insert the new set).
func (s *SQLiteAssurancePolicyStore) SetPolicy(ctx context.Context, policy *business.AssurancePolicy) error {
	if policy == nil {
		return fmt.Errorf("sqlite: assurance policy cannot be nil")
	}
	if policy.TenantID == "" {
		return fmt.Errorf("sqlite: assurance policy tenant_id cannot be empty")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: failed to begin assurance policy transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM assurance_policy_overrides WHERE tenant_id = ?`,
		policy.TenantID,
	); err != nil {
		return fmt.Errorf("sqlite: failed to delete existing assurance policy overrides for tenant %s: %w", policy.TenantID, err)
	}

	for _, o := range policy.Overrides {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO assurance_policy_overrides (tenant_id, permission_id, min_override, require_user_presence)
			VALUES (?, ?, ?, ?)`,
			policy.TenantID, o.PermissionID, nullableInt(o.MinOverride), o.RequireUserPresence,
		); err != nil {
			return fmt.Errorf("sqlite: failed to insert assurance policy override for tenant %s permission %s: %w",
				policy.TenantID, o.PermissionID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: failed to commit assurance policy transaction for tenant %s: %w", policy.TenantID, err)
	}
	return nil
}
