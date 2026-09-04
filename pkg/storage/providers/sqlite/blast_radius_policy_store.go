// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite implements BlastRadiusPolicyStore using the
// blast_radius_policy_overrides table (Issue #3698).
package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.BlastRadiusPolicyStore = (*SQLiteBlastRadiusPolicyStore)(nil)

// SQLiteBlastRadiusPolicyStore implements business.BlastRadiusPolicyStore using a
// SQLite database backed by the blast_radius_policy_overrides table.
type SQLiteBlastRadiusPolicyStore struct {
	db *sql.DB
}

// Close closes the underlying database connection.
func (s *SQLiteBlastRadiusPolicyStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// GetPolicy returns the blast-radius override for the given tenant. When no row
// exists, it returns {TenantID: tenantID, MaxTargets: nil} without error — "no
// override" and "no data" are equivalent (Issue #3698).
func (s *SQLiteBlastRadiusPolicyStore) GetPolicy(ctx context.Context, tenantID string) (*business.BlastRadiusPolicy, error) {
	var maxTargets sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT max_targets
		FROM blast_radius_policy_overrides
		WHERE tenant_id = ?`, tenantID).Scan(&maxTargets)
	if err == sql.ErrNoRows {
		return &business.BlastRadiusPolicy{TenantID: tenantID, MaxTargets: nil}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to get blast radius policy for tenant %s: %w", tenantID, err)
	}

	policy := &business.BlastRadiusPolicy{TenantID: tenantID}
	if maxTargets.Valid {
		v := int(maxTargets.Int64)
		policy.MaxTargets = &v
	}
	return policy, nil
}

// SetPolicy replaces the tenant's MaxTargets override (upsert semantics).
func (s *SQLiteBlastRadiusPolicyStore) SetPolicy(ctx context.Context, policy *business.BlastRadiusPolicy) error {
	if policy == nil {
		return fmt.Errorf("sqlite: blast radius policy cannot be nil")
	}
	if policy.TenantID == "" {
		return fmt.Errorf("sqlite: blast radius policy tenant_id cannot be empty")
	}

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO blast_radius_policy_overrides (tenant_id, max_targets)
		VALUES (?, ?)
		ON CONFLICT (tenant_id) DO UPDATE SET max_targets = excluded.max_targets`,
		policy.TenantID, nullableInt(policy.MaxTargets),
	); err != nil {
		return fmt.Errorf("sqlite: failed to upsert blast radius policy for tenant %s: %w", policy.TenantID, err)
	}
	return nil
}
