// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite implements RefreshPolicyStore using the refresh_policies table
// (ADR-010 §4, Issue #2093).
package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.RefreshPolicyStore = (*SQLiteRefreshPolicyStore)(nil)

// SQLiteRefreshPolicyStore implements business.RefreshPolicyStore using a
// SQLite database backed by the refresh_policies table.
type SQLiteRefreshPolicyStore struct {
	db *sql.DB
}

// Close closes the underlying database connection.
func (s *SQLiteRefreshPolicyStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// GetPolicy returns the refresh policy for the given tenant. When no record
// exists, it returns a default policy of {Mode: "require_approval",
// MaxDormancyDays: nil} without error (ADR-010 §4).
func (s *SQLiteRefreshPolicyStore) GetPolicy(ctx context.Context, tenantID string) (*business.RefreshPolicy, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT tenant_id, mode, max_dormancy_days
		FROM refresh_policies WHERE tenant_id = ?`, tenantID)

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
		return nil, fmt.Errorf("sqlite: failed to get refresh policy for tenant %s: %w", tenantID, err)
	}
	if maxDormancy.Valid {
		v := int(maxDormancy.Int64)
		p.MaxDormancyDays = &v
	}
	return p, nil
}

// SetPolicy creates or replaces the refresh policy for the tenant identified
// by policy.TenantID. Uses SQLite upsert semantics.
func (s *SQLiteRefreshPolicyStore) SetPolicy(ctx context.Context, policy *business.RefreshPolicy) error {
	if policy == nil {
		return fmt.Errorf("sqlite: policy cannot be nil")
	}
	if policy.TenantID == "" {
		return fmt.Errorf("sqlite: policy tenant_id cannot be empty")
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO refresh_policies (tenant_id, mode, max_dormancy_days)
		VALUES (?, ?, ?)
		ON CONFLICT(tenant_id) DO UPDATE SET
			mode              = excluded.mode,
			max_dormancy_days = excluded.max_dormancy_days`,
		policy.TenantID,
		policy.Mode,
		nullableInt(policy.MaxDormancyDays),
	)
	if err != nil {
		return fmt.Errorf("sqlite: failed to set refresh policy for tenant %s: %w", policy.TenantID, err)
	}
	return nil
}

// nullableInt converts a *int to a value suitable for binding as a nullable
// INTEGER column: nil pointers produce SQL NULL.
func nullableInt(v *int) interface{} {
	if v == nil {
		return nil
	}
	return *v
}
