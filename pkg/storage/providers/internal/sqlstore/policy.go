// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlstore

import (
	"context"
	"database/sql"
	"fmt"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// PolicyLabels supplies the provider-specific text of GetPolicy errors:
// "<Prefix>failed to get <Noun> for tenant <id>: <err>" and the scan/iterate variants.
// Prefix is "database: " or "sqlite: "; Noun is e.g. "assurance policy".
type PolicyLabels struct {
	Prefix string
	Noun   string
}

// GetPolicy runs a tenant-scoped query (the caller supplies dialect SQL whose single
// parameter is the tenant ID), decodes every row with scan, and builds the policy with
// build. A tenant with no rows yields build(tenantID, nil), never an error.
// It is generic over the override type O and the policy type P so every per-tenant policy
// store can use it.
func GetPolicy[O, P any](ctx context.Context, db *sql.DB, query, tenantID string, lbl PolicyLabels,
	scan func(*sql.Rows) (O, error), build func(tenantID string, overrides []O) *P) (*P, error) {
	rows, err := db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("%sfailed to get %s for tenant %s: %w", lbl.Prefix, lbl.Noun, tenantID, err)
	}
	defer func() { _ = rows.Close() }()

	var overrides []O
	for rows.Next() {
		o, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("%sfailed to scan %s row for tenant %s: %w", lbl.Prefix, lbl.Noun, tenantID, err)
		}
		overrides = append(overrides, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%sfailed to iterate %s rows for tenant %s: %w", lbl.Prefix, lbl.Noun, tenantID, err)
	}
	return build(tenantID, overrides), nil
}

// ScanAssuranceOverride decodes one (permission_id, min_override, require_user_presence) row.
func ScanAssuranceOverride(rows *sql.Rows) (business.AssurancePolicyOverride, error) {
	var o business.AssurancePolicyOverride
	var minOverride sql.NullInt64
	if err := rows.Scan(&o.PermissionID, &minOverride, &o.RequireUserPresence); err != nil {
		return o, err
	}
	if minOverride.Valid {
		v := int(minOverride.Int64)
		o.MinOverride = &v
	}
	return o, nil
}

// BuildAssurancePolicy assembles the policy returned by GetPolicy.
func BuildAssurancePolicy(tenantID string, overrides []business.AssurancePolicyOverride) *business.AssurancePolicy {
	return &business.AssurancePolicy{TenantID: tenantID, Overrides: overrides}
}
