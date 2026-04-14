// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite implements TenantStore using SQLite
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// SQLiteTenantStore implements interfaces.TenantStore using SQLite.
type SQLiteTenantStore struct {
	db *sql.DB
}

// Initialize is a no-op: schema is created in openAndInit before this store is returned.
func (s *SQLiteTenantStore) Initialize(ctx context.Context) error { return nil }

// Close closes the underlying database connection.
func (s *SQLiteTenantStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// CreateTenant persists a new tenant.
func (s *SQLiteTenantStore) CreateTenant(ctx context.Context, tenant *interfaces.TenantData) error {
	if tenant == nil {
		return fmt.Errorf("tenant cannot be nil")
	}
	if tenant.ID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	now := nowUTC()
	if tenant.CreatedAt.IsZero() {
		tenant.CreatedAt = now
	}
	if tenant.UpdatedAt.IsZero() {
		tenant.UpdatedAt = now
	}

	meta, err := marshalJSON(tenant.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal tenant metadata: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO tenants (id, name, description, parent_id, metadata, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		tenant.ID,
		tenant.Name,
		tenant.Description,
		nullString(tenant.ParentID),
		meta,
		string(tenant.Status),
		formatTime(tenant.CreatedAt),
		formatTime(tenant.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("failed to create tenant %s: %w", tenant.ID, err)
	}
	return nil
}

// GetTenant retrieves a tenant by ID.
func (s *SQLiteTenantStore) GetTenant(ctx context.Context, tenantID string) (*interfaces.TenantData, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, description, parent_id, metadata, status, created_at, updated_at
		FROM tenants WHERE id = ?`, tenantID)

	return scanTenant(row)
}

// UpdateTenant replaces all mutable fields of an existing tenant.
func (s *SQLiteTenantStore) UpdateTenant(ctx context.Context, tenant *interfaces.TenantData) error {
	if tenant == nil {
		return fmt.Errorf("tenant cannot be nil")
	}
	if tenant.ID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	tenant.UpdatedAt = nowUTC()

	meta, err := marshalJSON(tenant.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal tenant metadata: %w", err)
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE tenants
		SET name = ?, description = ?, parent_id = ?, metadata = ?, status = ?, updated_at = ?
		WHERE id = ?`,
		tenant.Name,
		tenant.Description,
		nullString(tenant.ParentID),
		meta,
		string(tenant.Status),
		formatTime(tenant.UpdatedAt),
		tenant.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update tenant %s: %w", tenant.ID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("tenant %s not found", tenant.ID)
	}
	return nil
}

// DeleteTenant removes a tenant by ID.
func (s *SQLiteTenantStore) DeleteTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	res, err := s.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = ?`, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete tenant %s: %w", tenantID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("tenant %s not found", tenantID)
	}
	return nil
}

// ListTenants returns tenants matching the optional filter.
func (s *SQLiteTenantStore) ListTenants(ctx context.Context, filter *interfaces.TenantFilter) ([]*interfaces.TenantData, error) {
	query := `SELECT id, name, description, parent_id, metadata, status, created_at, updated_at FROM tenants WHERE 1=1`
	args := []interface{}{}

	if filter != nil {
		if filter.ParentID != "" {
			query += ` AND parent_id = ?`
			args = append(args, filter.ParentID)
		}
		if filter.Status != "" {
			query += ` AND status = ?`
			args = append(args, string(filter.Status))
		}
		if filter.Name != "" {
			query += ` AND LOWER(name) LIKE LOWER(?)`
			args = append(args, "%"+filter.Name+"%")
		}
	}

	query += ` ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tenants []*interfaces.TenantData
	for rows.Next() {
		t, err := scanTenantRow(rows)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, t)
	}
	return tenants, rows.Err()
}

// GetTenantHierarchy returns the hierarchy (path, depth, direct children) for a tenant.
func (s *SQLiteTenantStore) GetTenantHierarchy(ctx context.Context, tenantID string) (*interfaces.TenantHierarchy, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	path, err := s.GetTenantPath(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	children, err := s.GetChildTenants(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	childIDs := make([]string, len(children))
	for i, c := range children {
		childIDs[i] = c.ID
	}

	return &interfaces.TenantHierarchy{
		TenantID: tenantID,
		Path:     path,
		Depth:    len(path) - 1,
		Children: childIDs,
	}, nil
}

// GetChildTenants returns direct children of the given parent.
func (s *SQLiteTenantStore) GetChildTenants(ctx context.Context, parentID string) ([]*interfaces.TenantData, error) {
	return s.ListTenants(ctx, &interfaces.TenantFilter{ParentID: parentID})
}

// GetTenantPath returns the path from root to the specified tenant (root first).
func (s *SQLiteTenantStore) GetTenantPath(ctx context.Context, tenantID string) ([]string, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	var path []string
	current := tenantID

	for current != "" {
		t, err := s.GetTenant(ctx, current)
		if err != nil {
			return nil, err
		}
		path = append([]string{current}, path...)
		current = t.ParentID

		if len(path) > 100 {
			return nil, fmt.Errorf("tenant hierarchy depth exceeded (possible circular reference)")
		}
	}
	return path, nil
}

// IsTenantAncestor returns true if ancestorID is an ancestor of descendantID.
func (s *SQLiteTenantStore) IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error) {
	if ancestorID == "" || descendantID == "" {
		return false, fmt.Errorf("ancestor and descendant IDs cannot be empty")
	}
	path, err := s.GetTenantPath(ctx, descendantID)
	if err != nil {
		return false, err
	}
	for _, id := range path {
		if id == ancestorID {
			return true, nil
		}
	}
	return false, nil
}

// scanTenant scans a single Row (QueryRow) into a TenantData.
func scanTenant(row *sql.Row) (*interfaces.TenantData, error) {
	var t interfaces.TenantData
	var parentID sql.NullString
	var metaStr, statusStr, createdStr, updatedStr string

	err := row.Scan(
		&t.ID, &t.Name, &t.Description,
		&parentID, &metaStr, &statusStr,
		&createdStr, &updatedStr,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("tenant not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan tenant: %w", err)
	}

	return populateTenant(&t, parentID, metaStr, statusStr, createdStr, updatedStr)
}

// scanTenantRow scans a Rows (Query) into a TenantData.
func scanTenantRow(rows *sql.Rows) (*interfaces.TenantData, error) {
	var t interfaces.TenantData
	var parentID sql.NullString
	var metaStr, statusStr, createdStr, updatedStr string

	if err := rows.Scan(
		&t.ID, &t.Name, &t.Description,
		&parentID, &metaStr, &statusStr,
		&createdStr, &updatedStr,
	); err != nil {
		return nil, fmt.Errorf("failed to scan tenant row: %w", err)
	}

	return populateTenant(&t, parentID, metaStr, statusStr, createdStr, updatedStr)
}

func populateTenant(t *interfaces.TenantData, parentID sql.NullString, metaStr, statusStr, createdStr, updatedStr string) (*interfaces.TenantData, error) {
	if parentID.Valid {
		t.ParentID = parentID.String
	}
	t.Status = interfaces.TenantStatus(statusStr)
	t.CreatedAt = parseTime(createdStr)
	t.UpdatedAt = parseTime(updatedStr)

	meta, err := unmarshalJSONMap(metaStr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tenant metadata: %w", err)
	}
	// Convert map[string]interface{} to map[string]string
	t.Metadata = make(map[string]string, len(meta))
	for k, v := range meta {
		if sv, ok := v.(string); ok {
			t.Metadata[k] = sv
		} else {
			t.Metadata[k] = fmt.Sprintf("%v", v)
		}
	}

	return t, nil
}

// ensure SQLiteTenantStore satisfies the interface at compile time
var _ interfaces.TenantStore = (*SQLiteTenantStore)(nil)

// nowForTenant returns current time (extracted so tests can verify timestamps are recent)
func nowForTenant() time.Time { return nowUTC() }
