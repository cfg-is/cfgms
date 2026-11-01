// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/internal/reporttemplate"
)

// Compile-time assertion.
var _ business.ReportTemplateStore = (*SQLiteReportTemplateStore)(nil)

// SQLiteReportTemplateStore implements business.ReportTemplateStore using the
// report_templates table. Every query is parameterized and scoped by tenant_id (owner
// access) or by a json_each match on the share list (recipient access); expiry and the
// final visibility decision are applied by the shared reporttemplate.ViewFor rule.
type SQLiteReportTemplateStore struct {
	db *sql.DB
}

// Close closes the underlying database connection.
func (s *SQLiteReportTemplateStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

const reportTemplateColumns = `id, tenant_id, name, description, definition, created_by, created_at,
	updated_at, is_shared, shared_with, tags, category, version, usage_count, last_used`

func scanReportTemplate(row interface{ Scan(...any) error }) (*business.ReportTemplate, error) {
	t := &business.ReportTemplate{}
	var definition, sharedWith, tags string
	var createdAt, updatedAt, lastUsed int64
	var isShared int
	if err := row.Scan(&t.ID, &t.TenantID, &t.Name, &t.Description, &definition, &t.CreatedBy,
		&createdAt, &updatedAt, &isShared, &sharedWith, &tags, &t.Category, &t.Version,
		&t.UsageCount, &lastUsed); err != nil {
		return nil, err
	}
	if definition != "" {
		t.Definition = json.RawMessage(definition)
	}
	t.CreatedAt = fromNanos(createdAt)
	t.UpdatedAt = fromNanos(updatedAt)
	t.IsShared = isShared != 0
	if lastUsed != 0 {
		lu := fromNanos(lastUsed)
		t.LastUsed = &lu
	}
	var err error
	if t.SharedWith, err = reporttemplate.DecodeShares(sharedWith); err != nil {
		return nil, err
	}
	if t.Tags, err = reporttemplate.DecodeTags(tags); err != nil {
		return nil, err
	}
	return t, nil
}

// Save implements business.ReportTemplateStore. The upsert only updates a row the saving
// tenant already owns; a conflicting row owned by another tenant affects zero rows.
func (s *SQLiteReportTemplateStore) Save(ctx context.Context, tenantID string, template *business.ReportTemplate) error {
	if err := reporttemplate.ValidateSave(tenantID, template); err != nil {
		return fmt.Errorf("sqlite: %w", err)
	}
	sharedWith, err := reporttemplate.EncodeShares(template.SharedWith)
	if err != nil {
		return fmt.Errorf("sqlite: %w", err)
	}
	tags, err := reporttemplate.EncodeTags(template.Tags)
	if err != nil {
		return fmt.Errorf("sqlite: %w", err)
	}
	var lastUsed int64
	if template.LastUsed != nil {
		lastUsed = nanos(*template.LastUsed)
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO report_templates (`+reportTemplateColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name, description = excluded.description, definition = excluded.definition,
			created_by = excluded.created_by, created_at = excluded.created_at,
			updated_at = excluded.updated_at, is_shared = excluded.is_shared,
			shared_with = excluded.shared_with, tags = excluded.tags, category = excluded.category,
			version = excluded.version, usage_count = excluded.usage_count, last_used = excluded.last_used
		WHERE report_templates.tenant_id = excluded.tenant_id`,
		template.ID, tenantID, template.Name, template.Description, string(template.Definition),
		template.CreatedBy, nanos(template.CreatedAt), nanos(template.UpdatedAt), boolInt(template.IsShared),
		sharedWith, tags, template.Category, template.Version, template.UsageCount, lastUsed)
	if err != nil {
		return fmt.Errorf("sqlite: failed to save report template: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return business.ErrReportTemplateExists
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// GetByID implements business.ReportTemplateStore.
func (s *SQLiteReportTemplateStore) GetByID(ctx context.Context, tenantID, id string) (*business.ReportTemplate, error) {
	if err := reporttemplate.ValidateTenant(tenantID); err != nil {
		return nil, fmt.Errorf("sqlite: %w", err)
	}
	if err := reporttemplate.ValidateID(id); err != nil {
		return nil, fmt.Errorf("sqlite: %w", err)
	}
	// The row is fetched by ID alone because a share recipient does not own it; the
	// tenant check is ViewFor, and the row is dropped here before it reaches the caller.
	t, err := scanReportTemplate(s.db.QueryRowContext(ctx,
		`SELECT `+reportTemplateColumns+` FROM report_templates WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, business.ErrReportTemplateNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to read report template: %w", err)
	}
	view, ok := reporttemplate.ViewFor(t, tenantID, time.Now())
	if !ok {
		return nil, business.ErrReportTemplateNotFound
	}
	return view, nil
}

// ListOwned implements business.ReportTemplateStore.
func (s *SQLiteReportTemplateStore) ListOwned(ctx context.Context, tenantID string) ([]*business.ReportTemplate, error) {
	if err := reporttemplate.ValidateTenant(tenantID); err != nil {
		return nil, fmt.Errorf("sqlite: %w", err)
	}
	return s.query(ctx, tenantID, `SELECT `+reportTemplateColumns+` FROM report_templates WHERE tenant_id = ?`, tenantID)
}

// ListSharedWith implements business.ReportTemplateStore.
func (s *SQLiteReportTemplateStore) ListSharedWith(ctx context.Context, tenantID string) ([]*business.ReportTemplate, error) {
	if err := reporttemplate.ValidateTenant(tenantID); err != nil {
		return nil, fmt.Errorf("sqlite: %w", err)
	}
	return s.query(ctx, tenantID, `SELECT `+reportTemplateColumns+` FROM report_templates
		WHERE tenant_id <> ? AND EXISTS (
			SELECT 1 FROM json_each(report_templates.shared_with)
			WHERE json_extract(json_each.value, '$.tenant_id') = ?)`, tenantID, tenantID)
}

func (s *SQLiteReportTemplateStore) query(ctx context.Context, tenantID, q string, args ...any) ([]*business.ReportTemplate, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list report templates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	now := time.Now()
	result := make([]*business.ReportTemplate, 0)
	for rows.Next() {
		t, err := scanReportTemplate(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: failed to scan report template: %w", err)
		}
		if view, ok := reporttemplate.ViewFor(t, tenantID, now); ok {
			result = append(result, view)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: failed to read report templates: %w", err)
	}
	reporttemplate.Sort(result)
	return result, nil
}

// Delete implements business.ReportTemplateStore.
func (s *SQLiteReportTemplateStore) Delete(ctx context.Context, tenantID, id string) error {
	if err := validateOwnerCall(tenantID, id); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM report_templates WHERE id = ? AND tenant_id = ?`, id, tenantID)
	if err != nil {
		return fmt.Errorf("sqlite: failed to delete report template: %w", err)
	}
	return notFoundIfNoRows(res)
}

// UpdateSharing implements business.ReportTemplateStore.
func (s *SQLiteReportTemplateStore) UpdateSharing(ctx context.Context, tenantID, id string, shares []business.ReportTemplateShare) error {
	if err := validateOwnerCall(tenantID, id); err != nil {
		return err
	}
	if err := reporttemplate.ValidateShares(shares); err != nil {
		return fmt.Errorf("sqlite: %w", err)
	}
	encoded, err := reporttemplate.EncodeShares(shares)
	if err != nil {
		return fmt.Errorf("sqlite: %w", err)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE report_templates SET shared_with = ?, is_shared = ? WHERE id = ? AND tenant_id = ?`,
		encoded, boolInt(len(shares) > 0), id, tenantID)
	if err != nil {
		return fmt.Errorf("sqlite: failed to update report template sharing: %w", err)
	}
	return notFoundIfNoRows(res)
}

func validateOwnerCall(tenantID, id string) error {
	if err := reporttemplate.ValidateTenant(tenantID); err != nil {
		return fmt.Errorf("sqlite: %w", err)
	}
	if err := reporttemplate.ValidateID(id); err != nil {
		return fmt.Errorf("sqlite: %w", err)
	}
	return nil
}

func notFoundIfNoRows(res sql.Result) error {
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return business.ErrReportTemplateNotFound
	}
	return nil
}
