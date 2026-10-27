// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/internal/reporttemplate"
)

// Compile-time assertion.
var _ business.ReportTemplateStore = (*DatabaseReportTemplateStore)(nil)

// DatabaseReportTemplateStore implements business.ReportTemplateStore using PostgreSQL —
// the custom report templates every controller node sees. Every query is parameterized
// and scoped by tenant_id (owner access) or by a JSONB containment match on the share
// list (recipient access); expiry and the final visibility decision are applied by the
// shared reporttemplate.ViewFor rule.
type DatabaseReportTemplateStore struct {
	db *sql.DB
}

// NewDatabaseReportTemplateStore creates the store on the shared connection pool db
// (owned by DatabaseProvider; ADR-031 Decision 6) and ensures its table exists.
func NewDatabaseReportTemplateStore(db *sql.DB, _ map[string]interface{}) (*DatabaseReportTemplateStore, error) {
	if err := NewDatabaseSchemas().CreateReportTemplatesTable(context.Background(), db); err != nil {
		return nil, err
	}
	return &DatabaseReportTemplateStore{db: db}, nil
}

// Close is a no-op: the connection pool is owned and closed by DatabaseProvider.
func (s *DatabaseReportTemplateStore) Close() error { return nil }

const reportTemplateColumns = `id, tenant_id, name, description, definition, created_by, created_at,
	updated_at, is_shared, shared_with, tags, category, version, usage_count, last_used`

func scanReportTemplate(row rowScanner) (*business.ReportTemplate, error) {
	t := &business.ReportTemplate{}
	var definition, sharedWith, tags string
	var lastUsed sql.NullTime
	if err := row.Scan(&t.ID, &t.TenantID, &t.Name, &t.Description, &definition, &t.CreatedBy,
		&t.CreatedAt, &t.UpdatedAt, &t.IsShared, &sharedWith, &tags, &t.Category, &t.Version,
		&t.UsageCount, &lastUsed); err != nil {
		return nil, err
	}
	if definition != "" {
		t.Definition = json.RawMessage(definition)
	}
	t.CreatedAt = t.CreatedAt.UTC()
	t.UpdatedAt = t.UpdatedAt.UTC()
	if lastUsed.Valid {
		lu := lastUsed.Time.UTC()
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
func (s *DatabaseReportTemplateStore) Save(ctx context.Context, tenantID string, template *business.ReportTemplate) error {
	if err := reporttemplate.ValidateSave(tenantID, template); err != nil {
		return err
	}
	sharedWith, err := reporttemplate.EncodeShares(template.SharedWith)
	if err != nil {
		return err
	}
	tags, err := reporttemplate.EncodeTags(template.Tags)
	if err != nil {
		return err
	}
	lastUsed := approvalNullTime(time.Time{})
	if template.LastUsed != nil {
		lastUsed = approvalNullTime(*template.LastUsed)
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO cfgms_report_templates (`+reportTemplateColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12, $13, $14, $15)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name, description = EXCLUDED.description, definition = EXCLUDED.definition,
			created_by = EXCLUDED.created_by, created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at, is_shared = EXCLUDED.is_shared,
			shared_with = EXCLUDED.shared_with, tags = EXCLUDED.tags, category = EXCLUDED.category,
			version = EXCLUDED.version, usage_count = EXCLUDED.usage_count, last_used = EXCLUDED.last_used
		WHERE cfgms_report_templates.tenant_id = EXCLUDED.tenant_id`,
		template.ID, tenantID, template.Name, template.Description, string(template.Definition),
		template.CreatedBy, template.CreatedAt.UTC(), template.UpdatedAt.UTC(), template.IsShared,
		sharedWith, tags, template.Category, template.Version, template.UsageCount, lastUsed)
	if err != nil {
		return fmt.Errorf("failed to save report template: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return business.ErrReportTemplateExists
	}
	return nil
}

// GetByID implements business.ReportTemplateStore.
func (s *DatabaseReportTemplateStore) GetByID(ctx context.Context, tenantID, id string) (*business.ReportTemplate, error) {
	if err := validateReportTemplateCall(tenantID, id); err != nil {
		return nil, err
	}
	// The row is fetched by ID alone because a share recipient does not own it; the
	// tenant check is ViewFor, and the row is dropped here before it reaches the caller.
	t, err := scanReportTemplate(s.db.QueryRowContext(ctx,
		`SELECT `+reportTemplateColumns+` FROM cfgms_report_templates WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, business.ErrReportTemplateNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read report template: %w", err)
	}
	view, ok := reporttemplate.ViewFor(t, tenantID, time.Now())
	if !ok {
		return nil, business.ErrReportTemplateNotFound
	}
	return view, nil
}

// ListOwned implements business.ReportTemplateStore.
func (s *DatabaseReportTemplateStore) ListOwned(ctx context.Context, tenantID string) ([]*business.ReportTemplate, error) {
	if err := reporttemplate.ValidateTenant(tenantID); err != nil {
		return nil, err
	}
	return s.query(ctx, tenantID, `SELECT `+reportTemplateColumns+
		` FROM cfgms_report_templates WHERE tenant_id = $1`, tenantID)
}

// ListSharedWith implements business.ReportTemplateStore.
func (s *DatabaseReportTemplateStore) ListSharedWith(ctx context.Context, tenantID string) ([]*business.ReportTemplate, error) {
	if err := reporttemplate.ValidateTenant(tenantID); err != nil {
		return nil, err
	}
	probe, err := json.Marshal([]map[string]string{{"tenant_id": tenantID}})
	if err != nil {
		return nil, fmt.Errorf("failed to build share lookup: %w", err)
	}
	return s.query(ctx, tenantID, `SELECT `+reportTemplateColumns+
		` FROM cfgms_report_templates WHERE tenant_id <> $1 AND shared_with @> $2::jsonb`,
		tenantID, string(probe))
}

func (s *DatabaseReportTemplateStore) query(ctx context.Context, tenantID, q string, args ...any) ([]*business.ReportTemplate, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list report templates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	now := time.Now()
	result := make([]*business.ReportTemplate, 0)
	for rows.Next() {
		t, err := scanReportTemplate(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan report template: %w", err)
		}
		if view, ok := reporttemplate.ViewFor(t, tenantID, now); ok {
			result = append(result, view)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read report templates: %w", err)
	}
	reporttemplate.Sort(result)
	return result, nil
}

// Delete implements business.ReportTemplateStore.
func (s *DatabaseReportTemplateStore) Delete(ctx context.Context, tenantID, id string) error {
	if err := validateReportTemplateCall(tenantID, id); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM cfgms_report_templates WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete report template: %w", err)
	}
	return reportTemplateNotFoundIfNoRows(res)
}

// UpdateSharing implements business.ReportTemplateStore.
func (s *DatabaseReportTemplateStore) UpdateSharing(ctx context.Context, tenantID, id string, shares []business.ReportTemplateShare) error {
	if err := validateReportTemplateCall(tenantID, id); err != nil {
		return err
	}
	if err := reporttemplate.ValidateShares(shares); err != nil {
		return err
	}
	encoded, err := reporttemplate.EncodeShares(shares)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE cfgms_report_templates SET shared_with = $1::jsonb, is_shared = $2 WHERE id = $3 AND tenant_id = $4`,
		encoded, len(shares) > 0, id, tenantID)
	if err != nil {
		return fmt.Errorf("failed to update report template sharing: %w", err)
	}
	return reportTemplateNotFoundIfNoRows(res)
}

func validateReportTemplateCall(tenantID, id string) error {
	if err := reporttemplate.ValidateTenant(tenantID); err != nil {
		return err
	}
	return reporttemplate.ValidateID(id)
}

func reportTemplateNotFoundIfNoRows(res sql.Result) error {
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return business.ErrReportTemplateNotFound
	}
	return nil
}
