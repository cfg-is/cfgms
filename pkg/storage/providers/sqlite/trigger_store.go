// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite implements TriggerStore using SQLite for durable workflow trigger persistence.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// SQLiteTriggerStore implements business.TriggerStore using a SQLite database.
// Trigger records are stored in the `triggers` table created by initializeSchema.
type SQLiteTriggerStore struct {
	db *sql.DB
}

// Compile-time assertion that SQLiteTriggerStore satisfies TriggerStore.
var _ business.TriggerStore = (*SQLiteTriggerStore)(nil)

// Close closes the underlying database connection.
func (s *SQLiteTriggerStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// StoreTrigger creates or updates a trigger record using an upsert.
// The record must have non-empty ID and TenantID.
func (s *SQLiteTriggerStore) StoreTrigger(ctx context.Context, record *business.TriggerRecord) error {
	if record == nil {
		return fmt.Errorf("sqlite: trigger record cannot be nil")
	}
	if record.ID == "" {
		return fmt.Errorf("sqlite: trigger ID is required")
	}
	if record.TenantID == "" {
		return fmt.Errorf("sqlite: trigger TenantID is required")
	}

	methodJSON, err := marshalJSONSlice(record.WebhookMethod)
	if err != nil {
		return fmt.Errorf("sqlite: failed to marshal webhook_method: %w", err)
	}

	now := nowUTC()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now

	// Use INSERT OR REPLACE for upsert semantics.
	_, err = s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO triggers
			(id, tenant_id, name, type, status, workflow_name,
			 created_at, updated_at,
			 webhook_path, webhook_method,
			 bearer_ref, hmac_ref, apikey_ref, basic_user_ref, basic_pass_ref,
			 payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID,
		record.TenantID,
		record.Name,
		record.Type,
		record.Status,
		record.WorkflowName,
		formatTime(record.CreatedAt),
		formatTime(record.UpdatedAt),
		record.WebhookPath,
		methodJSON,
		record.BearerTokenRef,
		record.HMACSecretRef,
		record.APIKeyRef,
		record.BasicUsernameRef,
		record.BasicPasswordRef,
		record.ConfigPayload,
	)
	if err != nil {
		return fmt.Errorf("sqlite: failed to store trigger %s: %w", record.ID, err)
	}
	return nil
}

// GetTrigger retrieves a trigger by ID. Returns ErrTriggerNotFound when absent.
func (s *SQLiteTriggerStore) GetTrigger(ctx context.Context, id string) (*business.TriggerRecord, error) {
	if id == "" {
		return nil, fmt.Errorf("sqlite: trigger ID is required")
	}

	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, name, type, status, workflow_name,
		       created_at, updated_at,
		       webhook_path, webhook_method,
		       bearer_ref, hmac_ref, apikey_ref, basic_user_ref, basic_pass_ref,
		       payload
		FROM triggers WHERE id = ?`, id)

	return scanTriggerRow(row.Scan)
}

// DeleteTrigger removes a trigger by ID. Returns ErrTriggerNotFound when absent.
func (s *SQLiteTriggerStore) DeleteTrigger(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("sqlite: trigger ID is required")
	}

	res, err := s.db.ExecContext(ctx, `DELETE FROM triggers WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: failed to delete trigger %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrTriggerNotFound
	}
	return nil
}

// ListTriggers returns triggers matching the filter, ordered by created_at descending.
func (s *SQLiteTriggerStore) ListTriggers(ctx context.Context, filter business.TriggerStoreFilter) ([]*business.TriggerRecord, error) {
	query := `
		SELECT id, tenant_id, name, type, status, workflow_name,
		       created_at, updated_at,
		       webhook_path, webhook_method,
		       bearer_ref, hmac_ref, apikey_ref, basic_user_ref, basic_pass_ref,
		       payload
		FROM triggers WHERE 1=1`
	var args []interface{}

	if filter.TenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, filter.TenantID)
	}
	if filter.Type != "" {
		query += ` AND type = ?`
		args = append(args, filter.Type)
	}
	if filter.Status != "" {
		query += ` AND status = ?`
		args = append(args, filter.Status)
	}

	query += ` ORDER BY created_at DESC`

	if filter.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			query += ` OFFSET ?`
			args = append(args, filter.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list triggers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var records []*business.TriggerRecord
	for rows.Next() {
		rec, err := scanTriggerRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// scanTriggerRow scans a single trigger row using the provided scan function.
// This works for both *sql.Row (via row.Scan) and *sql.Rows (via rows.Scan).
func scanTriggerRow(scan func(...interface{}) error) (*business.TriggerRecord, error) {
	var rec business.TriggerRecord
	var createdAtStr, updatedAtStr, methodJSON string
	var payload []byte

	err := scan(
		&rec.ID,
		&rec.TenantID,
		&rec.Name,
		&rec.Type,
		&rec.Status,
		&rec.WorkflowName,
		&createdAtStr,
		&updatedAtStr,
		&rec.WebhookPath,
		&methodJSON,
		&rec.BearerTokenRef,
		&rec.HMACSecretRef,
		&rec.APIKeyRef,
		&rec.BasicUsernameRef,
		&rec.BasicPasswordRef,
		&payload,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, business.ErrTriggerNotFound
		}
		return nil, fmt.Errorf("sqlite: failed to scan trigger row: %w", err)
	}

	rec.CreatedAt = parseTime(createdAtStr)
	rec.UpdatedAt = parseTime(updatedAtStr)
	rec.ConfigPayload = payload

	methods, err := unmarshalJSONSlice(methodJSON)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to unmarshal webhook_method: %w", err)
	}
	rec.WebhookMethod = methods

	return &rec, nil
}
