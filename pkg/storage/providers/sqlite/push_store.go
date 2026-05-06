// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite implements PushStore using SQLite for durable push-state persistence.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// SQLitePushStore implements business.PushStore using a SQLite database.
// Records are stored in the push_records table. A new leader queries this
// table to resume pending and in-progress pushes after failover.
type SQLitePushStore struct {
	db *sql.DB
}

// Initialize is a no-op; schema is applied in openAndInit.
func (s *SQLitePushStore) Initialize(_ context.Context) error { return nil }

// Close closes the database connection.
func (s *SQLitePushStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// CreatePush inserts a new push record. Returns an error if a record with the
// same ID already exists.
func (s *SQLitePushStore) CreatePush(ctx context.Context, record *business.PushRecord) error {
	if record == nil {
		return fmt.Errorf("sqlite: push record cannot be nil")
	}
	if record.ID == "" {
		return fmt.Errorf("sqlite: push record ID cannot be empty")
	}

	now := nowUTC()
	status := record.Status
	if status == "" {
		status = business.PushStatusPending
	}
	createdAt := record.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO push_records
			(id, config_id, tenant_id, version, status, initiated_by, data, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID,
		record.ConfigID,
		record.TenantID,
		record.Version,
		string(status),
		record.InitiatedBy,
		record.Data,
		formatTime(createdAt),
		formatTime(now),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("sqlite: push record %s already exists", record.ID)
		}
		return fmt.Errorf("sqlite: failed to create push record %s: %w", record.ID, err)
	}
	return nil
}

// UpdatePushStatus updates the status and updated_at of the given push record.
// Returns ErrPushNotFound if no record exists for the ID.
func (s *SQLitePushStore) UpdatePushStatus(ctx context.Context, id string, status business.PushStatus) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE push_records SET status = ?, updated_at = ? WHERE id = ?`,
		string(status), formatTime(nowUTC()), id,
	)
	if err != nil {
		return fmt.Errorf("sqlite: failed to update push status for %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrPushNotFound
	}
	return nil
}

// GetPendingPushes returns all records with status pending or in_progress.
// Both states are returned so a new leader can resume all unfinished work.
func (s *SQLitePushStore) GetPendingPushes(ctx context.Context) ([]*business.PushRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, config_id, tenant_id, version, status, initiated_by, data, created_at, updated_at
		FROM push_records
		WHERE status IN ('pending', 'in_progress')
		ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to get pending push records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanPushRows(rows)
}

// GetPush retrieves the push record for the given ID.
// Returns ErrPushNotFound if no record exists.
func (s *SQLitePushStore) GetPush(ctx context.Context, id string) (*business.PushRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, config_id, tenant_id, version, status, initiated_by, data, created_at, updated_at
		FROM push_records WHERE id = ?`, id)
	return scanPushRow(row)
}

// ---- helpers ----------------------------------------------------------------

// scanPushRow scans a *sql.Row into a PushRecord.
func scanPushRow(row *sql.Row) (*business.PushRecord, error) {
	r := &business.PushRecord{}
	var statusStr, createdStr, updatedStr string
	err := row.Scan(
		&r.ID, &r.ConfigID, &r.TenantID, &r.Version,
		&statusStr, &r.InitiatedBy, &r.Data,
		&createdStr, &updatedStr,
	)
	if err == sql.ErrNoRows {
		return nil, business.ErrPushNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to scan push record: %w", err)
	}
	return populatePush(r, statusStr, createdStr, updatedStr), nil
}

// scanPushRows scans *sql.Rows into a slice of PushRecords.
func scanPushRows(rows *sql.Rows) ([]*business.PushRecord, error) {
	var records []*business.PushRecord
	for rows.Next() {
		r := &business.PushRecord{}
		var statusStr, createdStr, updatedStr string
		if err := rows.Scan(
			&r.ID, &r.ConfigID, &r.TenantID, &r.Version,
			&statusStr, &r.InitiatedBy, &r.Data,
			&createdStr, &updatedStr,
		); err != nil {
			return nil, fmt.Errorf("sqlite: failed to scan push record row: %w", err)
		}
		records = append(records, populatePush(r, statusStr, createdStr, updatedStr))
	}
	return records, rows.Err()
}

// populatePush fills in the time and status fields from their string representations.
func populatePush(r *business.PushRecord, statusStr, createdStr, updatedStr string) *business.PushRecord {
	r.Status = business.PushStatus(statusStr)
	r.CreatedAt = parseTime(createdStr)
	r.UpdatedAt = parseTime(updatedStr)
	return r
}

// Compile-time assertion
var _ business.PushStore = (*SQLitePushStore)(nil)
