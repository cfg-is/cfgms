// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite implements PendingRegistrationStore using SQLite for the
// manual-review registration approval mode (Issue #1599).
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// SQLitePendingRegistrationStore implements business.PendingRegistrationStore
// using a SQLite database. Records are stored in the pending_registrations table.
type SQLitePendingRegistrationStore struct {
	db *sql.DB
}

// Initialize is a no-op; schema is applied in openAndInit.
func (s *SQLitePendingRegistrationStore) Initialize(_ context.Context) error { return nil }

// Close closes the database connection.
func (s *SQLitePendingRegistrationStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// CreatePending inserts a new pending-registration record. Returns an error if a
// record with the same ID already exists.
func (s *SQLitePendingRegistrationStore) CreatePending(ctx context.Context, record *business.PendingRegistrationData) error {
	if record == nil {
		return fmt.Errorf("sqlite: pending registration record cannot be nil")
	}
	if record.ID == "" {
		return fmt.Errorf("sqlite: pending registration ID cannot be empty")
	}

	status := record.Status
	if status == "" {
		status = business.PendingRegistrationStatusPending
	}
	createdAt := record.CreatedAt
	if createdAt.IsZero() {
		createdAt = nowUTC()
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pending_registrations
			(id, steward_id, tenant_id, source_ip, token_prefix, status, deny_reason, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID,
		record.StewardID,
		record.TenantID,
		record.SourceIP,
		record.TokenPrefix,
		string(status),
		record.DenyReason,
		formatTime(createdAt),
		formatTime(record.ExpiresAt),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("sqlite: pending registration %s already exists", record.ID)
		}
		return fmt.Errorf("sqlite: failed to create pending registration %s: %w", record.ID, err)
	}
	return nil
}

// GetPending retrieves the pending-registration record for the given ID.
// Returns ErrPendingRegistrationNotFound if no record exists.
func (s *SQLitePendingRegistrationStore) GetPending(ctx context.Context, id string) (*business.PendingRegistrationData, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, steward_id, tenant_id, source_ip, token_prefix, status, deny_reason, created_at, expires_at
		FROM pending_registrations WHERE id = ?`, id)

	r := &business.PendingRegistrationData{}
	var statusStr, createdStr, expiresStr string
	err := row.Scan(
		&r.ID, &r.StewardID, &r.TenantID, &r.SourceIP, &r.TokenPrefix,
		&statusStr, &r.DenyReason, &createdStr, &expiresStr,
	)
	if err == sql.ErrNoRows {
		return nil, business.ErrPendingRegistrationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to scan pending registration: %w", err)
	}
	populatePendingRegistration(r, statusStr, createdStr, expiresStr)
	return r, nil
}

// ListPending returns all records matching the filter, ordered by created_at ascending.
// A nil filter returns every record.
func (s *SQLitePendingRegistrationStore) ListPending(ctx context.Context, filter *business.PendingRegistrationFilter) ([]*business.PendingRegistrationData, error) {
	query := `
		SELECT id, steward_id, tenant_id, source_ip, token_prefix, status, deny_reason, created_at, expires_at
		FROM pending_registrations`
	var conds []string
	var args []interface{}
	if filter != nil {
		if filter.Status != nil {
			conds = append(conds, "status = ?")
			args = append(args, string(*filter.Status))
		}
		if filter.TenantID != nil {
			conds = append(conds, "tenant_id = ?")
			args = append(args, *filter.TenantID)
		}
		if filter.ExpiresBeforeOrAt != nil {
			conds = append(conds, "expires_at <= ?")
			args = append(args, formatTime(*filter.ExpiresBeforeOrAt))
		}
	}
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	query += " ORDER BY created_at ASC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list pending registrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var records []*business.PendingRegistrationData
	for rows.Next() {
		r := &business.PendingRegistrationData{}
		var statusStr, createdStr, expiresStr string
		if err := rows.Scan(
			&r.ID, &r.StewardID, &r.TenantID, &r.SourceIP, &r.TokenPrefix,
			&statusStr, &r.DenyReason, &createdStr, &expiresStr,
		); err != nil {
			return nil, fmt.Errorf("sqlite: failed to scan pending registration row: %w", err)
		}
		populatePendingRegistration(r, statusStr, createdStr, expiresStr)
		records = append(records, r)
	}
	return records, rows.Err()
}

// UpdatePendingStatus updates the status and deny reason of the given record.
// Returns ErrPendingRegistrationNotFound if no record exists for the ID.
func (s *SQLitePendingRegistrationStore) UpdatePendingStatus(ctx context.Context, id string, status business.PendingRegistrationStatus, reason string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE pending_registrations SET status = ?, deny_reason = ? WHERE id = ?`,
		string(status), reason, id,
	)
	if err != nil {
		return fmt.Errorf("sqlite: failed to update pending registration status for %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrPendingRegistrationNotFound
	}
	return nil
}

// DeletePending removes the pending-registration record for the given ID.
// Returns ErrPendingRegistrationNotFound if no record exists.
func (s *SQLitePendingRegistrationStore) DeletePending(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM pending_registrations WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: failed to delete pending registration %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrPendingRegistrationNotFound
	}
	return nil
}

// populatePendingRegistration fills in the time and status fields from their string representations.
func populatePendingRegistration(r *business.PendingRegistrationData, statusStr, createdStr, expiresStr string) {
	r.Status = business.PendingRegistrationStatus(statusStr)
	r.CreatedAt = parseTime(createdStr)
	r.ExpiresAt = parseTime(expiresStr)
}

// Compile-time assertion
var _ business.PendingRegistrationStore = (*SQLitePendingRegistrationStore)(nil)
