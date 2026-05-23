// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite implements PendingRegistrationStore using the cfgms_pending_registrations
// table — the generate-on-claim durable queue (Issue #1696).
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.PendingRegistrationStore = (*SQLitePendingRegistrationStore)(nil)

// SQLitePendingRegistrationStore implements business.PendingRegistrationStore
// using a SQLite database backed by the cfgms_pending_registrations table.
type SQLitePendingRegistrationStore struct {
	db *sql.DB
}

// Close closes the underlying database connection.
func (s *SQLitePendingRegistrationStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// AddPending inserts a new pending-registration entry.
// Returns an error if an entry with the same PendingID already exists.
func (s *SQLitePendingRegistrationStore) AddPending(ctx context.Context, entry *business.PendingRegistrationEntry) error {
	if entry == nil {
		return fmt.Errorf("sqlite: pending registration entry cannot be nil")
	}
	if entry.PendingID == "" {
		return fmt.Errorf("sqlite: pending_id cannot be empty")
	}
	if entry.TenantID == "" {
		return fmt.Errorf("sqlite: tenant_id cannot be empty")
	}

	registeredAt := entry.RegisteredAt
	if registeredAt.IsZero() {
		registeredAt = nowUTC()
	}
	status := entry.Status
	if status == "" {
		status = business.PendingRegistrationStatusPending
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cfgms_pending_registrations
			(pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.PendingID,
		entry.StewardID,
		entry.TenantID,
		entry.TokenStr,
		entry.SourceIP,
		formatTime(registeredAt),
		formatTime(entry.ExpiresAt),
		formatNullTime(entry.ClaimedAt),
		status,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("sqlite: pending registration %s already exists", entry.PendingID)
		}
		return fmt.Errorf("sqlite: failed to add pending registration %s: %w", entry.PendingID, err)
	}
	return nil
}

// GetPendingByID retrieves the entry for the given pending_id.
// Returns ErrPendingRegistrationNotFound if no record exists.
func (s *SQLitePendingRegistrationStore) GetPendingByID(ctx context.Context, pendingID string) (*business.PendingRegistrationEntry, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status
		FROM cfgms_pending_registrations WHERE pending_id = ?`, pendingID)
	return scanPendingEntry(row)
}

// GetPendingByToken retrieves the entry whose token_str matches the given token.
// Returns ErrPendingRegistrationNotFound if no matching record exists.
func (s *SQLitePendingRegistrationStore) GetPendingByToken(ctx context.Context, tokenStr string) (*business.PendingRegistrationEntry, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status
		FROM cfgms_pending_registrations WHERE token_str = ? LIMIT 1`, tokenStr)
	return scanPendingEntry(row)
}

// UpdateStatus updates the status of the entry identified by pendingID.
// When status is "claimed", claimed_at is also set to the current UTC time.
// Returns ErrPendingRegistrationNotFound if no record exists.
func (s *SQLitePendingRegistrationStore) UpdateStatus(ctx context.Context, pendingID, status string) error {
	var res sql.Result
	var err error

	if status == business.PendingRegistrationStatusClaimed {
		// Guard with AND status = 'approved' so concurrent polls of the same entry
		// result in exactly one winner: RowsAffected = 0 means already claimed.
		res, err = s.db.ExecContext(ctx, `
			UPDATE cfgms_pending_registrations
			SET status = ?, claimed_at = ?
			WHERE pending_id = ? AND status = 'approved'`,
			status, formatTime(nowUTC()), pendingID,
		)
	} else {
		res, err = s.db.ExecContext(ctx, `
			UPDATE cfgms_pending_registrations SET status = ? WHERE pending_id = ?`,
			status, pendingID,
		)
	}
	if err != nil {
		return fmt.Errorf("sqlite: failed to update status for %s: %w", pendingID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrPendingRegistrationNotFound
	}
	return nil
}

// ListPending returns all entries for the given tenantID ordered by registered_at ascending.
// An empty tenantID returns entries for all tenants.
func (s *SQLitePendingRegistrationStore) ListPending(ctx context.Context, tenantID string) ([]*business.PendingRegistrationEntry, error) {
	var (
		query string
		args  []interface{}
	)
	if tenantID == "" {
		query = `
			SELECT pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status
			FROM cfgms_pending_registrations ORDER BY registered_at ASC`
	} else {
		query = `
			SELECT pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status
			FROM cfgms_pending_registrations WHERE tenant_id = ? ORDER BY registered_at ASC`
		args = []interface{}{tenantID}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list pending registrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []*business.PendingRegistrationEntry
	for rows.Next() {
		e, err := scanPendingRow(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: failed to scan pending registration row: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// ExpireStale marks entries whose expires_at is at or before cutoff and whose status
// is "pending" as "expired". Returns the number of entries updated.
func (s *SQLitePendingRegistrationStore) ExpireStale(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE cfgms_pending_registrations
		SET status = ?
		WHERE status = ? AND expires_at <= ?`,
		business.PendingRegistrationStatusExpired,
		business.PendingRegistrationStatusPending,
		formatTime(cutoff),
	)
	if err != nil {
		return 0, fmt.Errorf("sqlite: failed to expire stale pending registrations: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// --- helpers -----------------------------------------------------------------

// formatNullTime formats a *time.Time for storage; NULL when nil.
func formatNullTime(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}

// scanPendingEntry scans a single row from a QueryRowContext call.
func scanPendingEntry(row *sql.Row) (*business.PendingRegistrationEntry, error) {
	e := &business.PendingRegistrationEntry{}
	var registeredStr, expiresStr string
	var claimedStr sql.NullString
	err := row.Scan(
		&e.PendingID, &e.StewardID, &e.TenantID, &e.TokenStr, &e.SourceIP,
		&registeredStr, &expiresStr, &claimedStr, &e.Status,
	)
	if err == sql.ErrNoRows {
		return nil, business.ErrPendingRegistrationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to scan pending registration: %w", err)
	}
	populatePendingEntry(e, registeredStr, expiresStr, claimedStr)
	return e, nil
}

// scanPendingRow scans a single row from an open Rows cursor.
func scanPendingRow(rows *sql.Rows) (*business.PendingRegistrationEntry, error) {
	e := &business.PendingRegistrationEntry{}
	var registeredStr, expiresStr string
	var claimedStr sql.NullString
	if err := rows.Scan(
		&e.PendingID, &e.StewardID, &e.TenantID, &e.TokenStr, &e.SourceIP,
		&registeredStr, &expiresStr, &claimedStr, &e.Status,
	); err != nil {
		return nil, err
	}
	populatePendingEntry(e, registeredStr, expiresStr, claimedStr)
	return e, nil
}

// populatePendingEntry fills time fields from their stored string representations.
func populatePendingEntry(e *business.PendingRegistrationEntry, registeredStr, expiresStr string, claimedStr sql.NullString) {
	e.RegisteredAt = parseTime(registeredStr)
	e.ExpiresAt = parseTime(expiresStr)
	if claimedStr.Valid && claimedStr.String != "" {
		t := parseTime(claimedStr.String)
		e.ClaimedAt = &t
	}
}
