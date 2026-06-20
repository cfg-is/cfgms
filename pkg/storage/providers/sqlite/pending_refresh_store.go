// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite implements PendingRefreshStore using the pending_refresh_requests
// table — the registration-refresh durable queue (ADR-010, Issue #2093).
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
var _ business.PendingRefreshStore = (*SQLitePendingRefreshStore)(nil)

// SQLitePendingRefreshStore implements business.PendingRefreshStore using a
// SQLite database backed by the pending_refresh_requests table.
type SQLitePendingRefreshStore struct {
	db *sql.DB
}

// Close closes the underlying database connection.
func (s *SQLitePendingRefreshStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// AddPendingRefresh inserts a new pending-refresh entry.
// Returns an error if an entry with the same PendingID already exists.
func (s *SQLitePendingRefreshStore) AddPendingRefresh(ctx context.Context, entry *business.PendingRefreshEntry) error {
	if entry == nil {
		return fmt.Errorf("sqlite: pending refresh entry cannot be nil")
	}
	if entry.PendingID == "" {
		return fmt.Errorf("sqlite: pending_id cannot be empty")
	}
	if entry.DeviceID == "" {
		return fmt.Errorf("sqlite: device_id cannot be empty")
	}
	if entry.TenantID == "" {
		return fmt.Errorf("sqlite: tenant_id cannot be empty")
	}

	createdAt := entry.CreatedAt
	if createdAt.IsZero() {
		createdAt = nowUTC()
	}
	status := entry.Status
	if status == "" {
		status = business.PendingRefreshStatusPending
	}

	claimBundle := entry.ClaimBundle
	if claimBundle == nil {
		claimBundle = []byte{}
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pending_refresh_requests
			(pending_id, device_id, tenant_id, source_ip,
			 provenance_matched_fields, provenance_total_fields,
			 claim_bundle, status, created_at, expires_at, resolved_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.PendingID,
		entry.DeviceID,
		entry.TenantID,
		entry.SourceIP,
		entry.ProvenanceMatchedFields,
		entry.ProvenanceTotalFields,
		claimBundle,
		status,
		formatTime(createdAt),
		formatTime(entry.ExpiresAt),
		formatNullTime(entry.ResolvedAt),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("sqlite: pending refresh %s already exists", entry.PendingID)
		}
		return fmt.Errorf("sqlite: failed to add pending refresh %s: %w", entry.PendingID, err)
	}
	return nil
}

// GetPendingRefreshByID retrieves the entry for the given pending_id.
// Returns ErrPendingRefreshNotFound if no record exists.
func (s *SQLitePendingRefreshStore) GetPendingRefreshByID(ctx context.Context, pendingID string) (*business.PendingRefreshEntry, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT pending_id, device_id, tenant_id, source_ip,
		       provenance_matched_fields, provenance_total_fields,
		       claim_bundle, status, created_at, expires_at, resolved_at
		FROM pending_refresh_requests WHERE pending_id = ?`, pendingID)
	return scanRefreshEntry(row)
}

// UpdateRefreshStatus updates the status of the entry identified by pendingID.
// For terminal statuses (approved, rejected), resolved_at is also set to now.
// Returns ErrPendingRefreshNotFound if no record exists.
func (s *SQLitePendingRefreshStore) UpdateRefreshStatus(ctx context.Context, pendingID, status string) error {
	var res sql.Result
	var err error

	isTerminal := status == business.PendingRefreshStatusApproved ||
		status == business.PendingRefreshStatusRejected
	if isTerminal {
		res, err = s.db.ExecContext(ctx, `
			UPDATE pending_refresh_requests
			SET status = ?, resolved_at = ?
			WHERE pending_id = ?`,
			status, formatTime(nowUTC()), pendingID,
		)
	} else {
		res, err = s.db.ExecContext(ctx, `
			UPDATE pending_refresh_requests SET status = ? WHERE pending_id = ?`,
			status, pendingID,
		)
	}
	if err != nil {
		return fmt.Errorf("sqlite: failed to update refresh status for %s: %w", pendingID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrPendingRefreshNotFound
	}
	return nil
}

// ListPendingRefresh returns all entries for the given tenantID ordered by
// created_at ascending. An empty tenantID returns entries for all tenants.
func (s *SQLitePendingRefreshStore) ListPendingRefresh(ctx context.Context, tenantID string) ([]*business.PendingRefreshEntry, error) {
	var (
		query string
		args  []interface{}
	)
	if tenantID == "" {
		query = `
			SELECT pending_id, device_id, tenant_id, source_ip,
			       provenance_matched_fields, provenance_total_fields,
			       claim_bundle, status, created_at, expires_at, resolved_at
			FROM pending_refresh_requests ORDER BY created_at ASC`
	} else {
		query = `
			SELECT pending_id, device_id, tenant_id, source_ip,
			       provenance_matched_fields, provenance_total_fields,
			       claim_bundle, status, created_at, expires_at, resolved_at
			FROM pending_refresh_requests WHERE tenant_id = ? ORDER BY created_at ASC`
		args = []interface{}{tenantID}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list pending refresh requests: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []*business.PendingRefreshEntry
	for rows.Next() {
		e, err := scanRefreshRow(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: failed to scan pending refresh row: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// ExpireStaleRefresh marks entries whose expires_at is at or before cutoff and
// whose status is "pending" as "expired", setting resolved_at to now.
func (s *SQLitePendingRefreshStore) ExpireStaleRefresh(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE pending_refresh_requests
		SET status = ?, resolved_at = ?
		WHERE status = ? AND expires_at <= ?`,
		business.PendingRefreshStatusExpired,
		formatTime(nowUTC()),
		business.PendingRefreshStatusPending,
		formatTime(cutoff),
	)
	if err != nil {
		return 0, fmt.Errorf("sqlite: failed to expire stale refresh requests: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// StoreClaimBundle persists the proof-of-possession payload for the given pendingID.
// Returns ErrPendingRefreshNotFound if no record exists.
func (s *SQLitePendingRefreshStore) StoreClaimBundle(ctx context.Context, pendingID string, bundle []byte) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE pending_refresh_requests SET claim_bundle = ? WHERE pending_id = ?`,
		bundle, pendingID,
	)
	if err != nil {
		return fmt.Errorf("sqlite: failed to store claim bundle for %s: %w", pendingID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrPendingRefreshNotFound
	}
	return nil
}

// --- helpers -----------------------------------------------------------------

// scanRefreshEntry scans a single row from a QueryRowContext call.
func scanRefreshEntry(row *sql.Row) (*business.PendingRefreshEntry, error) {
	e := &business.PendingRefreshEntry{}
	var createdStr, expiresStr string
	var resolvedStr sql.NullString
	var claimBundle []byte
	err := row.Scan(
		&e.PendingID, &e.DeviceID, &e.TenantID, &e.SourceIP,
		&e.ProvenanceMatchedFields, &e.ProvenanceTotalFields,
		&claimBundle, &e.Status, &createdStr, &expiresStr, &resolvedStr,
	)
	if err == sql.ErrNoRows {
		return nil, business.ErrPendingRefreshNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to scan pending refresh: %w", err)
	}
	e.ClaimBundle = claimBundle
	e.CreatedAt = parseTime(createdStr)
	e.ExpiresAt = parseTime(expiresStr)
	e.ResolvedAt = parseNullTime(resolvedStr)
	return e, nil
}

// scanRefreshRow scans a single row from an open Rows cursor.
func scanRefreshRow(rows *sql.Rows) (*business.PendingRefreshEntry, error) {
	e := &business.PendingRefreshEntry{}
	var createdStr, expiresStr string
	var resolvedStr sql.NullString
	var claimBundle []byte
	if err := rows.Scan(
		&e.PendingID, &e.DeviceID, &e.TenantID, &e.SourceIP,
		&e.ProvenanceMatchedFields, &e.ProvenanceTotalFields,
		&claimBundle, &e.Status, &createdStr, &expiresStr, &resolvedStr,
	); err != nil {
		return nil, err
	}
	e.ClaimBundle = claimBundle
	e.CreatedAt = parseTime(createdStr)
	e.ExpiresAt = parseTime(expiresStr)
	e.ResolvedAt = parseNullTime(resolvedStr)
	return e, nil
}
