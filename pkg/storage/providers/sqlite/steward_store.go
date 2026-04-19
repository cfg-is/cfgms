// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite implements StewardStore using SQLite for durable fleet registry storage.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// SQLiteStewardStore implements business.StewardStore using a SQLite database.
// It stores fleet registration data in the `stewards` table, which is append-only
// in practice (deregistered records are retained, never deleted).
type SQLiteStewardStore struct {
	db *sql.DB
}

// Initialize is a no-op; schema is applied in openAndInit.
func (s *SQLiteStewardStore) Initialize(_ context.Context) error { return nil }

// Close closes the database connection.
func (s *SQLiteStewardStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// RegisterSteward creates a new steward record. Returns ErrStewardAlreadyExists if
// a record with the same ID already exists.
func (s *SQLiteStewardStore) RegisterSteward(ctx context.Context, record *business.StewardRecord) error {
	if record == nil {
		return fmt.Errorf("sqlite: record cannot be nil")
	}
	if record.ID == "" {
		return fmt.Errorf("sqlite: steward ID cannot be empty")
	}

	now := nowUTC()
	status := record.Status
	if status == "" {
		status = business.StewardStatusRegistered
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO stewards
			(id, hostname, platform, arch, version, ip_address, status,
			 registered_at, last_seen, last_heartbeat_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID,
		record.Hostname,
		record.Platform,
		record.Arch,
		record.Version,
		record.IPAddress,
		string(status),
		formatTime(now),
		formatTime(now),
		"", // last_heartbeat_at empty until first heartbeat
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return business.ErrStewardAlreadyExists
		}
		return fmt.Errorf("sqlite: failed to register steward %s: %w", record.ID, err)
	}
	return nil
}

// UpdateHeartbeat records a heartbeat, updating last_heartbeat_at and last_seen.
func (s *SQLiteStewardStore) UpdateHeartbeat(ctx context.Context, stewardID string) error {
	now := formatTime(nowUTC())
	res, err := s.db.ExecContext(ctx, `
		UPDATE stewards SET last_heartbeat_at = ?, last_seen = ? WHERE id = ?`,
		now, now, stewardID,
	)
	if err != nil {
		return fmt.Errorf("sqlite: failed to update heartbeat for steward %s: %w", stewardID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrStewardNotFound
	}
	return nil
}

// GetSteward retrieves the record for the given steward ID.
func (s *SQLiteStewardStore) GetSteward(ctx context.Context, stewardID string) (*business.StewardRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, hostname, platform, arch, version, ip_address, status,
		       registered_at, last_seen, last_heartbeat_at
		FROM stewards WHERE id = ?`, stewardID)
	return scanStewardRow(row)
}

// ListStewards returns all steward records regardless of status.
func (s *SQLiteStewardStore) ListStewards(ctx context.Context) ([]*business.StewardRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, hostname, platform, arch, version, ip_address, status,
		       registered_at, last_seen, last_heartbeat_at
		FROM stewards ORDER BY registered_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list stewards: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanStewardRows(rows)
}

// ListStewardsByStatus returns records with the given status. Uses an indexed query.
func (s *SQLiteStewardStore) ListStewardsByStatus(ctx context.Context, status business.StewardStatus) ([]*business.StewardRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, hostname, platform, arch, version, ip_address, status,
		       registered_at, last_seen, last_heartbeat_at
		FROM stewards WHERE status = ? ORDER BY registered_at ASC`,
		string(status),
	)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list stewards by status: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanStewardRows(rows)
}

// UpdateStewardStatus updates the lifecycle status of the given steward and bumps last_seen.
func (s *SQLiteStewardStore) UpdateStewardStatus(ctx context.Context, stewardID string, status business.StewardStatus) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE stewards SET status = ?, last_seen = ? WHERE id = ?`,
		string(status), formatTime(nowUTC()), stewardID,
	)
	if err != nil {
		return fmt.Errorf("sqlite: failed to update steward status %s: %w", stewardID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrStewardNotFound
	}
	return nil
}

// DeregisterSteward marks the steward as deregistered. Records are retained for audit.
func (s *SQLiteStewardStore) DeregisterSteward(ctx context.Context, stewardID string) error {
	return s.UpdateStewardStatus(ctx, stewardID, business.StewardStatusDeregistered)
}

// GetStewardsSeen returns all stewards whose last_seen time is after the given time.
func (s *SQLiteStewardStore) GetStewardsSeen(ctx context.Context, since time.Time) ([]*business.StewardRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, hostname, platform, arch, version, ip_address, status,
		       registered_at, last_seen, last_heartbeat_at
		FROM stewards WHERE last_seen > ? ORDER BY last_seen DESC`,
		formatTime(since),
	)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to get stewards seen since %v: %w", since, err)
	}
	defer func() { _ = rows.Close() }()
	return scanStewardRows(rows)
}

// HealthCheck verifies the database is reachable.
func (s *SQLiteStewardStore) HealthCheck(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// ---- helpers ----------------------------------------------------------------

// scanStewardRow scans a *sql.Row into a StewardRecord.
func scanStewardRow(row *sql.Row) (*business.StewardRecord, error) {
	r := &business.StewardRecord{}
	var statusStr, regStr, lastSeenStr, lastHBStr string
	err := row.Scan(
		&r.ID, &r.Hostname, &r.Platform, &r.Arch, &r.Version, &r.IPAddress,
		&statusStr, &regStr, &lastSeenStr, &lastHBStr,
	)
	if err == sql.ErrNoRows {
		return nil, business.ErrStewardNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to scan steward: %w", err)
	}
	return populateSteward(r, statusStr, regStr, lastSeenStr, lastHBStr), nil
}

// scanStewardRows scans *sql.Rows into a slice of StewardRecords.
func scanStewardRows(rows *sql.Rows) ([]*business.StewardRecord, error) {
	var records []*business.StewardRecord
	for rows.Next() {
		r := &business.StewardRecord{}
		var statusStr, regStr, lastSeenStr, lastHBStr string
		if err := rows.Scan(
			&r.ID, &r.Hostname, &r.Platform, &r.Arch, &r.Version, &r.IPAddress,
			&statusStr, &regStr, &lastSeenStr, &lastHBStr,
		); err != nil {
			return nil, fmt.Errorf("sqlite: failed to scan steward row: %w", err)
		}
		records = append(records, populateSteward(r, statusStr, regStr, lastSeenStr, lastHBStr))
	}
	return records, rows.Err()
}

// populateSteward fills in the time and status fields from their string representations.
func populateSteward(r *business.StewardRecord, statusStr, regStr, lastSeenStr, lastHBStr string) *business.StewardRecord {
	r.Status = business.StewardStatus(statusStr)
	r.RegisteredAt = parseTime(regStr)
	r.LastSeen = parseTime(lastSeenStr)
	if lastHBStr != "" {
		r.LastHeartbeatAt = parseTime(lastHBStr)
	}
	return r
}

// Compile-time assertion
var _ business.StewardStore = (*SQLiteStewardStore)(nil)
