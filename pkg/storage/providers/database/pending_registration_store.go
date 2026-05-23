// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package database implements PendingRegistrationStore using PostgreSQL (Issue #1696).
package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.PendingRegistrationStore = (*DatabasePendingRegistrationStore)(nil)

// DatabasePendingRegistrationStore implements PendingRegistrationStore using PostgreSQL.
type DatabasePendingRegistrationStore struct {
	db      *sql.DB
	schemas DatabaseSchemas
}

// NewDatabasePendingRegistrationStore opens a PostgreSQL-backed PendingRegistrationStore at dsn.
func NewDatabasePendingRegistrationStore(dsn string, config map[string]interface{}) (*DatabasePendingRegistrationStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}
	maxOpenConns := getIntFromConfig(config, "max_open_connections", 25)
	maxIdleConns := getIntFromConfig(config, "max_idle_connections", 5)
	connMaxLifetime := time.Duration(getIntFromConfig(config, "connection_max_lifetime_minutes", 30)) * time.Minute
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	store := &DatabasePendingRegistrationStore{db: db, schemas: NewDatabaseSchemas()}
	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialise pending registration schema: %w", err)
	}
	return store, nil
}

func (s *DatabasePendingRegistrationStore) initSchema() error {
	ctx := context.Background()
	const lockID = 16924999
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("failed to acquire pending registration schema lock: %w", err)
	}
	defer func() {
		_, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID)
	}()
	return s.schemas.CreatePendingRegistrationsTable(ctx, s.db)
}

// AddPending inserts a new pending-registration entry.
func (s *DatabasePendingRegistrationStore) AddPending(ctx context.Context, entry *business.PendingRegistrationEntry) error {
	if entry == nil {
		return fmt.Errorf("database: pending registration entry cannot be nil")
	}
	if entry.PendingID == "" {
		return fmt.Errorf("database: pending_id cannot be empty")
	}

	registeredAt := entry.RegisteredAt
	if registeredAt.IsZero() {
		registeredAt = time.Now().UTC()
	}
	status := entry.Status
	if status == "" {
		status = business.PendingRegistrationStatusPending
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cfgms_pending_registrations
			(pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		entry.PendingID, entry.StewardID, entry.TenantID, entry.TokenStr, entry.SourceIP,
		registeredAt, entry.ExpiresAt, entry.ClaimedAt, status,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique_violation") {
			return fmt.Errorf("database: pending registration %s already exists", entry.PendingID)
		}
		return fmt.Errorf("database: failed to add pending registration %s: %w", entry.PendingID, err)
	}
	return nil
}

// GetPendingByID retrieves the entry for the given pending_id.
func (s *DatabasePendingRegistrationStore) GetPendingByID(ctx context.Context, pendingID string) (*business.PendingRegistrationEntry, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status
		FROM cfgms_pending_registrations WHERE pending_id = $1`, pendingID)
	return scanDBPendingEntry(row)
}

// GetPendingByToken retrieves the entry whose token_str matches.
func (s *DatabasePendingRegistrationStore) GetPendingByToken(ctx context.Context, tokenStr string) (*business.PendingRegistrationEntry, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status
		FROM cfgms_pending_registrations WHERE token_str = $1 LIMIT 1`, tokenStr)
	return scanDBPendingEntry(row)
}

// UpdateStatus updates the status of the entry.
// When status is "claimed", claimed_at is also set to now.
func (s *DatabasePendingRegistrationStore) UpdateStatus(ctx context.Context, pendingID, status string) error {
	var res sql.Result
	var err error

	if status == business.PendingRegistrationStatusClaimed {
		// Guard with AND status = 'approved' so concurrent polls of the same entry
		// result in exactly one winner: RowsAffected = 0 means already claimed.
		res, err = s.db.ExecContext(ctx, `
			UPDATE cfgms_pending_registrations
			SET status = $1, claimed_at = $2
			WHERE pending_id = $3 AND status = 'approved'`,
			status, time.Now().UTC(), pendingID,
		)
	} else {
		res, err = s.db.ExecContext(ctx, `
			UPDATE cfgms_pending_registrations SET status = $1 WHERE pending_id = $2`,
			status, pendingID,
		)
	}
	if err != nil {
		return fmt.Errorf("database: failed to update status for %s: %w", pendingID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrPendingRegistrationNotFound
	}
	return nil
}

// ListPending returns all entries for the given tenantID, or all tenants if empty.
func (s *DatabasePendingRegistrationStore) ListPending(ctx context.Context, tenantID string) ([]*business.PendingRegistrationEntry, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if tenantID == "" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status
			FROM cfgms_pending_registrations ORDER BY registered_at ASC`)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status
			FROM cfgms_pending_registrations WHERE tenant_id = $1 ORDER BY registered_at ASC`, tenantID)
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to list pending registrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []*business.PendingRegistrationEntry
	for rows.Next() {
		e := &business.PendingRegistrationEntry{}
		var claimedAt sql.NullTime
		if err := rows.Scan(
			&e.PendingID, &e.StewardID, &e.TenantID, &e.TokenStr, &e.SourceIP,
			&e.RegisteredAt, &e.ExpiresAt, &claimedAt, &e.Status,
		); err != nil {
			return nil, fmt.Errorf("database: failed to scan pending registration: %w", err)
		}
		if claimedAt.Valid {
			t := claimedAt.Time.UTC()
			e.ClaimedAt = &t
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// ExpireStale marks pending entries whose expires_at is at or before cutoff as expired.
func (s *DatabasePendingRegistrationStore) ExpireStale(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE cfgms_pending_registrations
		SET status = $1
		WHERE status = $2 AND expires_at <= $3`,
		business.PendingRegistrationStatusExpired,
		business.PendingRegistrationStatusPending,
		cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("database: failed to expire stale pending registrations: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// Close closes the database connection.
func (s *DatabasePendingRegistrationStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func scanDBPendingEntry(row *sql.Row) (*business.PendingRegistrationEntry, error) {
	e := &business.PendingRegistrationEntry{}
	var claimedAt sql.NullTime
	err := row.Scan(
		&e.PendingID, &e.StewardID, &e.TenantID, &e.TokenStr, &e.SourceIP,
		&e.RegisteredAt, &e.ExpiresAt, &claimedAt, &e.Status,
	)
	if err == sql.ErrNoRows {
		return nil, business.ErrPendingRegistrationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to scan pending registration: %w", err)
	}
	if claimedAt.Valid {
		t := claimedAt.Time.UTC()
		e.ClaimedAt = &t
	}
	e.RegisteredAt = e.RegisteredAt.UTC()
	e.ExpiresAt = e.ExpiresAt.UTC()
	return e, nil
}
