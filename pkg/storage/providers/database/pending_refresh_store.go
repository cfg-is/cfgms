// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements PendingRefreshStore using PostgreSQL (Issue #2329).
package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.PendingRefreshStore = (*DatabasePendingRefreshStore)(nil)

// DatabasePendingRefreshStore implements business.PendingRefreshStore using PostgreSQL.
type DatabasePendingRefreshStore struct {
	db *sql.DB
}

// NewDatabasePendingRefreshStore opens a pooled Postgres connection, initialises
// the schema, and returns a ready-to-use PendingRefreshStore.
func NewDatabasePendingRefreshStore(dsn string, config map[string]interface{}) (*DatabasePendingRefreshStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("database: failed to open pending refresh store connection: %w", err)
	}
	db.SetMaxOpenConns(getIntFromConfig(config, "max_open_connections", 25))
	db.SetMaxIdleConns(getIntFromConfig(config, "max_idle_connections", 5))
	db.SetConnMaxLifetime(time.Duration(getIntFromConfig(config, "connection_max_lifetime_minutes", 30)) * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to ping pending refresh store: %w", err)
	}
	store := &DatabasePendingRefreshStore{db: db}
	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to initialise pending refresh schema: %w", err)
	}
	return store, nil
}

func (s *DatabasePendingRefreshStore) initSchema() error {
	ctx := context.Background()
	const lockID = 41782095 // advisory lock ID unique to pending_refresh_requests schema
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("database: failed to acquire pending refresh schema lock: %w", err)
	}
	defer func() { _, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID) }()
	return NewDatabaseSchemas().CreatePendingRefreshRequestsTable(ctx, s.db)
}

// Close releases the database connection.
func (s *DatabasePendingRefreshStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// AddPendingRefresh inserts a new pending-refresh entry.
// Returns an error if an entry with the same PendingID already exists.
func (s *DatabasePendingRefreshStore) AddPendingRefresh(ctx context.Context, entry *business.PendingRefreshEntry) error {
	if entry == nil {
		return fmt.Errorf("database: pending refresh entry cannot be nil")
	}
	if entry.PendingID == "" {
		return fmt.Errorf("database: pending_id cannot be empty")
	}
	if entry.DeviceID == "" {
		return fmt.Errorf("database: device_id cannot be empty")
	}
	if entry.TenantID == "" {
		return fmt.Errorf("database: tenant_id cannot be empty")
	}

	createdAt := entry.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
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
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		entry.PendingID,
		entry.DeviceID,
		entry.TenantID,
		entry.SourceIP,
		entry.ProvenanceMatchedFields,
		entry.ProvenanceTotalFields,
		claimBundle,
		status,
		createdAt,
		entry.ExpiresAt,
		nullableTime(entry.ResolvedAt),
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return fmt.Errorf("database: pending refresh %s already exists", entry.PendingID)
		}
		return fmt.Errorf("database: failed to add pending refresh %s: %w", entry.PendingID, err)
	}
	return nil
}

// GetPendingRefreshByID retrieves the entry for the given pending_id.
// Returns ErrPendingRefreshNotFound if no record exists.
func (s *DatabasePendingRefreshStore) GetPendingRefreshByID(ctx context.Context, pendingID string) (*business.PendingRefreshEntry, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT pending_id, device_id, tenant_id, source_ip,
		       provenance_matched_fields, provenance_total_fields,
		       claim_bundle, status, created_at, expires_at, resolved_at
		FROM pending_refresh_requests WHERE pending_id = $1`, pendingID)
	return scanPendingRefreshDBRow(row)
}

// UpdateRefreshStatus updates the status of the entry identified by pendingID.
// For terminal statuses (approved, rejected), resolved_at is also set to now.
// Returns ErrPendingRefreshNotFound if no record exists.
func (s *DatabasePendingRefreshStore) UpdateRefreshStatus(ctx context.Context, pendingID, status string) error {
	var (
		res sql.Result
		err error
	)
	isTerminal := status == business.PendingRefreshStatusApproved ||
		status == business.PendingRefreshStatusRejected
	if isTerminal {
		res, err = s.db.ExecContext(ctx, `
			UPDATE pending_refresh_requests
			SET status = $1, resolved_at = $2
			WHERE pending_id = $3`,
			status, time.Now().UTC(), pendingID,
		)
	} else {
		res, err = s.db.ExecContext(ctx, `
			UPDATE pending_refresh_requests SET status = $1 WHERE pending_id = $2`,
			status, pendingID,
		)
	}
	if err != nil {
		return fmt.Errorf("database: failed to update refresh status for %s: %w", pendingID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrPendingRefreshNotFound
	}
	return nil
}

// ListPendingRefresh returns all entries for the given tenantID ordered by
// created_at ascending. An empty tenantID returns entries for all tenants.
func (s *DatabasePendingRefreshStore) ListPendingRefresh(ctx context.Context, tenantID string) ([]*business.PendingRefreshEntry, error) {
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
			FROM pending_refresh_requests WHERE tenant_id = $1 ORDER BY created_at ASC`
		args = []interface{}{tenantID}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("database: failed to list pending refresh requests: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []*business.PendingRefreshEntry
	for rows.Next() {
		e, err := scanPendingRefreshDBRows(rows)
		if err != nil {
			return nil, fmt.Errorf("database: failed to scan pending refresh row: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// ExpireStaleRefresh marks entries whose expires_at is at or before cutoff and
// whose status is "pending" as "expired", setting resolved_at to now.
func (s *DatabasePendingRefreshStore) ExpireStaleRefresh(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE pending_refresh_requests
		SET status = $1, resolved_at = $2
		WHERE status = $3 AND expires_at <= $4`,
		business.PendingRefreshStatusExpired,
		time.Now().UTC(),
		business.PendingRefreshStatusPending,
		cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("database: failed to expire stale refresh requests: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// StoreClaimBundle persists the proof-of-possession payload for the given pendingID.
// Returns ErrPendingRefreshNotFound if no record exists.
func (s *DatabasePendingRefreshStore) StoreClaimBundle(ctx context.Context, pendingID string, bundle []byte) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE pending_refresh_requests SET claim_bundle = $1 WHERE pending_id = $2`,
		bundle, pendingID,
	)
	if err != nil {
		return fmt.Errorf("database: failed to store claim bundle for %s: %w", pendingID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrPendingRefreshNotFound
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func scanPendingRefreshDBRow(row *sql.Row) (*business.PendingRefreshEntry, error) {
	e := &business.PendingRefreshEntry{}
	var resolvedAt sql.NullTime
	var claimBundle []byte
	err := row.Scan(
		&e.PendingID, &e.DeviceID, &e.TenantID, &e.SourceIP,
		&e.ProvenanceMatchedFields, &e.ProvenanceTotalFields,
		&claimBundle, &e.Status, &e.CreatedAt, &e.ExpiresAt, &resolvedAt,
	)
	if err == sql.ErrNoRows {
		return nil, business.ErrPendingRefreshNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to scan pending refresh: %w", err)
	}
	e.ClaimBundle = claimBundle
	if resolvedAt.Valid {
		t := resolvedAt.Time
		e.ResolvedAt = &t
	}
	return e, nil
}

func scanPendingRefreshDBRows(rows *sql.Rows) (*business.PendingRefreshEntry, error) {
	e := &business.PendingRefreshEntry{}
	var resolvedAt sql.NullTime
	var claimBundle []byte
	if err := rows.Scan(
		&e.PendingID, &e.DeviceID, &e.TenantID, &e.SourceIP,
		&e.ProvenanceMatchedFields, &e.ProvenanceTotalFields,
		&claimBundle, &e.Status, &e.CreatedAt, &e.ExpiresAt, &resolvedAt,
	); err != nil {
		return nil, err
	}
	e.ClaimBundle = claimBundle
	if resolvedAt.Valid {
		t := resolvedAt.Time
		e.ResolvedAt = &t
	}
	return e, nil
}

// nullableTime converts a *time.Time to an interface value suitable for
// binding as a nullable TIMESTAMP column: nil pointers produce SQL NULL.
func nullableTime(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return *t
}
