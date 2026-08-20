// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements PushStore using PostgreSQL (Issue #3402).
package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.PushStore = (*DatabasePushStore)(nil)

// DatabasePushStore implements business.PushStore using PostgreSQL.
// A new leader queries this store to resume pending and in-progress pushes
// after failover, replaying the stored StewardConfiguration blob.
type DatabasePushStore struct {
	db *sql.DB
}

// NewDatabasePushStore opens a pooled Postgres connection, initialises the
// schema, and returns a ready-to-use PushStore.
func NewDatabasePushStore(dsn string, config map[string]interface{}) (*DatabasePushStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("database: failed to open push store connection: %w", err)
	}
	db.SetMaxOpenConns(getIntFromConfig(config, "max_open_connections", 25))
	db.SetMaxIdleConns(getIntFromConfig(config, "max_idle_connections", 5))
	db.SetConnMaxLifetime(time.Duration(getIntFromConfig(config, "connection_max_lifetime_minutes", 30)) * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to ping push store: %w", err)
	}
	store := &DatabasePushStore{db: db}
	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to initialise push schema: %w", err)
	}
	return store, nil
}

func (s *DatabasePushStore) initSchema() error {
	ctx := context.Background()
	const lockID = 16925002 // advisory lock ID unique to cfgms_push_records schema
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("database: failed to acquire push schema lock: %w", err)
	}
	defer func() { _, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID) }()
	return NewDatabaseSchemas().CreatePushRecordsTable(ctx, s.db)
}

// Close releases the database connection.
func (s *DatabasePushStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// CreatePush inserts a new push record with status PushStatusPending.
// Returns an error (not ErrPushNotFound) if a record with the same ID exists.
func (s *DatabasePushStore) CreatePush(ctx context.Context, record *business.PushRecord) error {
	if record == nil {
		return fmt.Errorf("database: push record cannot be nil")
	}
	if record.ID == "" {
		return fmt.Errorf("database: push record ID cannot be empty")
	}

	now := time.Now().UTC()
	status := record.Status
	if status == "" {
		status = business.PushStatusPending
	}
	createdAt := record.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cfgms_push_records
			(id, config_id, tenant_id, version, status, initiated_by, data, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		record.ID,
		record.ConfigID,
		record.TenantID,
		record.Version,
		string(status),
		record.InitiatedBy,
		nullableBytes(record.Data),
		createdAt,
		now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique_violation") {
			return fmt.Errorf("database: push record %s already exists", record.ID)
		}
		return fmt.Errorf("database: failed to create push record %s: %w", record.ID, err)
	}
	return nil
}

// UpdatePushStatus updates the status and updated_at of the given push record.
// Returns ErrPushNotFound if no record exists for the ID.
func (s *DatabasePushStore) UpdatePushStatus(ctx context.Context, id string, status business.PushStatus) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE cfgms_push_records SET status = $1, updated_at = $2 WHERE id = $3`,
		string(status), time.Now().UTC(), id,
	)
	if err != nil {
		return fmt.Errorf("database: failed to update push status for %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrPushNotFound
	}
	return nil
}

// GetPendingPushes returns all records with status pending or in_progress,
// ordered by created_at ascending so older pushes are resumed first.
// A new leader calls this on startup to resume all unfinished work after failover.
func (s *DatabasePushStore) GetPendingPushes(ctx context.Context) ([]*business.PushRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, config_id, tenant_id, version, status, initiated_by, data, created_at, updated_at
		FROM cfgms_push_records
		WHERE status IN ($1, $2)
		ORDER BY created_at ASC`,
		string(business.PushStatusPending), string(business.PushStatusInProgress),
	)
	if err != nil {
		return nil, fmt.Errorf("database: failed to get pending push records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanDBPushRows(rows)
}

// GetPush retrieves the push record for the given ID.
// Returns ErrPushNotFound if no record exists.
func (s *DatabasePushStore) GetPush(ctx context.Context, id string) (*business.PushRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, config_id, tenant_id, version, status, initiated_by, data, created_at, updated_at
		FROM cfgms_push_records WHERE id = $1`, id)
	return scanDBPushRow(row)
}

// ListPushesByConfigID returns all push records for the given config ID scoped
// to the given tenant, ordered by created_at descending (most recent first).
// Both configID and tenantID are required — a non-empty tenantID prevents
// cross-tenant data disclosure.
func (s *DatabasePushStore) ListPushesByConfigID(ctx context.Context, configID, tenantID string) ([]*business.PushRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, config_id, tenant_id, version, status, initiated_by, data, created_at, updated_at
		FROM cfgms_push_records
		WHERE config_id = $1 AND tenant_id = $2
		ORDER BY created_at DESC`,
		configID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("database: failed to list push records for config %s: %w", configID, err)
	}
	defer func() { _ = rows.Close() }()
	records, err := scanDBPushRows(rows)
	if err != nil {
		return nil, err
	}
	if records == nil {
		return []*business.PushRecord{}, nil
	}
	return records, nil
}

// ---- helpers ----------------------------------------------------------------

// scanDBPushRow scans a *sql.Row into a PushRecord.
func scanDBPushRow(row *sql.Row) (*business.PushRecord, error) {
	r := &business.PushRecord{}
	var statusStr string
	var data []byte
	err := row.Scan(
		&r.ID, &r.ConfigID, &r.TenantID, &r.Version,
		&statusStr, &r.InitiatedBy, &data,
		&r.CreatedAt, &r.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, business.ErrPushNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to scan push record: %w", err)
	}
	r.Status = business.PushStatus(statusStr)
	r.CreatedAt = r.CreatedAt.UTC()
	r.UpdatedAt = r.UpdatedAt.UTC()
	r.Data = data
	return r, nil
}

// scanDBPushRows scans *sql.Rows into a slice of PushRecords.
func scanDBPushRows(rows *sql.Rows) ([]*business.PushRecord, error) {
	var records []*business.PushRecord
	for rows.Next() {
		r := &business.PushRecord{}
		var statusStr string
		var data []byte
		if err := rows.Scan(
			&r.ID, &r.ConfigID, &r.TenantID, &r.Version,
			&statusStr, &r.InitiatedBy, &data,
			&r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("database: failed to scan push record row: %w", err)
		}
		r.Status = business.PushStatus(statusStr)
		r.CreatedAt = r.CreatedAt.UTC()
		r.UpdatedAt = r.UpdatedAt.UTC()
		r.Data = data
		records = append(records, r)
	}
	return records, rows.Err()
}
