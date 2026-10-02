// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite implements UpgradeStore using SQLite for durable upgrade-state persistence.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// SQLiteUpgradeStore implements business.UpgradeStore using a SQLite database.
// Records survive controller restarts and are queryable across sessions, closing
// the CLAUDE.md "No memory-only storage" violation that the prior in-memory wiring introduced.
type SQLiteUpgradeStore struct {
	db *sql.DB
}

// NewUpgradeStoreSQLFromDSN opens a SQLite database at dsn and returns a
// SQLiteUpgradeStore backed by it. The caller must call Initialize before any
// other method, and Close when done to release the underlying connection.
// Mirrors features/controller/run/run.go:NewRunStoreSQLFromDSN — open + busy_timeout only;
// schema creation belongs in Initialize.
func NewUpgradeStoreSQLFromDSN(dsn string) (*SQLiteUpgradeStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("upgrade store: open sqlite %s: %w", dsn, err)
	}
	// busy_timeout prevents SQLITE_BUSY errors when the main connection is writing.
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("upgrade store: set busy_timeout: %w", err)
	}
	return &SQLiteUpgradeStore{db: db}, nil
}

// Initialize creates the upgrade_records table if it does not already exist.
// Safe to call multiple times (idempotent). Unlike push_store.go whose schema is
// applied in the composite plugin's openAndInit, this store is wired standalone so
// its own Initialize method owns the DDL.
func (s *SQLiteUpgradeStore) Initialize(_ context.Context) error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS upgrade_records (
    id                       TEXT NOT NULL PRIMARY KEY,
    steward_id               TEXT NOT NULL,
    tenant_id                TEXT NOT NULL,
    version                  TEXT NOT NULL,
    platform                 TEXT NOT NULL,
    arch                     TEXT NOT NULL,
    sha256                   TEXT NOT NULL,
    status                   TEXT NOT NULL,
    initiated_by_subject     TEXT NOT NULL,
    initiated_by_tenant      TEXT NOT NULL,
    initiated_by_auth_method TEXT NOT NULL,
    publisher                TEXT NOT NULL,
    signature_digest         TEXT NOT NULL,
    bundle_signature         BLOB NOT NULL,
    created_at               TEXT NOT NULL,
    operation_nonce          BLOB,
    dispatched_at            TEXT NOT NULL,
    completed_at             TEXT,
    error_message            TEXT NOT NULL DEFAULT ''
)`)
	if err != nil {
		return fmt.Errorf("sqlite: failed to create upgrade_records table: %w", err)
	}
	return nil
}

// Close releases the database connection.
func (s *SQLiteUpgradeStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// HealthCheck pings the database to verify it is reachable and operational.
func (s *SQLiteUpgradeStore) HealthCheck(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("sqlite: upgrade store health check failed: %w", err)
	}
	return nil
}

// CreateUpgrade inserts a new upgrade record.
// Returns an error if record.BundleSignature is nil or empty — enforcing the same
// audit-completeness invariant as the memory provider (memory/upgrade_store.go:31-34).
func (s *SQLiteUpgradeStore) CreateUpgrade(ctx context.Context, record *business.UpgradeRecord) error {
	if len(record.BundleSignature) == 0 {
		return fmt.Errorf("sqlite: bundle signature is required")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO upgrade_records (
			id, steward_id, tenant_id, version, platform, arch, sha256, status,
			initiated_by_subject, initiated_by_tenant, initiated_by_auth_method,
			publisher, signature_digest, bundle_signature,
			created_at, operation_nonce, dispatched_at, completed_at, error_message
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID,
		record.StewardID,
		record.TenantID,
		record.Version,
		record.Platform,
		record.Arch,
		record.SHA256,
		string(record.Status),
		record.InitiatedBy.Subject,
		record.InitiatedBy.TenantID,
		record.InitiatedBy.AuthMethod,
		record.Publisher,
		record.SignatureDigest,
		record.BundleSignature,
		formatTime(record.CreatedAt),
		record.OperationNonce,
		formatTime(record.DispatchedAt),
		nullTime(record.CompletedAt),
		record.ErrorMessage,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("sqlite: upgrade record %s already exists", record.ID)
		}
		return fmt.Errorf("sqlite: failed to create upgrade record %s: %w", record.ID, err)
	}
	return nil
}

// UpdateUpgradeStatus updates the status and error message of the given upgrade record.
// Sets completed_at to the current UTC time when status is a terminal state
// (Committed, RolledBack, Failed), preserving any existing completed_at otherwise.
// Returns ErrUpgradeNotFound if no record exists for the ID.
func (s *SQLiteUpgradeStore) UpdateUpgradeStatus(ctx context.Context, id string, status business.UpgradeStatus, errorMsg string) error {
	isTerminal := status == business.UpgradeStatusCommitted ||
		status == business.UpgradeStatusRolledBack ||
		status == business.UpgradeStatusFailed
	var completedAt sql.NullString
	if isTerminal {
		now := nowUTC()
		completedAt = nullTime(&now)
	}
	// COALESCE keeps the existing completed_at when completedAt is NULL (non-terminal status).
	res, err := s.db.ExecContext(ctx, `
		UPDATE upgrade_records
		SET status = ?, error_message = ?, completed_at = COALESCE(?, completed_at)
		WHERE id = ?`,
		string(status), errorMsg, completedAt, id,
	)
	if err != nil {
		return fmt.Errorf("sqlite: failed to update upgrade status for %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrUpgradeNotFound
	}
	return nil
}

// GetUpgrade retrieves the upgrade record for the given ID.
// Returns ErrUpgradeNotFound if no record exists.
func (s *SQLiteUpgradeStore) GetUpgrade(ctx context.Context, id string) (*business.UpgradeRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, steward_id, tenant_id, version, platform, arch, sha256, status,
		       initiated_by_subject, initiated_by_tenant, initiated_by_auth_method,
		       publisher, signature_digest, bundle_signature,
		       created_at, operation_nonce, dispatched_at, completed_at, error_message
		FROM upgrade_records WHERE id = ?`, id)
	return scanUpgradeRow(row)
}

// ListUpgradesBySteward returns all upgrade records for the given stewardID,
// ordered by created_at descending (most recent first).
// Returns an empty slice (not an error) when no records exist.
func (s *SQLiteUpgradeStore) ListUpgradesBySteward(ctx context.Context, stewardID string) ([]*business.UpgradeRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, steward_id, tenant_id, version, platform, arch, sha256, status,
		       initiated_by_subject, initiated_by_tenant, initiated_by_auth_method,
		       publisher, signature_digest, bundle_signature,
		       created_at, operation_nonce, dispatched_at, completed_at, error_message
		FROM upgrade_records
		WHERE steward_id = ?
		ORDER BY created_at DESC, rowid DESC`, stewardID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list upgrade records by steward: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanUpgradeRows(rows)
}

// ListUpgradesByTenant returns all upgrade records for the given tenantID,
// ordered by created_at descending (most recent first).
// Returns an empty slice (not an error) when no records exist.
func (s *SQLiteUpgradeStore) ListUpgradesByTenant(ctx context.Context, tenantID string) ([]*business.UpgradeRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, steward_id, tenant_id, version, platform, arch, sha256, status,
		       initiated_by_subject, initiated_by_tenant, initiated_by_auth_method,
		       publisher, signature_digest, bundle_signature,
		       created_at, operation_nonce, dispatched_at, completed_at, error_message
		FROM upgrade_records
		WHERE tenant_id = ?
		ORDER BY created_at DESC, rowid DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list upgrade records by tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanUpgradeRows(rows)
}

// ---- helpers ----------------------------------------------------------------

func scanUpgradeRow(row *sql.Row) (*business.UpgradeRecord, error) {
	r := &business.UpgradeRecord{}
	var statusStr, createdStr, dispatchedStr string
	var completedStr sql.NullString
	err := row.Scan(
		&r.ID, &r.StewardID, &r.TenantID, &r.Version, &r.Platform, &r.Arch, &r.SHA256,
		&statusStr,
		&r.InitiatedBy.Subject, &r.InitiatedBy.TenantID, &r.InitiatedBy.AuthMethod,
		&r.Publisher, &r.SignatureDigest, &r.BundleSignature,
		&createdStr, &r.OperationNonce, &dispatchedStr, &completedStr, &r.ErrorMessage,
	)
	if err == sql.ErrNoRows {
		return nil, business.ErrUpgradeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to scan upgrade record: %w", err)
	}
	return populateUpgrade(r, statusStr, createdStr, dispatchedStr, completedStr), nil
}

func scanUpgradeRows(rows *sql.Rows) ([]*business.UpgradeRecord, error) {
	var records []*business.UpgradeRecord
	for rows.Next() {
		r := &business.UpgradeRecord{}
		var statusStr, createdStr, dispatchedStr string
		var completedStr sql.NullString
		if err := rows.Scan(
			&r.ID, &r.StewardID, &r.TenantID, &r.Version, &r.Platform, &r.Arch, &r.SHA256,
			&statusStr,
			&r.InitiatedBy.Subject, &r.InitiatedBy.TenantID, &r.InitiatedBy.AuthMethod,
			&r.Publisher, &r.SignatureDigest, &r.BundleSignature,
			&createdStr, &r.OperationNonce, &dispatchedStr, &completedStr, &r.ErrorMessage,
		); err != nil {
			return nil, fmt.Errorf("sqlite: failed to scan upgrade record row: %w", err)
		}
		records = append(records, populateUpgrade(r, statusStr, createdStr, dispatchedStr, completedStr))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if records == nil {
		return []*business.UpgradeRecord{}, nil
	}
	return records, nil
}

func populateUpgrade(r *business.UpgradeRecord, statusStr, createdStr, dispatchedStr string, completedStr sql.NullString) *business.UpgradeRecord {
	r.Status = business.UpgradeStatus(statusStr)
	r.CreatedAt = parseTime(createdStr)
	r.DispatchedAt = parseTime(dispatchedStr)
	r.CompletedAt = parseNullTime(completedStr)
	return r
}

// Compile-time assertion that SQLiteUpgradeStore satisfies business.UpgradeStore.
var _ business.UpgradeStore = (*SQLiteUpgradeStore)(nil)
