// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements business.UpgradeStore using PostgreSQL — the
// durable steward upgrade records shared by every controller node (Issue #5977).
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.UpgradeStore = (*DatabaseUpgradeStore)(nil)

// upgradeSchemaLockID is the advisory lock ID unique to the upgrade records
// schema; it serialises concurrent node startups creating the table and its
// policies.
const upgradeSchemaLockID = 71934866

// pgUniqueViolation is the SQLSTATE of a primary-key or unique-index conflict.
const pgUniqueViolation = "23505"

// DatabaseUpgradeStore implements business.UpgradeStore using PostgreSQL with
// row-level tenant isolation. Writes run in a transaction that sets
// app.current_tenant; reads run without a tenant context, which the read policy
// permits (the HTTP handlers enforce tenant access on the returned record).
type DatabaseUpgradeStore struct {
	db *sql.DB
}

// NewDatabaseUpgradeStore creates the store on the shared connection pool db
// (owned by DatabaseProvider; ADR-031 Decision 6) and ensures its table exists.
//
//duplication:justified pkg/storage/providers/database/rollout_store.go -- same advisory-lock-then-create-schema constructor as NewDatabaseRolloutStore; the lock ID and the schema method differ
func NewDatabaseUpgradeStore(db *sql.DB, _ map[string]interface{}) (*DatabaseUpgradeStore, error) {
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("database: failed to acquire upgrade schema connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", upgradeSchemaLockID); err != nil {
		return nil, fmt.Errorf("database: failed to acquire upgrade schema lock: %w", err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", upgradeSchemaLockID) }()
	if err := NewDatabaseSchemas().CreateUpgradeRecordsTable(ctx, db); err != nil {
		return nil, err
	}
	return &DatabaseUpgradeStore{db: db}, nil
}

const upgradeColumns = `id, steward_id, tenant_id, version, platform, arch, sha256, status,
	initiated_by_subject, initiated_by_tenant, initiated_by_auth_method,
	publisher, signature_digest, bundle_signature,
	created_at, operation_nonce, dispatched_at, completed_at, error_message`

// CreateUpgrade implements business.UpgradeStore. A record without a bundle
// signature is refused: the publisher-signature provenance cannot be added later.
func (s *DatabaseUpgradeStore) CreateUpgrade(ctx context.Context, record *business.UpgradeRecord) error {
	if record == nil {
		return errors.New("database: upgrade record cannot be nil")
	}
	if len(record.BundleSignature) == 0 {
		return errors.New("database: bundle signature is required")
	}
	// An absent nonce is stored as NULL, not as an empty byte string.
	var nonce interface{}
	if len(record.OperationNonce) > 0 {
		nonce = record.OperationNonce
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: failed to begin create upgrade tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenantLocal(ctx, tx, record.TenantID); err != nil {
		return fmt.Errorf("database: failed to set tenant context: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cfgms_upgrade_records
			(`+upgradeColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		record.ID, record.StewardID, record.TenantID, record.Version, record.Platform, record.Arch,
		record.SHA256, string(record.Status),
		record.InitiatedBy.Subject, record.InitiatedBy.TenantID, record.InitiatedBy.AuthMethod,
		record.Publisher, record.SignatureDigest, record.BundleSignature,
		record.CreatedAt, nonce, record.DispatchedAt, record.CompletedAt, record.ErrorMessage,
	); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == pgUniqueViolation {
			return fmt.Errorf("database: upgrade record %s already exists", record.ID)
		}
		return fmt.Errorf("database: failed to insert upgrade record %s: %w", record.ID, err)
	}
	return tx.Commit()
}

func scanUpgrade(row rowScanner) (*business.UpgradeRecord, error) {
	r := &business.UpgradeRecord{}
	var status string
	var completed sql.NullTime
	if err := row.Scan(&r.ID, &r.StewardID, &r.TenantID, &r.Version, &r.Platform, &r.Arch, &r.SHA256,
		&status,
		&r.InitiatedBy.Subject, &r.InitiatedBy.TenantID, &r.InitiatedBy.AuthMethod,
		&r.Publisher, &r.SignatureDigest, &r.BundleSignature,
		&r.CreatedAt, &r.OperationNonce, &r.DispatchedAt, &completed, &r.ErrorMessage); err != nil {
		return nil, err
	}
	r.Status = business.UpgradeStatus(status)
	r.CreatedAt = r.CreatedAt.UTC()
	r.DispatchedAt = r.DispatchedAt.UTC()
	if completed.Valid {
		t := completed.Time.UTC()
		r.CompletedAt = &t
	}
	return r, nil
}

// GetUpgrade implements business.UpgradeStore. It reads by ID alone, so any
// controller node returns a record written by any other.
func (s *DatabaseUpgradeStore) GetUpgrade(ctx context.Context, id string) (*business.UpgradeRecord, error) {
	r, err := scanUpgrade(s.db.QueryRowContext(ctx,
		`SELECT `+upgradeColumns+` FROM cfgms_upgrade_records WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, business.ErrUpgradeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to get upgrade record %s: %w", id, err)
	}
	return r, nil
}

// UpdateUpgradeStatus implements business.UpgradeStore. A terminal status
// (committed, rolled_back, failed) stamps completed_at; any other status keeps
// the completed_at already recorded. The row-level update policy needs the
// record's tenant, so it is read first.
func (s *DatabaseUpgradeStore) UpdateUpgradeStatus(ctx context.Context, id string, status business.UpgradeStatus, errorMsg string) error {
	var tenantID string
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id FROM cfgms_upgrade_records WHERE id = $1`, id).Scan(&tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return business.ErrUpgradeNotFound
	}
	if err != nil {
		return fmt.Errorf("database: failed to fetch upgrade record tenant: %w", err)
	}

	var completedAt *time.Time
	if status == business.UpgradeStatusCommitted ||
		status == business.UpgradeStatusRolledBack ||
		status == business.UpgradeStatusFailed {
		now := time.Now().UTC()
		completedAt = &now
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: failed to begin update upgrade tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenantLocal(ctx, tx, tenantID); err != nil {
		return fmt.Errorf("database: failed to set tenant context: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE cfgms_upgrade_records
		SET status = $2, error_message = $3, completed_at = COALESCE($4, completed_at)
		WHERE id = $1`, id, string(status), errorMsg, completedAt)
	if err != nil {
		return fmt.Errorf("database: failed to update upgrade status for %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return business.ErrUpgradeNotFound
	}
	return tx.Commit()
}

// ListUpgradesBySteward implements business.UpgradeStore, newest first.
func (s *DatabaseUpgradeStore) ListUpgradesBySteward(ctx context.Context, stewardID string) ([]*business.UpgradeRecord, error) {
	return s.queryUpgrades(ctx,
		`SELECT `+upgradeColumns+` FROM cfgms_upgrade_records WHERE steward_id = $1 ORDER BY created_at DESC, id DESC`,
		stewardID)
}

// ListUpgradesByTenant implements business.UpgradeStore, newest first.
func (s *DatabaseUpgradeStore) ListUpgradesByTenant(ctx context.Context, tenantID string) ([]*business.UpgradeRecord, error) {
	return s.queryUpgrades(ctx,
		`SELECT `+upgradeColumns+` FROM cfgms_upgrade_records WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC`,
		tenantID)
}

// queryUpgrades runs a list query and returns its rows; no rows is an empty
// slice, not an error.
func (s *DatabaseUpgradeStore) queryUpgrades(ctx context.Context, query string, args ...interface{}) ([]*business.UpgradeRecord, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("database: failed to list upgrade records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []*business.UpgradeRecord{}
	for rows.Next() {
		r, err := scanUpgrade(rows)
		if err != nil {
			return nil, fmt.Errorf("database: failed to scan upgrade record: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("database: failed to list upgrade records: %w", err)
	}
	return out, nil
}

// HealthCheck implements business.UpgradeStore.
func (s *DatabaseUpgradeStore) HealthCheck(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Initialize implements business.UpgradeStore. The schema is created by
// NewDatabaseUpgradeStore, so there is nothing left to prepare.
func (s *DatabaseUpgradeStore) Initialize(_ context.Context) error { return nil }

// Close is a no-op: the connection pool is owned and closed by DatabaseProvider
// (ADR-031 Decision 6).
func (s *DatabaseUpgradeStore) Close() error { return nil }
