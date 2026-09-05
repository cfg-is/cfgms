// SPDX-License-Identifier: AGPL-3.0-only
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
func NewDatabasePendingRegistrationStore(db *sql.DB, config map[string]interface{}) (*DatabasePendingRegistrationStore, error) {
	store := &DatabasePendingRegistrationStore{db: db, schemas: NewDatabaseSchemas()}
	if err := store.initSchema(); err != nil {
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
	tokenLookupKey := business.RegistrationTokenLookupKey(entry.TokenStr)
	keyPub := entry.IdentityKeyPub
	if keyPub == nil {
		keyPub = []byte{}
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cfgms_pending_registrations
			(pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status,
			 device_id, identity_key_pub, key_protection_level, csr_pem, hostname, platform)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		entry.PendingID, entry.StewardID, entry.TenantID, tokenLookupKey, entry.SourceIP,
		registeredAt, entry.ExpiresAt, entry.ClaimedAt, status,
		entry.DeviceID, keyPub, entry.KeyProtectionLevel, entry.CSRPEM, entry.Hostname, entry.Platform,
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
		SELECT pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status,
		       device_id, identity_key_pub, key_protection_level, csr_pem, hostname, platform
		FROM cfgms_pending_registrations WHERE pending_id = $1`, pendingID)
	return scanDBPendingEntry(row)
}

// GetPendingByToken retrieves the entry whose token lookup key matches the raw
// token. The plaintext branch is read-only migration compatibility.
func (s *DatabasePendingRegistrationStore) GetPendingByToken(ctx context.Context, tokenStr string) (*business.PendingRegistrationEntry, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status,
		       device_id, identity_key_pub, key_protection_level, csr_pem, hostname, platform
		FROM cfgms_pending_registrations WHERE token_str IN ($1, $2) LIMIT 1`,
		business.RegistrationTokenLookupKey(tokenStr), tokenStr)
	return scanDBPendingEntry(row)
}

// UpdateStatus updates the status of the entry.
// When status is "claimed", claimed_at is also set to now. Returns
// ErrPendingRegistrationNotFound if no record exists, or (Issue #3895) if a
// guarded transition's precondition on the entry's current status no longer
// holds.
func (s *DatabasePendingRegistrationStore) UpdateStatus(ctx context.Context, pendingID, status string) error {
	var res sql.Result
	var err error

	switch status {
	case business.PendingRegistrationStatusClaimed:
		// Guard with AND status = 'approved' so concurrent polls of the same entry
		// result in exactly one winner: RowsAffected = 0 means already claimed.
		res, err = s.db.ExecContext(ctx, `
			UPDATE cfgms_pending_registrations
			SET status = $1, claimed_at = $2
			WHERE pending_id = $3 AND status = 'approved'`,
			status, time.Now().UTC(), pendingID,
		)
	case business.PendingRegistrationStatusApproved:
		// Issue #3895: guard with AND status = 'pending', mirroring the claimed
		// transition's guard above. Without this, an approve landing on an
		// any-node request after the entry was already claimed (or already
		// approved/denied by a concurrent request) would flip it back to
		// approved — reopening the claim window handleRegistrationStatus's own
		// "AND status = 'approved'" guard exists to close, and enabling a second
		// certificate issuance for one registration.
		res, err = s.db.ExecContext(ctx, `
			UPDATE cfgms_pending_registrations
			SET status = $1
			WHERE pending_id = $2 AND status = 'pending'`,
			status, pendingID,
		)
	case business.PendingRegistrationStatusDenied:
		// Deny is guarded on 'pending' OR 'approved', not on 'pending' alone.
		// approved → denied is the only mechanism that stops certificate
		// issuance for a registration an operator approved by mistake or later
		// judged hostile: an approved-but-unclaimed entry stays claimable until
		// ExpiresAt, so refusing this transition would leave the operator with
		// no way to revoke the approval before the steward claims its cert.
		// 'claimed', 'denied' and 'expired' remain excluded — those are terminal
		// (see pendingRegistrationTerminalStatuses in pkg/migrate/storage), and
		// denying a claimed entry would falsely suggest an issued cert had been
		// withdrawn.
		res, err = s.db.ExecContext(ctx, `
			UPDATE cfgms_pending_registrations
			SET status = $1
			WHERE pending_id = $2 AND status IN ('pending', 'approved')`,
			status, pendingID,
		)
	default:
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

// ListPending returns entries whose status is "pending" for the given tenantID,
// or all tenants if empty, ordered by registered_at ascending.
// Approved, denied, claimed, and expired entries are never included.
func (s *DatabasePendingRegistrationStore) ListPending(ctx context.Context, tenantID string) ([]*business.PendingRegistrationEntry, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if tenantID == "" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status,
			       device_id, identity_key_pub, key_protection_level, csr_pem, hostname, platform
			FROM cfgms_pending_registrations WHERE status = $1 ORDER BY registered_at ASC`,
			business.PendingRegistrationStatusPending)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status,
			       device_id, identity_key_pub, key_protection_level, csr_pem, hostname, platform
			FROM cfgms_pending_registrations WHERE tenant_id = $1 AND status = $2 ORDER BY registered_at ASC`,
			tenantID, business.PendingRegistrationStatusPending)
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to list pending registrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []*business.PendingRegistrationEntry
	for rows.Next() {
		e, err := scanDBPendingRow(rows)
		if err != nil {
			return nil, fmt.Errorf("database: failed to scan pending registration: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// ListAll returns entries in every status for the given tenantID, or all
// tenants if empty, ordered by registered_at ascending.
func (s *DatabasePendingRegistrationStore) ListAll(ctx context.Context, tenantID string) ([]*business.PendingRegistrationEntry, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if tenantID == "" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status,
			       device_id, identity_key_pub, key_protection_level, csr_pem, hostname, platform
			FROM cfgms_pending_registrations ORDER BY registered_at ASC`)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT pending_id, steward_id, tenant_id, token_str, source_ip, registered_at, expires_at, claimed_at, status,
			       device_id, identity_key_pub, key_protection_level, csr_pem, hostname, platform
			FROM cfgms_pending_registrations WHERE tenant_id = $1 ORDER BY registered_at ASC`,
			tenantID)
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to list all pending registrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []*business.PendingRegistrationEntry
	for rows.Next() {
		e, err := scanDBPendingRow(rows)
		if err != nil {
			return nil, fmt.Errorf("database: failed to scan pending registration: %w", err)
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
// Close is a no-op: the underlying connection pool is owned and closed by
// DatabaseProvider, not by individual stores (ADR-031 Decision 6).
func (s *DatabasePendingRegistrationStore) Close() error {
	return nil
}

func scanDBPendingEntry(row *sql.Row) (*business.PendingRegistrationEntry, error) {
	e := &business.PendingRegistrationEntry{}
	var claimedAt sql.NullTime
	var keyPub []byte
	err := row.Scan(
		&e.PendingID, &e.StewardID, &e.TenantID, &e.TokenStr, &e.SourceIP,
		&e.RegisteredAt, &e.ExpiresAt, &claimedAt, &e.Status,
		&e.DeviceID, &keyPub, &e.KeyProtectionLevel, &e.CSRPEM, &e.Hostname, &e.Platform,
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
	if len(keyPub) > 0 {
		e.IdentityKeyPub = keyPub
	}
	e.RegisteredAt = e.RegisteredAt.UTC()
	e.ExpiresAt = e.ExpiresAt.UTC()
	return e, nil
}

func scanDBPendingRow(rows *sql.Rows) (*business.PendingRegistrationEntry, error) {
	e := &business.PendingRegistrationEntry{}
	var claimedAt sql.NullTime
	var keyPub []byte
	if err := rows.Scan(
		&e.PendingID, &e.StewardID, &e.TenantID, &e.TokenStr, &e.SourceIP,
		&e.RegisteredAt, &e.ExpiresAt, &claimedAt, &e.Status,
		&e.DeviceID, &keyPub, &e.KeyProtectionLevel, &e.CSRPEM, &e.Hostname, &e.Platform,
	); err != nil {
		return nil, err
	}
	if claimedAt.Valid {
		t := claimedAt.Time.UTC()
		e.ClaimedAt = &t
	}
	if len(keyPub) > 0 {
		e.IdentityKeyPub = keyPub
	}
	e.RegisteredAt = e.RegisteredAt.UTC()
	e.ExpiresAt = e.ExpiresAt.UTC()
	return e, nil
}
