// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements StewardStore using PostgreSQL with RLS tenant isolation.
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

// DatabaseStewardStore implements business.StewardStore using PostgreSQL.
// Records are append-only in practice: deregistered stewards are retained for audit.
// Tenant isolation is enforced by setting app.current_tenant via set_config inside
// each transaction that performs a tenant-scoped write or list operation.
type DatabaseStewardStore struct {
	db *sql.DB
}

// Compile-time check.
var _ business.StewardStore = (*DatabaseStewardStore)(nil)

// NewDatabaseStewardStore opens a pooled Postgres connection, initialises the schema, and
// returns a ready-to-use StewardStore.
func NewDatabaseStewardStore(dsn string, config map[string]interface{}) (*DatabaseStewardStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("database: failed to open steward store connection: %w", err)
	}

	db.SetMaxOpenConns(getIntFromConfig(config, "max_open_connections", 25))
	db.SetMaxIdleConns(getIntFromConfig(config, "max_idle_connections", 5))
	db.SetConnMaxLifetime(time.Duration(getIntFromConfig(config, "connection_max_lifetime_minutes", 30)) * time.Minute)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to ping steward store: %w", err)
	}

	store := &DatabaseStewardStore{db: db}
	if err := store.initializeSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to initialise steward store schema: %w", err)
	}
	return store, nil
}

func (s *DatabaseStewardStore) initializeSchema() error {
	ctx := context.Background()
	const lockID = 98765432
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("failed to acquire steward schema lock: %w", err)
	}
	defer func() { _, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID) }()
	return NewDatabaseSchemas().CreateStewardRecordsTable(ctx, s.db)
}

// Initialize is a no-op; schema is applied in the constructor.
func (s *DatabaseStewardStore) Initialize(_ context.Context) error { return nil }

// Close releases the database connection.
func (s *DatabaseStewardStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// RegisterSteward inserts a new steward record.
// Returns ErrStewardAlreadyExists if a record with the same ID already exists.
func (s *DatabaseStewardStore) RegisterSteward(ctx context.Context, record *business.StewardRecord) error {
	if record == nil {
		return fmt.Errorf("database: steward record cannot be nil")
	}
	if record.ID == "" {
		return fmt.Errorf("database: steward ID cannot be empty")
	}

	now := time.Now().UTC()
	status := record.Status
	if status == "" {
		status = business.StewardStatusRegistered
	}

	keyPub := record.IdentityKeyPub
	if keyPub == nil {
		keyPub = []byte{}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: failed to begin register steward tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := setTenantLocal(ctx, tx, record.TenantID); err != nil {
		return fmt.Errorf("database: failed to set tenant context: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO steward_records
			(id, tenant_id, hostname, platform, arch, version, ip_address, status,
			 registered_at, last_seen, last_heartbeat_at,
			 device_id, identity_key_pub, key_protection_level, last_provenance_json, hidden)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,$11,$12,$13,$14,$15)`,
		record.ID,
		record.TenantID,
		record.Hostname,
		record.Platform,
		record.Arch,
		record.Version,
		record.IPAddress,
		string(status),
		now,
		now,
		record.DeviceID,
		keyPub,
		record.KeyProtectionLevel,
		record.LastProvenanceJSON,
		record.Hidden,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
			return business.ErrStewardAlreadyExists
		}
		return fmt.Errorf("database: failed to register steward %s: %w", record.ID, err)
	}
	return tx.Commit()
}

// UpdateHeartbeat updates last_heartbeat_at and last_seen to now.
func (s *DatabaseStewardStore) UpdateHeartbeat(ctx context.Context, stewardID string) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
		UPDATE steward_records SET last_heartbeat_at = $2, last_seen = $2 WHERE id = $1`,
		stewardID, now)
	if err != nil {
		return fmt.Errorf("database: failed to update heartbeat for %s: %w", stewardID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrStewardNotFound
	}
	return nil
}

// GetSteward retrieves the record for the given steward ID.
func (s *DatabaseStewardStore) GetSteward(ctx context.Context, stewardID string) (*business.StewardRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, hostname, platform, arch, version, ip_address, status,
		       registered_at, last_seen, last_heartbeat_at,
		       device_id, identity_key_pub, key_protection_level, last_provenance_json, hidden
		FROM steward_records WHERE id = $1`, stewardID)
	return scanStewardDBRow(row)
}

// GetStewardByDeviceID retrieves the record whose device_id matches the given fingerprint.
// Returns ErrStewardNotFound when no matching record exists.
// Callers must inspect the returned record's Status and return ErrStewardRevoked if
// Status == StewardStatusRevoked (revocation-before-PoP ordering invariant, ADR-010 §3).
func (s *DatabaseStewardStore) GetStewardByDeviceID(ctx context.Context, deviceID string) (*business.StewardRecord, error) {
	if deviceID == "" {
		return nil, fmt.Errorf("database: device ID cannot be empty")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, hostname, platform, arch, version, ip_address, status,
		       registered_at, last_seen, last_heartbeat_at,
		       device_id, identity_key_pub, key_protection_level, last_provenance_json, hidden
		FROM steward_records WHERE device_id = $1 LIMIT 1`, deviceID)
	return scanStewardDBRow(row)
}

// ListStewards returns all steward records regardless of status.
func (s *DatabaseStewardStore) ListStewards(ctx context.Context) ([]*business.StewardRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, hostname, platform, arch, version, ip_address, status,
		       registered_at, last_seen, last_heartbeat_at,
		       device_id, identity_key_pub, key_protection_level, last_provenance_json, hidden
		FROM steward_records ORDER BY registered_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("database: failed to list stewards: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanStewardDBRows(rows)
}

// ListStewardsByStatus returns records with the given status, enforcing tenant isolation.
func (s *DatabaseStewardStore) ListStewardsByStatus(ctx context.Context, status business.StewardStatus) ([]*business.StewardRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, hostname, platform, arch, version, ip_address, status,
		       registered_at, last_seen, last_heartbeat_at,
		       device_id, identity_key_pub, key_protection_level, last_provenance_json, hidden
		FROM steward_records WHERE status = $1 ORDER BY registered_at ASC`,
		string(status))
	if err != nil {
		return nil, fmt.Errorf("database: failed to list stewards by status: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanStewardDBRows(rows)
}

// UpdateStewardStatus sets the lifecycle status and bumps last_seen.
func (s *DatabaseStewardStore) UpdateStewardStatus(ctx context.Context, stewardID string, status business.StewardStatus) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE steward_records SET status = $2, last_seen = $3 WHERE id = $1`,
		stewardID, string(status), time.Now().UTC())
	if err != nil {
		return fmt.Errorf("database: failed to update steward status %s: %w", stewardID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrStewardNotFound
	}
	return nil
}

// SetStewardHidden sets the operator-controlled visibility flag for the given steward.
func (s *DatabaseStewardStore) SetStewardHidden(ctx context.Context, stewardID string, hidden bool) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE steward_records SET hidden = $2 WHERE id = $1`,
		stewardID, hidden)
	if err != nil {
		return fmt.Errorf("database: failed to set hidden flag for steward %s: %w", stewardID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrStewardNotFound
	}
	return nil
}

// DeregisterSteward marks the steward as deregistered. Records are retained for audit.
func (s *DatabaseStewardStore) DeregisterSteward(ctx context.Context, stewardID string) error {
	return s.UpdateStewardStatus(ctx, stewardID, business.StewardStatusDeregistered)
}

// UpdateStewardTenant moves a steward to a different tenant by updating its tenant_id column.
func (s *DatabaseStewardStore) UpdateStewardTenant(ctx context.Context, stewardID, newTenantID string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE steward_records SET tenant_id = $2 WHERE id = $1`,
		stewardID, newTenantID)
	if err != nil {
		return fmt.Errorf("database: failed to update tenant for steward %s: %w", stewardID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrStewardNotFound
	}
	return nil
}

// GetStewardsSeen returns all stewards whose last_seen is after the given time.
func (s *DatabaseStewardStore) GetStewardsSeen(ctx context.Context, since time.Time) ([]*business.StewardRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, hostname, platform, arch, version, ip_address, status,
		       registered_at, last_seen, last_heartbeat_at,
		       device_id, identity_key_pub, key_protection_level, last_provenance_json, hidden
		FROM steward_records WHERE last_seen > $1 ORDER BY last_seen DESC`,
		since)
	if err != nil {
		return nil, fmt.Errorf("database: failed to get stewards seen since %v: %w", since, err)
	}
	defer func() { _ = rows.Close() }()
	return scanStewardDBRows(rows)
}

// HealthCheck verifies the database is reachable.
func (s *DatabaseStewardStore) HealthCheck(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func scanStewardDBRow(row *sql.Row) (*business.StewardRecord, error) {
	r := &business.StewardRecord{}
	var statusStr string
	var registeredAt, lastSeen time.Time
	var lastHeartbeat sql.NullTime
	var keyPub []byte

	err := row.Scan(
		&r.ID, &r.TenantID, &r.Hostname, &r.Platform, &r.Arch, &r.Version, &r.IPAddress,
		&statusStr, &registeredAt, &lastSeen, &lastHeartbeat,
		&r.DeviceID, &keyPub, &r.KeyProtectionLevel, &r.LastProvenanceJSON, &r.Hidden,
	)
	if err == sql.ErrNoRows {
		return nil, business.ErrStewardNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to scan steward: %w", err)
	}
	r.Status = business.StewardStatus(statusStr)
	r.RegisteredAt = registeredAt
	r.LastSeen = lastSeen
	if lastHeartbeat.Valid {
		r.LastHeartbeatAt = lastHeartbeat.Time
	}
	r.IdentityKeyPub = keyPub
	return r, nil
}

func scanStewardDBRows(rows *sql.Rows) ([]*business.StewardRecord, error) {
	var records []*business.StewardRecord
	for rows.Next() {
		r := &business.StewardRecord{}
		var statusStr string
		var registeredAt, lastSeen time.Time
		var lastHeartbeat sql.NullTime
		var keyPub []byte

		if err := rows.Scan(
			&r.ID, &r.TenantID, &r.Hostname, &r.Platform, &r.Arch, &r.Version, &r.IPAddress,
			&statusStr, &registeredAt, &lastSeen, &lastHeartbeat,
			&r.DeviceID, &keyPub, &r.KeyProtectionLevel, &r.LastProvenanceJSON, &r.Hidden,
		); err != nil {
			return nil, fmt.Errorf("database: failed to scan steward row: %w", err)
		}
		r.Status = business.StewardStatus(statusStr)
		r.RegisteredAt = registeredAt
		r.LastSeen = lastSeen
		if lastHeartbeat.Valid {
			r.LastHeartbeatAt = lastHeartbeat.Time
		}
		r.IdentityKeyPub = keyPub
		records = append(records, r)
	}
	return records, rows.Err()
}
