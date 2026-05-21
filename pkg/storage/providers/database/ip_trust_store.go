// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq" // PostgreSQL driver

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.IPTrustStore = (*DatabaseIPTrustStore)(nil)

// DatabaseIPTrustStore implements IPTrustStore using PostgreSQL.
type DatabaseIPTrustStore struct {
	db      *sql.DB
	mu      sync.RWMutex
	schemas DatabaseSchemas
}

// NewDatabaseIPTrustStore opens a PostgreSQL-backed IPTrustStore at dsn.
func NewDatabaseIPTrustStore(dsn string, config map[string]interface{}) (*DatabaseIPTrustStore, error) {
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

	store := &DatabaseIPTrustStore{db: db, schemas: NewDatabaseSchemas()}
	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialise ip trust schema: %w", err)
	}
	return store, nil
}

func (s *DatabaseIPTrustStore) initSchema() error {
	ctx := context.Background()
	const lockID = 16923847 // unique advisory lock ID for this schema

	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("failed to acquire ip trust schema lock: %w", err)
	}
	defer func() {
		_, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID)
	}()

	return s.schemas.CreateIPTrustRangesTable(ctx, s.db)
}

// Close closes the underlying database connection.
func (s *DatabaseIPTrustStore) Close() error {
	return s.db.Close()
}

// normalizeCIDR returns the network-address form of cidr (e.g. "192.168.1.0/24").
func normalizeCIDR(cidr string) (string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	return ipNet.String(), nil
}

// AddTrustedRange implements IPTrustStore.AddTrustedRange.
// CIDR is normalised before storage. A previously revoked entry is re-activated.
func (s *DatabaseIPTrustStore) AddTrustedRange(ctx context.Context, tenantID, cidr string, preSeeded bool) error {
	normalized, err := normalizeCIDR(cidr)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	id := uuid.New().String()
	now := time.Now().UTC()

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO cfgms_ip_trust_ranges
			(id, tenant_id, cidr, pre_seeded, trusted_since)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, cidr) DO UPDATE SET
			pre_seeded    = EXCLUDED.pre_seeded,
			trusted_since = EXCLUDED.trusted_since,
			revoked       = FALSE,
			revoked_at    = NULL`,
		id, tenantID, normalized, preSeeded, now,
	)
	if err != nil {
		return fmt.Errorf("failed to add trusted range: %w", err)
	}
	return nil
}

// IsTrusted implements IPTrustStore.IsTrusted.
// Containment is evaluated in Go — not SQL — via net.ParseCIDR + ipNet.Contains.
func (s *DatabaseIPTrustStore) IsTrusted(ctx context.Context, tenantID, ip string) (bool, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, fmt.Errorf("invalid IP address: %s", ip)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx, `
		SELECT cidr FROM cfgms_ip_trust_ranges
		WHERE tenant_id = $1 AND revoked = FALSE`,
		tenantID,
	)
	if err != nil {
		return false, fmt.Errorf("failed to query trusted ranges: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var cidrStr string
		if err := rows.Scan(&cidrStr); err != nil {
			return false, fmt.Errorf("failed to scan CIDR: %w", err)
		}
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue // skip malformed stored entries
		}
		if ipNet.Contains(parsedIP) {
			return true, nil
		}
	}
	return false, rows.Err()
}

// ListTrustedRanges implements IPTrustStore.ListTrustedRanges.
// Returns all entries for the tenant (including revoked), ordered by trusted_since.
func (s *DatabaseIPTrustStore) ListTrustedRanges(ctx context.Context, tenantID string) ([]*business.IPTrustEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, cidr, pre_seeded, trusted_since,
		       last_activity, last_activity_ip, revoked, revoked_at
		FROM cfgms_ip_trust_ranges
		WHERE tenant_id = $1
		ORDER BY trusted_since ASC`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list trusted ranges: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []*business.IPTrustEntry
	for rows.Next() {
		e, err := scanIPTrustEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// RevokeTrustedRange implements IPTrustStore.RevokeTrustedRange.
func (s *DatabaseIPTrustStore) RevokeTrustedRange(ctx context.Context, tenantID, cidr string) error {
	normalized, err := normalizeCIDR(cidr)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
		UPDATE cfgms_ip_trust_ranges
		SET revoked = TRUE, revoked_at = $1
		WHERE tenant_id = $2 AND cidr = $3 AND revoked = FALSE`,
		now, tenantID, normalized,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke trusted range: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrIPTrustEntryNotFound
	}
	return nil
}

// RecordHealthySteward implements IPTrustStore.RecordHealthySteward.
// Finds the CIDR entry containing ip and upserts last_activity / last_activity_ip.
// No-op if no matching non-revoked entry exists.
func (s *DatabaseIPTrustStore) RecordHealthySteward(ctx context.Context, tenantID, ip string, at time.Time) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Fetch all non-revoked CIDRs for containment check in Go.
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, cidr FROM cfgms_ip_trust_ranges
		WHERE tenant_id = $1 AND revoked = FALSE`,
		tenantID,
	)
	if err != nil {
		return fmt.Errorf("failed to query ranges for activity update: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var matchID string
	for rows.Next() {
		var id, cidrStr string
		if err := rows.Scan(&id, &cidrStr); err != nil {
			return fmt.Errorf("failed to scan range row: %w", err)
		}
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		if ipNet.Contains(parsedIP) {
			matchID = id
			break
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating ranges: %w", err)
	}
	if matchID == "" {
		return nil // no matching entry — no-op per spec
	}

	_, err = s.db.ExecContext(ctx, `
		UPDATE cfgms_ip_trust_ranges
		SET last_activity = $1, last_activity_ip = $2
		WHERE id = $3`,
		at.UTC(), ip, matchID,
	)
	if err != nil {
		return fmt.Errorf("failed to record healthy steward: %w", err)
	}
	return nil
}

// GetLastActivity implements IPTrustStore.GetLastActivity.
// Returns nil, nil when no matching entry or no activity has been recorded.
func (s *DatabaseIPTrustStore) GetLastActivity(ctx context.Context, tenantID, ip string) (*business.IPTrustActivity, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx, `
		SELECT cidr, last_activity FROM cfgms_ip_trust_ranges
		WHERE tenant_id = $1 AND revoked = FALSE`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query ranges for activity: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var cidrStr string
		var lastActivity sql.NullTime
		if err := rows.Scan(&cidrStr, &lastActivity); err != nil {
			return nil, fmt.Errorf("failed to scan activity row: %w", err)
		}
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		if ipNet.Contains(parsedIP) {
			if !lastActivity.Valid {
				return nil, nil
			}
			return &business.IPTrustActivity{
				TenantID: tenantID,
				IP:       ip,
				LastSeen: lastActivity.Time,
			}, nil
		}
	}
	return nil, rows.Err()
}

// rowScanner abstracts *sql.Rows so scanIPTrustEntry can be shared.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

// scanIPTrustEntry scans one row from cfgms_ip_trust_ranges into an IPTrustEntry.
func scanIPTrustEntry(row rowScanner) (*business.IPTrustEntry, error) {
	var (
		e            business.IPTrustEntry
		lastActivity sql.NullTime
		lastActIP    sql.NullString
		revokedAt    sql.NullTime
	)
	if err := row.Scan(
		&e.ID,
		&e.TenantID,
		&e.CIDR,
		&e.PreSeeded,
		&e.TrustedSince,
		&lastActivity,
		&lastActIP,
		&e.Revoked,
		&revokedAt,
	); err != nil {
		return nil, fmt.Errorf("failed to scan ip trust entry: %w", err)
	}
	if lastActivity.Valid {
		e.LastActivity = lastActivity.Time
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		e.RevokedAt = &t
	}
	return &e, nil
}
