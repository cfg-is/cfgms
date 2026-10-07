// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements certinterfaces.RevocationStore using PostgreSQL
// (Issue #3852, ADR-031 Decision 1: pkg/cert's revocation list must be
// cluster-visible so a revocation issued by one controller node is observed
// by every node).
package database

import (
	"context"
	"database/sql"
	"fmt"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
)

// Compile-time assertion.
var _ certinterfaces.RevocationStore = (*DatabaseCertRevocationStore)(nil)

// DatabaseCertRevocationStore implements certinterfaces.RevocationStore using
// PostgreSQL. No caching: IsRevoked issues a direct read on every call, so a
// revocation is visible cluster-wide the instant it commits, at the cost of a
// network round trip per call on the mTLS admin-auth hot path. That trade is
// deliberate — the alternative (a local cache) reintroduces exactly the
// silent-staleness window this store exists to close, and cannot be made
// safe without a cluster-wide invalidation channel this store does not have.
type DatabaseCertRevocationStore struct {
	db *sql.DB
}

// NewDatabaseCertRevocationStore initialises the schema on the given shared
// connection pool and returns a ready-to-use CertRevocationStore.
func NewDatabaseCertRevocationStore(db *sql.DB, config map[string]interface{}) (*DatabaseCertRevocationStore, error) {
	store := &DatabaseCertRevocationStore{db: db}
	if err := NewDatabaseSchemas().CreateCertRevocationsTable(context.Background(), db); err != nil {
		return nil, fmt.Errorf("database: failed to initialise cert revocation schema: %w", err)
	}
	return store, nil
}

// Close is a no-op — DatabaseProvider.Close() owns the shared pool's lifecycle.
func (s *DatabaseCertRevocationStore) Close() error {
	return nil
}

// Revoke implements certinterfaces.RevocationStore.Revoke. ON CONFLICT DO
// NOTHING preserves the original RevokedAt on a repeated revoke of the same
// serial, matching the legacy node-local store's semantics exactly.
func (s *DatabaseCertRevocationStore) Revoke(ctx context.Context, entry certinterfaces.RevocationEntry) error {
	if entry.Serial == "" {
		return fmt.Errorf("database: revocation serial cannot be empty")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cfgms_cert_revocations (serial, revoked_at, reason)
		VALUES ($1, $2, $3)
		ON CONFLICT (serial) DO NOTHING`,
		entry.Serial, entry.RevokedAt, entry.Reason,
	)
	if err != nil {
		return fmt.Errorf("database: failed to store revocation: %w", err)
	}
	return nil
}

// IsRevoked implements certinterfaces.RevocationStore.IsRevoked.
func (s *DatabaseCertRevocationStore) IsRevoked(ctx context.Context, serial string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM cfgms_cert_revocations WHERE serial = $1)", serial,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("database: failed to check revocation status: %w", err)
	}
	return exists, nil
}

// ListRevoked implements certinterfaces.RevocationStore.ListRevoked.
func (s *DatabaseCertRevocationStore) ListRevoked(ctx context.Context) ([]certinterfaces.RevocationEntry, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT serial, revoked_at, reason FROM cfgms_cert_revocations")
	if err != nil {
		return nil, fmt.Errorf("database: failed to list revocations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []certinterfaces.RevocationEntry
	for rows.Next() {
		var e certinterfaces.RevocationEntry
		if err := rows.Scan(&e.Serial, &e.RevokedAt, &e.Reason); err != nil {
			return nil, fmt.Errorf("database: failed to scan revocation entry: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("database: failed to read revocations: %w", err)
	}
	return entries, nil
}
