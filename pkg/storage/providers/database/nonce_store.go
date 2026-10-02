// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements NonceStore using PostgreSQL (Issue #3755, ADR-031
// amendment to ADR-011).
package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.NonceStore = (*DatabaseNonceStore)(nil)

// DatabaseNonceStore implements business.NonceStore using PostgreSQL.
type DatabaseNonceStore struct {
	db *sql.DB
}

// NewDatabaseNonceStore initialises the schema on the given shared connection
// pool and returns a ready-to-use NonceStore.
func NewDatabaseNonceStore(db *sql.DB, config map[string]interface{}) (*DatabaseNonceStore, error) {
	store := &DatabaseNonceStore{db: db}
	if err := store.initSchema(); err != nil {
		return nil, fmt.Errorf("database: failed to initialise nonce schema: %w", err)
	}
	return store, nil
}

func (s *DatabaseNonceStore) initSchema() error {
	ctx := context.Background()
	const lockID = 71934864 // advisory lock ID unique to refresh_nonces schema
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("database: failed to acquire nonce schema lock: %w", err)
	}
	defer func() { _, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID) }()
	return NewDatabaseSchemas().CreateRefreshNoncesTable(ctx, s.db)
}

// Close is a no-op — DatabaseProvider.Close() owns the shared pool's lifecycle.
func (s *DatabaseNonceStore) Close() error {
	return nil
}

// PutNonce implements business.NonceStore.PutNonce.
func (s *DatabaseNonceStore) PutNonce(ctx context.Context, key string, entry []byte, ttl time.Duration) error {
	if key == "" {
		return fmt.Errorf("database: nonce key cannot be empty")
	}
	expiresAt := time.Now().UTC().Add(ttl)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO refresh_nonces (key, entry, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (key) DO UPDATE SET entry = EXCLUDED.entry, expires_at = EXCLUDED.expires_at`,
		key, entry, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("database: failed to store nonce: %w", err)
	}
	return nil
}

// GetAndConsumeNonce implements business.NonceStore.GetAndConsumeNonce.
// DELETE ... RETURNING is a single atomic statement: concurrent callers racing
// on the same key — including callers on different controller nodes — can
// never both observe found=true.
func (s *DatabaseNonceStore) GetAndConsumeNonce(ctx context.Context, key string) ([]byte, bool, error) {
	row := s.db.QueryRowContext(ctx, `
		DELETE FROM refresh_nonces WHERE key = $1 AND expires_at > $2 RETURNING entry`,
		key, time.Now().UTC(),
	)
	var entry []byte
	if err := row.Scan(&entry); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("database: failed to consume nonce: %w", err)
	}
	return entry, true, nil
}
