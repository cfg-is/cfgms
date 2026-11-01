// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite implements NonceStore using SQLite (Issue #3755, ADR-031
// amendment to ADR-011).
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.NonceStore = (*SQLiteNonceStore)(nil)

// SQLiteNonceStore implements business.NonceStore using SQLite.
type SQLiteNonceStore struct {
	db *sql.DB
}

// Close closes the underlying database connection.
func (s *SQLiteNonceStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// PutNonce implements business.NonceStore.PutNonce.
func (s *SQLiteNonceStore) PutNonce(ctx context.Context, key string, entry []byte, ttl time.Duration) error {
	if key == "" {
		return fmt.Errorf("sqlite: nonce key cannot be empty")
	}
	expiresAt := formatTime(nowUTC().Add(ttl))
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO refresh_nonces (key, entry, expires_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET entry = excluded.entry, expires_at = excluded.expires_at`,
		key, entry, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("sqlite: failed to store nonce: %w", err)
	}
	return nil
}

// GetAndConsumeNonce implements business.NonceStore.GetAndConsumeNonce.
// DELETE ... RETURNING is a single atomic statement under SQLite's file-level
// locking, so concurrent callers racing on the same key cannot both observe
// found=true.
func (s *SQLiteNonceStore) GetAndConsumeNonce(ctx context.Context, key string) ([]byte, bool, error) {
	row := s.db.QueryRowContext(ctx, `
		DELETE FROM refresh_nonces WHERE key = ? AND expires_at > ? RETURNING entry`,
		key, formatTime(nowUTC()),
	)
	var entry []byte
	if err := row.Scan(&entry); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("sqlite: failed to consume nonce: %w", err)
	}
	return entry, true, nil
}
