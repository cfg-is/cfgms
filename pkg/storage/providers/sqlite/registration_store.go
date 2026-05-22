// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite implements RegistrationTokenStore using SQLite
package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"fmt"
	"strings"
	"sync"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// SQLiteRegistrationTokenStore implements business.RegistrationTokenStore using SQLite.
type SQLiteRegistrationTokenStore struct {
	db       *sql.DB
	rotateMu sync.Mutex // serializes concurrent RotateToken calls per-instance
}

// Initialize is a no-op; schema is applied in openAndInit.
func (s *SQLiteRegistrationTokenStore) Initialize(_ context.Context) error { return nil }

// Close closes the database connection.
func (s *SQLiteRegistrationTokenStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// SaveToken persists a registration token. Uses UPSERT semantics so that
// subsequent calls with the same token update mutable state.
func (s *SQLiteRegistrationTokenStore) SaveToken(ctx context.Context, token *business.RegistrationTokenData) error {
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}
	if token.Token == "" {
		return fmt.Errorf("token string cannot be empty")
	}
	if token.CreatedAt.IsZero() {
		token.CreatedAt = nowUTC()
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO registration_tokens
			(token, tenant_id, controller_url, group_name, created_at,
			 expires_at, revoked, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(token) DO UPDATE SET
			tenant_id = excluded.tenant_id,
			controller_url = excluded.controller_url,
			group_name = excluded.group_name,
			expires_at = excluded.expires_at,
			revoked = excluded.revoked,
			revoked_at = excluded.revoked_at`,
		token.Token,
		token.TenantID,
		token.ControllerURL,
		token.Group,
		formatTime(token.CreatedAt),
		nullTime(token.ExpiresAt),
		boolToInt(token.Revoked),
		nullTime(token.RevokedAt),
	)
	if err != nil {
		return fmt.Errorf("failed to save registration token: %w", err)
	}
	return nil
}

// GetToken retrieves a registration token by its token string.
func (s *SQLiteRegistrationTokenStore) GetToken(ctx context.Context, tokenStr string) (*business.RegistrationTokenData, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT token, tenant_id, controller_url, group_name, created_at,
		       expires_at, revoked, revoked_at
		FROM registration_tokens WHERE token = ?`, tokenStr)
	return scanToken(row)
}

// UpdateToken replaces a registration token's mutable state.
func (s *SQLiteRegistrationTokenStore) UpdateToken(ctx context.Context, token *business.RegistrationTokenData) error {
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE registration_tokens
		SET tenant_id = ?, controller_url = ?, group_name = ?,
		    expires_at = ?, revoked = ?, revoked_at = ?
		WHERE token = ?`,
		token.TenantID,
		token.ControllerURL,
		token.Group,
		nullTime(token.ExpiresAt),
		boolToInt(token.Revoked),
		nullTime(token.RevokedAt),
		token.Token,
	)
	if err != nil {
		return fmt.Errorf("failed to update registration token: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("registration token not found")
	}
	return nil
}

// DeleteToken removes a registration token.
func (s *SQLiteRegistrationTokenStore) DeleteToken(ctx context.Context, tokenStr string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM registration_tokens WHERE token = ?`, tokenStr)
	if err != nil {
		return fmt.Errorf("failed to delete registration token: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("registration token not found")
	}
	return nil
}

// ListTokens returns registration tokens matching an optional filter.
func (s *SQLiteRegistrationTokenStore) ListTokens(ctx context.Context, filter *business.RegistrationTokenFilter) ([]*business.RegistrationTokenData, error) {
	query := `SELECT token, tenant_id, controller_url, group_name, created_at,
	                 expires_at, revoked, revoked_at
	          FROM registration_tokens WHERE 1=1`
	var args []interface{}

	if filter != nil {
		if filter.TenantID != "" {
			query += ` AND tenant_id = ?`
			args = append(args, filter.TenantID)
		}
		if filter.Group != "" {
			query += ` AND group_name = ?`
			args = append(args, filter.Group)
		}
		if filter.Revoked != nil {
			query += ` AND revoked = ?`
			args = append(args, boolToInt(*filter.Revoked))
		}
	}

	query += ` ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list registration tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tokens []*business.RegistrationTokenData
	for rows.Next() {
		t, err := scanTokenRow(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// RotateToken atomically revokes all prior tokens for tenant+group and creates a new one in
// a single SQLite transaction, ensuring no overlap window between old and new tokens.
// rotateMu serializes concurrent callers to prevent SQLite snapshot-isolation conflicts.
func (s *SQLiteRegistrationTokenStore) RotateToken(ctx context.Context, tenantID, group string) (*business.RegistrationTokenData, error) {
	s.rotateMu.Lock()
	defer s.rotateMu.Unlock()

	newTokenStr, err := generateTokenString()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin rotation transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Find an existing active token to inherit controller_url.
	var controllerURL string
	err = tx.QueryRowContext(ctx, `
		SELECT controller_url FROM registration_tokens
		WHERE tenant_id = ? AND group_name = ? AND revoked = 0
		ORDER BY created_at DESC LIMIT 1`,
		tenantID, group,
	).Scan(&controllerURL)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no active tokens found for tenant %q group %q", tenantID, group)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find existing token: %w", err)
	}

	now := nowUTC()
	nowStr := formatTime(now)

	// Insert the new token.
	_, err = tx.ExecContext(ctx, `
		INSERT INTO registration_tokens
			(token, tenant_id, controller_url, group_name, created_at, revoked)
		VALUES (?, ?, ?, ?, ?, 0)`,
		newTokenStr, tenantID, controllerURL, group, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert new token: %w", err)
	}

	// Revoke all prior tokens for this tenant+group atomically.
	_, err = tx.ExecContext(ctx, `
		UPDATE registration_tokens
		SET revoked = 1, revoked_at = ?
		WHERE tenant_id = ? AND group_name = ? AND revoked = 0 AND token != ?`,
		nowStr, tenantID, group, newTokenStr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke old tokens: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit rotation: %w", err)
	}
	committed = true

	return &business.RegistrationTokenData{
		Token:         newTokenStr,
		TenantID:      tenantID,
		ControllerURL: controllerURL,
		Group:         group,
		CreatedAt:     now,
	}, nil
}

// ---- helpers ----------------------------------------------------------------

func scanToken(row *sql.Row) (*business.RegistrationTokenData, error) {
	t := &business.RegistrationTokenData{}
	var createdStr string
	var expiresAt, revokedAt sql.NullString
	var revoked int

	err := row.Scan(
		&t.Token, &t.TenantID, &t.ControllerURL, &t.Group,
		&createdStr, &expiresAt, &revoked, &revokedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("registration token not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan registration token: %w", err)
	}
	return populateToken(t, createdStr, revoked, expiresAt, revokedAt)
}

func scanTokenRow(rows *sql.Rows) (*business.RegistrationTokenData, error) {
	t := &business.RegistrationTokenData{}
	var createdStr string
	var expiresAt, revokedAt sql.NullString
	var revoked int

	if err := rows.Scan(
		&t.Token, &t.TenantID, &t.ControllerURL, &t.Group,
		&createdStr, &expiresAt, &revoked, &revokedAt,
	); err != nil {
		return nil, fmt.Errorf("failed to scan registration token row: %w", err)
	}
	return populateToken(t, createdStr, revoked, expiresAt, revokedAt)
}

func populateToken(
	t *business.RegistrationTokenData,
	createdStr string,
	revoked int,
	expiresAt, revokedAt sql.NullString,
) (*business.RegistrationTokenData, error) {
	t.CreatedAt = parseTime(createdStr)
	t.Revoked = revoked != 0
	t.ExpiresAt = parseNullTime(expiresAt)
	t.RevokedAt = parseNullTime(revokedAt)
	return t, nil
}

// generateTokenString produces a random base32-encoded token string (16 bytes / 128-bit entropy).
func generateTokenString() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

// ensure SQLiteRegistrationTokenStore satisfies the interface at compile time
var _ business.RegistrationTokenStore = (*SQLiteRegistrationTokenStore)(nil)
