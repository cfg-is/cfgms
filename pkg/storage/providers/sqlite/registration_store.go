// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite implements RegistrationTokenStore using SQLite
package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// SQLiteRegistrationTokenStore implements interfaces.RegistrationTokenStore using SQLite.
type SQLiteRegistrationTokenStore struct {
	db *sql.DB
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
// subsequent calls with the same token update mutable state — required for
// single-use enforcement (Story #299 parity with the database provider).
func (s *SQLiteRegistrationTokenStore) SaveToken(ctx context.Context, token *interfaces.RegistrationTokenData) error {
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
			 expires_at, single_use, used_at, used_by, revoked, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(token) DO UPDATE SET
			tenant_id = excluded.tenant_id,
			controller_url = excluded.controller_url,
			group_name = excluded.group_name,
			expires_at = excluded.expires_at,
			single_use = excluded.single_use,
			used_at = excluded.used_at,
			used_by = excluded.used_by,
			revoked = excluded.revoked,
			revoked_at = excluded.revoked_at`,
		token.Token,
		token.TenantID,
		token.ControllerURL,
		token.Group,
		formatTime(token.CreatedAt),
		nullTime(token.ExpiresAt),
		boolToInt(token.SingleUse),
		nullTime(token.UsedAt),
		token.UsedBy,
		boolToInt(token.Revoked),
		nullTime(token.RevokedAt),
	)
	if err != nil {
		return fmt.Errorf("failed to save registration token: %w", err)
	}
	return nil
}

// GetToken retrieves a registration token by its token string.
func (s *SQLiteRegistrationTokenStore) GetToken(ctx context.Context, tokenStr string) (*interfaces.RegistrationTokenData, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT token, tenant_id, controller_url, group_name, created_at,
		       expires_at, single_use, used_at, used_by, revoked, revoked_at
		FROM registration_tokens WHERE token = ?`, tokenStr)
	return scanToken(row)
}

// UpdateToken replaces a registration token's mutable state.
func (s *SQLiteRegistrationTokenStore) UpdateToken(ctx context.Context, token *interfaces.RegistrationTokenData) error {
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE registration_tokens
		SET tenant_id = ?, controller_url = ?, group_name = ?,
		    expires_at = ?, single_use = ?, used_at = ?, used_by = ?,
		    revoked = ?, revoked_at = ?
		WHERE token = ?`,
		token.TenantID,
		token.ControllerURL,
		token.Group,
		nullTime(token.ExpiresAt),
		boolToInt(token.SingleUse),
		nullTime(token.UsedAt),
		token.UsedBy,
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
func (s *SQLiteRegistrationTokenStore) ListTokens(ctx context.Context, filter *interfaces.RegistrationTokenFilter) ([]*interfaces.RegistrationTokenData, error) {
	query := `SELECT token, tenant_id, controller_url, group_name, created_at,
	                 expires_at, single_use, used_at, used_by, revoked, revoked_at
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
		if filter.SingleUse != nil {
			query += ` AND single_use = ?`
			args = append(args, boolToInt(*filter.SingleUse))
		}
		if filter.Used != nil {
			if *filter.Used {
				query += ` AND used_at IS NOT NULL`
			} else {
				query += ` AND used_at IS NULL`
			}
		}
	}

	query += ` ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list registration tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tokens []*interfaces.RegistrationTokenData
	for rows.Next() {
		t, err := scanTokenRow(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// ---- helpers ----------------------------------------------------------------

func scanToken(row *sql.Row) (*interfaces.RegistrationTokenData, error) {
	t := &interfaces.RegistrationTokenData{}
	var createdStr string
	var expiresAt, usedAt, revokedAt sql.NullString
	var singleUse, revoked int

	err := row.Scan(
		&t.Token, &t.TenantID, &t.ControllerURL, &t.Group,
		&createdStr, &expiresAt, &singleUse, &usedAt, &t.UsedBy,
		&revoked, &revokedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("registration token not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan registration token: %w", err)
	}
	return populateToken(t, createdStr, singleUse, revoked, expiresAt, usedAt, revokedAt)
}

func scanTokenRow(rows *sql.Rows) (*interfaces.RegistrationTokenData, error) {
	t := &interfaces.RegistrationTokenData{}
	var createdStr string
	var expiresAt, usedAt, revokedAt sql.NullString
	var singleUse, revoked int

	if err := rows.Scan(
		&t.Token, &t.TenantID, &t.ControllerURL, &t.Group,
		&createdStr, &expiresAt, &singleUse, &usedAt, &t.UsedBy,
		&revoked, &revokedAt,
	); err != nil {
		return nil, fmt.Errorf("failed to scan registration token row: %w", err)
	}
	return populateToken(t, createdStr, singleUse, revoked, expiresAt, usedAt, revokedAt)
}

func populateToken(
	t *interfaces.RegistrationTokenData,
	createdStr string,
	singleUse, revoked int,
	expiresAt, usedAt, revokedAt sql.NullString,
) (*interfaces.RegistrationTokenData, error) {
	t.CreatedAt = parseTime(createdStr)
	t.SingleUse = singleUse != 0
	t.Revoked = revoked != 0
	t.ExpiresAt = parseNullTime(expiresAt)
	t.UsedAt = parseNullTime(usedAt)
	t.RevokedAt = parseNullTime(revokedAt)
	return t, nil
}

// ensure SQLiteRegistrationTokenStore satisfies the interface at compile time
var _ interfaces.RegistrationTokenStore = (*SQLiteRegistrationTokenStore)(nil)
