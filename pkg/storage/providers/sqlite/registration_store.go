// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite implements RegistrationTokenStore using SQLite
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// SQLiteRegistrationTokenStore implements business.RegistrationTokenStore using SQLite.
type SQLiteRegistrationTokenStore struct {
	db        *sql.DB
	consumeMu sync.Mutex // serializes ConsumeToken to prevent SQLITE_BUSY under high concurrency
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
func (s *SQLiteRegistrationTokenStore) GetToken(ctx context.Context, tokenStr string) (*business.RegistrationTokenData, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT token, tenant_id, controller_url, group_name, created_at,
		       expires_at, single_use, used_at, used_by, revoked, revoked_at
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
func (s *SQLiteRegistrationTokenStore) ListTokens(ctx context.Context, filter *business.RegistrationTokenFilter) ([]*business.RegistrationTokenData, error) {
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

// ConsumeToken atomically validates and marks a single-use token as used via a single UPDATE
// with a WHERE guard. If rows-affected == 0 for a single-use token, a follow-up SELECT
// distinguishes "not found" from "already used" to return the correct error.
// The consumeMu mutex serializes callers within the same process because the pure-Go SQLite
// driver does not reliably propagate busy_timeout across all pool connections.
func (s *SQLiteRegistrationTokenStore) ConsumeToken(ctx context.Context, tokenStr, stewardID string) error {
	s.consumeMu.Lock()
	defer s.consumeMu.Unlock()

	now := formatTime(nowUTC())

	// Attempt atomic mark-used for single-use tokens that are still unused.
	res, err := s.db.ExecContext(ctx, `
		UPDATE registration_tokens
		SET used_at = ?, used_by = ?
		WHERE token = ? AND single_use = 1 AND used_at IS NULL AND revoked = 0`,
		now, stewardID, tokenStr,
	)
	if err != nil {
		return fmt.Errorf("failed to consume registration token: %w", err)
	}

	n, _ := res.RowsAffected()
	if n > 0 {
		return nil
	}

	// Rows-affected == 0: either not found, already used, revoked, or multi-use. Inspect.
	data, err := s.GetToken(ctx, tokenStr)
	if err != nil {
		// Token genuinely does not exist.
		return fmt.Errorf("token not found")
	}

	if data.Revoked {
		return fmt.Errorf("token is revoked")
	}

	if data.SingleUse && data.UsedAt != nil {
		return business.ErrTokenAlreadyUsed
	}

	// Multi-use token or expired — validate then mark used unconditionally.
	if !data.IsValid() {
		return fmt.Errorf("token is not valid")
	}

	// Multi-use: mark used (tracks last consumer; non-blocking for concurrent callers).
	_, err = s.db.ExecContext(ctx, `
		UPDATE registration_tokens SET used_at = ?, used_by = ? WHERE token = ?`,
		now, stewardID, tokenStr,
	)
	if err != nil {
		return fmt.Errorf("failed to mark multi-use token as used: %w", err)
	}
	return nil
}

// ---- helpers ----------------------------------------------------------------

func scanToken(row *sql.Row) (*business.RegistrationTokenData, error) {
	t := &business.RegistrationTokenData{}
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

func scanTokenRow(rows *sql.Rows) (*business.RegistrationTokenData, error) {
	t := &business.RegistrationTokenData{}
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
	t *business.RegistrationTokenData,
	createdStr string,
	singleUse, revoked int,
	expiresAt, usedAt, revokedAt sql.NullString,
) (*business.RegistrationTokenData, error) {
	t.CreatedAt = parseTime(createdStr)
	t.SingleUse = singleUse != 0
	t.Revoked = revoked != 0
	t.ExpiresAt = parseNullTime(expiresAt)
	t.UsedAt = parseNullTime(usedAt)
	t.RevokedAt = parseNullTime(revokedAt)
	return t, nil
}

// ensure SQLiteRegistrationTokenStore satisfies the interface at compile time
var _ business.RegistrationTokenStore = (*SQLiteRegistrationTokenStore)(nil)
