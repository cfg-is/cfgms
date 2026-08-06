// SPDX-License-Identifier: AGPL-3.0-only
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
	"time"

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
	// Every persisted token carries a stable, non-secret UUID (Issue #2970) so the
	// web UI can address it without holding the secret.
	if token.ID == "" {
		id, err := generateTokenID()
		if err != nil {
			return fmt.Errorf("failed to generate token id: %w", err)
		}
		token.ID = id
	}

	// The id is assigned once and never reassigned: on conflict the stored id wins and
	// excluded.id only fills in a row that has none. NULLIF treats an empty stored id as
	// absent — the same "missing" predicate the back-fill uses (id IS NULL OR id = '') —
	// so a row that reaches this path unaddressable is healed rather than kept that way.
	// RETURNING keeps the caller's in-memory ID identical to the persisted one.
	var storedID sql.NullString
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO registration_tokens
			(token, id, tenant_id, controller_url, group_name, created_at,
			 expires_at, revoked, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(token) DO UPDATE SET
			id = COALESCE(NULLIF(registration_tokens.id, ''), excluded.id),
			tenant_id = excluded.tenant_id,
			controller_url = excluded.controller_url,
			group_name = excluded.group_name,
			expires_at = excluded.expires_at,
			revoked = excluded.revoked,
			revoked_at = excluded.revoked_at
		RETURNING id`,
		business.RegistrationTokenLookupKey(token.Token),
		nullableStr(token.ID),
		token.TenantID,
		token.ControllerURL,
		token.Group,
		formatTime(token.CreatedAt),
		nullTime(token.ExpiresAt),
		boolToInt(token.Revoked),
		nullTime(token.RevokedAt),
	).Scan(&storedID)
	if err != nil {
		return fmt.Errorf("failed to save registration token: %w", err)
	}
	token.ID = storedID.String
	return nil
}

// GetToken retrieves a registration token by its token string.
func (s *SQLiteRegistrationTokenStore) GetToken(ctx context.Context, tokenStr string) (*business.RegistrationTokenData, error) {
	lookupKey := business.RegistrationTokenLookupKey(tokenStr)
	row := s.db.QueryRowContext(ctx, `
		SELECT token, id, tenant_id, controller_url, group_name, created_at,
		       expires_at, revoked, revoked_at
		FROM registration_tokens WHERE token = ?`, lookupKey)
	token, err := scanToken(row)
	if err != nil && lookupKey != tokenStr {
		// Read legacy plaintext rows so they can be rotated without downtime.
		token, err = scanToken(s.db.QueryRowContext(ctx, `
			SELECT token, id, tenant_id, controller_url, group_name, created_at,
			       expires_at, revoked, revoked_at
			FROM registration_tokens WHERE token = ?`, tokenStr))
	}
	if err == nil {
		token.Token = tokenStr
	}
	return token, err
}

// GetTokenByID retrieves a registration token by its stable UUID (Issue #2970).
func (s *SQLiteRegistrationTokenStore) GetTokenByID(ctx context.Context, id string) (*business.RegistrationTokenData, error) {
	if id == "" {
		return nil, fmt.Errorf("registration token not found")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT token, id, tenant_id, controller_url, group_name, created_at,
		       expires_at, revoked, revoked_at
		FROM registration_tokens WHERE id = ?`, id)
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
		WHERE token IN (?, ?)`,
		token.TenantID,
		token.ControllerURL,
		token.Group,
		nullTime(token.ExpiresAt),
		boolToInt(token.Revoked),
		nullTime(token.RevokedAt),
		business.RegistrationTokenLookupKey(token.Token),
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
	res, err := s.db.ExecContext(ctx, `DELETE FROM registration_tokens WHERE token IN (?, ?)`,
		business.RegistrationTokenLookupKey(tokenStr), tokenStr)
	if err != nil {
		return fmt.Errorf("failed to delete registration token: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("registration token not found")
	}
	return nil
}

// ClaimToken atomically reserves a valid token for one device identity at the
// REST admission boundary. It does not revoke the token: registration tokens are
// perennial (Issue #1690) and one fleet token enrols many endpoints.
func (s *SQLiteRegistrationTokenStore) ClaimToken(ctx context.Context, tokenStr, claimID string) (bool, error) {
	if tokenStr == "" {
		return false, fmt.Errorf("token string cannot be empty")
	}
	if claimID == "" {
		return false, fmt.Errorf("registration claim ID cannot be empty")
	}

	now := nowUTC()
	lookupKey := business.RegistrationTokenLookupKey(tokenStr)
	res, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO registration_token_claims (token, claim_id, claimed_at)
		SELECT ?, ?, ?
		WHERE EXISTS (
			SELECT 1 FROM registration_tokens
			WHERE token IN (?, ?)
			  AND revoked = 0
			  AND (expires_at IS NULL OR expires_at > ?)
		)`,
		lookupKey,
		claimID,
		formatTime(now),
		lookupKey,
		tokenStr,
		formatTime(now),
	)
	if err != nil {
		return false, fmt.Errorf("failed to claim registration token: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to confirm registration token claim: %w", err)
	}
	if affected == 1 {
		return true, nil
	}

	// No row was inserted: either this device already holds a claim (a retry) or
	// the token itself is not usable. Distinguishing the two keeps a retry
	// idempotent without reporting a revoked token as a successful claim.
	var claimed int
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM registration_token_claims WHERE token = ? AND claim_id = ?`,
		lookupKey, claimID,
	).Scan(&claimed)
	if err != nil {
		return false, fmt.Errorf("failed to inspect registration token claim: %w", err)
	}
	if claimed == 1 {
		return false, nil
	}
	return false, fmt.Errorf("registration token is invalid, expired, or revoked")
}

// ReleaseTokenClaim removes only the exact claim made by this REST attempt.
func (s *SQLiteRegistrationTokenStore) ReleaseTokenClaim(ctx context.Context, tokenStr, claimID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM registration_token_claims WHERE token = ? AND claim_id = ?`,
		business.RegistrationTokenLookupKey(tokenStr),
		claimID,
	)
	if err != nil {
		return fmt.Errorf("failed to release registration token claim: %w", err)
	}
	return nil
}

// ListTokens returns registration tokens matching an optional filter.
func (s *SQLiteRegistrationTokenStore) ListTokens(ctx context.Context, filter *business.RegistrationTokenFilter) ([]*business.RegistrationTokenData, error) {
	query := `SELECT token, id, tenant_id, controller_url, group_name, created_at,
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
	expiresAt := now.Add(15 * time.Minute)
	newLookupKey := business.RegistrationTokenLookupKey(newTokenStr)

	newID, err := generateTokenID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	// Insert the new token.
	_, err = tx.ExecContext(ctx, `
		INSERT INTO registration_tokens
			(token, id, tenant_id, controller_url, group_name, created_at, expires_at, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
		newLookupKey, newID, tenantID, controllerURL, group, nowStr, formatTime(expiresAt),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert new token: %w", err)
	}

	// Revoke all prior tokens for this tenant+group atomically.
	_, err = tx.ExecContext(ctx, `
		UPDATE registration_tokens
		SET revoked = 1, revoked_at = ?
		WHERE tenant_id = ? AND group_name = ? AND revoked = 0 AND token != ?`,
		nowStr, tenantID, group, newLookupKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke old tokens: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit rotation: %w", err)
	}
	committed = true

	return &business.RegistrationTokenData{
		ID:            newID,
		Token:         newTokenStr,
		TenantID:      tenantID,
		ControllerURL: controllerURL,
		Group:         group,
		CreatedAt:     now,
		ExpiresAt:     &expiresAt,
	}, nil
}

// ---- helpers ----------------------------------------------------------------

func scanToken(row *sql.Row) (*business.RegistrationTokenData, error) {
	t := &business.RegistrationTokenData{}
	var createdStr string
	var id sql.NullString
	var expiresAt, revokedAt sql.NullString
	var revoked int

	err := row.Scan(
		&t.Token, &id, &t.TenantID, &t.ControllerURL, &t.Group,
		&createdStr, &expiresAt, &revoked, &revokedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("registration token not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan registration token: %w", err)
	}
	t.ID = id.String
	return populateToken(t, createdStr, revoked, expiresAt, revokedAt)
}

func scanTokenRow(rows *sql.Rows) (*business.RegistrationTokenData, error) {
	t := &business.RegistrationTokenData{}
	var createdStr string
	var id sql.NullString
	var expiresAt, revokedAt sql.NullString
	var revoked int

	if err := rows.Scan(
		&t.Token, &id, &t.TenantID, &t.ControllerURL, &t.Group,
		&createdStr, &expiresAt, &revoked, &revokedAt,
	); err != nil {
		return nil, fmt.Errorf("failed to scan registration token row: %w", err)
	}
	t.ID = id.String
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

// nullableStr returns nil for an empty string (allowing SQL NULL storage).
func nullableStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// generateTokenString produces a random base32-encoded token string (16 bytes / 128-bit entropy).
func generateTokenString() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

// generateTokenID produces a UUID v4 string for use as a stable non-secret token identifier.
func generateTokenID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to read random bytes for token ID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ensure SQLiteRegistrationTokenStore satisfies the interface at compile time
var _ business.RegistrationTokenStore = (*SQLiteRegistrationTokenStore)(nil)
var _ business.RegistrationTokenClaimer = (*SQLiteRegistrationTokenStore)(nil)
