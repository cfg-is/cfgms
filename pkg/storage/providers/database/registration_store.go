// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// DatabaseRegistrationTokenStore implements RegistrationTokenStore using PostgreSQL for persistence
type DatabaseRegistrationTokenStore struct {
	db      *sql.DB
	config  map[string]interface{}
	mutex   sync.RWMutex
	schemas DatabaseSchemas
}

// NewDatabaseRegistrationTokenStore creates a new PostgreSQL-based registration token store
func NewDatabaseRegistrationTokenStore(db *sql.DB, config map[string]interface{}) (*DatabaseRegistrationTokenStore, error) {
	store := &DatabaseRegistrationTokenStore{
		db:      db,
		config:  config,
		schemas: NewDatabaseSchemas(),
	}

	if err := store.initializeSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	return store, nil

}

// initializeSchema creates the necessary database tables and indexes for registration tokens
func (s *DatabaseRegistrationTokenStore) initializeSchema() error {
	ctx := context.Background()

	const schemaLockID = 13579248

	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", schemaLockID); err != nil {
		return fmt.Errorf("failed to acquire registration token schema initialization lock: %w", err)
	}

	defer func() {
		if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", schemaLockID); err != nil {
			_ = err
		}
	}()

	if err := s.schemas.CreateRegistrationTokensTable(ctx, s.db); err != nil {
		return fmt.Errorf("failed to create registration token tables: %w", err)
	}

	return nil
}

// Initialize implements RegistrationTokenStore.Initialize
func (s *DatabaseRegistrationTokenStore) Initialize(ctx context.Context) error {
	return s.initializeSchema()
}

// Close implements RegistrationTokenStore.Close
// Close is a no-op: the underlying connection pool is owned and closed by
// DatabaseProvider, not by individual stores (ADR-031 Decision 6).
func (s *DatabaseRegistrationTokenStore) Close() error {
	return nil
}

// SaveToken implements RegistrationTokenStore.SaveToken using UPSERT semantics.
func (s *DatabaseRegistrationTokenStore) SaveToken(ctx context.Context, token *business.RegistrationTokenData) error {
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}
	if token.Token == "" {
		return fmt.Errorf("token string cannot be empty")
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

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// The id is assigned once and never reassigned: on conflict the stored id wins and
	// EXCLUDED.id only fills in a row that has none. NULLIF treats an empty stored id as
	// absent — the same "missing" predicate the back-fill uses (id IS NULL OR id = '') —
	// so a row that reaches this path unaddressable is healed rather than kept that way.
	// RETURNING keeps the caller's in-memory ID identical to the persisted one.
	var storedID string
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO cfgms_registration_tokens
			(token, id, tenant_id, controller_url, group_name, created_at, expires_at, revoked, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (token) DO UPDATE SET
			id = COALESCE(NULLIF(cfgms_registration_tokens.id, ''), EXCLUDED.id),
			tenant_id = EXCLUDED.tenant_id,
			controller_url = EXCLUDED.controller_url,
			group_name = EXCLUDED.group_name,
			expires_at = EXCLUDED.expires_at,
			revoked = EXCLUDED.revoked,
			revoked_at = EXCLUDED.revoked_at
		RETURNING id`,
		business.RegistrationTokenLookupKey(token.Token),
		token.ID,
		token.TenantID,
		token.ControllerURL,
		token.Group,
		token.CreatedAt,
		nullTimeOrNil(token.ExpiresAt),
		token.Revoked,
		nullTimeOrNil(token.RevokedAt),
	).Scan(&storedID)
	if err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}
	token.ID = storedID
	return nil
}

// GetToken implements RegistrationTokenStore.GetToken
func (s *DatabaseRegistrationTokenStore) GetToken(ctx context.Context, tokenStr string) (*business.RegistrationTokenData, error) {
	if tokenStr == "" {
		return nil, fmt.Errorf("token string cannot be empty")
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var token business.RegistrationTokenData
	var expiresAt, revokedAt sql.NullTime
	var group, id sql.NullString

	lookupKey := business.RegistrationTokenLookupKey(tokenStr)
	err := s.db.QueryRowContext(ctx, `
		SELECT token, id, tenant_id, controller_url, group_name, created_at, expires_at, revoked, revoked_at
		FROM cfgms_registration_tokens
		WHERE token = $1`, lookupKey).Scan(
		&token.Token,
		&id,
		&token.TenantID,
		&token.ControllerURL,
		&group,
		&token.CreatedAt,
		&expiresAt,
		&token.Revoked,
		&revokedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			// Read legacy plaintext rows so they can be rotated without downtime.
			err = s.db.QueryRowContext(ctx, `
				SELECT token, id, tenant_id, controller_url, group_name, created_at, expires_at, revoked, revoked_at
				FROM cfgms_registration_tokens
				WHERE token = $1`, tokenStr).Scan(
				&token.Token, &id, &token.TenantID, &token.ControllerURL, &group,
				&token.CreatedAt, &expiresAt, &token.Revoked, &revokedAt,
			)
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("token not found")
			}
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get token: %w", err)
		}
	}

	token.ID = id.String
	token.Group = group.String
	if expiresAt.Valid {
		token.ExpiresAt = &expiresAt.Time
	}
	if revokedAt.Valid {
		token.RevokedAt = &revokedAt.Time
	}
	token.Token = tokenStr

	return &token, nil
}

// GetTokenByID implements RegistrationTokenStore.GetTokenByID (Issue #2970).
func (s *DatabaseRegistrationTokenStore) GetTokenByID(ctx context.Context, id string) (*business.RegistrationTokenData, error) {
	if id == "" {
		return nil, fmt.Errorf("token id cannot be empty")
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var token business.RegistrationTokenData
	var expiresAt, revokedAt sql.NullTime
	var group sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT token, tenant_id, controller_url, group_name, created_at, expires_at, revoked, revoked_at
		FROM cfgms_registration_tokens
		WHERE id = $1`, id).Scan(
		&token.Token,
		&token.TenantID,
		&token.ControllerURL,
		&group,
		&token.CreatedAt,
		&expiresAt,
		&token.Revoked,
		&revokedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("registration token not found")
		}
		return nil, fmt.Errorf("failed to get token by id: %w", err)
	}

	token.ID = id
	token.Group = group.String
	if expiresAt.Valid {
		token.ExpiresAt = &expiresAt.Time
	}
	if revokedAt.Valid {
		token.RevokedAt = &revokedAt.Time
	}

	return &token, nil
}

// UpdateToken implements RegistrationTokenStore.UpdateToken
func (s *DatabaseRegistrationTokenStore) UpdateToken(ctx context.Context, token *business.RegistrationTokenData) error {
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}
	if token.Token == "" {
		return fmt.Errorf("token string cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	result, err := s.db.ExecContext(ctx, `
		UPDATE cfgms_registration_tokens
		SET tenant_id = $2, controller_url = $3, group_name = $4,
		    expires_at = $5, revoked = $6, revoked_at = $7
		WHERE token = $1 OR token = $8`,
		business.RegistrationTokenLookupKey(token.Token),
		token.TenantID,
		token.ControllerURL,
		token.Group,
		nullTimeOrNil(token.ExpiresAt),
		token.Revoked,
		nullTimeOrNil(token.RevokedAt),
		token.Token,
	)
	if err != nil {
		return fmt.Errorf("failed to update token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("token not found")
	}
	return nil
}

// DeleteToken implements RegistrationTokenStore.DeleteToken
func (s *DatabaseRegistrationTokenStore) DeleteToken(ctx context.Context, tokenStr string) error {
	if tokenStr == "" {
		return fmt.Errorf("token string cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	result, err := s.db.ExecContext(ctx,
		`DELETE FROM cfgms_registration_tokens WHERE token = $1 OR token = $2`,
		business.RegistrationTokenLookupKey(tokenStr), tokenStr)
	if err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("token not found")
	}
	return nil
}

// ClaimToken atomically reserves a valid token for one device identity at the
// REST admission boundary. It does not revoke the token: registration tokens are
// perennial (Issue #1690) and one fleet token enrols many endpoints.
func (s *DatabaseRegistrationTokenStore) ClaimToken(ctx context.Context, tokenStr, claimID string) (bool, error) {
	if tokenStr == "" {
		return false, fmt.Errorf("token string cannot be empty")
	}
	if claimID == "" {
		return false, fmt.Errorf("registration claim ID cannot be empty")
	}

	now := time.Now().UTC()
	lookupKey := business.RegistrationTokenLookupKey(tokenStr)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("failed to begin registration token claim: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Serialize with any concurrent UPDATE of the same token row, so a claim
	// cannot observe a stale valid snapshot while another controller process is
	// revoking or rotating the token.
	var storedToken string
	err = tx.QueryRowContext(ctx, `
		SELECT token FROM cfgms_registration_tokens
		WHERE (token = $1 OR token = $2)
		  AND revoked = false
		  AND (expires_at IS NULL OR expires_at > $3)
		FOR UPDATE`,
		lookupKey,
		tokenStr,
		now,
	).Scan(&storedToken)
	if err == sql.ErrNoRows {
		return false, fmt.Errorf("registration token is invalid, expired, or revoked")
	}
	if err != nil {
		return false, fmt.Errorf("failed to lock registration token for claim: %w", err)
	}

	result, err := tx.ExecContext(ctx, `
		INSERT INTO cfgms_registration_token_claims (token, claim_id, claimed_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (token, claim_id) DO NOTHING`,
		lookupKey, claimID, now)
	if err != nil {
		return false, fmt.Errorf("failed to claim registration token: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to confirm registration token claim: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("failed to commit registration token claim: %w", err)
	}
	committed = true

	// The token row was locked and valid above, so the only reason the insert
	// found a conflict is that this same device already holds the claim.
	return affected == 1, nil
}

// ReleaseTokenClaim removes only the exact claim made by this REST attempt.
func (s *DatabaseRegistrationTokenStore) ReleaseTokenClaim(ctx context.Context, tokenStr, claimID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM cfgms_registration_token_claims WHERE token = $1 AND claim_id = $2`,
		business.RegistrationTokenLookupKey(tokenStr),
		claimID,
	)
	if err != nil {
		return fmt.Errorf("failed to release registration token claim: %w", err)
	}
	return nil
}

var _ business.RegistrationTokenClaimer = (*DatabaseRegistrationTokenStore)(nil)

// ListTokens implements RegistrationTokenStore.ListTokens
func (s *DatabaseRegistrationTokenStore) ListTokens(ctx context.Context, filter *business.RegistrationTokenFilter) ([]*business.RegistrationTokenData, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT token, id, tenant_id, controller_url, group_name, created_at, expires_at, revoked, revoked_at
		FROM cfgms_registration_tokens
		WHERE 1=1`
	args := []interface{}{}
	argCount := 1

	if filter != nil {
		if filter.TenantID != "" {
			query += fmt.Sprintf(" AND tenant_id = $%d", argCount)
			args = append(args, filter.TenantID)
			argCount++
		}
		if filter.Group != "" {
			query += fmt.Sprintf(" AND group_name = $%d", argCount)
			args = append(args, filter.Group)
			argCount++
		}
		if filter.Revoked != nil {
			// #nosec G202 -- only the generated placeholder index is formatted;
			// the boolean filter value remains a bound argument.
			query += fmt.Sprintf(" AND revoked = $%d", argCount)
			args = append(args, *filter.Revoked)
			argCount++
		}
	}
	_ = argCount

	query += " ORDER BY created_at DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tokens []*business.RegistrationTokenData
	for rows.Next() {
		var token business.RegistrationTokenData
		var expiresAt, revokedAt sql.NullTime
		var group, id sql.NullString

		if err := rows.Scan(
			&token.Token,
			&id,
			&token.TenantID,
			&token.ControllerURL,
			&group,
			&token.CreatedAt,
			&expiresAt,
			&token.Revoked,
			&revokedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan token row: %w", err)
		}

		token.ID = id.String
		token.Group = group.String
		if expiresAt.Valid {
			token.ExpiresAt = &expiresAt.Time
		}
		if revokedAt.Valid {
			token.RevokedAt = &revokedAt.Time
		}

		tokens = append(tokens, &token)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating token rows: %w", err)
	}

	return tokens, nil
}

// RotateToken atomically revokes all prior tokens for tenant+group and creates a new one in
// a single PostgreSQL transaction, ensuring no overlap window between old and new tokens.
func (s *DatabaseRegistrationTokenStore) RotateToken(ctx context.Context, tenantID, group string) (*business.RegistrationTokenData, error) {
	newTokenStr, err := generateTokenString()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

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
		SELECT controller_url FROM cfgms_registration_tokens
		WHERE tenant_id = $1 AND group_name = $2 AND revoked = false
		ORDER BY created_at DESC LIMIT 1`,
		tenantID, group,
	).Scan(&controllerURL)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no active tokens found for tenant %q group %q", tenantID, group)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find existing token: %w", err)
	}

	now := time.Now().UTC()
	expiresAt := now.Add(15 * time.Minute)
	newLookupKey := business.RegistrationTokenLookupKey(newTokenStr)

	newID, err := generateTokenID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token id: %w", err)
	}

	// Insert the new token.
	_, err = tx.ExecContext(ctx, `
		INSERT INTO cfgms_registration_tokens
			(token, id, tenant_id, controller_url, group_name, created_at, expires_at, revoked)
		VALUES ($1, $2, $3, $4, $5, $6, $7, false)`,
		newLookupKey, newID, tenantID, controllerURL, group, now, expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert new token: %w", err)
	}

	// Revoke all prior tokens for this tenant+group atomically.
	_, err = tx.ExecContext(ctx, `
		UPDATE cfgms_registration_tokens
		SET revoked = true, revoked_at = $1
		WHERE tenant_id = $2 AND group_name = $3 AND revoked = false AND token != $4`,
		now, tenantID, group, newLookupKey,
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

// nullTimeOrNil converts a *time.Time pointer to sql.NullTime
func nullTimeOrNil(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{Valid: false}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

// generateTokenString produces a random base32-encoded token string (16 bytes / 128-bit entropy).
func generateTokenString() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

// generateTokenID produces a UUID v4 string used as a stable, non-secret token identifier
// (Issue #2970). It is the value the web UI addresses a token by.
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
