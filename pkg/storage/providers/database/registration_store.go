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
func NewDatabaseRegistrationTokenStore(dsn string, config map[string]interface{}) (*DatabaseRegistrationTokenStore, error) {
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

	store := &DatabaseRegistrationTokenStore{
		db:      db,
		config:  config,
		schemas: NewDatabaseSchemas(),
	}

	if err := store.initializeSchema(); err != nil {
		_ = db.Close()
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
func (s *DatabaseRegistrationTokenStore) Close() error {
	return s.db.Close()
}

// SaveToken implements RegistrationTokenStore.SaveToken using UPSERT semantics.
func (s *DatabaseRegistrationTokenStore) SaveToken(ctx context.Context, token *business.RegistrationTokenData) error {
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}
	if token.Token == "" {
		return fmt.Errorf("token string cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cfgms_registration_tokens
			(token, tenant_id, controller_url, group_name, created_at, expires_at, revoked, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (token) DO UPDATE SET
			tenant_id = EXCLUDED.tenant_id,
			controller_url = EXCLUDED.controller_url,
			group_name = EXCLUDED.group_name,
			expires_at = EXCLUDED.expires_at,
			revoked = EXCLUDED.revoked,
			revoked_at = EXCLUDED.revoked_at`,
		token.Token,
		token.TenantID,
		token.ControllerURL,
		token.Group,
		token.CreatedAt,
		nullTimeOrNil(token.ExpiresAt),
		token.Revoked,
		nullTimeOrNil(token.RevokedAt),
	)
	if err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}
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
	var group sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT token, tenant_id, controller_url, group_name, created_at, expires_at, revoked, revoked_at
		FROM cfgms_registration_tokens
		WHERE token = $1`, tokenStr).Scan(
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
			return nil, fmt.Errorf("token not found")
		}
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

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
		WHERE token = $1`,
		token.Token,
		token.TenantID,
		token.ControllerURL,
		token.Group,
		nullTimeOrNil(token.ExpiresAt),
		token.Revoked,
		nullTimeOrNil(token.RevokedAt),
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

	result, err := s.db.ExecContext(ctx, `DELETE FROM cfgms_registration_tokens WHERE token = $1`, tokenStr)
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

// ListTokens implements RegistrationTokenStore.ListTokens
func (s *DatabaseRegistrationTokenStore) ListTokens(ctx context.Context, filter *business.RegistrationTokenFilter) ([]*business.RegistrationTokenData, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT token, tenant_id, controller_url, group_name, created_at, expires_at, revoked, revoked_at
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
		var group sql.NullString

		if err := rows.Scan(
			&token.Token,
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

	// Insert the new token.
	_, err = tx.ExecContext(ctx, `
		INSERT INTO cfgms_registration_tokens
			(token, tenant_id, controller_url, group_name, created_at, revoked)
		VALUES ($1, $2, $3, $4, $5, false)`,
		newTokenStr, tenantID, controllerURL, group, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert new token: %w", err)
	}

	// Revoke all prior tokens for this tenant+group atomically.
	_, err = tx.ExecContext(ctx, `
		UPDATE cfgms_registration_tokens
		SET revoked = true, revoked_at = $1
		WHERE tenant_id = $2 AND group_name = $3 AND revoked = false AND token != $4`,
		now, tenantID, group, newTokenStr,
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
