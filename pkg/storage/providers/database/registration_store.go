// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package database

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
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
	// Open database connection with connection pooling
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool
	maxOpenConns := getIntFromConfig(config, "max_open_connections", 25)
	maxIdleConns := getIntFromConfig(config, "max_idle_connections", 5)
	connMaxLifetime := time.Duration(getIntFromConfig(config, "connection_max_lifetime_minutes", 30)) * time.Minute

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)

	// Test connection
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	store := &DatabaseRegistrationTokenStore{
		db:      db,
		config:  config,
		schemas: NewDatabaseSchemas(),
	}

	// Initialize database schema
	if err := store.initializeSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	return store, nil
}

// initializeSchema creates the necessary database tables and indexes for registration tokens
func (s *DatabaseRegistrationTokenStore) initializeSchema() error {
	ctx := context.Background()

	// Use PostgreSQL advisory lock to prevent concurrent schema initialization
	// Lock ID: 13579248 (different from other schemas)
	const schemaLockID = 13579248

	// Acquire advisory lock - will wait if another instance is initializing
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", schemaLockID); err != nil {
		return fmt.Errorf("failed to acquire registration token schema initialization lock: %w", err)
	}

	// Ensure we release the lock when done
	defer func() {
		if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", schemaLockID); err != nil {
			// Log but don't fail - lock will be released when connection closes
			_ = err
		}
	}()

	// Create registration token tables
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

// SaveToken implements RegistrationTokenStore.SaveToken
func (s *DatabaseRegistrationTokenStore) SaveToken(ctx context.Context, token *interfaces.RegistrationTokenData) error {
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}
	if token.Token == "" {
		return fmt.Errorf("token string cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	query := `
		INSERT INTO cfgms_registration_tokens (token, tenant_id, controller_url, group_name, created_at, expires_at, single_use, used_at, used_by, revoked, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := s.db.ExecContext(ctx, query,
		token.Token,
		token.TenantID,
		token.ControllerURL,
		token.Group,
		token.CreatedAt,
		nullTimeOrNil(token.ExpiresAt),
		token.SingleUse,
		nullTimeOrNil(token.UsedAt),
		token.UsedBy,
		token.Revoked,
		nullTimeOrNil(token.RevokedAt),
	)

	if err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return nil
}

// GetToken implements RegistrationTokenStore.GetToken
func (s *DatabaseRegistrationTokenStore) GetToken(ctx context.Context, tokenStr string) (*interfaces.RegistrationTokenData, error) {
	if tokenStr == "" {
		return nil, fmt.Errorf("token string cannot be empty")
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT token, tenant_id, controller_url, group_name, created_at, expires_at, single_use, used_at, used_by, revoked, revoked_at
		FROM cfgms_registration_tokens
		WHERE token = $1
	`

	var token interfaces.RegistrationTokenData
	var expiresAt, usedAt, revokedAt sql.NullTime
	var group sql.NullString
	var usedBy sql.NullString

	err := s.db.QueryRowContext(ctx, query, tokenStr).Scan(
		&token.Token,
		&token.TenantID,
		&token.ControllerURL,
		&group,
		&token.CreatedAt,
		&expiresAt,
		&token.SingleUse,
		&usedAt,
		&usedBy,
		&token.Revoked,
		&revokedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("token not found")
		}
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	// Convert nullable fields
	token.Group = group.String
	token.UsedBy = usedBy.String

	if expiresAt.Valid {
		token.ExpiresAt = &expiresAt.Time
	}
	if usedAt.Valid {
		token.UsedAt = &usedAt.Time
	}
	if revokedAt.Valid {
		token.RevokedAt = &revokedAt.Time
	}

	return &token, nil
}

// UpdateToken implements RegistrationTokenStore.UpdateToken
func (s *DatabaseRegistrationTokenStore) UpdateToken(ctx context.Context, token *interfaces.RegistrationTokenData) error {
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}
	if token.Token == "" {
		return fmt.Errorf("token string cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	query := `
		UPDATE cfgms_registration_tokens
		SET tenant_id = $2, controller_url = $3, group_name = $4, expires_at = $5, single_use = $6, used_at = $7, used_by = $8, revoked = $9, revoked_at = $10
		WHERE token = $1
	`

	result, err := s.db.ExecContext(ctx, query,
		token.Token,
		token.TenantID,
		token.ControllerURL,
		token.Group,
		nullTimeOrNil(token.ExpiresAt),
		token.SingleUse,
		nullTimeOrNil(token.UsedAt),
		token.UsedBy,
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

	query := `DELETE FROM cfgms_registration_tokens WHERE token = $1`

	result, err := s.db.ExecContext(ctx, query, tokenStr)
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
func (s *DatabaseRegistrationTokenStore) ListTokens(ctx context.Context, filter *interfaces.RegistrationTokenFilter) ([]*interfaces.RegistrationTokenData, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT token, tenant_id, controller_url, group_name, created_at, expires_at, single_use, used_at, used_by, revoked, revoked_at
		FROM cfgms_registration_tokens
		WHERE 1=1
	`
	args := []interface{}{}
	argCount := 1

	// Apply filters
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
		if filter.SingleUse != nil {
			query += fmt.Sprintf(" AND single_use = $%d", argCount)
			args = append(args, *filter.SingleUse)
			// argCount not incremented as Used filter uses IS NULL/IS NOT NULL
		}
		if filter.Used != nil {
			if *filter.Used {
				query += " AND used_at IS NOT NULL"
			} else {
				query += " AND used_at IS NULL"
			}
		}
	}

	query += " ORDER BY created_at DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tokens []*interfaces.RegistrationTokenData
	for rows.Next() {
		var token interfaces.RegistrationTokenData
		var expiresAt, usedAt, revokedAt sql.NullTime
		var group sql.NullString
		var usedBy sql.NullString

		err := rows.Scan(
			&token.Token,
			&token.TenantID,
			&token.ControllerURL,
			&group,
			&token.CreatedAt,
			&expiresAt,
			&token.SingleUse,
			&usedAt,
			&usedBy,
			&token.Revoked,
			&revokedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan token row: %w", err)
		}

		// Convert nullable fields
		token.Group = group.String
		token.UsedBy = usedBy.String

		if expiresAt.Valid {
			token.ExpiresAt = &expiresAt.Time
		}
		if usedAt.Valid {
			token.UsedAt = &usedAt.Time
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

// nullTimeOrNil converts a *time.Time pointer to sql.NullTime
func nullTimeOrNil(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{Valid: false}
	}
	return sql.NullTime{Time: *t, Valid: true}
}
