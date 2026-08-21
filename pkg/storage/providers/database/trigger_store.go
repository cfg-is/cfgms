// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements TriggerStore using PostgreSQL (Issue #3402).
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/lib/pq"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.TriggerStore = (*DatabaseTriggerStore)(nil)

// DatabaseTriggerStore implements business.TriggerStore using PostgreSQL.
type DatabaseTriggerStore struct {
	db *sql.DB
}

// NewDatabaseTriggerStore opens a pooled Postgres connection, initialises
// the schema, and returns a ready-to-use TriggerStore.
func NewDatabaseTriggerStore(dsn string, config map[string]interface{}) (*DatabaseTriggerStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("database: failed to open trigger store connection: %w", err)
	}
	db.SetMaxOpenConns(getIntFromConfig(config, "max_open_connections", 25))
	db.SetMaxIdleConns(getIntFromConfig(config, "max_idle_connections", 5))
	db.SetConnMaxLifetime(time.Duration(getIntFromConfig(config, "connection_max_lifetime_minutes", 30)) * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to ping trigger store: %w", err)
	}
	store := &DatabaseTriggerStore{db: db}
	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to initialise trigger schema: %w", err)
	}
	return store, nil
}

func (s *DatabaseTriggerStore) initSchema() error {
	ctx := context.Background()
	const lockID = 16925001 // advisory lock ID unique to cfgms_triggers schema
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("database: failed to acquire trigger schema lock: %w", err)
	}
	defer func() { _, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID) }()
	return NewDatabaseSchemas().CreateTriggersTable(ctx, s.db)
}

// Close releases the database connection.
func (s *DatabaseTriggerStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// StoreTrigger creates or updates a trigger record using upsert semantics.
// The record must have non-empty ID and TenantID.
func (s *DatabaseTriggerStore) StoreTrigger(ctx context.Context, record *business.TriggerRecord) error {
	if record == nil {
		return fmt.Errorf("database: trigger record cannot be nil")
	}
	if record.ID == "" {
		return fmt.Errorf("database: trigger ID is required")
	}
	if record.TenantID == "" {
		return fmt.Errorf("database: trigger TenantID is required")
	}

	now := time.Now().UTC()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now

	methodJSON, err := json.Marshal(record.WebhookMethod)
	if err != nil {
		return fmt.Errorf("database: failed to marshal webhook_method for trigger %s: %w", record.ID, err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO cfgms_triggers
			(id, tenant_id, name, type, status, workflow_name,
			 created_at, updated_at,
			 webhook_path, webhook_method,
			 bearer_token_ref, hmac_secret_ref, apikey_ref, basic_username_ref, basic_password_ref,
			 config_payload)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (id) DO UPDATE SET
			tenant_id          = EXCLUDED.tenant_id,
			name               = EXCLUDED.name,
			type               = EXCLUDED.type,
			status             = EXCLUDED.status,
			workflow_name      = EXCLUDED.workflow_name,
			updated_at         = EXCLUDED.updated_at,
			webhook_path       = EXCLUDED.webhook_path,
			webhook_method     = EXCLUDED.webhook_method,
			bearer_token_ref   = EXCLUDED.bearer_token_ref,
			hmac_secret_ref    = EXCLUDED.hmac_secret_ref,
			apikey_ref         = EXCLUDED.apikey_ref,
			basic_username_ref = EXCLUDED.basic_username_ref,
			basic_password_ref = EXCLUDED.basic_password_ref,
			config_payload     = EXCLUDED.config_payload`,
		record.ID,
		record.TenantID,
		record.Name,
		record.Type,
		record.Status,
		record.WorkflowName,
		record.CreatedAt,
		record.UpdatedAt,
		record.WebhookPath,
		methodJSON,
		nullableString(record.BearerTokenRef),
		nullableString(record.HMACSecretRef),
		nullableString(record.APIKeyRef),
		nullableString(record.BasicUsernameRef),
		nullableString(record.BasicPasswordRef),
		nullableBytes(record.ConfigPayload),
	)
	if err != nil {
		return fmt.Errorf("database: failed to store trigger %s: %w", record.ID, err)
	}
	return nil
}

// GetTrigger retrieves a trigger by ID. Returns ErrTriggerNotFound when absent.
func (s *DatabaseTriggerStore) GetTrigger(ctx context.Context, id string) (*business.TriggerRecord, error) {
	if id == "" {
		return nil, fmt.Errorf("database: trigger ID is required")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, name, type, status, workflow_name,
		       created_at, updated_at,
		       webhook_path, webhook_method,
		       bearer_token_ref, hmac_secret_ref, apikey_ref, basic_username_ref, basic_password_ref,
		       config_payload
		FROM cfgms_triggers WHERE id = $1`, id)
	return scanDBTriggerRow(row)
}

// DeleteTrigger removes a trigger by ID. Returns ErrTriggerNotFound when absent.
func (s *DatabaseTriggerStore) DeleteTrigger(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("database: trigger ID is required")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM cfgms_triggers WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("database: failed to delete trigger %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrTriggerNotFound
	}
	return nil
}

// ListTriggers returns triggers matching the filter, ordered by created_at descending.
// An empty filter returns all triggers.
func (s *DatabaseTriggerStore) ListTriggers(ctx context.Context, filter business.TriggerStoreFilter) ([]*business.TriggerRecord, error) {
	query := `
		SELECT id, tenant_id, name, type, status, workflow_name,
		       created_at, updated_at,
		       webhook_path, webhook_method,
		       bearer_token_ref, hmac_secret_ref, apikey_ref, basic_username_ref, basic_password_ref,
		       config_payload
		FROM cfgms_triggers WHERE 1=1`

	var args []interface{}
	argN := 0

	if filter.TenantID != "" {
		argN++
		query += fmt.Sprintf(" AND tenant_id = $%d", argN)
		args = append(args, filter.TenantID)
	}
	if filter.Type != "" {
		argN++
		query += fmt.Sprintf(" AND type = $%d", argN)
		args = append(args, filter.Type)
	}
	if filter.Status != "" {
		argN++
		query += fmt.Sprintf(" AND status = $%d", argN)
		args = append(args, filter.Status)
	}

	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		argN++
		// #nosec G202 -- only the generated placeholder index is formatted; values are bound parameters
		query += fmt.Sprintf(" LIMIT $%d", argN)
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			argN++
			// #nosec G202 -- only the generated placeholder index is formatted; values are bound parameters
			query += fmt.Sprintf(" OFFSET $%d", argN)
			args = append(args, filter.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("database: failed to list triggers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var records []*business.TriggerRecord
	for rows.Next() {
		rec, err := scanDBTriggerRowsNext(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// scanDBTriggerRow scans a *sql.Row into a TriggerRecord.
func scanDBTriggerRow(row *sql.Row) (*business.TriggerRecord, error) {
	var rec business.TriggerRecord
	var methodJSON []byte
	var payload []byte
	var bearerRef, hmacRef, apikeyRef, basicUser, basicPass sql.NullString

	err := row.Scan(
		&rec.ID,
		&rec.TenantID,
		&rec.Name,
		&rec.Type,
		&rec.Status,
		&rec.WorkflowName,
		&rec.CreatedAt,
		&rec.UpdatedAt,
		&rec.WebhookPath,
		&methodJSON,
		&bearerRef,
		&hmacRef,
		&apikeyRef,
		&basicUser,
		&basicPass,
		&payload,
	)
	if err == sql.ErrNoRows {
		return nil, business.ErrTriggerNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to scan trigger: %w", err)
	}
	return populateDBTrigger(&rec, methodJSON, payload, bearerRef, hmacRef, apikeyRef, basicUser, basicPass)
}

// scanDBTriggerRowsNext scans the current row from *sql.Rows into a TriggerRecord.
func scanDBTriggerRowsNext(rows *sql.Rows) (*business.TriggerRecord, error) {
	var rec business.TriggerRecord
	var methodJSON []byte
	var payload []byte
	var bearerRef, hmacRef, apikeyRef, basicUser, basicPass sql.NullString

	if err := rows.Scan(
		&rec.ID,
		&rec.TenantID,
		&rec.Name,
		&rec.Type,
		&rec.Status,
		&rec.WorkflowName,
		&rec.CreatedAt,
		&rec.UpdatedAt,
		&rec.WebhookPath,
		&methodJSON,
		&bearerRef,
		&hmacRef,
		&apikeyRef,
		&basicUser,
		&basicPass,
		&payload,
	); err != nil {
		return nil, fmt.Errorf("database: failed to scan trigger row: %w", err)
	}
	return populateDBTrigger(&rec, methodJSON, payload, bearerRef, hmacRef, apikeyRef, basicUser, basicPass)
}

// populateDBTrigger fills webhook_method, times, and nullable ref fields from
// their raw DB representations.
func populateDBTrigger(
	rec *business.TriggerRecord,
	methodJSON, payload []byte,
	bearerRef, hmacRef, apikeyRef, basicUser, basicPass sql.NullString,
) (*business.TriggerRecord, error) {
	rec.CreatedAt = rec.CreatedAt.UTC()
	rec.UpdatedAt = rec.UpdatedAt.UTC()
	rec.ConfigPayload = payload

	rec.BearerTokenRef = bearerRef.String
	rec.HMACSecretRef = hmacRef.String
	rec.APIKeyRef = apikeyRef.String
	rec.BasicUsernameRef = basicUser.String
	rec.BasicPasswordRef = basicPass.String

	if len(methodJSON) > 0 {
		if err := json.Unmarshal(methodJSON, &rec.WebhookMethod); err != nil {
			return nil, fmt.Errorf("database: failed to unmarshal webhook_method for trigger %s: %w", rec.ID, err)
		}
	}
	return rec, nil
}

// nullableString converts an empty string to nil so that credential reference
// fields are stored as SQL NULL rather than an empty string — avoids the
// empty-string-vs-NULL defect class identified in the database provider (#3127).
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// nullableBytes converts a nil or empty byte slice to nil for SQL NULL storage.
func nullableBytes(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return b
}
