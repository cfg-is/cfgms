// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite implements CommandStore using SQLite for durable command dispatch state.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// SQLiteCommandStore implements business.CommandStore using a SQLite database.
// Command records and their audit trail are stored in the `commands` and
// `command_transitions` tables, which are created by initializeSchema.
type SQLiteCommandStore struct {
	db *sql.DB
}

// Compile-time assertion that SQLiteCommandStore satisfies CommandStore.
var _ business.CommandStore = (*SQLiteCommandStore)(nil)

// Initialize is a no-op; schema is applied in openAndInit before this store is returned.
func (s *SQLiteCommandStore) Initialize(_ context.Context) error { return nil }

// Close closes the underlying database connection.
func (s *SQLiteCommandStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// CreateCommandRecord inserts a new command record with status=pending and records
// the initial transition in the audit trail.
func (s *SQLiteCommandStore) CreateCommandRecord(ctx context.Context, record *business.CommandRecord) error {
	if record == nil {
		return fmt.Errorf("sqlite: command record cannot be nil")
	}
	if record.ID == "" {
		return business.ErrCommandIDRequired
	}
	if record.StewardID == "" {
		return business.ErrCommandStewardIDRequired
	}

	now := nowUTC()
	if record.IssuedAt.IsZero() {
		record.IssuedAt = now
	}
	// Always start in pending state.
	record.Status = business.CommandStatusPending

	payload, err := marshalJSON(record.Payload)
	if err != nil {
		return fmt.Errorf("sqlite: failed to marshal command payload: %w", err)
	}
	result, err := marshalJSON(record.Result)
	if err != nil {
		return fmt.Errorf("sqlite: failed to marshal command result: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO commands
			(id, type, steward_id, tenant_id, payload, status,
			 issued_at, started_at, completed_at, result, error_message, issued_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?)`,
		record.ID,
		record.Type,
		record.StewardID,
		record.TenantID,
		payload,
		string(business.CommandStatusPending),
		formatTime(record.IssuedAt),
		result,
		record.ErrorMessage,
		record.IssuedBy,
	)
	if err != nil {
		return fmt.Errorf("sqlite: failed to create command record %s: %w", record.ID, err)
	}

	// Record initial transition (creation counts as first audit entry).
	if err := insertTransition(ctx, tx, record.ID, business.CommandStatusPending, now, ""); err != nil {
		return err
	}

	return tx.Commit()
}

// UpdateCommandStatus transitions a command to the given status and appends a
// transition entry to the audit trail.
func (s *SQLiteCommandStore) UpdateCommandStatus(
	ctx context.Context,
	id string,
	status business.CommandStatus,
	result map[string]interface{},
	errorMessage string,
) error {
	if id == "" {
		return business.ErrCommandIDRequired
	}

	now := nowUTC()

	resultJSON, err := marshalJSON(result)
	if err != nil {
		return fmt.Errorf("sqlite: failed to marshal command result: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Build the UPDATE: set timestamps based on the new status.
	var res sql.Result
	switch status {
	case business.CommandStatusExecuting:
		res, err = tx.ExecContext(ctx, `
			UPDATE commands SET status = ?, started_at = ?, result = ?, error_message = ?
			WHERE id = ?`,
			string(status), formatTime(now), resultJSON, errorMessage, id)
	case business.CommandStatusCompleted, business.CommandStatusFailed, business.CommandStatusCancelled:
		res, err = tx.ExecContext(ctx, `
			UPDATE commands SET status = ?, completed_at = ?, result = ?, error_message = ?
			WHERE id = ?`,
			string(status), formatTime(now), resultJSON, errorMessage, id)
	default:
		res, err = tx.ExecContext(ctx, `
			UPDATE commands SET status = ?, result = ?, error_message = ?
			WHERE id = ?`,
			string(status), resultJSON, errorMessage, id)
	}
	if err != nil {
		return fmt.Errorf("sqlite: failed to update command %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrCommandNotFound
	}

	if err := insertTransition(ctx, tx, id, status, now, errorMessage); err != nil {
		return err
	}

	return tx.Commit()
}

// GetCommandRecord retrieves the current state of a command by ID.
func (s *SQLiteCommandStore) GetCommandRecord(ctx context.Context, id string) (*business.CommandRecord, error) {
	if id == "" {
		return nil, business.ErrCommandIDRequired
	}

	row := s.db.QueryRowContext(ctx, `
		SELECT id, type, steward_id, tenant_id, payload, status,
		       issued_at, started_at, completed_at, result, error_message, issued_by
		FROM commands WHERE id = ?`, id)

	return scanCommandRecord(row)
}

// ListCommandRecords returns commands matching the optional filter.
func (s *SQLiteCommandStore) ListCommandRecords(ctx context.Context, filter *business.CommandFilter) ([]*business.CommandRecord, error) {
	query := `
		SELECT id, type, steward_id, tenant_id, payload, status,
		       issued_at, started_at, completed_at, result, error_message, issued_by
		FROM commands WHERE 1=1`
	var args []interface{}

	if filter != nil {
		if filter.StewardID != "" {
			query += ` AND steward_id = ?`
			args = append(args, filter.StewardID)
		}
		if filter.TenantID != "" {
			query += ` AND tenant_id = ?`
			args = append(args, filter.TenantID)
		}
		if filter.Status != "" {
			query += ` AND status = ?`
			args = append(args, string(filter.Status))
		}
		if filter.IssuedBy != "" {
			query += ` AND issued_by = ?`
			args = append(args, filter.IssuedBy)
		}
	}

	query += ` ORDER BY issued_at DESC`

	if filter != nil && filter.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			query += ` OFFSET ?`
			args = append(args, filter.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list commands: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var records []*business.CommandRecord
	for rows.Next() {
		rec, err := scanCommandRow(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// ListCommandsByDevice returns all commands dispatched to the given steward.
func (s *SQLiteCommandStore) ListCommandsByDevice(ctx context.Context, stewardID string) ([]*business.CommandRecord, error) {
	return s.ListCommandRecords(ctx, &business.CommandFilter{StewardID: stewardID})
}

// ListCommandsByStatus returns all commands in the given status.
func (s *SQLiteCommandStore) ListCommandsByStatus(ctx context.Context, status business.CommandStatus) ([]*business.CommandRecord, error) {
	return s.ListCommandRecords(ctx, &business.CommandFilter{Status: status})
}

// GetCommandAuditTrail returns all state transitions for the command in
// chronological order (oldest first).
func (s *SQLiteCommandStore) GetCommandAuditTrail(ctx context.Context, commandID string) ([]*business.CommandTransition, error) {
	if commandID == "" {
		return nil, business.ErrCommandIDRequired
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT command_id, status, timestamp, error_message
		FROM command_transitions
		WHERE command_id = ?
		ORDER BY id ASC`, commandID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to query audit trail for %s: %w", commandID, err)
	}
	defer func() { _ = rows.Close() }()

	var transitions []*business.CommandTransition
	for rows.Next() {
		var t business.CommandTransition
		var tsStr, statusStr string
		if err := rows.Scan(&t.CommandID, &statusStr, &tsStr, &t.ErrorMessage); err != nil {
			return nil, fmt.Errorf("sqlite: failed to scan transition: %w", err)
		}
		t.Status = business.CommandStatus(statusStr)
		t.Timestamp = parseTime(tsStr)
		transitions = append(transitions, &t)
	}
	return transitions, rows.Err()
}

// PurgeExpiredRecords deletes completed or failed commands whose issued_at is
// older than olderThan. Executing and pending records are never purged.
// Returns the count of command records deleted.
func (s *SQLiteCommandStore) PurgeExpiredRecords(ctx context.Context, olderThan time.Time) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("sqlite: failed to begin purge transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	cutoff := formatTime(olderThan)

	// First collect IDs to purge so we can also remove their transitions.
	rows, err := tx.QueryContext(ctx, `
		SELECT id FROM commands
		WHERE status IN ('completed', 'failed', 'cancelled')
		  AND issued_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("sqlite: failed to query expired commands: %w", err)
	}

	var ids []interface{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("sqlite: failed to scan expired command id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("sqlite: rows close error: %w", err)
	}

	if len(ids) == 0 {
		return 0, tx.Commit()
	}

	// Delete transitions first (no FK constraint, but keep data consistent).
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `DELETE FROM command_transitions WHERE command_id = ?`, id); err != nil {
			return 0, fmt.Errorf("sqlite: failed to delete transitions for %v: %w", id, err)
		}
	}

	// Delete the command records.
	res, err := tx.ExecContext(ctx, `
		DELETE FROM commands
		WHERE status IN ('completed', 'failed', 'cancelled')
		  AND issued_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("sqlite: failed to purge expired commands: %w", err)
	}

	n, _ := res.RowsAffected()
	return n, tx.Commit()
}

// HealthCheck verifies the store is operational.
func (s *SQLiteCommandStore) HealthCheck(ctx context.Context) error {
	var dummy int
	return s.db.QueryRowContext(ctx, `SELECT 1`).Scan(&dummy)
}

// ---- internal helpers -------------------------------------------------------

// insertTransition appends a single row to command_transitions within tx.
func insertTransition(ctx context.Context, tx *sql.Tx, commandID string, status business.CommandStatus, ts time.Time, errorMessage string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO command_transitions (command_id, status, timestamp, error_message)
		VALUES (?, ?, ?, ?)`,
		commandID, string(status), formatTime(ts), errorMessage)
	if err != nil {
		return fmt.Errorf("sqlite: failed to insert command transition for %s: %w", commandID, err)
	}
	return nil
}

// scanCommandRecord scans a *sql.Row (single QueryRow result) into a CommandRecord.
func scanCommandRecord(row *sql.Row) (*business.CommandRecord, error) {
	var rec business.CommandRecord
	var payloadStr, statusStr, issuedAtStr, resultStr string
	var startedAt, completedAt sql.NullString

	err := row.Scan(
		&rec.ID, &rec.Type, &rec.StewardID, &rec.TenantID,
		&payloadStr, &statusStr,
		&issuedAtStr, &startedAt, &completedAt,
		&resultStr, &rec.ErrorMessage, &rec.IssuedBy,
	)
	if err == sql.ErrNoRows {
		return nil, business.ErrCommandNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to scan command record: %w", err)
	}
	return populateCommandRecord(&rec, payloadStr, statusStr, issuedAtStr, startedAt, completedAt, resultStr)
}

// scanCommandRow scans a *sql.Rows (multi-row Query result) into a CommandRecord.
func scanCommandRow(rows *sql.Rows) (*business.CommandRecord, error) {
	var rec business.CommandRecord
	var payloadStr, statusStr, issuedAtStr, resultStr string
	var startedAt, completedAt sql.NullString

	if err := rows.Scan(
		&rec.ID, &rec.Type, &rec.StewardID, &rec.TenantID,
		&payloadStr, &statusStr,
		&issuedAtStr, &startedAt, &completedAt,
		&resultStr, &rec.ErrorMessage, &rec.IssuedBy,
	); err != nil {
		return nil, fmt.Errorf("sqlite: failed to scan command row: %w", err)
	}
	return populateCommandRecord(&rec, payloadStr, statusStr, issuedAtStr, startedAt, completedAt, resultStr)
}

// populateCommandRecord deserialises JSON columns and nullable timestamps.
func populateCommandRecord(
	rec *business.CommandRecord,
	payloadStr, statusStr, issuedAtStr string,
	startedAt, completedAt sql.NullString,
	resultStr string,
) (*business.CommandRecord, error) {
	rec.Status = business.CommandStatus(statusStr)
	rec.IssuedAt = parseTime(issuedAtStr)
	rec.StartedAt = parseNullTime(startedAt)
	rec.CompletedAt = parseNullTime(completedAt)

	if payload, err := unmarshalJSONMap(payloadStr); err == nil {
		rec.Payload = payload
	}
	if result, err := unmarshalJSONMap(resultStr); err == nil {
		rec.Result = result
	}

	return rec, nil
}
