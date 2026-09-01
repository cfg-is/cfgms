// SPDX-License-Identifier: AGPL-3.0-only
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
	if record.DeliveryStatus == "" {
		record.DeliveryStatus = business.DeliveryStatusPending
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := sqliteInsertCommandRecord(ctx, tx, record, now); err != nil {
		return err
	}

	return tx.Commit()
}

// CreateCommandRecords atomically creates a batch of command records in a single
// transaction: every record commits, or none do (Issue #3757, ADR-031 Decision 2).
func (s *SQLiteCommandStore) CreateCommandRecords(ctx context.Context, records []*business.CommandRecord) error {
	if len(records) == 0 {
		return nil
	}
	for _, r := range records {
		if r == nil {
			return fmt.Errorf("sqlite: command record cannot be nil")
		}
		if r.ID == "" {
			return business.ErrCommandIDRequired
		}
		if r.StewardID == "" {
			return business.ErrCommandStewardIDRequired
		}
	}

	now := nowUTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: failed to begin batch transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, record := range records {
		if record.IssuedAt.IsZero() {
			record.IssuedAt = now
		}
		record.Status = business.CommandStatusPending
		if record.DeliveryStatus == "" {
			record.DeliveryStatus = business.DeliveryStatusPending
		}
		if err := sqliteInsertCommandRecord(ctx, tx, record, now); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// CreatePushAndCommandRecords atomically creates push (the "config write") and
// records (the per-steward delivery rows it requires) in a single transaction:
// both commit together, or neither does (Issue #3757, ADR-031 Decision 2). push
// may be nil (only the delivery rows are written); records may be empty (only
// the push row is written).
func (s *SQLiteCommandStore) CreatePushAndCommandRecords(ctx context.Context, push *business.PushRecord, records []*business.CommandRecord) error {
	if push == nil && len(records) == 0 {
		return nil
	}
	for _, r := range records {
		if r == nil {
			return fmt.Errorf("sqlite: command record cannot be nil")
		}
		if r.ID == "" {
			return business.ErrCommandIDRequired
		}
		if r.StewardID == "" {
			return business.ErrCommandStewardIDRequired
		}
	}

	now := nowUTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: failed to begin push+command tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if push != nil {
		if err := sqliteInsertPushRecord(ctx, tx, push); err != nil {
			return err
		}
	}

	for _, record := range records {
		if record.IssuedAt.IsZero() {
			record.IssuedAt = now
		}
		record.Status = business.CommandStatusPending
		if record.DeliveryStatus == "" {
			record.DeliveryStatus = business.DeliveryStatusPending
		}
		if err := sqliteInsertCommandRecord(ctx, tx, record, now); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// sqliteInsertCommandRecord inserts a single commands row plus its initial
// pending transition within tx. Shared by CreateCommandRecord and
// CreateCommandRecords so both paths persist identically.
func sqliteInsertCommandRecord(ctx context.Context, tx *sql.Tx, record *business.CommandRecord, transitionTime time.Time) error {
	payload, err := marshalJSON(record.Payload)
	if err != nil {
		return fmt.Errorf("sqlite: failed to marshal command payload: %w", err)
	}
	result, err := marshalJSON(record.Result)
	if err != nil {
		return fmt.Errorf("sqlite: failed to marshal command result: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO commands
			(id, type, steward_id, tenant_id, payload, status,
			 issued_at, started_at, completed_at, result, error_message, issued_by,
			 delivery_status, delivery_detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?)`,
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
		string(record.DeliveryStatus),
		record.DeliveryDetail,
	)
	if err != nil {
		return fmt.Errorf("sqlite: failed to create command record %s: %w", record.ID, err)
	}

	// Record initial transition (creation counts as first audit entry).
	return insertTransition(ctx, tx, record.ID, business.CommandStatusPending, transitionTime, "")
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

// UpdateDeliveryStatus transitions a command record's outbox DeliveryStatus
// (Issue #3757, ADR-031 Decision 2). Independent of UpdateCommandStatus: this
// updates delivery_status/delivery_detail only and does not touch the
// command_transitions audit trail (that trail records CommandStatus, not
// DeliveryStatus).
func (s *SQLiteCommandStore) UpdateDeliveryStatus(
	ctx context.Context,
	id string,
	status business.DeliveryStatus,
	detail string,
) error {
	if id == "" {
		return business.ErrCommandIDRequired
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE commands SET delivery_status = ?, delivery_detail = ?
		WHERE id = ?`,
		string(status), detail, id)
	if err != nil {
		return fmt.Errorf("sqlite: failed to update delivery status for %s: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: failed to read rows affected for %s: %w", id, err)
	}
	if n == 0 {
		return business.ErrCommandNotFound
	}
	return nil
}

// ListPendingDeliveries returns every command record targeting stewardID whose
// DeliveryStatus is still pending (Issue #3757) — the set a steward drains on
// reconnect.
//
// The query is scoped to stewardTenant and its ancestor tenants as well as to
// steward_id. steward_id on its own is not a tenant boundary: a steward can be
// moved between tenants (Issue #2341) while its older rows keep the tenant_id
// they were written under, and SQLite has no row-level security to compensate.
func (s *SQLiteCommandStore) ListPendingDeliveries(ctx context.Context, stewardID, stewardTenant string) ([]*business.CommandRecord, error) {
	if stewardID == "" {
		return nil, business.ErrCommandStewardIDRequired
	}
	if stewardTenant == "" {
		return nil, business.ErrCommandTenantIDRequired
	}

	// The tenant predicate is a fixed statement with bound parameters — no
	// generated fragment, so nothing about the tenant path reaches the SQL text.
	// It matches business.TenantPathChain exactly: the record's own tenant, or an
	// ancestor of it, tested by prefix equality against the separator rather than
	// LIKE (a tenant path containing % or _ would otherwise widen the match).
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, steward_id, tenant_id, payload, status,
		       issued_at, started_at, completed_at, result, error_message, issued_by,
		       delivery_status, delivery_detail
		FROM commands
		WHERE steward_id = ? AND delivery_status = ?
		  AND (tenant_id = ? OR substr(?, 1, length(tenant_id) + 1) = tenant_id || '/')
		ORDER BY issued_at ASC`,
		stewardID, string(business.DeliveryStatusPending), stewardTenant, stewardTenant)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list pending deliveries for %s: %w", stewardID, err)
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

// GetCommandRecord retrieves the current state of a command by ID.
func (s *SQLiteCommandStore) GetCommandRecord(ctx context.Context, id string) (*business.CommandRecord, error) {
	if id == "" {
		return nil, business.ErrCommandIDRequired
	}

	row := s.db.QueryRowContext(ctx, `
		SELECT id, type, steward_id, tenant_id, payload, status,
		       issued_at, started_at, completed_at, result, error_message, issued_by,
		       delivery_status, delivery_detail
		FROM commands WHERE id = ?`, id)

	return scanCommandRecord(row)
}

// ListCommandRecords returns commands matching the optional filter.
func (s *SQLiteCommandStore) ListCommandRecords(ctx context.Context, filter *business.CommandFilter) ([]*business.CommandRecord, error) {
	query := `
		SELECT id, type, steward_id, tenant_id, payload, status,
		       issued_at, started_at, completed_at, result, error_message, issued_by,
		       delivery_status, delivery_detail
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
	var payloadStr, statusStr, issuedAtStr, resultStr, deliveryStatusStr string
	var startedAt, completedAt sql.NullString

	err := row.Scan(
		&rec.ID, &rec.Type, &rec.StewardID, &rec.TenantID,
		&payloadStr, &statusStr,
		&issuedAtStr, &startedAt, &completedAt,
		&resultStr, &rec.ErrorMessage, &rec.IssuedBy,
		&deliveryStatusStr, &rec.DeliveryDetail,
	)
	if err == sql.ErrNoRows {
		return nil, business.ErrCommandNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to scan command record: %w", err)
	}
	return populateCommandRecord(&rec, payloadStr, statusStr, deliveryStatusStr, issuedAtStr, startedAt, completedAt, resultStr)
}

// scanCommandRow scans a *sql.Rows (multi-row Query result) into a CommandRecord.
func scanCommandRow(rows *sql.Rows) (*business.CommandRecord, error) {
	var rec business.CommandRecord
	var payloadStr, statusStr, issuedAtStr, resultStr, deliveryStatusStr string
	var startedAt, completedAt sql.NullString

	if err := rows.Scan(
		&rec.ID, &rec.Type, &rec.StewardID, &rec.TenantID,
		&payloadStr, &statusStr,
		&issuedAtStr, &startedAt, &completedAt,
		&resultStr, &rec.ErrorMessage, &rec.IssuedBy,
		&deliveryStatusStr, &rec.DeliveryDetail,
	); err != nil {
		return nil, fmt.Errorf("sqlite: failed to scan command row: %w", err)
	}
	return populateCommandRecord(&rec, payloadStr, statusStr, deliveryStatusStr, issuedAtStr, startedAt, completedAt, resultStr)
}

// populateCommandRecord deserialises JSON columns and nullable timestamps.
func populateCommandRecord(
	rec *business.CommandRecord,
	payloadStr, statusStr, deliveryStatusStr, issuedAtStr string,
	startedAt, completedAt sql.NullString,
	resultStr string,
) (*business.CommandRecord, error) {
	rec.Status = business.CommandStatus(statusStr)
	rec.DeliveryStatus = business.DeliveryStatus(deliveryStatusStr)
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
