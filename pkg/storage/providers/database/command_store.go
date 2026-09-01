// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements CommandStore using PostgreSQL with RLS tenant isolation.
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// DatabaseCommandStore implements business.CommandStore using PostgreSQL.
// CreateCommandRecord and UpdateCommandStatus are atomic: each opens a transaction,
// sets app.current_tenant, writes the main row and appends a transition in one commit.
type DatabaseCommandStore struct {
	db *sql.DB
}

// Compile-time check.
var _ business.CommandStore = (*DatabaseCommandStore)(nil)

// NewDatabaseCommandStore opens a pooled Postgres connection, initialises the schema, and
// returns a ready-to-use CommandStore.
func NewDatabaseCommandStore(dsn string, config map[string]interface{}) (*DatabaseCommandStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("database: failed to open command store connection: %w", err)
	}

	db.SetMaxOpenConns(getIntFromConfig(config, "max_open_connections", 25))
	db.SetMaxIdleConns(getIntFromConfig(config, "max_idle_connections", 5))
	db.SetConnMaxLifetime(time.Duration(getIntFromConfig(config, "connection_max_lifetime_minutes", 30)) * time.Minute)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to ping command store: %w", err)
	}

	store := &DatabaseCommandStore{db: db}
	if err := store.initializeSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: failed to initialise command store schema: %w", err)
	}
	return store, nil
}

func (s *DatabaseCommandStore) initializeSchema() error {
	ctx := context.Background()
	const lockID = 98765433
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("failed to acquire command schema lock: %w", err)
	}
	defer func() { _, _ = s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID) }()
	schemas := NewDatabaseSchemas()
	if err := schemas.CreateCommandRecordsTable(ctx, s.db); err != nil {
		return err
	}
	if err := schemas.BackfillCommandRecordsDeliveryStatus(ctx, s.db); err != nil {
		return err
	}
	return schemas.CreateCommandTransitionsTable(ctx, s.db)
}

// Close releases the database connection.
func (s *DatabaseCommandStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// CreateCommandRecord inserts a new command record with status=pending and records
// the initial transition in the audit trail.
func (s *DatabaseCommandStore) CreateCommandRecord(ctx context.Context, record *business.CommandRecord) error {
	if record == nil {
		return fmt.Errorf("database: command record cannot be nil")
	}
	if record.ID == "" {
		return business.ErrCommandIDRequired
	}
	if record.StewardID == "" {
		return business.ErrCommandStewardIDRequired
	}

	now := time.Now().UTC()
	if record.IssuedAt.IsZero() {
		record.IssuedAt = now
	}
	record.Status = business.CommandStatusPending
	if record.DeliveryStatus == "" {
		record.DeliveryStatus = business.DeliveryStatusPending
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: failed to begin create command tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := setTenantLocal(ctx, tx, record.TenantID); err != nil {
		return fmt.Errorf("database: failed to set tenant context: %w", err)
	}

	if err := dbInsertCommandRecord(ctx, tx, record, now); err != nil {
		return err
	}

	return tx.Commit()
}

// CreateCommandRecords atomically creates a batch of command records in a single
// transaction: every record commits, or none do (Issue #3757, ADR-031 Decision 2).
// All records must share the same tenant — callers fanning a single desired-state
// write out to multiple stewards in one tenant call this once with the full batch
// so the durable outbox rows for that fan-out are one commit, not N independent ones.
func (s *DatabaseCommandStore) CreateCommandRecords(ctx context.Context, records []*business.CommandRecord) error {
	if len(records) == 0 {
		return nil
	}
	tenantID := records[0].TenantID
	for _, r := range records {
		if r == nil {
			return fmt.Errorf("database: command record cannot be nil")
		}
		if r.ID == "" {
			return business.ErrCommandIDRequired
		}
		if r.StewardID == "" {
			return business.ErrCommandStewardIDRequired
		}
	}

	now := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: failed to begin batch create command tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := setTenantLocal(ctx, tx, tenantID); err != nil {
		return fmt.Errorf("database: failed to set tenant context: %w", err)
	}

	for _, record := range records {
		if record.IssuedAt.IsZero() {
			record.IssuedAt = now
		}
		record.Status = business.CommandStatusPending
		if record.DeliveryStatus == "" {
			record.DeliveryStatus = business.DeliveryStatusPending
		}
		if err := dbInsertCommandRecord(ctx, tx, record, now); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// dbInsertCommandRecord inserts a single command_records row plus its initial
// pending transition within tx. Shared by CreateCommandRecord and
// CreateCommandRecords so both paths persist identically.
func dbInsertCommandRecord(ctx context.Context, tx *sql.Tx, record *business.CommandRecord, transitionTime time.Time) error {
	payloadJSON, err := json.Marshal(record.Payload)
	if err != nil {
		return fmt.Errorf("database: failed to marshal command payload: %w", err)
	}
	resultJSON, err := json.Marshal(record.Result)
	if err != nil {
		return fmt.Errorf("database: failed to marshal command result: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO command_records
			(id, type, steward_id, tenant_id, payload, status,
			 issued_at, started_at, completed_at, result, error_message, issued_by,
			 delivery_status, delivery_detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7,NULL,NULL,$8,$9,$10,$11,$12)`,
		record.ID,
		record.Type,
		record.StewardID,
		record.TenantID,
		payloadJSON,
		string(business.CommandStatusPending),
		record.IssuedAt,
		resultJSON,
		record.ErrorMessage,
		record.IssuedBy,
		string(record.DeliveryStatus),
		record.DeliveryDetail,
	)
	if err != nil {
		return fmt.Errorf("database: failed to insert command record %s: %w", record.ID, err)
	}

	return dbInsertTransition(ctx, tx, record.ID, business.CommandStatusPending, transitionTime, "")
}

// UpdateCommandStatus transitions a command to the given status and appends a transition.
func (s *DatabaseCommandStore) UpdateCommandStatus(
	ctx context.Context,
	id string,
	status business.CommandStatus,
	result map[string]interface{},
	errorMessage string,
) error {
	if id == "" {
		return business.ErrCommandIDRequired
	}

	now := time.Now().UTC()

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("database: failed to marshal result: %w", err)
	}

	// Determine the tenant from the existing record first (needed for RLS on the UPDATE).
	var tenantID string
	err = s.db.QueryRowContext(ctx, `SELECT tenant_id FROM command_records WHERE id = $1`, id).Scan(&tenantID)
	if err == sql.ErrNoRows {
		return business.ErrCommandNotFound
	}
	if err != nil {
		return fmt.Errorf("database: failed to fetch command tenant: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: failed to begin update command tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := setTenantLocal(ctx, tx, tenantID); err != nil {
		return fmt.Errorf("database: failed to set tenant context: %w", err)
	}

	var res sql.Result
	switch status {
	case business.CommandStatusExecuting:
		res, err = tx.ExecContext(ctx, `
			UPDATE command_records SET status=$2, started_at=$3, result=$4, error_message=$5
			WHERE id=$1`,
			id, string(status), now, resultJSON, errorMessage)
	case business.CommandStatusCompleted, business.CommandStatusFailed, business.CommandStatusCancelled:
		res, err = tx.ExecContext(ctx, `
			UPDATE command_records SET status=$2, completed_at=$3, result=$4, error_message=$5
			WHERE id=$1`,
			id, string(status), now, resultJSON, errorMessage)
	default:
		res, err = tx.ExecContext(ctx, `
			UPDATE command_records SET status=$2, result=$3, error_message=$4
			WHERE id=$1`,
			id, string(status), resultJSON, errorMessage)
	}
	if err != nil {
		return fmt.Errorf("database: failed to update command %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return business.ErrCommandNotFound
	}

	if err := dbInsertTransition(ctx, tx, id, status, now, errorMessage); err != nil {
		return err
	}

	return tx.Commit()
}

// UpdateDeliveryStatus transitions a command record's outbox DeliveryStatus
// (Issue #3757, ADR-031 Decision 2). Independent of UpdateCommandStatus: this
// updates delivery_status/delivery_detail only and does not touch status,
// started_at, completed_at, result, or the command_transitions audit trail
// (that trail records CommandStatus, not DeliveryStatus).
func (s *DatabaseCommandStore) UpdateDeliveryStatus(
	ctx context.Context,
	id string,
	status business.DeliveryStatus,
	detail string,
) error {
	if id == "" {
		return business.ErrCommandIDRequired
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE command_records SET delivery_status = $2, delivery_detail = $3
		WHERE id = $1`,
		id, string(status), detail)
	if err != nil {
		return fmt.Errorf("database: failed to update delivery status for %s: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("database: failed to read rows affected for %s: %w", id, err)
	}
	if n == 0 {
		return business.ErrCommandNotFound
	}
	return nil
}

// ListPendingDeliveries returns every command record targeting stewardID whose
// DeliveryStatus is still pending (Issue #3757) — the set a steward drains on
// reconnect.
func (s *DatabaseCommandStore) ListPendingDeliveries(ctx context.Context, stewardID string) ([]*business.CommandRecord, error) {
	if stewardID == "" {
		return nil, business.ErrCommandStewardIDRequired
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, steward_id, tenant_id, payload, status,
		       issued_at, started_at, completed_at, result, error_message, issued_by,
		       delivery_status, delivery_detail
		FROM command_records
		WHERE steward_id = $1 AND delivery_status = $2
		ORDER BY issued_at ASC`, stewardID, string(business.DeliveryStatusPending))
	if err != nil {
		return nil, fmt.Errorf("database: failed to list pending deliveries for %s: %w", stewardID, err)
	}
	defer func() { _ = rows.Close() }()
	return scanDBCommandRows(rows)
}

// GetCommandRecord retrieves the current state of a command by ID.
func (s *DatabaseCommandStore) GetCommandRecord(ctx context.Context, id string) (*business.CommandRecord, error) {
	if id == "" {
		return nil, business.ErrCommandIDRequired
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, type, steward_id, tenant_id, payload, status,
		       issued_at, started_at, completed_at, result, error_message, issued_by,
		       delivery_status, delivery_detail
		FROM command_records WHERE id = $1`, id)
	return scanDBCommandRecord(row)
}

// ListCommandRecords returns commands matching the optional filter.
func (s *DatabaseCommandStore) ListCommandRecords(ctx context.Context, filter *business.CommandFilter) ([]*business.CommandRecord, error) {
	query := `
		SELECT id, type, steward_id, tenant_id, payload, status,
		       issued_at, started_at, completed_at, result, error_message, issued_by,
		       delivery_status, delivery_detail
		FROM command_records WHERE 1=1`
	var args []interface{}
	argN := 0
	tenantID := ""

	if filter != nil {
		if filter.StewardID != "" {
			argN++
			query += fmt.Sprintf(" AND steward_id = $%d", argN)
			args = append(args, filter.StewardID)
		}
		if filter.TenantID != "" {
			tenantID = filter.TenantID
			argN++
			query += fmt.Sprintf(" AND tenant_id = $%d", argN)
			args = append(args, filter.TenantID)
		}
		if filter.Status != "" {
			argN++
			query += fmt.Sprintf(" AND status = $%d", argN)
			args = append(args, string(filter.Status))
		}
		if filter.IssuedBy != "" {
			argN++
			query += fmt.Sprintf(" AND issued_by = $%d", argN)
			args = append(args, filter.IssuedBy)
		}
	}

	query += " ORDER BY issued_at DESC"

	if filter != nil && filter.Limit > 0 {
		argN++
		query += fmt.Sprintf(" LIMIT $%d", argN)
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			argN++
			// #nosec G202 -- only the generated PostgreSQL placeholder number is
			// formatted into SQL; the caller's offset remains a bound argument.
			query += fmt.Sprintf(" OFFSET $%d", argN)
			args = append(args, filter.Offset)
		}
	}

	if tenantID != "" {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("database: failed to begin list commands tx: %w", err)
		}
		defer func() { _ = tx.Rollback() }()
		if err := setTenantLocal(ctx, tx, tenantID); err != nil {
			return nil, fmt.Errorf("database: failed to set tenant context: %w", err)
		}
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("database: failed to list commands: %w", err)
		}
		defer func() { _ = rows.Close() }()
		result, scanErr := scanDBCommandRows(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		return result, tx.Commit()
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("database: failed to list commands: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanDBCommandRows(rows)
}

// ListCommandsByDevice returns all commands dispatched to the given steward.
func (s *DatabaseCommandStore) ListCommandsByDevice(ctx context.Context, stewardID string) ([]*business.CommandRecord, error) {
	return s.ListCommandRecords(ctx, &business.CommandFilter{StewardID: stewardID})
}

// ListCommandsByStatus returns all commands in the given status.
func (s *DatabaseCommandStore) ListCommandsByStatus(ctx context.Context, status business.CommandStatus) ([]*business.CommandRecord, error) {
	return s.ListCommandRecords(ctx, &business.CommandFilter{Status: status})
}

// GetCommandAuditTrail returns all state transitions for the command in chronological order.
func (s *DatabaseCommandStore) GetCommandAuditTrail(ctx context.Context, commandID string) ([]*business.CommandTransition, error) {
	if commandID == "" {
		return nil, business.ErrCommandIDRequired
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT command_id, status, timestamp, error_message
		FROM command_transitions
		WHERE command_id = $1
		ORDER BY id ASC`, commandID)
	if err != nil {
		return nil, fmt.Errorf("database: failed to query audit trail for %s: %w", commandID, err)
	}
	defer func() { _ = rows.Close() }()

	var transitions []*business.CommandTransition
	for rows.Next() {
		var t business.CommandTransition
		var statusStr string
		if err := rows.Scan(&t.CommandID, &statusStr, &t.Timestamp, &t.ErrorMessage); err != nil {
			return nil, fmt.Errorf("database: failed to scan transition: %w", err)
		}
		t.Status = business.CommandStatus(statusStr)
		transitions = append(transitions, &t)
	}
	return transitions, rows.Err()
}

// PurgeExpiredRecords deletes completed/failed/cancelled commands older than olderThan.
// Executing and pending records are never purged.
func (s *DatabaseCommandStore) PurgeExpiredRecords(ctx context.Context, olderThan time.Time) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("database: failed to begin purge tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT id FROM command_records
		WHERE status = ANY($1) AND issued_at < $2`,
		[]string{"completed", "failed", "cancelled"}, olderThan)
	if err != nil {
		return 0, fmt.Errorf("database: failed to query expired commands: %w", err)
	}

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("database: failed to scan expired command id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("database: rows close: %w", err)
	}

	if len(ids) == 0 {
		return 0, tx.Commit()
	}

	// Delete transitions first.
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	inClause := strings.Join(placeholders, ",")

	if _, err := tx.ExecContext(ctx,
		fmt.Sprintf("DELETE FROM command_transitions WHERE command_id IN (%s)", inClause), args...); err != nil {
		return 0, fmt.Errorf("database: failed to delete transitions: %w", err)
	}

	res, err := tx.ExecContext(ctx, `
		DELETE FROM command_records
		WHERE status = ANY($1) AND issued_at < $2`,
		[]string{"completed", "failed", "cancelled"}, olderThan)
	if err != nil {
		return 0, fmt.Errorf("database: failed to purge command records: %w", err)
	}

	n, _ := res.RowsAffected()
	return n, tx.Commit()
}

// HealthCheck verifies the store is operational.
func (s *DatabaseCommandStore) HealthCheck(ctx context.Context) error {
	var dummy int
	return s.db.QueryRowContext(ctx, `SELECT 1`).Scan(&dummy)
}

// ── internal helpers ─────────────────────────────────────────────────────────

func dbInsertTransition(ctx context.Context, tx *sql.Tx, commandID string, status business.CommandStatus, ts time.Time, errMsg string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO command_transitions (command_id, status, timestamp, error_message)
		VALUES ($1, $2, $3, $4)`,
		commandID, string(status), ts, errMsg)
	if err != nil {
		return fmt.Errorf("database: failed to insert transition for %s: %w", commandID, err)
	}
	return nil
}

func scanDBCommandRecord(row *sql.Row) (*business.CommandRecord, error) {
	var rec business.CommandRecord
	var payloadJSON, resultJSON []byte
	var statusStr, deliveryStatusStr string
	var startedAt, completedAt sql.NullTime

	err := row.Scan(
		&rec.ID, &rec.Type, &rec.StewardID, &rec.TenantID,
		&payloadJSON, &statusStr,
		&rec.IssuedAt, &startedAt, &completedAt,
		&resultJSON, &rec.ErrorMessage, &rec.IssuedBy,
		&deliveryStatusStr, &rec.DeliveryDetail,
	)
	if err == sql.ErrNoRows {
		return nil, business.ErrCommandNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("database: failed to scan command record: %w", err)
	}
	return populateDBCommandRecord(&rec, statusStr, deliveryStatusStr, startedAt, completedAt, payloadJSON, resultJSON)
}

func scanDBCommandRows(rows *sql.Rows) ([]*business.CommandRecord, error) {
	var records []*business.CommandRecord
	for rows.Next() {
		var rec business.CommandRecord
		var payloadJSON, resultJSON []byte
		var statusStr, deliveryStatusStr string
		var startedAt, completedAt sql.NullTime

		if err := rows.Scan(
			&rec.ID, &rec.Type, &rec.StewardID, &rec.TenantID,
			&payloadJSON, &statusStr,
			&rec.IssuedAt, &startedAt, &completedAt,
			&resultJSON, &rec.ErrorMessage, &rec.IssuedBy,
			&deliveryStatusStr, &rec.DeliveryDetail,
		); err != nil {
			return nil, fmt.Errorf("database: failed to scan command row: %w", err)
		}
		populated, err := populateDBCommandRecord(&rec, statusStr, deliveryStatusStr, startedAt, completedAt, payloadJSON, resultJSON)
		if err != nil {
			return nil, err
		}
		records = append(records, populated)
	}
	return records, rows.Err()
}

func populateDBCommandRecord(
	rec *business.CommandRecord,
	statusStr, deliveryStatusStr string,
	startedAt, completedAt sql.NullTime,
	payloadJSON, resultJSON []byte,
) (*business.CommandRecord, error) {
	rec.Status = business.CommandStatus(statusStr)
	rec.DeliveryStatus = business.DeliveryStatus(deliveryStatusStr)
	if startedAt.Valid {
		t := startedAt.Time
		rec.StartedAt = &t
	}
	if completedAt.Valid {
		t := completedAt.Time
		rec.CompletedAt = &t
	}
	if len(payloadJSON) > 0 {
		var payload map[string]interface{}
		if err := json.Unmarshal(payloadJSON, &payload); err == nil {
			rec.Payload = payload
		}
	}
	if len(resultJSON) > 0 {
		var result map[string]interface{}
		if err := json.Unmarshal(resultJSON, &result); err == nil {
			rec.Result = result
		}
	}
	return rec, nil
}
