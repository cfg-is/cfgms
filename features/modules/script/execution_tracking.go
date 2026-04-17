// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ExecutionRecord is the durable audit record written when a script execution
// reaches a terminal state (completed, failed, cancelled, timeout).
//
// One record is written per device per execution. WorkflowRunID is empty for
// ad-hoc (non-workflow) executions — this is not an error.
type ExecutionRecord struct {
	ExecutionID   string    `json:"execution_id"`
	DeviceID      string    `json:"device_id"`
	WorkflowRunID string    `json:"workflow_run_id,omitempty"` // empty = ad-hoc
	WorkflowName  string    `json:"workflow_name,omitempty"`
	ScriptRef     string    `json:"script_ref"`
	ScriptVersion string    `json:"script_version,omitempty"`
	Shell         string    `json:"shell,omitempty"`
	ExitCode      int       `json:"exit_code"`
	State         string    `json:"state"` // completed | failed | cancelled | timeout
	Stdout        string    `json:"stdout,omitempty"`
	Stderr        string    `json:"stderr,omitempty"`
	DurationMs    int64     `json:"duration_ms,omitempty"`
	QueuedAt      time.Time `json:"queued_at,omitempty"`
	DispatchedAt  time.Time `json:"dispatched_at,omitempty"`
	CompletedAt   time.Time `json:"completed_at"`
}

// ExecutionTracker is the feature-local interface for durable execution audit
// records. It is NOT a central provider — it is used only within the script
// module and script_node.go.
type ExecutionTracker interface {
	// Record writes a terminal execution result. Calling Record with the same
	// (ExecutionID, DeviceID) pair is idempotent: the existing row is replaced
	// without error and without creating a duplicate.
	Record(ctx context.Context, r *ExecutionRecord) error

	// QueryByDevice returns up to limit records for deviceID, ordered by
	// CompletedAt DESC. Returns an empty slice (not an error) when no records
	// exist for the device.
	QueryByDevice(ctx context.Context, deviceID string, limit int) ([]*ExecutionRecord, error)

	// QueryByWorkflowRun returns all device records for workflowRunID, ordered
	// by CompletedAt DESC. Returns an empty slice (not an error) when no records
	// exist for the run.
	QueryByWorkflowRun(ctx context.Context, workflowRunID string) ([]*ExecutionRecord, error)
}

// ExecutionTrackingStore is the SQLite-backed implementation of ExecutionTracker.
// Call Init before using — it creates the table and indexes if they do not exist.
type ExecutionTrackingStore struct {
	db *sql.DB
}

// NewExecutionTrackingStore creates an ExecutionTrackingStore that uses db for
// persistence. The caller must call Init before any other method.
func NewExecutionTrackingStore(db *sql.DB) *ExecutionTrackingStore {
	return &ExecutionTrackingStore{db: db}
}

// Init creates the script_execution_results table and its two indexes if they
// do not already exist. Safe to call multiple times (idempotent).
func (s *ExecutionTrackingStore) Init(_ context.Context) error {
	const createTable = `
CREATE TABLE IF NOT EXISTS script_execution_results (
    execution_id     TEXT NOT NULL,
    device_id        TEXT NOT NULL,
    workflow_run_id  TEXT,
    workflow_name    TEXT,
    script_ref       TEXT NOT NULL,
    script_version   TEXT,
    shell            TEXT,
    exit_code        INTEGER,
    state            TEXT NOT NULL,
    stdout           TEXT,
    stderr           TEXT,
    duration_ms      INTEGER,
    queued_at        DATETIME,
    dispatched_at    DATETIME,
    completed_at     DATETIME NOT NULL,
    PRIMARY KEY (execution_id, device_id)
);`
	const createDeviceIndex = `
CREATE INDEX IF NOT EXISTS idx_ser_device
    ON script_execution_results (device_id, completed_at DESC);`
	const createWorkflowIndex = `
CREATE INDEX IF NOT EXISTS idx_ser_workflow
    ON script_execution_results (workflow_run_id, completed_at DESC);`

	for _, stmt := range []string{createTable, createDeviceIndex, createWorkflowIndex} {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("execution tracking store init: %w", err)
		}
	}
	return nil
}

// Record writes r to the database. If a row with the same (execution_id,
// device_id) already exists it is replaced, making the operation idempotent.
func (s *ExecutionTrackingStore) Record(_ context.Context, r *ExecutionRecord) error {
	const q = `
INSERT OR REPLACE INTO script_execution_results
    (execution_id, device_id, workflow_run_id, workflow_name, script_ref,
     script_version, shell, exit_code, state, stdout, stderr, duration_ms,
     queued_at, dispatched_at, completed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(q,
		r.ExecutionID,
		r.DeviceID,
		nullableString(r.WorkflowRunID),
		nullableString(r.WorkflowName),
		r.ScriptRef,
		nullableString(r.ScriptVersion),
		nullableString(r.Shell),
		r.ExitCode,
		r.State,
		nullableString(r.Stdout),
		nullableString(r.Stderr),
		nullableInt64(r.DurationMs),
		nullableTime(r.QueuedAt),
		nullableTime(r.DispatchedAt),
		r.CompletedAt,
	)
	if err != nil {
		return fmt.Errorf("execution tracking record: %w", err)
	}
	return nil
}

// QueryByDevice returns up to limit records for deviceID ordered by
// completed_at DESC. Pass limit ≤ 0 to return all matching records.
func (s *ExecutionTrackingStore) QueryByDevice(_ context.Context, deviceID string, limit int) ([]*ExecutionRecord, error) {
	const q = `
SELECT execution_id, device_id, workflow_run_id, workflow_name, script_ref,
       script_version, shell, exit_code, state, stdout, stderr, duration_ms,
       queued_at, dispatched_at, completed_at
FROM script_execution_results
WHERE device_id = ?
ORDER BY completed_at DESC
LIMIT ?`

	if limit <= 0 {
		limit = -1 // SQLite: LIMIT -1 = no limit
	}

	rows, err := s.db.Query(q, deviceID, limit)
	if err != nil {
		return nil, fmt.Errorf("execution tracking query by device: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanRecords(rows)
}

// QueryByWorkflowRun returns all records for workflowRunID ordered by
// completed_at DESC.
func (s *ExecutionTrackingStore) QueryByWorkflowRun(_ context.Context, workflowRunID string) ([]*ExecutionRecord, error) {
	const q = `
SELECT execution_id, device_id, workflow_run_id, workflow_name, script_ref,
       script_version, shell, exit_code, state, stdout, stderr, duration_ms,
       queued_at, dispatched_at, completed_at
FROM script_execution_results
WHERE workflow_run_id = ?
ORDER BY completed_at DESC`

	rows, err := s.db.Query(q, workflowRunID)
	if err != nil {
		return nil, fmt.Errorf("execution tracking query by workflow run: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanRecords(rows)
}

// scanRecords reads all rows from rows into ExecutionRecord slices.
func scanRecords(rows *sql.Rows) ([]*ExecutionRecord, error) {
	var records []*ExecutionRecord
	for rows.Next() {
		r := &ExecutionRecord{}
		var (
			workflowRunID sql.NullString
			workflowName  sql.NullString
			scriptVersion sql.NullString
			shell         sql.NullString
			exitCode      sql.NullInt64
			stdout        sql.NullString
			stderr        sql.NullString
			durationMs    sql.NullInt64
			queuedAt      sql.NullTime
			dispatchedAt  sql.NullTime
		)
		if err := rows.Scan(
			&r.ExecutionID,
			&r.DeviceID,
			&workflowRunID,
			&workflowName,
			&r.ScriptRef,
			&scriptVersion,
			&shell,
			&exitCode,
			&r.State,
			&stdout,
			&stderr,
			&durationMs,
			&queuedAt,
			&dispatchedAt,
			&r.CompletedAt,
		); err != nil {
			return nil, fmt.Errorf("execution tracking scan: %w", err)
		}

		r.WorkflowRunID = workflowRunID.String
		r.WorkflowName = workflowName.String
		r.ScriptVersion = scriptVersion.String
		r.Shell = shell.String
		r.ExitCode = int(exitCode.Int64)
		r.Stdout = stdout.String
		r.Stderr = stderr.String
		r.DurationMs = durationMs.Int64
		if queuedAt.Valid {
			r.QueuedAt = queuedAt.Time
		}
		if dispatchedAt.Valid {
			r.DispatchedAt = dispatchedAt.Time
		}

		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("execution tracking rows: %w", err)
	}
	return records, nil
}

// nullableString converts an empty string to sql.NullString{Valid: false}.
func nullableString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// nullableInt64 converts 0 to sql.NullInt64{Valid: false}.
func nullableInt64(n int64) sql.NullInt64 {
	return sql.NullInt64{Int64: n, Valid: n != 0}
}

// nullableTime converts a zero time.Time to sql.NullTime{Valid: false}.
func nullableTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t, Valid: !t.IsZero()}
}
