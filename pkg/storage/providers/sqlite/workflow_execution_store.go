// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.WorkflowExecutionStore = (*SQLiteWorkflowExecutionStore)(nil)

// SQLiteWorkflowExecutionStore implements business.WorkflowExecutionStore using the
// workflow_executions table, keyed by (tenant_id, execution_id). Timestamps are UNIX
// nanoseconds (0 = unset) so ordering is numeric. The empty tenant id is the root
// tenant's key.
type SQLiteWorkflowExecutionStore struct {
	db *sql.DB
}

// Close closes the underlying database connection.
func (s *SQLiteWorkflowExecutionStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// terminalExecutionStatuses is the SQL form of business.IsTerminalWorkflowExecutionStatus.
const terminalExecutionStatuses = `('completed', 'failed', 'cancelled')`

const workflowExecutionColumns = `tenant_id, execution_id, workflow_name, status, start_time, end_time, payload`

func scanWorkflowExecution(row interface{ Scan(...any) error }) (*business.WorkflowExecutionRecord, error) {
	r := &business.WorkflowExecutionRecord{}
	var start, end int64
	if err := row.Scan(&r.TenantID, &r.ExecutionID, &r.WorkflowName, &r.Status, &start, &end, &r.Payload); err != nil {
		return nil, err
	}
	r.StartTime = fromNanos(start)
	r.EndTime = fromNanos(end)
	return r, nil
}

// Save implements business.WorkflowExecutionStore. The upsert's WHERE clause is the
// terminal guard: a stored terminal record is only replaced by another terminal one.
func (s *SQLiteWorkflowExecutionStore) Save(ctx context.Context, r *business.WorkflowExecutionRecord) error {
	if r == nil || r.ExecutionID == "" {
		return fmt.Errorf("sqlite: workflow execution requires an execution id")
	}
	payload := r.Payload
	if payload == nil {
		payload = []byte{}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO workflow_executions (`+workflowExecutionColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id, execution_id) DO UPDATE SET
			workflow_name = excluded.workflow_name, status = excluded.status,
			start_time = excluded.start_time, end_time = excluded.end_time, payload = excluded.payload
		WHERE workflow_executions.status NOT IN `+terminalExecutionStatuses+`
			OR excluded.status IN `+terminalExecutionStatuses,
		r.TenantID, r.ExecutionID, r.WorkflowName, r.Status, nanos(r.StartTime), nanos(r.EndTime), payload)
	if err != nil {
		return fmt.Errorf("sqlite: failed to save workflow execution: %w", err)
	}
	return nil
}

// Get implements business.WorkflowExecutionStore.
func (s *SQLiteWorkflowExecutionStore) Get(ctx context.Context, tenantID, executionID string) (*business.WorkflowExecutionRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+workflowExecutionColumns+` FROM workflow_executions
		WHERE tenant_id = ? AND execution_id = ?`, tenantID, executionID)
	r, err := scanWorkflowExecution(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, business.ErrWorkflowExecutionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to get workflow execution: %w", err)
	}
	return r, nil
}

// List implements business.WorkflowExecutionStore.
func (s *SQLiteWorkflowExecutionStore) List(ctx context.Context, tenantID, workflowName string, limit int) ([]*business.WorkflowExecutionRecord, error) {
	query := `SELECT ` + workflowExecutionColumns + ` FROM workflow_executions WHERE tenant_id = ?`
	args := []any{tenantID}
	if workflowName != "" {
		query += ` AND workflow_name = ?`
		args = append(args, workflowName)
	}
	query += ` ORDER BY start_time DESC, execution_id DESC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list workflow executions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]*business.WorkflowExecutionRecord, 0)
	for rows.Next() {
		r, err := scanWorkflowExecution(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: failed to scan workflow execution: %w", err)
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: failed to read workflow executions: %w", err)
	}
	return result, nil
}

// Prune implements business.WorkflowExecutionStore.
func (s *SQLiteWorkflowExecutionStore) Prune(ctx context.Context, tenantID string, keep int) (int, error) {
	if keep < 0 {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM workflow_executions
		WHERE tenant_id = ? AND status IN `+terminalExecutionStatuses+` AND execution_id NOT IN (
			SELECT execution_id FROM workflow_executions
			WHERE tenant_id = ? AND status IN `+terminalExecutionStatuses+`
			ORDER BY start_time DESC, execution_id DESC LIMIT ?)`,
		tenantID, tenantID, keep)
	if err != nil {
		return 0, fmt.Errorf("sqlite: failed to prune workflow executions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return int(n), nil
}
