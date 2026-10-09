// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.WorkflowExecutionStore = (*DatabaseWorkflowExecutionStore)(nil)

// DatabaseWorkflowExecutionStore implements business.WorkflowExecutionStore using
// PostgreSQL — the execution history every controller node reads and writes.
type DatabaseWorkflowExecutionStore struct {
	db *sql.DB
}

// NewDatabaseWorkflowExecutionStore creates the store on the shared connection pool db
// (owned by DatabaseProvider; ADR-031 Decision 6) and ensures its table exists.
func NewDatabaseWorkflowExecutionStore(db *sql.DB, _ map[string]interface{}) (*DatabaseWorkflowExecutionStore, error) {
	if err := NewDatabaseSchemas().CreateWorkflowExecutionsTable(context.Background(), db); err != nil {
		return nil, err
	}
	return &DatabaseWorkflowExecutionStore{db: db}, nil
}

// Close is a no-op: the connection pool is owned and closed by DatabaseProvider.
func (s *DatabaseWorkflowExecutionStore) Close() error { return nil }

const workflowExecutionColumns = `tenant_id, execution_id, workflow_name, status, start_time, end_time, payload`

const terminalExecutionStatuses = `('completed', 'failed', 'cancelled')`

func scanWorkflowExecution(row rowScanner) (*business.WorkflowExecutionRecord, error) {
	r := &business.WorkflowExecutionRecord{}
	var end sql.NullTime
	if err := row.Scan(&r.TenantID, &r.ExecutionID, &r.WorkflowName, &r.Status, &r.StartTime, &end, &r.Payload); err != nil {
		return nil, err
	}
	r.StartTime = r.StartTime.UTC()
	r.EndTime = approvalTimeOrZero(end)
	return r, nil
}

// Save implements business.WorkflowExecutionStore. The upsert's WHERE clause is the
// terminal guard: a stored terminal row is only replaced by another terminal one.
func (s *DatabaseWorkflowExecutionStore) Save(ctx context.Context, r *business.WorkflowExecutionRecord) error {
	if r == nil || r.ExecutionID == "" {
		return fmt.Errorf("workflow execution requires an execution id")
	}
	payload := r.Payload
	if payload == nil {
		payload = []byte{}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO cfgms_workflow_executions (`+workflowExecutionColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, execution_id) DO UPDATE SET
			workflow_name = EXCLUDED.workflow_name, status = EXCLUDED.status,
			start_time = EXCLUDED.start_time, end_time = EXCLUDED.end_time, payload = EXCLUDED.payload
		WHERE cfgms_workflow_executions.status NOT IN `+terminalExecutionStatuses+`
			OR EXCLUDED.status IN `+terminalExecutionStatuses,
		r.TenantID, r.ExecutionID, r.WorkflowName, r.Status, r.StartTime.UTC(), approvalNullTime(r.EndTime), payload)
	if err != nil {
		return fmt.Errorf("failed to save workflow execution: %w", err)
	}
	return nil
}

// Get implements business.WorkflowExecutionStore.
func (s *DatabaseWorkflowExecutionStore) Get(ctx context.Context, tenantID, executionID string) (*business.WorkflowExecutionRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+workflowExecutionColumns+` FROM cfgms_workflow_executions
		WHERE tenant_id = $1 AND execution_id = $2`, tenantID, executionID)
	r, err := scanWorkflowExecution(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, business.ErrWorkflowExecutionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow execution: %w", err)
	}
	return r, nil
}

// List implements business.WorkflowExecutionStore.
func (s *DatabaseWorkflowExecutionStore) List(ctx context.Context, tenantID, workflowName string, limit int) ([]*business.WorkflowExecutionRecord, error) {
	if limit < 0 {
		limit = 0
	}
	// One static, fully parameterized statement: an empty workflow name matches
	// every workflow, and a zero limit becomes LIMIT NULL, which Postgres treats
	// as no limit.
	rows, err := s.db.QueryContext(ctx, `SELECT `+workflowExecutionColumns+` FROM cfgms_workflow_executions
		WHERE tenant_id = $1 AND ($2::text = '' OR workflow_name = $2::text)
		ORDER BY start_time DESC, execution_id DESC
		LIMIT NULLIF($3::bigint, 0)`,
		tenantID, workflowName, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list workflow executions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]*business.WorkflowExecutionRecord, 0)
	for rows.Next() {
		r, err := scanWorkflowExecution(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan workflow execution: %w", err)
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read workflow executions: %w", err)
	}
	return result, nil
}

// Prune implements business.WorkflowExecutionStore.
func (s *DatabaseWorkflowExecutionStore) Prune(ctx context.Context, tenantID string, keep int) (int, error) {
	if keep < 0 {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM cfgms_workflow_executions
		WHERE tenant_id = $1 AND status IN `+terminalExecutionStatuses+` AND execution_id NOT IN (
			SELECT execution_id FROM cfgms_workflow_executions
			WHERE tenant_id = $1 AND status IN `+terminalExecutionStatuses+`
			ORDER BY start_time DESC, execution_id DESC LIMIT $2)`,
		tenantID, keep)
	if err != nil {
		return 0, fmt.Errorf("failed to prune workflow executions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return int(n), nil
}
