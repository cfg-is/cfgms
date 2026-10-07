// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database implements business.ScriptRunStore using PostgreSQL — the
// shared script run, job and execution-grant tables (Issue #4528).
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.ScriptRunStore = (*DatabaseScriptRunStore)(nil)

// DatabaseScriptRunStore implements business.ScriptRunStore using PostgreSQL.
type DatabaseScriptRunStore struct {
	db *sql.DB
}

// NewDatabaseScriptRunStore creates the store on the shared connection pool db
// (owned by DatabaseProvider; ADR-031 Decision 6) and ensures its tables exist.
func NewDatabaseScriptRunStore(db *sql.DB, _ map[string]interface{}) (*DatabaseScriptRunStore, error) {
	if err := NewDatabaseSchemas().CreateScriptRunTables(context.Background(), db); err != nil {
		return nil, err
	}
	return &DatabaseScriptRunStore{db: db}, nil
}

// nullJSON stores an empty filter as SQL NULL rather than invalid JSONB.
func nullJSON(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

const scriptRunColumns = `run_id, tenant_id, created_by, created_at, status, filter_json,
	script_ref, inline_content, shell, job_count, completed_jobs, failed_jobs, kind, action_json`

const scriptRunJobColumns = `job_id, run_id, device_id, execution_id, status,
	created_at, completed_at, output, stderr, exit_code, result_code, dispatched_at`

// runKindOrScript normalises the empty kind to the script default.
func runKindOrScript(kind string) string {
	if kind == "" {
		return business.ScriptRunKindScript
	}
	return kind
}

// CreateRun implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) CreateRun(ctx context.Context, r *business.ScriptRun) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO script_runs (`+scriptRunColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		r.RunID, r.TenantID, r.CreatedBy, r.CreatedAt.UTC(), r.Status, nullJSON(r.FilterJSON),
		r.ScriptRef, r.InlineContent, r.Shell, r.JobCount, r.CompletedJobs, r.FailedJobs,
		runKindOrScript(r.Kind), nullJSON(r.ActionJSON))
	if err != nil {
		return fmt.Errorf("database: create script run: %w", err)
	}
	return nil
}

// CreateJob implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) CreateJob(ctx context.Context, j *business.ScriptRunJob) error {
	var completedAt interface{}
	if j.CompletedAt != nil {
		completedAt = j.CompletedAt.UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO script_run_jobs
		(job_id, run_id, device_id, execution_id, status, created_at, completed_at, output, stderr, exit_code,
		 result_code, dispatched_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		j.JobID, j.RunID, j.DeviceID, j.ExecutionID, j.Status, j.CreatedAt.UTC(), completedAt,
		j.Output, j.Stderr, j.ExitCode, j.ResultCode, nullTime(j.DispatchedAt))
	if err != nil {
		return fmt.Errorf("database: create script run job: %w", err)
	}
	return nil
}

func scanScriptRun(row rowScanner) (*business.ScriptRun, error) {
	r := &business.ScriptRun{}
	var filter, action sql.NullString
	if err := row.Scan(&r.RunID, &r.TenantID, &r.CreatedBy, &r.CreatedAt, &r.Status, &filter,
		&r.ScriptRef, &r.InlineContent, &r.Shell, &r.JobCount, &r.CompletedJobs, &r.FailedJobs,
		&r.Kind, &action); err != nil {
		return nil, err
	}
	if filter.Valid {
		r.FilterJSON = []byte(filter.String)
	}
	if action.Valid {
		r.ActionJSON = []byte(action.String)
	}
	return r, nil
}

// GetRun implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) GetRun(ctx context.Context, runID string) (*business.ScriptRun, error) {
	r, err := scanScriptRun(s.db.QueryRowContext(ctx,
		`SELECT `+scriptRunColumns+` FROM script_runs WHERE run_id = $1`, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, business.ErrScriptRunNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("database: get script run: %w", err)
	}
	return r, nil
}

// ListRuns implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) ListRuns(ctx context.Context, tenantID string, limit, offset int) ([]*business.ScriptRun, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" {
		rows, err = s.db.QueryContext(ctx, `SELECT `+scriptRunColumns+` FROM script_runs
			WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, tenantID, limit, offset)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT `+scriptRunColumns+` FROM script_runs
			ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	}
	if err != nil {
		return nil, fmt.Errorf("database: list script runs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var runs []*business.ScriptRun
	for rows.Next() {
		r, err := scanScriptRun(rows)
		if err != nil {
			return nil, fmt.Errorf("database: scan script run: %w", err)
		}
		runs = append(runs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("database: list script runs: %w", err)
	}
	return runs, nil
}

func scanScriptRunJob(row rowScanner) (*business.ScriptRunJob, error) {
	j := &business.ScriptRunJob{}
	var completedAt, dispatchedAt sql.NullTime
	if err := row.Scan(&j.JobID, &j.RunID, &j.DeviceID, &j.ExecutionID, &j.Status,
		&j.CreatedAt, &completedAt, &j.Output, &j.Stderr, &j.ExitCode, &j.ResultCode, &dispatchedAt); err != nil {
		return nil, err
	}
	if completedAt.Valid {
		t := completedAt.Time
		j.CompletedAt = &t
	}
	if dispatchedAt.Valid {
		t := dispatchedAt.Time
		j.DispatchedAt = &t
	}
	return j, nil
}

func collectScriptRunJobs(rows *sql.Rows) ([]*business.ScriptRunJob, error) {
	var jobs []*business.ScriptRunJob
	for rows.Next() {
		j, err := scanScriptRunJob(rows)
		if err != nil {
			return nil, fmt.Errorf("database: scan script run job: %w", err)
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("database: list script run jobs: %w", err)
	}
	return jobs, nil
}

// ListRunJobs implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) ListRunJobs(ctx context.Context, runID string) ([]*business.ScriptRunJob, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+scriptRunJobColumns+`
		FROM script_run_jobs WHERE run_id = $1 ORDER BY created_at ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("database: list script run jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return collectScriptRunJobs(rows)
}

// jobColumnsQualified is scriptRunJobColumns prefixed for the jobs/runs join.
const jobColumnsQualified = `j.job_id, j.run_id, j.device_id, j.execution_id, j.status,
	j.created_at, j.completed_at, j.output, j.stderr, j.exit_code, j.result_code, j.dispatched_at`

func nullTime(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return t.UTC()
}

// UpdateJobStatus implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) UpdateJobStatus(ctx context.Context, jobID, status, executionID string, completedAt *time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE script_run_jobs
		SET status = $1,
		    execution_id = CASE WHEN $2::text <> '' THEN $2::text ELSE execution_id END,
		    completed_at = COALESCE($3::timestamptz, completed_at)
		WHERE job_id = $4`, status, executionID, nullTime(completedAt), jobID)
	if err != nil {
		return fmt.Errorf("database: update script run job status: %w", err)
	}
	return nil
}

// UpdateJobResult implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) UpdateJobResult(ctx context.Context, jobID, status, executionID, output, stderr string, exitCode int, completedAt *time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE script_run_jobs
		SET status = $1,
		    execution_id = CASE WHEN $2::text <> '' THEN $2::text ELSE execution_id END,
		    completed_at = COALESCE($3::timestamptz, completed_at),
		    output = $4, stderr = $5, exit_code = $6
		WHERE job_id = $7`, status, executionID, nullTime(completedAt), output, stderr, exitCode, jobID)
	if err != nil {
		return fmt.Errorf("database: update script run job result: %w", err)
	}
	return nil
}

// UpdateJobResultCode implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) UpdateJobResultCode(ctx context.Context, jobID, code string) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE script_run_jobs SET result_code = $1 WHERE job_id = $2`, code, jobID); err != nil {
		return fmt.Errorf("database: update script run job result code: %w", err)
	}
	return nil
}

// MarkJobDispatched implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) MarkJobDispatched(ctx context.Context, jobID string, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE script_run_jobs SET status = 'dispatched', dispatched_at = $1
		WHERE job_id = $2 AND status = 'pending'`, at.UTC(), jobID)
	if err != nil {
		return false, fmt.Errorf("database: mark script run job dispatched: %w", err)
	}
	return rowsChanged(res)
}

// ListStaleActionJobs implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) ListStaleActionJobs(ctx context.Context, pendingBefore, dispatchedBefore time.Time) ([]*business.ScriptRunJob, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+jobColumnsQualified+`
		FROM script_run_jobs j JOIN script_runs r ON r.run_id = j.run_id
		WHERE r.kind = $1 AND j.completed_at IS NULL AND j.result_code = ''
		  AND ((j.status = 'pending' AND j.created_at < $2)
		    OR (j.status = 'dispatched' AND j.dispatched_at < $3))
		ORDER BY j.created_at ASC`,
		business.ScriptRunKindStewardAction, pendingBefore.UTC(), dispatchedBefore.UTC())
	if err != nil {
		return nil, fmt.Errorf("database: list stale action jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return collectScriptRunJobs(rows)
}

// ExpireJobIfStatus implements business.ScriptRunStore. The single conditional
// UPDATE is atomic: of several concurrent callers exactly one matches the
// status predicate and reports changed.
func (s *DatabaseScriptRunStore) ExpireJobIfStatus(ctx context.Context, jobID, fromStatus, resultCode string, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE script_run_jobs
		SET status = $1, result_code = $1, completed_at = $2
		WHERE job_id = $3 AND status = $4`, resultCode, at.UTC(), jobID, fromStatus)
	if err != nil {
		return false, fmt.Errorf("database: expire script run job: %w", err)
	}
	return rowsChanged(res)
}

func rowsChanged(res sql.Result) (bool, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("database: rows affected: %w", err)
	}
	return n > 0, nil
}

// UpdateRunStatus implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) UpdateRunStatus(ctx context.Context, runID, status string) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE script_runs SET status = $1 WHERE run_id = $2`, status, runID); err != nil {
		return fmt.Errorf("database: update script run status: %w", err)
	}
	return nil
}

// UpdateRunCounts implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) UpdateRunCounts(ctx context.Context, runID string, completedJobs, failedJobs int) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE script_runs SET completed_jobs = $1, failed_jobs = $2 WHERE run_id = $3`,
		completedJobs, failedJobs, runID); err != nil {
		return fmt.Errorf("database: update script run counts: %w", err)
	}
	return nil
}

// CreateExecutionGrant implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) CreateExecutionGrant(ctx context.Context, g *business.ExecutionGrant) error {
	scope, err := json.Marshal(g.Scope)
	if err != nil {
		return fmt.Errorf("database: marshal grant scope: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO execution_grants
		(execution_id, device_id, tenant_id, scope_json, created_at, expires_at, consumed)
		VALUES ($1, $2, $3, $4, $5, $6, false)`,
		g.ExecutionID, g.DeviceID, g.TenantID, string(scope), g.CreatedAt.UTC(), g.ExpiresAt.UTC()); err != nil {
		return fmt.Errorf("database: create execution grant: %w", err)
	}
	return nil
}

// LookupGrant implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) LookupGrant(ctx context.Context, deviceID, executionID string) (*business.ExecutionGrant, error) {
	g := &business.ExecutionGrant{}
	var scope string
	err := s.db.QueryRowContext(ctx, `SELECT device_id, tenant_id, execution_id, scope_json,
		created_at, expires_at, consumed FROM execution_grants
		WHERE execution_id = $1 AND device_id = $2`, executionID, deviceID).
		Scan(&g.DeviceID, &g.TenantID, &g.ExecutionID, &scope, &g.CreatedAt, &g.ExpiresAt, &g.Consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, business.ErrExecutionGrantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("database: lookup execution grant: %w", err)
	}
	if g.Consumed {
		return nil, business.ErrExecutionGrantConsumed
	}
	if time.Now().After(g.ExpiresAt) {
		return nil, business.ErrExecutionGrantNotFound
	}
	if err := json.Unmarshal([]byte(scope), &g.Scope); err != nil {
		return nil, fmt.Errorf("database: unmarshal grant scope: %w", err)
	}
	return g, nil
}

// ConsumeGrant implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) ConsumeGrant(ctx context.Context, executionID string) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE execution_grants SET consumed = true WHERE execution_id = $1`, executionID); err != nil {
		return fmt.Errorf("database: consume execution grant: %w", err)
	}
	return nil
}
