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
	script_ref, inline_content, shell, job_count, completed_jobs, failed_jobs`

// CreateRun implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) CreateRun(ctx context.Context, r *business.ScriptRun) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO script_runs (`+scriptRunColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		r.RunID, r.TenantID, r.CreatedBy, r.CreatedAt.UTC(), r.Status, nullJSON(r.FilterJSON),
		r.ScriptRef, r.InlineContent, r.Shell, r.JobCount, r.CompletedJobs, r.FailedJobs)
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
		(job_id, run_id, device_id, execution_id, status, created_at, completed_at, output, stderr, exit_code)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		j.JobID, j.RunID, j.DeviceID, j.ExecutionID, j.Status, j.CreatedAt.UTC(), completedAt,
		j.Output, j.Stderr, j.ExitCode)
	if err != nil {
		return fmt.Errorf("database: create script run job: %w", err)
	}
	return nil
}

func scanScriptRun(row rowScanner) (*business.ScriptRun, error) {
	r := &business.ScriptRun{}
	var filter sql.NullString
	if err := row.Scan(&r.RunID, &r.TenantID, &r.CreatedBy, &r.CreatedAt, &r.Status, &filter,
		&r.ScriptRef, &r.InlineContent, &r.Shell, &r.JobCount, &r.CompletedJobs, &r.FailedJobs); err != nil {
		return nil, err
	}
	if filter.Valid {
		r.FilterJSON = []byte(filter.String)
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

// ListRunJobs implements business.ScriptRunStore.
func (s *DatabaseScriptRunStore) ListRunJobs(ctx context.Context, runID string) ([]*business.ScriptRunJob, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT job_id, run_id, device_id, execution_id, status,
		created_at, completed_at, output, stderr, exit_code
		FROM script_run_jobs WHERE run_id = $1 ORDER BY created_at ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("database: list script run jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var jobs []*business.ScriptRunJob
	for rows.Next() {
		j := &business.ScriptRunJob{}
		var completedAt sql.NullTime
		if err := rows.Scan(&j.JobID, &j.RunID, &j.DeviceID, &j.ExecutionID, &j.Status,
			&j.CreatedAt, &completedAt, &j.Output, &j.Stderr, &j.ExitCode); err != nil {
			return nil, fmt.Errorf("database: scan script run job: %w", err)
		}
		if completedAt.Valid {
			t := completedAt.Time
			j.CompletedAt = &t
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("database: list script run jobs: %w", err)
	}
	return jobs, nil
}

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
