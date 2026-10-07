// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package batchjob

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteBatchJobStore is the SQLite-backed implementation of BatchJobStore.
// Call Initialize before any other method — it creates tables idempotently.
type SQLiteBatchJobStore struct {
	db *sql.DB
}

// NewSQLiteBatchJobStoreFromDSN opens a SQLite database at dsn and returns a
// SQLiteBatchJobStore backed by it. The caller must call Initialize and Close.
func NewSQLiteBatchJobStoreFromDSN(dsn string) (*SQLiteBatchJobStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("batch job store: open sqlite %s: %w", dsn, err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("batch job store: set busy_timeout: %w", err)
	}
	return &SQLiteBatchJobStore{db: db}, nil
}

// NewSQLiteBatchJobStore creates a SQLiteBatchJobStore that uses an existing db connection.
// The caller must call Initialize and is responsible for closing db.
func NewSQLiteBatchJobStore(db *sql.DB) *SQLiteBatchJobStore {
	return &SQLiteBatchJobStore{db: db}
}

// Initialize creates the batch_jobs and batch_steps tables if they do not already exist.
// Safe to call multiple times (idempotent).
func (s *SQLiteBatchJobStore) Initialize(_ context.Context) error {
	const createJobs = `
CREATE TABLE IF NOT EXISTS batch_jobs (
    id              TEXT NOT NULL PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    selector        TEXT NOT NULL,
    config_json     TEXT NOT NULL,
    targets_json    TEXT NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL,
    created_at      DATETIME NOT NULL,
    updated_at      DATETIME NOT NULL,
    initiated_by    TEXT
);`

	const createSteps = `
CREATE TABLE IF NOT EXISTS batch_steps (
    job_id           TEXT NOT NULL,
    step_index       INTEGER NOT NULL,
    status           TEXT NOT NULL,
    steward_ids_json TEXT NOT NULL DEFAULT '[]',
    started_at       DATETIME,
    completed_at     DATETIME,
    failed_ids_json  TEXT NOT NULL DEFAULT '[]',
    rollback_job_id  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (job_id, step_index)
);`

	const createStepsIndex = `
CREATE INDEX IF NOT EXISTS idx_batch_steps_job_id ON batch_steps(job_id);`

	for _, stmt := range []string{createJobs, createSteps, createStepsIndex} {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("batch job store init: %w", err)
		}
	}
	return nil
}

// CreateBatchJob inserts a new batch job. Returns an error if the ID already exists.
func (s *SQLiteBatchJobStore) CreateBatchJob(_ context.Context, job *BatchJob) error {
	configJSON, err := json.Marshal(job.Config)
	if err != nil {
		return fmt.Errorf("batch job store create: marshal config: %w", err)
	}
	targetsJSON, err := json.Marshal(job.Targets)
	if err != nil {
		return fmt.Errorf("batch job store create: marshal targets: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("batch job store create: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	const q = `
INSERT INTO batch_jobs
    (id, tenant_id, selector, config_json, targets_json, status, created_at, updated_at, initiated_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = tx.Exec(q,
		job.ID, job.TenantID, job.Selector,
		string(configJSON), string(targetsJSON),
		string(job.Status),
		job.CreatedAt.UTC(), job.UpdatedAt.UTC(),
		nullableStr(job.InitiatedBy),
	)
	if err != nil {
		return fmt.Errorf("batch job store create: insert job: %w", err)
	}

	for _, step := range job.Steps {
		if err := insertStep(tx, job.ID, step); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("batch job store create: commit: %w", err)
	}
	return nil
}

// UpdateBatchJobStatus sets the top-level status and updated_at for the job.
func (s *SQLiteBatchJobStore) UpdateBatchJobStatus(_ context.Context, id string, status BatchJobStatus) error {
	const q = `UPDATE batch_jobs SET status = ?, updated_at = ? WHERE id = ?`
	res, err := s.db.Exec(q, string(status), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("batch job store update status: %w", err)
	}
	return requireOneRow(res, "update status", id)
}

// UpdateBatchTargets replaces the resolved target steward IDs for the job.
func (s *SQLiteBatchJobStore) UpdateBatchTargets(_ context.Context, id string, targets []string) error {
	if targets == nil {
		targets = []string{}
	}
	targetsJSON, err := json.Marshal(targets)
	if err != nil {
		return fmt.Errorf("batch job store update targets: marshal: %w", err)
	}
	const q = `UPDATE batch_jobs SET targets_json = ?, updated_at = ? WHERE id = ?`
	res, err := s.db.Exec(q, string(targetsJSON), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("batch job store update targets: %w", err)
	}
	return requireOneRow(res, "update targets", id)
}

// UpdateBatchStep upserts a step within the batch job identified by jobID.
func (s *SQLiteBatchJobStore) UpdateBatchStep(_ context.Context, jobID string, step BatchStep) error {
	var exists int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM batch_jobs WHERE id = ?`, jobID,
	).Scan(&exists); err != nil {
		return fmt.Errorf("batch job store update step: check job: %w", err)
	}
	if exists == 0 {
		return ErrBatchJobNotFound
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("batch job store update step: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(
		`DELETE FROM batch_steps WHERE job_id = ? AND step_index = ?`,
		jobID, step.Index,
	); err != nil {
		return fmt.Errorf("batch job store update step: delete old: %w", err)
	}
	if err := insertStep(tx, jobID, step); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`UPDATE batch_jobs SET updated_at = ? WHERE id = ?`,
		time.Now().UTC(), jobID,
	); err != nil {
		return fmt.Errorf("batch job store update step: update job timestamp: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("batch job store update step: commit: %w", err)
	}
	return nil
}

// GetBatchJob retrieves the batch job with the given id, including all its steps.
func (s *SQLiteBatchJobStore) GetBatchJob(_ context.Context, id string) (*BatchJob, error) {
	const q = `
SELECT id, tenant_id, selector, config_json, targets_json, status,
       created_at, updated_at, initiated_by
FROM batch_jobs WHERE id = ?`

	row := s.db.QueryRow(q, id)
	job, err := scanJob(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrBatchJobNotFound
		}
		return nil, fmt.Errorf("batch job store get: %w", err)
	}

	steps, err := s.loadSteps(id)
	if err != nil {
		return nil, err
	}
	job.Steps = steps
	return job, nil
}

// ListBatchJobsByTenant returns all batch jobs belonging to tenantID including steps.
func (s *SQLiteBatchJobStore) ListBatchJobsByTenant(_ context.Context, tenantID string) ([]*BatchJob, error) {
	const q = `
SELECT id, tenant_id, selector, config_json, targets_json, status,
       created_at, updated_at, initiated_by
FROM batch_jobs WHERE tenant_id = ?
ORDER BY created_at ASC`

	rows, err := s.db.Query(q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("batch job store list: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var jobs []*BatchJob
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("batch job store list scan: %w", err)
		}
		steps, err := s.loadSteps(job.ID)
		if err != nil {
			return nil, err
		}
		job.Steps = steps
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("batch job store list rows: %w", err)
	}
	if jobs == nil {
		jobs = []*BatchJob{}
	}
	return jobs, nil
}

// ListBatchJobs returns batch jobs ordered by created_at DESC with pagination.
// When tenantID is non-empty only jobs belonging to that tenant are returned.
// An empty tenantID returns all jobs across tenants (global-scope admin callers).
func (s *SQLiteBatchJobStore) ListBatchJobs(_ context.Context, tenantID string, limit, offset int) ([]*BatchJob, error) {
	const selectCols = `
SELECT id, tenant_id, selector, config_json, targets_json, status,
       created_at, updated_at, initiated_by
FROM batch_jobs`

	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" {
		rows, err = s.db.Query(selectCols+`
WHERE tenant_id = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?`, tenantID, limit, offset)
	} else {
		rows, err = s.db.Query(selectCols+`
ORDER BY created_at DESC
LIMIT ? OFFSET ?`, limit, offset)
	}
	if err != nil {
		return nil, fmt.Errorf("batch job store list: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var jobs []*BatchJob
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("batch job store list scan: %w", err)
		}
		steps, err := s.loadSteps(job.ID)
		if err != nil {
			return nil, err
		}
		job.Steps = steps
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("batch job store list rows: %w", err)
	}
	if jobs == nil {
		jobs = []*BatchJob{}
	}
	return jobs, nil
}

// HealthCheck verifies the store is reachable.
func (s *SQLiteBatchJobStore) HealthCheck(_ context.Context) error {
	if err := s.db.Ping(); err != nil {
		return fmt.Errorf("batch job store health check: %w", err)
	}
	return nil
}

// Close releases the underlying database connection.
func (s *SQLiteBatchJobStore) Close() error {
	return s.db.Close()
}

var _ BatchJobStore = (*SQLiteBatchJobStore)(nil)

// --- helpers ---

// scanner is the common interface for sql.Row and sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanJob(s scanner) (*BatchJob, error) {
	var (
		configJSON  string
		targetsJSON string
		initiatedBy sql.NullString
		createdAt   time.Time
		updatedAt   time.Time
	)
	job := &BatchJob{}
	err := s.Scan(
		&job.ID, &job.TenantID, &job.Selector,
		&configJSON, &targetsJSON,
		(*string)(&job.Status),
		&createdAt, &updatedAt,
		&initiatedBy,
	)
	if err != nil {
		return nil, err
	}
	job.CreatedAt = createdAt.UTC()
	job.UpdatedAt = updatedAt.UTC()
	job.InitiatedBy = initiatedBy.String

	if err := json.Unmarshal([]byte(configJSON), &job.Config); err != nil {
		return nil, fmt.Errorf("scan job: unmarshal config: %w", err)
	}
	if targetsJSON != "" {
		if err := json.Unmarshal([]byte(targetsJSON), &job.Targets); err != nil {
			return nil, fmt.Errorf("scan job: unmarshal targets: %w", err)
		}
	}
	if job.Targets == nil {
		job.Targets = []string{}
	}
	return job, nil
}

func (s *SQLiteBatchJobStore) loadSteps(jobID string) ([]BatchStep, error) {
	const q = `
SELECT step_index, status, steward_ids_json, started_at, completed_at, failed_ids_json, rollback_job_id
FROM batch_steps WHERE job_id = ?
ORDER BY step_index ASC`

	rows, err := s.db.Query(q, jobID)
	if err != nil {
		return nil, fmt.Errorf("batch job store load steps: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var steps []BatchStep
	for rows.Next() {
		var (
			stewardIDsJSON string
			failedIDsJSON  string
			rollbackJobID  string
			startedAt      sql.NullTime
			completedAt    sql.NullTime
		)
		step := BatchStep{}
		if err := rows.Scan(
			&step.Index,
			(*string)(&step.Status),
			&stewardIDsJSON,
			&startedAt, &completedAt,
			&failedIDsJSON, &rollbackJobID,
		); err != nil {
			return nil, fmt.Errorf("batch job store scan step: %w", err)
		}
		if stewardIDsJSON != "" {
			if err := json.Unmarshal([]byte(stewardIDsJSON), &step.StewardIDs); err != nil {
				return nil, fmt.Errorf("batch job store scan step steward_ids: %w", err)
			}
		}
		if failedIDsJSON != "" {
			if err := json.Unmarshal([]byte(failedIDsJSON), &step.FailedIDs); err != nil {
				return nil, fmt.Errorf("batch job store scan step failed_ids: %w", err)
			}
		}
		step.RollbackJobID = rollbackJobID
		if startedAt.Valid {
			t := startedAt.Time.UTC()
			step.StartedAt = &t
		}
		if completedAt.Valid {
			t := completedAt.Time.UTC()
			step.CompletedAt = &t
		}
		if step.StewardIDs == nil {
			step.StewardIDs = []string{}
		}
		if step.FailedIDs == nil {
			step.FailedIDs = []string{}
		}
		steps = append(steps, step)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("batch job store steps rows: %w", err)
	}
	return steps, nil
}

// txer is the common interface for sql.DB and sql.Tx for Exec.
type txer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func insertStep(tx txer, jobID string, step BatchStep) error {
	stewardIDs := step.StewardIDs
	if stewardIDs == nil {
		stewardIDs = []string{}
	}
	failedIDs := step.FailedIDs
	if failedIDs == nil {
		failedIDs = []string{}
	}
	stewardIDsJSON, err := json.Marshal(stewardIDs)
	if err != nil {
		return fmt.Errorf("batch job store insert step: marshal steward_ids: %w", err)
	}
	failedIDsJSON, err := json.Marshal(failedIDs)
	if err != nil {
		return fmt.Errorf("batch job store insert step: marshal failed_ids: %w", err)
	}

	var startedAt, completedAt interface{}
	if step.StartedAt != nil {
		startedAt = step.StartedAt.UTC()
	}
	if step.CompletedAt != nil {
		completedAt = step.CompletedAt.UTC()
	}

	const q = `
INSERT INTO batch_steps
    (job_id, step_index, status, steward_ids_json, started_at, completed_at, failed_ids_json, rollback_job_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = tx.Exec(q,
		jobID, step.Index, string(step.Status),
		string(stewardIDsJSON),
		startedAt, completedAt,
		string(failedIDsJSON),
		step.RollbackJobID,
	)
	if err != nil {
		return fmt.Errorf("batch job store insert step: %w", err)
	}
	return nil
}

func requireOneRow(res sql.Result, op, id string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("batch job store %s %q: rows affected: %w", op, id, err)
	}
	if n == 0 {
		return ErrBatchJobNotFound
	}
	return nil
}

func nullableStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
