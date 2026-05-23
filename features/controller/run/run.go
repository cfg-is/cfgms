// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package run

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet"
	scriptmodule "github.com/cfgis/cfgms/features/modules/script"
	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a run or job record does not exist.
var ErrNotFound = errors.New("run not found")

// ErrAlreadyTerminal is returned when an operation targets a run that has already reached a terminal state.
var ErrAlreadyTerminal = errors.New("run is already in a terminal state")

// ErrGrantNotFound is returned when no active grant exists for (deviceID, executionID).
var ErrGrantNotFound = errors.New("execution grant not found or expired")

// ErrGrantConsumed is returned when the grant has already been consumed.
var ErrGrantConsumed = errors.New("execution grant already consumed")

// RunStatus represents the lifecycle state of a run.
type RunStatus string

const (
	RunStatusPending   RunStatus = "pending"
	RunStatusRunning   RunStatus = "running"
	RunStatusCompleted RunStatus = "completed"
	RunStatusFailed    RunStatus = "failed"
	RunStatusCancelled RunStatus = "cancelled"
)

// IsTerminal reports whether the status is a terminal (non-progressing) state.
func (s RunStatus) IsTerminal() bool {
	return s == RunStatusCompleted || s == RunStatusFailed || s == RunStatusCancelled
}

// JobStatus represents the lifecycle state of a single job within a run.
type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusRunning   JobStatus = "running"
	JobStatusCompleted JobStatus = "completed"
	JobStatusFailed    JobStatus = "failed"
	JobStatusCancelled JobStatus = "cancelled"
)

// IsTerminal reports whether the job status is a terminal state.
func (s JobStatus) IsTerminal() bool {
	return s == JobStatusCompleted || s == JobStatusFailed || s == JobStatusCancelled
}

// RunRecord is the durable tracking record for a multi-steward script dispatch.
// One RunRecord fans out to one JobRecord per matched steward.
type RunRecord struct {
	RunID         string                 `json:"run_id"`
	TenantID      string                 `json:"tenant_id"`
	CreatedBy     string                 `json:"created_by,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	Status        RunStatus              `json:"status"`
	Filter        fleet.Filter           `json:"filter,omitempty"`
	ScriptRef     string                 `json:"script_ref,omitempty"`
	InlineContent string                 `json:"inline_content,omitempty"`
	Shell         scriptmodule.ShellType `json:"shell,omitempty"`
	JobCount      int                    `json:"job_count"`
	CompletedJobs int                    `json:"completed_jobs"`
	FailedJobs    int                    `json:"failed_jobs"`
}

// JobRecord tracks the dispatch state for one steward within a run.
type JobRecord struct {
	JobID       string     `json:"job_id"`
	RunID       string     `json:"run_id"`
	DeviceID    string     `json:"device_id"`
	ExecutionID string     `json:"execution_id,omitempty"`
	Status      JobStatus  `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// ExecutionGrant records a per-execution API access grant created at dispatch time.
// Grants are consumed when the execution completes and expire after their TTL.
type ExecutionGrant struct {
	DeviceID    string
	TenantID    string
	ExecutionID string
	Scope       []string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Consumed    bool
}

// RunStore is the durable storage interface for run and job records.
type RunStore interface {
	CreateRun(*RunRecord) error
	CreateJob(*JobRecord) error
	GetRun(runID string) (*RunRecord, error)
	ListRunJobs(runID string) ([]*JobRecord, error)
	UpdateJobStatus(jobID string, status JobStatus, executionID string) error
	UpdateRunStatus(runID string, status RunStatus) error
	UpdateRunCounts(runID string, completedJobs, failedJobs int) error

	// Grant management for zero-trust script API access (Issue #1675).

	// CreateExecutionGrant records a JIT grant keyed on (deviceID, executionID).
	// tenantID is stored with the grant so the relay handler can construct a scoped Principal.
	// The grant expires after ttl elapses and is also invalidated by ConsumeGrant.
	CreateExecutionGrant(deviceID, tenantID, executionID string, scope []string, ttl time.Duration) error

	// LookupGrant returns the grant for (deviceID, executionID).
	// Returns ErrGrantNotFound when no grant exists or it is expired.
	// Returns ErrGrantConsumed when the grant has been consumed.
	LookupGrant(deviceID, executionID string) (*ExecutionGrant, error)

	// ConsumeGrant marks the grant for executionID as consumed so further relay
	// requests return ErrGrantConsumed. Called when AcknowledgeCompletion fires.
	ConsumeGrant(executionID string) error
}

// RunStoreSQL is the SQLite-backed implementation of RunStore.
// Call Init before any other method — it creates tables and indexes idempotently.
type RunStoreSQL struct {
	db *sql.DB
}

// NewRunStoreSQL creates a RunStoreSQL that uses db for persistence.
// The caller must call Init before any other method.
func NewRunStoreSQL(db *sql.DB) *RunStoreSQL {
	return &RunStoreSQL{db: db}
}

// NewRunStoreSQLFromDSN opens a SQLite database at dsn and returns a RunStoreSQL
// backed by it. The caller must call Init before any other method, and Close when
// done to release the underlying connection. Use this constructor instead of
// calling sql.Open directly in callers outside pkg/storage.
func NewRunStoreSQLFromDSN(dsn string) (*RunStoreSQL, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("run store: open sqlite %s: %w", dsn, err)
	}
	// busy_timeout prevents SQLITE_BUSY errors when the main connection is writing.
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("run store: set busy_timeout: %w", err)
	}
	return &RunStoreSQL{db: db}, nil
}

// Init creates the script_runs, script_run_jobs, and execution_grants tables and
// their indexes if they do not already exist. Safe to call multiple times (idempotent).
func (s *RunStoreSQL) Init(_ context.Context) error {
	const createRuns = `
CREATE TABLE IF NOT EXISTS script_runs (
    run_id         TEXT NOT NULL PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    created_by     TEXT,
    created_at     DATETIME NOT NULL,
    status         TEXT NOT NULL,
    filter_json    TEXT,
    script_ref     TEXT,
    inline_content TEXT,
    shell          TEXT,
    job_count      INTEGER DEFAULT 0,
    completed_jobs INTEGER DEFAULT 0,
    failed_jobs    INTEGER DEFAULT 0
);`
	const createJobs = `
CREATE TABLE IF NOT EXISTS script_run_jobs (
    job_id        TEXT NOT NULL PRIMARY KEY,
    run_id        TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    execution_id  TEXT,
    status        TEXT NOT NULL,
    created_at    DATETIME NOT NULL,
    completed_at  DATETIME
);`
	const createJobsIndex = `
CREATE INDEX IF NOT EXISTS idx_srj_run_id ON script_run_jobs(run_id);`

	const createGrants = `
CREATE TABLE IF NOT EXISTS execution_grants (
    execution_id TEXT NOT NULL PRIMARY KEY,
    device_id    TEXT NOT NULL,
    tenant_id    TEXT NOT NULL,
    scope_json   TEXT NOT NULL,
    created_at   DATETIME NOT NULL,
    expires_at   DATETIME NOT NULL,
    consumed     INTEGER NOT NULL DEFAULT 0
);`
	const createGrantsIndex = `
CREATE INDEX IF NOT EXISTS idx_eg_device ON execution_grants(device_id, execution_id);`

	for _, stmt := range []string{createRuns, createJobs, createJobsIndex, createGrants, createGrantsIndex} {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("run store init: %w", err)
		}
	}
	return nil
}

// CreateRun persists a new run record. RunID must be unique.
func (s *RunStoreSQL) CreateRun(r *RunRecord) error {
	filterJSON, err := json.Marshal(r.Filter)
	if err != nil {
		return fmt.Errorf("run store create run: marshal filter: %w", err)
	}
	const q = `
INSERT INTO script_runs
    (run_id, tenant_id, created_by, created_at, status, filter_json,
     script_ref, inline_content, shell, job_count, completed_jobs, failed_jobs)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = s.db.Exec(q,
		r.RunID, r.TenantID,
		nullableStr(r.CreatedBy),
		r.CreatedAt, string(r.Status), string(filterJSON),
		nullableStr(r.ScriptRef),
		nullableStr(r.InlineContent),
		nullableStr(string(r.Shell)),
		r.JobCount, r.CompletedJobs, r.FailedJobs,
	)
	return err
}

// CreateJob persists a new job record.
func (s *RunStoreSQL) CreateJob(j *JobRecord) error {
	const q = `
INSERT INTO script_run_jobs
    (job_id, run_id, device_id, execution_id, status, created_at, completed_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`
	var completedAt interface{}
	if j.CompletedAt != nil {
		completedAt = *j.CompletedAt
	}
	_, err := s.db.Exec(q,
		j.JobID, j.RunID, j.DeviceID,
		nullableStr(j.ExecutionID),
		string(j.Status), j.CreatedAt, completedAt,
	)
	return err
}

// GetRun returns the run record for runID, or ErrNotFound if not found.
func (s *RunStoreSQL) GetRun(runID string) (*RunRecord, error) {
	const q = `
SELECT run_id, tenant_id, created_by, created_at, status, filter_json,
       script_ref, inline_content, shell, job_count, completed_jobs, failed_jobs
FROM script_runs
WHERE run_id = ?`

	row := s.db.QueryRow(q, runID)
	r := &RunRecord{}
	var (
		createdBy     sql.NullString
		filterJSON    sql.NullString
		scriptRef     sql.NullString
		inlineContent sql.NullString
		shell         sql.NullString
	)
	err := row.Scan(
		&r.RunID, &r.TenantID, &createdBy, &r.CreatedAt,
		(*string)(&r.Status), &filterJSON,
		&scriptRef, &inlineContent, &shell,
		&r.JobCount, &r.CompletedJobs, &r.FailedJobs,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("run store get run: %w", err)
	}
	r.CreatedBy = createdBy.String
	r.ScriptRef = scriptRef.String
	r.InlineContent = inlineContent.String
	r.Shell = scriptmodule.ShellType(shell.String)
	if filterJSON.Valid && filterJSON.String != "" {
		_ = json.Unmarshal([]byte(filterJSON.String), &r.Filter)
	}
	return r, nil
}

// ListRunJobs returns all job records for runID ordered by created_at ASC.
func (s *RunStoreSQL) ListRunJobs(runID string) ([]*JobRecord, error) {
	const q = `
SELECT job_id, run_id, device_id, execution_id, status, created_at, completed_at
FROM script_run_jobs
WHERE run_id = ?
ORDER BY created_at ASC`

	rows, err := s.db.Query(q, runID)
	if err != nil {
		return nil, fmt.Errorf("run store list jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var jobs []*JobRecord
	for rows.Next() {
		j := &JobRecord{}
		var executionID sql.NullString
		var completedAt sql.NullTime
		if err := rows.Scan(
			&j.JobID, &j.RunID, &j.DeviceID, &executionID,
			(*string)(&j.Status), &j.CreatedAt, &completedAt,
		); err != nil {
			return nil, fmt.Errorf("run store scan job: %w", err)
		}
		j.ExecutionID = executionID.String
		if completedAt.Valid {
			t := completedAt.Time
			j.CompletedAt = &t
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("run store list jobs rows: %w", err)
	}
	return jobs, nil
}

// UpdateJobStatus sets the status and optionally the executionID for a job.
// When status is terminal, completed_at is set to the current UTC time.
func (s *RunStoreSQL) UpdateJobStatus(jobID string, status JobStatus, executionID string) error {
	var completedAt interface{}
	if status.IsTerminal() {
		completedAt = time.Now().UTC()
	}
	// Update execution_id only when a non-empty value is supplied.
	const q = `
UPDATE script_run_jobs
SET status       = ?,
    execution_id = CASE WHEN ? != '' THEN ? ELSE execution_id END,
    completed_at = COALESCE(?, completed_at)
WHERE job_id = ?`
	_, err := s.db.Exec(q, string(status), executionID, executionID, completedAt, jobID)
	return err
}

// UpdateRunStatus updates the top-level status for a run.
func (s *RunStoreSQL) UpdateRunStatus(runID string, status RunStatus) error {
	const q = `UPDATE script_runs SET status = ? WHERE run_id = ?`
	_, err := s.db.Exec(q, string(status), runID)
	return err
}

// UpdateRunCounts updates the completed and failed job counts for a run.
func (s *RunStoreSQL) UpdateRunCounts(runID string, completedJobs, failedJobs int) error {
	const q = `UPDATE script_runs SET completed_jobs = ?, failed_jobs = ? WHERE run_id = ?`
	_, err := s.db.Exec(q, completedJobs, failedJobs, runID)
	return err
}

// CreateExecutionGrant stores a JIT relay grant keyed on (deviceID, executionID).
func (s *RunStoreSQL) CreateExecutionGrant(deviceID, tenantID, executionID string, scope []string, ttl time.Duration) error {
	scopeJSON, err := json.Marshal(scope)
	if err != nil {
		return fmt.Errorf("run store create grant: marshal scope: %w", err)
	}
	now := time.Now().UTC()
	const q = `
INSERT INTO execution_grants (execution_id, device_id, tenant_id, scope_json, created_at, expires_at, consumed)
VALUES (?, ?, ?, ?, ?, ?, 0)`
	_, err = s.db.Exec(q, executionID, deviceID, tenantID, string(scopeJSON), now, now.Add(ttl))
	return err
}

// LookupGrant returns the grant for (deviceID, executionID).
// Returns ErrGrantNotFound when no matching unexpired grant exists.
// Returns ErrGrantConsumed when the grant has been consumed.
func (s *RunStoreSQL) LookupGrant(deviceID, executionID string) (*ExecutionGrant, error) {
	const q = `
SELECT device_id, tenant_id, execution_id, scope_json, created_at, expires_at, consumed
FROM execution_grants
WHERE execution_id = ? AND device_id = ?`

	row := s.db.QueryRow(q, executionID, deviceID)
	g := &ExecutionGrant{}
	var scopeJSON string
	var consumed int
	err := row.Scan(&g.DeviceID, &g.TenantID, &g.ExecutionID, &scopeJSON, &g.CreatedAt, &g.ExpiresAt, &consumed)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrGrantNotFound
		}
		return nil, fmt.Errorf("run store lookup grant: %w", err)
	}
	if consumed != 0 {
		return nil, ErrGrantConsumed
	}
	if time.Now().After(g.ExpiresAt) {
		return nil, ErrGrantNotFound
	}
	if err := json.Unmarshal([]byte(scopeJSON), &g.Scope); err != nil {
		return nil, fmt.Errorf("run store lookup grant: unmarshal scope: %w", err)
	}
	g.Consumed = consumed != 0
	return g, nil
}

// ConsumeGrant marks the grant for executionID as consumed.
func (s *RunStoreSQL) ConsumeGrant(executionID string) error {
	const q = `UPDATE execution_grants SET consumed = 1 WHERE execution_id = ?`
	_, err := s.db.Exec(q, executionID)
	return err
}

// Close releases the underlying database connection. After Close, the store
// must not be used. Safe to call on a store backed by a shared *sql.DB only
// when that connection is dedicated to the run store.
func (s *RunStoreSQL) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func nullableStr(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// Manager coordinates the lifecycle of run records: retrieval and cancellation.
// Run creation is performed by the synthesis functions in synthesis.go.
type Manager struct {
	store          RunStore
	executionQueue *scriptmodule.ExecutionQueue
}

// NewManager creates a Manager backed by store and executionQueue.
// executionQueue may be nil; CancelRun will then skip queue-level cancellation.
func NewManager(store RunStore, executionQueue *scriptmodule.ExecutionQueue) *Manager {
	return &Manager{store: store, executionQueue: executionQueue}
}

// GetRun returns the run record for runID.
// Returns ErrNotFound when no run exists with that ID.
func (m *Manager) GetRun(_ context.Context, runID string) (*RunRecord, error) {
	return m.store.GetRun(runID)
}

// ListRunJobs returns all job records for the given run.
// Returns ErrNotFound when the run does not exist.
func (m *Manager) ListRunJobs(_ context.Context, runID string) ([]*JobRecord, error) {
	if _, err := m.store.GetRun(runID); err != nil {
		return nil, err
	}
	return m.store.ListRunJobs(runID)
}

// CancelRun transitions a non-terminal run and all its non-terminal jobs to
// cancelled. It also calls CancelExecution on the queue for each job that has
// a non-empty ExecutionID.
//
// Returns ErrNotFound if the run does not exist.
// Returns ErrAlreadyTerminal if the run is already completed, failed, or cancelled.
func (m *Manager) CancelRun(_ context.Context, runID string) error {
	run, err := m.store.GetRun(runID)
	if err != nil {
		return err
	}
	if run.Status.IsTerminal() {
		return ErrAlreadyTerminal
	}

	jobs, err := m.store.ListRunJobs(runID)
	if err != nil {
		return fmt.Errorf("cancel run: list jobs: %w", err)
	}

	for _, job := range jobs {
		if job.Status.IsTerminal() {
			continue
		}
		if m.executionQueue != nil && job.ExecutionID != "" {
			_ = m.executionQueue.CancelExecution(job.DeviceID, job.ExecutionID)
		}
		if updateErr := m.store.UpdateJobStatus(job.JobID, JobStatusCancelled, ""); updateErr != nil {
			return fmt.Errorf("cancel run: update job %s: %w", job.JobID, updateErr)
		}
	}

	return m.store.UpdateRunStatus(runID, RunStatusCancelled)
}

// RecordJobCompletion records a terminal state for one job and advances the
// run's status when every job has finished. It is invoked by the dispatcher
// when a steward reports an execution complete (Issue #1673, AC3).
//
// The job is moved to completed or failed. Job states are then aggregated: once
// every job in the run is terminal the run transitions to completed, or to
// failed if any job failed. A run that is already terminal (e.g. cancelled) is
// left untouched so a late completion callback cannot resurrect it.
func (m *Manager) RecordJobCompletion(_ context.Context, runID, jobID, executionID string, failed bool) error {
	jobStatus := JobStatusCompleted
	if failed {
		jobStatus = JobStatusFailed
	}
	if err := m.store.UpdateJobStatus(jobID, jobStatus, executionID); err != nil {
		return fmt.Errorf("record job completion: update job %s: %w", jobID, err)
	}

	jobs, err := m.store.ListRunJobs(runID)
	if err != nil {
		return fmt.Errorf("record job completion: list jobs for run %s: %w", runID, err)
	}

	completed, failedCount := 0, 0
	allTerminal := true
	for _, j := range jobs {
		switch j.Status {
		case JobStatusCompleted:
			completed++
		case JobStatusFailed:
			failedCount++
		case JobStatusCancelled:
			// Terminal, but counts toward neither completed nor failed.
		default:
			allTerminal = false
		}
	}

	if err := m.store.UpdateRunCounts(runID, completed, failedCount); err != nil {
		return fmt.Errorf("record job completion: update counts for run %s: %w", runID, err)
	}

	if !allTerminal {
		return nil
	}

	run, err := m.store.GetRun(runID)
	if err != nil {
		return fmt.Errorf("record job completion: get run %s: %w", runID, err)
	}
	if run.Status.IsTerminal() {
		return nil
	}

	finalStatus := RunStatusCompleted
	if failedCount > 0 {
		finalStatus = RunStatusFailed
	}
	if err := m.store.UpdateRunStatus(runID, finalStatus); err != nil {
		return fmt.Errorf("record job completion: update run status for run %s: %w", runID, err)
	}
	return nil
}

// CreateGrant creates a JIT relay grant. Called by the dispatcher at dispatch time.
func (m *Manager) CreateGrant(deviceID, tenantID, executionID string, scope []string, ttl time.Duration) error {
	return m.store.CreateExecutionGrant(deviceID, tenantID, executionID, scope, ttl)
}

// LookupGrant validates and returns the grant for (deviceID, executionID).
// Used by the relay handler to construct the scoped Principal.
func (m *Manager) LookupGrant(deviceID, executionID string) (*ExecutionGrant, error) {
	return m.store.LookupGrant(deviceID, executionID)
}

// ConsumeGrant marks the grant consumed. Called by the dispatcher on AcknowledgeCompletion.
func (m *Manager) ConsumeGrant(executionID string) error {
	return m.store.ConsumeGrant(executionID)
}

// Close releases resources held by the Manager's store. If the store does not
// own a closable resource, Close is a no-op.
func (m *Manager) Close() error {
	if closer, ok := m.store.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
