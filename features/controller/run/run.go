// SPDX-License-Identifier: AGPL-3.0-only
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
	scriptmodule "github.com/cfgis/cfgms/features/modules/stdlib/script"
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

	// Steward-action job statuses (Issue #4625). Dispatched means the action was
	// sent to the steward and no result has come back. Expired means it was never
	// delivered before its TTL ("expired, not run"). NoResult means it was sent
	// but never reported ("sent, no result reported": the action may have run).
	JobStatusDispatched JobStatus = "dispatched"
	JobStatusExpired    JobStatus = "expired"
	JobStatusNoResult   JobStatus = "no_result"
)

// IsTerminal reports whether the job status is a terminal state.
func (s JobStatus) IsTerminal() bool {
	switch s {
	case JobStatusCompleted, JobStatusFailed, JobStatusCancelled, JobStatusExpired, JobStatusNoResult:
		return true
	}
	return false
}

// Run kinds. An empty Kind is a script run.
const (
	RunKindScript        = "script"
	RunKindStewardAction = "steward_action"
)

// Steward-action result codes recorded on JobRecord.ResultCode. The first five
// are reported by the steward; the last two are recorded by the controller.
const (
	ResultCodeOK             = "ok"
	ResultCodeSelfProtect    = "self_protect"
	ResultCodeProcessChanged = "process_changed"
	ResultCodeUnsupported    = "unsupported"
	ResultCodeFailed         = "failed"
	ResultCodeExpired        = "expired"
	ResultCodeNoResult       = "no_result"
)

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

	// Kind is RunKindScript (or empty) for script runs and RunKindStewardAction
	// for a structured steward action (Issue #4625). ActionJSON holds
	// {verb, target_kind, target_name, parameters} for an action run.
	Kind       string `json:"kind,omitempty"`
	ActionJSON []byte `json:"-"`
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

	// Captured execution result, persisted when the dispatcher records a terminal
	// completion (Issue #1995, root cause D). Output is stdout; the CLI surfaces
	// Output and ExitCode for `cfg steward exec`.
	Output   string `json:"output,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`

	// ResultCode is the steward-action outcome (Issue #4625); empty for scripts.
	// DispatchedAt is when an action job was handed to its steward.
	ResultCode   string     `json:"result_code,omitempty"`
	DispatchedAt *time.Time `json:"dispatched_at,omitempty"`
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
	// ListRuns returns runs ordered by created_at DESC with pagination. When tenantID is
	// non-empty only runs belonging to that tenant are returned. An empty tenantID returns
	// all runs across tenants (for use by global-scope admin callers).
	ListRuns(tenantID string, limit, offset int) ([]*RunRecord, error)
	ListRunJobs(runID string) ([]*JobRecord, error)
	UpdateJobStatus(jobID string, status JobStatus, executionID string) error
	// UpdateJobResult sets the terminal status, executionID, and captured execution
	// result (stdout/stderr/exit code) for a job (Issue #1995, root cause D).
	UpdateJobResult(jobID string, status JobStatus, executionID, output, stderr string, exitCode int) error
	UpdateRunStatus(runID string, status RunStatus) error
	UpdateRunCounts(runID string, completedJobs, failedJobs int) error

	// Steward-action jobs (Issue #4625).

	// UpdateJobResultCode records a steward-action result code on a job.
	UpdateJobResultCode(jobID, code string) error
	// MarkJobDispatched is a compare-and-set from pending to dispatched that
	// stamps DispatchedAt; it reports whether the job changed.
	MarkJobDispatched(jobID string, at time.Time) (changed bool, err error)
	// ListStaleActionJobs returns steward-action jobs with no result that are
	// still pending and were created before pendingBefore, or dispatched before
	// dispatchedBefore, across all runs and tenants.
	ListStaleActionJobs(pendingBefore, dispatchedBefore time.Time) ([]*JobRecord, error)
	// ExpireJobIfStatus is a compare-and-set: it moves the job to the terminal
	// status resultCode (recording resultCode as its result code) only when its
	// current status equals fromStatus, and reports whether the job changed.
	ExpireJobIfStatus(jobID string, fromStatus JobStatus, resultCode string, at time.Time) (changed bool, err error)

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
    failed_jobs    INTEGER DEFAULT 0,
    kind           TEXT NOT NULL DEFAULT 'script',
    action_json    TEXT
);`
	const createJobs = `
CREATE TABLE IF NOT EXISTS script_run_jobs (
    job_id        TEXT NOT NULL PRIMARY KEY,
    run_id        TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    execution_id  TEXT,
    status        TEXT NOT NULL,
    created_at    DATETIME NOT NULL,
    completed_at  DATETIME,
    output        TEXT,
    stderr        TEXT,
    exit_code     INTEGER,
    result_code   TEXT,
    dispatched_at DATETIME
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

	// Idempotent column migration for databases created before the output-capture
	// columns existed (Issue #1995, root cause D). CREATE TABLE IF NOT EXISTS does
	// not add columns to a pre-existing table. Detect which columns are already
	// present via PRAGMA table_info and ADD only the missing ones — no reliance on
	// driver-specific error-string matching, and no spurious error on fresh DBs.
	if err := s.migrateJobColumns(); err != nil {
		return fmt.Errorf("run store init: migrate jobs columns: %w", err)
	}
	if err := s.migrateRunColumns(); err != nil {
		return fmt.Errorf("run store init: migrate runs columns: %w", err)
	}
	return nil
}

// migrateJobColumns adds the columns script_run_jobs gained after its first
// release when they are missing: output/stderr/exit_code (Issue #1995) and the
// steward-action result_code/dispatched_at (Issue #4625).
func (s *RunStoreSQL) migrateJobColumns() error {
	return s.addMissingColumns("script_run_jobs", []columnDDL{
		{"output", "ALTER TABLE script_run_jobs ADD COLUMN output TEXT"},
		{"stderr", "ALTER TABLE script_run_jobs ADD COLUMN stderr TEXT"},
		{"exit_code", "ALTER TABLE script_run_jobs ADD COLUMN exit_code INTEGER"},
		{"result_code", "ALTER TABLE script_run_jobs ADD COLUMN result_code TEXT"},
		{"dispatched_at", "ALTER TABLE script_run_jobs ADD COLUMN dispatched_at DATETIME"},
	})
}

// migrateRunColumns adds the steward-action kind/action_json columns to
// script_runs when they are missing (Issue #4625). Existing rows take the
// 'script' default, so runs created before steward actions read back as script.
func (s *RunStoreSQL) migrateRunColumns() error {
	return s.addMissingColumns("script_runs", []columnDDL{
		{"kind", "ALTER TABLE script_runs ADD COLUMN kind TEXT NOT NULL DEFAULT 'script'"},
		{"action_json", "ALTER TABLE script_runs ADD COLUMN action_json TEXT"},
	})
}

type columnDDL struct {
	name string
	ddl  string
}

// addMissingColumns inspects the live schema via PRAGMA table_info so it is
// idempotent across repeated calls and across sqlite driver versions.
func (s *RunStoreSQL) addMissingColumns(table string, wanted []columnDDL) error {
	existing, err := s.tableColumns(table)
	if err != nil {
		return err
	}
	for _, c := range wanted {
		if existing[c.name] {
			continue
		}
		if _, err := s.db.Exec(c.ddl); err != nil {
			return fmt.Errorf("add column %s.%s: %w", table, c.name, err)
		}
	}
	return nil
}

// jobColumns returns the set of column names currently defined on script_run_jobs.
func (s *RunStoreSQL) jobColumns() (map[string]bool, error) {
	return s.tableColumns("script_run_jobs")
}

// tableColumns returns the set of column names currently defined on table. The
// table name is a package constant, never caller input.
func (s *RunStoreSQL) tableColumns(table string) (map[string]bool, error) {
	if table != "script_runs" && table != "script_run_jobs" {
		return nil, fmt.Errorf("inspect schema: unexpected table %q", table)
	}
	rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return nil, fmt.Errorf("inspect schema: %w", err)
	}
	defer func() { _ = rows.Close() }()

	cols := make(map[string]bool)
	for rows.Next() {
		// PRAGMA table_info columns: cid, name, type, notnull, dflt_value, pk.
		var (
			cid       int
			name      string
			ctype     string
			notnull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return nil, fmt.Errorf("scan schema row: %w", err)
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read schema rows: %w", err)
	}
	return cols, nil
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
     script_ref, inline_content, shell, job_count, completed_jobs, failed_jobs, kind, action_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	kind := r.Kind
	if kind == "" {
		kind = RunKindScript
	}
	_, err = s.db.Exec(q,
		r.RunID, r.TenantID,
		nullableStr(r.CreatedBy),
		r.CreatedAt, string(r.Status), string(filterJSON),
		nullableStr(r.ScriptRef),
		nullableStr(r.InlineContent),
		nullableStr(string(r.Shell)),
		r.JobCount, r.CompletedJobs, r.FailedJobs,
		kind, nullableStr(string(r.ActionJSON)),
	)
	return err
}

// CreateJob persists a new job record.
func (s *RunStoreSQL) CreateJob(j *JobRecord) error {
	const q = `
INSERT INTO script_run_jobs
    (job_id, run_id, device_id, execution_id, status, created_at, completed_at, output, stderr, exit_code,
     result_code, dispatched_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	var completedAt, dispatchedAt interface{}
	if j.CompletedAt != nil {
		completedAt = *j.CompletedAt
	}
	if j.DispatchedAt != nil {
		dispatchedAt = *j.DispatchedAt
	}
	_, err := s.db.Exec(q,
		j.JobID, j.RunID, j.DeviceID,
		nullableStr(j.ExecutionID),
		string(j.Status), j.CreatedAt, completedAt,
		nullableStr(j.Output), nullableStr(j.Stderr), j.ExitCode,
		nullableStr(j.ResultCode), dispatchedAt,
	)
	return err
}

const runSelectCols = `
SELECT run_id, tenant_id, created_by, created_at, status, filter_json,
       script_ref, inline_content, shell, job_count, completed_jobs, failed_jobs,
       kind, action_json
FROM script_runs`

// rowScanner is satisfied by *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanRun(row rowScanner) (*RunRecord, error) {
	r := &RunRecord{}
	var (
		createdBy     sql.NullString
		filterJSON    sql.NullString
		scriptRef     sql.NullString
		inlineContent sql.NullString
		shell         sql.NullString
		kind          sql.NullString
		actionJSON    sql.NullString
	)
	if err := row.Scan(
		&r.RunID, &r.TenantID, &createdBy, &r.CreatedAt,
		(*string)(&r.Status), &filterJSON,
		&scriptRef, &inlineContent, &shell,
		&r.JobCount, &r.CompletedJobs, &r.FailedJobs,
		&kind, &actionJSON,
	); err != nil {
		return nil, err
	}
	r.CreatedBy = createdBy.String
	r.ScriptRef = scriptRef.String
	r.InlineContent = inlineContent.String
	r.Shell = scriptmodule.ShellType(shell.String)
	r.Kind = kind.String
	if r.Kind == "" {
		r.Kind = RunKindScript
	}
	if actionJSON.Valid && actionJSON.String != "" {
		r.ActionJSON = []byte(actionJSON.String)
	}
	if filterJSON.Valid && filterJSON.String != "" {
		_ = json.Unmarshal([]byte(filterJSON.String), &r.Filter)
	}
	return r, nil
}

// GetRun returns the run record for runID, or ErrNotFound if not found.
func (s *RunStoreSQL) GetRun(runID string) (*RunRecord, error) {
	r, err := scanRun(s.db.QueryRow(runSelectCols+`
WHERE run_id = ?`, runID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("run store get run: %w", err)
	}
	return r, nil
}

// ListRuns returns run records ordered by created_at DESC with pagination.
// When tenantID is non-empty only runs belonging to that tenant are returned.
// An empty tenantID returns all runs (for global-scope admin callers).
func (s *RunStoreSQL) ListRuns(tenantID string, limit, offset int) ([]*RunRecord, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if tenantID != "" {
		rows, err = s.db.Query(runSelectCols+`
WHERE tenant_id = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?`, tenantID, limit, offset)
	} else {
		rows, err = s.db.Query(runSelectCols+`
ORDER BY created_at DESC
LIMIT ? OFFSET ?`, limit, offset)
	}
	if err != nil {
		return nil, fmt.Errorf("run store list runs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var runs []*RunRecord
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, fmt.Errorf("run store list runs scan: %w", err)
		}
		runs = append(runs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("run store list runs rows: %w", err)
	}
	return runs, nil
}

const jobSelectCols = `job_id, run_id, device_id, execution_id, status, created_at, completed_at, output, stderr, exit_code,
       result_code, dispatched_at`

// jobSelectColsQualified is jobSelectCols prefixed with the "j" alias for the
// jobs/runs join in ListStaleActionJobs. It is a literal so the query text is
// never built at runtime; a test keeps it in step with jobSelectCols.
const jobSelectColsQualified = `j.job_id, j.run_id, j.device_id, j.execution_id, j.status, j.created_at, j.completed_at, j.output, j.stderr, j.exit_code,
       j.result_code, j.dispatched_at`

func scanJob(row rowScanner) (*JobRecord, error) {
	j := &JobRecord{}
	var (
		executionID  sql.NullString
		completedAt  sql.NullTime
		output       sql.NullString
		stderr       sql.NullString
		exitCode     sql.NullInt64
		resultCode   sql.NullString
		dispatchedAt sql.NullTime
	)
	if err := row.Scan(
		&j.JobID, &j.RunID, &j.DeviceID, &executionID,
		(*string)(&j.Status), &j.CreatedAt, &completedAt,
		&output, &stderr, &exitCode, &resultCode, &dispatchedAt,
	); err != nil {
		return nil, err
	}
	j.ExecutionID = executionID.String
	if completedAt.Valid {
		t := completedAt.Time
		j.CompletedAt = &t
	}
	if dispatchedAt.Valid {
		t := dispatchedAt.Time
		j.DispatchedAt = &t
	}
	j.Output = output.String
	j.Stderr = stderr.String
	j.ExitCode = int(exitCode.Int64)
	j.ResultCode = resultCode.String
	return j, nil
}

// ListRunJobs returns all job records for runID ordered by created_at ASC.
func (s *RunStoreSQL) ListRunJobs(runID string) ([]*JobRecord, error) {
	rows, err := s.db.Query(`SELECT `+jobSelectCols+`
FROM script_run_jobs
WHERE run_id = ?
ORDER BY created_at ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("run store list jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var jobs []*JobRecord
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("run store scan job: %w", err)
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("run store list jobs rows: %w", err)
	}
	return jobs, nil
}

// UpdateJobResultCode records a steward-action result code on a job.
func (s *RunStoreSQL) UpdateJobResultCode(jobID, code string) error {
	_, err := s.db.Exec(`UPDATE script_run_jobs SET result_code = ? WHERE job_id = ?`, nullableStr(code), jobID)
	return err
}

// MarkJobDispatched moves a pending job to dispatched and stamps dispatched_at.
// The WHERE clause makes it a compare-and-set: a job that is no longer pending
// (for instance already expired by a sweep) is left untouched.
func (s *RunStoreSQL) MarkJobDispatched(jobID string, at time.Time) (bool, error) {
	res, err := s.db.Exec(`UPDATE script_run_jobs SET status = ?, dispatched_at = ?
WHERE job_id = ? AND status = ?`, string(JobStatusDispatched), at.UTC(), jobID, string(JobStatusPending))
	if err != nil {
		return false, err
	}
	return rowsChanged(res)
}

// ListStaleActionJobs returns steward-action jobs with no result that are still
// pending and created before pendingBefore, or dispatched before dispatchedBefore.
// The time comparison runs in Go: sqlite stores times as text, and only the
// small set of open action jobs is read.
func (s *RunStoreSQL) ListStaleActionJobs(pendingBefore, dispatchedBefore time.Time) ([]*JobRecord, error) {
	rows, err := s.db.Query(`SELECT `+jobSelectColsQualified+`
FROM script_run_jobs j JOIN script_runs r ON r.run_id = j.run_id
WHERE r.kind = ? AND j.completed_at IS NULL AND (j.result_code IS NULL OR j.result_code = '')
  AND j.status IN (?, ?)
ORDER BY j.created_at ASC`, RunKindStewardAction, string(JobStatusPending), string(JobStatusDispatched))
	if err != nil {
		return nil, fmt.Errorf("run store list stale action jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var stale []*JobRecord
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("run store scan stale action job: %w", err)
		}
		switch {
		case j.Status == JobStatusPending && j.CreatedAt.Before(pendingBefore):
			stale = append(stale, j)
		case j.Status == JobStatusDispatched && j.DispatchedAt != nil && j.DispatchedAt.Before(dispatchedBefore):
			stale = append(stale, j)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("run store list stale action jobs rows: %w", err)
	}
	return stale, nil
}

// ExpireJobIfStatus is a compare-and-set from fromStatus to the terminal status
// resultCode. The single conditional UPDATE is atomic: of several concurrent
// callers exactly one matches the status predicate and reports changed.
func (s *RunStoreSQL) ExpireJobIfStatus(jobID string, fromStatus JobStatus, resultCode string, at time.Time) (bool, error) {
	res, err := s.db.Exec(`UPDATE script_run_jobs
SET status = ?, result_code = ?, completed_at = ?
WHERE job_id = ? AND status = ?`, resultCode, resultCode, at.UTC(), jobID, string(fromStatus))
	if err != nil {
		return false, err
	}
	return rowsChanged(res)
}

func rowsChanged(res sql.Result) (bool, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return n > 0, nil
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

// UpdateJobResult sets the terminal status, executionID, and captured execution
// result (stdout/stderr/exit code) for a job (Issue #1995, root cause D).
// When status is terminal, completed_at is set to the current UTC time.
func (s *RunStoreSQL) UpdateJobResult(jobID string, status JobStatus, executionID, output, stderr string, exitCode int) error {
	var completedAt interface{}
	if status.IsTerminal() {
		completedAt = time.Now().UTC()
	}
	const q = `
UPDATE script_run_jobs
SET status       = ?,
    execution_id = CASE WHEN ? != '' THEN ? ELSE execution_id END,
    completed_at = COALESCE(?, completed_at),
    output       = ?,
    stderr       = ?,
    exit_code    = ?
WHERE job_id = ?`
	_, err := s.db.Exec(q, string(status), executionID, executionID, completedAt,
		nullableStr(output), nullableStr(stderr), exitCode, jobID)
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

// DeviceLockReleaser releases a per-device dispatcher lock for a cancelled
// execution. It is implemented by *dispatcher.Dispatcher. The Manager depends on
// this narrow interface rather than importing the dispatcher package directly.
type DeviceLockReleaser interface {
	// ReleaseDeviceForCancelledExecution releases the device lock only if the
	// currently-held execution matches executionID, preventing a late cancel from
	// freeing a lock now held by a newer execution for the same device.
	// Returns true if the lock was released.
	ReleaseDeviceForCancelledExecution(deviceID, executionID string) bool
}

// Manager coordinates the lifecycle of run records: retrieval and cancellation.
// Run creation is performed by the synthesis functions in synthesis.go.
type Manager struct {
	store          RunStore
	executionQueue *scriptmodule.ExecutionQueue
	lockReleaser   DeviceLockReleaser
}

// NewManager creates a Manager backed by store and executionQueue.
// executionQueue may be nil; CancelRun will then skip queue-level cancellation.
func NewManager(store RunStore, executionQueue *scriptmodule.ExecutionQueue) *Manager {
	return &Manager{store: store, executionQueue: executionQueue}
}

// SetDeviceLockReleaser wires the dispatcher's cancel-release path so CancelRun
// immediately frees the per-device dispatcher lock for cancelled jobs. Must be
// called before any CancelRun call. Nil removes the wiring.
func (m *Manager) SetDeviceLockReleaser(r DeviceLockReleaser) {
	m.lockReleaser = r
}

// GetRun returns the run record for runID.
// Returns ErrNotFound when no run exists with that ID.
func (m *Manager) GetRun(_ context.Context, runID string) (*RunRecord, error) {
	return m.store.GetRun(runID)
}

// ListRuns returns runs with pagination, optionally scoped to tenantID.
// An empty tenantID returns runs across all tenants (global-scope admin callers).
func (m *Manager) ListRuns(_ context.Context, tenantID string, limit, offset int) ([]*RunRecord, error) {
	return m.store.ListRuns(tenantID, limit, offset)
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
		if m.lockReleaser != nil && job.ExecutionID != "" {
			m.lockReleaser.ReleaseDeviceForCancelledExecution(job.DeviceID, job.ExecutionID)
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
func (m *Manager) RecordJobCompletion(ctx context.Context, runID, jobID, executionID string, failed bool) error {
	return m.RecordJobResult(ctx, runID, jobID, executionID, failed, "", "", 0)
}

// RecordJobResult is RecordJobCompletion with the captured execution result
// (stdout/stderr/exit code) persisted onto the job record (Issue #1995, root
// cause D). The dispatcher calls this so `cfg steward exec` can surface output.
func (m *Manager) RecordJobResult(_ context.Context, runID, jobID, executionID string, failed bool, output, stderr string, exitCode int) error {
	jobStatus := JobStatusCompleted
	if failed {
		jobStatus = JobStatusFailed
	}
	if err := m.store.UpdateJobResult(jobID, jobStatus, executionID, output, stderr, exitCode); err != nil {
		return fmt.Errorf("record job completion: update job %s: %w", jobID, err)
	}
	return m.refreshRun(runID)
}

// refreshRun recomputes a run's job counts from its jobs and, once every job is
// terminal, moves the run to completed (or failed when any job failed, expired
// or produced no result). A run that is already terminal (e.g. cancelled) is
// left untouched so a late callback cannot resurrect it.
func (m *Manager) refreshRun(runID string) error {
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
		case JobStatusFailed, JobStatusExpired, JobStatusNoResult:
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

// ClaimActionDispatch is the compare-and-set that must succeed before a
// steward-action command is sent: it moves the job from pending to dispatched.
// It reports claimed == false when the job is no longer pending — already
// dispatched (status "dispatched": the action was sent, never send it twice) or
// closed by the expiry sweep or a cancel — and returns the job's current status.
func (m *Manager) ClaimActionDispatch(_ context.Context, runID, jobID string, at time.Time) (claimed bool, status string, err error) {
	changed, err := m.store.MarkJobDispatched(jobID, at)
	if err != nil {
		return false, "", fmt.Errorf("claim action dispatch: job %s: %w", jobID, err)
	}
	if changed {
		return true, string(JobStatusDispatched), nil
	}
	jobs, err := m.store.ListRunJobs(runID)
	if err != nil {
		return false, "", fmt.Errorf("claim action dispatch: list jobs for run %s: %w", runID, err)
	}
	for _, j := range jobs {
		if j.JobID == jobID {
			return false, string(j.Status), nil
		}
	}
	return false, "", fmt.Errorf("claim action dispatch: job %s: %w", jobID, ErrNotFound)
}

// RecordActionResult records a steward-action outcome: the result code is
// persisted on the job and the job moves to completed (ok) or failed (any other
// code). A code outside the known set is recorded as failed so a steward cannot
// write arbitrary text into the run record. The run advances as for scripts.
func (m *Manager) RecordActionResult(ctx context.Context, runID, jobID, executionID, resultCode string) error {
	code := NormalizeResultCode(resultCode)
	if err := m.store.UpdateJobResultCode(jobID, code); err != nil {
		return fmt.Errorf("record action result: update job %s: %w", jobID, err)
	}
	exitCode := 0
	if code != ResultCodeOK {
		exitCode = 1
	}
	return m.RecordJobResult(ctx, runID, jobID, executionID, code != ResultCodeOK, "", "", exitCode)
}

// NormalizeResultCode maps a steward-reported result code to the recorded set.
// The codes a steward reports are kept; anything else (including empty) is failed.
func NormalizeResultCode(code string) string {
	switch code {
	case ResultCodeOK, ResultCodeSelfProtect, ResultCodeProcessChanged, ResultCodeUnsupported,
		ResultCodeFailed, "not_found", "permission_denied":
		return code
	}
	return ResultCodeFailed
}

// ExpireActionJobs closes steward-action jobs that will never report. A job
// still pending past scriptmodule.StewardActionTTL ends "expired" ("expired, not
// run"); one dispatched but unreported past scriptmodule.StewardActionTimeout
// ends "no_result" ("sent, no result reported": the action may have run).
//
// Every node's dispatcher runs this sweep, so each transition is a
// compare-and-set in the store. Only the caller whose update changed the row
// tears down the queue entry, advances the run and returns the job — a node that
// loses the race does nothing and audits nothing. The jobs this call closed are
// returned (alongside any error for the ones it could not process) so the
// dispatcher can audit each exactly once.
func (m *Manager) ExpireActionJobs(ctx context.Context, now time.Time) ([]scriptmodule.ExpiredActionJob, error) {
	stale, err := m.store.ListStaleActionJobs(now.Add(-scriptmodule.StewardActionTTL), now.Add(-scriptmodule.StewardActionTimeout))
	if err != nil {
		return nil, fmt.Errorf("expire action jobs: list stale jobs: %w", err)
	}

	var (
		closed []scriptmodule.ExpiredActionJob
		errs   []error
	)
	for _, job := range stale {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		code, detail := ResultCodeExpired, "expired, not run"
		if job.Status == JobStatusDispatched {
			code, detail = ResultCodeNoResult, "sent, no result reported"
		}
		changed, err := m.store.ExpireJobIfStatus(job.JobID, job.Status, code, now)
		if err != nil {
			errs = append(errs, fmt.Errorf("expire action job %s: %w", job.JobID, err))
			continue
		}
		if !changed {
			continue
		}

		// The entry must not be re-dispatched, and the device slot is freed.
		if job.ExecutionID != "" {
			if m.executionQueue != nil {
				_ = m.executionQueue.CancelExecution(job.DeviceID, job.ExecutionID) //nolint:errcheck // entry may already be gone from the active queue
			}
			if m.lockReleaser != nil {
				m.lockReleaser.ReleaseDeviceForCancelledExecution(job.DeviceID, job.ExecutionID)
			}
		}
		if err := m.refreshRun(job.RunID); err != nil {
			errs = append(errs, err)
		}

		expired := scriptmodule.ExpiredActionJob{
			RunID: job.RunID, JobID: job.JobID, DeviceID: job.DeviceID, ExecutionID: job.ExecutionID,
			ResultCode: code, Detail: detail, At: now,
		}
		if run, err := m.store.GetRun(job.RunID); err == nil {
			expired.TenantID = run.TenantID
			expired.CreatedBy = run.CreatedBy
			if len(run.ActionJSON) > 0 {
				_ = json.Unmarshal(run.ActionJSON, &expired.Action) //nolint:errcheck // a malformed action leaves the audit fields empty
			}
		}
		closed = append(closed, expired)
	}
	return closed, errors.Join(errs...)
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
