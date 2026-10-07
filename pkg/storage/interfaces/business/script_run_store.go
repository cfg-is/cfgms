// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"context"
	"errors"
	"time"
)

// ErrScriptRunNotFound is returned by ScriptRunStore.GetRun when no run exists.
var ErrScriptRunNotFound = errors.New("script run not found")

// ErrExecutionGrantNotFound is returned by ScriptRunStore.LookupGrant when no
// unexpired grant exists for the (device, execution) pair.
var ErrExecutionGrantNotFound = errors.New("execution grant not found or expired")

// ErrExecutionGrantConsumed is returned by ScriptRunStore.LookupGrant when the
// grant exists but has already been consumed.
var ErrExecutionGrantConsumed = errors.New("execution grant already consumed")

// Run kinds. An empty Kind is stored and read back as ScriptRunKindScript.
const (
	ScriptRunKindScript        = "script"
	ScriptRunKindStewardAction = "steward_action"
)

// ScriptRun is the durable record for one multi-steward script, command or
// steward-action run. Status values and the filter encoding are owned by the
// run feature; the store persists them verbatim.
type ScriptRun struct {
	RunID         string
	TenantID      string
	CreatedBy     string
	CreatedAt     time.Time
	Status        string
	FilterJSON    []byte
	ScriptRef     string
	InlineContent string
	Shell         string
	JobCount      int
	CompletedJobs int
	FailedJobs    int
	// Kind is ScriptRunKindScript or ScriptRunKindStewardAction. Empty is stored
	// as ScriptRunKindScript, so runs created before this field read back as script.
	Kind string
	// ActionJSON is {verb, target_kind, target_name, parameters} for a
	// steward-action run; empty for a script run.
	ActionJSON []byte
}

// ScriptRunJob tracks one steward's share of a ScriptRun.
type ScriptRunJob struct {
	JobID       string
	RunID       string
	DeviceID    string
	ExecutionID string
	Status      string
	CreatedAt   time.Time
	CompletedAt *time.Time
	Output      string
	Stderr      string
	ExitCode    int
	// ResultCode is the steward-action outcome (ok, self_protect, process_changed,
	// unsupported, failed, expired, no_result); empty for script jobs.
	ResultCode string
	// DispatchedAt is when a steward-action job was handed to its steward.
	DispatchedAt *time.Time
}

// ExecutionGrant is a per-execution API access grant created at dispatch time.
type ExecutionGrant struct {
	DeviceID    string
	TenantID    string
	ExecutionID string
	Scope       []string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Consumed    bool
}

// ScriptRunStore persists script runs, their per-steward jobs, and execution
// grants. In cluster mode it is backed by the shared database so that a run
// created on one controller node is visible to, and completable by, every
// node (Issue #4528): a steward reports results only to the node holding its
// session, which need not be the node that accepted the run.
type ScriptRunStore interface {
	CreateRun(ctx context.Context, run *ScriptRun) error
	CreateJob(ctx context.Context, job *ScriptRunJob) error
	// GetRun returns ErrScriptRunNotFound when runID does not exist.
	GetRun(ctx context.Context, runID string) (*ScriptRun, error)
	// ListRuns returns runs newest first. An empty tenantID lists every tenant.
	ListRuns(ctx context.Context, tenantID string, limit, offset int) ([]*ScriptRun, error)
	// ListRunJobs returns a run's jobs oldest first.
	ListRunJobs(ctx context.Context, runID string) ([]*ScriptRunJob, error)
	// UpdateJobStatus sets status, sets executionID when non-empty, and sets
	// completed_at when completedAt is non-nil.
	UpdateJobStatus(ctx context.Context, jobID, status, executionID string, completedAt *time.Time) error
	// UpdateJobResult is UpdateJobStatus plus the captured execution result.
	UpdateJobResult(ctx context.Context, jobID, status, executionID, output, stderr string, exitCode int, completedAt *time.Time) error
	// UpdateJobResultCode records a steward-action result code on a job without
	// touching the job's status or captured output.
	UpdateJobResultCode(ctx context.Context, jobID, code string) error
	// MarkJobDispatched is a compare-and-set from "pending" to "dispatched" that
	// stamps dispatched_at. It reports whether the row changed; a job that is no
	// longer pending (e.g. already expired by a sweep) is left untouched.
	MarkJobDispatched(ctx context.Context, jobID string, at time.Time) (changed bool, err error)
	// ListStaleActionJobs returns steward-action jobs, across all runs and
	// tenants, with no result that are still "pending" and were created before
	// pendingBefore, or "dispatched" before dispatchedBefore.
	ListStaleActionJobs(ctx context.Context, pendingBefore, dispatchedBefore time.Time) ([]*ScriptRunJob, error)
	// ExpireJobIfStatus is a compare-and-set: it moves the job to the terminal
	// status resultCode (with that result code and completed_at = at) only when
	// the job's current status equals fromStatus, and reports whether the row
	// changed. Exactly one of several concurrent callers sees changed == true.
	ExpireJobIfStatus(ctx context.Context, jobID, fromStatus, resultCode string, at time.Time) (changed bool, err error)
	UpdateRunStatus(ctx context.Context, runID, status string) error
	UpdateRunCounts(ctx context.Context, runID string, completedJobs, failedJobs int) error
	CreateExecutionGrant(ctx context.Context, grant *ExecutionGrant) error
	// LookupGrant returns ErrExecutionGrantNotFound when no grant exists or it
	// has expired, and ErrExecutionGrantConsumed when it has been consumed.
	LookupGrant(ctx context.Context, deviceID, executionID string) (*ExecutionGrant, error)
	ConsumeGrant(ctx context.Context, executionID string) error
}
