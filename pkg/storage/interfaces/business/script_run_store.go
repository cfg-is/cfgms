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

// ScriptRun is the durable record for one multi-steward script or command run.
// Status values and the filter encoding are owned by the run feature; the store
// persists them verbatim.
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
	UpdateRunStatus(ctx context.Context, runID, status string) error
	UpdateRunCounts(ctx context.Context, runID string, completedJobs, failedJobs int) error
	CreateExecutionGrant(ctx context.Context, grant *ExecutionGrant) error
	// LookupGrant returns ErrExecutionGrantNotFound when no grant exists or it
	// has expired, and ErrExecutionGrantConsumed when it has been consumed.
	LookupGrant(ctx context.Context, deviceID, executionID string) (*ExecutionGrant, error)
	ConsumeGrant(ctx context.Context, executionID string) error
}
