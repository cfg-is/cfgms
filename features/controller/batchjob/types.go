// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package batchjob defines the domain types for fleet-wide rolling batch update jobs.
// It is intentionally import-free of other CFGMS packages so that the storage
// interface, executor, REST API, quorum-check, and rollback stories can all depend
// on it without circular imports.
package batchjob

import "time"

// BatchJobStatus is the lifecycle state of a batch job.
type BatchJobStatus string

const (
	// BatchJobStatusPending — job is created but execution has not started.
	BatchJobStatusPending BatchJobStatus = "pending"

	// BatchJobStatusRunning — at least one step is actively deploying.
	BatchJobStatusRunning BatchJobStatus = "running"

	// BatchJobStatusPaused — execution halted on step failure; awaits operator action.
	BatchJobStatusPaused BatchJobStatus = "paused"

	// BatchJobStatusCompleted — all steps finished successfully.
	BatchJobStatusCompleted BatchJobStatus = "completed"

	// BatchJobStatusFailed — terminal; rollback not attempted or itself failed.
	BatchJobStatusFailed BatchJobStatus = "failed"

	// BatchJobStatusRolledBack — compensating dispatch completed.
	BatchJobStatusRolledBack BatchJobStatus = "rolled_back"
)

// BatchStepStatus is the lifecycle state of a single step within a batch job.
type BatchStepStatus string

const (
	// BatchStepStatusPending — step has not yet started.
	BatchStepStatusPending BatchStepStatus = "pending"

	// BatchStepStatusRunning — step is actively deploying to its stewards.
	BatchStepStatusRunning BatchStepStatus = "running"

	// BatchStepStatusCompleted — all stewards in the step converged successfully.
	BatchStepStatusCompleted BatchStepStatus = "completed"

	// BatchStepStatusFailed — one or more stewards failed; step is terminal.
	BatchStepStatusFailed BatchStepStatus = "failed"

	// BatchStepStatusRolledBack — compensating dispatch for this step completed.
	BatchStepStatusRolledBack BatchStepStatus = "rolled_back"
)

// BatchStep is one wave of stewards within a rolling batch job.
type BatchStep struct {
	// Index is the zero-based position of this step in the job's step sequence.
	Index int

	// StewardIDs is the set of stewards targeted by this step.
	StewardIDs []string

	// Status is the current lifecycle state of the step.
	Status BatchStepStatus

	// StartedAt is set when the step transitions to running.
	StartedAt *time.Time

	// CompletedAt is set when the step reaches a terminal state.
	CompletedAt *time.Time

	// FailedIDs lists stewards that reported a failure during this step.
	FailedIDs []string

	// RollbackJobID is set when a compensating dispatch is queued for this step.
	RollbackJobID string
}

// BatchJobConfig holds the parameters that control batch execution.
type BatchJobConfig struct {
	// BatchSize is the number of stewards per batch wave; must be > 0.
	BatchSize int

	// PreviousConfigRef is the config version to restore on rollback.
	// Captured at job creation time so rollback is always available.
	PreviousConfigRef string
}

// BatchJob is a fleet-wide rolling update operation managed by the controller.
type BatchJob struct {
	// ID is the unique job identifier.
	ID string

	// TenantID scopes the job to a single tenant.
	TenantID string

	// Selector is the fleet.Filter expression used to resolve Targets.
	// Stored verbatim for audit — re-evaluating later could yield different results.
	Selector string

	// Config holds the static parameters for this job.
	Config BatchJobConfig

	// Targets is the resolved set of steward IDs captured at job creation time.
	Targets []string

	// Status is the current lifecycle state of the job.
	Status BatchJobStatus

	// Steps is the ordered sequence of batch waves.
	Steps []BatchStep

	// CreatedAt is the wall-clock time when the job was created.
	CreatedAt time.Time

	// UpdatedAt is the wall-clock time of the last state change.
	UpdatedAt time.Time

	// InitiatedBy identifies the operator who created the job.
	InitiatedBy string
}
