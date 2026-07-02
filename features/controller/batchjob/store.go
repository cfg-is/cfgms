// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package batchjob

import (
	"context"
	"errors"
)

// ErrBatchJobNotFound is returned when a batch job record does not exist.
// Defined here (not in pkg/storage/interfaces/business) so that storage
// implementations in this package can reference it without an import cycle:
//
//	batchjob → business → batchjob
//
// pkg/storage/interfaces/business re-exports this value so all callers that
// already import business continue to work unchanged.
var ErrBatchJobNotFound = errors.New("batch job not found")

// BatchJobStore defines the storage interface for fleet rolling-batch job persistence.
//
// Defined here so executor.go and store_sqlite.go can reference it from within the
// batchjob package, avoiding the import cycle that would arise if they depended on
// pkg/storage/interfaces/business (which itself imports this package for the domain types).
//
// pkg/storage/interfaces/business re-exports this interface as a type alias so all
// existing callers continue to compile without changes.
//
// All implementations must be safe for concurrent use.
type BatchJobStore interface {
	// CreateBatchJob inserts a new batch job record.
	// Returns an error if a record with the same ID already exists.
	CreateBatchJob(ctx context.Context, job *BatchJob) error

	// UpdateBatchJobStatus sets the top-level status of an existing batch job.
	// Returns ErrBatchJobNotFound if no record exists for the given id.
	UpdateBatchJobStatus(ctx context.Context, id string, status BatchJobStatus) error

	// UpdateBatchTargets replaces the resolved target steward IDs for the job.
	// Called by the executor after fleet selector resolution at job start.
	// Returns ErrBatchJobNotFound if the job does not exist.
	UpdateBatchTargets(ctx context.Context, id string, targets []string) error

	// UpdateBatchStep upserts a step within the batch job identified by jobID.
	// If a step with the same Index already exists it is replaced; otherwise the
	// step is appended. Returns ErrBatchJobNotFound if the job does not exist.
	UpdateBatchStep(ctx context.Context, jobID string, step BatchStep) error

	// GetBatchJob retrieves the batch job with the given id.
	// Returns ErrBatchJobNotFound if no record exists.
	GetBatchJob(ctx context.Context, id string) (*BatchJob, error)

	// ListBatchJobsByTenant returns all batch jobs belonging to tenantID.
	// Returns an empty slice (not an error) when no records exist.
	ListBatchJobsByTenant(ctx context.Context, tenantID string) ([]*BatchJob, error)

	// HealthCheck verifies the store is reachable and operational.
	HealthCheck(ctx context.Context) error

	// Initialize prepares the store (creates directories, tables, schemas, etc.).
	Initialize(ctx context.Context) error

	// Close releases resources held by the store.
	Close() error
}
