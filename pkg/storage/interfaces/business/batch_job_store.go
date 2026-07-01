// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines the BatchJobStore interface for durable batch-job persistence.
package business

import (
	"context"
	"errors"

	"github.com/cfgis/cfgms/features/controller/batchjob"
)

// ErrBatchJobNotFound is returned when a batch job record does not exist.
var ErrBatchJobNotFound = errors.New("batch job not found")

// BatchJobStore defines the storage interface for fleet rolling-batch job persistence.
//
// All implementations must be safe for concurrent use.
// The interface is used by the batch executor, REST API, quorum-check logic,
// and rollback dispatch — none of which may import each other, so all depend
// on this package and features/controller/batchjob for shared types.
type BatchJobStore interface {
	// CreateBatchJob inserts a new batch job record.
	// Returns an error if a record with the same ID already exists.
	CreateBatchJob(ctx context.Context, job *batchjob.BatchJob) error

	// UpdateBatchJobStatus sets the top-level status of an existing batch job.
	// Returns ErrBatchJobNotFound if no record exists for the given id.
	UpdateBatchJobStatus(ctx context.Context, id string, status batchjob.BatchJobStatus) error

	// UpdateBatchStep upserts a step within the batch job identified by jobID.
	// If a step with the same Index already exists it is replaced; otherwise the
	// step is appended. Returns ErrBatchJobNotFound if the job does not exist.
	UpdateBatchStep(ctx context.Context, jobID string, step batchjob.BatchStep) error

	// GetBatchJob retrieves the batch job with the given id.
	// Returns ErrBatchJobNotFound if no record exists.
	GetBatchJob(ctx context.Context, id string) (*batchjob.BatchJob, error)

	// ListBatchJobsByTenant returns all batch jobs belonging to tenantID.
	// Returns an empty slice (not an error) when no records exist.
	ListBatchJobsByTenant(ctx context.Context, tenantID string) ([]*batchjob.BatchJob, error)

	// HealthCheck verifies the store is reachable and operational.
	HealthCheck(ctx context.Context) error

	// Initialize prepares the store (creates directories, tables, schemas, etc.).
	Initialize(ctx context.Context) error

	// Close releases resources held by the store.
	Close() error
}
