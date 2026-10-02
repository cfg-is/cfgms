// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package batchjob

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/controller/commands"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

const batchStepTimeout = 10 * time.Minute

// FleetQuery is the selector resolution interface the executor depends on.
// Defined here (not in the fleet package) to avoid the import cycle:
//
//	batchjob → fleet → business → batchjob
//
// The real wiring uses a thin adapter around fleet.FleetQuery; tests use a
// staticFleetQuery that returns a fixed list of StewardMeta.
type FleetQuery interface {
	// Search resolves selector scoped to tenantID and returns matching steward metadata.
	Search(ctx context.Context, selector, tenantID string) ([]StewardMeta, error)
}

// QuorumChecker partitions a steward list so no batch violates cluster-quorum rules.
// A nil QuorumChecker performs naive round-robin partitioning only.
type QuorumChecker interface {
	Partition(stewards []StewardMeta, batchSize int) [][]string
}

// RollingBatchExecutor dispatches CommandSyncConfig to stewards in sequential batches,
// advancing to the next batch only when all members of the current batch succeed.
// On any batch failure the job transitions to rolled_back (when PreviousConfigRef is set,
// compensating dispatches are sent to already-completed batches) or paused (no baseline).
type RollingBatchExecutor struct {
	store       BatchJobStore
	fleetQuery  FleetQuery
	publisher   *commands.Publisher
	quorumCheck QuorumChecker
	logger      logging.Logger
}

// NewRollingBatchExecutor creates an executor with the provided dependencies.
// quorumCheck may be nil; in that case naive round-robin partitioning is used.
func NewRollingBatchExecutor(
	store BatchJobStore,
	fleetQuery FleetQuery,
	publisher *commands.Publisher,
	quorumCheck QuorumChecker,
	logger logging.Logger,
) *RollingBatchExecutor {
	return &RollingBatchExecutor{
		store:       store,
		fleetQuery:  fleetQuery,
		publisher:   publisher,
		quorumCheck: quorumCheck,
		logger:      logger,
	}
}

// Execute runs the rolling batch job to completion (or stops on failure).
//
// Algorithm:
//  1. Resolve job.Selector via fleetQuery scoped to job.TenantID; persist Targets.
//  2. Partition steward IDs into batches (quorum-aware or naive round-robin).
//  3. For each batch: dispatch CommandSyncConfig with callback; wait for all results.
//     All succeeded → advance. Any failed → rollback applied steps if PreviousConfigRef
//     is set (job → rolled_back or failed), else set job status paused; return nil.
//  4. All batches done → set job status completed.
func (e *RollingBatchExecutor) Execute(ctx context.Context, job *BatchJob) error {
	// 1. Resolve fleet selector scoped to the job's tenant.
	stewards, err := e.fleetQuery.Search(ctx, job.Selector, job.TenantID)
	if err != nil {
		return fmt.Errorf("executor: fleet search: %w", err)
	}
	ids := make([]string, len(stewards))
	for i, s := range stewards {
		ids[i] = s.ID
	}
	job.Targets = ids

	if err := e.store.UpdateBatchTargets(ctx, job.ID, ids); err != nil {
		return fmt.Errorf("executor: persist targets: %w", err)
	}

	// 2. Partition into batches.
	var batches [][]string
	if e.quorumCheck != nil {
		batches = e.quorumCheck.Partition(stewards, job.Config.BatchSize)
	} else {
		batches = naivePartition(ids, job.Config.BatchSize)
	}

	if err := e.store.UpdateBatchJobStatus(ctx, job.ID, BatchJobStatusRunning); err != nil {
		return fmt.Errorf("executor: set running: %w", err)
	}
	job.Status = BatchJobStatusRunning

	// 3. Execute batches sequentially.
	for i, batch := range batches {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// a. Mark step running.
		now := time.Now().UTC()
		step := BatchStep{
			Index:      i,
			StewardIDs: batch,
			Status:     BatchStepStatusRunning,
			StartedAt:  &now,
		}
		if err := e.store.UpdateBatchStep(ctx, job.ID, step); err != nil {
			return fmt.Errorf("executor: set step %d running: %w", i, err)
		}

		e.logger.Info("Executing batch step",
			"job_id", logging.SanitizeLogValue(job.ID),
			"step", i,
			"size", len(batch))

		// b–c. Dispatch and wait for all results.
		failedIDs, err := e.dispatchBatch(ctx, batch)
		if err != nil {
			return err
		}

		completedAt := time.Now().UTC()
		step.CompletedAt = &completedAt

		if len(failedIDs) > 0 {
			// e. At least one steward failed.
			step.Status = BatchStepStatusFailed
			step.FailedIDs = failedIDs
			if persistErr := e.store.UpdateBatchStep(ctx, job.ID, step); persistErr != nil {
				e.logger.Error("Failed to persist failed step",
					"job_id", logging.SanitizeLogValue(job.ID),
					"step", i, "error", persistErr)
			}
			e.logger.Info("Batch step failed",
				"job_id", logging.SanitizeLogValue(job.ID),
				"step", i, "failed_count", len(failedIDs))
			if job.Config.PreviousConfigRef != "" {
				// Baseline captured: compensating dispatch to already-applied stewards.
				e.rollbackAppliedSteps(ctx, job)
			} else {
				// No baseline: pause for operator action.
				if pauseErr := e.store.UpdateBatchJobStatus(ctx, job.ID, BatchJobStatusPaused); pauseErr != nil {
					e.logger.Error("Failed to set job paused",
						"job_id", logging.SanitizeLogValue(job.ID),
						"error", pauseErr)
				}
				job.Status = BatchJobStatusPaused
				e.logger.Info("Job paused (no PreviousConfigRef; rollback skipped)",
					"job_id", logging.SanitizeLogValue(job.ID))
			}
			return nil
		}

		// d. All succeeded → advance.
		step.Status = BatchStepStatusCompleted
		if err := e.store.UpdateBatchStep(ctx, job.ID, step); err != nil {
			return fmt.Errorf("executor: set step %d completed: %w", i, err)
		}

		e.logger.Info("Batch step completed",
			"job_id", logging.SanitizeLogValue(job.ID), "step", i)
	}

	// 4. All batches completed.
	if err := e.store.UpdateBatchJobStatus(ctx, job.ID, BatchJobStatusCompleted); err != nil {
		return fmt.Errorf("executor: set job completed: %w", err)
	}
	job.Status = BatchJobStatusCompleted
	e.logger.Info("Batch job completed", "job_id", logging.SanitizeLogValue(job.ID))
	return nil
}

type stewardDispatchResult struct {
	stewardID string
	success   bool
}

// dispatchBatch sends CommandSyncConfig to each steward in batch and waits for all
// callbacks (success, failure, or timeout). Returns the IDs of failed stewards.
func (e *RollingBatchExecutor) dispatchBatch(ctx context.Context, batch []string) ([]string, error) {
	ch := make(chan stewardDispatchResult, len(batch))

	for _, id := range batch {
		id := id
		_, publishErr := e.publisher.PublishCommandWithCallback(
			ctx, id,
			controlplaneTypes.CommandSyncConfig, nil,
			batchStepTimeout,
			func(event *controlplaneTypes.Event) {
				success := event.Type == controlplaneTypes.EventCommandCompleted
				ch <- stewardDispatchResult{id, success}
			},
			func() {
				e.logger.Warn("Batch dispatch timed out for steward",
					"steward_id", logging.SanitizeLogValue(id))
				ch <- stewardDispatchResult{id, false}
			},
		)
		if publishErr != nil {
			e.logger.Error("Failed to dispatch to steward",
				"steward_id", logging.SanitizeLogValue(id), "error", publishErr)
			ch <- stewardDispatchResult{id, false}
		}
	}

	var failedIDs []string
	for range batch {
		select {
		case r := <-ch:
			if !r.success {
				failedIDs = append(failedIDs, r.stewardID)
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return failedIDs, nil
}

// naivePartition splits ids into consecutive slices of at most batchSize each.
func naivePartition(ids []string, batchSize int) [][]string {
	if len(ids) == 0 {
		return nil
	}
	if batchSize <= 0 {
		batchSize = len(ids)
	}
	var batches [][]string
	for len(ids) > 0 {
		size := batchSize
		if size > len(ids) {
			size = len(ids)
		}
		batches = append(batches, ids[:size])
		ids = ids[size:]
	}
	return batches
}
