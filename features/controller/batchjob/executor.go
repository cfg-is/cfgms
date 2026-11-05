// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package batchjob

import (
	"context"
	"errors"
	"fmt"
	"time"

	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const batchStepTimeout = 10 * time.Minute

// FleetQuery is the steward metadata lookup interface the executor depends on.
// Defined here (not in the fleet package) to avoid the import cycle:
//
//	batchjob → fleet → business → batchjob
//
// The real wiring uses a thin adapter around fleet.FleetQuery; tests use a
// static fleet query that returns a fixed list of StewardMeta.
type FleetQuery interface {
	// Lookup returns metadata for the given steward IDs. IDs the fleet source
	// does not know are omitted; the result is never wider than ids.
	Lookup(ctx context.Context, ids []string) ([]StewardMeta, error)
}

// QuorumChecker partitions a steward list so no batch violates cluster-quorum rules.
// A nil QuorumChecker performs naive round-robin partitioning only.
type QuorumChecker interface {
	Partition(stewards []StewardMeta, batchSize int) [][]string
}

// CommandPublisher is the slice of the controller command publisher the batch
// executor needs. It is an interface so this package does not import
// features/controller/commands, which would close an import cycle through
// pkg/cache and the storage business interfaces.
type CommandPublisher interface {
	PublishCommandWithCallback(
		ctx context.Context,
		stewardID string,
		cmdType controlplaneTypes.CommandType,
		params map[string]interface{},
		timeout time.Duration,
		onComplete func(event *controlplaneTypes.Event),
		onTimeout func(),
	) (string, error)
}

// RollingBatchExecutor dispatches CommandSyncConfig to stewards in sequential batches,
// advancing to the next batch only when all members of the current batch succeed.
// On any batch failure the job transitions to rolled_back (when PreviousConfigRef is set,
// compensating dispatches are sent to already-completed batches) or paused (no baseline).
type RollingBatchExecutor struct {
	store       business.BatchJobStore
	fleetQuery  FleetQuery
	publisher   CommandPublisher
	quorumCheck QuorumChecker
	logger      logging.Logger
}

// NewRollingBatchExecutor creates an executor with the provided dependencies.
// quorumCheck may be nil; in that case naive round-robin partitioning is used.
func NewRollingBatchExecutor(
	store business.BatchJobStore,
	fleetQuery FleetQuery,
	publisher CommandPublisher,
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
//  1. Take job.Targets (deduplicated) as the authorized recipient set. It is never
//     re-resolved from job.Selector or job.TenantID.
//  2. Look up metadata for those IDs and partition them into batches (quorum-aware
//     or naive round-robin). IDs without metadata are still dispatched.
//  3. For each batch: dispatch CommandSyncConfig with callback; wait for all results.
//     All succeeded → advance. Any failed → rollback applied steps if PreviousConfigRef
//     is set (job → rolled_back or failed), else set job status paused; return nil.
//  4. All batches done → set job status completed.
//
// job.Targets is the set the create handler authorized. Execute sends commands to
// those stewards only and never replaces the persisted targets.
func (e *RollingBatchExecutor) Execute(ctx context.Context, job *business.BatchJob) error {
	// 1–2. The authorized set, without duplicates, partitioned into batches.
	batches, err := e.partitionTargets(ctx, job)
	if err != nil {
		return err
	}

	if err := e.store.UpdateBatchJobStatus(ctx, job.ID, business.BatchJobStatusRunning); err != nil {
		return fmt.Errorf("executor: set running: %w", err)
	}
	job.Status = business.BatchJobStatusRunning

	// 3. Execute batches sequentially.
	for i, batch := range batches {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		stopped, err := e.runBatchStep(ctx, job, i, batch)
		if err != nil {
			return err
		}
		if stopped {
			return nil
		}
	}

	// 4. All batches completed.
	if err := e.store.UpdateBatchJobStatus(ctx, job.ID, business.BatchJobStatusCompleted); err != nil {
		return fmt.Errorf("executor: set job completed: %w", err)
	}
	job.Status = business.BatchJobStatusCompleted
	e.logger.Info("Batch job completed", "job_id", logging.SanitizeLogValue(job.ID))
	return nil
}

// partitionTargets deduplicates job.Targets and splits them into batches,
// quorum-aware when a QuorumChecker is configured, else naive round-robin.
func (e *RollingBatchExecutor) partitionTargets(ctx context.Context, job *business.BatchJob) ([][]string, error) {
	ids := dedupeIDs(job.Targets)
	if len(ids) == 0 {
		return nil, nil
	}
	if e.quorumCheck == nil {
		return naivePartition(ids, job.Config.BatchSize), nil
	}
	found, err := e.fleetQuery.Lookup(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("executor: fleet lookup: %w", err)
	}
	return e.quorumCheck.Partition(orderedMeta(ids, found), job.Config.BatchSize), nil
}

// runBatchStep executes one batch: marks the step running, dispatches to every
// steward in the batch and waits for results. It returns stopped=true when the
// batch failed and the job has been rolled back or paused.
func (e *RollingBatchExecutor) runBatchStep(ctx context.Context, job *business.BatchJob, i int, batch []string) (bool, error) {
	// a. Mark step running.
	now := time.Now().UTC()
	step := business.BatchStep{
		Index:      i,
		StewardIDs: batch,
		Status:     business.BatchStepStatusRunning,
		StartedAt:  &now,
	}
	if err := e.store.UpdateBatchStep(ctx, job.ID, step); err != nil {
		return false, fmt.Errorf("executor: set step %d running: %w", i, err)
	}

	e.logger.Info("Executing batch step",
		"job_id", logging.SanitizeLogValue(job.ID),
		"step", i,
		"size", len(batch))

	// b–c. Dispatch and wait for all results.
	failedIDs, err := e.dispatchBatch(ctx, batch)
	if err != nil {
		return false, err
	}

	completedAt := time.Now().UTC()
	step.CompletedAt = &completedAt

	if len(failedIDs) > 0 {
		// e. At least one steward failed.
		e.handleFailedStep(ctx, job, step, failedIDs)
		return true, nil
	}

	// d. All succeeded → advance.
	step.Status = business.BatchStepStatusCompleted
	if err := e.store.UpdateBatchStep(ctx, job.ID, step); err != nil {
		return false, fmt.Errorf("executor: set step %d completed: %w", i, err)
	}

	e.logger.Info("Batch step completed",
		"job_id", logging.SanitizeLogValue(job.ID), "step", i)
	return false, nil
}

// handleFailedStep persists a failed step, then rolls back applied steps when a
// baseline (PreviousConfigRef) exists, or pauses the job for operator action.
func (e *RollingBatchExecutor) handleFailedStep(ctx context.Context, job *business.BatchJob, step business.BatchStep, failedIDs []string) {
	step.Status = business.BatchStepStatusFailed
	step.FailedIDs = failedIDs
	if persistErr := e.store.UpdateBatchStep(ctx, job.ID, step); persistErr != nil {
		e.logger.Error("Failed to persist failed step",
			"job_id", logging.SanitizeLogValue(job.ID),
			"step", step.Index, "error", persistErr)
	}
	e.logger.Info("Batch step failed",
		"job_id", logging.SanitizeLogValue(job.ID),
		"step", step.Index, "failed_count", len(failedIDs))

	if job.Config.PreviousConfigRef != "" {
		// Baseline captured: compensating dispatch to already-applied stewards.
		e.rollbackAppliedSteps(ctx, job)
		return
	}

	// No baseline: pause for operator action.
	if pauseErr := e.store.UpdateBatchJobStatus(ctx, job.ID, business.BatchJobStatusPaused); pauseErr != nil {
		e.logger.Error("Failed to set job paused",
			"job_id", logging.SanitizeLogValue(job.ID),
			"error", pauseErr)
	}
	job.Status = business.BatchJobStatusPaused
	e.logger.Info("Job paused (no PreviousConfigRef; rollback skipped)",
		"job_id", logging.SanitizeLogValue(job.ID))
}

type stewardDispatchResult struct {
	stewardID string
	success   bool
	// refused marks a steward the lockdown gate refused (Issue #5665). It is
	// skipped: success is true so it never counts as a failed steward.
	refused bool
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
				ch <- stewardDispatchResult{stewardID: id, success: success}
			},
			func() {
				e.logger.Warn("Batch dispatch timed out for steward",
					"steward_id", logging.SanitizeLogValue(id))
				ch <- stewardDispatchResult{stewardID: id, success: false}
			},
		)
		if errors.Is(publishErr, controlplaneInterfaces.ErrStewardLockedDown) {
			// A refusal, not a failure: nothing was sent, so the step neither
			// fails nor triggers a rollback for this steward (Issue #5665).
			e.logger.Warn("refused: locked down; steward skipped",
				"steward_id", logging.SanitizeLogValue(id))
			ch <- stewardDispatchResult{stewardID: id, success: true, refused: true}
			continue
		}
		if publishErr != nil {
			e.logger.Error("Failed to dispatch to steward",
				"steward_id", logging.SanitizeLogValue(id), "error", publishErr)
			ch <- stewardDispatchResult{stewardID: id, success: false}
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

// dedupeIDs returns ids without duplicates or empty entries, preserving order.
func dedupeIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// orderedMeta returns one StewardMeta per id, in ids order. Metadata the lookup
// did not return (or returned for an ID outside ids) is ignored; a missing ID
// gets a bare StewardMeta so it is still partitioned and dispatched.
func orderedMeta(ids []string, found []StewardMeta) []StewardMeta {
	byID := make(map[string]StewardMeta, len(found))
	for _, m := range found {
		byID[m.ID] = m
	}
	out := make([]StewardMeta, 0, len(ids))
	for _, id := range ids {
		if m, ok := byID[id]; ok {
			out = append(out, m)
		} else {
			out = append(out, StewardMeta{ID: id})
		}
	}
	return out
}
