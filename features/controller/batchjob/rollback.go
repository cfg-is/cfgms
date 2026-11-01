// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package batchjob

import (
	"context"
	"time"

	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

const rollbackTimeout = 5 * time.Minute

// rollbackAppliedSteps dispatches CommandSyncConfig with PreviousConfigRef to every
// steward in a completed step, waits for callbacks, then transitions the job status.
//
// Result states:
//   - All compensating dispatches succeed → steps marked rolled_back; job → rolled_back.
//   - Any compensating dispatch fails     → job → failed.
//   - No completed steps (first batch failed) → job → paused (nothing to undo).
func (e *RollingBatchExecutor) rollbackAppliedSteps(ctx context.Context, job *BatchJob) {
	current, err := e.store.GetBatchJob(ctx, job.ID)
	if err != nil {
		e.logger.Error("Rollback: failed to fetch job state",
			"job_id", logging.SanitizeLogValue(job.ID), "error", err)
		if statusErr := e.store.UpdateBatchJobStatus(ctx, job.ID, BatchJobStatusFailed); statusErr != nil {
			e.logger.Error("Rollback: failed to set job failed",
				"job_id", logging.SanitizeLogValue(job.ID), "error", statusErr)
		}
		job.Status = BatchJobStatusFailed
		return
	}

	var completedSteps []BatchStep
	for _, step := range current.Steps {
		if step.Status == BatchStepStatusCompleted {
			completedSteps = append(completedSteps, step)
		}
	}

	if len(completedSteps) == 0 {
		// First batch failed — no forward progress to undo; pause for operator action.
		if statusErr := e.store.UpdateBatchJobStatus(ctx, job.ID, BatchJobStatusPaused); statusErr != nil {
			e.logger.Error("Rollback: failed to set job paused",
				"job_id", logging.SanitizeLogValue(job.ID), "error", statusErr)
		}
		job.Status = BatchJobStatusPaused
		e.logger.Info("Batch step failed with no prior completed steps; job paused",
			"job_id", logging.SanitizeLogValue(job.ID))
		return
	}

	e.logger.Info("Rolling back completed steps",
		"job_id", logging.SanitizeLogValue(job.ID),
		"completed_step_count", len(completedSteps))

	params := map[string]interface{}{
		"config_ref": job.Config.PreviousConfigRef,
	}

	allSucceeded := true
	for i := range completedSteps {
		step := completedSteps[i]
		failedIDs, dispatchErr := e.dispatchRollbackBatch(ctx, step.StewardIDs, params)
		if dispatchErr != nil {
			allSucceeded = false
			e.logger.Error("Rollback dispatch error",
				"job_id", logging.SanitizeLogValue(job.ID),
				"step", step.Index, "error", dispatchErr)
			break
		}
		if len(failedIDs) > 0 {
			allSucceeded = false
			e.logger.Warn("Rollback dispatch failed for some stewards",
				"job_id", logging.SanitizeLogValue(job.ID),
				"step", step.Index, "failed_count", len(failedIDs))
			continue
		}
		// All stewards in this step acknowledged rollback.
		step.Status = BatchStepStatusRolledBack
		if persistErr := e.store.UpdateBatchStep(ctx, job.ID, step); persistErr != nil {
			e.logger.Error("Rollback: failed to persist rolled_back step",
				"job_id", logging.SanitizeLogValue(job.ID),
				"step", step.Index, "error", persistErr)
		}
	}

	if allSucceeded {
		if statusErr := e.store.UpdateBatchJobStatus(ctx, job.ID, BatchJobStatusRolledBack); statusErr != nil {
			e.logger.Error("Rollback: failed to set job rolled_back",
				"job_id", logging.SanitizeLogValue(job.ID), "error", statusErr)
		}
		job.Status = BatchJobStatusRolledBack
		e.logger.Info("Rollback completed",
			"job_id", logging.SanitizeLogValue(job.ID))
	} else {
		if statusErr := e.store.UpdateBatchJobStatus(ctx, job.ID, BatchJobStatusFailed); statusErr != nil {
			e.logger.Error("Rollback: failed to set job failed",
				"job_id", logging.SanitizeLogValue(job.ID), "error", statusErr)
		}
		job.Status = BatchJobStatusFailed
		e.logger.Warn("Rollback failed; job marked failed",
			"job_id", logging.SanitizeLogValue(job.ID))
	}
}

// dispatchRollbackBatch sends CommandSyncConfig with rollback params to all stewards
// in a previously-completed step and waits for callbacks.
// Returns the IDs of stewards that failed or timed out.
func (e *RollingBatchExecutor) dispatchRollbackBatch(ctx context.Context, stewardIDs []string, params map[string]interface{}) ([]string, error) {
	ch := make(chan stewardDispatchResult, len(stewardIDs))

	for _, id := range stewardIDs {
		id := id
		_, publishErr := e.publisher.PublishCommandWithCallback(
			ctx, id,
			controlplaneTypes.CommandSyncConfig, params,
			rollbackTimeout,
			func(event *controlplaneTypes.Event) {
				success := event.Type == controlplaneTypes.EventCommandCompleted
				ch <- stewardDispatchResult{id, success}
			},
			func() {
				e.logger.Warn("Rollback dispatch timed out for steward",
					"steward_id", logging.SanitizeLogValue(id))
				ch <- stewardDispatchResult{id, false}
			},
		)
		if publishErr != nil {
			e.logger.Error("Failed to dispatch rollback to steward",
				"steward_id", logging.SanitizeLogValue(id), "error", publishErr)
			ch <- stewardDispatchResult{id, false}
		}
	}

	var failedIDs []string
	for range stewardIDs {
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
