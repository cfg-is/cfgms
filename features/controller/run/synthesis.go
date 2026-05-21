// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package run

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/features/controller/fleet"
	scriptmodule "github.com/cfgis/cfgms/features/modules/script"
)

// SynthesizeScriptRun resolves matching devices from the fleet and creates a
// RunRecord plus one JobRecord per device, each backed by a QueuedExecution.
// It returns the new run ID so callers can redirect to GET /runs/{run_id}.
//
// The filter is tenant-scoped: filter.TenantID is always overwritten with tenantID
// so that a principal cannot target devices outside its own tenant.
func SynthesizeScriptRun(
	ctx context.Context,
	manager *Manager,
	executionQueue *scriptmodule.ExecutionQueue,
	fleetQuery fleet.FleetQuery,
	tenantID, createdBy string,
	filter fleet.Filter,
	scriptRef, scriptVersion string,
	shell scriptmodule.ShellType,
	params map[string]string,
) (string, error) {
	filter.TenantID = tenantID

	devices, err := fleetQuery.Search(ctx, filter)
	if err != nil {
		return "", fmt.Errorf("synthesize script run: fleet search: %w", err)
	}

	runID := uuid.New().String()
	now := time.Now().UTC()

	run := &RunRecord{
		RunID:     runID,
		TenantID:  tenantID,
		CreatedBy: createdBy,
		CreatedAt: now,
		Status:    RunStatusPending,
		Filter:    filter,
		ScriptRef: scriptRef,
		Shell:     shell,
		JobCount:  len(devices),
	}
	if err := manager.store.CreateRun(run); err != nil {
		return "", fmt.Errorf("synthesize script run: create run: %w", err)
	}

	for _, device := range devices {
		jobID := uuid.New().String()
		executionID := uuid.New().String()

		job := &JobRecord{
			JobID:       jobID,
			RunID:       runID,
			DeviceID:    device.ID,
			ExecutionID: executionID,
			Status:      JobStatusPending,
			CreatedAt:   now,
		}
		if err := manager.store.CreateJob(job); err != nil {
			return "", fmt.Errorf("synthesize script run: create job for device %s: %w", device.ID, err)
		}

		qe := &scriptmodule.QueuedExecution{
			ExecutionID:   executionID,
			ScriptRef:     scriptRef,
			ScriptVersion: scriptVersion,
			Shell:         shell,
			Parameters:    params,
			Metadata: map[string]interface{}{
				"workflow_run_id": runID,
				"job_id":          jobID,
			},
		}
		if err := executionQueue.QueueExecution(device.ID, qe); err != nil {
			if errors.Is(err, scriptmodule.ErrDuplicateExecution) {
				continue
			}
			return "", fmt.Errorf("synthesize script run: enqueue for device %s: %w", device.ID, err)
		}
	}

	if err := manager.store.UpdateRunStatus(runID, RunStatusRunning); err != nil {
		return "", fmt.Errorf("synthesize script run: update run status: %w", err)
	}

	return runID, nil
}

// SynthesizeCommandRun resolves matching devices and creates a RunRecord plus one
// JobRecord per device for an inline (ad-hoc) script. Inline content is stored in
// QueuedExecution.Metadata["inline_script_content"]; actual delivery to the steward
// is handled by the dispatcher.
func SynthesizeCommandRun(
	ctx context.Context,
	manager *Manager,
	executionQueue *scriptmodule.ExecutionQueue,
	fleetQuery fleet.FleetQuery,
	tenantID, createdBy string,
	filter fleet.Filter,
	inlineContent string,
	shell scriptmodule.ShellType,
	params map[string]string,
) (string, error) {
	filter.TenantID = tenantID

	devices, err := fleetQuery.Search(ctx, filter)
	if err != nil {
		return "", fmt.Errorf("synthesize command run: fleet search: %w", err)
	}

	runID := uuid.New().String()
	now := time.Now().UTC()

	run := &RunRecord{
		RunID:         runID,
		TenantID:      tenantID,
		CreatedBy:     createdBy,
		CreatedAt:     now,
		Status:        RunStatusPending,
		Filter:        filter,
		InlineContent: inlineContent,
		Shell:         shell,
		JobCount:      len(devices),
	}
	if err := manager.store.CreateRun(run); err != nil {
		return "", fmt.Errorf("synthesize command run: create run: %w", err)
	}

	for _, device := range devices {
		jobID := uuid.New().String()
		executionID := uuid.New().String()

		job := &JobRecord{
			JobID:       jobID,
			RunID:       runID,
			DeviceID:    device.ID,
			ExecutionID: executionID,
			Status:      JobStatusPending,
			CreatedAt:   now,
		}
		if err := manager.store.CreateJob(job); err != nil {
			return "", fmt.Errorf("synthesize command run: create job for device %s: %w", device.ID, err)
		}

		qe := &scriptmodule.QueuedExecution{
			ExecutionID: executionID,
			Shell:       shell,
			Parameters:  params,
			Metadata: map[string]interface{}{
				"workflow_run_id":       runID,
				"job_id":                jobID,
				"inline_script_content": inlineContent,
			},
		}
		if err := executionQueue.QueueExecution(device.ID, qe); err != nil {
			if errors.Is(err, scriptmodule.ErrDuplicateExecution) {
				continue
			}
			return "", fmt.Errorf("synthesize command run: enqueue for device %s: %w", device.ID, err)
		}
	}

	if err := manager.store.UpdateRunStatus(runID, RunStatusRunning); err != nil {
		return "", fmt.Errorf("synthesize command run: update run status: %w", err)
	}

	return runID, nil
}
