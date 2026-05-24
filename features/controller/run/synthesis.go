// SPDX-License-Identifier: AGPL-3.0-only
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
//
// runtimeParams are operator-supplied overrides. scriptMeta (optional) and
// paramPlatformBindings (optional) drive per-device parameter resolution via
// ResolveParams; when scriptMeta is nil the runtime params are used as-is.
//
// requiredAPIScope is the script's stored RequiredAPIScope from ScriptPrivilegeMetadata.
// When non-empty it is threaded into QueuedExecution.Metadata so the dispatcher can
// create a JIT relay grant at dispatch time (Issue #1675).
func SynthesizeScriptRun(
	ctx context.Context,
	manager *Manager,
	executionQueue *scriptmodule.ExecutionQueue,
	fleetQuery fleet.FleetQuery,
	tenantID, createdBy string,
	filter fleet.Filter,
	scriptRef, scriptVersion string,
	shell scriptmodule.ShellType,
	runtimeParams map[string]string,
	scriptMeta *scriptmodule.ScriptMetadata,
	paramPlatformBindings map[string]string,
	requiredAPIScope []string,
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

	idempotent := scriptMeta != nil && scriptMeta.Idempotent

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

		resolved, err := ResolveParams(nil, scriptMeta, paramPlatformBindings, runtimeParams, device.DNAAttributes)
		if err != nil {
			return "", fmt.Errorf("synthesize script run: resolve params for device %s: %w", device.ID, err)
		}

		meta := map[string]interface{}{
			"workflow_run_id": runID,
			"job_id":          jobID,
			"tenant_id":       tenantID,
		}
		if idempotent {
			meta["idempotent"] = true
		}
		if len(requiredAPIScope) > 0 {
			meta["required_api_scope"] = requiredAPIScope
		}

		qe := &scriptmodule.QueuedExecution{
			ExecutionID:   executionID,
			ScriptRef:     scriptRef,
			ScriptVersion: scriptVersion,
			Shell:         shell,
			Parameters:    resolved,
			Metadata:      meta,
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
//
// Runtime params are resolved per-device via ResolveParams. Inline scripts have no
// declared parameters, so DNA bindings do not apply and runtimeParams are passed
// through unchanged.
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

		// Inline scripts have no declared parameters; nil metadata means ResolveParams
		// passes runtime params through unchanged.
		resolved, err := ResolveParams(nil, nil, nil, params, device.DNAAttributes)
		if err != nil {
			return "", fmt.Errorf("synthesize command run: resolve params for device %s: %w", device.ID, err)
		}

		qe := &scriptmodule.QueuedExecution{
			ExecutionID: executionID,
			Shell:       shell,
			Parameters:  resolved,
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
