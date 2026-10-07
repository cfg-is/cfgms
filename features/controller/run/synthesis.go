// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/features/controller/fleet"
	scriptmodule "github.com/cfgis/cfgms/features/modules/stdlib/script"
)

// CommandSignature is the operator signature over inline ad-hoc content. It is
// carried unchanged from the authenticated HTTP request to steward verification.
//
// Algorithm, Value and PublicKey are the X.509 credential; the WebAuthn fields are
// the passkey assertion and the roster manifest a steward needs to verify it. A
// steward action carries exactly one of the two.
type CommandSignature struct {
	Algorithm string
	Value     string
	PublicKey string

	WebAuthnAuthenticatorData string
	WebAuthnClientDataJSON    string
	WebAuthnSignature         string
	WebAuthnCredentialID      string
	WebAuthnManifest          string
}

// HasProof reports whether the signature carries a complete X.509 or WebAuthn
// operator credential.
func (c *CommandSignature) HasProof() bool {
	if c == nil {
		return false
	}
	x509 := c.Algorithm != "" && c.Value != "" && c.PublicKey != ""
	webauthn := c.WebAuthnAuthenticatorData != "" && c.WebAuthnClientDataJSON != "" &&
		c.WebAuthnSignature != "" && c.WebAuthnCredentialID != ""
	return x509 || webauthn
}

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
	return SynthesizeScriptRunForDevices(ctx, manager, executionQueue, devices, tenantID, createdBy, filter,
		scriptRef, scriptVersion, shell, runtimeParams, scriptMeta, paramPlatformBindings, requiredAPIScope)
}

// SynthesizeScriptRunForDevices is SynthesizeScriptRun over an already-resolved
// device list: the caller that authorized exactly these devices dispatches
// exactly these devices, with no second fleet search in between (Issue #4554).
// filter is recorded on the run for display only.
func SynthesizeScriptRunForDevices(
	ctx context.Context,
	manager *Manager,
	executionQueue *scriptmodule.ExecutionQueue,
	devices []fleet.StewardResult,
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
//
// targets, nonce, and expiresAt (Issue #3694) are the operator's signed
// operatorpayload.Envelope coordinates, forwarded into QueuedExecution.Metadata
// unmodified alongside commandSignature so the dispatcher can pass them on to the
// steward, which independently verifies target membership, expiry, and nonce replay.
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
	commandSignature *CommandSignature,
	targets []string,
	nonce string,
	expiresAt time.Time,
) (string, error) {
	filter.TenantID = tenantID
	devices, err := fleetQuery.Search(ctx, filter)
	if err != nil {
		return "", fmt.Errorf("synthesize command run: fleet search: %w", err)
	}
	return SynthesizeCommandRunForDevices(ctx, manager, executionQueue, devices, tenantID, createdBy, filter,
		inlineContent, shell, params, commandSignature, targets, nonce, expiresAt)
}

// SynthesizeCommandRunForDevices is SynthesizeCommandRun over an already-resolved
// device list: the caller that authorized exactly these devices dispatches
// exactly these devices, with no second fleet search in between (Issue #4554).
// filter is recorded on the run for display only.
func SynthesizeCommandRunForDevices(
	ctx context.Context,
	manager *Manager,
	executionQueue *scriptmodule.ExecutionQueue,
	devices []fleet.StewardResult,
	tenantID, createdBy string,
	filter fleet.Filter,
	inlineContent string,
	shell scriptmodule.ShellType,
	params map[string]string,
	commandSignature *CommandSignature,
	targets []string,
	nonce string,
	expiresAt time.Time,
) (string, error) {
	filter.TenantID = tenantID

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

		metadata := map[string]interface{}{
			"workflow_run_id":       runID,
			"job_id":                jobID,
			"inline_script_content": inlineContent,
		}
		if commandSignature != nil {
			metadata["signature_algorithm"] = commandSignature.Algorithm
			metadata["signature_value"] = commandSignature.Value
			metadata["signature_public_key"] = commandSignature.PublicKey
			metadata["targets"] = targets
			metadata["nonce"] = nonce
			metadata["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
		}

		qe := &scriptmodule.QueuedExecution{
			ExecutionID: executionID,
			Shell:       shell,
			Parameters:  resolved,
			Metadata:    metadata,
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

// SynthesizeActionRunForDevices creates a steward-action RunRecord plus one
// JobRecord per device, each backed by a QueuedExecution of kind steward_action
// (Issue #4625). Like SynthesizeCommandRunForDevices it takes the already-authorized
// device list and the operator's CommandSignature, and forwards the proof, nonce,
// expiry and targets into the queue entry Metadata unmodified so whichever
// node dispatches the entry sends exactly what the operator signed. The
// controller never re-signs or strips that envelope.
//
// Each entry expires after scriptmodule.StewardActionTTL — a stale "stop service"
// must not fire when a steward reconnects later — and carries
// scriptmodule.StewardActionTimeout, so a steward that never reports releases
// its device slot instead of blocking the device's other runs.
func SynthesizeActionRunForDevices(
	_ context.Context,
	manager *Manager,
	executionQueue *scriptmodule.ExecutionQueue,
	devices []fleet.StewardResult,
	tenantID, createdBy string,
	filter fleet.Filter,
	action scriptmodule.StewardActionSpec,
	commandSignature *CommandSignature,
	targets []string,
	nonce string,
	expiresAt time.Time,
) (string, error) {
	if !commandSignature.HasProof() {
		return "", errors.New("synthesize action run: operator proof is required")
	}
	actionJSON, err := json.Marshal(action)
	if err != nil {
		return "", fmt.Errorf("synthesize action run: marshal action: %w", err)
	}
	filter.TenantID = tenantID

	runID := uuid.New().String()
	now := time.Now().UTC()

	run := &RunRecord{
		RunID:      runID,
		TenantID:   tenantID,
		CreatedBy:  createdBy,
		CreatedAt:  now,
		Status:     RunStatusPending,
		Filter:     filter,
		JobCount:   len(devices),
		Kind:       RunKindStewardAction,
		ActionJSON: actionJSON,
	}
	if err := manager.store.CreateRun(run); err != nil {
		return "", fmt.Errorf("synthesize action run: create run: %w", err)
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
			return "", fmt.Errorf("synthesize action run: create job for device %s: %w", device.ID, err)
		}

		metadata := map[string]interface{}{
			"workflow_run_id": runID,
			"job_id":          jobID,
			"tenant_id":       tenantID,
			"created_by":      createdBy, // read back to attribute the completion audit event
			"targets":         targets,
			"nonce":           nonce,
			"expires_at":      expiresAt.UTC().Format(time.RFC3339),
		}
		for key, value := range map[string]string{
			"signature_algorithm":         commandSignature.Algorithm,
			"signature_value":             commandSignature.Value,
			"signature_public_key":        commandSignature.PublicKey,
			"webauthn_authenticator_data": commandSignature.WebAuthnAuthenticatorData,
			"webauthn_client_data_json":   commandSignature.WebAuthnClientDataJSON,
			"webauthn_signature":          commandSignature.WebAuthnSignature,
			"webauthn_credential_id":      commandSignature.WebAuthnCredentialID,
			"webauthn_manifest":           commandSignature.WebAuthnManifest,
		} {
			if value != "" {
				metadata[key] = value
			}
		}

		spec := action
		qe := &scriptmodule.QueuedExecution{
			ExecutionID: executionID,
			Kind:        scriptmodule.QueueKindStewardAction,
			Action:      &spec,
			Timeout:     scriptmodule.StewardActionTimeout,
			QueuedAt:    now,
			ExpiresAt:   now.Add(scriptmodule.StewardActionTTL),
			Metadata:    metadata,
		}
		if err := executionQueue.QueueExecution(device.ID, qe); err != nil {
			if errors.Is(err, scriptmodule.ErrDuplicateExecution) {
				continue
			}
			return "", fmt.Errorf("synthesize action run: enqueue for device %s: %w", device.ID, err)
		}
	}

	if err := manager.store.UpdateRunStatus(runID, RunStatusRunning); err != nil {
		return "", fmt.Errorf("synthesize action run: update run status: %w", err)
	}

	return runID, nil
}
