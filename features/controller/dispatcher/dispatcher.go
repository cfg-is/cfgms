// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package dispatcher drains the controller ExecutionQueue, sending pending
// script executions to stewards via the control plane.
//
// A per-device ownership lock (sync.Map[deviceID → chan struct{}] with capacity 1)
// ensures at most one job runs per steward at a time. The dispatcher fires on
// every heartbeat and on a configurable polling interval (default 30 s). On
// startup it fires once immediately to drain any executions queued before the
// dispatcher started.
package dispatcher

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/features/config/signature"
	script "github.com/cfgis/cfgms/features/modules/script"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

const (
	defaultPollInterval = 30 * time.Second
	// maxScriptContentBytes is the decoded size cap for script_content params.
	// gRPC default max recv is 4 MB; 1 MB decoded ≈ 1.33 MB base64 leaves margin.
	maxScriptContentBytes = 1 << 20 // 1 MiB
)

// Dispatcher drains the ExecutionQueue and sends CommandExecuteScript to stewards.
//
// Per-device serialization: a capacity-1 channel stored in deviceLocks acts as
// a mutex for each steward. The lock is acquired BEFORE calling DequeueForDevice
// (so nothing is dequeued when the device is already busy) and released only
// inside handleCompletionEvent or on send failure, ensuring exactly one
// execution is in-flight per device at any given time.
type Dispatcher struct {
	queue        *script.ExecutionQueue
	controlPlane controlplaneInterfaces.ControlPlaneProvider
	signer       signature.Signer // optional; when nil commands are sent unsigned
	// deviceLocks maps deviceID → chan struct{} (capacity 1).
	// A non-blocking send acquires the slot; a receive releases it.
	deviceLocks  sync.Map
	pollInterval time.Duration
	logger       logging.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// mu protects stopped. wg.Add must only be called when stopped is false
	// to prevent a race between external callbacks and wg.Wait in Stop.
	mu      sync.Mutex
	stopped bool
}

// Config holds Dispatcher configuration.
type Config struct {
	Queue        *script.ExecutionQueue
	ControlPlane controlplaneInterfaces.ControlPlaneProvider
	// Signer signs each CommandExecuteScript before transmission.
	// When nil commands are sent without a signature (unsecured/transitional mode).
	// Should be set to the same signer used by the command publisher so all
	// controller-issued commands carry consistent signatures.
	Signer signature.Signer
	// PollInterval is how often the background loop polls all devices.
	// Defaults to 30 s when zero.
	PollInterval time.Duration
	Logger       logging.Logger
}

// New creates a new Dispatcher. Call Start to begin operation.
func New(cfg *Config) (*Dispatcher, error) {
	if cfg.Queue == nil {
		return nil, fmt.Errorf("execution queue is required")
	}
	if cfg.ControlPlane == nil {
		return nil, fmt.Errorf("control plane provider is required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	interval := cfg.PollInterval
	if interval == 0 {
		interval = defaultPollInterval
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Dispatcher{
		queue:        cfg.Queue,
		controlPlane: cfg.ControlPlane,
		signer:       cfg.Signer,
		pollInterval: interval,
		logger:       cfg.Logger,
		ctx:          ctx,
		cancel:       cancel,
	}, nil
}

// Start begins the polling loop and subscribes to EventScriptCompleted events.
func (d *Dispatcher) Start(ctx context.Context) error {
	filter := &controlplaneTypes.EventFilter{
		EventTypes: []controlplaneTypes.EventType{controlplaneTypes.EventScriptCompleted},
	}
	if err := d.controlPlane.SubscribeEvents(ctx, filter, d.handleCompletionEvent); err != nil {
		return fmt.Errorf("dispatcher: subscribe events: %w", err)
	}

	d.wg.Add(1)
	go d.pollLoop()

	d.logger.Info("Job dispatcher started", "poll_interval", d.pollInterval)
	return nil
}

// Stop cancels the polling loop and waits for in-flight goroutines to exit.
func (d *Dispatcher) Stop() {
	d.cancel()
	// Mark as stopped under lock so concurrent external callers (OnHeartbeat,
	// handleCompletionEvent) see the flag before wg.Wait returns and wg reaches 0.
	d.mu.Lock()
	d.stopped = true
	d.mu.Unlock()
	d.wg.Wait()
	d.logger.Info("Job dispatcher stopped")
}

// tryAdd calls wg.Add(1) only if the dispatcher has not yet been stopped.
// Returns false if Stop has already been called — caller must not launch a goroutine.
func (d *Dispatcher) tryAdd() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped {
		return false
	}
	d.wg.Add(1)
	return true
}

// OnHeartbeat is called by the heartbeat service on every received heartbeat.
// It dispatches pending jobs for the given device without waiting for the poll cycle.
func (d *Dispatcher) OnHeartbeat(stewardID string) {
	if !d.tryAdd() {
		return
	}
	go func() {
		defer d.wg.Done()
		d.dispatchForDevice(d.ctx, stewardID)
	}()
}

// lockForDevice returns (or creates) the capacity-1 channel for deviceID.
func (d *Dispatcher) lockForDevice(deviceID string) chan struct{} {
	val, _ := d.deviceLocks.LoadOrStore(deviceID, make(chan struct{}, 1))
	return val.(chan struct{})
}

// tryAcquireDevice attempts a non-blocking send on the device's channel.
// Returns true if the lock was acquired, false if another dispatch is in-flight.
func (d *Dispatcher) tryAcquireDevice(deviceID string) bool {
	ch := d.lockForDevice(deviceID)
	select {
	case ch <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseDevice drains the device's channel, freeing the slot for the next dispatch.
func (d *Dispatcher) releaseDevice(deviceID string) {
	ch := d.lockForDevice(deviceID)
	select {
	case <-ch:
	default:
	}
}

// pollLoop fires dispatchAll immediately on startup, then on each poll interval tick.
func (d *Dispatcher) pollLoop() {
	defer d.wg.Done()

	// Drain on startup without waiting for the first tick.
	d.dispatchAll(d.ctx)

	ticker := time.NewTicker(d.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.dispatchAll(d.ctx)
		}
	}
}

// dispatchAll iterates all devices with pending executions and dispatches each.
func (d *Dispatcher) dispatchAll(ctx context.Context) {
	execsByDevice := d.queue.ListQueuedExecutions()
	for deviceID := range execsByDevice {
		if ctx.Err() != nil {
			return
		}
		deviceID := deviceID
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.dispatchForDevice(ctx, deviceID)
		}()
	}
}

// dispatchForDevice sends the next queued execution for a device.
//
// The per-device lock is acquired BEFORE calling DequeueForDevice. If the lock
// is already held (another execution is in-flight), the device is skipped
// entirely — its executions remain in queued state and will be dispatched on
// the next heartbeat or poll cycle after the current execution completes.
//
// The lock is released on error (before the command is sent) or by
// handleCompletionEvent when the steward reports completion.
func (d *Dispatcher) dispatchForDevice(ctx context.Context, deviceID string) {
	if ctx.Err() != nil {
		return
	}

	// Acquire per-device slot BEFORE dequeuing.
	if !d.tryAcquireDevice(deviceID) {
		// Another execution is in-flight for this device — skip this cycle.
		return
	}

	executions, err := d.queue.DequeueForDevice(deviceID)
	if err != nil {
		d.logger.Error("Failed to dequeue for device", "device_id", logging.SanitizeLogValue(deviceID), "error", err)
		d.releaseDevice(deviceID)
		return
	}

	if len(executions) == 0 {
		d.releaseDevice(deviceID)
		return
	}

	// Dispatch only the first execution to enforce one-job-per-device serialization.
	// Remaining executions (if any) were moved to dispatched state by DequeueForDevice;
	// the queue's background maintenance (RequeueStale) will move them back to queued
	// after dispatchTimeout so they can be picked up in a future cycle.
	exec := executions[0]

	prepared, err := d.queue.PrepareExecutionForDevice(ctx, deviceID, "", exec)
	if err != nil {
		d.logger.Error("Failed to prepare execution",
			"device_id", logging.SanitizeLogValue(deviceID),
			"execution_id", exec.ExecutionID,
			"error", err)
		d.releaseDevice(deviceID)
		return
	}

	if err := d.sendCommand(ctx, deviceID, exec, prepared); err != nil {
		d.logger.Error("Failed to send execute_script command",
			"device_id", logging.SanitizeLogValue(deviceID),
			"execution_id", exec.ExecutionID,
			"error", err)
		// Release lock — the dispatched entry will be re-queued by background maintenance.
		d.releaseDevice(deviceID)
		return
	}

	// Lock is intentionally NOT released here. It is held until handleCompletionEvent
	// receives the steward's EventScriptCompleted and calls releaseDevice. This ensures
	// no second execution is dispatched while the first is running.
}

// sendCommand builds and transmits a CommandExecuteScript via the control plane.
func (d *Dispatcher) sendCommand(ctx context.Context, deviceID string, exec *script.QueuedExecution, prepared *script.PreparedExecution) error {
	content := prepared.ScriptContent

	// Enforce decoded script content size cap before base64 encoding.
	if len(content) > maxScriptContentBytes {
		return fmt.Errorf("script exceeds maximum inline size of 1 MB (execution_id=%s, size=%d bytes)",
			exec.ExecutionID, len(content))
	}

	encodedContent := base64.StdEncoding.EncodeToString([]byte(content))

	params := map[string]interface{}{
		"execution_id":   exec.ExecutionID,
		"script_content": encodedContent,
		"shell":          string(exec.Shell),
	}

	if exec.ExecutionContext != "" {
		params["execution_context"] = string(exec.ExecutionContext)
	}

	if exec.Timeout > 0 {
		params["timeout_seconds"] = int64(exec.Timeout.Seconds())
	}

	if len(prepared.Environment) > 0 {
		params["environment"] = prepared.Environment
	}

	cmd := &controlplaneTypes.Command{
		ID:        uuid.New().String(),
		Type:      controlplaneTypes.CommandExecuteScript,
		StewardID: deviceID,
		Timestamp: time.Now(),
		Params:    params,
	}

	signed := &controlplaneTypes.SignedCommand{Command: *cmd}
	if d.signer != nil {
		rawParams := controlplaneTypes.InterfaceParamsToStringMap(cmd.Params)
		cmdBytes, err := controlplaneTypes.CommandSigningBytes(cmd, rawParams)
		if err != nil {
			return fmt.Errorf("marshal command for signing: %w", err)
		}
		sig, err := d.signer.Sign(cmdBytes)
		if err != nil {
			return fmt.Errorf("sign command: %w", err)
		}
		signed.Signature = sig
	}

	if err := d.controlPlane.SendCommand(ctx, signed); err != nil {
		return fmt.Errorf("send command: %w", err)
	}

	d.logger.Info("Sent execute_script command",
		"device_id", logging.SanitizeLogValue(deviceID),
		"execution_id", exec.ExecutionID,
		"shell", exec.Shell)

	return nil
}

// handleCompletionEvent processes EventScriptCompleted from stewards and calls
// AcknowledgeCompletion. The event's StewardID (from the mTLS-verified control
// plane connection) is used as the authoritative device identity — the
// execution_id field alone is never trusted, preventing a compromised steward
// from acknowledging another device's execution.
func (d *Dispatcher) handleCompletionEvent(ctx context.Context, event *controlplaneTypes.Event) error {
	if event.Type != controlplaneTypes.EventScriptCompleted {
		return nil
	}

	// StewardID is set by the control plane from the mTLS peer certificate.
	deviceID := event.StewardID
	if deviceID == "" {
		d.logger.Warn("Received script_completed event with empty steward_id — ignoring")
		return nil
	}

	var executionID string
	if event.Details != nil {
		executionID, _ = event.Details["execution_id"].(string)
	}
	if executionID == "" {
		d.logger.Warn("Received script_completed event with no execution_id",
			"device_id", logging.SanitizeLogValue(deviceID))
		return nil
	}

	// Determine completion state from exit code in event details.
	state := script.QueueStateCompleted
	if event.Details != nil {
		if exitCode, ok := event.Details["exit_code"].(float64); ok && exitCode != 0 {
			state = script.QueueStateFailed
		}
	}

	var result *script.ExecutionResult
	if event.Details != nil {
		result = &script.ExecutionResult{}
		if ec, ok := event.Details["exit_code"].(float64); ok {
			result.ExitCode = int(ec)
		}
		if stdout, ok := event.Details["stdout"].(string); ok {
			result.Stdout = stdout
		}
		if stderr, ok := event.Details["stderr"].(string); ok {
			result.Stderr = stderr
		}
		if durMs, ok := event.Details["duration_ms"].(float64); ok {
			result.Duration = time.Duration(durMs) * time.Millisecond
		}
	}

	if err := d.queue.AcknowledgeCompletion(executionID, deviceID, state, result); err != nil {
		d.logger.Error("Failed to acknowledge completion",
			"device_id", logging.SanitizeLogValue(deviceID),
			"execution_id", executionID,
			"error", err)
		// Still release the lock to prevent permanent stall.
	} else {
		d.logger.Info("Script execution completed",
			"device_id", logging.SanitizeLogValue(deviceID),
			"execution_id", executionID,
			"state", state)
	}

	// Release the per-device lock so the next queued execution can be dispatched.
	d.releaseDevice(deviceID)

	// Immediately try to dispatch the next queued execution for this device.
	// Use d.ctx (not the subscription ctx) so the goroutine exits on Stop.
	if d.tryAdd() {
		go func() {
			defer d.wg.Done()
			d.dispatchForDevice(d.ctx, deviceID)
		}()
	}

	return nil
}
