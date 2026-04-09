// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"context"
	"fmt"
	"time"
)

// ExecutionQueue manages pending script executions for offline devices.
// All state is persisted through a QueueStore, so executions survive controller
// restarts. The state machine enforces: queued → dispatched → completed/failed.
// Dispatched executions that receive no completion callback within dispatchTimeout
// are automatically re-queued for retry on next steward reconnect.
type ExecutionQueue struct {
	store           QueueStore
	scriptRepo      ScriptRepository // optional; used for latest-version content resolution
	monitor         *ExecutionMonitor
	keyManager      *EphemeralKeyManager
	maxAge          time.Duration  // Maximum time to keep queued executions
	dispatchTimeout time.Duration  // Maximum time a dispatched execution may wait before re-queue
	controllerURL   string         // Controller external URL for script callbacks
	stopCh          chan struct{}
}

// QueuedExecution represents a script execution waiting for a device to come online.
// ScriptRef identifies the script in the repository; actual content is resolved
// at dispatch time via ScriptRepository.Get(ScriptRef, "").
type QueuedExecution struct {
	ExecutionID       string                 `json:"execution_id"`
	ScriptID          string                 `json:"script_id"`
	ScriptVersion     string                 `json:"script_version"` // empty = resolve latest at dispatch
	ScriptRef         string                 `json:"script_ref"`     // script identifier in the repository
	Shell             ShellType              `json:"shell"`
	Parameters        map[string]string      `json:"parameters"`
	Environment       map[string]string      `json:"environment"`
	Timeout           time.Duration          `json:"timeout"`
	QueuedAt          time.Time              `json:"queued_at"`
	ExpiresAt         time.Time              `json:"expires_at"`
	State             QueueState             `json:"state"`
	GenerateAPIKey    bool                   `json:"generate_api_key"`
	APIKeyTTL         time.Duration          `json:"api_key_ttl"`
	APIKeyPermissions []string               `json:"api_key_permissions"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// NewExecutionQueue creates a new ExecutionQueue backed by the provided QueueStore.
//
// If store is nil, an InMemoryQueueStore is used (suitable for testing and dev).
// If scriptRepo is nil, PrepareExecutionForDevice will leave ScriptContent empty.
// If maxAge is 0, defaults to 24 hours.
// If dispatchTimeout is 0, defaults to 1 hour.
// If controllerURL is empty, defaults to "https://localhost:8080".
func NewExecutionQueue(
	monitor *ExecutionMonitor,
	keyManager *EphemeralKeyManager,
	maxAge time.Duration,
	controllerURL string,
	store QueueStore,
	scriptRepo ScriptRepository,
	dispatchTimeout time.Duration,
) *ExecutionQueue {
	if maxAge == 0 {
		maxAge = 24 * time.Hour
	}
	if dispatchTimeout == 0 {
		dispatchTimeout = 1 * time.Hour
	}
	if controllerURL == "" {
		controllerURL = "https://localhost:8080"
	}
	if store == nil {
		store = NewInMemoryQueueStore()
	}

	q := &ExecutionQueue{
		store:           store,
		scriptRepo:      scriptRepo,
		monitor:         monitor,
		keyManager:      keyManager,
		maxAge:          maxAge,
		dispatchTimeout: dispatchTimeout,
		controllerURL:   controllerURL,
		stopCh:          make(chan struct{}),
	}

	go q.backgroundMaintenance()

	return q
}

// QueueExecution queues a script execution for a device.
// Dedup: same ScriptRef + deviceID + parameters → ErrDuplicateExecution (silently ignored
// by the queue; callers may check if dedup is relevant to them).
func (q *ExecutionQueue) QueueExecution(deviceID string, execution *QueuedExecution) error {
	now := time.Now()
	if execution.QueuedAt.IsZero() {
		execution.QueuedAt = now
	}
	if execution.ExpiresAt.IsZero() {
		execution.ExpiresAt = execution.QueuedAt.Add(q.maxAge)
	}

	scriptRef := execution.ScriptRef
	if scriptRef == "" {
		scriptRef = execution.ScriptID
	}

	entry := &QueueEntry{
		ExecutionID:       execution.ExecutionID,
		DeviceID:          deviceID,
		ScriptRef:         scriptRef,
		Shell:             execution.Shell,
		Parameters:        execution.Parameters,
		Environment:       execution.Environment,
		Timeout:           execution.Timeout,
		QueuedAt:          execution.QueuedAt,
		ExpiresAt:         execution.ExpiresAt,
		State:             QueueStateQueued,
		ParamHash:         ComputeParamHash(scriptRef, deviceID, execution.Parameters),
		GenerateAPIKey:    execution.GenerateAPIKey,
		APIKeyTTL:         execution.APIKeyTTL,
		APIKeyPermissions: execution.APIKeyPermissions,
		Metadata:          execution.Metadata,
	}

	if err := q.store.Enqueue(entry); err != nil {
		if err == ErrDuplicateExecution {
			// Dedup: silently ignore duplicate queued executions
			return nil
		}
		return fmt.Errorf("failed to enqueue execution: %w", err)
	}

	return nil
}

// DequeueForDevice retrieves all pending executions for a device and transitions
// them to the dispatched state. This is called when a device comes online (heartbeat
// received). It also re-dispatches any previously-dispatched executions that the
// steward has not yet reported completion for (handles steward reconnect).
func (q *ExecutionQueue) DequeueForDevice(deviceID string) ([]*QueuedExecution, error) {
	entries, err := q.store.Dequeue(deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to dequeue for device %s: %w", deviceID, err)
	}

	if len(entries) == 0 {
		return nil, nil
	}

	result := make([]*QueuedExecution, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entryToQueued(entry))
	}

	return result, nil
}

// PeekForDevice returns pending (queued + dispatched) executions without changing state.
func (q *ExecutionQueue) PeekForDevice(deviceID string) []*QueuedExecution {
	entries, err := q.store.List(deviceID)
	if err != nil {
		return nil
	}

	result := make([]*QueuedExecution, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entryToQueued(entry))
	}

	return result
}

// GetQueueDepth returns the number of active (queued + dispatched) executions for a device.
func (q *ExecutionQueue) GetQueueDepth(deviceID string) int {
	entries, err := q.store.List(deviceID)
	if err != nil {
		return 0
	}
	return len(entries)
}

// GetTotalQueueDepth returns the total number of active executions across all devices.
func (q *ExecutionQueue) GetTotalQueueDepth() int {
	entries, err := q.store.List("")
	if err != nil {
		return 0
	}
	return len(entries)
}

// CancelExecution removes a specific execution from the active queue.
func (q *ExecutionQueue) CancelExecution(deviceID, executionID string) error {
	if err := q.store.Cancel(deviceID, executionID); err != nil {
		return err
	}

	if q.monitor != nil {
		// UpdateDeviceStatus is best-effort: the monitor may not have an entry for
		// every queued execution (tracking is optional). Ignore the error intentionally.
		_ = q.monitor.UpdateDeviceStatus(executionID, deviceID, StatusCancelled, nil, nil) //nolint:errcheck // monitor is optional audit side-channel
	}

	return nil
}

// AcknowledgeCompletion records the completion of a dispatched execution.
// This is called when the steward reports back with the execution result.
// state must be QueueStateCompleted or QueueStateFailed.
func (q *ExecutionQueue) AcknowledgeCompletion(executionID, deviceID string, state QueueState, result *ExecutionResult) error {
	if err := q.store.AcknowledgeCompletion(executionID, deviceID, state, result); err != nil {
		return fmt.Errorf("failed to acknowledge completion: %w", err)
	}

	if q.monitor != nil {
		var monitorStatus ExecutionStatus
		switch state {
		case QueueStateCompleted:
			monitorStatus = StatusCompleted
		default:
			monitorStatus = StatusFailed
		}
		// UpdateDeviceStatus is best-effort: the monitor may not have an entry for
		// every queued execution (tracking is optional). Ignore the error intentionally.
		_ = q.monitor.UpdateDeviceStatus(executionID, deviceID, monitorStatus, result, nil) //nolint:errcheck // monitor is optional audit side-channel
	}

	return nil
}

// PrepareExecutionForDevice prepares an execution for immediate delivery to a device.
// It generates ephemeral API keys just-in-time and resolves the latest script content
// from the script repository.
func (q *ExecutionQueue) PrepareExecutionForDevice(ctx context.Context, deviceID, tenantID string, execution *QueuedExecution) (*PreparedExecution, error) {
	scriptRef := execution.ScriptRef
	if scriptRef == "" {
		scriptRef = execution.ScriptID
	}

	// Resolve latest script content from repository
	var resolvedContent string
	var resolvedVersion string

	if q.scriptRepo != nil && scriptRef != "" {
		pinVersion := execution.ScriptVersion // empty = resolve latest
		script, err := q.scriptRepo.Get(scriptRef, pinVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve script %q from repository: %w", scriptRef, err)
		}
		resolvedContent = script.Content
		resolvedVersion = script.Metadata.Version.String()
	}

	prepared := &PreparedExecution{
		ExecutionID:   execution.ExecutionID,
		ScriptID:      execution.ScriptID,
		ScriptVersion: resolvedVersion,
		ScriptContent: resolvedContent,
		Shell:         execution.Shell,
		Timeout:       execution.Timeout,
		Environment:   make(map[string]string),
		PreparedAt:    time.Now(),
	}

	for k, v := range execution.Environment {
		prepared.Environment[k] = v
	}

	// Generate ephemeral API key just-in-time if requested
	if execution.GenerateAPIKey && q.keyManager != nil {
		ttl := execution.APIKeyTTL
		if ttl == 0 {
			ttl = 1 * time.Hour
		}

		permissions := execution.APIKeyPermissions
		if len(permissions) == 0 {
			permissions = ScriptCallbackPermissions()
		}

		apiKey, err := q.keyManager.GenerateKey(
			execution.ScriptID,
			execution.ExecutionID,
			tenantID,
			deviceID,
			ttl,
			permissions,
			0, // unlimited usage
		)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral API key: %w", err)
		}

		prepared.Environment["CFGMS_API_KEY"] = apiKey.Key
		prepared.Environment["CFGMS_EXECUTION_ID"] = execution.ExecutionID
		prepared.Environment["CFGMS_DEVICE_ID"] = deviceID
		prepared.Environment["CFGMS_TENANT_ID"] = tenantID
		prepared.Environment["CFGMS_CONTROLLER_URL"] = q.controllerURL

		prepared.EphemeralKey = apiKey.Key
		prepared.KeyExpiresAt = apiKey.ExpiresAt
	}

	return prepared, nil
}

// PreparedExecution represents a script execution ready for immediate delivery.
type PreparedExecution struct {
	ExecutionID   string            `json:"execution_id"`
	ScriptID      string            `json:"script_id"`
	ScriptVersion string            `json:"script_version"` // resolved version
	ScriptContent string            `json:"script_content"` // resolved content
	Shell         ShellType         `json:"shell"`
	Timeout       time.Duration     `json:"timeout"`
	Environment   map[string]string `json:"environment"`
	EphemeralKey  string            `json:"ephemeral_key,omitempty"`
	KeyExpiresAt  time.Time         `json:"key_expires_at,omitempty"`
	PreparedAt    time.Time         `json:"prepared_at"`
}

// ListQueuedExecutions returns all active (queued + dispatched) executions.
func (q *ExecutionQueue) ListQueuedExecutions() map[string][]*QueuedExecution {
	entries, err := q.store.List("")
	if err != nil {
		return make(map[string][]*QueuedExecution)
	}

	result := make(map[string][]*QueuedExecution)
	for _, entry := range entries {
		result[entry.DeviceID] = append(result[entry.DeviceID], entryToQueued(entry))
	}

	return result
}

// GetStatistics returns queue statistics.
func (q *ExecutionQueue) GetStatistics() QueueStatistics {
	stats, err := q.store.GetStats()
	if err != nil {
		return QueueStatistics{
			DeviceQueueDepths: make(map[string]int),
		}
	}

	return QueueStatistics{
		TotalDevicesWithQueue: len(stats.DeviceQueueDepths),
		TotalQueuedExecutions: stats.QueuedCount + stats.DispatchedCount,
		ExpiredExecutions:     stats.ExpiredCount,
		DeviceQueueDepths:     stats.DeviceQueueDepths,
	}
}

// QueueStatistics provides insights into the execution queue.
type QueueStatistics struct {
	TotalDevicesWithQueue int            `json:"total_devices_with_queue"`
	TotalQueuedExecutions int            `json:"total_queued_executions"`
	ExpiredExecutions     int            `json:"expired_executions"`
	OldestQueuedAt        time.Time      `json:"oldest_queued_at"`
	DeviceQueueDepths     map[string]int `json:"device_queue_depths"`
}

// backgroundMaintenance runs periodic queue maintenance until Stop is called.
func (q *ExecutionQueue) backgroundMaintenance() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			q.performMaintenance()
		case <-q.stopCh:
			return
		}
	}
}

// performMaintenance expires stale queued entries and re-queues timed-out dispatched entries.
func (q *ExecutionQueue) performMaintenance() {
	// Expire queued entries past their TTL.
	// CleanupExpired errors are intentionally ignored: the InMemoryQueueStore never
	// errors here, and a future durable store failure leaves entries in a safe state
	// (they remain queued and will be expired on the next maintenance cycle).
	_, _ = q.store.CleanupExpired() //nolint:errcheck // best-effort background cleanup; entries stay safe on error

	// Re-queue dispatched entries that never received a completion callback.
	// RequeueStale errors are intentionally ignored for the same reason: a failure
	// leaves dispatched entries in place and they will be retried next cycle.
	_, _ = q.store.RequeueStale(q.dispatchTimeout) //nolint:errcheck // best-effort background maintenance; entries stay safe on error
}

// Stop halts the background maintenance goroutine.
func (q *ExecutionQueue) Stop() {
	close(q.stopCh)
}

// entryToQueued converts a QueueEntry to a QueuedExecution for API compatibility.
func entryToQueued(entry *QueueEntry) *QueuedExecution {
	exec := &QueuedExecution{
		ExecutionID:       entry.ExecutionID,
		ScriptID:          entry.ScriptRef, // ScriptRef doubles as ScriptID
		ScriptRef:         entry.ScriptRef,
		Shell:             entry.Shell,
		Timeout:           entry.Timeout,
		QueuedAt:          entry.QueuedAt,
		ExpiresAt:         entry.ExpiresAt,
		State:             entry.State,
		GenerateAPIKey:    entry.GenerateAPIKey,
		APIKeyTTL:         entry.APIKeyTTL,
		APIKeyPermissions: entry.APIKeyPermissions,
	}

	if entry.Parameters != nil {
		exec.Parameters = make(map[string]string, len(entry.Parameters))
		for k, v := range entry.Parameters {
			exec.Parameters[k] = v
		}
	}

	if entry.Environment != nil {
		exec.Environment = make(map[string]string, len(entry.Environment))
		for k, v := range entry.Environment {
			exec.Environment[k] = v
		}
	}

	if entry.APIKeyPermissions != nil {
		exec.APIKeyPermissions = make([]string, len(entry.APIKeyPermissions))
		copy(exec.APIKeyPermissions, entry.APIKeyPermissions)
	}

	if entry.Metadata != nil {
		exec.Metadata = make(map[string]interface{}, len(entry.Metadata))
		for k, v := range entry.Metadata {
			exec.Metadata[k] = v
		}
	}

	return exec
}
