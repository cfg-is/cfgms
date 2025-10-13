package script

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ExecutionQueue manages pending script executions for offline devices
type ExecutionQueue struct {
	queue      map[string][]*QueuedExecution // deviceID -> executions
	mu         sync.RWMutex
	monitor    *ExecutionMonitor
	keyManager *EphemeralKeyManager
	maxAge     time.Duration // Maximum time to keep queued executions
}

// QueuedExecution represents a script execution waiting for device to come online
type QueuedExecution struct {
	ExecutionID      string                 `json:"execution_id"`
	ScriptID         string                 `json:"script_id"`
	ScriptVersion    string                 `json:"script_version"`
	ScriptContent    string                 `json:"script_content"`
	Shell            ShellType              `json:"shell"`
	Parameters       map[string]string      `json:"parameters"`
	Environment      map[string]string      `json:"environment"`
	Timeout          time.Duration          `json:"timeout"`
	QueuedAt         time.Time              `json:"queued_at"`
	ExpiresAt        time.Time              `json:"expires_at"`
	GenerateAPIKey   bool                   `json:"generate_api_key"`
	APIKeyTTL        time.Duration          `json:"api_key_ttl"`
	APIKeyPermissions []string              `json:"api_key_permissions"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// NewExecutionQueue creates a new execution queue
func NewExecutionQueue(monitor *ExecutionMonitor, keyManager *EphemeralKeyManager, maxAge time.Duration) *ExecutionQueue {
	if maxAge == 0 {
		maxAge = 24 * time.Hour // Default: keep queued executions for 24 hours
	}

	queue := &ExecutionQueue{
		queue:      make(map[string][]*QueuedExecution),
		monitor:    monitor,
		keyManager: keyManager,
		maxAge:     maxAge,
	}

	// Start cleanup goroutine
	go queue.cleanupExpired()

	return queue
}

// QueueExecution queues a script execution for a device
func (q *ExecutionQueue) QueueExecution(deviceID string, execution *QueuedExecution) error {
	if execution.QueuedAt.IsZero() {
		execution.QueuedAt = time.Now()
	}

	if execution.ExpiresAt.IsZero() {
		execution.ExpiresAt = execution.QueuedAt.Add(q.maxAge)
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	if _, exists := q.queue[deviceID]; !exists {
		q.queue[deviceID] = make([]*QueuedExecution, 0)
	}

	q.queue[deviceID] = append(q.queue[deviceID], execution)

	return nil
}

// DequeueForDevice retrieves and removes all pending executions for a device
// This is called when a device comes online (heartbeat received)
func (q *ExecutionQueue) DequeueForDevice(deviceID string) ([]*QueuedExecution, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	executions, exists := q.queue[deviceID]
	if !exists || len(executions) == 0 {
		return nil, nil
	}

	// Remove expired executions
	validExecutions := make([]*QueuedExecution, 0)
	now := time.Now()
	for _, exec := range executions {
		if now.Before(exec.ExpiresAt) {
			validExecutions = append(validExecutions, exec)
		} else {
			// Mark as failed in monitor
			if q.monitor != nil {
				_ = q.monitor.UpdateDeviceStatus(
					exec.ExecutionID,
					deviceID,
					StatusFailed,
					nil,
					fmt.Errorf("execution expired while waiting for device to come online"),
				)
			}
		}
	}

	// Clear the queue for this device
	delete(q.queue, deviceID)

	return validExecutions, nil
}

// PeekForDevice returns pending executions without removing them
func (q *ExecutionQueue) PeekForDevice(deviceID string) []*QueuedExecution {
	q.mu.RLock()
	defer q.mu.RUnlock()

	executions, exists := q.queue[deviceID]
	if !exists {
		return nil
	}

	// Return a deep copy to prevent external modification
	result := make([]*QueuedExecution, len(executions))
	for i, exec := range executions {
		execCopy := *exec
		// Deep copy maps
		if exec.Parameters != nil {
			execCopy.Parameters = make(map[string]string, len(exec.Parameters))
			for k, v := range exec.Parameters {
				execCopy.Parameters[k] = v
			}
		}
		if exec.Environment != nil {
			execCopy.Environment = make(map[string]string, len(exec.Environment))
			for k, v := range exec.Environment {
				execCopy.Environment[k] = v
			}
		}
		if exec.APIKeyPermissions != nil {
			execCopy.APIKeyPermissions = make([]string, len(exec.APIKeyPermissions))
			copy(execCopy.APIKeyPermissions, exec.APIKeyPermissions)
		}
		if exec.Metadata != nil {
			execCopy.Metadata = make(map[string]interface{}, len(exec.Metadata))
			for k, v := range exec.Metadata {
				execCopy.Metadata[k] = v
			}
		}
		result[i] = &execCopy
	}
	return result
}

// GetQueueDepth returns the number of pending executions for a device
func (q *ExecutionQueue) GetQueueDepth(deviceID string) int {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if executions, exists := q.queue[deviceID]; exists {
		return len(executions)
	}
	return 0
}

// GetTotalQueueDepth returns the total number of pending executions across all devices
func (q *ExecutionQueue) GetTotalQueueDepth() int {
	q.mu.RLock()
	defer q.mu.RUnlock()

	total := 0
	for _, executions := range q.queue {
		total += len(executions)
	}
	return total
}

// CancelExecution removes a specific execution from the queue
func (q *ExecutionQueue) CancelExecution(deviceID, executionID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	executions, exists := q.queue[deviceID]
	if !exists {
		return fmt.Errorf("no queued executions for device %s", deviceID)
	}

	// Find and remove the execution
	for i, exec := range executions {
		if exec.ExecutionID == executionID {
			// Remove from slice
			q.queue[deviceID] = append(executions[:i], executions[i+1:]...)

			// Update monitor
			if q.monitor != nil {
				_ = q.monitor.UpdateDeviceStatus(
					executionID,
					deviceID,
					StatusCancelled,
					nil,
					nil,
				)
			}

			return nil
		}
	}

	return fmt.Errorf("execution %s not found in queue for device %s", executionID, deviceID)
}

// PrepareExecutionForDevice prepares an execution for immediate delivery to a device
// This generates ephemeral API keys just-in-time and injects parameters
func (q *ExecutionQueue) PrepareExecutionForDevice(ctx context.Context, deviceID, tenantID string, execution *QueuedExecution) (*PreparedExecution, error) {
	prepared := &PreparedExecution{
		ExecutionID:   execution.ExecutionID,
		ScriptID:      execution.ScriptID,
		ScriptVersion: execution.ScriptVersion,
		ScriptContent: execution.ScriptContent,
		Shell:         execution.Shell,
		Timeout:       execution.Timeout,
		Environment:   make(map[string]string),
		PreparedAt:    time.Now(),
	}

	// Copy environment variables
	for k, v := range execution.Environment {
		prepared.Environment[k] = v
	}

	// Generate ephemeral API key just-in-time if requested
	if execution.GenerateAPIKey && q.keyManager != nil {
		ttl := execution.APIKeyTTL
		if ttl == 0 {
			ttl = 1 * time.Hour // Default TTL
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

		// Add API key to environment
		prepared.Environment["CFGMS_API_KEY"] = apiKey.Key
		prepared.Environment["CFGMS_EXECUTION_ID"] = execution.ExecutionID
		prepared.Environment["CFGMS_DEVICE_ID"] = deviceID
		prepared.Environment["CFGMS_TENANT_ID"] = tenantID
		prepared.Environment["CFGMS_CONTROLLER_URL"] = "" // TODO: Get from config

		prepared.EphemeralKey = apiKey.Key
		prepared.KeyExpiresAt = apiKey.ExpiresAt
	}

	return prepared, nil
}

// PreparedExecution represents a script execution ready for immediate delivery
type PreparedExecution struct {
	ExecutionID   string            `json:"execution_id"`
	ScriptID      string            `json:"script_id"`
	ScriptVersion string            `json:"script_version"`
	ScriptContent string            `json:"script_content"`
	Shell         ShellType         `json:"shell"`
	Timeout       time.Duration     `json:"timeout"`
	Environment   map[string]string `json:"environment"`
	EphemeralKey  string            `json:"ephemeral_key,omitempty"`
	KeyExpiresAt  time.Time         `json:"key_expires_at,omitempty"`
	PreparedAt    time.Time         `json:"prepared_at"`
}

// cleanupExpired periodically removes expired executions
func (q *ExecutionQueue) cleanupExpired() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		q.performCleanup()
	}
}

// performCleanup removes expired executions and updates monitoring
func (q *ExecutionQueue) performCleanup() {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	expiredCount := 0

	for deviceID, executions := range q.queue {
		validExecutions := make([]*QueuedExecution, 0)

		for _, exec := range executions {
			if now.Before(exec.ExpiresAt) {
				validExecutions = append(validExecutions, exec)
			} else {
				// Mark as failed in monitor
				if q.monitor != nil {
					_ = q.monitor.UpdateDeviceStatus(
						exec.ExecutionID,
						deviceID,
						StatusFailed,
						nil,
						fmt.Errorf("execution expired while waiting for device (queued at %v, expired at %v)",
							exec.QueuedAt.Format(time.RFC3339),
							exec.ExpiresAt.Format(time.RFC3339)),
					)
				}
				expiredCount++
			}
		}

		if len(validExecutions) > 0 {
			q.queue[deviceID] = validExecutions
		} else {
			delete(q.queue, deviceID)
		}
	}

	if expiredCount > 0 {
		// Log cleanup (would use proper logger in production)
		_ = fmt.Sprintf("Cleaned up %d expired executions from queue", expiredCount)
	}
}

// ListQueuedExecutions returns all queued executions (for monitoring/debugging)
func (q *ExecutionQueue) ListQueuedExecutions() map[string][]*QueuedExecution {
	q.mu.RLock()
	defer q.mu.RUnlock()

	// Return a deep copy to prevent external modification
	result := make(map[string][]*QueuedExecution)
	for deviceID, executions := range q.queue {
		deviceExecs := make([]*QueuedExecution, len(executions))
		for i, exec := range executions {
			execCopy := *exec
			// Deep copy maps
			if exec.Parameters != nil {
				execCopy.Parameters = make(map[string]string, len(exec.Parameters))
				for k, v := range exec.Parameters {
					execCopy.Parameters[k] = v
				}
			}
			if exec.Environment != nil {
				execCopy.Environment = make(map[string]string, len(exec.Environment))
				for k, v := range exec.Environment {
					execCopy.Environment[k] = v
				}
			}
			if exec.APIKeyPermissions != nil {
				execCopy.APIKeyPermissions = make([]string, len(exec.APIKeyPermissions))
				copy(execCopy.APIKeyPermissions, exec.APIKeyPermissions)
			}
			if exec.Metadata != nil {
				execCopy.Metadata = make(map[string]interface{}, len(exec.Metadata))
				for k, v := range exec.Metadata {
					execCopy.Metadata[k] = v
				}
			}
			deviceExecs[i] = &execCopy
		}
		result[deviceID] = deviceExecs
	}

	return result
}

// GetStatistics returns queue statistics
func (q *ExecutionQueue) GetStatistics() QueueStatistics {
	q.mu.RLock()
	defer q.mu.RUnlock()

	stats := QueueStatistics{
		TotalDevicesWithQueue: len(q.queue),
		TotalQueuedExecutions: 0,
		OldestQueuedAt:        time.Now(),
		DeviceQueueDepths:     make(map[string]int),
	}

	now := time.Now()
	for deviceID, executions := range q.queue {
		stats.DeviceQueueDepths[deviceID] = len(executions)
		stats.TotalQueuedExecutions += len(executions)

		for _, exec := range executions {
			if exec.QueuedAt.Before(stats.OldestQueuedAt) {
				stats.OldestQueuedAt = exec.QueuedAt
			}

			if now.After(exec.ExpiresAt) {
				stats.ExpiredExecutions++
			}
		}
	}

	return stats
}

// QueueStatistics provides insights into the execution queue
type QueueStatistics struct {
	TotalDevicesWithQueue int            `json:"total_devices_with_queue"`
	TotalQueuedExecutions int            `json:"total_queued_executions"`
	ExpiredExecutions     int            `json:"expired_executions"`
	OldestQueuedAt        time.Time      `json:"oldest_queued_at"`
	DeviceQueueDepths     map[string]int `json:"device_queue_depths"`
}
