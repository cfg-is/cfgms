// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// QueueState represents the lifecycle state of a queued execution.
// Valid transitions: queued → dispatched → completed | failed
//
//	queued → expired (TTL elapsed before dispatch)
//	queued | dispatched → cancelled (explicit cancellation)
//	dispatched → queued (dispatch timeout exceeded; re-queued for retry)
type QueueState string

const (
	// QueueStateQueued means the execution is waiting for the device to come online.
	QueueStateQueued QueueState = "queued"

	// QueueStateDispatched means the execution was sent to the steward,
	// awaiting a completion callback.
	QueueStateDispatched QueueState = "dispatched"

	// QueueStateCompleted means the execution finished successfully.
	QueueStateCompleted QueueState = "completed"

	// QueueStateFailed means the execution finished with an error.
	QueueStateFailed QueueState = "failed"

	// QueueStateExpired means the execution was never dispatched before its TTL elapsed.
	QueueStateExpired QueueState = "expired"

	// QueueStateCancelled means the execution was explicitly cancelled.
	QueueStateCancelled QueueState = "cancelled"
)

// ErrDuplicateExecution is returned by Enqueue when an entry with the same
// ParamHash already exists in the queued state for the same device.
var ErrDuplicateExecution = errors.New("duplicate execution: identical script+device+params already queued")

// QueueEntry is the durable record stored by a QueueStore.
type QueueEntry struct {
	ExecutionID       string                 `json:"execution_id"`
	DeviceID          string                 `json:"device_id"`
	TenantID          string                 `json:"tenant_id"`
	ScriptRef         string                 `json:"script_ref"` // Script identifier in the repository (used for latest-version lookup)
	Shell             ShellType              `json:"shell"`
	Parameters        map[string]string      `json:"parameters,omitempty"`
	Environment       map[string]string      `json:"environment,omitempty"`
	Timeout           time.Duration          `json:"timeout"`
	QueuedAt          time.Time              `json:"queued_at"`
	ExpiresAt         time.Time              `json:"expires_at"`
	DispatchedAt      *time.Time             `json:"dispatched_at,omitempty"`
	CompletedAt       *time.Time             `json:"completed_at,omitempty"`
	State             QueueState             `json:"state"`
	ParamHash         string                 `json:"param_hash"` // Dedup key: ComputeParamHash(scriptRef, deviceID, parameters)
	GenerateAPIKey    bool                   `json:"generate_api_key"`
	APIKeyTTL         time.Duration          `json:"api_key_ttl"`
	APIKeyPermissions []string               `json:"api_key_permissions,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// QueueStoreStats provides aggregate statistics about the queue store.
type QueueStoreStats struct {
	TotalEntries      int            `json:"total_entries"`
	QueuedCount       int            `json:"queued_count"`
	DispatchedCount   int            `json:"dispatched_count"`
	CompletedCount    int            `json:"completed_count"`
	FailedCount       int            `json:"failed_count"`
	ExpiredCount      int            `json:"expired_count"`
	CancelledCount    int            `json:"cancelled_count"`
	DeviceQueueDepths map[string]int `json:"device_queue_depths"` // counts only queued+dispatched
}

// QueueStore defines the persistence contract for the durable execution queue.
// This is a feature-local interface (NOT a central provider) used exclusively by
// the script module.
//
// Implementations MUST be thread-safe.
type QueueStore interface {
	// Enqueue adds a new execution entry to the store.
	// Returns ErrDuplicateExecution if an entry with the same ParamHash already
	// exists in the queued state for the same device.
	Enqueue(entry *QueueEntry) error

	// Dequeue returns all queued entries AND any previously-dispatched (not yet
	// acknowledged) entries for the given device, transitioning them all to the
	// dispatched state. This handles both initial dispatch and re-dispatch when
	// a steward reconnects without reporting completion.
	Dequeue(deviceID string) ([]*QueueEntry, error)

	// AcknowledgeCompletion transitions a dispatched entry to completed or failed.
	// The state parameter MUST be QueueStateCompleted or QueueStateFailed.
	AcknowledgeCompletion(executionID, deviceID string, state QueueState, result *ExecutionResult) error

	// Cancel transitions a queued or dispatched entry to the cancelled state.
	// Returns an error if the entry does not exist or is not cancellable.
	Cancel(deviceID, executionID string) error

	// RequeueStale finds dispatched entries whose DispatchedAt time exceeds
	// the given timeout and transitions them back to queued for retry.
	// Returns the count of re-queued entries.
	RequeueStale(dispatchTimeout time.Duration) (int, error)

	// CleanupExpired marks queued entries past their ExpiresAt as expired.
	// Returns the count of entries marked expired.
	CleanupExpired() (int, error)

	// List returns active entries (queued + dispatched) for the given device.
	// Pass an empty deviceID to list active entries across all devices.
	List(deviceID string) ([]*QueueEntry, error)

	// GetStats returns aggregate statistics about the queue.
	GetStats() (QueueStoreStats, error)
}

// ComputeParamHash computes the dedup key for an execution:
// sha256(scriptRef + "|" + deviceID + "|" + sorted_json(parameters))
func ComputeParamHash(scriptRef, deviceID string, parameters map[string]string) string {
	// Sort parameter keys for deterministic serialization
	keys := make([]string, 0, len(parameters))
	for k := range parameters {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	sorted := make(map[string]string, len(parameters))
	for _, k := range keys {
		sorted[k] = parameters[k]
	}

	paramsJSON, _ := json.Marshal(sorted)

	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|", scriptRef, deviceID)
	h.Write(paramsJSON)

	return fmt.Sprintf("%x", h.Sum(nil))
}

// ----------------------------------------------------------------------------
// InMemoryQueueStore
// ----------------------------------------------------------------------------

// InMemoryQueueStore implements QueueStore using in-memory storage.
// It is suitable for testing, development, and as the default backend when
// no durable store is configured. Because the store is a separate object from
// ExecutionQueue, creating a new ExecutionQueue with the same store instance
// simulates a controller restart with durable state preserved.
type InMemoryQueueStore struct {
	entries map[string]*QueueEntry // executionID → entry
	mu      sync.RWMutex
}

// NewInMemoryQueueStore creates a new InMemoryQueueStore.
func NewInMemoryQueueStore() QueueStore {
	return &InMemoryQueueStore{
		entries: make(map[string]*QueueEntry),
	}
}

// Enqueue adds an entry to the store, enforcing dedup on (deviceID, paramHash).
func (s *InMemoryQueueStore) Enqueue(entry *QueueEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Dedup: reject if an identical execution is already queued for the same device
	for _, existing := range s.entries {
		if existing.DeviceID == entry.DeviceID &&
			existing.ParamHash == entry.ParamHash &&
			existing.State == QueueStateQueued {
			return ErrDuplicateExecution
		}
	}

	s.entries[entry.ExecutionID] = s.cloneEntry(entry)
	return nil
}

// Dequeue returns and transitions all actionable entries for a device to dispatched.
func (s *InMemoryQueueStore) Dequeue(deviceID string) ([]*QueueEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	result := make([]*QueueEntry, 0)

	for _, entry := range s.entries {
		if entry.DeviceID != deviceID {
			continue
		}

		switch entry.State {
		case QueueStateQueued:
			if now.After(entry.ExpiresAt) {
				entry.State = QueueStateExpired
				continue
			}
			entry.State = QueueStateDispatched
			t := now
			entry.DispatchedAt = &t
			result = append(result, s.cloneEntry(entry))

		case QueueStateDispatched:
			// Steward reconnected without reporting completion — re-dispatch
			result = append(result, s.cloneEntry(entry))
		}
	}

	return result, nil
}

// AcknowledgeCompletion marks a dispatched entry as completed or failed.
func (s *InMemoryQueueStore) AcknowledgeCompletion(executionID, deviceID string, state QueueState, _ *ExecutionResult) error {
	if state != QueueStateCompleted && state != QueueStateFailed {
		return fmt.Errorf("invalid completion state %q: must be completed or failed", state)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.entries[executionID]
	if !exists || entry.DeviceID != deviceID {
		return fmt.Errorf("execution %s not found for device %s", executionID, deviceID)
	}

	if entry.State != QueueStateDispatched {
		return fmt.Errorf("execution %s is in state %q, expected dispatched", executionID, entry.State)
	}

	entry.State = state
	now := time.Now()
	entry.CompletedAt = &now
	return nil
}

// Cancel transitions a queued or dispatched entry to the cancelled state.
func (s *InMemoryQueueStore) Cancel(deviceID, executionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if device has any active entries at all
	deviceHasEntries := false
	for _, e := range s.entries {
		if e.DeviceID == deviceID && (e.State == QueueStateQueued || e.State == QueueStateDispatched) {
			deviceHasEntries = true
			break
		}
	}

	if !deviceHasEntries {
		return fmt.Errorf("no queued executions for device %s", deviceID)
	}

	entry, exists := s.entries[executionID]
	if !exists || entry.DeviceID != deviceID {
		return fmt.Errorf("execution %s not found in queue for device %s", executionID, deviceID)
	}

	switch entry.State {
	case QueueStateQueued, QueueStateDispatched:
		entry.State = QueueStateCancelled
		return nil
	default:
		return fmt.Errorf("execution %s not found in queue for device %s", executionID, deviceID)
	}
}

// RequeueStale re-queues dispatched entries that have exceeded the dispatch timeout.
func (s *InMemoryQueueStore) RequeueStale(dispatchTimeout time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	now := time.Now()

	for _, entry := range s.entries {
		if entry.State != QueueStateDispatched || entry.DispatchedAt == nil {
			continue
		}
		if now.Sub(*entry.DispatchedAt) > dispatchTimeout {
			entry.State = QueueStateQueued
			entry.DispatchedAt = nil
			count++
		}
	}

	return count, nil
}

// CleanupExpired marks queued entries past their ExpiresAt as expired.
func (s *InMemoryQueueStore) CleanupExpired() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	now := time.Now()

	for _, entry := range s.entries {
		if entry.State == QueueStateQueued && now.After(entry.ExpiresAt) {
			entry.State = QueueStateExpired
			count++
		}
	}

	return count, nil
}

// List returns active (queued + dispatched) entries for the given device.
func (s *InMemoryQueueStore) List(deviceID string) ([]*QueueEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*QueueEntry, 0)
	for _, entry := range s.entries {
		if deviceID != "" && entry.DeviceID != deviceID {
			continue
		}
		if entry.State == QueueStateQueued || entry.State == QueueStateDispatched {
			result = append(result, s.cloneEntry(entry))
		}
	}

	return result, nil
}

// GetStats returns aggregate statistics about the store.
func (s *InMemoryQueueStore) GetStats() (QueueStoreStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := QueueStoreStats{
		DeviceQueueDepths: make(map[string]int),
	}

	for _, entry := range s.entries {
		stats.TotalEntries++

		switch entry.State {
		case QueueStateQueued:
			stats.QueuedCount++
			stats.DeviceQueueDepths[entry.DeviceID]++
		case QueueStateDispatched:
			stats.DispatchedCount++
			stats.DeviceQueueDepths[entry.DeviceID]++
		case QueueStateCompleted:
			stats.CompletedCount++
		case QueueStateFailed:
			stats.FailedCount++
		case QueueStateExpired:
			stats.ExpiredCount++
		case QueueStateCancelled:
			stats.CancelledCount++
		}
	}

	return stats, nil
}

// cloneEntry returns a deep copy of a QueueEntry.
func (s *InMemoryQueueStore) cloneEntry(entry *QueueEntry) *QueueEntry {
	clone := *entry

	if entry.Parameters != nil {
		clone.Parameters = make(map[string]string, len(entry.Parameters))
		for k, v := range entry.Parameters {
			clone.Parameters[k] = v
		}
	}

	if entry.Environment != nil {
		clone.Environment = make(map[string]string, len(entry.Environment))
		for k, v := range entry.Environment {
			clone.Environment[k] = v
		}
	}

	if entry.APIKeyPermissions != nil {
		clone.APIKeyPermissions = make([]string, len(entry.APIKeyPermissions))
		copy(clone.APIKeyPermissions, entry.APIKeyPermissions)
	}

	if entry.Metadata != nil {
		clone.Metadata = make(map[string]interface{}, len(entry.Metadata))
		for k, v := range entry.Metadata {
			clone.Metadata[k] = v
		}
	}

	if entry.DispatchedAt != nil {
		t := *entry.DispatchedAt
		clone.DispatchedAt = &t
	}

	if entry.CompletedAt != nil {
		t := *entry.CompletedAt
		clone.CompletedAt = &t
	}

	return &clone
}
