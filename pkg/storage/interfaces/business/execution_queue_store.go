// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"context"
	"errors"
	"time"
)

// Execution queue states. They mirror the script module's QueueState values;
// the store only needs them to select and transition rows.
const (
	ExecutionQueueStateQueued     = "queued"
	ExecutionQueueStateDispatched = "dispatched"
	ExecutionQueueStateCompleted  = "completed"
	ExecutionQueueStateFailed     = "failed"
	ExecutionQueueStateExpired    = "expired"
	ExecutionQueueStateCancelled  = "cancelled"
)

// ErrDuplicateQueuedExecution is returned by ExecutionQueueStore.Enqueue when a
// queued entry with the same ParamHash already exists for the device.
var ErrDuplicateQueuedExecution = errors.New("duplicate execution: identical script+device+params already queued")

// ErrExecutionQueueEntryNotFound is returned when an entry does not exist for
// the device, or is not in a state the operation accepts.
var ErrExecutionQueueEntryNotFound = errors.New("execution queue entry not found in an eligible state")

// ExecutionQueueEntry is one queued script execution. The columns the store
// queries on are first-class fields; Payload is the feature's complete entry,
// stored opaquely (JSON) and returned as written. State, DispatchedAt and
// CompletedAt are authoritative over any copy inside Payload.
type ExecutionQueueEntry struct {
	ExecutionID  string
	DeviceID     string
	ParamHash    string
	State        string
	QueuedAt     time.Time
	ExpiresAt    time.Time
	DispatchedAt *time.Time
	CompletedAt  *time.Time
	Payload      []byte
}

// ExecutionQueueStats aggregates queue entries by state.
type ExecutionQueueStats struct {
	TotalEntries      int
	CountsByState     map[string]int
	DeviceQueueDepths map[string]int // queued + dispatched only
}

// ExecutionQueueStore is the durable execution queue for ad-hoc and catalogued
// script runs. In cluster mode it is backed by the shared database so that any
// controller node can dispatch work to the stewards connected to it, whichever
// node accepted the run (Issue #4528). Every method is safe to call
// concurrently from several nodes.
type ExecutionQueueStore interface {
	// Enqueue adds a queued entry. Returns ErrDuplicateQueuedExecution when a
	// queued entry with the same ParamHash exists for the same device.
	Enqueue(ctx context.Context, entry *ExecutionQueueEntry) error
	// Dequeue atomically claims the device's entries: queued entries past
	// their expiry become expired; the remaining queued entries move to
	// dispatched (DispatchedAt = now); entries already dispatched but not yet
	// acknowledged are returned again for re-dispatch. Concurrent callers never
	// receive the same queued entry.
	Dequeue(ctx context.Context, deviceID string, now time.Time) ([]*ExecutionQueueEntry, error)
	// AcknowledgeCompletion moves a dispatched entry to state (completed or
	// failed). Returns ErrExecutionQueueEntryNotFound when the entry does not
	// exist for the device or is not dispatched.
	AcknowledgeCompletion(ctx context.Context, executionID, deviceID, state string, now time.Time) error
	// Cancel moves a queued or dispatched entry to cancelled. Returns
	// ErrExecutionQueueEntryNotFound otherwise.
	Cancel(ctx context.Context, deviceID, executionID string) error
	// RequeueStale returns dispatched entries older than dispatchedBefore to
	// queued, clearing DispatchedAt. Returns the number re-queued.
	RequeueStale(ctx context.Context, dispatchedBefore time.Time) (int, error)
	// CleanupExpired marks queued entries past their expiry as expired.
	// Returns the number expired.
	CleanupExpired(ctx context.Context, now time.Time) (int, error)
	// List returns queued and dispatched entries; an empty deviceID lists all.
	List(ctx context.Context, deviceID string) ([]*ExecutionQueueEntry, error)
	GetStats(ctx context.Context) (ExecutionQueueStats, error)
}
