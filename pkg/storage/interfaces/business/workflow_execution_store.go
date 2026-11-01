// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"context"
	"errors"
	"time"
)

// Workflow execution statuses the store distinguishes. The store only needs to
// know which statuses are terminal; every other status string is treated as
// non-terminal and stored verbatim.
const (
	WorkflowExecutionStatusCompleted = "completed"
	WorkflowExecutionStatusFailed    = "failed"
	WorkflowExecutionStatusCancelled = "cancelled"
)

// ErrWorkflowExecutionNotFound is returned by Get when no execution exists for
// (tenantID, executionID).
var ErrWorkflowExecutionNotFound = errors.New("workflow execution not found")

// IsTerminalWorkflowExecutionStatus reports whether status is a final state: a
// terminal record is never overwritten by a later non-terminal write, and Prune
// only ever deletes terminal records.
func IsTerminalWorkflowExecutionStatus(status string) bool {
	switch status {
	case WorkflowExecutionStatusCompleted, WorkflowExecutionStatusFailed, WorkflowExecutionStatusCancelled:
		return true
	}
	return false
}

// WorkflowExecutionRecord is the durable, serializable part of one workflow run.
//
// Tenant, execution id, workflow name, status and the two timestamps are first-class
// columns. Everything else the engine reports (step results, error, trace) is an
// opaque JSON Payload the store never interprets. The engine omits run variables
// from the payload because they can carry resolved secret values.
type WorkflowExecutionRecord struct {
	// TenantID owns the record. The empty string is the root tenant's key; it is a
	// tenant like any other, never "all tenants".
	TenantID     string
	ExecutionID  string
	WorkflowName string
	Status       string
	StartTime    time.Time
	// EndTime is the zero value while the run is not finished.
	EndTime time.Time
	// Payload is opaque JSON owned by the engine.
	Payload []byte
}

// WorkflowExecutionStore is the durable, tenant-scoped storage contract for workflow
// execution history. It makes a run's status, step results and error readable from
// every controller node and across restarts. No method crosses tenants.
type WorkflowExecutionStore interface {
	// Save inserts the record or replaces the stored one for (TenantID, ExecutionID).
	// Concurrent writers resolve last-writer-wins, with one exception: a record whose
	// stored status is terminal is never replaced by a non-terminal one, so a late
	// "running" snapshot cannot undo a "completed" write. That ignored write is not
	// an error. ExecutionID is required.
	Save(ctx context.Context, record *WorkflowExecutionRecord) error

	// Get returns the record for (tenantID, executionID), or
	// ErrWorkflowExecutionNotFound — also when the id exists under another tenant.
	Get(ctx context.Context, tenantID, executionID string) (*WorkflowExecutionRecord, error)

	// List returns tenantID's records, newest StartTime first. A non-empty
	// workflowName restricts the result to that workflow; limit <= 0 means no limit.
	// Returns an empty (non-nil) slice when there are none.
	List(ctx context.Context, tenantID, workflowName string, limit int) ([]*WorkflowExecutionRecord, error)

	// Prune deletes tenantID's terminal records beyond the newest keep (by StartTime)
	// and returns how many it deleted. Non-terminal records are never deleted and do
	// not count toward keep. keep < 0 deletes nothing.
	Prune(ctx context.Context, tenantID string, keep int) (int, error)
}
