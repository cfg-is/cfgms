// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces defines global storage contracts used by all CFGMS modules
package interfaces

import (
	"context"
	"time"
)

// CommandStatus is a typed string enum for command execution states.
type CommandStatus string

const (
	CommandStatusPending   CommandStatus = "pending"
	CommandStatusExecuting CommandStatus = "executing"
	CommandStatusCompleted CommandStatus = "completed"
	CommandStatusFailed    CommandStatus = "failed"
	CommandStatusCancelled CommandStatus = "cancelled"
)

// CommandRecord persists the full lifecycle of a command dispatched to a steward.
// It is the durable state backing the steward command handler so that dispatch
// state survives a process restart and forms a crash-survivable audit trail.
type CommandRecord struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	StewardID    string                 `json:"steward_id"`
	TenantID     string                 `json:"tenant_id"`
	Payload      map[string]interface{} `json:"payload,omitempty"`
	Status       CommandStatus          `json:"status"`
	IssuedAt     time.Time              `json:"issued_at"`
	StartedAt    *time.Time             `json:"started_at,omitempty"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	Result       map[string]interface{} `json:"result,omitempty"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	IssuedBy     string                 `json:"issued_by,omitempty"`
}

// CommandTransition records a single state change in the command audit trail.
// Transitions are immutable — once recorded they are never updated or deleted
// by anything other than PurgeExpiredRecords (which purges by parent record age).
type CommandTransition struct {
	CommandID    string        `json:"command_id"`
	Status       CommandStatus `json:"status"`
	Timestamp    time.Time     `json:"timestamp"`
	ErrorMessage string        `json:"error_message,omitempty"`
}

// CommandFilter constrains ListCommandRecords queries.
type CommandFilter struct {
	StewardID string        // filter by steward
	TenantID  string        // filter by tenant
	Status    CommandStatus // filter by status ("" = all)
	IssuedBy  string        // filter by issuer
	Limit     int           // 0 = no limit
	Offset    int
}

// CommandStore defines the storage interface for command dispatch state.
// Implementations must be safe for concurrent use.
type CommandStore interface {
	// CreateCommandRecord creates a new command record.
	// The record must have a non-empty ID; status is set to pending on creation.
	// A corresponding transition entry is recorded for audit purposes.
	CreateCommandRecord(ctx context.Context, record *CommandRecord) error

	// UpdateCommandStatus transitions a command to a new status.
	// result is serialised to JSON and stored in the result column.
	// A corresponding transition entry is appended to the audit trail.
	UpdateCommandStatus(ctx context.Context, id string, status CommandStatus, result map[string]interface{}, errorMessage string) error

	// GetCommandRecord retrieves the current state of a command by ID.
	GetCommandRecord(ctx context.Context, id string) (*CommandRecord, error)

	// ListCommandRecords returns commands matching the optional filter.
	ListCommandRecords(ctx context.Context, filter *CommandFilter) ([]*CommandRecord, error)

	// ListCommandsByDevice returns all commands dispatched to the given steward.
	ListCommandsByDevice(ctx context.Context, stewardID string) ([]*CommandRecord, error)

	// ListCommandsByStatus returns all commands in the given status.
	ListCommandsByStatus(ctx context.Context, status CommandStatus) ([]*CommandRecord, error)

	// GetCommandAuditTrail returns all state transitions for a command in
	// chronological order (oldest first). The initial creation counts as the
	// first transition (status = pending).
	GetCommandAuditTrail(ctx context.Context, commandID string) ([]*CommandTransition, error)

	// PurgeExpiredRecords deletes commands in completed or failed status whose
	// issued_at is older than olderThan. Executing and pending records are never
	// purged. Returns the number of records deleted.
	PurgeExpiredRecords(ctx context.Context, olderThan time.Time) (int64, error)

	// HealthCheck verifies the store is operational.
	HealthCheck(ctx context.Context) error

	// Close releases the store's resources.
	Close() error
}

// Common CommandStore errors.
var (
	ErrCommandNotFound = &CommandValidationError{
		Field:   "id",
		Message: "command record not found",
		Code:    "COMMAND_NOT_FOUND",
	}
	ErrCommandIDRequired = &CommandValidationError{
		Field:   "id",
		Message: "command ID is required",
		Code:    "COMMAND_ID_REQUIRED",
	}
	ErrCommandStewardIDRequired = &CommandValidationError{
		Field:   "steward_id",
		Message: "steward ID is required",
		Code:    "COMMAND_STEWARD_ID_REQUIRED",
	}
)

// CommandValidationError represents a validation failure for CommandStore operations.
type CommandValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (e *CommandValidationError) Error() string {
	return e.Field + ": " + e.Message
}
