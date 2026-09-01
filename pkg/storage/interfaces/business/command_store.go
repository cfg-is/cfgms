// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines business-data storage contracts for CFGMS
package business

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

// DeliveryStatus is a typed string enum for the outbox delivery lifecycle of a
// command/notification destined for a steward (ADR-031 Decision 2). It is
// orthogonal to CommandStatus: CommandStatus tracks whether the receiving
// steward has executed the command; DeliveryStatus tracks whether the
// dispatching controller has gotten the command onto the wire to that steward
// at all. A record's DeliveryStatus reaches DeliveryStatusDelivered the moment
// a transport attempt succeeds (e.g. SendCommand returns nil) — independent of
// whatever the steward later does with it.
type DeliveryStatus string

const (
	// DeliveryStatusPending means the row is durable but no delivery attempt has
	// succeeded yet (never attempted, or every attempt so far failed transiently).
	DeliveryStatusPending DeliveryStatus = "pending"
	// DeliveryStatusDelivered means a transport attempt to the steward succeeded.
	DeliveryStatusDelivered DeliveryStatus = "delivered"
	// DeliveryStatusAcknowledged means the steward positively acknowledged receipt.
	DeliveryStatusAcknowledged DeliveryStatus = "acknowledged"
	// DeliveryStatusFailed means delivery terminally failed (e.g. steward
	// deregistered) and will not be retried.
	DeliveryStatusFailed DeliveryStatus = "failed"
)

// CommandRecord persists the full lifecycle of a command dispatched to a steward.
// It is the durable state backing the steward command handler so that dispatch
// state survives a process restart and forms a crash-survivable audit trail.
//
// DeliveryStatus/DeliveryDetail (Issue #3757, ADR-031 Decision 2) track the
// controller-side outbox delivery lifecycle (pending -> delivered -> acknowledged,
// terminal failures recorded distinctly) and are independent of Status, which
// tracks the steward-side execution lifecycle.
type CommandRecord struct {
	ID             string                 `json:"id"`
	Type           string                 `json:"type"`
	StewardID      string                 `json:"steward_id"`
	TenantID       string                 `json:"tenant_id"`
	Payload        map[string]interface{} `json:"payload,omitempty"`
	Status         CommandStatus          `json:"status"`
	IssuedAt       time.Time              `json:"issued_at"`
	StartedAt      *time.Time             `json:"started_at,omitempty"`
	CompletedAt    *time.Time             `json:"completed_at,omitempty"`
	Result         map[string]interface{} `json:"result,omitempty"`
	ErrorMessage   string                 `json:"error_message,omitempty"`
	IssuedBy       string                 `json:"issued_by,omitempty"`
	DeliveryStatus DeliveryStatus         `json:"delivery_status,omitempty"`
	DeliveryDetail string                 `json:"delivery_detail,omitempty"`
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
	// DeliveryStatus is persisted as given, defaulting to DeliveryStatusPending
	// when the caller leaves it empty. A corresponding transition entry is
	// recorded for audit purposes.
	CreateCommandRecord(ctx context.Context, record *CommandRecord) error

	// CreateCommandRecords atomically creates a batch of command records in a
	// single database transaction: every record commits, or none do (Issue #3757,
	// ADR-031 Decision 2). This is the seam a caller like handleConfigPush uses so
	// that the durable delivery row(s) for a fan-out commit together as one fact
	// rather than leaving a partial set of stewards silently un-queued. Each
	// record follows the same defaulting rules as CreateCommandRecord.
	CreateCommandRecords(ctx context.Context, records []*CommandRecord) error

	// UpdateCommandStatus transitions a command to a new status.
	// result is serialised to JSON and stored in the result column.
	// A corresponding transition entry is appended to the audit trail.
	UpdateCommandStatus(ctx context.Context, id string, status CommandStatus, result map[string]interface{}, errorMessage string) error

	// UpdateDeliveryStatus transitions a command record's outbox DeliveryStatus
	// (Issue #3757, ADR-031 Decision 2). detail carries a human-readable reason
	// (e.g. a sanitized transport error) and is stored verbatim in DeliveryDetail;
	// callers must sanitize any error-derived value before passing it here
	// (logging.SanitizeLogValue) since detail is also written to logs by callers.
	// Returns ErrCommandNotFound if no record exists for id.
	UpdateDeliveryStatus(ctx context.Context, id string, status DeliveryStatus, detail string) error

	// ListPendingDeliveries returns every command record targeting stewardID whose
	// DeliveryStatus is still DeliveryStatusPending (Issue #3757). A steward calls
	// this on reconnect to drain any delivery that was queued while it was
	// unreachable — the row survived any controller restart in the interim, so
	// nothing queued for it is ever silently lost.
	ListPendingDeliveries(ctx context.Context, stewardID string) ([]*CommandRecord, error)

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
