// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines the PushStore interface for durable push-state persistence.
package business

import (
	"context"
	"errors"
	"time"
)

// ErrPushNotFound is returned when a push record does not exist.
var ErrPushNotFound = errors.New("push record not found")

// PushStatus represents the lifecycle state of a configuration push operation.
type PushStatus string

const (
	// PushStatusPending indicates the push has been created but not yet started.
	PushStatusPending PushStatus = "pending"

	// PushStatusInProgress indicates the push is actively being distributed.
	PushStatusInProgress PushStatus = "in_progress"

	// PushStatusCompleted indicates the push completed successfully.
	PushStatusCompleted PushStatus = "completed"

	// PushStatusFailed indicates the push encountered a terminal error.
	PushStatusFailed PushStatus = "failed"
)

// PushRecord holds the durable state for a single configuration push operation.
// Data stores the full StewardConfiguration as a JSON blob so the push can be
// replayed by a new leader without referencing the push package.
type PushRecord struct {
	// ID is the unique push operation identifier.
	ID string

	// ConfigID is the identifier of the configuration being pushed.
	ConfigID string

	// TenantID is the tenant that owns this push.
	TenantID string

	// Version is the configuration version being pushed.
	Version string

	// Status is the current lifecycle state of the push.
	Status PushStatus

	// InitiatedBy identifies the user or system that initiated the push.
	InitiatedBy string

	// Data is the full StewardConfiguration JSON blob for replay.
	Data []byte

	// CreatedAt is the time the push record was created.
	CreatedAt time.Time

	// UpdatedAt is the time the push record was last modified.
	UpdatedAt time.Time
}

// PushStore defines the storage interface for durable push-state persistence.
//
// A new leader uses this interface to resume pending and in-progress pushes
// after a failover, replaying the stored StewardConfiguration blob rather than
// reconstructing the push from the feature layer.
type PushStore interface {
	// CreatePush inserts a new push record with status PushStatusPending.
	CreatePush(ctx context.Context, record *PushRecord) error

	// UpdatePushStatus updates the status and updated_at of the given push record.
	// Returns ErrPushNotFound if no record exists for the ID.
	UpdatePushStatus(ctx context.Context, id string, status PushStatus) error

	// GetPendingPushes returns all records with status pending or in_progress.
	// A new leader calls this to resume both states after failover.
	GetPendingPushes(ctx context.Context) ([]*PushRecord, error)

	// GetPush retrieves the push record for the given ID.
	// Returns ErrPushNotFound if no record exists.
	GetPush(ctx context.Context, id string) (*PushRecord, error)

	// ListPushesByConfigID returns all push records for the given config ID scoped
	// to the given tenant, ordered by created_at descending (most recent first).
	// Both configID and tenantID are required — a non-empty tenantID prevents
	// cross-tenant data disclosure. Returns an empty slice (not an error) when no
	// records exist for the config within the tenant.
	ListPushesByConfigID(ctx context.Context, configID, tenantID string) ([]*PushRecord, error)
}
