// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines storage interfaces for the controller business tier.
package business

import (
	"context"
	"errors"
	"time"
)

// ErrRolloutNotFound is returned when a rollout record does not exist.
var ErrRolloutNotFound = errors.New("rollout record not found")

// RolloutStatus is the lifecycle state of a ring-advance rollout orchestration.
type RolloutStatus string

const (
	// RolloutStatusInProgress indicates the rollout is actively advancing through rings.
	RolloutStatusInProgress RolloutStatus = "in-progress"

	// RolloutStatusHalted indicates the rollout was halted due to a health threshold breach
	// or operator intervention.
	RolloutStatusHalted RolloutStatus = "halted"

	// RolloutStatusCompleted indicates all rings reached the target version successfully.
	RolloutStatusCompleted RolloutStatus = "completed"
)

// RolloutRecord holds the durable state for a ring-advance rollout operation.
//
// This is the orchestration-state record for the rollout workflow — it tracks which
// rings have been completed and which stewards have been deferred for retry. Individual
// per-steward upgrade state is stored separately in UpgradeStore.
//
// The DeferredStewards list holds steward IDs that failed during this rollout and
// should be retried; this is data on the record, not a DNA mutation.
type RolloutRecord struct {
	// ID is the unique rollout operation identifier.
	ID string

	// TenantID scopes this rollout to a single tenant.
	TenantID string

	// TargetVersion is the steward binary version this rollout is promoting.
	TargetVersion string

	// CurrentRing is the ring currently being processed. Empty when completed.
	CurrentRing string

	// RingsCompleted is the count of rings that have reached the target version.
	RingsCompleted int

	// RingsTotal is the total number of rings in the rollout plan.
	RingsTotal int

	// Status is the current lifecycle state of this rollout.
	Status RolloutStatus

	// StartedAt is when the rollout was initiated.
	StartedAt time.Time

	// HaltedAt is set when the rollout transitions to RolloutStatusHalted.
	HaltedAt *time.Time

	// Error holds the halt or failure reason; empty when Status is in-progress or completed.
	Error string

	// DeferredStewards is the list of steward IDs that failed during this rollout
	// and are queued for a subsequent retry pass. This list grows monotonically;
	// it is never cleared automatically.
	DeferredStewards []string
}

// RolloutStore defines the storage interface for durable rollout-orchestration-state persistence.
//
// This interface is the durability seam between the in-memory workflow engine and any
// future durable workflow execution backend (ADR-008). All implementations must be safe
// for concurrent use.
//
// Do NOT add rollout types to upgrade_store.go — that file owns the UpgradeRecord/UpgradeStore
// concern and mixing them would trip make check-architecture.
type RolloutStore interface {
	// CreateRollout inserts a new rollout record.
	// Returns an error if a record with the same ID already exists.
	CreateRollout(ctx context.Context, record *RolloutRecord) error

	// GetRollout retrieves the rollout record for the given ID.
	// Returns ErrRolloutNotFound if no record exists.
	GetRollout(ctx context.Context, id string) (*RolloutRecord, error)

	// UpdateRolloutProgress updates the status, current ring, completed ring count,
	// and optional halt metadata for a rollout. Pass haltedAt as non-nil only when
	// transitioning to RolloutStatusHalted.
	// Returns ErrRolloutNotFound if no record exists for id.
	UpdateRolloutProgress(ctx context.Context, id string, status RolloutStatus, currentRing string, ringsCompleted int, haltedAt *time.Time, errorMsg string) error

	// AppendDeferredStewards adds steward IDs to the deferred-retry list.
	// IDs already in the list are not deduplicated — callers are responsible for
	// ensuring each ID is appended only once per rollout.
	// Returns ErrRolloutNotFound if no record exists for rolloutID.
	AppendDeferredStewards(ctx context.Context, rolloutID string, stewardIDs []string) error

	// ListRolloutsByTenant returns all rollout records for the given tenantID.
	// Returns an empty slice (not an error) when no records exist.
	ListRolloutsByTenant(ctx context.Context, tenantID string) ([]*RolloutRecord, error)

	// HealthCheck verifies the store is reachable and operational.
	HealthCheck(ctx context.Context) error

	// Initialize prepares the store (creates directories, tables, etc.).
	Initialize(ctx context.Context) error

	// Close releases resources held by the store.
	Close() error
}
