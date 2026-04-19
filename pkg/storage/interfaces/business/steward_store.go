// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package business defines the StewardStore interface for durable fleet registry persistence.
package business

import (
	"context"
	"errors"
	"time"
)

// ErrStewardNotFound is returned when a steward record does not exist.
var ErrStewardNotFound = errors.New("steward not found")

// ErrStewardAlreadyExists is returned when attempting to register an already-registered steward.
var ErrStewardAlreadyExists = errors.New("steward already exists")

// StewardStatus represents the lifecycle state of a steward in the fleet.
// Records are never deleted; deregistered stewards are retained for audit.
type StewardStatus string

const (
	// StewardStatusRegistered indicates the steward has registered but not yet sent a heartbeat.
	StewardStatusRegistered StewardStatus = "registered"

	// StewardStatusActive indicates the steward is actively sending heartbeats.
	StewardStatusActive StewardStatus = "active"

	// StewardStatusLost indicates the steward has not been seen within the configured TTL.
	// The record is retained for audit; the steward may re-register.
	StewardStatusLost StewardStatus = "lost"

	// StewardStatusDeregistered indicates the steward has been explicitly deregistered.
	// Records are retained for audit history.
	StewardStatusDeregistered StewardStatus = "deregistered"
)

// StewardRecord holds the durable fleet registration data for a single steward.
// Fields that are only meaningful during the current process lifetime (task latency
// counters, recovery attempt counters) belong in HealthMetrics, not here.
type StewardRecord struct {
	// ID is the unique steward identifier, assigned at registration.
	ID string `json:"id"`

	// Hostname is the DNS hostname of the steward's machine.
	Hostname string `json:"hostname"`

	// Platform is the operating system (e.g. "linux", "windows", "darwin").
	Platform string `json:"platform"`

	// Arch is the CPU architecture (e.g. "amd64", "arm64").
	Arch string `json:"arch"`

	// Version is the steward binary version at last registration.
	Version string `json:"version"`

	// IPAddress is the IP address of the steward at last contact.
	IPAddress string `json:"ip_address"`

	// Status is the current lifecycle state of the steward.
	Status StewardStatus `json:"status"`

	// RegisteredAt is the time the steward first registered.
	RegisteredAt time.Time `json:"registered_at"`

	// LastSeen is the time of any steward activity (registration, heartbeat, or other RPC).
	LastSeen time.Time `json:"last_seen"`

	// LastHeartbeatAt is the time of the last explicit heartbeat RPC.
	// Distinct from LastSeen: a steward may be visible (last_seen recent) without sending heartbeats.
	LastHeartbeatAt time.Time `json:"last_heartbeat_at"`
}

// StewardFilter defines criteria for filtering steward queries.
type StewardFilter struct {
	// Status filters records to the given lifecycle state. Empty means no filter.
	Status StewardStatus `json:"status,omitempty"`
}

// StewardStore defines the storage interface for durable fleet registry data.
//
// The controller uses this interface to persist steward registrations so that the
// fleet view (last-seen, heartbeat, status, platform) survives controller restarts
// without waiting for all stewards to re-register.
//
// Ephemeral per-process metrics (task latency, config errors, recovery counters)
// belong in HealthMetrics and must NOT be stored here.
type StewardStore interface {
	// RegisterSteward creates a new steward record. Returns ErrStewardAlreadyExists
	// if a record with the same ID already exists.
	RegisterSteward(ctx context.Context, record *StewardRecord) error

	// UpdateHeartbeat records a heartbeat for the given steward, updating both
	// last_heartbeat_at and last_seen to the current time.
	// Returns ErrStewardNotFound if no record exists for the ID.
	UpdateHeartbeat(ctx context.Context, stewardID string) error

	// GetSteward retrieves the record for the given steward ID.
	// Returns ErrStewardNotFound if no record exists.
	GetSteward(ctx context.Context, stewardID string) (*StewardRecord, error)

	// ListStewards returns all steward records regardless of status.
	ListStewards(ctx context.Context) ([]*StewardRecord, error)

	// ListStewardsByStatus returns steward records with the given status.
	// Uses an indexed query on the SQLite backend for efficiency.
	ListStewardsByStatus(ctx context.Context, status StewardStatus) ([]*StewardRecord, error)

	// UpdateStewardStatus updates the lifecycle status of the given steward.
	// Returns ErrStewardNotFound if no record exists.
	UpdateStewardStatus(ctx context.Context, stewardID string, status StewardStatus) error

	// DeregisterSteward marks the steward as deregistered. Records are retained
	// for audit history; use ListStewardsByStatus to exclude them from active views.
	// Returns ErrStewardNotFound if no record exists.
	DeregisterSteward(ctx context.Context, stewardID string) error

	// GetStewardsSeen returns all stewards whose last_seen time is after the given time.
	GetStewardsSeen(ctx context.Context, since time.Time) ([]*StewardRecord, error)

	// HealthCheck verifies the store is reachable and operational.
	HealthCheck(ctx context.Context) error

	// Initialize prepares the store (creates directories, tables, etc.).
	// Safe to call multiple times.
	Initialize(ctx context.Context) error

	// Close releases any resources held by the store.
	Close() error
}

// StewardStoreProvider is an optional extension interface that providers implement
// when they support StewardStore.
type StewardStoreProvider interface {
	CreateStewardStore(config map[string]interface{}) (StewardStore, error)
}
