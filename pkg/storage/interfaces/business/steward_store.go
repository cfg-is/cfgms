// SPDX-License-Identifier: AGPL-3.0-only
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

// ErrStewardDeviceIDConflict is returned when a steward record cannot be written
// because a DIFFERENT steward in the same tenant already holds its device_id.
// It is distinct from ErrStewardAlreadyExists, which reports the same steward
// being registered twice and is benign for an idempotent retry. A device_id
// collision is not benign: two records sharing one device_id break
// GetStewardByDeviceID, the single lookup feeding the revocation gate, so a
// record still in "registered" state alongside a revoked sibling would let the
// revoked holder pass that gate. Providers enforce this with a unique index on
// (tenant_id, device_id) restricted to non-empty device_id, which is what makes
// the guard hold under concurrent claims rather than only in sequence (Issue #3403).
var ErrStewardDeviceIDConflict = errors.New("device_id already registered by another steward in this tenant")

// ErrStewardRevoked is returned by callers of GetStewardByDeviceID when the
// returned record has Status == StewardStatusRevoked. The gate handler must
// check for revocation before verifying the proof-of-possession signature
// (revocation-before-PoP invariant, ADR-010 §3).
var ErrStewardRevoked = errors.New("steward revoked")

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

	// StewardStatusArchived indicates the steward's mTLS cert has expired and the
	// steward is offline. The steward may re-enter the fleet via the registration-refresh
	// flow (ADR-010). A pending_refresh_requests entry is created when a refresh challenge
	// is received for an archived steward.
	StewardStatusArchived StewardStatus = "archived"

	// StewardStatusDormant indicates the steward has been archived for longer than
	// RefreshPolicy.MaxDormancyDays. Refresh requests are auto-rejected unless an
	// operator overrides the policy. MaxDormancyDays == nil means the dormancy backstop
	// is disabled (default OFF, ADR-010 §4).
	StewardStatusDormant StewardStatus = "dormant"

	// StewardStatusRevoked indicates the steward has been permanently denied re-entry.
	// GetStewardByDeviceID returns the record regardless; callers must check the status
	// and return ErrStewardRevoked before performing any proof-of-possession verification
	// (revocation-before-PoP ordering invariant, ADR-010 §3).
	StewardStatusRevoked StewardStatus = "revoked"
)

// StewardRecord holds the durable fleet registration data for a single steward.
// Fields that are only meaningful during the current process lifetime (task latency
// counters, recovery attempt counters) belong in HealthMetrics, not here.
type StewardRecord struct {
	// ID is the unique steward identifier, assigned at registration.
	ID string `json:"id"`

	// TenantID is the tenant this steward belongs to, derived from the registration token
	// used during HTTP registration. Set at first registration; authoritative source is
	// RegistrationToken.TenantID from the RegistrationTokenStore.
	TenantID string `json:"tenant_id"`

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

	// Hidden is the operator-controlled fleet-view visibility flag (Issue #2944).
	// Orthogonal to Status: hiding a steward does not change its lifecycle state.
	Hidden bool `json:"hidden"`

	// RegisteredAt is the time the steward first registered.
	RegisteredAt time.Time `json:"registered_at"`

	// LastSeen is the time of any steward activity (registration, heartbeat, or other RPC).
	LastSeen time.Time `json:"last_seen"`

	// LastHeartbeatAt is the time of the last explicit heartbeat RPC.
	// Distinct from LastSeen: a steward may be visible (last_seen recent) without sending heartbeats.
	LastHeartbeatAt time.Time `json:"last_heartbeat_at"`

	// DeviceID is the 64-character lowercase hex fingerprint of the steward's Ed25519
	// identity key. Set by S2c (populate-identity-fields story). Empty for stewards
	// registered before ADR-010 was implemented.
	DeviceID string `json:"device_id"`

	// IdentityKeyPub is the raw 32-byte Ed25519 public key for this steward's device
	// identity. Separate from the rotating mTLS certificate (ADR-010 §1). Set by S2c.
	IdentityKeyPub []byte `json:"identity_key_pub"`

	// KeyProtectionLevel describes how the private key material is protected on the
	// steward host: "file" (software-only) or "tpm" (hardware-backed). Set by S2c.
	KeyProtectionLevel string `json:"key_protection_level"`

	// LastProvenanceJSON is the last observed provenance snapshot serialised as JSON.
	// Provenance is a set of device-identity signals (hostname, MAC, CPU serial, etc.)
	// used by the gate handler (S3b) to score re-entry confidence. Updated at each
	// successful refresh. Empty until the first refresh cycle completes.
	LastProvenanceJSON string `json:"last_provenance_json"`
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

	// GetStewardByDeviceID retrieves the record whose DeviceID matches the given
	// 64-character hex fingerprint. Returns ErrStewardNotFound when no matching
	// record exists. Callers must inspect the returned record's Status field and
	// return ErrStewardRevoked if Status == StewardStatusRevoked — the store does
	// not surface the revocation error directly (ADR-010 §3 revocation-before-PoP
	// ordering invariant).
	GetStewardByDeviceID(ctx context.Context, deviceID string) (*StewardRecord, error)

	// ListStewards returns all steward records regardless of status.
	ListStewards(ctx context.Context) ([]*StewardRecord, error)

	// ListStewardsByStatus returns steward records with the given status.
	// Uses an indexed query on the SQLite backend for efficiency.
	ListStewardsByStatus(ctx context.Context, status StewardStatus) ([]*StewardRecord, error)

	// UpdateStewardStatus updates the lifecycle status of the given steward.
	// Returns ErrStewardNotFound if no record exists.
	UpdateStewardStatus(ctx context.Context, stewardID string, status StewardStatus) error

	// SetStewardHidden sets the operator-controlled visibility flag for the given steward.
	// Returns ErrStewardNotFound if no record exists.
	SetStewardHidden(ctx context.Context, stewardID string, hidden bool) error

	// UpdateStewardTenant moves a steward to a different tenant.
	// Returns ErrStewardNotFound if no record exists for stewardID.
	UpdateStewardTenant(ctx context.Context, stewardID, newTenantID string) error

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
