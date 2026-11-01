// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines the UpgradeStore interface for durable upgrade-state persistence.
package business

import (
	"context"
	"errors"
	"time"
)

// ErrUpgradeNotFound is returned when an upgrade record does not exist.
var ErrUpgradeNotFound = errors.New("upgrade record not found")

// UpgradeStatus is the lifecycle state of a single steward upgrade operation.
type UpgradeStatus string

const (
	// UpgradeStatusDispatched indicates the upgrade has been dispatched to the steward.
	UpgradeStatusDispatched UpgradeStatus = "dispatched"

	// UpgradeStatusDownloaded indicates the steward has downloaded the binary.
	UpgradeStatusDownloaded UpgradeStatus = "downloaded"

	// UpgradeStatusSwapped indicates the binary swap has been performed.
	UpgradeStatusSwapped UpgradeStatus = "swapped"

	// UpgradeStatusCommitted indicates the upgrade was verified and committed.
	UpgradeStatusCommitted UpgradeStatus = "committed"

	// UpgradeStatusRolledBack indicates the steward rolled back to the prior binary.
	UpgradeStatusRolledBack UpgradeStatus = "rolled_back"

	// UpgradeStatusFailed indicates the upgrade encountered a terminal error.
	UpgradeStatusFailed UpgradeStatus = "failed"
)

// InitiatedByIdentity captures the structured identity of the operator who
// initiated the upgrade. Free-form strings are not accepted.
type InitiatedByIdentity struct {
	// Subject is the operator email or service-account name from the auth context.
	Subject string

	// TenantID is the tenant scope of the initiating session.
	TenantID string

	// AuthMethod is the authentication method used (e.g. "api_key", "mtls", "session_token").
	AuthMethod string
}

// UpgradeRecord holds the durable state for a single steward upgrade operation.
//
// Publisher-signature provenance fields (Publisher, SignatureDigest, BundleSignature)
// are mandatory at creation time and cannot be patched in retroactively, ensuring the
// audit trail is complete from the moment an upgrade is dispatched.
type UpgradeRecord struct {
	// ID is the unique upgrade operation identifier (uuid).
	ID string

	// StewardID is the target steward.
	StewardID string

	// TenantID is the tenant scope (for cross-tenant guard).
	TenantID string

	// Version is the target binary version.
	Version string

	// Platform is the target OS platform (e.g. "linux", "windows").
	Platform string

	// Arch is the target CPU architecture (e.g. "amd64", "arm64").
	Arch string

	// SHA256 is the expected sha256 hex digest of the binary.
	SHA256 string

	// Status is the current lifecycle state.
	Status UpgradeStatus

	// InitiatedBy is the structured operator identity (not free-form).
	InitiatedBy InitiatedByIdentity

	// Publisher is the publisher name from the trust store (e.g. "cfgms").
	Publisher string

	// SignatureDigest is the SHA-256 hex of the BundleSignature bytes (audit lookup).
	SignatureDigest string

	// BundleSignature is the 64-byte Ed25519 signature over ContentHash.
	// CreateUpgrade returns an error if this field is nil or empty.
	BundleSignature []byte

	// CreatedAt is the record creation time set by the caller; used for replay defense and ordering.
	CreatedAt time.Time

	// OperationNonce is a 32-byte random nonce set by the caller for replay defense.
	OperationNonce []byte

	// DispatchedAt is the time the upgrade was dispatched.
	DispatchedAt time.Time

	// CompletedAt is nil until the record reaches a terminal state.
	CompletedAt *time.Time

	// ErrorMessage is set on failed or rolled_back status.
	ErrorMessage string
}

// UpgradeStore defines the storage interface for durable upgrade-state persistence.
//
// The controller uses this interface to record and query per-steward upgrade operation
// state without any in-memory-only state. All publisher-signature provenance is stored
// at creation time.
type UpgradeStore interface {
	// CreateUpgrade inserts a new upgrade record.
	// Returns an error if record.BundleSignature is nil or empty — no upgrade record
	// may be created without a publisher signature on file.
	CreateUpgrade(ctx context.Context, record *UpgradeRecord) error

	// UpdateUpgradeStatus updates the status of the given upgrade record.
	// errorMsg is stored when status is UpgradeStatusFailed or UpgradeStatusRolledBack.
	// Returns ErrUpgradeNotFound if no record exists for the ID.
	UpdateUpgradeStatus(ctx context.Context, id string, status UpgradeStatus, errorMsg string) error

	// GetUpgrade retrieves the upgrade record for the given ID.
	// Returns ErrUpgradeNotFound if no record exists.
	GetUpgrade(ctx context.Context, id string) (*UpgradeRecord, error)

	// ListUpgradesBySteward returns all upgrade records for the given stewardID,
	// ordered by created_at descending (most recent first).
	// Returns an empty slice (not an error) when no records exist.
	ListUpgradesBySteward(ctx context.Context, stewardID string) ([]*UpgradeRecord, error)

	// ListUpgradesByTenant returns all upgrade records for the given tenantID,
	// ordered by created_at descending (most recent first).
	// Returns an empty slice (not an error) when no records exist.
	ListUpgradesByTenant(ctx context.Context, tenantID string) ([]*UpgradeRecord, error)

	// HealthCheck verifies the store is reachable and operational.
	HealthCheck(ctx context.Context) error

	// Initialize prepares the store (creates directories, tables, etc.).
	Initialize(ctx context.Context) error

	// Close releases resources held by the store.
	Close() error
}
