// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines the PendingRefreshStore interface for the
// registration-refresh approval flow (ADR-010, Issue #2093).
package business

import (
	"context"
	"errors"
	"time"
)

// ErrPendingRefreshNotFound is returned when a pending refresh record does not exist.
var ErrPendingRefreshNotFound = errors.New("pending refresh not found")

// Pending refresh status values.
const (
	PendingRefreshStatusPending  = "pending"
	PendingRefreshStatusApproved = "approved"
	PendingRefreshStatusRejected = "rejected"
	PendingRefreshStatusExpired  = "expired"
)

// PendingRefreshEntry holds the durable state for a single registration-refresh
// request awaiting manual review or auto-accept processing (ADR-010 §4).
//
// ClaimBundle is populated by StoreClaimBundle once the steward submits its
// proof-of-possession response. It is never stored until after the challenge
// phase succeeds; a nil ClaimBundle means the steward has not yet responded.
type PendingRefreshEntry struct {
	// PendingID is the unique pending-refresh identifier (e.g. "refresh-<nanoseconds>").
	PendingID string

	// DeviceID is the 64-character hex fingerprint of the steward's Ed25519 identity key.
	DeviceID string

	// TenantID is the tenant the refreshing steward belongs to.
	TenantID string

	// SourceIP is the remote address of the refreshing steward at challenge time.
	SourceIP string

	// CSRPEM is the PEM-encoded CERTIFICATE REQUEST the steward submitted with its
	// /refresh/complete call (Issue #3781). The controller never generates a keypair
	// for this credential; when the refresh is queued for manual or auto-accept
	// processing rather than signed immediately, this is the CSR that gets signed
	// once the request is approved.
	CSRPEM string

	// ProvenanceMatchedFields is the number of provenance signal fields that matched
	// the last recorded provenance snapshot (LastProvenanceJSON in StewardRecord).
	ProvenanceMatchedFields int

	// ProvenanceTotalFields is the total number of provenance signal fields evaluated.
	ProvenanceTotalFields int

	// ClaimBundle is the serialised proof-of-possession payload submitted by the
	// steward during the /refresh/complete call. Nil until StoreClaimBundle is called.
	ClaimBundle []byte

	// Status is the current lifecycle state: pending | approved | rejected | expired.
	Status string

	// CreatedAt is the time the refresh challenge was issued.
	CreatedAt time.Time

	// ExpiresAt is the deadline after which the entry is eligible for expiry sweep.
	// Nonce TTL is 65 seconds (ADR-010 §2); entries are typically short-lived.
	ExpiresAt time.Time

	// ResolvedAt is set when the entry reaches a terminal state (approved/rejected/expired).
	ResolvedAt *time.Time
}

// PendingRefreshStore defines the storage interface for durable persistence of
// registration-refresh requests in the ADR-010 approval flow.
type PendingRefreshStore interface {
	// AddPendingRefresh inserts a new pending-refresh entry.
	// Returns an error if an entry with the same PendingID already exists.
	AddPendingRefresh(ctx context.Context, entry *PendingRefreshEntry) error

	// GetPendingRefreshByID retrieves the entry for the given pending_id.
	// Returns ErrPendingRefreshNotFound if no record exists.
	GetPendingRefreshByID(ctx context.Context, pendingID string) (*PendingRefreshEntry, error)

	// UpdateRefreshStatus updates the status of the entry identified by pendingID.
	// For terminal statuses (approved, rejected), resolved_at is also set to now.
	// Returns ErrPendingRefreshNotFound if no record exists for the ID.
	UpdateRefreshStatus(ctx context.Context, pendingID, status string) error

	// ListPendingRefresh returns all entries for the given tenantID ordered by
	// created_at ascending. An empty tenantID returns entries for all tenants.
	ListPendingRefresh(ctx context.Context, tenantID string) ([]*PendingRefreshEntry, error)

	// ExpireStaleRefresh marks entries whose expires_at is at or before cutoff and
	// whose status is "pending" as "expired", setting resolved_at to now.
	// Returns the number of entries updated.
	ExpireStaleRefresh(ctx context.Context, cutoff time.Time) (int, error)

	// StoreClaimBundle persists the proof-of-possession payload for the given
	// pendingID. Called by the /refresh/complete handler after signature verification.
	// Returns ErrPendingRefreshNotFound if no record exists for the ID.
	StoreClaimBundle(ctx context.Context, pendingID string, bundle []byte) error
}
