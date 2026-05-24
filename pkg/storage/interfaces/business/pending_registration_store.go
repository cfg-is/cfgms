// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines the PendingRegistrationStore interface for the
// generate-on-claim registration approval flow (Issue #1696).
package business

import (
	"context"
	"errors"
	"time"
)

// ErrPendingRegistrationNotFound is returned when a pending registration record does not exist.
var ErrPendingRegistrationNotFound = errors.New("pending registration not found")

// Pending registration status values.
const (
	PendingRegistrationStatusPending  = "pending"
	PendingRegistrationStatusApproved = "approved"
	PendingRegistrationStatusClaimed  = "claimed"
	PendingRegistrationStatusDenied   = "denied"
	PendingRegistrationStatusExpired  = "expired"
)

// PendingRegistrationEntry holds the durable state for a single registration request
// awaiting manual review and generate-on-claim cert issuance.
//
// No private key or certificate bundle is ever stored — cert generation happens
// in memory when the steward first polls an approved entry.
type PendingRegistrationEntry struct {
	// PendingID is the unique pending-registration identifier (e.g. "pending-<nanoseconds>").
	PendingID string

	// StewardID is the steward identifier assigned at registration time.
	StewardID string

	// TenantID is the tenant the registering steward belongs to.
	TenantID string

	// TokenStr is the full registration token presented at registration time.
	// Stored so GetPendingByToken can locate the entry without the pending_id.
	TokenStr string

	// SourceIP is the remote address of the registering steward.
	SourceIP string

	// RegisteredAt is the time the steward first registered (and was quarantined).
	RegisteredAt time.Time

	// ExpiresAt is the deadline after which the entry is eligible for expiry sweep.
	ExpiresAt time.Time

	// ClaimedAt is set when the steward first polls an approved entry and receives its cert.
	// It is persisted before cert generation so a restart cannot yield a second cert.
	ClaimedAt *time.Time

	// Status is the current lifecycle state: pending | approved | claimed | denied | expired.
	Status string
}

// PendingRegistrationStore defines the storage interface for durable persistence of
// registration requests in the generate-on-claim approval flow.
type PendingRegistrationStore interface {
	// AddPending inserts a new pending-registration entry.
	// Returns an error if an entry with the same PendingID already exists.
	AddPending(ctx context.Context, entry *PendingRegistrationEntry) error

	// GetPendingByID retrieves the entry for the given pending_id.
	// Returns ErrPendingRegistrationNotFound if no record exists.
	GetPendingByID(ctx context.Context, pendingID string) (*PendingRegistrationEntry, error)

	// GetPendingByToken retrieves the entry whose TokenStr matches the given token.
	// Returns ErrPendingRegistrationNotFound if no matching record exists.
	GetPendingByToken(ctx context.Context, tokenStr string) (*PendingRegistrationEntry, error)

	// UpdateStatus updates the status of the entry identified by pendingID.
	// When status is "claimed", the implementation also persists claimed_at = now().
	// Returns ErrPendingRegistrationNotFound if no record exists for the ID.
	UpdateStatus(ctx context.Context, pendingID, status string) error

	// ListPending returns all entries for the given tenantID, ordered by registered_at ascending.
	// An empty tenantID returns entries for all tenants (operator list view).
	ListPending(ctx context.Context, tenantID string) ([]*PendingRegistrationEntry, error)

	// ExpireStale marks entries whose expires_at is at or before cutoff and whose status
	// is "pending" as "expired". Returns the number of entries updated.
	ExpireStale(ctx context.Context, cutoff time.Time) (int, error)
}
