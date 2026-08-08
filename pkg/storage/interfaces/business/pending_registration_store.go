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

	// TokenStr is a deterministic, non-reversible registration-token lookup key.
	// Stores must hash a raw token before persistence; legacy plaintext rows may be
	// read only for migration compatibility.
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

	// GetPendingByToken hashes the supplied raw token and retrieves *an* entry that
	// matches. Returns ErrPendingRegistrationNotFound if no matching record exists.
	//
	// Registration tokens are perennial (Issue #1690), so one token routinely has
	// several devices quarantined against it and this lookup cannot say which
	// entry it returned. Never use it to answer a specific device — doing so hands
	// that device another device's pending_id. Address a known device's entry by
	// PendingID via GetPendingByID instead.
	GetPendingByToken(ctx context.Context, tokenStr string) (*PendingRegistrationEntry, error)

	// UpdateStatus updates the status of the entry identified by pendingID.
	// When status is "claimed", the implementation also persists claimed_at = now().
	// Returns ErrPendingRegistrationNotFound if no record exists for the ID.
	UpdateStatus(ctx context.Context, pendingID, status string) error

	// ListPending returns entries whose status is "pending", ordered by registered_at ascending.
	// An empty tenantID returns pending entries for all tenants (operator list view).
	// Approved, denied, claimed, and expired entries are never included.
	ListPending(ctx context.Context, tenantID string) ([]*PendingRegistrationEntry, error)

	// ExpireStale marks entries whose expires_at is at or before cutoff and whose status
	// is "pending" as "expired". Returns the number of entries updated.
	ExpireStale(ctx context.Context, cutoff time.Time) (int, error)
}
