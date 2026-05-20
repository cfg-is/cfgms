// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package business defines the PendingRegistrationStore interface for the
// manual-review registration approval mode (Issue #1599).
package business

import (
	"context"
	"errors"
	"time"
)

// ErrPendingRegistrationNotFound is returned when a pending registration record does not exist.
var ErrPendingRegistrationNotFound = errors.New("pending registration not found")

// PendingRegistrationStatus represents the lifecycle state of a pending registration request.
type PendingRegistrationStatus string

const (
	// PendingRegistrationStatusPending indicates the request is awaiting operator action.
	PendingRegistrationStatusPending PendingRegistrationStatus = "pending"

	// PendingRegistrationStatusApproved indicates an operator approved the request.
	PendingRegistrationStatusApproved PendingRegistrationStatus = "approved"

	// PendingRegistrationStatusDenied indicates an operator denied the request.
	PendingRegistrationStatusDenied PendingRegistrationStatus = "denied"

	// PendingRegistrationStatusTimedOut indicates the request expired before an operator acted.
	PendingRegistrationStatusTimedOut PendingRegistrationStatus = "timed-out"
)

// PendingRegistrationData holds the durable state for a single registration request
// queued for manual review.
//
// The full registration token is never stored. TokenPrefix holds only a redacted
// identifier so operators can correlate the request without exposing the secret.
type PendingRegistrationData struct {
	// ID is the unique pending-registration identifier.
	ID string

	// StewardID is the steward identifier assigned after approval. Empty while pending.
	StewardID string

	// TenantID is the tenant the registering steward belongs to.
	TenantID string

	// SourceIP is the remote address of the registering steward.
	SourceIP string

	// TokenPrefix is the redacted registration-token identifier (never the full token).
	TokenPrefix string

	// Status is the current lifecycle state of the request.
	Status PendingRegistrationStatus

	// DenyReason is a human-readable reason set when the request is denied or timed out.
	DenyReason string

	// CreatedAt is the time the request was queued.
	CreatedAt time.Time

	// ExpiresAt is the deadline after which the request is auto-rejected.
	ExpiresAt time.Time
}

// PendingRegistrationFilter narrows the results of ListPending. A nil filter, or a
// filter with all fields nil, returns every pending-registration record.
type PendingRegistrationFilter struct {
	// Status, when set, restricts results to records with the given status.
	Status *PendingRegistrationStatus

	// ExpiresBeforeOrAt, when set, restricts results to records whose ExpiresAt
	// is at or before the given time. Used by the expiry sweep to find timed-out records.
	ExpiresBeforeOrAt *time.Time

	// TenantID, when set, restricts results to records for the given tenant.
	TenantID *string
}

// PendingRegistrationStore defines the storage interface for durable persistence
// of registration requests awaiting manual review.
type PendingRegistrationStore interface {
	// CreatePending inserts a new pending-registration record.
	// Returns an error if a record with the same ID already exists.
	CreatePending(ctx context.Context, record *PendingRegistrationData) error

	// GetPending retrieves the pending-registration record for the given ID.
	// Returns ErrPendingRegistrationNotFound if no record exists.
	GetPending(ctx context.Context, id string) (*PendingRegistrationData, error)

	// ListPending returns all records matching the filter, ordered by CreatedAt ascending.
	// A nil filter returns every record.
	ListPending(ctx context.Context, filter *PendingRegistrationFilter) ([]*PendingRegistrationData, error)

	// UpdatePendingStatus updates the status and deny reason of the given record.
	// Returns ErrPendingRegistrationNotFound if no record exists for the ID.
	UpdatePendingStatus(ctx context.Context, id string, status PendingRegistrationStatus, reason string) error

	// DeletePending removes the pending-registration record for the given ID.
	// Returns ErrPendingRegistrationNotFound if no record exists.
	DeletePending(ctx context.Context, id string) error
}
