// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines business-data storage contracts for CFGMS
package business

import (
	"context"
	"errors"
	"time"
)

// ErrAlertNotFound is returned when an alert state record does not exist.
var ErrAlertNotFound = errors.New("alert not found")

// AlertStore defines the storage contract for tenant-scoped alert state.
// Alerts are identified by an opaque caller-supplied alertID string.
// The store records acknowledgement and silence state; it does not generate alerts.
type AlertStore interface {
	// AcknowledgeAlert records that principal acknowledged alertID for tenantID at time at.
	// If no record exists for the alertID it is created. Idempotent for the same alertID.
	AcknowledgeAlert(ctx context.Context, tenantID, alertID, principal string, at time.Time) error

	// SilenceAlert records that principal silenced alertID for tenantID until the given time.
	// If no record exists for the alertID it is created. A subsequent call replaces the
	// silence window. Silencing is independent of acknowledgement.
	SilenceAlert(ctx context.Context, tenantID, alertID, principal string, until time.Time) error

	// GetAlertState returns the persisted state for (tenantID, alertID).
	// Returns nil, nil when the alertID has never been acknowledged or silenced.
	GetAlertState(ctx context.Context, tenantID, alertID string) (*AlertState, error)

	// ListAlertStates returns all persisted alert states for tenantID.
	// Returns an empty (non-nil) slice when no states exist.
	ListAlertStates(ctx context.Context, tenantID string) ([]*AlertState, error)
}

// AlertState records the operator-supplied acknowledgement and silence state for one alert.
type AlertState struct {
	AlertID        string
	TenantID       string
	Acknowledged   bool
	AcknowledgedBy string
	AcknowledgedAt time.Time
	Silenced       bool
	SilencedBy     string
	SilencedUntil  time.Time
}
