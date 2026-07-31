// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"fmt"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// StewardApprovalChecker is the extension point for the approval-gate epic
// (#1690–#1698). When injected via WithApprovalChecker, the ControlChannel
// handler calls it for every connecting steward before admitting the stream.
//
// Implementors return (false, nil) to reject the steward, (true, nil) to admit
// it, or (_, err) when the check cannot be completed. Errors are fail-closed.
//
// The default behaviour (no checker injected) is equivalent to always returning
// (true, nil): all mTLS-authenticated stewards are admitted.
type StewardApprovalChecker interface {
	// IsApproved returns true when the steward identified by stewardID is
	// permitted to open a ControlChannel stream.
	IsApproved(ctx context.Context, stewardID string) (bool, error)
}

// WithApprovalChecker injects a StewardApprovalChecker into the Provider.
// The checker is called in server mode whenever a steward opens a ControlChannel.
// Intended for the approval-gate epic (#1690–#1698); production code that does
// not need approval gating should leave the default (nil, always-admit).
func WithApprovalChecker(checker StewardApprovalChecker) option {
	return func(p *Provider) {
		p.approvalChecker = checker
	}
}

type stewardStoreApprovalChecker struct {
	store business.StewardStore
}

// NewStewardStoreApprovalChecker builds the production admission checker. Only
// stewards in reconnect-capable lifecycle states may open a ControlChannel.
func NewStewardStoreApprovalChecker(store business.StewardStore) StewardApprovalChecker {
	return &stewardStoreApprovalChecker{store: store}
}

func (c *stewardStoreApprovalChecker) IsApproved(ctx context.Context, stewardID string) (bool, error) {
	if c.store == nil {
		return false, fmt.Errorf("steward approval store is unavailable")
	}
	record, err := c.store.GetSteward(ctx, stewardID)
	if err != nil {
		return false, fmt.Errorf("load steward approval state: %w", err)
	}
	switch record.Status {
	case business.StewardStatusRegistered, business.StewardStatusActive, business.StewardStatusLost:
		return true, nil
	default:
		return false, nil
	}
}
