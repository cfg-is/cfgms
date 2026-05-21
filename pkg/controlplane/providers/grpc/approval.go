// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package grpc

import "context"

// StewardApprovalChecker is the extension point for the approval-gate epic
// (#1690–#1698). When injected via WithApprovalChecker, the ControlChannel
// handler calls it for every connecting steward before admitting the stream.
//
// Implementors return (false, nil) to silently reject the steward, (true, nil)
// to admit it, or (_, err) when the check cannot be completed (the ControlChannel
// handler logs the error and admits the steward so transient failures do not
// take endpoints offline — the same fail-open policy used by the HTTP
// registration approval hook).
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
