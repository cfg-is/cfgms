// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package interfaces

import "context"

// CheckStewardPull is the one gate on steward-initiated pulls of controller
// data (SyncConfig, FetchModuleBundle, the controller-to-steward half of
// BulkTransfer, IssueInitialCredential). stewardID must come from the
// authenticated peer certificate, never from a request body.
//
// A locked-down steward gets the typed lockdown refusal (NewLockedDownError),
// which the steward tells apart from an identity rejection. A lookup error
// refuses too (fail closed). A nil checker installs no gate; the controller
// always wires the predicate.
func CheckStewardPull(ctx context.Context, checker LockdownChecker, stewardID string) error {
	if checker == nil {
		return nil
	}
	locked, err := checker.IsLockedDown(ctx, stewardID)
	if err != nil || locked {
		return NewLockedDownError()
	}
	return nil
}

// CheckControllerRequest is the gate on a request the controller originates
// toward a steward over a stream the steward opened (TelemetryRequest,
// OsqueryQuery). For a locked-down steward the request runs only when ctx
// carries the operator-origin marker. A lookup error refuses. It returns
// ErrStewardLockedDown, as the command gate does.
func CheckControllerRequest(ctx context.Context, checker LockdownChecker, stewardID string) error {
	if checker == nil {
		return nil
	}
	locked, err := checker.IsLockedDown(ctx, stewardID)
	if err != nil {
		return ErrStewardLockedDown
	}
	if !locked {
		return nil
	}
	if _, ok := OperatorOriginFrom(ctx); !ok {
		return ErrStewardLockedDown
	}
	return nil
}
