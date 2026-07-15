// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package completion implements the controller-side completion reconciler for
// Hyper-V VM provisioning. It advances finalizing provisioning records to ready
// when the connecting steward's mTLS CN matches the stored CorrelationID, and
// sweeps overdue non-terminal records to failed on every OnConnect call.
//
// This package has no Windows build tags and compiles on all platforms so the
// controller can import it without pulling in steward-only Windows-tagged code.
package completion

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/modules/hyperv"
	"github.com/cfgis/cfgms/pkg/logging"
)

const defaultCompletionTimeout = 30 * time.Minute

// ProvisionCompletionReconciler implements grpc.StewardOnConnectHook. On each
// OnConnect call it:
//  1. Sweeps all non-terminal provisioning records — those whose StartedAt +
//     completionTimeout has elapsed are advanced to failed.
//  2. Searches for a record in state finalizing whose CorrelationID matches the
//     connecting steward's mTLS CN (case-insensitive) and advances it to ready.
//
// Errors are fail-open: a missed flip is recoverable on the next reconnect.
type ProvisionCompletionReconciler struct {
	store             hyperv.ProvisionStore
	completionTimeout time.Duration
	logger            logging.Logger
}

// option is a functional option for ProvisionCompletionReconciler.
type option func(*ProvisionCompletionReconciler)

// WithCompletionTimeout overrides the default completion timeout (30 min).
// Primarily used in tests to inject short durations.
func WithCompletionTimeout(d time.Duration) option {
	return func(r *ProvisionCompletionReconciler) {
		r.completionTimeout = d
	}
}

// New constructs a ProvisionCompletionReconciler with the given store and
// options. If store is nil, OnConnect is a no-op.
func New(store hyperv.ProvisionStore, logger logging.Logger, opts ...option) *ProvisionCompletionReconciler {
	r := &ProvisionCompletionReconciler{
		store:             store,
		completionTimeout: defaultCompletionTimeout,
		logger:            logger,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// OnConnect implements grpc.StewardOnConnectHook. stewardID is the
// mTLS-authenticated CN of the connecting steward.
func (r *ProvisionCompletionReconciler) OnConnect(ctx context.Context, stewardID string) error {
	if r == nil || r.store == nil {
		return nil
	}

	records, err := r.store.ListProvisions(ctx)
	if err != nil {
		return fmt.Errorf("hyperv completion reconciler: list provisions: %w", err)
	}

	now := time.Now()

	for _, rec := range records {
		if isTerminalState(rec.State) {
			continue
		}

		// Timeout sweep takes priority: advance overdue records to failed
		// regardless of whether their CorrelationID matches this steward.
		if now.Sub(rec.StartedAt) > r.completionTimeout {
			// Preserve the phase we timed out from before overwriting State, so
			// the host-side power-on gate (applySourceGated, #2467) can tell this
			// post-power-on completion timeout (fails from installing/finalizing)
			// apart from a host-side seed-phase failure. Without it these records
			// would carry an empty FailedFrom and be treated as unknown.
			rec.FailedFrom = rec.State
			rec.State = hyperv.ProvisionStateFailed
			rec.LastError = "completion.timeout elapsed"
			rec.UpdatedAt = now
			if setErr := r.store.SetProvision(ctx, rec); setErr != nil && r.logger != nil {
				r.logger.Warn("hyperv completion: failed to mark timed-out record",
					"vm_name", logging.SanitizeLogValue(rec.VMName), "error", setErr)
			}
			continue
		}

		// CorrelationID match: only finalizing records are eligible for the
		// ready transition — earlier states are still in-progress on the host.
		if rec.State == hyperv.ProvisionStateFinalizing &&
			strings.EqualFold(rec.CorrelationID, stewardID) {
			rec.State = hyperv.ProvisionStateReady
			rec.UpdatedAt = now
			if setErr := r.store.SetProvision(ctx, rec); setErr != nil {
				if r.logger != nil {
					r.logger.Warn("hyperv completion: failed to advance record to ready",
						"vm_name", logging.SanitizeLogValue(rec.VMName), "error", setErr)
				}
				return setErr
			}
			if r.logger != nil {
				r.logger.Info("hyperv completion: steward matched, record advanced to ready",
					"vm_name", logging.SanitizeLogValue(rec.VMName),
					"steward_id", logging.SanitizeLogValue(stewardID))
			}
		}
	}

	return nil
}

// isTerminalState returns true for states that require no further transitions.
func isTerminalState(s hyperv.ProvisionState) bool {
	return s == hyperv.ProvisionStateReady || s == hyperv.ProvisionStateFailed
}
