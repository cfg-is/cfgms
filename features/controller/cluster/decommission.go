// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cluster

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// ErrNodeNotDraining is returned by Decommission when the target node is not
// in StateDraining. Callers should treat this as HTTP 409.
var ErrNodeNotDraining = errors.New("cluster: node is not draining")

// SessionCounter provides the active-session count on the local node.
// Satisfied by registry.Registry; defined here as a minimal interface to
// avoid coupling the cluster package to the transport layer.
type SessionCounter interface {
	Count() int
}

// decommissionPollInterval is the interval between session-count polls.
const decommissionPollInterval = 5 * time.Second

// Decommission waits for active steward sessions on the local node to reach
// zero (or for timeout to elapse), then marks nodeID as StateDecommissioned
// in store.
//
// The node must be in StateDraining before Decommission is called. If it is
// not, Decommission returns ErrNodeNotDraining without touching the store.
//
// If timeout elapses before counter.Count() reaches zero, Decommission logs a
// warning and proceeds to mark the node decommissioned anyway — forced
// decommission on timeout is by design.
//
// After a successful return, store.ListActiveNodes() will not include nodeID.
func Decommission(ctx context.Context, nodeID string, store MembershipStore, counter SessionCounter, logger logging.Logger, timeout time.Duration) error {
	node, err := store.GetNode(nodeID)
	if err != nil {
		return fmt.Errorf("decommission %s: %w", nodeID, err)
	}
	if node.State != StateDraining {
		return fmt.Errorf("decommission %s: %w (current state: %s)", nodeID, ErrNodeNotDraining, node.State)
	}

	pollCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if !waitForSessionDrain(pollCtx, counter) {
		logger.Warn("decommission timeout: sessions still active on node, proceeding",
			"active_sessions", counter.Count(),
			"node_id", logging.SanitizeLogValue(nodeID))
	}

	if err := store.SetState(nodeID, StateDecommissioned); err != nil {
		return fmt.Errorf("decommission %s: set state: %w", nodeID, err)
	}
	return nil
}

// waitForSessionDrain polls counter.Count() every decommissionPollInterval
// until it reaches zero or ctx is cancelled. Returns true when drained,
// false on context cancellation (timeout or explicit cancel).
func waitForSessionDrain(ctx context.Context, counter SessionCounter) bool {
	if counter.Count() == 0 {
		return true
	}
	ticker := time.NewTicker(decommissionPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			if counter.Count() == 0 {
				return true
			}
		}
	}
}
