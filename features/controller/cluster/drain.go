// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cluster

import (
	"context"
	"errors"
	"fmt"
)

// ErrNodeNotActive is returned by Drain when the target node exists but is not
// in StateActive. Draining a node that is already draining or decommissioned is
// a no-op-equivalent that callers should treat as HTTP 409.
var ErrNodeNotActive = errors.New("cluster: node is not active")

// DrainHealthRegistrar is implemented by the API server to bridge the drain
// operation to the health endpoint. When SetDraining(true) is called, GET
// /api/v1/health returns HTTP 503, signalling the load balancer to stop routing
// new steward connections to this node.
type DrainHealthRegistrar interface {
	SetDraining(bool)
}

// Drain marks nodeID as StateDraining in store and calls registrar.SetDraining(true).
// It validates that the node exists and is currently StateActive before making any
// state change, so the store and the health gate are never mutated for invalid targets.
func Drain(_ context.Context, nodeID string, store MembershipStore, registrar DrainHealthRegistrar) error {
	node, err := store.GetNode(nodeID)
	if err != nil {
		return fmt.Errorf("drain %s: %w", nodeID, err)
	}
	if node.State != StateActive {
		return fmt.Errorf("drain %s: %w (current state: %s)", nodeID, ErrNodeNotActive, node.State)
	}
	if err := store.SetState(nodeID, StateDraining); err != nil {
		return fmt.Errorf("drain %s: set state: %w", nodeID, err)
	}
	registrar.SetDraining(true)
	return nil
}
