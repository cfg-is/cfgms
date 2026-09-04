// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines business-data storage contracts for CFGMS
package business

import (
	"context"
	"time"
)

// NodeRegistryStaleAfter is the liveness window evaluated by
// NodeRegistryStore.ListNodes (Issue #3763, ADR-031 Decision 5's post-Raft
// membership mechanism). A node record that has not been refreshed within
// this window is stale and must not be reported as a live cluster member:
// the owning process may have crashed or lost connectivity to the shared
// store without ever deregistering. A stale record is dropped from
// ListNodes entirely, mirroring RoutingStore's staleness handling.
//
// Matches backgroundLoopLeaseTTL (pkg/ha) so a dead node's registry record
// frees up on the same cadence as a dead background-loop lease holder.
const NodeRegistryStaleAfter = 90 * time.Second

// NodeRecord is a single controller node's advertised identity in the shared
// node registry.
type NodeRecord struct {
	// ID is the node's unique identifier (Config.Node.ID in pkg/ha).
	ID string

	// Address is the node's advertised address for peer-to-peer traffic
	// (e.g. the internal delivery service).
	Address string
}

// NodeRegistryStore defines the shared controller-node registry (Issue
// #3763, ADR-031 Decision 5's post-Raft membership mechanism): each
// ClusterMode node's advertised identity, visible to every node in a
// cluster deployment.
//
// This is the primitive pkg/ha's GetClusterNodes()/GetLeader() read to
// report cluster membership beyond the local node, replacing the Raft FSM's
// confState-derived membership view.
//
// One clock only: staleness is evaluated by comparing each record's
// last-refreshed timestamp against the store's own clock, exactly as
// RoutingStore.LookupNode and LeaseStore.AcquireOrRenew do — never against a
// timestamp the caller computed, which would let a clock offset between
// hosts decide cluster membership (ADR-029 Decision 2 / Issue #2037).
//
// Implementations must be safe for concurrent use.
type NodeRegistryStore interface {
	// RegisterNode upserts self's record, refreshing its liveness timestamp
	// to the store's own clock at the instant the call is applied. Called
	// repeatedly on a fixed interval (pkg/ha's runNodeRegistration) so a live
	// node's record never goes stale.
	RegisterNode(ctx context.Context, self NodeRecord) error

	// ListNodes returns every node record whose liveness timestamp is within
	// NodeRegistryStaleAfter of the store's own clock. A stale record is
	// omitted entirely, never returned with a "stale" flag a caller might
	// forget to check.
	ListNodes(ctx context.Context) ([]NodeRecord, error)

	// Close releases resources held by the store.
	Close() error
}
