// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines business-data storage contracts for CFGMS
package business

import (
	"context"
	"time"
)

// RoutingStaleAfter is the liveness window evaluated by RoutingStore.LookupNode
// (ADR-031 Decision 3, Issue #3764). A connection record whose owning node has
// not refreshed it within this window is stale and must not be trusted: the
// owning node may have crashed or lost its steward connection without ever
// reaching RemoveConnection (e.g. a hard process kill, or a network partition
// that prevents the disconnect hook from running). A stale record is treated
// the same as no record — the caller falls back to the durable outbox (Issue
// #3757) rather than forwarding to a node that may no longer hold the
// connection.
//
// The owning node refreshes its own records on every steward connect and on
// every subsequent heartbeat (heartbeats arrive well inside this window at
// normal cadence), so a live connection's record never goes stale in normal
// operation.
const RoutingStaleAfter = 90 * time.Second

// RoutingStore defines the shared steward-routing table (ADR-031 Decision 3,
// Issue #3764): which controller node currently holds a steward's
// control-plane connection, visible to every node in a cluster deployment.
//
// This is the primitive the internal controller-to-controller delivery
// service consults to resolve node locality before forwarding a command to a
// peer: node A looks up stewardID here, and if a peer node B's ID comes back,
// A calls B's delivery RPC instead of failing with "steward not connected".
//
// One clock only: staleness is evaluated by comparing each record's
// last-refreshed timestamp against the store's own clock, exactly as
// LeaseStore's expiry check does — never against a timestamp the caller
// computed, which would let a clock offset between hosts decide whether a
// connection record is trusted (ADR-029 Decision 2 / Issue #2037).
//
// Implementations must be safe for concurrent use.
type RoutingStore interface {
	// RecordConnection upserts the fact that stewardID's control-plane
	// connection is currently held by nodeID, refreshing the record's
	// liveness timestamp to the store's own clock at the instant the call is
	// applied. Called on every steward connect and on every subsequent
	// heartbeat so a live connection's record never goes stale.
	RecordConnection(ctx context.Context, stewardID, nodeID string) error

	// LookupNode returns the node currently believed to hold stewardID's
	// connection. ok is false when no record exists, or when the existing
	// record's liveness timestamp is older than RoutingStaleAfter as measured
	// by the store's own clock — a stale record is reported exactly like a
	// missing one, never as a stale nodeID a caller might act on.
	LookupNode(ctx context.Context, stewardID string) (nodeID string, ok bool, err error)

	// RemoveConnection deletes the routing record for stewardID, but only if
	// it is currently attributed to nodeID. A record already reassigned to a
	// different node (the steward reconnected elsewhere before this node's
	// disconnect hook ran) must not be removed by a late-arriving disconnect
	// from the node that lost the race — doing so would erase the newer,
	// correct record. Idempotent: removing an already-absent record is a
	// no-op.
	RemoveConnection(ctx context.Context, stewardID, nodeID string) error

	// Close releases resources held by the store.
	Close() error
}
