// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines business-data storage contracts for CFGMS
package business

import (
	"context"
	"errors"
	"time"
)

// ErrLeaseNotFound is returned by GetLease when no row has ever been created
// for the given lease name (it has never been acquired).
var ErrLeaseNotFound = errors.New("lease not found")

// LeaseStore defines the durable interface backing pkg/lease — the fenced,
// quorum-equivalent singleton-claim primitive described in ADR-031 Decision 5.
//
// A lease row is identified by name and tracks a current holder, a monotonic
// fencing token, and an expiry. The fencing token is never reused: every
// successful acquisition (first creation, a different holder taking over an
// expired lease, or the same holder re-acquiring after its own lease expired)
// assigns a strictly higher token than any previously issued for that name. A
// renewal by the current, unexpired holder never advances the token.
//
// The expiry is expressed in the store's own clock — the database server's for
// a networked provider, the local process clock for single-process providers.
// That clock only needs to be consistent with itself. Implementations must
// therefore derive and evaluate expiry entirely on that one clock: a caller's
// wall clock must never reach the stored column, because the offset between a
// caller's clock and the store's would then decide who holds the lease, which
// fails open (two simultaneous holders) after a routine NTP step or VM
// suspend/resume. This mirrors ADR-029 Decision 2 / Issue #2037: absolute
// wall-clock offset between hosts must never enter an authority decision.
//
// Consequently ExpiresAt is reported for observability only. Validity is
// reported separately, in LeaseState.Valid, as evaluated by the store against
// its own clock; callers must never re-derive it by comparing ExpiresAt to
// their own time.Now(). Callers needing an authority check that survives a
// store outage use pkg/lease's monotonic-clock local cache rather than reading
// the store on every check.
type LeaseStore interface {
	// AcquireOrRenew attempts to claim or renew the lease named name on behalf
	// of holderID for ttl measured from the store's own clock at the instant
	// the store applies the call — never from a timestamp computed by the
	// caller.
	//
	// If no row exists yet, one is created with a fresh token and the returned
	// LeaseState has Acquired set to true.
	//
	// If a row exists and is expired (regardless of which holder last held it,
	// including holderID itself), it is claimed by holderID with a strictly
	// higher token than any previously issued for name; Acquired is true.
	//
	// If a row exists, is unexpired, and is currently held by holderID, this is
	// a renewal: expires_at is extended by ttl from now and the token is left
	// unchanged; Acquired is true.
	//
	// If a row exists, is unexpired, and is held by a different holder, the
	// call does not change any state. The returned LeaseState reflects the
	// current holder/token/expiry and Acquired is false.
	AcquireOrRenew(ctx context.Context, name, holderID string, ttl time.Duration) (*LeaseState, error)

	// Release relinquishes the lease named name if it is currently held by
	// holderID with the given token. The token is preserved as the lease's
	// high-water mark (a subsequent acquisition still receives a strictly
	// higher token) — the row is force-expired, never deleted or reset.
	//
	// Idempotent: if the lease does not exist, or is held by a different
	// holder or a different (already-superseded) token, Release is a no-op
	// and returns nil. A stale, fenced-out holder's release must never disturb
	// whichever holder currently owns the lease.
	Release(ctx context.Context, name, holderID string, token uint64) error

	// GetLease returns the current row for name, regardless of whether it is
	// expired. Validity is evaluated by the store against its own clock and
	// reported in LeaseState.Valid; callers must read that field rather than
	// comparing ExpiresAt against their own notion of "now". Returns
	// ErrLeaseNotFound if name has never been acquired.
	GetLease(ctx context.Context, name string) (*LeaseState, error)

	// Close releases resources held by the store.
	Close() error
}

// NodeSharedLeaseStore is an optional LeaseStore extension by which an
// implementation declares whether its lease rows are shared by every controller
// node in the deployment.
//
// Mutual exclusion is a property of the substrate, not of the lease algorithm: a
// perfectly correct fenced lease held in a per-node database file excludes
// nothing, because each node contends only with itself. Every node then acquires
// the same lease name, reports itself the singleton holder, and mints its own
// token sequence starting at 1 — the failure the lease exists to prevent. A
// deployment that uses the lease as cluster-wide authority (ADR-031 Decision 5)
// must therefore verify the substrate is shared, not merely that a store exists.
//
// Implementations report the property of their backend, not of a particular
// deployment: a networked database every node connects to is shared; a local file
// or embedded database opened at a path on the node's own disk is not.
type NodeSharedLeaseStore interface {
	LeaseStore

	// SharedAcrossNodes reports true only when every controller node in a
	// multi-node deployment contends for the same lease rows through this
	// backend.
	SharedAcrossNodes() bool
}

// LeaseStoreIsNodeShared reports whether store's substrate is shared by all
// controller nodes, and is therefore usable as cluster-wide authority.
//
// Fails closed in both directions: a nil store and a store that does not
// implement NodeSharedLeaseStore are both reported as node-local. A backend that
// is genuinely shared has to say so; silence never grants authority.
func LeaseStoreIsNodeShared(store LeaseStore) bool {
	if store == nil {
		return false
	}
	shared, ok := store.(NodeSharedLeaseStore)
	return ok && shared.SharedAcrossNodes()
}

// LeaseState is a snapshot of a lease row.
type LeaseState struct {
	Name     string
	HolderID string
	Token    uint64

	// ExpiresAt is the stored expiry, expressed in the store's clock. It is
	// reported for observability (logging, status endpoints) only: comparing
	// it against a caller's local clock is exactly the cross-host offset the
	// LeaseStore contract forbids from entering an authority decision. Use
	// Valid instead.
	ExpiresAt time.Time

	// Valid is the store's own verdict, computed against the same clock that
	// produced ExpiresAt, on whether the row was unexpired at the instant the
	// store evaluated it.
	Valid bool

	// Acquired is meaningful only as the return value of AcquireOrRenew: true
	// if the call's caller now holds the lease (whether by fresh acquisition
	// or renewal), false if a different holder currently holds it unexpired.
	Acquired bool
}
