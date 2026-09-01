// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package lease implements the fenced, quorum-equivalent singleton-claim
// primitive described in ADR-031 Decision 5. It is the standalone primitive
// that will eventually replace pkg/ha's Raft-backed HasLeadership()/GetTerm()
// (that cutover is a later story — S6 — and is not performed here).
//
// # Split-brain bound
//
// ADR-029 Decisions 1-2 bound how long two Raft nodes can simultaneously
// believe they hold authority. This package derives and enforces the
// equivalent bound for the database-lease substrate:
//
//   - A successful TryAcquire/Renew is cached locally with a monotonic-clock
//     deadline (HasLocalAuthority) so admission checks do not require a live
//     database round-trip on every call.
//   - The cache is valid only until safetyMargin has elapsed since the store
//     call that granted the last successful acquire/renew was *issued* (not
//     since it returned — see recordLocalAuthority), where
//     safetyMargin = leaseTTL − renewalInterval − maxAllowedRenewalLatency
//     (SafetyMargin), validated strictly positive at Manager construction.
//   - Elapsed-time arithmetic for that cached deadline uses only Go's
//     monotonic clock (time.Since on a time.Time obtained from time.Now()) —
//     mirroring ADR-029 Decision 2 exactly, for the same reason (Issue
//     #2037): absolute wall-clock offset between hosts must never enter an
//     authority decision.
//   - The lease row's own expires_at, used by TryAcquire's contention logic
//     inside business.LeaseStore, may use database/wall-clock time — that
//     clock only needs to be consistent with itself on one database server.
//     For that to hold, the row's expiry must also be *derived* and *evaluated*
//     on that one clock, never on a client's: mixing the two would reintroduce
//     the cross-host offset by the back door, and fail open (a client whose
//     clock trails the server writes an already-expired lease, so a second
//     node acquires while the first still reports local authority). This
//     package therefore never compares a stored expires_at to its own
//     time.Now(); it reads the store's own verdict
//     (business.LeaseState.Valid) — see CurrentHolder.
package lease

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// SafetyMargin derives the interval for which a cached local-authority check
// (HasLocalAuthority) may be trusted without a live database read, mirroring
// ADR-029 Decision 1's derivation of the Raft lease margin from
// ElectionTimeout.
//
//	safetyMargin = leaseTTL − renewalInterval − maxAllowedRenewalLatency
//
// leaseTTL is the duration a database lease row remains valid after an
// acquire/renew. renewalInterval is how often the holder attempts to renew.
// maxAllowedRenewalLatency is the longest a renewal call is allowed to take
// (including retries) before it must be treated as failed. The result must be
// strictly positive: a non-positive margin means the holder cannot possibly
// renew often enough, relative to the TTL, to keep the lease alive, which is
// a configuration error the primitive must refuse to start with rather than
// a latent bug discovered under load.
func SafetyMargin(leaseTTL, renewalInterval, maxAllowedRenewalLatency time.Duration) (time.Duration, error) {
	margin := leaseTTL - renewalInterval - maxAllowedRenewalLatency
	if margin <= 0 {
		return 0, fmt.Errorf(
			"lease: derived safety margin must be strictly positive: leaseTTL(%s) - renewalInterval(%s) - maxAllowedRenewalLatency(%s) = %s",
			leaseTTL, renewalInterval, maxAllowedRenewalLatency, margin)
	}
	return margin, nil
}

// cachedAuthority is the local record of the most recent successful
// acquire/renew for one lease name, keyed on a monotonic time.Time.
type cachedAuthority struct {
	holderID            string
	token               uint64
	acquiredOrRenewedAt time.Time
}

// Manager is the client-facing entry point for pkg/lease. One Manager is
// configured with a single leaseTTL (and the renewalInterval/
// maxAllowedRenewalLatency used to derive its safety margin); every lease
// name it manages shares that configuration, so TryAcquire's ttl argument
// must equal the configured leaseTTL — the safety margin is only a valid
// bound for the TTL it was derived from.
type Manager struct {
	store business.LeaseStore

	leaseTTL                 time.Duration
	renewalInterval          time.Duration
	maxAllowedRenewalLatency time.Duration
	safetyMargin             time.Duration

	mu     sync.RWMutex
	cached map[string]cachedAuthority
}

// NewManager constructs a Manager backed by store. It computes and validates
// SafetyMargin(leaseTTL, renewalInterval, maxAllowedRenewalLatency) and
// refuses to start if the derived margin is not strictly positive.
func NewManager(store business.LeaseStore, leaseTTL, renewalInterval, maxAllowedRenewalLatency time.Duration) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("lease: store cannot be nil")
	}
	margin, err := SafetyMargin(leaseTTL, renewalInterval, maxAllowedRenewalLatency)
	if err != nil {
		return nil, err
	}
	return &Manager{
		store:                    store,
		leaseTTL:                 leaseTTL,
		renewalInterval:          renewalInterval,
		maxAllowedRenewalLatency: maxAllowedRenewalLatency,
		safetyMargin:             margin,
		cached:                   make(map[string]cachedAuthority),
	}, nil
}

// SafetyMargin returns this Manager's derived local-authority-cache window.
func (m *Manager) SafetyMargin() time.Duration { return m.safetyMargin }

// LeaseTTL returns this Manager's configured lease TTL.
func (m *Manager) LeaseTTL() time.Duration { return m.leaseTTL }

// TryAcquire attempts to claim or renew the lease named name on behalf of
// holderID. ttl must equal the Manager's configured leaseTTL — the local
// -authority safety margin is derived from that TTL and is not a valid bound
// for any other duration.
//
// On success (acquired == true) the returned token is cached locally as
// name's current local authority, starting a fresh safetyMargin-bounded
// validity window (see HasLocalAuthority). On contention (acquired == false)
// any previously cached local authority for name held by holderID is
// invalidated, since the database has just confirmed a different holder owns
// it.
func (m *Manager) TryAcquire(ctx context.Context, name string, holderID string, ttl time.Duration) (token uint64, acquired bool, err error) {
	if ttl != m.leaseTTL {
		return 0, false, fmt.Errorf(
			"lease: ttl %s does not match this Manager's configured lease TTL %s; the derived safety margin is not valid for any other TTL",
			ttl, m.leaseTTL)
	}

	callStart := time.Now()
	state, err := m.store.AcquireOrRenew(ctx, name, holderID, ttl)
	if err != nil {
		return 0, false, err
	}
	if !state.Acquired {
		m.invalidateLocalAuthority(name, holderID)
		return state.Token, false, nil
	}

	m.recordLocalAuthority(name, holderID, state.Token, callStart)
	return state.Token, true, nil
}

// Renew extends the lease named name on behalf of holderID, which must
// currently hold token. Renew never changes the fencing token — a change
// would mean the database had already treated the call as a fresh
// acquisition (because the lease had actually expired, or is now held by
// someone else), which Renew reports as an error rather than silently
// returning a token the caller did not ask to hold.
func (m *Manager) Renew(ctx context.Context, name string, holderID string, token uint64) (newToken uint64, err error) {
	callStart := time.Now()
	state, err := m.store.AcquireOrRenew(ctx, name, holderID, m.leaseTTL)
	if err != nil {
		return 0, err
	}
	if !state.Acquired {
		m.invalidateLocalAuthority(name, holderID)
		return 0, fmt.Errorf("lease: %q is held by a different holder (%s); %s is fenced out", name, state.HolderID, holderID)
	}
	if state.Token != token {
		m.invalidateLocalAuthority(name, holderID)
		return 0, fmt.Errorf(
			"lease: %q was re-acquired with a new token (%d) before this renewal; holder %s's token %d is fenced out",
			name, state.Token, holderID, token)
	}

	m.recordLocalAuthority(name, holderID, token, callStart)
	return token, nil
}

// Release relinquishes the lease named name on behalf of holderID/token and
// invalidates any locally cached authority for name. Idempotent: releasing a
// lease already lost to another holder (a stale token) is a no-op at the
// store layer.
func (m *Manager) Release(ctx context.Context, name string, holderID string, token uint64) error {
	m.invalidateLocalAuthority(name, holderID)
	return m.store.Release(ctx, name, holderID, token)
}

// CurrentHolder performs a live read of the lease named name. Unlike
// HasLocalAuthority, this always reads through to the durable store — it is
// the "who holds this right now" query, not the cached admission check. ok is
// true only when a row exists and the store reported it unexpired.
//
// The expiry verdict is the store's (business.LeaseState.Valid), evaluated
// against the store's own clock; it is deliberately not re-derived here by
// comparing the returned expiresAt to this host's time.Now(). Doing so would
// put the offset between this host's wall clock and the database server's into
// an authority answer — the thing this package's split-brain bound exists to
// exclude. expiresAt is returned for observability only.
func (m *Manager) CurrentHolder(ctx context.Context, name string) (holderID string, token uint64, expiresAt time.Time, ok bool, err error) {
	state, err := m.store.GetLease(ctx, name)
	if err != nil {
		if errors.Is(err, business.ErrLeaseNotFound) {
			return "", 0, time.Time{}, false, nil
		}
		return "", 0, time.Time{}, false, err
	}
	return state.HolderID, state.Token, state.ExpiresAt, state.Valid, nil
}

// HasLocalAuthority reports whether holderID's most recent successful
// TryAcquire/Renew for name is still within this Manager's safety-margin
// window, using only Go's monotonic clock (time.Since) — no database read.
// This is the admission-check primitive: callers gate side effects on this,
// not on CurrentHolder.
func (m *Manager) HasLocalAuthority(name string, holderID string) (token uint64, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	c, exists := m.cached[name]
	if !exists || c.holderID != holderID {
		return 0, false
	}
	if time.Since(c.acquiredOrRenewedAt) >= m.safetyMargin {
		return 0, false
	}
	return c.token, true
}

// recordLocalAuthority caches holderID's authority for name. callStart is the
// monotonic instant *before* the store call that granted it, never the instant
// the call returned: the store stamps expires_at when it applies the write,
// which is at or after callStart, so anchoring the window at callStart keeps
// the cache lapsing (callStart+safetyMargin) strictly before the row can
// expire (>= callStart+leaseTTL, and safetyMargin < leaseTTL by construction)
// no matter how long the call took. Anchoring on the return instant instead
// leaks the round-trip latency into the window, and a call slower than
// maxAllowedRenewalLatency then leaves this holder claiming authority past the
// point where another holder can legitimately take the lease — the dual-holder
// overlap this package exists to bound.
func (m *Manager) recordLocalAuthority(name, holderID string, token uint64, callStart time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cached[name] = cachedAuthority{
		holderID:            holderID,
		token:               token,
		acquiredOrRenewedAt: callStart,
	}
}

// invalidateLocalAuthority clears the cached entry for name, but only if it
// currently belongs to holderID — a losing contender must not be able to
// clear the winner's cache entry out from under it.
func (m *Manager) invalidateLocalAuthority(name, holderID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, exists := m.cached[name]; exists && c.holderID == holderID {
		delete(m.cached, name)
	}
}
