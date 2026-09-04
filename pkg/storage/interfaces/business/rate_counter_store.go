// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
// Package business defines the RateCounterStore interface for cluster-visible
// abuse-budget counters (ADR-031 Decision 1, Issue #3896 — the durable follow-up
// to Issue #3761's clusterBudgetDivisor approximation). Before this store
// existed, the per-source rate limiters (features/controller/api/rate_limiter.go)
// and the operator-payload sign-ceremony throttle
// (features/controller/api/handlers_operator_payload_sign.go) kept their
// counters in per-process memory and divided their configured budget by the
// live cluster-node count to approximate a shared counter under any-node
// service — an approximation that assumed attempts spread evenly across nodes
// and that an adversary deliberately targeting one node could defeat. This
// store lets a fixed-window budget be enforced against the real fleet-wide
// count instead.
package business

import (
	"context"
	"errors"
	"time"
)

// ErrRateCounterCapacityExhausted reports that a store declined to begin
// tracking a new key because doing so would push it past its bound on distinct
// tracked keys. Callers MUST treat it as a denial (fail closed), not as a
// generic store error to be failed open: the keys driving these counters
// include the source address of unauthenticated routes, so an attacker
// rotating addresses is exactly what exhausts the bound, and allowing the call
// would hand every fresh address an untracked, unlimited budget. It is the
// shared-store equivalent of the in-memory limiter's maxTrackedKeys backstop
// (features/controller/api/rate_limiter.go), which denies a brand-new key
// rather than tracking it once the cap is reached.
var ErrRateCounterCapacityExhausted = errors.New("rate counter store: tracked-key capacity exhausted")

// RateCounterStore defines durable, cluster-visible storage for fixed-window
// abuse-budget counters. A cluster-visible implementation makes an attempt
// recorded on one controller node immediately visible to, and counted against
// the same budget by, every other node sharing the store — closing the gap an
// any-node deployment opens for a per-process counter.
//
// Because the counters are keyed on attacker-chosen identities (the source
// address of unauthenticated routes among them), an implementation MUST bound
// its own growth on both axes the in-memory limiter it replaces bounds:
//
//   - Elapsed windows must be reclaimed, not merely overwritten on the next
//     Increment. A key that never recurs — the flooding case — is never
//     overwritten, so overwrite-in-place alone lets storage grow with the
//     number of distinct keys ever seen.
//   - The number of distinct keys tracked at once must be capped. On reaching
//     the cap, Increment must decline a brand-new key with an error wrapping
//     ErrRateCounterCapacityExhausted, while continuing to serve keys already
//     tracked so live budgets keep being enforced.
type RateCounterStore interface {
	// Increment atomically records one attempt against key within its current
	// fixed window and returns the resulting count together with the
	// remaining time until that window resets. A window is fresh — starting
	// at count 1 — whenever the previous one has fully elapsed (i.e. more
	// than window has passed since the window began), mirroring the
	// in-memory fixed-window record this store replaces. The atomicity is
	// with respect to every other caller of this store, including callers on
	// different controller nodes sharing it, so a concurrent increment race
	// from two nodes against the same key never loses an attempt.
	//
	// When key is not already tracked and the store is at its tracked-key
	// cap, Increment records nothing and returns an error wrapping
	// ErrRateCounterCapacityExhausted together with the duration the caller
	// should deny for; callers fail closed on that error.
	Increment(ctx context.Context, key string, window time.Duration) (count int, retryAfter time.Duration, err error)

	// Peek reports the count and remaining window time currently recorded for
	// key, without recording a new attempt. found is false when key has no
	// currently open window — either it has never been incremented, or its
	// window has fully elapsed — in which case count and retryAfter are zero.
	Peek(ctx context.Context, key string, window time.Duration) (count int, retryAfter time.Duration, found bool, err error)

	Close() error
}
