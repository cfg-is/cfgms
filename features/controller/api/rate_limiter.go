// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// sourceRateLimiterDefaultMaxTrackedKeys bounds the limiter's own memory. Once this
// many distinct keys are tracked, a brand-new key is denied rather than tracked, so
// a flood of distinct source addresses cannot grow the limiter's map without limit.
const sourceRateLimiterDefaultMaxTrackedKeys = 10_000

// sourceRateLimiterRecord tracks request counts for a single key within the
// current fixed window.
type sourceRateLimiterRecord struct {
	windowStart time.Time
	lastSeen    time.Time
	count       int
}

// clusterRateCounterBackend is the pluggable, cluster-visible counter
// sourceRateLimiter.allow consults instead of its own in-memory map once
// useSharedCounter has been called (Issue #3896, ADR-031 follow-up to Issue
// #3761's clusterBudgetDivisor even-distribution approximation). Satisfied by
// business.RateCounterStore; declared locally, narrowed to the one method this
// limiter needs, so tests can substitute a fake without a real database.
type clusterRateCounterBackend interface {
	Increment(ctx context.Context, key string, window time.Duration) (count int, retryAfter time.Duration, err error)
}

// sourceRateLimiter is a reusable per-key, fixed-window rate limiter for controller
// API endpoints (Issue #3714). Handlers key it on the trusted-proxy-aware source
// address returned by extractSourceIP — never on the raw remote address — so a
// caller behind an untrusted proxy cannot spoof a forwarded-for header to obtain a
// fresh budget.
//
// It is safe for concurrent use. Stale keys are evicted opportunistically, and a
// hard cap on tracked keys is enforced as a backstop, so a flood of distinct source
// addresses cannot grow its memory without bound. The same two guarantees hold on
// the shared-counter path: business.RateCounterStore requires its implementations
// to reclaim elapsed windows and to cap tracked keys, and allowShared fails closed
// on business.ErrRateCounterCapacityExhausted exactly as the in-memory path denies
// a new key at maxTrackedKeys.
type sourceRateLimiter struct {
	limit          int
	window         time.Duration
	maxTrackedKeys int
	now            func() time.Time

	// routeName namespaces this limiter's keys within sharedCounter's table, so
	// multiple sourceRateLimiter instances sharing one cluster-visible store never
	// collide on the same source address. Only consulted when sharedCounter is set.
	routeName string

	// sharedCounter, if set (via useSharedCounter), makes this limiter's count
	// cluster-visible through a database-backed clusterRateCounterBackend instead
	// of the per-process in-memory map below (Issue #3896). nil — the default —
	// means the in-memory, single-node-equivalent behavior.
	sharedCounter clusterRateCounterBackend

	mu      sync.Mutex
	entries map[string]*sourceRateLimiterRecord
}

// newSourceRateLimiter returns a limiter that allows up to limit calls per key
// within window.
func newSourceRateLimiter(limit int, window time.Duration) *sourceRateLimiter {
	return &sourceRateLimiter{
		limit:          limit,
		window:         window,
		maxTrackedKeys: sourceRateLimiterDefaultMaxTrackedKeys,
		now:            time.Now,
		entries:        make(map[string]*sourceRateLimiterRecord),
	}
}

// useSharedCounter switches this limiter from its default in-memory backend to
// a cluster-visible counter (Issue #3896), namespacing every key under
// routeName so distinct sourceRateLimiter instances sharing one backend's table
// never collide on the same source address.
func (l *sourceRateLimiter) useSharedCounter(routeName string, backend clusterRateCounterBackend) {
	l.routeName = routeName
	l.sharedCounter = backend
}

// allow reports whether a call keyed by key may proceed under the configured rate,
// incrementing the counter on success. When the limit has been exceeded it returns
// false along with the duration the caller should wait before retrying.
//
// This is the direct call form, for handlers that need to rate-limit only part of
// their work rather than an entire route.
func (l *sourceRateLimiter) allow(key string) (bool, time.Duration) {
	if l.sharedCounter != nil {
		return l.allowShared(key)
	}

	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	rec, exists := l.entries[key]
	if !exists {
		l.evictStaleLocked(now)
		if len(l.entries) >= l.maxTrackedKeys {
			// Fail closed under memory pressure rather than track an unbounded
			// number of keys: deny without ever storing this one.
			return false, l.window
		}
		rec = &sourceRateLimiterRecord{windowStart: now}
		l.entries[key] = rec
	}

	if now.Sub(rec.windowStart) >= l.window {
		rec.windowStart = now
		rec.count = 0
	}
	rec.lastSeen = now

	if rec.count >= l.limit {
		retryAfter := rec.windowStart.Add(l.window).Sub(now)
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		return false, retryAfter
	}
	rec.count++
	return true, 0
}

// allowShared consults sharedCounter instead of the in-memory map. The
// increment always happens, even on a call that will be denied — the count
// only ever grows within its window regardless of outcome, matching the
// in-memory path's own "count first, then compare" accounting once corrected
// for order. On a counter-store error this fails open (allows the call): the
// shared counter is a defense-in-depth budget, not the primary auth gate this
// route sits behind, and an outage in it must not become an availability
// outage for every legitimate caller of a clustered route.
//
// The one error that denies instead is ErrRateCounterCapacityExhausted: it is
// not an outage but the store's tracked-key backstop reporting that it refused
// to begin tracking this key. Failing open there would hand an untracked,
// unlimited budget to every fresh source address — the very flood the backstop
// exists to bound — so this mirrors the in-memory path's maxTrackedKeys denial.
func (l *sourceRateLimiter) allowShared(key string) (bool, time.Duration) {
	count, retryAfter, err := l.sharedCounter.Increment(context.Background(), l.routeName+":"+key, l.window)
	if err != nil {
		if errors.Is(err, business.ErrRateCounterCapacityExhausted) {
			if retryAfter <= 0 {
				retryAfter = l.window
			}
			if retryAfter < time.Second {
				retryAfter = time.Second
			}
			return false, retryAfter
		}
		return true, 0
	}
	if count > l.limit {
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		return false, retryAfter
	}
	return true, 0
}

// evictStaleLocked removes entries whose window has fully elapsed since they were
// last seen. Called with mu held, only when a brand-new key is about to be tracked,
// so the sweep cost is amortized across new-key insertions rather than paid on
// every call.
func (l *sourceRateLimiter) evictStaleLocked(now time.Time) {
	for key, rec := range l.entries {
		if now.Sub(rec.lastSeen) >= l.window {
			delete(l.entries, key)
		}
	}
}

// middleware returns route middleware that applies the limiter keyed on the
// trusted-proxy-aware source address extracted via extractSourceIP. Exceeding the
// limit responds with 429 Too Many Requests and a Retry-After header before next is
// ever invoked; the response body is a fixed, generic status text that says nothing
// about the wrapped route or the resource it serves.
//
// This is the middleware form, for wrapping a whole route.
func (l *sourceRateLimiter) middleware(trustedProxies []net.IPNet, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source := extractSourceIP(r, trustedProxies)
		if ok, retryAfter := l.allow(source); !ok {
			writeTooManyRequests(w, retryAfter)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeTooManyRequests writes a generic 429 response that discloses nothing about
// the resource behind the rate-limited route.
func writeTooManyRequests(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(retryAfter / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
}
