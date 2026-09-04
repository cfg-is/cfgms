// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
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

// sourceRateLimiter is a reusable per-key, fixed-window rate limiter for controller
// API endpoints (Issue #3714). Handlers key it on the trusted-proxy-aware source
// address returned by extractSourceIP — never on the raw remote address — so a
// caller behind an untrusted proxy cannot spoof a forwarded-for header to obtain a
// fresh budget.
//
// It is safe for concurrent use. Stale keys are evicted opportunistically, and a
// hard cap on tracked keys is enforced as a backstop, so a flood of distinct source
// addresses cannot grow its memory without bound.
type sourceRateLimiter struct {
	limit          int
	window         time.Duration
	maxTrackedKeys int
	now            func() time.Time

	// divisor, if set, scales limit down to a fleet-wide budget when more than one
	// cluster node can serve the limited route (Issue #3761; see
	// Server.clusterBudgetDivisor's doc comment). nil means limit is applied as
	// configured — the pre-#3761, single-server-equivalent behavior.
	divisor func() int

	mu      sync.Mutex
	entries map[string]*sourceRateLimiterRecord
}

// effectiveLimit returns limit divided by divisor() when divisor is set, floored at
// one call so a large cluster can never divide a route's budget down to zero and
// lock it out entirely.
func (l *sourceRateLimiter) effectiveLimit() int {
	if l.divisor == nil {
		return l.limit
	}
	d := l.divisor()
	if d < 1 {
		d = 1
	}
	eff := l.limit / d
	if eff < 1 {
		eff = 1
	}
	return eff
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

// allow reports whether a call keyed by key may proceed under the configured rate,
// incrementing the counter on success. When the limit has been exceeded it returns
// false along with the duration the caller should wait before retrying.
//
// This is the direct call form, for handlers that need to rate-limit only part of
// their work rather than an entire route.
func (l *sourceRateLimiter) allow(key string) (bool, time.Duration) {
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

	if rec.count >= l.effectiveLimit() {
		retryAfter := rec.windowStart.Add(l.window).Sub(now)
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		return false, retryAfter
	}
	rec.count++
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
