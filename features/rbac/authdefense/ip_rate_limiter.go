// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package authdefense

import (
	"time"

	"github.com/cfgis/cfgms/pkg/cache"
)

// IPRateLimiter implements Tier 1 per-IP rate limiting using a ring buffer
// of failure timestamps stored in pkg/cache.Cache with LRU eviction.
type IPRateLimiter struct {
	cache  *cache.Cache
	clock  Clock
	limit  int
	window time.Duration
	ring   int // ring buffer capacity per IP
}

// failureRing is a fixed-size circular buffer of failure timestamps.
// Using a ring buffer avoids unbounded []time.Time slice growth.
type failureRing struct {
	times []time.Time
	head  int // next write position
	count int // number of valid entries (up to cap)
}

// newFailureRing creates a ring buffer with the given capacity
func newFailureRing(capacity int) *failureRing {
	return &failureRing{
		times: make([]time.Time, capacity),
	}
}

// add records a failure timestamp
func (r *failureRing) add(t time.Time) {
	r.times[r.head] = t
	r.head = (r.head + 1) % len(r.times)
	if r.count < len(r.times) {
		r.count++
	}
}

// countWithin returns how many recorded timestamps fall within the window ending at now
func (r *failureRing) countWithin(now time.Time, window time.Duration) int {
	cutoff := now.Add(-window)
	n := 0
	for i := 0; i < r.count; i++ {
		idx := (r.head - 1 - i + len(r.times)) % len(r.times)
		if !r.times[idx].Before(cutoff) {
			n++
		}
	}
	return n
}

// NewIPRateLimiter creates a new per-IP rate limiter
func NewIPRateLimiter(cfg AuthDefenseConfig, clock Clock) *IPRateLimiter {
	ringSize := max(cfg.IPRingSize, cfg.IPRateLimit)

	c := cache.NewCache(cache.CacheConfig{
		Name:            "ip-rate-limiter",
		MaxRuntimeItems: cfg.IPMaxTracked,
		DefaultTTL:      cfg.IPRateWindow * 2, // keep entries alive a bit beyond window
		CleanupInterval: cfg.IPRateWindow,
		EvictionPolicy:  cache.EvictionLRU,
	})

	return &IPRateLimiter{
		cache:  c,
		clock:  clock,
		limit:  cfg.IPRateLimit,
		window: cfg.IPRateWindow,
		ring:   ringSize,
	}
}

// RecordFailure records an authentication failure for the given IP
func (l *IPRateLimiter) RecordFailure(ip string) {
	now := l.clock.Now()

	val, found := l.cache.Get(ip)
	var ring *failureRing
	if found {
		ring = val.(*failureRing)
	} else {
		ring = newFailureRing(l.ring)
	}

	ring.add(now)
	// Always re-set to refresh TTL
	_ = l.cache.Set(ip, ring, l.window*2)
}

// IsRateLimited checks whether the given IP has exceeded the failure threshold
func (l *IPRateLimiter) IsRateLimited(ip string) bool {
	val, found := l.cache.Get(ip)
	if !found {
		return false
	}

	ring := val.(*failureRing)
	return ring.countWithin(l.clock.Now(), l.window) >= l.limit
}

// Close releases resources held by the rate limiter
func (l *IPRateLimiter) Close() {
	l.cache.Close()
}
