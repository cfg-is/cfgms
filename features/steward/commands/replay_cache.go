// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package commands

import (
	"sync"
	"time"
)

const maxReplayCacheEntries = 10_000

// ttlReplayCache is a bounded in-memory deduplication cache keyed by command ID.
// Add returns false when an ID is already present within the TTL window, providing
// replay protection for authenticated commands. Entries are evicted when older than
// the configured TTL or when the entry cap is reached (oldest evicted first).
type ttlReplayCache struct {
	mu  sync.Mutex
	ttl time.Duration

	// entries maps command ID → insertion time.
	entries map[string]time.Time

	// order tracks insertion order for bounded eviction (oldest first).
	order []string
}

// newReplayCache creates a replay cache with the given time-to-live.
func newReplayCache(ttl time.Duration) *ttlReplayCache {
	return &ttlReplayCache{
		ttl:     ttl,
		entries: make(map[string]time.Time),
	}
}

// Add records id in the cache and returns true if this is the first time the id
// has been seen within the TTL window. Returns false if the id is already present
// (i.e. a replay was detected). Expired entries are evicted on each call.
func (c *ttlReplayCache) Add(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	c.evictExpiredLocked(now)

	if t, exists := c.entries[id]; exists && now.Sub(t) < c.ttl {
		return false
	}

	// Enforce the hard cap by evicting the oldest entries first.
	for len(c.entries) >= maxReplayCacheEntries {
		c.evictOldestLocked()
	}

	c.entries[id] = now
	c.order = append(c.order, id)
	return true
}

// evictExpiredLocked removes entries whose age exceeds the TTL.
// Must be called with c.mu held.
func (c *ttlReplayCache) evictExpiredLocked(now time.Time) {
	cutoff := now.Add(-c.ttl)
	newOrder := c.order[:0]
	for _, id := range c.order {
		t, exists := c.entries[id]
		if !exists {
			continue
		}
		if t.Before(cutoff) {
			delete(c.entries, id)
		} else {
			newOrder = append(newOrder, id)
		}
	}
	c.order = newOrder
}

// evictOldestLocked removes the single oldest entry from the cache.
// Must be called with c.mu held.
func (c *ttlReplayCache) evictOldestLocked() {
	for len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		if _, exists := c.entries[oldest]; exists {
			delete(c.entries, oldest)
			return
		}
	}
}
