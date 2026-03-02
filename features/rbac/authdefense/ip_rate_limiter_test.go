// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package authdefense

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPRateLimiter_BasicRateLimiting(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 5
	cfg.IPRingSize = 5
	cfg.IPRateWindow = 1 * time.Minute

	limiter := NewIPRateLimiter(cfg, clock)
	defer limiter.Close()

	ip := "192.168.1.1"

	// First 5 failures should not trigger rate limiting
	for i := 0; i < 5; i++ {
		limiter.RecordFailure(ip)
	}
	assert.True(t, limiter.IsRateLimited(ip), "should be rate limited after reaching limit")

	// Different IP should not be affected
	assert.False(t, limiter.IsRateLimited("192.168.1.2"), "different IP should not be limited")
}

func TestIPRateLimiter_BelowThreshold(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 10
	cfg.IPRingSize = 10
	cfg.IPRateWindow = 1 * time.Minute

	limiter := NewIPRateLimiter(cfg, clock)
	defer limiter.Close()

	ip := "10.0.0.1"

	// Record fewer failures than the limit
	for i := 0; i < 9; i++ {
		limiter.RecordFailure(ip)
	}
	assert.False(t, limiter.IsRateLimited(ip), "should not be limited below threshold")
}

func TestIPRateLimiter_WindowExpiration(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 3
	cfg.IPRingSize = 3
	cfg.IPRateWindow = 1 * time.Minute

	limiter := NewIPRateLimiter(cfg, clock)
	defer limiter.Close()

	ip := "10.0.0.1"

	// Trip the rate limit
	for i := 0; i < 3; i++ {
		limiter.RecordFailure(ip)
	}
	assert.True(t, limiter.IsRateLimited(ip))

	// Advance past the window
	clock.Advance(2 * time.Minute)

	// Failures are now outside the window — should be unblocked
	assert.False(t, limiter.IsRateLimited(ip), "should be unblocked after window expires")
}

func TestIPRateLimiter_RingBufferOverflow(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 3
	cfg.IPRingSize = 5 // ring larger than limit
	cfg.IPRateWindow = 1 * time.Minute

	limiter := NewIPRateLimiter(cfg, clock)
	defer limiter.Close()

	ip := "10.0.0.1"

	// Fill ring beyond capacity
	for i := 0; i < 10; i++ {
		limiter.RecordFailure(ip)
	}

	// Should still be rate-limited (ring wraps, recent entries still within window)
	assert.True(t, limiter.IsRateLimited(ip))

	// Advance past window — all entries expire
	clock.Advance(2 * time.Minute)
	assert.False(t, limiter.IsRateLimited(ip))
}

func TestIPRateLimiter_LRUEviction(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 1
	cfg.IPRingSize = 1
	cfg.IPRateWindow = 1 * time.Minute
	cfg.IPMaxTracked = 10

	limiter := NewIPRateLimiter(cfg, clock)
	defer limiter.Close()

	// Fill cache beyond max tracked
	for i := 0; i < 20; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		limiter.RecordFailure(ip)
	}

	// Most recent IPs should still be tracked
	assert.True(t, limiter.IsRateLimited("10.0.0.19"))

	// Earliest IPs may have been evicted (LRU) — exact behavior depends on cache eviction
	// We just verify no panic and that recent entries work
}

func TestIPRateLimiter_ConcurrentAccess(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 100
	cfg.IPRingSize = 100
	cfg.IPRateWindow = 1 * time.Minute
	cfg.IPMaxTracked = 10_000

	limiter := NewIPRateLimiter(cfg, clock)
	defer limiter.Close()

	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.%d.%d.%d", id/256, id%256, 1)
			for j := 0; j < 50; j++ {
				limiter.RecordFailure(ip)
				limiter.IsRateLimited(ip)
			}
		}(g)
	}

	wg.Wait()
	// No panics or data races (run with -race)
}

func TestIPRateLimiter_ExactThreshold(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 100
	cfg.IPRingSize = 100
	cfg.IPRateWindow = 1 * time.Minute

	limiter := NewIPRateLimiter(cfg, clock)
	defer limiter.Close()

	ip := "1.2.3.4"

	// Record exactly limit-1 failures
	for i := 0; i < 99; i++ {
		limiter.RecordFailure(ip)
	}
	require.False(t, limiter.IsRateLimited(ip), "should not be limited at limit-1")

	// One more should trigger
	limiter.RecordFailure(ip)
	require.True(t, limiter.IsRateLimited(ip), "should be limited at exactly limit")
}
