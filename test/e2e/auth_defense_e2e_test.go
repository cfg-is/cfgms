// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package e2e

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/rbac/authdefense"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestAuthDefenseE2E tests the three-tier auth defense system end-to-end
// with realistic request volumes. No server boot required — tests create
// standalone AuthDefenseSystem instances.
//
// Story #380: Reduced from 47M to ~25K total requests, target <10s execution.
func TestAuthDefenseE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping auth defense E2E tests in short mode")
	}

	startTime := time.Now()
	var totalRequests atomic.Int64

	t.Run("Tier1_IPRateLimit", func(t *testing.T) {
		testTier1IPRateLimit(t, &totalRequests)
	})

	t.Run("Tier2_TenantCircuitBreaker", func(t *testing.T) {
		testTier2TenantCircuitBreaker(t, &totalRequests)
	})

	t.Run("Tier3_GlobalCircuitBreaker", func(t *testing.T) {
		testTier3GlobalCircuitBreaker(t, &totalRequests)
	})

	t.Run("MemoryManagement", func(t *testing.T) {
		testMemoryManagement(t, &totalRequests)
	})

	t.Run("ConcurrentAttackSimulation", func(t *testing.T) {
		testConcurrentAttackSimulation(t, &totalRequests)
	})

	elapsed := time.Since(startTime)
	t.Logf("Auth defense E2E: %d total requests in %v", totalRequests.Load(), elapsed)

	// Story #380 acceptance criteria: test execution < 10 seconds
	assert.Less(t, elapsed, 10*time.Second,
		"Auth defense E2E suite should complete in < 10 seconds, took %v", elapsed)
}

// testTier1IPRateLimit tests per-IP rate limiting through the HTTP middleware.
// ~150 requests per IP, verifying that requests beyond the limit are blocked with 429.
func testTier1IPRateLimit(t *testing.T, totalRequests *atomic.Int64) {
	clock := authdefense.NewTestClock(time.Time{})
	cfg := authdefense.DefaultConfig()
	cfg.IPRateLimit = 100
	cfg.IPRingSize = 100
	cfg.IPRateWindow = 1 * time.Minute
	cfg.GCTriggerThreshold = 1_000_000

	logger := logging.NewLogger("error")
	defense := authdefense.New(cfg, logger,
		authdefense.WithClock(clock),
		authdefense.WithIPExtractor(&fixedIPExtractor{ip: "attacker-1.2.3.4"}),
	)
	defer defense.Stop()

	// Backend handler simulates auth failure (401)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	handler := defense.Middleware(backend)

	passed := 0
	blocked := 0

	// Send 150 requests — first 100 should pass, remaining should be blocked
	for range 150 {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code == http.StatusTooManyRequests {
			blocked++
		} else {
			passed++
		}
		totalRequests.Add(1)
	}

	require.GreaterOrEqual(t, passed, 100, "expected at least 100 passed requests")
	require.GreaterOrEqual(t, blocked, 1, "expected at least 1 blocked request after rate limit")

	t.Logf("Tier 1: passed=%d blocked=%d", passed, blocked)
}

// testTier2TenantCircuitBreaker tests per-tenant circuit breaker with distributed IPs.
// Uses the direct API (RecordResult + CheckRequest) because the tenant circuit breaker
// is inherently a post-auth check — the middleware's pre-auth check doesn't know the
// tenant ID. ~12K requests across multiple IPs targeting the same tenant.
func testTier2TenantCircuitBreaker(t *testing.T, totalRequests *atomic.Int64) {
	clock := authdefense.NewTestClock(time.Time{})
	cfg := authdefense.DefaultConfig()
	cfg.IPRateLimit = 1_000_000      // don't trip IP limiter
	cfg.TenantFailureThreshold = 500 // trip after 500 failures
	cfg.TenantRecoveryTime = 10 * time.Second
	cfg.TenantHalfOpenMax = 5
	cfg.TenantWindowDuration = 1 * time.Minute
	cfg.GCTriggerThreshold = 1_000_000

	logger := logging.NewLogger("error")
	defense := authdefense.New(cfg, logger,
		authdefense.WithClock(clock),
	)
	defer defense.Stop()

	tripped := false
	requestCount := 0

	// Send up to 2K requests — circuit should trip around 500
	for range 2_000 {
		// Cycling IPs to simulate distributed attack on same tenant
		ip := fmt.Sprintf("10.0.%d.%d", (requestCount/256)%256, requestCount%256)
		defense.RecordResult(ip, "target-tenant", false)
		requestCount++
		totalRequests.Add(1)

		allowed, _ := defense.CheckRequest(ip, "target-tenant")
		if !allowed {
			tripped = true
			break
		}
	}

	require.True(t, tripped, "tenant circuit breaker did not trip after %d requests", requestCount)

	// Verify tenant is now blocked (even from a fresh IP)
	allowed, reason := defense.CheckRequest("99.99.99.99", "target-tenant")
	require.False(t, allowed, "tenant should be blocked after circuit trip")
	require.Equal(t, "tenant_circuit_open", reason)

	// Verify other tenant is unaffected
	allowed, _ = defense.CheckRequest("99.99.99.99", "innocent-tenant")
	require.True(t, allowed, "innocent tenant should not be blocked")

	// Test auto-recovery
	clock.Advance(11 * time.Second)
	allowed, _ = defense.CheckRequest("99.99.99.99", "target-tenant")
	require.True(t, allowed, "tenant should recover after recovery time")

	t.Logf("Tier 2: tripped after %d requests", requestCount)
}

// testTier3GlobalCircuitBreaker tests the global circuit breaker through the HTTP middleware.
// Uses a low threshold to avoid sending 1M real requests.
func testTier3GlobalCircuitBreaker(t *testing.T, totalRequests *atomic.Int64) {
	clock := authdefense.NewTestClock(time.Time{})
	cfg := authdefense.DefaultConfig()
	cfg.IPRateLimit = 1_000_000
	cfg.TenantFailureThreshold = 1_000_000
	cfg.GlobalFailureThreshold = 500 // low threshold for testing
	cfg.GlobalRecoveryTime = 5 * time.Second
	cfg.GlobalHalfOpenMax = 3
	cfg.GlobalWindowDuration = 1 * time.Minute
	cfg.GCTriggerThreshold = 1_000_000

	logger := logging.NewLogger("error")
	ipCycler := &cyclingIPExtractor{prefix: "172.16"}
	defense := authdefense.New(cfg, logger,
		authdefense.WithClock(clock),
		authdefense.WithIPExtractor(ipCycler),
	)
	defer defense.Stop()

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	handler := defense.Middleware(backend)

	// Trip global breaker
	tripped := false
	for range 1000 {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		totalRequests.Add(1)

		if rec.Code == http.StatusTooManyRequests {
			tripped = true
			break
		}
	}

	require.True(t, tripped, "global circuit breaker did not trip")

	// Verify blocked
	allowed, reason := defense.CheckRequest("1.1.1.1", "")
	require.False(t, allowed, "global breaker should block all requests")
	require.Equal(t, "global_circuit_open", reason)

	// Test recovery
	clock.Advance(6 * time.Second)
	allowed, _ = defense.CheckRequest("1.1.1.1", "")
	require.True(t, allowed, "global breaker should allow requests after recovery")

	t.Logf("Tier 3: global circuit breaker validated")
}

// testMemoryManagement validates memory usage stays under 100MB for 5K auth requests
// through the full middleware stack.
func testMemoryManagement(t *testing.T, totalRequests *atomic.Int64) {
	clock := authdefense.NewTestClock(time.Time{})
	cfg := authdefense.DefaultConfig()
	cfg.IPMaxTracked = 50_000
	cfg.GCTriggerThreshold = 1_000_000

	logger := logging.NewLogger("error")
	ipCycler := &cyclingIPExtractor{prefix: "10.0"}
	defense := authdefense.New(cfg, logger,
		authdefense.WithClock(clock),
		authdefense.WithIPExtractor(ipCycler),
		authdefense.WithTenantExtractor(func(r *http.Request) string {
			return "mem-test-tenant"
		}),
	)
	defer defense.Stop()

	// Mix of success and failure responses
	callCount := atomic.Int64{}
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n%10 == 0 {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	})
	handler := defense.Middleware(backend)

	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)

	// Send 5K requests through the full middleware
	for range 5_000 {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/s1", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		totalRequests.Add(1)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	allocMB := float64(after.Alloc) / (1024 * 1024)

	// Auth subsystem should be well under 100MB
	require.Less(t, after.Alloc, uint64(100*1024*1024),
		"memory usage %.2f MB exceeds 100 MB limit", allocMB)

	// Verify lightweight audit captured failures
	snapshots := defense.FailedAudit.Flush()
	require.NotEmpty(t, snapshots, "lightweight audit should have aggregated failure entries")

	t.Logf("Memory: %.2f MB after 5K middleware requests", allocMB)
}

// testConcurrentAttackSimulation validates defense under concurrent attack from 50 goroutines.
func testConcurrentAttackSimulation(t *testing.T, totalRequests *atomic.Int64) {
	clock := authdefense.NewTestClock(time.Time{})
	cfg := authdefense.DefaultConfig()
	cfg.IPRateLimit = 20
	cfg.IPRingSize = 20
	cfg.IPRateWindow = 1 * time.Minute
	cfg.GCTriggerThreshold = 1_000_000

	logger := logging.NewLogger("error")
	defense := authdefense.New(cfg, logger, authdefense.WithClock(clock))
	defer defense.Stop()

	var wg sync.WaitGroup
	var totalBlocked atomic.Int64
	goroutines := 50
	requestsPerGoroutine := 50 // 50 * 50 = 2,500 requests

	for g := range goroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := fmt.Sprintf("attacker-%d.0.0.1", id)

			for range requestsPerGoroutine {
				// Use shared defense system through direct API
				defense.RecordResult(ip, "", false)
				allowed, _ := defense.CheckRequest(ip, "")
				if !allowed {
					totalBlocked.Add(1)
				}
				totalRequests.Add(1)
			}
		}(g)
	}

	wg.Wait()

	blocked := totalBlocked.Load()
	total := int64(goroutines * requestsPerGoroutine)

	// Each IP has limit of 20, so each goroutine should see 30+ blocks
	require.GreaterOrEqual(t, blocked, int64(goroutines),
		"expected at least %d blocked requests (one per goroutine), got %d out of %d",
		goroutines, blocked, total)

	t.Logf("Concurrent: %d blocked / %d total across %d goroutines", blocked, total, goroutines)
}

// fixedIPExtractor always returns the same IP
type fixedIPExtractor struct {
	ip string
}

func (e *fixedIPExtractor) Extract(_ *http.Request) string { return e.ip }

// cyclingIPExtractor generates unique IPs from a prefix to simulate distributed attacks
type cyclingIPExtractor struct {
	prefix string
	count  atomic.Int64
}

func (e *cyclingIPExtractor) Extract(_ *http.Request) string {
	n := e.count.Add(1)
	return fmt.Sprintf("%s.%d.%d", e.prefix, (n/256)%256, n%256)
}
