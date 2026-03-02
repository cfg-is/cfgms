// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package authdefense

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// staticIPExtractor returns a fixed IP for testing
type staticIPExtractor struct {
	ip string
}

func (e *staticIPExtractor) Extract(_ *http.Request) string { return e.ip }

// multiIPExtractor cycles through a list of IPs
type multiIPExtractor struct {
	ips []string
	idx int
}

func (e *multiIPExtractor) Extract(_ *http.Request) string {
	ip := e.ips[e.idx%len(e.ips)]
	e.idx++
	return ip
}

func newTestLogger(t *testing.T) logging.Logger {
	t.Helper()
	return logging.NewLogger("debug")
}

func TestDefense_Tier1_IPFloodBlocked(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 5
	cfg.IPRingSize = 5
	cfg.IPRateWindow = 1 * time.Minute
	cfg.GCTriggerThreshold = 1_000_000 // disable GC for test

	logger := newTestLogger(t)
	d := New(cfg, logger, WithClock(clock), WithIPExtractor(&staticIPExtractor{ip: "1.2.3.4"}))
	defer d.Stop()

	ip := "1.2.3.4"

	// Record failures to trip IP rate limiter
	for i := 0; i < 5; i++ {
		d.RecordResult(ip, "", false)
	}

	allowed, reason := d.CheckRequest(ip, "")
	assert.False(t, allowed)
	assert.Equal(t, "ip_rate_limited", reason)
}

func TestDefense_Tier2_TenantFloodBlocked(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 1_000_000 // high enough to not trigger
	cfg.TenantFailureThreshold = 5
	cfg.TenantRecoveryTime = 10 * time.Second
	cfg.TenantHalfOpenMax = 2
	cfg.TenantWindowDuration = 1 * time.Minute
	cfg.GCTriggerThreshold = 1_000_000

	logger := newTestLogger(t)
	ext := &multiIPExtractor{ips: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}}
	d := New(cfg, logger, WithClock(clock), WithIPExtractor(ext))
	defer d.Stop()

	// Distribute failures across different IPs but same tenant
	for i := 0; i < 5; i++ {
		ip := ext.ips[i%len(ext.ips)]
		d.RecordResult(ip, "tenant-A", false)
	}

	// Tenant circuit should be open
	allowed, reason := d.CheckRequest("10.0.0.99", "tenant-A")
	assert.False(t, allowed)
	assert.Equal(t, "tenant_circuit_open", reason)
}

func TestDefense_Tier2_TenantIsolation(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 1_000_000
	cfg.TenantFailureThreshold = 3
	cfg.TenantRecoveryTime = 10 * time.Second
	cfg.TenantWindowDuration = 1 * time.Minute
	cfg.GCTriggerThreshold = 1_000_000

	logger := newTestLogger(t)
	d := New(cfg, logger, WithClock(clock))
	defer d.Stop()

	// Trip tenant A
	for i := 0; i < 3; i++ {
		d.RecordResult("10.0.0.1", "tenant-A", false)
	}

	// Tenant A blocked
	allowed, _ := d.CheckRequest("10.0.0.1", "tenant-A")
	assert.False(t, allowed)

	// Tenant B unaffected
	allowed, _ = d.CheckRequest("10.0.0.1", "tenant-B")
	assert.True(t, allowed)
}

func TestDefense_Tier3_GlobalCircuitBreaker(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 1_000_000
	cfg.TenantFailureThreshold = 1_000_000
	cfg.GlobalFailureThreshold = 10
	cfg.GlobalRecoveryTime = 30 * time.Second
	cfg.GlobalWindowDuration = 1 * time.Second
	cfg.GCTriggerThreshold = 1_000_000

	logger := newTestLogger(t)
	d := New(cfg, logger, WithClock(clock))
	defer d.Stop()

	// Flood global breaker from various IPs/tenants
	for i := 0; i < 10; i++ {
		d.RecordResult("10.0.0.1", "tenant-X", false)
	}

	allowed, reason := d.CheckRequest("99.99.99.99", "")
	assert.False(t, allowed)
	assert.Equal(t, "global_circuit_open", reason)
}

func TestDefense_GlobalRecovery(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 1_000_000
	cfg.TenantFailureThreshold = 1_000_000
	cfg.GlobalFailureThreshold = 3
	cfg.GlobalRecoveryTime = 10 * time.Second
	cfg.GlobalHalfOpenMax = 2
	cfg.GlobalWindowDuration = 1 * time.Minute
	cfg.GCTriggerThreshold = 1_000_000

	logger := newTestLogger(t)
	d := New(cfg, logger, WithClock(clock))
	defer d.Stop()

	// Trip global breaker
	for i := 0; i < 3; i++ {
		d.RecordResult("10.0.0.1", "", false)
	}
	allowed, _ := d.CheckRequest("10.0.0.1", "")
	require.False(t, allowed)

	// Wait for recovery
	clock.Advance(11 * time.Second)

	// Should be in half-open — requests allowed
	allowed, _ = d.CheckRequest("10.0.0.1", "")
	assert.True(t, allowed)

	// Record successes to fully close
	d.RecordResult("10.0.0.1", "", true)
	d.RecordResult("10.0.0.1", "", true)

	allowed, _ = d.CheckRequest("10.0.0.1", "")
	assert.True(t, allowed)
}

func TestDefense_LogSampling(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.LogSamplingThreshold = 10
	cfg.LogSampleRate = 0.0 // drop everything above threshold

	logger := newTestLogger(t)
	d := New(cfg, logger, WithClock(clock))
	defer d.Stop()

	logged := 0
	for i := 0; i < 100; i++ {
		if d.ShouldLog() {
			logged++
		}
	}

	// First 10 should be logged (below threshold), rest dropped
	assert.Equal(t, 10, logged, "only requests below threshold should be logged with 0%% sample rate")
}

func TestDefense_LogSampling_AllBelowThreshold(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.LogSamplingThreshold = 1000
	cfg.LogSampleRate = 0.01

	logger := newTestLogger(t)
	d := New(cfg, logger, WithClock(clock))
	defer d.Stop()

	logged := 0
	for i := 0; i < 100; i++ {
		if d.ShouldLog() {
			logged++
		}
	}

	assert.Equal(t, 100, logged, "all requests below threshold should be logged")
}

func TestDefense_GCTrigger(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 1_000_000
	cfg.GCTriggerThreshold = 10

	logger := newTestLogger(t)
	d := New(cfg, logger, WithClock(clock))
	defer d.Stop()

	// Record enough results to trigger GC
	for i := 0; i < 20; i++ {
		d.RecordResult("10.0.0.1", "", true)
	}

	assert.GreaterOrEqual(t, d.Metrics.GCTriggered.Load(), int64(1), "GC should have been triggered")
}

func TestDefense_MetricsSnapshot(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 3
	cfg.IPRingSize = 3
	cfg.GCTriggerThreshold = 1_000_000

	logger := newTestLogger(t)
	d := New(cfg, logger, WithClock(clock))
	defer d.Stop()

	ip := "1.2.3.4"

	// Generate some traffic
	for i := 0; i < 3; i++ {
		d.RecordResult(ip, "", false)
	}
	d.CheckRequest(ip, "")

	snap := d.GetMetrics()
	assert.Greater(t, snap.TotalProcessed, int64(0))
	assert.Greater(t, snap.TotalBlocked, int64(0))
}

func TestDefense_Middleware_BlocksRateLimited(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 3
	cfg.IPRingSize = 3
	cfg.IPRateWindow = 1 * time.Minute
	cfg.GCTriggerThreshold = 1_000_000

	logger := newTestLogger(t)
	d := New(cfg, logger,
		WithClock(clock),
		WithIPExtractor(&staticIPExtractor{ip: "1.2.3.4"}),
	)
	defer d.Stop()

	// Trip the rate limiter
	for i := 0; i < 3; i++ {
		d.RecordResult("1.2.3.4", "", false)
	}

	handler := d.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
}

func TestDefense_Middleware_PassesNormalTraffic(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.GCTriggerThreshold = 1_000_000

	logger := newTestLogger(t)
	d := New(cfg, logger, WithClock(clock), WithIPExtractor(&staticIPExtractor{ip: "1.2.3.4"}))
	defer d.Stop()

	called := false
	handler := d.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestDefense_Middleware_RecordsAuthFailure(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 2
	cfg.IPRingSize = 2
	cfg.IPRateWindow = 1 * time.Minute
	cfg.GCTriggerThreshold = 1_000_000

	logger := newTestLogger(t)
	d := New(cfg, logger, WithClock(clock), WithIPExtractor(&staticIPExtractor{ip: "5.5.5.5"}))
	defer d.Stop()

	// Handler returns 401 to simulate auth failure
	handler := d.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	// First two requests succeed (but record failures)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	}

	// Third request should be blocked by rate limiter
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestDefense_WithTenantExtractor(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cfg := DefaultConfig()
	cfg.IPRateLimit = 1_000_000
	cfg.TenantFailureThreshold = 3
	cfg.TenantRecoveryTime = 10 * time.Second
	cfg.TenantWindowDuration = 1 * time.Minute
	cfg.GCTriggerThreshold = 1_000_000

	logger := newTestLogger(t)
	d := New(cfg, logger,
		WithClock(clock),
		WithIPExtractor(&staticIPExtractor{ip: "1.1.1.1"}),
		WithTenantExtractor(func(r *http.Request) string {
			return "test-tenant"
		}),
	)
	defer d.Stop()

	// Handler returns 401 to trigger tenant failure recording
	handler := d.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// Tenant circuit should now be open
	allowed, reason := d.CheckRequest("99.99.99.99", "test-tenant")
	assert.False(t, allowed)
	assert.Equal(t, "tenant_circuit_open", reason)
}
