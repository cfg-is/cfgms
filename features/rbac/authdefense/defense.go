// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package authdefense

import (
	"math/rand/v2"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"sync/atomic"

	"github.com/cfgis/cfgms/pkg/cache"
	"github.com/cfgis/cfgms/pkg/logging"
)

// IPExtractor extracts the client IP address from an HTTP request
type IPExtractor interface {
	Extract(r *http.Request) string
}

// TenantExtractor extracts the tenant ID from an HTTP request (post-auth)
type TenantExtractor func(r *http.Request) string

// defaultIPExtractor parses the IP from r.RemoteAddr
type defaultIPExtractor struct{}

func (defaultIPExtractor) Extract(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// AuthDefenseSystem orchestrates the three-tier defense:
//   - Tier 1: Per-IP rate limiting (IPRateLimiter)
//   - Tier 2: Per-tenant circuit breaker (cache of CircuitBreakers)
//   - Tier 3: Global circuit breaker
type AuthDefenseSystem struct {
	config        AuthDefenseConfig
	logger        logging.Logger
	clock         Clock
	ipExtractor   IPExtractor
	tenantExtract TenantExtractor

	// Tier 1
	ipRateLimiter *IPRateLimiter

	// Tier 2: tenant circuit breakers stored in LRU cache
	tenantBreakers *cache.Cache

	// Tier 3
	globalBreaker *CircuitBreaker

	// Metrics
	Metrics *DefenseMetrics

	// Memory management
	requestsSinceGC atomic.Int64

	// Log sampling state
	recentRequests atomic.Int64
	samplingEpoch  atomic.Int64 // unix second of current sampling epoch
}

// Option configures the AuthDefenseSystem
type Option func(*AuthDefenseSystem)

// WithClock sets a custom clock (for testing)
func WithClock(c Clock) Option {
	return func(d *AuthDefenseSystem) {
		d.clock = c
	}
}

// WithIPExtractor sets a custom IP extraction strategy
func WithIPExtractor(e IPExtractor) Option {
	return func(d *AuthDefenseSystem) {
		d.ipExtractor = e
	}
}

// WithTenantExtractor sets the function used to extract tenant IDs post-auth
func WithTenantExtractor(fn TenantExtractor) Option {
	return func(d *AuthDefenseSystem) {
		d.tenantExtract = fn
	}
}

// New creates a new AuthDefenseSystem with the given configuration
func New(cfg AuthDefenseConfig, logger logging.Logger, opts ...Option) *AuthDefenseSystem {
	d := &AuthDefenseSystem{
		config:      cfg,
		logger:      logger,
		clock:       realClock{},
		ipExtractor: defaultIPExtractor{},
		Metrics:     &DefenseMetrics{},
	}

	for _, opt := range opts {
		opt(d)
	}

	// Tier 1
	d.ipRateLimiter = NewIPRateLimiter(cfg, d.clock)

	// Tier 2: cache of per-tenant circuit breakers
	d.tenantBreakers = cache.NewCache(cache.CacheConfig{
		Name:            "tenant-circuit-breakers",
		MaxRuntimeItems: cfg.TenantMaxTracked,
		DefaultTTL:      cfg.TenantRecoveryTime * 10,
		CleanupInterval: cfg.TenantRecoveryTime,
		EvictionPolicy:  cache.EvictionLRU,
	})

	// Tier 3
	d.globalBreaker = NewCircuitBreaker(
		cfg.GlobalFailureThreshold,
		cfg.GlobalRecoveryTime,
		cfg.GlobalHalfOpenMax,
		cfg.GlobalWindowDuration,
		d.clock,
	)

	d.samplingEpoch.Store(d.clock.Now().Unix())

	return d
}

// CheckRequest evaluates the three tiers in order and returns whether the request is allowed.
// tenantID may be empty if not yet known (pre-auth check).
func (d *AuthDefenseSystem) CheckRequest(ip, tenantID string) (allowed bool, reason string) {
	d.Metrics.TotalProcessed.Add(1)

	// Tier 1: Per-IP rate limiting
	if d.ipRateLimiter.IsRateLimited(ip) {
		d.Metrics.TotalBlocked.Add(1)
		d.Metrics.RateLimitedIPs.Add(1)
		return false, "ip_rate_limited"
	}

	// Tier 2: Per-tenant circuit breaker (only if tenant is known)
	if tenantID != "" {
		cb := d.getOrCreateTenantBreaker(tenantID)
		if !cb.Allow() {
			d.Metrics.TotalBlocked.Add(1)
			return false, "tenant_circuit_open"
		}
	}

	// Tier 3: Global circuit breaker
	if !d.globalBreaker.Allow() {
		d.Metrics.TotalBlocked.Add(1)
		return false, "global_circuit_open"
	}

	return true, ""
}

// RecordResult records the authentication outcome for all tiers
func (d *AuthDefenseSystem) RecordResult(ip, tenantID string, success bool) {
	if !success {
		// Tier 1: record IP failure
		d.ipRateLimiter.RecordFailure(ip)

		// Tier 2: record tenant failure
		if tenantID != "" {
			cb := d.getOrCreateTenantBreaker(tenantID)
			cb.RecordFailure()
			if cb.State() == CircuitOpen {
				d.Metrics.CircuitBreakerOpens.Add(1)
			}
		}

		// Tier 3: record global failure
		d.globalBreaker.RecordFailure()
		if d.globalBreaker.State() == CircuitOpen {
			d.Metrics.CircuitBreakerOpens.Add(1)
		}
	} else {
		// Record successes for half-open recovery
		if tenantID != "" {
			cb := d.getOrCreateTenantBreaker(tenantID)
			cb.RecordSuccess()
		}
		d.globalBreaker.RecordSuccess()
	}

	d.maybeGC()
}

// ShouldLog returns whether this request should be logged based on sampling config.
// Below the threshold, all requests are logged. Above it, only LogSampleRate fraction.
func (d *AuthDefenseSystem) ShouldLog() bool {
	currentEpoch := d.clock.Now().Unix()
	storedEpoch := d.samplingEpoch.Load()

	if currentEpoch != storedEpoch {
		// New second — reset counter
		if d.samplingEpoch.CompareAndSwap(storedEpoch, currentEpoch) {
			d.recentRequests.Store(1)
		} else {
			d.recentRequests.Add(1)
		}
	} else {
		d.recentRequests.Add(1)
	}

	if d.recentRequests.Load() <= d.config.LogSamplingThreshold {
		return true
	}

	// Above threshold: sample
	if rand.Float64() < d.config.LogSampleRate {
		return true
	}

	d.Metrics.DroppedLogs.Add(1)
	return false
}

// GetMetrics returns a snapshot of current defense metrics
func (d *AuthDefenseSystem) GetMetrics() DefenseMetricsSnapshot {
	return d.Metrics.Snapshot()
}

// Stop releases all resources
func (d *AuthDefenseSystem) Stop() {
	d.ipRateLimiter.Close()
	d.tenantBreakers.Close()
}

// getOrCreateTenantBreaker retrieves or creates a circuit breaker for the tenant
func (d *AuthDefenseSystem) getOrCreateTenantBreaker(tenantID string) *CircuitBreaker {
	val, found := d.tenantBreakers.Get(tenantID)
	if found {
		return val.(*CircuitBreaker)
	}

	cb := NewCircuitBreaker(
		d.config.TenantFailureThreshold,
		d.config.TenantRecoveryTime,
		d.config.TenantHalfOpenMax,
		d.config.TenantWindowDuration,
		d.clock,
	)
	_ = d.tenantBreakers.Set(tenantID, cb, d.config.TenantRecoveryTime*10)
	return cb
}

// maybeGC triggers garbage collection when request count crosses threshold
func (d *AuthDefenseSystem) maybeGC() {
	count := d.requestsSinceGC.Add(1)
	if count >= d.config.GCTriggerThreshold {
		if d.requestsSinceGC.CompareAndSwap(count, 0) {
			runtime.GC()
			debug.FreeOSMemory()
			d.Metrics.GCTriggered.Add(1)
		}
	}
}
