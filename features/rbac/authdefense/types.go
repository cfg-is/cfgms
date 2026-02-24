// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package authdefense provides three-tier authorization defense: per-IP rate limiting,
// per-tenant circuit breakers, and a global circuit breaker to protect against
// auth flooding attacks.
package authdefense

import (
	"sync/atomic"
	"time"
)

// CircuitState represents the state of a circuit breaker
type CircuitState int32

const (
	// CircuitClosed allows requests through (normal operation)
	CircuitClosed CircuitState = iota
	// CircuitOpen rejects all requests (failure threshold exceeded)
	CircuitOpen
	// CircuitHalfOpen allows limited requests to test recovery
	CircuitHalfOpen
)

// String returns the string representation of a CircuitState
func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// AuthDefenseConfig holds configuration for the three-tier defense system
type AuthDefenseConfig struct {
	// Tier 1: Per-IP rate limiting
	IPRateLimit  int           // Max failed auth attempts per IP within window
	IPRateWindow time.Duration // Time window for rate limiting
	IPMaxTracked int           // Max IPs tracked (LRU eviction beyond this)
	IPRingSize   int           // Ring buffer size per IP (must be >= IPRateLimit)

	// Tier 2: Per-tenant circuit breaker
	TenantFailureThreshold int           // Failures to trip tenant circuit breaker
	TenantRecoveryTime     time.Duration // Time before half-open transition
	TenantHalfOpenMax      int           // Max requests allowed in half-open state
	TenantWindowDuration   time.Duration // Fixed window duration for failure counting
	TenantMaxTracked       int           // Max tenants tracked (LRU eviction)

	// Tier 3: Global circuit breaker
	GlobalFailureThreshold int           // Failures to trip global circuit breaker
	GlobalRecoveryTime     time.Duration // Time before half-open transition
	GlobalHalfOpenMax      int           // Max requests allowed in half-open state
	GlobalWindowDuration   time.Duration // Fixed window duration for failure counting

	// Log sampling
	LogSamplingThreshold int64   // Requests/sec before sampling kicks in
	LogSampleRate        float64 // Sample rate when above threshold (0.0-1.0)

	// Memory management
	GCTriggerThreshold int64 // Request count between forced GC cycles
}

// DefaultConfig returns sensible defaults for production use
func DefaultConfig() AuthDefenseConfig {
	return AuthDefenseConfig{
		// Tier 1: Per-IP
		IPRateLimit:  100,
		IPRateWindow: 1 * time.Minute,
		IPMaxTracked: 100_000,
		IPRingSize:   100,

		// Tier 2: Per-tenant
		TenantFailureThreshold: 10_000,
		TenantRecoveryTime:     30 * time.Second,
		TenantHalfOpenMax:      10,
		TenantWindowDuration:   1 * time.Minute,
		TenantMaxTracked:       10_000,

		// Tier 3: Global
		GlobalFailureThreshold: 1_000_000,
		GlobalRecoveryTime:     60 * time.Second,
		GlobalHalfOpenMax:      100,
		GlobalWindowDuration:   1 * time.Second,

		// Log sampling
		LogSamplingThreshold: 1000,
		LogSampleRate:        0.01, // 1%

		// Memory management
		GCTriggerThreshold: 100_000,
	}
}

// DefenseMetrics tracks operational metrics using atomic counters for lock-free access
type DefenseMetrics struct {
	TotalProcessed      atomic.Int64
	TotalBlocked        atomic.Int64
	RateLimitedIPs      atomic.Int64
	CircuitBreakerOpens atomic.Int64
	DroppedLogs         atomic.Int64
	GCTriggered         atomic.Int64
}

// DefenseMetricsSnapshot is a point-in-time copy of defense metrics for export
type DefenseMetricsSnapshot struct {
	TotalProcessed      int64 `json:"total_processed"`
	TotalBlocked        int64 `json:"total_blocked"`
	RateLimitedIPs      int64 `json:"rate_limited_ips"`
	CircuitBreakerOpens int64 `json:"circuit_breaker_opens"`
	DroppedLogs         int64 `json:"dropped_logs"`
	GCTriggered         int64 `json:"gc_triggered"`
}

// Snapshot returns a point-in-time copy of the metrics
func (m *DefenseMetrics) Snapshot() DefenseMetricsSnapshot {
	return DefenseMetricsSnapshot{
		TotalProcessed:      m.TotalProcessed.Load(),
		TotalBlocked:        m.TotalBlocked.Load(),
		RateLimitedIPs:      m.RateLimitedIPs.Load(),
		CircuitBreakerOpens: m.CircuitBreakerOpens.Load(),
		DroppedLogs:         m.DroppedLogs.Load(),
		GCTriggered:         m.GCTriggered.Load(),
	}
}
