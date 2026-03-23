// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package grpc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackoffNextProducesIncreasingIntervals(t *testing.T) {
	bo := &backoff{
		initial:    1 * time.Second,
		max:        60 * time.Second,
		multiplier: 2.0,
		jitter:     0, // no jitter for deterministic test
	}

	intervals := make([]time.Duration, 8)
	for i := range intervals {
		intervals[i] = bo.next()
	}

	// Without jitter, intervals should be exactly: 1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s
	assert.Equal(t, 1*time.Second, intervals[0])
	assert.Equal(t, 2*time.Second, intervals[1])
	assert.Equal(t, 4*time.Second, intervals[2])
	assert.Equal(t, 8*time.Second, intervals[3])
	assert.Equal(t, 16*time.Second, intervals[4])
	assert.Equal(t, 32*time.Second, intervals[5])
	assert.Equal(t, 60*time.Second, intervals[6]) // capped at max
	assert.Equal(t, 60*time.Second, intervals[7]) // stays at max
}

func TestBackoffJitterBounds(t *testing.T) {
	bo := &backoff{
		initial:    1 * time.Second,
		max:        60 * time.Second,
		multiplier: 2.0,
		jitter:     0.2, // ±20%
	}

	// Run many iterations and verify all fall within bounds
	for i := 0; i < 100; i++ {
		bo.attempt = 0 // reset to test first interval

		d := bo.next()

		// Base is 1s, jitter ±20% = 0.8s to 1.2s, clamped to [1s, 60s]
		// Since 0.8s < initial (1s), the lower bound is 1s
		require.GreaterOrEqual(t, d, 1*time.Second, "interval must be >= initial")
		require.LessOrEqual(t, d, 60*time.Second, "interval must be <= max")
	}
}

func TestBackoffJitterAtMax(t *testing.T) {
	bo := &backoff{
		initial:    1 * time.Second,
		max:        60 * time.Second,
		multiplier: 2.0,
		jitter:     0.2,
		attempt:    10, // well past max
	}

	// At attempt 10, base = min(1*2^10, 60) = 60s
	// Jitter ±20% = 48s to 72s, clamped to [1s, 60s]
	for i := 0; i < 100; i++ {
		bo.attempt = 10
		d := bo.next()

		// Lower bound: 60 * 0.8 = 48s, but clamped to initial=1s (48s > 1s, so 48s)
		require.GreaterOrEqual(t, d, 48*time.Second, "jittered max should be >= 48s")
		require.LessOrEqual(t, d, 60*time.Second, "jittered max should be <= 60s (clamped)")
	}
}

func TestBackoffReset(t *testing.T) {
	bo := &backoff{
		initial:    1 * time.Second,
		max:        60 * time.Second,
		multiplier: 2.0,
		jitter:     0,
	}

	bo.next() // 1s, attempt=1
	bo.next() // 2s, attempt=2
	bo.next() // 4s, attempt=3

	bo.reset()

	d := bo.next()
	assert.Equal(t, 1*time.Second, d, "after reset, should start from initial")
}

func TestDefaultBackoff(t *testing.T) {
	bo := defaultBackoff()

	assert.Equal(t, 1*time.Second, bo.initial)
	assert.Equal(t, 60*time.Second, bo.max)
	assert.Equal(t, 2.0, bo.multiplier)
	assert.Equal(t, 0.2, bo.jitter)
	assert.Equal(t, 0, bo.attempt)
}

func TestConnectionStateString(t *testing.T) {
	assert.Equal(t, "disconnected", StateDisconnected.String())
	assert.Equal(t, "connecting", StateConnecting.String())
	assert.Equal(t, "connected", StateConnected.String())
	assert.Equal(t, "reconnecting", StateReconnecting.String())
}
