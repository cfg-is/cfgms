// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package authdefense

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCircuitBreaker_InitialState(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cb := NewCircuitBreaker(5, 10*time.Second, 3, 1*time.Minute, clock)

	assert.Equal(t, CircuitClosed, cb.State())
	assert.True(t, cb.Allow())
}

func TestCircuitBreaker_ClosedToOpen(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cb := NewCircuitBreaker(5, 10*time.Second, 3, 1*time.Minute, clock)

	// Record failures up to threshold
	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}

	assert.Equal(t, CircuitOpen, cb.State())
	assert.False(t, cb.Allow(), "open circuit should reject requests")
}

func TestCircuitBreaker_OpenToHalfOpen(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cb := NewCircuitBreaker(3, 10*time.Second, 2, 1*time.Minute, clock)

	// Trip the breaker
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}
	require.Equal(t, CircuitOpen, cb.State())

	// Advance past recovery time
	clock.Advance(11 * time.Second)

	assert.Equal(t, CircuitHalfOpen, cb.State())
	assert.True(t, cb.Allow(), "half-open should allow requests")
}

func TestCircuitBreaker_HalfOpenToClosed(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cb := NewCircuitBreaker(3, 10*time.Second, 2, 1*time.Minute, clock)

	// Trip → open
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}

	// Wait for half-open
	clock.Advance(11 * time.Second)
	require.Equal(t, CircuitHalfOpen, cb.State())

	// Record enough successes to close
	cb.RecordSuccess()
	cb.RecordSuccess()

	assert.Equal(t, CircuitClosed, cb.State())
	assert.True(t, cb.Allow())
}

func TestCircuitBreaker_HalfOpenToOpen(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cb := NewCircuitBreaker(3, 10*time.Second, 5, 1*time.Minute, clock)

	// Trip → open
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}

	// Wait for half-open
	clock.Advance(11 * time.Second)
	require.Equal(t, CircuitHalfOpen, cb.State())

	// Failure in half-open trips back to open
	cb.RecordFailure()

	assert.Equal(t, CircuitOpen, cb.State())
}

func TestCircuitBreaker_WindowReset(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cb := NewCircuitBreaker(5, 10*time.Second, 2, 1*time.Minute, clock)

	// Record some failures (below threshold)
	for i := 0; i < 4; i++ {
		cb.RecordFailure()
	}
	assert.Equal(t, CircuitClosed, cb.State())

	// Advance past the window
	clock.Advance(2 * time.Minute)

	// Failures reset — still need 5 more to trip
	cb.RecordFailure()
	assert.Equal(t, CircuitClosed, cb.State(), "counter should reset after window")
}

func TestCircuitBreaker_FullCycle(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cb := NewCircuitBreaker(3, 5*time.Second, 2, 1*time.Minute, clock)

	// Closed → Open
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}
	require.Equal(t, CircuitOpen, cb.State())

	// Open → HalfOpen
	clock.Advance(6 * time.Second)
	require.Equal(t, CircuitHalfOpen, cb.State())

	// HalfOpen → Open (failure)
	cb.RecordFailure()
	require.Equal(t, CircuitOpen, cb.State())

	// Open → HalfOpen again
	clock.Advance(6 * time.Second)
	require.Equal(t, CircuitHalfOpen, cb.State())

	// HalfOpen → Closed (successes)
	cb.RecordSuccess()
	cb.RecordSuccess()
	require.Equal(t, CircuitClosed, cb.State())

	// Verify fully operational
	assert.True(t, cb.Allow())
}

func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
	clock := NewTestClock(time.Time{})
	cb := NewCircuitBreaker(1000, 10*time.Second, 10, 1*time.Minute, clock)

	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				cb.Allow()
				cb.RecordFailure()
				cb.RecordSuccess()
				cb.State()
			}
		}()
	}

	wg.Wait()
	// No panics or data races (run with -race)
}

func TestCircuitState_String(t *testing.T) {
	assert.Equal(t, "closed", CircuitClosed.String())
	assert.Equal(t, "open", CircuitOpen.String())
	assert.Equal(t, "half-open", CircuitHalfOpen.String())
	assert.Equal(t, "unknown", CircuitState(99).String())
}
