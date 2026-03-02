// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package authdefense

import (
	"sync/atomic"
	"time"
)

// CircuitBreaker implements a state machine for rate-based circuit breaking.
// All state is managed with atomic operations following the ZeroTrustStats CAS pattern.
type CircuitBreaker struct {
	state       atomic.Int32 // CircuitState
	failures    atomic.Int64 // failure count in current window
	successes   atomic.Int64 // success count in half-open state
	windowStart atomic.Int64 // unix nano of current window start
	openedAt    atomic.Int64 // unix nano when circuit was opened

	threshold      int           // failures to trip
	recoveryTime   time.Duration // time in open before half-open
	halfOpenMax    int           // successes needed to close from half-open
	windowDuration time.Duration // fixed window duration

	clock Clock
}

// NewCircuitBreaker creates a circuit breaker with the given parameters
func NewCircuitBreaker(threshold int, recoveryTime time.Duration, halfOpenMax int, windowDuration time.Duration, clock Clock) *CircuitBreaker {
	cb := &CircuitBreaker{
		threshold:      threshold,
		recoveryTime:   recoveryTime,
		halfOpenMax:    halfOpenMax,
		windowDuration: windowDuration,
		clock:          clock,
	}
	cb.state.Store(int32(CircuitClosed))
	cb.windowStart.Store(clock.Now().UnixNano())
	return cb
}

// State returns the current circuit state, accounting for automatic open→half-open transitions
func (cb *CircuitBreaker) State() CircuitState {
	s := CircuitState(cb.state.Load())
	if s == CircuitOpen {
		openedAt := time.Unix(0, cb.openedAt.Load())
		if cb.clock.Since(openedAt) >= cb.recoveryTime {
			// Attempt transition to half-open
			if cb.state.CompareAndSwap(int32(CircuitOpen), int32(CircuitHalfOpen)) {
				cb.successes.Store(0)
			}
			return CircuitHalfOpen
		}
	}
	return s
}

// Allow checks whether a request should be permitted through the circuit breaker.
// Returns true if the request is allowed.
func (cb *CircuitBreaker) Allow() bool {
	s := cb.State() // may trigger open→half-open
	switch s {
	case CircuitClosed:
		return true
	case CircuitOpen:
		return false
	case CircuitHalfOpen:
		// Allow limited requests in half-open
		return true
	default:
		return false
	}
}

// RecordFailure records a failed request outcome
func (cb *CircuitBreaker) RecordFailure() {
	s := cb.State()

	switch s {
	case CircuitClosed:
		cb.maybeResetWindow()
		count := cb.failures.Add(1)
		if int(count) >= cb.threshold {
			cb.trip()
		}
	case CircuitHalfOpen:
		// Any failure in half-open trips back to open
		cb.trip()
	case CircuitOpen:
		// Already open, nothing to do
	}
}

// RecordSuccess records a successful request outcome
func (cb *CircuitBreaker) RecordSuccess() {
	s := cb.State()

	switch s {
	case CircuitClosed:
		// No action needed
	case CircuitHalfOpen:
		count := cb.successes.Add(1)
		if int(count) >= cb.halfOpenMax {
			// Enough successes — close the circuit
			cb.reset()
		}
	case CircuitOpen:
		// Shouldn't happen (open state blocks requests)
	}
}

// trip transitions the circuit to open state
func (cb *CircuitBreaker) trip() {
	cb.state.Store(int32(CircuitOpen))
	cb.openedAt.Store(cb.clock.Now().UnixNano())
	cb.failures.Store(0)
	cb.successes.Store(0)
}

// reset transitions the circuit back to closed state
func (cb *CircuitBreaker) reset() {
	cb.state.Store(int32(CircuitClosed))
	cb.failures.Store(0)
	cb.successes.Store(0)
	cb.windowStart.Store(cb.clock.Now().UnixNano())
}

// maybeResetWindow resets the failure counter if the current window has elapsed
func (cb *CircuitBreaker) maybeResetWindow() {
	ws := time.Unix(0, cb.windowStart.Load())
	if cb.clock.Since(ws) >= cb.windowDuration {
		cb.failures.Store(0)
		cb.windowStart.Store(cb.clock.Now().UnixNano())
	}
}
