// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package grpc

import (
	"math"
	"math/rand/v2"
	"time"
)

// ConnectionState represents the client provider's connection lifecycle state.
type ConnectionState int

const (
	// StateDisconnected means the provider has no active ControlChannel stream.
	StateDisconnected ConnectionState = iota

	// StateConnecting means the provider is attempting to establish a connection.
	StateConnecting

	// StateConnected means the provider has an active ControlChannel stream.
	StateConnected

	// StateReconnecting means the provider lost its stream and is attempting to reconnect.
	StateReconnecting
)

func (s ConnectionState) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateReconnecting:
		return "reconnecting"
	default:
		return "unknown"
	}
}

// backoff calculates exponential backoff intervals with jitter.
//
// At 50k stewards with 20% jitter and 60s max, a controller restart spreads
// reconnections over a ~24s window (60s × 0.4 jitter range) instead of a
// thundering herd spike.
type backoff struct {
	initial    time.Duration
	max        time.Duration
	multiplier float64
	jitter     float64 // fraction, e.g. 0.2 = ±20%
	attempt    int
}

// defaultBackoff returns the standard reconnection backoff configuration.
func defaultBackoff() *backoff {
	return &backoff{
		initial:    1 * time.Second,
		max:        60 * time.Second,
		multiplier: 2.0,
		jitter:     0.2,
	}
}

// next returns the next backoff duration and increments the attempt counter.
func (b *backoff) next() time.Duration {
	base := float64(b.initial) * math.Pow(b.multiplier, float64(b.attempt))
	if base > float64(b.max) {
		base = float64(b.max)
	}

	// Apply jitter: ±jitter fraction
	jitterRange := base * b.jitter
	jittered := base + (rand.Float64()*2-1)*jitterRange

	// Clamp to [initial, max]
	if jittered < float64(b.initial) {
		jittered = float64(b.initial)
	}
	if jittered > float64(b.max) {
		jittered = float64(b.max)
	}

	b.attempt++
	return time.Duration(jittered)
}

// reset resets the attempt counter after a successful connection.
func (b *backoff) reset() {
	b.attempt = 0
}
