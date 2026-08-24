// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/transport/registry"
	quicgo "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression coverage for Issue #3481.
//
// A steward whose ControlChannel is refused by the server's approval gate used
// to reconnect at the initial backoff interval forever. Two behaviours combined:
//
//   - reconnectLoop built a fresh backoff on every invocation, so the escalation
//     state did not survive a cycle; and
//   - it treated "the stream opened" as success and reset the backoff there, but
//     an admission refusal is not delivered by dialAndOpenStream — it surfaces on
//     the first Recv, which sends control straight back into reconnectLoop.
//
// The result was dial → "reconnected" → rejected → dial, roughly once a second,
// indefinitely. Measured on the cfg-lab cluster with three refused stewards:
// 78 MB of controller log and 63 MB of steward log in a single day, with the
// steward logging "attempt 1, backoff 1s" every time.
//
// The backoff now lives on the Provider and is only reset once a stream has
// actually delivered a message, so these tests assert the escalation directly
// rather than going through the full QUIC/mTLS stack.

// TestReconnectBackoff_PersistsAcrossLoopInvocations is the core guard: the
// delay must keep growing across successive reconnectLoop entries, which is what
// a refused steward produces. Against the pre-fix code every call returned the
// initial interval, because the backoff was rebuilt per invocation.
func TestReconnectBackoff_PersistsAcrossLoopInvocations(t *testing.T) {
	t.Parallel()
	p := New(ModeClient, withBackoff(&backoff{
		initial:    10 * time.Millisecond,
		max:        640 * time.Millisecond,
		multiplier: 2.0,
		// No jitter: this asserts on ordering of successive delays, and jitter
		// would make adjacent attempts overlap.
		jitter: 0,
	}))

	var delays []time.Duration
	var attempts []int
	for i := 0; i < 5; i++ {
		d, a := p.nextReconnectBackoff()
		delays = append(delays, d)
		attempts = append(attempts, a)
	}

	for i := 1; i < len(delays); i++ {
		assert.Greaterf(t, delays[i], delays[i-1],
			"delay must grow across reconnect cycles: %v then %v (attempt %d -> %d). "+
				"Equal delays mean the backoff was rebuilt per invocation again (Issue #3481)",
			delays[i-1], delays[i], attempts[i-1], attempts[i])
	}
	assert.Equal(t, []int{1, 2, 3, 4, 5}, attempts,
		"the attempt counter must advance monotonically, not reset to 1 each cycle")
}

// TestReconnectBackoff_ResetOnlyAfterStreamCarriesTraffic pins the other half of
// the fix. Resetting at stream-open rewarded a connection that was about to be
// refused; the reset now belongs to a stream that has actually received a
// message. A refused steward therefore keeps escalating, while an ordinary
// transport drop — which does receive messages before it breaks — still
// reconnects promptly.
func TestReconnectBackoff_ResetOnlyAfterStreamCarriesTraffic(t *testing.T) {
	t.Parallel()
	p := New(ModeClient, withBackoff(&backoff{
		initial:    10 * time.Millisecond,
		max:        640 * time.Millisecond,
		multiplier: 2.0,
		jitter:     0,
	}))

	// Three refused cycles: nothing ever received, so nothing resets.
	first, _ := p.nextReconnectBackoff()
	p.nextReconnectBackoff()
	escalated, attempt := p.nextReconnectBackoff()
	require.Greater(t, escalated, first, "precondition: backoff should have escalated")
	require.Equal(t, 3, attempt)

	// A stream finally carries a message — this is what clientReceiveLoop calls
	// on a successful Recv.
	p.resetReconnectBackoff()

	afterReset, attemptAfter := p.nextReconnectBackoff()
	assert.Equal(t, first, afterReset,
		"after a stream has carried traffic the backoff must return to its initial interval")
	assert.Equal(t, 1, attemptAfter,
		"a proven-good connection must reset the attempt counter")
}

// TestReconnectBackoff_CeilingKeepsRetrying guards the operational requirement
// that escalation must not become abandonment: a steward that is refused today
// may be approved by an operator later, and it has to still be knocking. The
// delay must saturate at max rather than growing without bound or stopping.
func TestReconnectBackoff_CeilingKeepsRetrying(t *testing.T) {
	t.Parallel()
	const maxDelay = 80 * time.Millisecond
	p := New(ModeClient, withBackoff(&backoff{
		initial:    10 * time.Millisecond,
		max:        maxDelay,
		multiplier: 2.0,
		jitter:     0,
	}))

	var last time.Duration
	for i := 0; i < 12; i++ {
		last, _ = p.nextReconnectBackoff()
		require.LessOrEqual(t, last, maxDelay, "backoff must never exceed its configured ceiling")
		require.Positive(t, last, "backoff must keep producing a real delay, never zero or negative")
	}
	assert.Equal(t, maxDelay, last,
		"a long-refused steward should settle at the ceiling and keep retrying there")
}

// TestReconnectBackoff_DefaultsWhenNoOverride confirms the provider-scoped
// backoff is lazily created with production defaults when no test override is
// injected, since that is the path a real steward takes.
func TestReconnectBackoff_DefaultsWhenNoOverride(t *testing.T) {
	t.Parallel()
	p := New(ModeClient)

	d, attempt := p.nextReconnectBackoff()

	require.Equal(t, 1, attempt)
	def := defaultBackoff()
	// Jitter is on by default, so assert the band rather than an exact value.
	assert.GreaterOrEqual(t, d, def.initial, "first delay must be at least the initial interval")
	assert.LessOrEqual(t, d, def.max, "first delay must not exceed the ceiling")
}

// TestReconnectBackoff_EscalatesThroughRealReconnectPath drives the actual bug
// described in Issue #3481 end-to-end: a real server whose approval checker
// admits the ControlChannel stream (dialAndOpenStream succeeds) and then
// refuses it — the rejection only surfaces on the client's first Recv, which
// is what sent control straight back into reconnectLoop with a rebuilt backoff
// before this fix. Unlike the other tests in this file, which call
// nextReconnectBackoff/resetReconnectBackoff directly, this one only observes
// state transitions produced by reconnectLoop/clientReceiveLoop/
// dialAndOpenStream against a live rejectAll server, using the same
// newTestCA/on_state_change harness as reconnect_test.go.
//
// Measurement note: the gap between two StateReconnecting callbacks is the
// backoff the loop waited *plus* a full QUIC/mTLS dial, stream open and refusal
// round-trip. That overhead is neither small nor constant — measured at ~260 ms
// on one cycle and ~130 ms on the next during a loaded `-race` package run — so
// comparing adjacent gaps to each other cannot distinguish escalation from
// overhead noise when the backoff step is of the same order (a 40 ms → 80 ms
// step produced gaps of 303 ms then 210 ms and a false failure). Overhead is
// strictly additive, though, so each gap has the backoff it followed as a hard
// lower bound. Asserting that lower bound per cycle is immune to the noise and
// is still a strict pre-fix detector: the rebuilt-per-invocation backoff never
// exceeded its initial interval, which is an order of magnitude below the
// bounds checked here.
func TestReconnectBackoff_EscalatesThroughRealReconnectPath(t *testing.T) {
	t.Parallel()

	// Escalation ladder driven end-to-end: 100, 200, 400, 800, then saturated at
	// the 1.6 s ceiling. Kept well clear of dial overhead so each expected wait
	// remains a meaningful lower bound.
	const (
		initialWait = 100 * time.Millisecond
		maxWait     = 1600 * time.Millisecond
	)
	expectedWaits := []time.Duration{
		initialWait,
		2 * initialWait,
		4 * initialWait,
		8 * initialWait,
		maxWait,
	}

	tc := newTestCA(t)
	reg := registry.NewRegistry()
	const stewardID = "steward-refused-escalation"

	server := New(ModeServer, WithApprovalChecker(rejectAll{}))
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)

	var mu sync.Mutex
	var reconnectingAt []time.Time

	client := New(ModeClient,
		withBackoff(&backoff{
			initial:    initialWait,
			max:        maxWait,
			multiplier: 2.0,
			// No jitter: the assertions below use each cycle's configured wait as
			// an exact lower bound, and negative jitter would undercut it.
			jitter: 0,
		}),
		withQUICConfig(&quicgo.Config{
			MaxIdleTimeout:  3 * time.Second,
			KeepAlivePeriod: 200 * time.Millisecond,
		}),
	)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       server.ListenAddr(),
		"tls_config": tc.clientTLSConfig(t, stewardID),
		"steward_id": stewardID,
		"on_state_change": func(state ConnectionState) {
			if state == StateReconnecting {
				mu.Lock()
				reconnectingAt = append(reconnectingAt, time.Now())
				mu.Unlock()
			}
		},
	}))
	require.NoError(t, client.Start(context.Background()))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })

	// A refused steward must keep retrying (not give up), so wait for enough
	// reconnect cycles to observe the backoff escalate and then saturate.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(reconnectingAt) >= len(expectedWaits)+1
	}, 30*time.Second, 20*time.Millisecond, "a refused steward must keep re-entering reconnectLoop")

	// It must never actually be admitted — the approval checker rejects every
	// attempt, so the stream is refused on first Recv every cycle.
	_, ok := reg.Get(stewardID)
	assert.False(t, ok, "a steward refused by the approval checker must never be admitted to the registry")

	mu.Lock()
	timestamps := append([]time.Time(nil), reconnectingAt...)
	mu.Unlock()

	gaps := make([]time.Duration, 0, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		gaps = append(gaps, timestamps[i].Sub(timestamps[i-1]))
	}
	require.GreaterOrEqual(t, len(gaps), len(expectedWaits))

	// Every reconnect cycle draws exactly one backoff step and then waits it out
	// before dialing, so gap i is expectedWaits[i] plus dial/refusal overhead —
	// never less. A cycle that comes back sooner than its configured wait can
	// only mean the escalation state was lost between reconnectLoop entries,
	// which is Issue #3481 exactly. The slack absorbs timer/clock granularity
	// only; it is three orders of magnitude below the escalation being measured.
	const timerSlack = 5 * time.Millisecond
	for i, want := range expectedWaits {
		assert.GreaterOrEqual(t, gaps[i], want-timerSlack,
			"cycle %d of a persistently refused steward must wait at least its escalated backoff (%v), "+
				"measured gap %v; a shorter gap means the backoff restarted at its initial interval (Issue #3481)",
			i+1, want, gaps[i])
	}

	// The tail must have saturated at the ceiling and still be retrying, rather
	// than stopping or collapsing back to one attempt per initial interval.
	last := gaps[len(gaps)-1]
	assert.GreaterOrEqual(t, last, maxWait-timerSlack,
		"the tail reconnect interval must sit at the configured ceiling (%v), measured %v — "+
			"not flat at ~1 attempt per initial interval forever", maxWait, last)
}
