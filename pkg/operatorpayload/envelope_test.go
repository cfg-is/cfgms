// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package operatorpayload_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// baseEnvelope returns a well-formed Envelope, valid until overridden per-test.
func baseEnvelope() operatorpayload.Envelope {
	return operatorpayload.Envelope{
		Content:   []byte("echo hello | tee /tmp/out"),
		Shell:     "bash",
		Targets:   []string{"host-1"},
		Nonce:     "nonce-1",
		ExpiresAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// TestCanonicalBytes_DifferentTargetsProduceDifferentOutput proves the resolved target
// list is bound into the signed bytes: two envelopes differing only in Targets must not
// collide, or a signature over the shorter list could be replayed against the longer one.
func TestCanonicalBytes_DifferentTargetsProduceDifferentOutput(t *testing.T) {
	one := baseEnvelope()
	one.Targets = []string{"host-1"}
	two := baseEnvelope()
	two.Targets = []string{"host-1", "host-2"}

	gotOne, err := operatorpayload.CanonicalBytes(one)
	require.NoError(t, err)
	gotTwo, err := operatorpayload.CanonicalBytes(two)
	require.NoError(t, err)

	assert.NotEqual(t, gotOne, gotTwo)
}

// TestCanonicalBytes_DifferentNonceProducesDifferentOutput proves the nonce is bound into
// the signed bytes even when the business content is otherwise identical — the property
// that lets a nonce defeat replay without depending on the content being unpredictable.
func TestCanonicalBytes_DifferentNonceProducesDifferentOutput(t *testing.T) {
	one := baseEnvelope()
	one.Nonce = "nonce-1"
	two := baseEnvelope()
	two.Nonce = "nonce-2"

	gotOne, err := operatorpayload.CanonicalBytes(one)
	require.NoError(t, err)
	gotTwo, err := operatorpayload.CanonicalBytes(two)
	require.NoError(t, err)

	assert.NotEqual(t, gotOne, gotTwo)
}

// TestCanonicalBytes_RejectsSeparatorInField proves the reserved separators are hard
// rejected rather than sanitized — stripping or escaping would let two distinct envelopes
// collide on one signed message.
func TestCanonicalBytes_RejectsSeparatorInField(t *testing.T) {
	cases := map[string]func(*operatorpayload.Envelope){
		"shell contains outer separator":  func(e *operatorpayload.Envelope) { e.Shell = "ba|sh" },
		"nonce contains outer separator":  func(e *operatorpayload.Envelope) { e.Nonce = "non|ce" },
		"target contains outer separator": func(e *operatorpayload.Envelope) { e.Targets = []string{"host|1"} },
		"target contains inner separator": func(e *operatorpayload.Envelope) { e.Targets = []string{"host,1"} },
		"one of several targets is dirty": func(e *operatorpayload.Envelope) {
			e.Targets = []string{"host-1", "host|2", "host-3"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := baseEnvelope()
			mutate(&e)

			_, err := operatorpayload.CanonicalBytes(e)
			require.Error(t, err)
			assert.ErrorIs(t, err, operatorpayload.ErrInvalidEnvelope)
		})
	}
}

// TestCanonicalBytes_RejectsEmptyField proves an unbound coordinate cannot be signed —
// an empty field would defeat the binding it exists to provide.
func TestCanonicalBytes_RejectsEmptyField(t *testing.T) {
	cases := map[string]func(*operatorpayload.Envelope){
		"content is empty":       func(e *operatorpayload.Envelope) { e.Content = nil },
		"shell is empty":         func(e *operatorpayload.Envelope) { e.Shell = "" },
		"targets is empty":       func(e *operatorpayload.Envelope) { e.Targets = nil },
		"a target is empty":      func(e *operatorpayload.Envelope) { e.Targets = []string{"host-1", ""} },
		"nonce is empty":         func(e *operatorpayload.Envelope) { e.Nonce = "" },
		"expiresAt is zero-time": func(e *operatorpayload.Envelope) { e.ExpiresAt = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := baseEnvelope()
			mutate(&e)

			_, err := operatorpayload.CanonicalBytes(e)
			require.Error(t, err)
			assert.ErrorIs(t, err, operatorpayload.ErrInvalidEnvelope)
		})
	}
}

// TestCanonicalBytes_DeterministicRoundTrip proves identical envelopes always produce
// byte-identical output — signer and verifier must agree without any hidden state.
func TestCanonicalBytes_DeterministicRoundTrip(t *testing.T) {
	e := baseEnvelope()

	got1, err := operatorpayload.CanonicalBytes(e)
	require.NoError(t, err)
	got2, err := operatorpayload.CanonicalBytes(e)
	require.NoError(t, err)

	assert.Equal(t, got1, got2)
}

// TestCanonicalBytes_TargetOrderIsSignificant proves target order is preserved rather than
// normalized: CanonicalBytes trusts the caller to pass an already-deterministic list, and
// silently reordering would let two operators sign what looks like the same list but bind
// different bytes, or vice versa mask a genuine reordering as identical.
func TestCanonicalBytes_TargetOrderIsSignificant(t *testing.T) {
	forward := baseEnvelope()
	forward.Targets = []string{"host-1", "host-2"}
	reversed := baseEnvelope()
	reversed.Targets = []string{"host-2", "host-1"}

	gotForward, err := operatorpayload.CanonicalBytes(forward)
	require.NoError(t, err)
	gotReversed, err := operatorpayload.CanonicalBytes(reversed)
	require.NoError(t, err)

	assert.NotEqual(t, gotForward, gotReversed)
}

// TestCanonicalBytes_DifferentContentProducesDifferentOutput proves the content hash binds
// the actual command bytes, not just its length or shape.
func TestCanonicalBytes_DifferentContentProducesDifferentOutput(t *testing.T) {
	one := baseEnvelope()
	one.Content = []byte("echo one")
	two := baseEnvelope()
	two.Content = []byte("echo two")

	gotOne, err := operatorpayload.CanonicalBytes(one)
	require.NoError(t, err)
	gotTwo, err := operatorpayload.CanonicalBytes(two)
	require.NoError(t, err)

	assert.NotEqual(t, gotOne, gotTwo)
}

// TestCanonicalBytes_DifferentExpiryProducesDifferentOutput proves the expiry is bound
// into the signed bytes so it cannot be silently extended after signing.
func TestCanonicalBytes_DifferentExpiryProducesDifferentOutput(t *testing.T) {
	one := baseEnvelope()
	one.ExpiresAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	two := baseEnvelope()
	two.ExpiresAt = time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)

	gotOne, err := operatorpayload.CanonicalBytes(one)
	require.NoError(t, err)
	gotTwo, err := operatorpayload.CanonicalBytes(two)
	require.NoError(t, err)

	assert.NotEqual(t, gotOne, gotTwo)
}
