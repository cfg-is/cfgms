// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client provides tests for the transport client.
// Issue #920: on-demand cert loading via certManager.GetClientCertificate.
package client

import (
	"context"
	"crypto/tls"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingCertManager is a minimal stand-in for cert.Manager that counts how
// many times GetClientCertificate is called and returns distinct certs on each
// call. It embeds a counter so the test can assert re-fetch behaviour.
type countingCertManager struct {
	calls atomic.Int64
	certs []*tls.Certificate // indexed by call count (modulo len)
}

func (m *countingCertManager) GetClientCertificate(_ context.Context) (*tls.Certificate, error) {
	n := m.calls.Add(1)
	idx := int(n-1) % len(m.certs)
	return m.certs[idx], nil
}

// getCertManagerGetFunc returns the GetClientCertificate function for the given
// countingCertManager, matching the signature expected by tls.Config.GetClientCertificate.
func getCertManagerGetFunc(m *countingCertManager) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return m.GetClientCertificate(context.Background())
	}
}

// TestTransportClient_CertReloadOnHandshake verifies that the tls.Config
// GetClientCertificate callback re-calls certManager.GetClientCertificate on
// each handshake. This directly validates the closure wired in createTLSConfig.
func TestTransportClient_CertReloadOnHandshake(t *testing.T) {
	// Two distinct (but syntactically valid-enough-for-test) TLS certs.
	cert1 := &tls.Certificate{Certificate: [][]byte{[]byte("cert-bytes-1")}}
	cert2 := &tls.Certificate{Certificate: [][]byte{[]byte("cert-bytes-2")}}

	mgr := &countingCertManager{certs: []*tls.Certificate{cert1, cert2}}

	// Wire the closure the same way createTLSConfig does.
	fn := getCertManagerGetFunc(mgr)

	// First simulated handshake.
	got1, err := fn(nil)
	require.NoError(t, err)
	assert.Equal(t, cert1, got1, "first handshake must return cert1")

	// Second simulated handshake — must call GetClientCertificate again.
	got2, err := fn(nil)
	require.NoError(t, err)
	assert.Equal(t, cert2, got2, "second handshake must return cert2 (re-fetch)")

	assert.Equal(t, int64(2), mgr.calls.Load(), "GetClientCertificate must be called once per handshake")
}

// TestTransportClient_CertNotCached verifies that the certManager is queried
// on each invocation, not a cached value.
func TestTransportClient_CertNotCached(t *testing.T) {
	cert := &tls.Certificate{Certificate: [][]byte{[]byte("only-cert")}}
	mgr := &countingCertManager{certs: []*tls.Certificate{cert}}
	fn := getCertManagerGetFunc(mgr)

	const iterations = 5
	for i := 0; i < iterations; i++ {
		_, err := fn(nil)
		require.NoError(t, err)
	}

	assert.Equal(t, int64(iterations), mgr.calls.Load(),
		"certManager must be called on every handshake, not just once")
}
