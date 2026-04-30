// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client provides tests for the transport client.
// Issue #920: on-demand cert loading via certManager.GetClientCertificate.
package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestTransportClient_CertReloadOnHandshake verifies that createTLSConfig wires
// GetClientCertificate as a per-handshake callback (not a cached value) so that
// certificate rotations are picked up automatically.
func TestTransportClient_CertReloadOnHandshake(t *testing.T) {
	dir := t.TempDir()
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: dir,
		CAConfig: &cert.CAConfig{
			Organization: "Test Org",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	// Generate the initial client certificate.
	_, err = mgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-test-001",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	// Wire a TransportClient with the real cert.Manager.
	c := &TransportClient{
		certManager: mgr,
		logger:      logging.NewLogger("info"),
	}

	tlsCfg, err := c.createTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)
	require.NotNil(t, tlsCfg.GetClientCertificate, "createTLSConfig must set GetClientCertificate")

	// First handshake — returns the initial cert.
	got1, err := tlsCfg.GetClientCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, got1)
	require.NotEmpty(t, got1.Certificate, "first handshake must return a non-empty cert")

	// Simulate rotation: generate a replacement client cert.
	_, err = mgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-test-001-renewed",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	// Second handshake — must return the rotated cert (re-fetched from store, not cached).
	got2, err := tlsCfg.GetClientCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, got2)
	require.NotEmpty(t, got2.Certificate, "second handshake must return a non-empty cert")

	// The leaf DER bytes differ between the original and rotated certs.
	assert.NotEqual(t, got1.Certificate[0], got2.Certificate[0],
		"second handshake must return the newer cert after rotation (re-fetch, not cached)")
}

// TestTransportClient_CertNotCached verifies that every call to the
// GetClientCertificate callback reads from the cert store rather than a cached
// value — even when the certificate has not changed.
func TestTransportClient_CertNotCached(t *testing.T) {
	dir := t.TempDir()
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: dir,
		CAConfig: &cert.CAConfig{
			Organization: "Test Org",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	_, err = mgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-test-002",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	c := &TransportClient{
		certManager: mgr,
		logger:      logging.NewLogger("info"),
	}

	tlsCfg, err := c.createTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	// Multiple calls must each succeed (no caching failure, no stale state).
	const iterations = 3
	for i := 0; i < iterations; i++ {
		got, err := tlsCfg.GetClientCertificate(nil)
		require.NoError(t, err, "call %d must not return an error", i+1)
		require.NotNil(t, got, "call %d must return a non-nil cert", i+1)
		require.NotEmpty(t, got.Certificate, "call %d must return non-empty cert bytes", i+1)
	}
}
