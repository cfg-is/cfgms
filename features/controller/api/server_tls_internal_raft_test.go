// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newHAManagerWithCAPEM builds a real SingleServerMode ha.Manager whose
// GetCACertPEM() returns exactly caPEM, by writing those bytes to a temp file and
// pointing CACertPath at it. Passing nil leaves CACertPath empty, which is the
// documented "no HA CA configured" case (GetCACertPEM returns nil).
//
// SingleServerMode is deliberate: internalRaftTLSConfig reads nothing from the
// manager but GetCACertPEM, so starting a raft cluster would add election and
// goroutine-leak surface without exercising any additional branch.
func newHAManagerWithCAPEM(t *testing.T, caPEM []byte) *ha.Manager {
	t.Helper()

	cfg := ha.DefaultConfig()
	cfg.Mode = ha.SingleServerMode
	if caPEM != nil {
		caPath := filepath.Join(t.TempDir(), "ha-ca.pem")
		require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))
		cfg.CACertPath = caPath
	}

	// Empty raftLogDir: these cases never start raft, so no WAL directory is
	// needed. GetCACertPEM is the only manager surface internalRaftTLSConfig
	// touches.
	manager, err := ha.NewManager(cfg, logging.NewNoopLogger(), nil, nil, "")
	require.NoError(t, err)
	return manager
}

// newPublicTLSWithCert returns a *tls.Config carrying one real server certificate
// and the supplied ClientCAs pool, standing in for the public API's TLS config that
// internalRaftTLSConfig clones.
func newPublicTLSWithCert(t *testing.T, clientCAs *x509.CertPool) *tls.Config {
	t.Helper()

	caCert, caKey, _ := makeCommercialTestCA(t)
	serverCert := makeCommercialTestClientCertFromCA(t, caCert, caKey)

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}
}

// TestInternalRaftTLSConfig_RejectsMissingServerCertificate covers the entry guard:
// the internal Raft listener must never be constructed without a server identity,
// so both a nil config and a config with an empty Certificates slice fail closed.
func TestInternalRaftTLSConfig_RejectsMissingServerCertificate(t *testing.T) {
	server := newMinimalTLSServer(t, nil, nil)

	tests := []struct {
		name      string
		publicTLS *tls.Config
	}{
		{name: "nil public TLS config", publicTLS: nil},
		{name: "no certificates", publicTLS: &tls.Config{MinVersion: tls.VersionTLS12}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := server.internalRaftTLSConfig(tc.publicTLS)
			require.Error(t, err, "a listener without a server certificate must not be built")
			assert.ErrorContains(t, err, "server certificate is unavailable")
			assert.Nil(t, got, "no TLS config may be returned when the guard rejects the input")
		})
	}
}

// TestInternalRaftTLSConfig_NilClientCAs covers the branch where the inherited
// public TLS config carries no client CA pool, leaving the HA peer CA as the only
// possible trust anchor. A valid HA CA becomes the pool; anything else must fail
// closed rather than start a listener that trusts nothing.
func TestInternalRaftTLSConfig_NilClientCAs(t *testing.T) {
	_, _, haCAPEM := makeCommercialTestCA(t)

	t.Run("valid HA CA becomes the client CA pool", func(t *testing.T) {
		server := newMinimalTLSServer(t, nil, newHAManagerWithCAPEM(t, haCAPEM))

		got, err := server.internalRaftTLSConfig(newPublicTLSWithCert(t, nil))
		require.NoError(t, err)
		require.NotNil(t, got)

		assert.NotNil(t, got.ClientCAs, "the HA peer CA must be installed as the client CA pool")
		assert.Equal(t, tls.RequireAndVerifyClientCert, got.ClientAuth,
			"the internal Raft listener must require and verify a peer certificate")
		assert.Equal(t, uint16(tls.VersionTLS13), got.MinVersion,
			"the internal listener must be pinned to TLS 1.3 regardless of the public config")
	})

	t.Run("no HA manager leaves no trust anchor", func(t *testing.T) {
		server := newMinimalTLSServer(t, nil, nil)

		got, err := server.internalRaftTLSConfig(newPublicTLSWithCert(t, nil))
		require.Error(t, err, "with neither an inherited pool nor an HA CA there is nothing to trust")
		assert.ErrorContains(t, err, "no trusted client CA is configured")
		assert.Nil(t, got)
	})

	t.Run("unparseable HA CA PEM is rejected", func(t *testing.T) {
		server := newMinimalTLSServer(t, nil, newHAManagerWithCAPEM(t, []byte("not a certificate")))

		got, err := server.internalRaftTLSConfig(newPublicTLSWithCert(t, nil))
		require.Error(t, err, "garbage PEM must not produce an empty pool that silently trusts nothing")
		assert.ErrorContains(t, err, "no trusted client CA is configured")
		assert.Nil(t, got)
	})
}

// TestInternalRaftTLSConfig_InheritedPoolWithHACA covers the branch where a client
// CA pool is inherited AND an HA CA is configured. The HA CA is appended so peers
// signed by either CA verify — but unparseable PEM must fail loudly, because
// AppendCertsFromPEM reports failure only through a boolean that the append path
// does not consult.
func TestInternalRaftTLSConfig_InheritedPoolWithHACA(t *testing.T) {
	_, _, inheritedCAPEM := makeCommercialTestCA(t)
	inheritedPool, err := cert.NewCertPoolFromPEM(inheritedCAPEM)
	require.NoError(t, err)

	t.Run("valid HA CA is appended to the inherited pool", func(t *testing.T) {
		_, _, haCAPEM := makeCommercialTestCA(t)
		server := newMinimalTLSServer(t, nil, newHAManagerWithCAPEM(t, haCAPEM))

		got, err := server.internalRaftTLSConfig(newPublicTLSWithCert(t, inheritedPool.Clone()))
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.NotNil(t, got.ClientCAs, "the inherited pool must survive with the HA CA added")
		assert.Equal(t, tls.RequireAndVerifyClientCert, got.ClientAuth)
		assert.Equal(t, uint16(tls.VersionTLS13), got.MinVersion)
	})

	t.Run("invalid HA CA PEM is rejected before append", func(t *testing.T) {
		server := newMinimalTLSServer(t, nil, newHAManagerWithCAPEM(t, []byte("-----BEGIN CERTIFICATE-----\nbroken\n-----END CERTIFICATE-----\n")))

		got, err := server.internalRaftTLSConfig(newPublicTLSWithCert(t, inheritedPool.Clone()))
		require.Error(t, err,
			"an unparseable HA CA must fail loudly: appending it silently no-ops and peers are rejected at handshake time")
		assert.ErrorContains(t, err, "HA peer CA is invalid")
		assert.Nil(t, got)
	})
}

// TestInternalRaftTLSConfig_EmptyInheritedPool covers the last branch: a non-nil but
// empty inherited pool with no HA CA to add. Serving mTLS from an empty trust store
// can never verify a peer, so the listener must refuse to start rather than accept
// connections it will always reject.
func TestInternalRaftTLSConfig_EmptyInheritedPool(t *testing.T) {
	server := newMinimalTLSServer(t, nil, newHAManagerWithCAPEM(t, nil))

	got, err := server.internalRaftTLSConfig(newPublicTLSWithCert(t, x509.NewCertPool()))
	require.Error(t, err, "an empty trust store must not back a RequireAndVerifyClientCert listener")
	assert.ErrorContains(t, err, "no trusted client CA is configured")
	assert.Nil(t, got)
}
