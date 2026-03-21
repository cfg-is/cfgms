// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package quic

import (
	"crypto/tls"
	"testing"
	"time"

	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/stretchr/testify/require"
)

// testALPN is the ALPN protocol used in tests to distinguish from production traffic.
const testALPN = "cfgms-transport-test"

// testTLSPair holds matched server and client TLS configurations.
type testTLSPair struct {
	server *tls.Config
	client *tls.Config
}

// newTestTLSPair creates a CA, signs server and client certificates, and returns
// matched TLS configs for both sides.
func newTestTLSPair(t *testing.T) *testTLSPair {
	t.Helper()

	// Create and initialize a test CA.
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	// Server certificate signed by the CA.
	serverCert, err := ca.GenerateServerCertificate(&cfgcert.ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	// Client certificate signed by the same CA.
	clientCert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   "test-client",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	// Build server TLS config (requires and verifies client cert).
	serverTLS, err := cfgcert.CreateServerTLSConfig(
		serverCert.CertificatePEM, serverCert.PrivateKeyPEM,
		caPEM, tls.VersionTLS13,
	)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{testALPN}

	// Build client TLS config (provides client cert, verifies server).
	clientTLS, err := cfgcert.CreateClientTLSConfig(
		clientCert.CertificatePEM, clientCert.PrivateKeyPEM,
		caPEM, "localhost", tls.VersionTLS13,
	)
	require.NoError(t, err)
	clientTLS.NextProtos = []string{testALPN}

	return &testTLSPair{server: serverTLS, client: clientTLS}
}

// dialPair starts a QUIC listener, dials it, and returns matching server and
// client Conn values ready for use. The listener is closed via t.Cleanup.
//
// QUIC only notifies the server of a new bidirectional stream when it receives
// data on that stream. dialPair writes a 1-byte sync signal from client to
// server and drains it before returning, so callers receive clean connections.
func dialPair(t *testing.T, tlsPair *testTLSPair) (serverConn, clientConn *Conn) {
	t.Helper()

	lis, err := Listen("127.0.0.1:0", tlsPair.server, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })

	type serverResult struct {
		conn *Conn
		err  error
	}
	serverCh := make(chan serverResult, 1)
	go func() {
		nc, aerr := lis.Accept()
		if aerr != nil {
			serverCh <- serverResult{err: aerr}
			return
		}
		serverCh <- serverResult{conn: nc.(*Conn)}
	}()

	addr := lis.Addr().String()
	cc, err := Dial(t.Context(), addr, tlsPair.client, nil)
	require.NoError(t, err)

	// QUIC only delivers stream notifications when data is received on the
	// stream. Write a single sync byte to wake up the server's AcceptStream.
	_, err = cc.Write([]byte{0x00})
	require.NoError(t, err)

	sr := <-serverCh
	require.NoError(t, sr.err)

	// Drain the sync byte from the server side so tests start with clean buffers.
	require.NoError(t, sr.conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	syncBuf := make([]byte, 1)
	_, err = sr.conn.Read(syncBuf)
	require.NoError(t, err)
	require.NoError(t, sr.conn.SetReadDeadline(time.Time{}))

	t.Cleanup(func() { _ = cc.Close() })
	t.Cleanup(func() { _ = sr.conn.Close() })

	return sr.conn, cc.(*Conn)
}
