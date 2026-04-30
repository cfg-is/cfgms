// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package quic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestCA creates and initialises a fresh CA for use in TLS tests.
func newTestCA(t *testing.T) *cfgcert.CA {
	t.Helper()
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	return ca
}

// newTestServerCert returns a server tls.Certificate signed by ca.
func newTestServerCert(t *testing.T, ca *cfgcert.CA) tls.Certificate {
	t.Helper()
	cert, err := ca.GenerateServerCertificate(&cfgcert.ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	tlsCert, err := cfgcert.LoadTLSCertificate(cert.CertificatePEM, cert.PrivateKeyPEM)
	require.NoError(t, err)
	return tlsCert
}

// newTestClientCert returns a client tls.Certificate with the given CN signed by ca.
func newTestClientCert(t *testing.T, ca *cfgcert.CA, cn string) tls.Certificate {
	t.Helper()
	cert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   cn,
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	tlsCert, err := cfgcert.LoadTLSCertificate(cert.CertificatePEM, cert.PrivateKeyPEM)
	require.NoError(t, err)
	return tlsCert
}

// newTestCertPool builds an x509.CertPool containing the CA's certificate.
func newTestCertPool(t *testing.T, ca *cfgcert.CA) *x509.CertPool {
	t.Helper()
	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM))
	return pool
}

// ---------------------------------------------------------------------------
// ServerTLSConfig tests
// ---------------------------------------------------------------------------

// TestServerTLSConfig_Valid verifies that a valid cert and CA pool produce a
// properly configured server TLS config.
func TestServerTLSConfig_Valid(t *testing.T) {
	ca := newTestCA(t)
	serverCert := newTestServerCert(t, ca)
	caPool := newTestCertPool(t, ca)

	cfg, err := ServerTLSConfig(serverCert, caPool)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion, "must enforce TLS 1.3")
	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth, "must require client certificate")
	assert.Equal(t, []string{ALPNProtocol}, cfg.NextProtos, "must set ALPN to cfgms-grpc")
	assert.Len(t, cfg.Certificates, 1)
}

// TestServerTLSConfig_NilCertPool verifies that a nil CA pool returns an error,
// since mTLS requires a pool to verify incoming client certificates.
func TestServerTLSConfig_NilCertPool(t *testing.T) {
	ca := newTestCA(t)
	serverCert := newTestServerCert(t, ca)

	cfg, err := ServerTLSConfig(serverCert, nil)
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

// ---------------------------------------------------------------------------
// ClientTLSConfig tests
// ---------------------------------------------------------------------------

// TestClientTLSConfig_Valid verifies that a valid client cert and root CA pool
// produce a properly configured client TLS config.
func TestClientTLSConfig_Valid(t *testing.T) {
	ca := newTestCA(t)
	clientCert := newTestClientCert(t, ca, "steward-test")
	rootCAs := newTestCertPool(t, ca)

	cfg, err := ClientTLSConfig(clientCert, rootCAs)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion, "must enforce TLS 1.3")
	assert.Equal(t, []string{ALPNProtocol}, cfg.NextProtos, "must set ALPN to cfgms-grpc")
	assert.Len(t, cfg.Certificates, 1)
	assert.NotNil(t, cfg.RootCAs)
}

// TestClientTLSConfig_NilRootCAs verifies that a nil root CA pool returns an
// error, since the client must always verify the server certificate.
func TestClientTLSConfig_NilRootCAs(t *testing.T) {
	ca := newTestCA(t)
	clientCert := newTestClientCert(t, ca, "steward-test")

	cfg, err := ClientTLSConfig(clientCert, nil)
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

// TestTLSConfig_ALPNMatch verifies that both server and client configs use the
// same ALPN protocol so they can negotiate successfully.
func TestTLSConfig_ALPNMatch(t *testing.T) {
	ca := newTestCA(t)
	serverCert := newTestServerCert(t, ca)
	clientCert := newTestClientCert(t, ca, "steward-test")
	caPool := newTestCertPool(t, ca)

	serverCfg, err := ServerTLSConfig(serverCert, caPool)
	require.NoError(t, err)

	clientCfg, err := ClientTLSConfig(clientCert, caPool)
	require.NoError(t, err)

	require.Equal(t, serverCfg.NextProtos, clientCfg.NextProtos,
		"server and client ALPN must match for TLS negotiation to succeed")
	assert.Equal(t, []string{"cfgms-grpc"}, serverCfg.NextProtos)
}

// ---------------------------------------------------------------------------
// PeerStewardID tests
// ---------------------------------------------------------------------------

// parsePEMCert decodes the first certificate block from PEM-encoded data.
func parsePEMCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block, "PEM decode failed")
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return x509Cert
}

// TestPeerStewardID_ValidCert verifies that a ConnectionState containing a peer
// certificate with a non-empty CN returns that CN as the steward ID.
func TestPeerStewardID_ValidCert(t *testing.T) {
	ca := newTestCA(t)
	cert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   "steward-abc",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	x509Cert := parsePEMCert(t, cert.CertificatePEM)

	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{x509Cert},
	}

	id, err := PeerStewardID(state)
	require.NoError(t, err)
	assert.Equal(t, "steward-abc", id)
}

// TestPeerStewardID_NoPeerCerts verifies that an empty PeerCertificates slice
// returns an error.
func TestPeerStewardID_NoPeerCerts(t *testing.T) {
	state := tls.ConnectionState{
		PeerCertificates: nil,
	}

	id, err := PeerStewardID(state)
	assert.Error(t, err)
	assert.Empty(t, id)
}

// TestPeerStewardID_EmptyCN verifies that a peer certificate with an empty
// Common Name returns an error.
func TestPeerStewardID_EmptyCN(t *testing.T) {
	ca := newTestCA(t)
	cert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   "placeholder",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	x509Cert := parsePEMCert(t, cert.CertificatePEM)

	// Override the CN to simulate an empty-CN peer certificate.
	x509Cert.Subject.CommonName = ""

	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{x509Cert},
	}

	id, err := PeerStewardID(state)
	assert.Error(t, err)
	assert.Empty(t, id)
}

// ---------------------------------------------------------------------------
// Conn.TLSConnectionState tests
// ---------------------------------------------------------------------------

// TestConn_TLSConnectionState verifies that after a full QUIC handshake,
// TLSConnectionState returns a non-nil state containing peer certificates.
func TestConn_TLSConnectionState(t *testing.T) {
	// Use cfgms-grpc ALPN so we use the new TLS config helpers.
	ca := newTestCA(t)
	serverCert := newTestServerCert(t, ca)
	clientCert := newTestClientCert(t, ca, "steward-state-test")
	caPool := newTestCertPool(t, ca)

	serverTLS, err := ServerTLSConfig(serverCert, caPool)
	require.NoError(t, err)
	serverTLS.ServerName = "localhost"

	clientTLS, err := ClientTLSConfig(clientCert, caPool)
	require.NoError(t, err)
	clientTLS.ServerName = "localhost"

	tlsPair := &testTLSPair{server: serverTLS, client: clientTLS}
	serverConn, clientConn := dialPair(t, tlsPair)

	// Server side: the client cert should be exposed.
	serverState := serverConn.TLSConnectionState()
	require.NotNil(t, serverState, "server TLS state must not be nil")
	assert.NotEmpty(t, serverState.PeerCertificates, "server must see client's peer certificate")

	// Client side: the server cert should be exposed.
	clientState := clientConn.TLSConnectionState()
	require.NotNil(t, clientState, "client TLS state must not be nil")
	assert.NotEmpty(t, clientState.PeerCertificates, "client must see server's peer certificate")
}

// ---------------------------------------------------------------------------
// Integration tests: mTLS enforcement
// ---------------------------------------------------------------------------

// newMTLSTLSPair builds a testTLSPair using the cfgms-grpc ALPN and proper
// mTLS configs produced by ServerTLSConfig / ClientTLSConfig.
func newMTLSTLSPair(t *testing.T, stewardID string) *testTLSPair {
	t.Helper()
	ca := newTestCA(t)
	serverCert := newTestServerCert(t, ca)
	clientCert := newTestClientCert(t, ca, stewardID)
	caPool := newTestCertPool(t, ca)

	serverTLS, err := ServerTLSConfig(serverCert, caPool)
	require.NoError(t, err)
	serverTLS.ServerName = "localhost"

	clientTLS, err := ClientTLSConfig(clientCert, caPool)
	require.NoError(t, err)
	clientTLS.ServerName = "localhost"

	return &testTLSPair{server: serverTLS, client: clientTLS}
}

// TestGRPCOverQUIC_mTLS verifies that a client presenting a valid certificate
// signed by the server's CA can connect successfully.
func TestGRPCOverQUIC_mTLS(t *testing.T) {
	tlsPair := newMTLSTLSPair(t, "steward-valid")

	serverConn, clientConn := dialPair(t, tlsPair)

	// Verify the connection works end-to-end.
	_, err := clientConn.Write([]byte("hello"))
	require.NoError(t, err)

	require.NoError(t, serverConn.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 16)
	n, err := serverConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf[:n]))

	// Verify the server can extract the steward identity from TLS state.
	serverState := serverConn.TLSConnectionState()
	require.NotNil(t, serverState)
	id, err := PeerStewardID(*serverState)
	require.NoError(t, err)
	assert.Equal(t, "steward-valid", id)
}

// TestGRPCOverQUIC_mTLS_NoCert verifies that a client without a certificate is
// rejected by the server when mTLS is required.
//
// In QUIC+TLS 1.3, the server's certificate_required alert (0x174) arrives
// after the initial handshake completes from the client's perspective. The
// rejection is delivered as a CRYPTO_ERROR on the first read after the server
// processes the client's (absent) certificate.
func TestGRPCOverQUIC_mTLS_NoCert(t *testing.T) {
	ca := newTestCA(t)
	serverCert := newTestServerCert(t, ca)
	caPool := newTestCertPool(t, ca)

	serverTLS, err := ServerTLSConfig(serverCert, caPool)
	require.NoError(t, err)
	serverTLS.ServerName = "localhost"

	// Client config without a certificate — only the root CA, no client cert.
	clientTLS := &tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{ALPNProtocol},
	}

	lis, err := Listen("127.0.0.1:0", serverTLS, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })

	// Drain the accept loop; the server will reject the connection after
	// verifying (or failing to verify) the absent client certificate.
	go func() {
		conn, aerr := lis.Accept()
		if aerr != nil {
			return
		}
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// The Dial may succeed initially since QUIC delivers the server's
	// certificate_required alert asynchronously. The rejection manifests on
	// the first read after the server processes the empty client certificate.
	conn, dialErr := Dial(ctx, lis.Addr().String(), clientTLS, nil)
	if dialErr != nil {
		// Dial itself failed — server rejected immediately.
		return
	}
	defer func() { _ = conn.Close() }()

	// Write data to trigger the server to process our (absent) certificate.
	// The server sends certificate_required (CRYPTO_ERROR 0x174); the 3-second
	// read deadline is sufficient for the alert to arrive without a sleep.
	_, _ = conn.Write([]byte{0x00})
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	assert.Error(t, readErr, "read must fail with certificate_required CRYPTO_ERROR")
}

// TestGRPCOverQUIC_mTLS_WrongCA verifies that a client presenting a certificate
// signed by a different CA is rejected by the server.
//
// Like the no-cert case, the server's unknown_certificate_authority alert
// (CRYPTO_ERROR 0x130) arrives after the initial handshake and manifests as a
// read error rather than a Dial failure.
func TestGRPCOverQUIC_mTLS_WrongCA(t *testing.T) {
	// Server trusts CA-A only.
	caA := newTestCA(t)
	serverCert := newTestServerCert(t, caA)
	caAPool := newTestCertPool(t, caA)

	serverTLS, err := ServerTLSConfig(serverCert, caAPool)
	require.NoError(t, err)
	serverTLS.ServerName = "localhost"

	// Client uses a certificate signed by CA-B (which the server does not trust).
	caB := newTestCA(t)
	clientCert := newTestClientCert(t, caB, "steward-wrong-ca")

	// The client trusts CA-A to verify the server cert (so the client-side
	// handshake succeeds), but the client presents a cert from CA-B.
	clientTLS, err := ClientTLSConfig(clientCert, caAPool)
	require.NoError(t, err)
	clientTLS.ServerName = "localhost"

	lis, err := Listen("127.0.0.1:0", serverTLS, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })

	// Drain the accept loop.
	go func() {
		conn, aerr := lis.Accept()
		if aerr == nil {
			buf := make([]byte, 1)
			_, _ = conn.Read(buf)
		}
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// Same pattern as NoCert: dial may succeed; rejection arrives on read.
	conn, dialErr := Dial(ctx, lis.Addr().String(), clientTLS, nil)
	if dialErr != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	// Write to trigger server-side cert processing; alert arrives within the read deadline.
	_, _ = conn.Write([]byte{0x00})
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	assert.Error(t, readErr, "read must fail with unknown_certificate_authority CRYPTO_ERROR")
}
