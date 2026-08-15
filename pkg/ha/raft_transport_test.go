// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestRaftTransport_Start_returnsNoError(t *testing.T) {
	transport := newRaftTransport(1, "localhost:8080", nil, nil, nil, nil, nil, logging.GetLogger())

	ctx := context.Background()
	err := transport.Start(ctx)
	require.NoError(t, err)
}

// testPeerCertWithCN returns a minimal x509.Certificate with the given CN, suitable
// for populating r.TLS.PeerCertificates in unit tests. No signature validation is
// performed by verifyPeerCN — only the CN string is checked.
func testPeerCertWithCN(cn string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{CommonName: cn},
	}
}

// TestHandleMessage_NilTLS_Returns403 verifies that HandleMessage rejects requests
// that arrive without a TLS connection state (i.e., plain HTTP).
func TestHandleMessage_NilTLS_Returns403(t *testing.T) {
	transport := newRaftTransport(1, "localhost:8080", nil, nil, nil, nil, []string{"node-1"}, logging.GetLogger())

	req := httptest.NewRequest("POST", "/raft/message", nil)
	// r.TLS is nil (plain HTTP, no peer certificate)
	w := httptest.NewRecorder()
	transport.HandleMessage(w, req)

	assert.Equal(t, 403, w.Code, "nil r.TLS must be rejected with 403")
}

// TestHandleMessage_EmptyPeerCertificates_Returns403 verifies that HandleMessage
// rejects TLS connections where the peer did not present a client certificate
// (r.TLS is non-nil but PeerCertificates is empty). This is a distinct reachable
// scenario from nil-TLS: e.g., a non-peer HTTPS client hitting /raft/message.
func TestHandleMessage_EmptyPeerCertificates_Returns403(t *testing.T) {
	transport := newRaftTransport(1, "localhost:8080", nil, nil, nil, nil, []string{"node-1"}, logging.GetLogger())

	req := httptest.NewRequest("POST", "/raft/message", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: nil, // TLS handshake succeeded but no client cert presented
	}
	w := httptest.NewRecorder()
	transport.HandleMessage(w, req)

	assert.Equal(t, 403, w.Code, "empty PeerCertificates must be rejected with 403")
}

// TestHandleMessage_UnknownCN_Returns403 verifies that HandleMessage rejects requests
// whose peer certificate CN is not in the configured cluster node allowlist.
func TestHandleMessage_UnknownCN_Returns403(t *testing.T) {
	transport := newRaftTransport(1, "localhost:8080", nil, nil, nil, nil, []string{"node-1"}, logging.GetLogger())

	req := httptest.NewRequest("POST", "/raft/message", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{testPeerCertWithCN("evil-node")},
	}
	w := httptest.NewRecorder()
	transport.HandleMessage(w, req)

	assert.Equal(t, 403, w.Code, "unknown peer CN must be rejected with 403")
}

// TestHandleMessage_RejectedPeer_SanitizesLoggedRemoteAddr verifies that the
// rejection path passes attacker-controlled values through logging.SanitizeLogValue
// before they reach the log record. r.RemoteAddr is the injectable field here: unlike
// the numeric raftpb.Message accessors it is a free-form string that can carry CR/LF
// and forge additional log lines (CWE-117).
func TestHandleMessage_RejectedPeer_SanitizesLoggedRemoteAddr(t *testing.T) {
	logger := logging.NewCapturingLogger()
	transport := newRaftTransport(1, "localhost:8080", nil, nil, nil, nil, []string{"node-1"}, logger)

	req := httptest.NewRequest("POST", "/raft/message", nil)
	req.RemoteAddr = "10.0.0.9:7000\r\nlevel=INFO msg=\"forged cluster join\""
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{testPeerCertWithCN("evil-node")},
	}
	w := httptest.NewRecorder()
	transport.HandleMessage(w, req)

	require.Equal(t, 403, w.Code, "unknown peer CN must be rejected with 403")

	entry, ok := logger.FindWarn("Rejected message from unauthorized peer")
	require.True(t, ok, "rejection must emit the unauthorized-peer warning")

	remoteAddr, ok := entry["remote_addr"].(string)
	require.True(t, ok, "remote_addr must be logged as a sanitized string, got %T", entry["remote_addr"])
	assert.NotContains(t, remoteAddr, "\n", "logged remote_addr must not carry a raw newline")
	assert.NotContains(t, remoteAddr, "\r", "logged remote_addr must not carry a raw carriage return")

	// The verifyPeerCN error embeds the presented peer CN and must be sanitized too.
	loggedErr, ok := entry["error"].(string)
	require.True(t, ok, "error must be logged as a sanitized string, got %T", entry["error"])
	assert.NotContains(t, loggedErr, "\n", "logged error must not carry a raw newline")
	assert.NotContains(t, loggedErr, "\r", "logged error must not carry a raw carriage return")
}

// TestHandleMessage_ValidPeerCN_Returns200 verifies that HandleMessage accepts requests
// whose peer certificate CN matches a known cluster node. A real RaftConsensus is used
// so that consensus.Process() (node.Step) succeeds and the handler returns 200.
func TestHandleMessage_ValidPeerCN_Returns200(t *testing.T) {
	logger := logging.GetLogger()
	clusterCfg := newTestClusterCfg()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{ID: "node-1", State: NodeStateHealthy, Role: NodeRoleFollower}
	consensus, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, clusterCfg, "", logger)
	require.NoError(t, err)
	defer func() {
		if stopErr := consensus.Stop(); stopErr != nil {
			t.Logf("consensus.Stop: %v", stopErr)
		}
	}()

	transport := newRaftTransport(1, "localhost:8080", consensus, nil, nil, nil, []string{"node-1"}, logger)

	// Marshal a minimal raftpb.Message (empty message, Type=MsgHup).
	// node.Step is non-blocking: it enqueues to the raft goroutine and returns nil.
	// v3.7.0: use proto.Marshal on a pointer; raftpb.Message no longer has Marshal().
	msg := &raftpb.Message{}
	data, err := proto.Marshal(msg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/raft/message", bytes.NewReader(data))
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{testPeerCertWithCN("node-1")},
	}
	w := httptest.NewRecorder()
	transport.HandleMessage(w, req)

	assert.Equal(t, 200, w.Code,
		"valid peer CN must pass CN verification and reach the handler (got %d)", w.Code)
}

// TestNewRaftTransport_WithClientCert_SetsTLSCertificates verifies that when
// clientCertPEM and clientKeyPEM are both supplied to newRaftTransport, the
// resulting transport's underlying http.Transport.TLSClientConfig.Certificates
// slice is non-empty (the mTLS client cert is loaded and ready to present to peers).
func TestNewRaftTransport_WithClientCert_SetsTLSCertificates(t *testing.T) {
	// Create a CA and generate a client cert signed by it so that caCertPEM
	// activates the CreateClientTLSConfig path (which loads Certificates).
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS Transport Test CA",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	caCertPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	clientCert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   "node-1",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	clientCertPEM := clientCert.CertificatePEM
	clientKeyPEM := clientCert.PrivateKeyPEM

	transport := newRaftTransport(1, "localhost:8080", nil, caCertPEM, clientCertPEM, clientKeyPEM, nil, logging.GetLogger())

	httpT, ok := transport.client.Transport.(*http.Transport)
	require.True(t, ok, "http.Client.Transport must be *http.Transport")
	require.NotNil(t, httpT.TLSClientConfig, "TLSClientConfig must be set")
	assert.NotEmpty(t, httpT.TLSClientConfig.Certificates,
		"TLSClientConfig.Certificates must be non-empty when client cert/key PEM are supplied")
}

// TestNewRaftTransport_WithoutClientCert_EmptyTLSCertificates verifies that when
// no clientCertPEM/clientKeyPEM are passed (single-server or misconfigured cluster mode
// that falls through to the no-CA path), TLSClientConfig.Certificates is empty —
// the transport falls back to server-auth-only TLS and will be rejected by peers that
// enforce mTLS CN verification.
func TestNewRaftTransport_WithoutClientCert_EmptyTLSCertificates(t *testing.T) {
	// No CA cert → falls to CreateBasicTLSConfig which never sets Certificates.
	transport := newRaftTransport(1, "localhost:8080", nil, nil, nil, nil, nil, logging.GetLogger())

	httpT, ok := transport.client.Transport.(*http.Transport)
	require.True(t, ok, "http.Client.Transport must be *http.Transport")
	// Either TLSClientConfig is nil or Certificates is empty — both mean no client cert.
	if httpT.TLSClientConfig != nil {
		assert.Empty(t, httpT.TLSClientConfig.Certificates,
			"TLSClientConfig.Certificates must be empty when no client cert is provided")
	}
}
