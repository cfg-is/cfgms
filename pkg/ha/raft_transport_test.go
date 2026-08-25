// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.etcd.io/raft/v3"
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

// callHandleStatus calls transport.HandleStatus and decodes the response body into
// raftStatusResponse. Fails the test if the response is not 200 or cannot be decoded.
func callHandleStatus(t *testing.T, transport *raftTransport) raftStatusResponse {
	t.Helper()
	req := httptest.NewRequest("GET", "/raft/status", nil)
	w := httptest.NewRecorder()
	transport.HandleStatus(w, req)
	require.Equal(t, 200, w.Code, "HandleStatus must return 200")

	var resp raftStatusResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp),
		"HandleStatus response must decode into raftStatusResponse")
	return resp
}

// TestHandleStatus_BothSurfacesAgreeOnIsLeader is the REQUIRED test asserting that
// HandleStatus (the raft status surface, /api/v1/raft/status) and Manager.HasLeadership()
// (the ha status surface, /api/v1/ha/status) agree on is_leader for all three
// leadership states mandated by Issue #3435's acceptance criteria:
//
//  1. Non-leader: both surfaces report is_leader=false.
//  2. Raft leader with valid lease: both report is_leader=true.
//  3. Raft leader with expired lease: both report is_leader=false (raft_is_leader=true).
//
// The ha status surface is represented by rc.HasLeadership() — the same method
// Manager.HasLeadership() delegates to in ClusterMode — so both surfaces draw from
// the identical source of truth and can only diverge if one of them is wired
// incorrectly. States 2 and 3 additionally confirm that is_leader tracks HasLeadership()
// (not IsLeader()/IsRaftLeader()) by demonstrating the split when lease expires.
func TestHandleStatus_BothSurfacesAgreeOnIsLeader(t *testing.T) {
	t.Run("non-leader", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// nil peers → RestartNode with empty voter config → node stays follower,
		// cannot self-elect, IsRaftLeader() = false and HasLeadership() = false.
		nodeInfo := &NodeInfo{ID: "status-non-leader", State: NodeStateHealthy, Role: NodeRoleFollower}
		rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, newTestClusterCfg(), "", logging.GetLogger())
		require.NoError(t, err)
		defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

		transport := newRaftTransport(1, "localhost:8080", rc, nil, nil, nil, nil, logging.GetLogger())

		resp := callHandleStatus(t, transport)

		// Both surfaces: HandleStatus.is_leader and rc.HasLeadership() must be false.
		assert.False(t, resp.IsLeader,
			"is_leader must be false in the non-leader state (HasLeadership() = false)")
		assert.False(t, resp.RaftIsLeader,
			"raft_is_leader must be false in the non-leader state (IsRaftLeader() = false)")
		assert.Equal(t, rc.HasLeadership(), resp.IsLeader,
			"HandleStatus.is_leader must equal rc.HasLeadership() (ha status surface)")
		assert.Equal(t, rc.IsRaftLeader(), resp.RaftIsLeader,
			"HandleStatus.raft_is_leader must equal rc.IsRaftLeader()")
	})

	t.Run("raft-leader-with-valid-lease", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cfg := FastElectionConfig()
		nodeInfo := &NodeInfo{ID: "status-leader-lease", State: NodeStateHealthy, Role: NodeRoleFollower}
		// One peer (self) → StartNode bootstraps a single-node cluster that can elect itself.
		peers := []raft.Peer{{ID: 1}}
		rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, &cfg, "", logging.GetLogger())
		require.NoError(t, err)
		defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

		// Wait for both Raft leadership and lease establishment.
		require.Eventually(t, rc.HasLeadership,
			5*time.Second, 5*time.Millisecond,
			"single-node cluster must elect itself leader and establish the lease")

		transport := newRaftTransport(1, "localhost:8080", rc, nil, nil, nil, nil, logging.GetLogger())

		resp := callHandleStatus(t, transport)

		// Both surfaces must report true while the lease is valid.
		assert.True(t, resp.IsLeader,
			"is_leader must be true when HasLeadership() is true (lease valid)")
		assert.True(t, resp.RaftIsLeader,
			"raft_is_leader must be true when IsRaftLeader() is true")
		assert.Equal(t, rc.HasLeadership(), resp.IsLeader,
			"HandleStatus.is_leader must equal rc.HasLeadership() (ha status surface)")
		assert.Equal(t, rc.IsRaftLeader(), resp.RaftIsLeader,
			"HandleStatus.raft_is_leader must equal rc.IsRaftLeader()")
	})

	t.Run("raft-leader-with-expired-lease", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cfg := FastElectionConfig()
		nodeInfo := &NodeInfo{ID: "status-expired-lease", State: NodeStateHealthy, Role: NodeRoleFollower}
		peers := []raft.Peer{{ID: 1}}
		rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, &cfg, "", logging.GetLogger())
		require.NoError(t, err)
		defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

		require.Eventually(t, rc.HasLeadership,
			5*time.Second, 5*time.Millisecond,
			"single-node cluster must elect itself leader and establish the lease")

		// Expire the lease stably by zeroing leaseDuration.
		// HasLeadership() = time.Since(leaseLastAck) < leaseDuration; with leaseDuration=0
		// every positive elapsed time is ≥ 0, so the window is always closed.
		// Backdating leaseLastAck alone would race the tick loop, which refreshes
		// leaseLastAck on every tick (~40ms) for single-node clusters — it can undo the
		// backdate before callHandleStatus runs. leaseDuration is written once at
		// construction and never touched by the tick loop, so zeroing it is stable.
		rc.mu.Lock()
		rc.leaseDuration = 0
		rc.mu.Unlock()

		// HasLeadership must now be false; IsRaftLeader must remain true.
		require.False(t, rc.HasLeadership(), "HasLeadership must be false after lease expiry")
		require.True(t, rc.IsRaftLeader(), "IsRaftLeader must remain true (Raft protocol still leader)")

		transport := newRaftTransport(1, "localhost:8080", rc, nil, nil, nil, nil, logging.GetLogger())

		resp := callHandleStatus(t, transport)

		// is_leader follows HasLeadership (false), raft_is_leader follows IsRaftLeader (true).
		// This is the key discriminator: if is_leader were wired to IsRaftLeader or IsLeader,
		// it would be true here — proving the correct primitive is used.
		assert.False(t, resp.IsLeader,
			"is_leader must be false when lease has expired (HasLeadership() = false)")
		assert.True(t, resp.RaftIsLeader,
			"raft_is_leader must be true while Raft protocol still sees this node as leader")
		assert.Equal(t, rc.HasLeadership(), resp.IsLeader,
			"HandleStatus.is_leader must equal rc.HasLeadership() (ha status surface)")
		assert.Equal(t, rc.IsRaftLeader(), resp.RaftIsLeader,
			"HandleStatus.raft_is_leader must equal rc.IsRaftLeader()")
	})
}
