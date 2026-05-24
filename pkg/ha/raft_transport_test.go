// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz

package ha

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"testing"

	"go.etcd.io/raft/v3/raftpb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

func TestRaftTransport_Start_returnsNoError(t *testing.T) {
	transport := newRaftTransport(1, "localhost:8080", nil, nil, nil, logging.GetLogger())

	ctx := context.Background()
	err := transport.Start(ctx)
	require.NoError(t, err)
}

// makeFakePeerCert returns a minimal x509.Certificate with the given CN, suitable
// for populating r.TLS.PeerCertificates in unit tests. No signature validation is
// performed by verifyPeerCN — only the CN string is inspected.
func makeFakePeerCert(cn string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{CommonName: cn},
	}
}

// TestHandleMessage_NilTLS_Returns403 verifies that HandleMessage rejects requests
// that arrive without a TLS connection state (i.e., plain HTTP).
func TestHandleMessage_NilTLS_Returns403(t *testing.T) {
	transport := newRaftTransport(1, "localhost:8080", nil, nil, []string{"node-1"}, logging.GetLogger())

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
	transport := newRaftTransport(1, "localhost:8080", nil, nil, []string{"node-1"}, logging.GetLogger())

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
	transport := newRaftTransport(1, "localhost:8080", nil, nil, []string{"node-1"}, logging.GetLogger())

	req := httptest.NewRequest("POST", "/raft/message", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{makeFakePeerCert("evil-node")},
	}
	w := httptest.NewRecorder()
	transport.HandleMessage(w, req)

	assert.Equal(t, 403, w.Code, "unknown peer CN must be rejected with 403")
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
	consensus, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, clusterCfg, logger)
	require.NoError(t, err)
	defer func() {
		if stopErr := consensus.Stop(); stopErr != nil {
			t.Logf("consensus.Stop: %v", stopErr)
		}
	}()

	transport := newRaftTransport(1, "localhost:8080", consensus, nil, []string{"node-1"}, logger)

	// Marshal a minimal raftpb.Message (empty message, Type=MsgHup).
	// node.Step is non-blocking: it enqueues to the raft goroutine and returns nil.
	var msg raftpb.Message
	data, err := msg.Marshal()
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/raft/message", bytes.NewReader(data))
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{makeFakePeerCert("node-1")},
	}
	w := httptest.NewRecorder()
	transport.HandleMessage(w, req)

	assert.Equal(t, 200, w.Code,
		"valid peer CN must pass CN verification and reach the handler (got %d)", w.Code)
}
