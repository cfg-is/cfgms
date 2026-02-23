//go:build commercial

// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz
// +build commercial

package ha

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"go.etcd.io/raft/v3/raftpb"

	"github.com/cfgis/cfgms/pkg/cert"
)

// raftTransport handles network communication between Raft nodes
type raftTransport struct {
	mu sync.RWMutex

	// Node identity
	nodeID  uint64
	address string // This node's address (host:port)

	// Peer addresses
	peers map[uint64]string

	// HTTP client for sending messages
	client *http.Client
	useTLS bool // Whether to use HTTPS for peer communication

	// Consensus engine
	consensus *RaftConsensus

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	stopC  chan struct{}
}

// newRaftTransport creates a new Raft transport
func newRaftTransport(nodeID uint64, address string, consensus *RaftConsensus, caCertPEM []byte) *raftTransport {
	var tlsConfig *tls.Config
	var err error

	if len(caCertPEM) > 0 {
		// Proper TLS validation with CA certificate
		tlsConfig, err = cert.CreateClientTLSConfig(nil, nil, caCertPEM, "", tls.VersionTLS12)
		if err != nil {
			log.Printf("RAFT_TRANSPORT: Failed to create TLS config with CA cert, using basic TLS: %v", err)
			tlsConfig, _ = cert.CreateBasicTLSConfig(nil, nil, tls.VersionTLS12)
		}
	} else {
		// No CA cert available — use basic TLS without InsecureSkipVerify.
		// Connections to peers will fail TLS validation (correct: don't run HA without proper certs).
		log.Printf("RAFT_TRANSPORT: WARNING: No CA certificate configured for HA transport. " +
			"Set CFGMS_HA_CA_CERT_PATH for proper TLS validation between cluster nodes.")
		tlsConfig, _ = cert.CreateBasicTLSConfig(nil, nil, tls.VersionTLS12)
	}

	transport := &http.Transport{
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		TLSClientConfig:     tlsConfig,
	}

	return &raftTransport{
		nodeID:    nodeID,
		address:   address,
		peers:     make(map[uint64]string),
		consensus: consensus,
		useTLS:    true, // Default to TLS for cluster communication
		client: &http.Client{
			Timeout:   3 * time.Second,
			Transport: transport,
		},
		stopC: make(chan struct{}),
	}
}

// Start begins the transport layer
func (t *raftTransport) Start(ctx context.Context) error {
	t.ctx, t.cancel = context.WithCancel(ctx)
	log.Printf("RAFT_TRANSPORT: Started transport, node_id=%d, address=%s", t.nodeID, t.address)
	return nil
}

// Stop stops the transport layer
func (t *raftTransport) Stop() {
	if t.cancel != nil {
		t.cancel()
	}
	close(t.stopC)
	log.Printf("RAFT_TRANSPORT: Stopped transport, node_id=%d", t.nodeID)
}

// AddPeer adds a peer node address
func (t *raftTransport) AddPeer(nodeID uint64, address string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peers[nodeID] = address
	log.Printf("RAFT_TRANSPORT: Added peer, node_id=%d, address=%s", nodeID, address)
}

// RemovePeer removes a peer node
func (t *raftTransport) RemovePeer(nodeID uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.peers, nodeID)
	log.Printf("RAFT_TRANSPORT: Removed peer, node_id=%d", nodeID)
}

// Send sends messages to peer nodes
func (t *raftTransport) Send(messages []raftpb.Message) {
	for _, msg := range messages {
		if msg.To == 0 {
			continue // Skip messages with no destination
		}

		// Send asynchronously to avoid blocking
		go t.sendMessage(msg)
	}
}

// sendMessage sends a single message to a peer
func (t *raftTransport) sendMessage(msg raftpb.Message) {
	t.mu.RLock()
	peerAddr, ok := t.peers[msg.To]
	t.mu.RUnlock()

	if !ok {
		log.Printf("RAFT_TRANSPORT: No address for peer, peer_id=%d", msg.To)
		return
	}

	// Serialize message
	data, err := msg.Marshal()
	if err != nil {
		log.Printf("RAFT_TRANSPORT: Failed to marshal message: %v", err)
		return
	}

	// Construct URL for peer's Raft endpoint
	scheme := "http"
	if t.useTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/raft/message", scheme, peerAddr)

	// Send HTTP POST
	req, err := http.NewRequestWithContext(t.ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		log.Printf("RAFT_TRANSPORT: Failed to create request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Raft-From", fmt.Sprintf("%d", t.nodeID))

	resp, err := t.client.Do(req)
	if err != nil {
		log.Printf("RAFT_TRANSPORT: Failed to send message to peer %d at %s: %v", msg.To, peerAddr, err)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("RAFT_TRANSPORT: Failed to close response body for peer %d: %v", msg.To, err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("RAFT_TRANSPORT: Peer %d returned error %d: %s", msg.To, resp.StatusCode, string(body))
	}
}

// HandleMessage processes incoming Raft messages (HTTP handler)
func (t *raftTransport) HandleMessage(w http.ResponseWriter, r *http.Request) {
	log.Printf("RAFT_TRANSPORT: Received message HTTP request, node_id=%d, remote_addr=%s", t.nodeID, r.RemoteAddr)

	// Read message body
	data, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("RAFT_TRANSPORT: Failed to read message body: %v", err)
		http.Error(w, "Failed to read message", http.StatusBadRequest)
		return
	}
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Printf("RAFT_TRANSPORT: Failed to close request body: %v", err)
		}
	}()

	log.Printf("RAFT_TRANSPORT: Read %d bytes from request body", len(data))

	// Deserialize message
	var msg raftpb.Message
	if err := msg.Unmarshal(data); err != nil {
		log.Printf("RAFT_TRANSPORT: Failed to unmarshal message: %v", err)
		http.Error(w, "Failed to unmarshal message", http.StatusBadRequest)
		return
	}

	log.Printf("RAFT_TRANSPORT: Received Raft message, node_id=%d, from=%d, to=%d, type=%s",
		t.nodeID, msg.From, msg.To, msg.Type)

	// Process message through Raft
	if err := t.consensus.Process(r.Context(), msg); err != nil {
		log.Printf("RAFT_TRANSPORT: Failed to process message from peer %d: %v", msg.From, err)
		http.Error(w, "Failed to process message", http.StatusInternalServerError)
		return
	}

	log.Printf("RAFT_TRANSPORT: Successfully processed message from peer %d", msg.From)
	w.WriteHeader(http.StatusOK)
}

// raftStatusResponse is returned by the status endpoint
type raftStatusResponse struct {
	NodeID   uint64 `json:"node_id"`
	IsLeader bool   `json:"is_leader"`
	Leader   uint64 `json:"leader"`
	Term     uint64 `json:"term"`
	Nodes    int    `json:"nodes"`
}

// HandleStatus returns Raft status (HTTP handler)
func (t *raftTransport) HandleStatus(w http.ResponseWriter, r *http.Request) {
	status := raftStatusResponse{
		NodeID:   t.nodeID,
		IsLeader: t.consensus.IsLeader(),
		Leader:   t.consensus.GetLeader(),
		Term:     t.consensus.node.Status().Term,
		Nodes:    len(t.consensus.GetClusterNodes()),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		log.Printf("RAFT_TRANSPORT: Failed to encode status response: %v", err)
	}
}
