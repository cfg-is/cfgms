// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"testing"
	"time"

	"go.etcd.io/raft/v3"
	"go.etcd.io/raft/v3/raftpb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// newTestClusterCfg returns a minimal ClusterConfig that mirrors the old hardcoded
// Raft defaults (100ms tick, 10 election ticks, 1 heartbeat tick) for tests that
// do not exercise timing-specific behaviour.
func newTestClusterCfg() *ClusterConfig {
	return &ClusterConfig{
		HeartbeatInterval: 100 * time.Millisecond,
		ElectionTimeout:   1 * time.Second,
	}
}

// TestRaftConsensus_TimingDerivedFromClusterConfig verifies that HeartbeatTick,
// ElectionTick, and the internal ticker interval are all derived from ClusterConfig
// rather than hardcoded constants. With HeartbeatInterval=500ms / ElectionTimeout=5s
// the expected values are: tickInterval=500ms, HeartbeatTick=1, ElectionTick=10.
func TestRaftConsensus_TimingDerivedFromClusterConfig(t *testing.T) {
	clusterCfg := &ClusterConfig{
		HeartbeatInterval: 500 * time.Millisecond,
		ElectionTimeout:   5 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{ID: "timing-node", State: NodeStateHealthy, Role: NodeRoleFollower}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, clusterCfg, logging.GetLogger())
	require.NoError(t, err)
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	assert.Equal(t, 500*time.Millisecond, rc.tickInterval, "tickInterval must equal HeartbeatInterval")
	assert.Equal(t, 1, rc.config.HeartbeatTick, "HeartbeatTick must be 1 (Raft recommendation)")
	assert.Equal(t, 10, rc.config.ElectionTick, "ElectionTick must equal ElectionTimeout/HeartbeatInterval")
}

// TestRaftConsensus_NewRaftConsensus_NilClusterCfgReturnsError verifies that a nil
// ClusterConfig is rejected at construction time with a descriptive error.
func TestRaftConsensus_NewRaftConsensus_NilClusterCfgReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nodeInfo := &NodeInfo{ID: "err-node", State: NodeStateHealthy, Role: NodeRoleFollower}
	_, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, nil, logging.GetLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "clusterCfg")
}

// TestRaftConsensus_NewRaftConsensus_ZeroHeartbeatIntervalReturnsError verifies that
// a non-positive HeartbeatInterval is rejected at construction time.
func TestRaftConsensus_NewRaftConsensus_ZeroHeartbeatIntervalReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nodeInfo := &NodeInfo{ID: "err-node", State: NodeStateHealthy, Role: NodeRoleFollower}
	cfg := &ClusterConfig{HeartbeatInterval: 0, ElectionTimeout: 1 * time.Second}
	_, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, cfg, logging.GetLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HeartbeatInterval")
}

// TestRaftConsensus_NewRaftConsensus_ZeroElectionTimeoutReturnsError verifies that
// a non-positive ElectionTimeout is rejected at construction time.
func TestRaftConsensus_NewRaftConsensus_ZeroElectionTimeoutReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nodeInfo := &NodeInfo{ID: "err-node", State: NodeStateHealthy, Role: NodeRoleFollower}
	cfg := &ClusterConfig{HeartbeatInterval: 100 * time.Millisecond, ElectionTimeout: 0}
	_, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, cfg, logging.GetLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ElectionTimeout")
}

// TestRaftConsensus_NewRaftConsensus_ElectionTickTooSmallReturnsError verifies that
// an ElectionTimeout less than 5× HeartbeatInterval is rejected (Raft safety requirement).
func TestRaftConsensus_NewRaftConsensus_ElectionTickTooSmallReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nodeInfo := &NodeInfo{ID: "err-node", State: NodeStateHealthy, Role: NodeRoleFollower}
	// ElectionTimeout / HeartbeatInterval = 2, which is < 5×HeartbeatTick (= 5).
	cfg := &ClusterConfig{HeartbeatInterval: 500 * time.Millisecond, ElectionTimeout: 1 * time.Second}
	_, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, cfg, logging.GetLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ElectionTimeout")
}

func TestRaftConsensus_propose_stoppedNodeDoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{
		ID:    "test-node",
		State: NodeStateHealthy,
		Role:  NodeRoleFollower,
	}

	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, newTestClusterCfg(), logging.GetLogger())
	require.NoError(t, err)

	// Stop the underlying raft node so that Propose returns ErrStopped.
	// The runRaft goroutine continues running (stopC and ctx not closed),
	// so it will read from proposeC, call Propose, get ErrStopped, and log.
	rc.node.Stop()

	// Send a proposal; runRaft will attempt Propose on the stopped node and
	// log the error without panicking or deadlocking.
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		select {
		case rc.proposeC <- []byte("trigger error"):
		case <-time.After(2 * time.Second):
		}
	}()

	select {
	case <-sent:
	case <-time.After(3 * time.Second):
		t.Fatal("proposal goroutine did not complete in time")
	}
}

// TestRaftConsensus_ProposeNodeUpdate_AppliedViaRaft verifies that ProposeNodeUpdate
// encodes the command and sends it through proposeC, and that after the Raft loop
// processes the entry, GetClusterNodes returns the updated NodeInfo.
func TestRaftConsensus_ProposeNodeUpdate_AppliedViaRaft(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodeInfo := &NodeInfo{
		ID:      "test-node",
		Address: "127.0.0.1:1111",
		State:   NodeStateHealthy,
		Role:    NodeRoleFollower,
	}

	// Single-peer list so StartNode bootstraps a new single-node cluster.
	peers := []raft.Peer{{ID: 1}}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, newTestClusterCfg(), logging.GetLogger())
	require.NoError(t, err)
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	// Wait for the node to win the election and become leader before proposing.
	require.Eventually(t, func() bool {
		return rc.IsLeader()
	}, 10*time.Second, 50*time.Millisecond, "single-node cluster must elect itself leader")

	// Propose an update with a distinctive address to verify the value came
	// through the apply path (not any construction-time initialisation).
	updatedInfo := &NodeInfo{
		ID:      "test-node",
		Address: "127.0.0.1:9999",
		State:   NodeStateHealthy,
		Role:    NodeRoleLeader,
	}

	err = rc.ProposeNodeUpdate(updatedInfo)
	require.NoError(t, err)

	// Wait for the Raft loop to commit and apply the entry.
	require.Eventually(t, func() bool {
		for _, n := range rc.GetClusterNodes() {
			if n.Address == "127.0.0.1:9999" {
				return true
			}
		}
		return false
	}, 5*time.Second, 25*time.Millisecond, "ProposeNodeUpdate must be committed and applied via the Raft log")
}

// TestRaftConsensus_ProposeAddNode_SubmitsToChannel verifies ProposeAddNode does not
// block the caller and enqueues a ConfChange of type ConfChangeAddNode to confChangeC.
func TestRaftConsensus_ProposeAddNode_SubmitsToChannel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{ID: "node-1", Address: "127.0.0.1:2000"}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, newTestClusterCfg(), logging.GetLogger())
	require.NoError(t, err)
	// Stop before the deferred Stop — stopOnce makes this safe; both return nil.
	rc.Stop()       //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	// Raft loop has fully exited (Stop blocks on wg.Wait), so confChangeC won't be drained.
	peerInfo := &NodeInfo{ID: "node-2", Address: "127.0.0.1:2001"}
	err = rc.ProposeAddNode(2, peerInfo)
	require.NoError(t, err, "ProposeAddNode must not return an error when channel has capacity")

	// Drain the channel to confirm the correct ConfChange was enqueued.
	select {
	case cc := <-rc.confChangeC:
		assert.Equal(t, raftpb.ConfChangeAddNode, cc.Type)
		assert.Equal(t, uint64(2), cc.NodeID)
	default:
		t.Fatal("confChangeC should contain the enqueued ConfChange")
	}
}

// TestRaftConsensus_ProposeRemoveNode_SubmitsToChannel verifies ProposeRemoveNode does
// not block and enqueues a ConfChange of type ConfChangeRemoveNode to confChangeC.
func TestRaftConsensus_ProposeRemoveNode_SubmitsToChannel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{ID: "node-1", Address: "127.0.0.1:3000"}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, newTestClusterCfg(), logging.GetLogger())
	require.NoError(t, err)
	rc.Stop()       //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	err = rc.ProposeRemoveNode(2)
	require.NoError(t, err, "ProposeRemoveNode must not return an error when channel has capacity")

	select {
	case cc := <-rc.confChangeC:
		assert.Equal(t, raftpb.ConfChangeRemoveNode, cc.Type)
		assert.Equal(t, uint64(2), cc.NodeID)
	default:
		t.Fatal("confChangeC should contain the enqueued ConfChange")
	}
}

// TestRaftConsensus_ProposeNodeUpdate_ChannelFull_ReturnsError verifies that
// ProposeNodeUpdate returns a non-nil error rather than blocking when proposeC is full.
func TestRaftConsensus_ProposeNodeUpdate_ChannelFull_ReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{ID: "node-fill", Address: "127.0.0.1:4000"}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, newTestClusterCfg(), logging.GetLogger())
	require.NoError(t, err)

	// Stop blocks until runRaft exits, guaranteeing proposeC won't be drained.
	rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	const bufSize = 16
	for i := 0; i < bufSize; i++ {
		rc.proposeC <- []byte("fill")
	}

	// With proposeC at capacity, ProposeNodeUpdate must return an error immediately.
	err = rc.ProposeNodeUpdate(nodeInfo)
	require.Error(t, err, "ProposeNodeUpdate must return an error when proposeC is full")
}

// TestRaftConsensus_ProposeAddNode_ChannelFull_ReturnsError verifies that
// ProposeAddNode returns a non-nil error rather than blocking when confChangeC is full.
func TestRaftConsensus_ProposeAddNode_ChannelFull_ReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{ID: "node-add-fill", Address: "127.0.0.1:5000"}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, newTestClusterCfg(), logging.GetLogger())
	require.NoError(t, err)

	// Stop blocks until runRaft exits, guaranteeing confChangeC won't be drained.
	rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	const bufSize = 16
	for i := 0; i < bufSize; i++ {
		rc.confChangeC <- raftpb.ConfChange{Type: raftpb.ConfChangeAddNode, NodeID: uint64(i + 10)}
	}

	// With confChangeC at capacity, ProposeAddNode must return an error immediately.
	err = rc.ProposeAddNode(99, &NodeInfo{ID: "overflow", Address: "127.0.0.1:6000"})
	require.Error(t, err, "ProposeAddNode must return an error when confChangeC is full")
}

// TestRaftConsensus_ProposeRemoveNode_ChannelFull_ReturnsError verifies that
// ProposeRemoveNode returns a non-nil error rather than blocking when confChangeC is full.
func TestRaftConsensus_ProposeRemoveNode_ChannelFull_ReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{ID: "node-rem-fill", Address: "127.0.0.1:7000"}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, newTestClusterCfg(), logging.GetLogger())
	require.NoError(t, err)

	// Stop blocks until runRaft exits, guaranteeing confChangeC won't be drained.
	rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	const bufSize = 16
	for i := 0; i < bufSize; i++ {
		rc.confChangeC <- raftpb.ConfChange{Type: raftpb.ConfChangeRemoveNode, NodeID: uint64(i + 10)}
	}

	// With confChangeC at capacity, ProposeRemoveNode must return an error immediately.
	err = rc.ProposeRemoveNode(99)
	require.Error(t, err, "ProposeRemoveNode must return an error when confChangeC is full")
}

// TestRaftConsensus_ProposeSessionUpdate_AppliedViaRaft verifies that
// ProposeSessionUpdate(connected=true) commits through the Raft log and
// clusterState.Sessions["steward-1"].Connected becomes true via applySessionUpdate.
func TestRaftConsensus_ProposeSessionUpdate_AppliedViaRaft(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodeInfo := &NodeInfo{
		ID:      "session-test-node",
		Address: "127.0.0.1:8111",
		State:   NodeStateHealthy,
		Role:    NodeRoleFollower,
	}

	peers := []raft.Peer{{ID: 1}}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, newTestClusterCfg(), logging.GetLogger())
	require.NoError(t, err)
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	require.Eventually(t, func() bool {
		return rc.IsLeader()
	}, 10*time.Second, 50*time.Millisecond, "single-node cluster must elect itself leader")

	err = rc.ProposeSessionUpdate("steward-1", "node-1", true)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		rc.clusterState.mu.RLock()
		cmd, ok := rc.clusterState.Sessions["steward-1"]
		rc.clusterState.mu.RUnlock()
		return ok && cmd.Connected
	}, 5*time.Second, 25*time.Millisecond, "session connect must be committed and applied via the Raft log")

	// Verify all fields are preserved through the apply path.
	rc.clusterState.mu.RLock()
	cmd := rc.clusterState.Sessions["steward-1"]
	rc.clusterState.mu.RUnlock()
	assert.Equal(t, "steward-1", cmd.StewardID)
	assert.Equal(t, "node-1", cmd.NodeID)
	assert.True(t, cmd.Connected)
	assert.False(t, cmd.Timestamp.IsZero(), "Timestamp must be set")
}

// TestRaftConsensus_ProposeSessionUpdate_Disconnect_DeletesEntry verifies that
// ProposeSessionUpdate(connected=false) removes the entry from ClusterState.Sessions
// after the entry is committed via the Raft log.
func TestRaftConsensus_ProposeSessionUpdate_Disconnect_DeletesEntry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodeInfo := &NodeInfo{ID: "session-disconnect-node", Address: "127.0.0.1:8222", State: NodeStateHealthy, Role: NodeRoleFollower}
	peers := []raft.Peer{{ID: 1}}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, newTestClusterCfg(), logging.GetLogger())
	require.NoError(t, err)
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	require.Eventually(t, func() bool {
		return rc.IsLeader()
	}, 10*time.Second, 50*time.Millisecond, "single-node cluster must elect itself leader")

	// First connect, then disconnect.
	require.NoError(t, rc.ProposeSessionUpdate("steward-2", "node-1", true))
	require.Eventually(t, func() bool {
		rc.clusterState.mu.RLock()
		_, ok := rc.clusterState.Sessions["steward-2"]
		rc.clusterState.mu.RUnlock()
		return ok
	}, 5*time.Second, 25*time.Millisecond, "connect must be applied before disconnect is proposed")

	require.NoError(t, rc.ProposeSessionUpdate("steward-2", "node-1", false))
	require.Eventually(t, func() bool {
		rc.clusterState.mu.RLock()
		_, ok := rc.clusterState.Sessions["steward-2"]
		rc.clusterState.mu.RUnlock()
		return !ok
	}, 5*time.Second, 25*time.Millisecond, "session disconnect must delete the entry via the Raft log")
}

// TestRaftConsensus_ProposeSessionUpdate_ChannelFull_ReturnsError verifies that
// ProposeSessionUpdate returns a non-nil error rather than blocking when proposeC is full.
func TestRaftConsensus_ProposeSessionUpdate_ChannelFull_ReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{ID: "session-full-node", Address: "127.0.0.1:8333"}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, newTestClusterCfg(), logging.GetLogger())
	require.NoError(t, err)

	rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	const bufSize = 16
	for i := 0; i < bufSize; i++ {
		rc.proposeC <- []byte("fill")
	}

	err = rc.ProposeSessionUpdate("steward-x", "node-1", true)
	require.Error(t, err, "ProposeSessionUpdate must return an error when proposeC is full")
}
