// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"runtime"
	"sync"
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
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, clusterCfg, "", logging.GetLogger())
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
	_, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, nil, "", logging.GetLogger())
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
	_, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, cfg, "", logging.GetLogger())
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
	_, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, cfg, "", logging.GetLogger())
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
	_, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, cfg, "", logging.GetLogger())
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

	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, newTestClusterCfg(), "", logging.GetLogger())
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
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, newTestClusterCfg(), "", logging.GetLogger())
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
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, newTestClusterCfg(), "", logging.GetLogger())
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
		// confChangeC carries pointers (raftpb.ConfChange must not be copied).
		require.NotNil(t, cc, "enqueued ConfChange must not be nil")
		// v3.7.0: Type is *ConfChangeType and NodeId is *uint64; use getters.
		assert.Equal(t, raftpb.ConfChangeAddNode, cc.GetType())
		assert.Equal(t, uint64(2), cc.GetNodeId())
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
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, newTestClusterCfg(), "", logging.GetLogger())
	require.NoError(t, err)
	rc.Stop()       //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	err = rc.ProposeRemoveNode(2)
	require.NoError(t, err, "ProposeRemoveNode must not return an error when channel has capacity")

	select {
	case cc := <-rc.confChangeC:
		// confChangeC carries pointers (raftpb.ConfChange must not be copied).
		require.NotNil(t, cc, "enqueued ConfChange must not be nil")
		// v3.7.0: Type is *ConfChangeType and NodeId is *uint64; use getters.
		assert.Equal(t, raftpb.ConfChangeRemoveNode, cc.GetType())
		assert.Equal(t, uint64(2), cc.GetNodeId())
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
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, newTestClusterCfg(), "", logging.GetLogger())
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
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, newTestClusterCfg(), "", logging.GetLogger())
	require.NoError(t, err)

	// Stop blocks until runRaft exits, guaranteeing confChangeC won't be drained.
	rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	const bufSize = 16
	for i := 0; i < bufSize; i++ {
		// v3.7.0: Type is *ConfChangeType (.Enum()), NodeId is *uint64 (new(value)).
		nodeIDVal := uint64(i + 10)
		rc.confChangeC <- &raftpb.ConfChange{Type: raftpb.ConfChangeAddNode.Enum(), NodeId: new(nodeIDVal)}
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
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, newTestClusterCfg(), "", logging.GetLogger())
	require.NoError(t, err)

	// Stop blocks until runRaft exits, guaranteeing confChangeC won't be drained.
	rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	const bufSize = 16
	for i := 0; i < bufSize; i++ {
		// v3.7.0: Type is *ConfChangeType (.Enum()), NodeId is *uint64 (new(value)).
		nodeIDVal := uint64(i + 10)
		rc.confChangeC <- &raftpb.ConfChange{Type: raftpb.ConfChangeRemoveNode.Enum(), NodeId: new(nodeIDVal)}
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
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, newTestClusterCfg(), "", logging.GetLogger())
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
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, newTestClusterCfg(), "", logging.GetLogger())
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
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, newTestClusterCfg(), "", logging.GetLogger())
	require.NoError(t, err)

	rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	const bufSize = 16
	for i := 0; i < bufSize; i++ {
		rc.proposeC <- []byte("fill")
	}

	err = rc.ProposeSessionUpdate("steward-x", "node-1", true)
	require.Error(t, err, "ProposeSessionUpdate must return an error when proposeC is full")
}

// TestRaftConsensus_RestartRecoversLogAndRejoinsAtCorrectIndex verifies that a
// RaftConsensus stopped and reconstructed against the same on-disk store starts
// from the persisted term and commit index rather than bootstrapping from index 0.
// The test uses no mocks: real raft.Node instances and a t.TempDir() log directory.
func TestRaftConsensus_RestartRecoversLogAndRejoinsAtCorrectIndex(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	logDir := t.TempDir()
	nodeInfo := &NodeInfo{ID: "restart-node", Address: "127.0.0.1:0", State: NodeStateHealthy, Role: NodeRoleFollower}
	peers := []raft.Peer{{ID: 1}}
	cfg := newTestClusterCfg()

	// Phase 1: start a single-node cluster and commit some entries.
	rc1, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, cfg, logDir, logging.GetLogger())
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return rc1.IsLeader()
	}, 10*time.Second, 50*time.Millisecond, "single-node cluster must elect itself leader")

	// Propose and wait for two entries to be applied through the log.
	require.NoError(t, rc1.ProposeNodeUpdate(&NodeInfo{
		ID: "restart-node", Address: "127.0.0.1:1111", State: NodeStateHealthy, Role: NodeRoleLeader,
	}))
	require.Eventually(t, func() bool {
		return rc1.HasNode(1)
	}, 5*time.Second, 25*time.Millisecond, "node update must be applied via the Raft log")

	// Capture the term and commit index before stopping.
	// v3.7.0: Status.Term and Status.Commit are *uint64 (via embedded *pb.HardState);
	// use GetTerm()/GetCommit() to obtain uint64 values for comparison.
	status1 := rc1.node.Status()
	preStopTerm := status1.GetTerm()
	preStopCommit := status1.GetCommit()

	require.Greater(t, preStopTerm, uint64(0), "term must be > 0 after election")
	require.Greater(t, preStopCommit, uint64(0), "commit index must be > 0 after entry apply")

	require.NoError(t, rc1.Stop())

	// Phase 2: reconstruct a new RaftConsensus against the same log directory.
	// peers is still passed but must NOT be used for StartNode — the store has data
	// so RestartNode is selected internally.
	rc2, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, cfg, logDir, logging.GetLogger())
	require.NoError(t, err)
	defer rc2.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	// The recovered node must restart at the persisted term and commit index.
	status2 := rc2.node.Status()
	assert.GreaterOrEqual(t, status2.GetTerm(), preStopTerm,
		"recovered term must be >= pre-stop term")
	assert.GreaterOrEqual(t, status2.GetCommit(), preStopCommit,
		"recovered commit index must be >= pre-stop commit index")
	assert.Equal(t, preStopCommit, rc2.appliedIndex,
		"recovered appliedIndex must match pre-stop commit index so entries are not re-delivered")
}

// TestRaftConsensus_RestartRebuildsMembershipFromPersistedStore verifies the
// fix for Issue #3394: a node that restarts into a live cluster reads its
// cluster membership from the durable store rather than from log-entry replay,
// which config.Applied deliberately blocks to avoid double-firing side effects.
//
// The test reproduces the minimal failure scenario: a single-node cluster
// commits a node_update (populating clusterState), a simulated peer entry is
// injected and persisted, the node stops, restarts — and GetClusterNodes()
// must immediately return the full membership without waiting for new entries.
func TestRaftConsensus_RestartRebuildsMembershipFromPersistedStore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	logDir := t.TempDir()
	nodeInfo := &NodeInfo{ID: "node-1", Address: "127.0.0.1:0", State: NodeStateHealthy, Role: NodeRoleFollower}
	peers := []raft.Peer{{ID: 1}}
	cfg := newTestClusterCfg()

	// Phase 1: start a single-node cluster, commit an entry so clusterState
	// is populated and persisted, then inject a simulated peer and stop.
	rc1, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, cfg, logDir, logging.GetLogger())
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return rc1.IsLeader()
	}, 10*time.Second, 50*time.Millisecond, "single-node cluster must elect itself leader")

	require.NoError(t, rc1.ProposeNodeUpdate(&NodeInfo{
		ID: "node-1", Address: "127.0.0.1:1111", State: NodeStateHealthy, Role: NodeRoleLeader,
	}))
	require.Eventually(t, func() bool {
		return rc1.HasNode(1)
	}, 5*time.Second, 25*time.Millisecond, "node update must be applied via the Raft log")

	// Inject a second (simulated peer) node directly into clusterState, as
	// would happen in a real multi-node cluster where the peer proposes its own
	// NodeInfo through the log. Then persist so the snapshot includes both nodes.
	const peerRaftID = uint64(99)
	peerInfo := &NodeInfo{ID: "peer-node", Address: "127.0.0.1:9999", State: NodeStateHealthy, Role: NodeRoleFollower}
	rc1.clusterState.mu.Lock()
	rc1.clusterState.Nodes[peerRaftID] = peerInfo
	rc1.clusterState.mu.Unlock()
	rc1.persistClusterState()

	require.NoError(t, rc1.Stop())

	// Phase 2: restart against the same log directory.
	// The log store has data, so RestartNode is used — config.Applied is set to
	// recoveredApplied, which means the node_update entries that populated
	// clusterState.Nodes on the first run are NOT redelivered as CommittedEntries.
	rc2, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, cfg, logDir, logging.GetLogger())
	require.NoError(t, err)
	defer rc2.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	// clusterState.Nodes must be restored from the persisted snapshot immediately
	// at construction — before any new Raft entries are committed.
	require.True(t, rc2.HasNode(1),
		"restarted node must restore its own entry from the persisted cluster membership")
	require.True(t, rc2.HasNode(peerRaftID),
		"restarted node must restore peer entry from the persisted cluster membership")

	nodes := rc2.GetClusterNodes()
	require.Len(t, nodes, 2,
		"restarted node must report full 2-node membership without waiting for log replay")
}

// TestRaftConsensus_ProcessReady_DurableWritePrecedesMessageDispatch verifies
// that processReady persists entries and HardState to the durable log store
// before the Raft loop advances to apply committed entries. Because entries
// must be persisted before messages are sent (Raft's safety contract), and
// messages are sent before apply, a fully applied entry is proof the write
// happened earlier in the same processReady call.
func TestRaftConsensus_ProcessReady_DurableWritePrecedesMessageDispatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	logDir := t.TempDir()
	nodeInfo := &NodeInfo{ID: "ordering-node", State: NodeStateHealthy, Role: NodeRoleFollower}
	peers := []raft.Peer{{ID: 1}}

	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, newTestClusterCfg(), logDir, logging.GetLogger())
	require.NoError(t, err)
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	require.Eventually(t, func() bool {
		return rc.IsLeader()
	}, 10*time.Second, 50*time.Millisecond, "single-node cluster must elect itself leader")

	// Propose an entry and wait for it to be applied via the Raft log.
	// publishEntries (apply) is the last observable step in processReady after
	// the durable write and message dispatch, so observing the apply proves the
	// write happened earlier in the same cycle.
	require.NoError(t, rc.ProposeNodeUpdate(&NodeInfo{
		ID: "ordering-node", Address: "127.0.0.1:2222", State: NodeStateHealthy, Role: NodeRoleLeader,
	}))
	require.Eventually(t, func() bool {
		return rc.HasNode(1)
	}, 5*time.Second, 25*time.Millisecond, "node update must be applied before asserting log store state")

	// Verify via the in-process log store (same package — direct field access).
	// Opening a second bbolt handle while the consensus holds the flock would block
	// indefinitely; instead we read through the already-open store that processReady
	// wrote to. logStore is set once at construction and never reassigned, so no
	// mutex is needed here. HasData() and LoadState() are read-only bbolt views,
	// safe to call from the test goroutine while the consensus loop is between ticks.
	require.NotNil(t, rc.logStore, "log store must be initialised when logDir is non-empty")
	require.True(t, rc.logStore.HasData(),
		"log store must contain persisted entries after a committed Raft proposal")

	_, entries, _, _, err := rc.logStore.LoadState()
	require.NoError(t, err)
	require.NotEmpty(t, entries,
		"at least the conf-change bootstrap entries must be persisted before apply completes")
}

// TestRaftConsensus_IsRaftLeader_MatchesRaftProtocolState verifies that IsRaftLeader
// reports the raw Raft replication-protocol state, identical to the pre-split
// IsLeader() behaviour.
func TestRaftConsensus_IsRaftLeader_MatchesRaftProtocolState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nodeInfo := &NodeInfo{ID: "raftleader-test", State: NodeStateHealthy, Role: NodeRoleFollower}
	peers := []raft.Peer{{ID: 1}}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, newTestClusterCfg(), "", logging.GetLogger())
	require.NoError(t, err)
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	// Before election: must not report itself as leader.
	// (Not asserted because the node might win immediately; just start timing.)

	// Single-node cluster elects itself leader.
	require.Eventually(t, func() bool {
		return rc.IsRaftLeader()
	}, 10*time.Second, 20*time.Millisecond, "single-node cluster must elect itself leader via IsRaftLeader")

	// IsRaftLeader reads the Raft state machine directly, so it flips the instant
	// raft's internal state changes; clusterState.Leader is updated one Ready
	// batch later by updateLeadership(). The replicated view must therefore
	// converge on the same answer, not match it instantaneously.
	require.Eventually(t, func() bool {
		rc.mu.RLock()
		defer rc.mu.RUnlock()
		return rc.clusterState.Leader == rc.nodeID
	}, 5*time.Second, 10*time.Millisecond,
		"clusterState.Leader must converge to nodeID once IsRaftLeader is true")
}

// TestRaftConsensus_GetTerm_ReturnsNonZeroAfterElection verifies that GetTerm
// returns a positive term once a leader has been elected.
func TestRaftConsensus_GetTerm_ReturnsNonZeroAfterElection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nodeInfo := &NodeInfo{ID: "getterm-test", State: NodeStateHealthy, Role: NodeRoleFollower}
	peers := []raft.Peer{{ID: 1}}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, newTestClusterCfg(), "", logging.GetLogger())
	require.NoError(t, err)
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	require.Eventually(t, func() bool {
		return rc.IsRaftLeader()
	}, 10*time.Second, 20*time.Millisecond, "single-node cluster must elect itself leader")

	term := rc.GetTerm()
	assert.Greater(t, term, uint64(0), "Raft term must be > 0 after election")

	// GetTerm must agree with Status().GetTerm() — it is a pass-through, not
	// an independently tracked value.
	statusTerm := rc.node.Status().GetTerm()
	assert.Equal(t, statusTerm, term, "GetTerm must match rc.node.Status().GetTerm()")
}

// TestRaftConsensus_HasLeadership_DivergesFromIsRaftLeader_OnLeaseExpiry is the
// REQUIRED test asserting that the two primitives demonstrably diverge: HasLeadership
// goes false once the lease has expired while IsRaftLeader remains true.
//
// "Stalling quorum acks" is simulated by setting leaseLastAck to a time just past
// the leaseDuration boundary, which is what would happen in a real partition once
// the lease window elapsed. FastElectionConfig gives leaseDuration = 0.8 × 200ms
// = 160ms — real elapsed time in-process, exercising the monotonic comparison.
func TestRaftConsensus_HasLeadership_DivergesFromIsRaftLeader_OnLeaseExpiry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := FastElectionConfig()
	nodeInfo := &NodeInfo{ID: "lease-diverge-test", State: NodeStateHealthy, Role: NodeRoleFollower}
	peers := []raft.Peer{{ID: 1}}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, &cfg, "", logging.GetLogger())
	require.NoError(t, err)
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	// leaseDuration = 0.8 × ElectionTimeout (FastElectionConfig: 0.8 × 200ms = 160ms).
	leaseDuration := time.Duration(float64(cfg.ElectionTimeout) * 0.8)

	// Wait for leadership and lease establishment.
	require.Eventually(t, func() bool {
		return rc.IsRaftLeader()
	}, 5*time.Second, 5*time.Millisecond, "single-node cluster must elect itself leader")

	require.Eventually(t, func() bool {
		return rc.HasLeadership()
	}, 5*time.Second, 5*time.Millisecond, "lease must be established after leader election")

	// Stall quorum acks: set leaseLastAck to a point just past the expiry
	// boundary. This reproduces what happens when heartbeat responses stop
	// arriving — the lease ages past leaseDuration without a refresh.
	rc.mu.Lock()
	rc.leaseLastAck = time.Now().Add(-(leaseDuration + time.Millisecond))
	rc.mu.Unlock()

	// HasLeadership must go false immediately (lease expired).
	// IsRaftLeader must remain true — the Raft protocol has not stepped down.
	assert.False(t, rc.HasLeadership(),
		"HasLeadership must be false once the lease has expired")
	assert.True(t, rc.IsRaftLeader(),
		"IsRaftLeader must remain true while Raft protocol still sees this node as leader")
}

// TestRaftConsensus_HasLeadership_ConcurrentReads_NoDataRace is the REQUIRED
// concurrency test. It exercises HasLeadership() reads against an active leader
// loop under -race to confirm there is no data race on leaseLastAck.
func TestRaftConsensus_HasLeadership_ConcurrentReads_NoDataRace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := FastElectionConfig()
	nodeInfo := &NodeInfo{ID: "race-test", State: NodeStateHealthy, Role: NodeRoleFollower}
	peers := []raft.Peer{{ID: 1}}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, &cfg, "", logging.GetLogger())
	require.NoError(t, err)
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	require.Eventually(t, func() bool {
		return rc.IsRaftLeader()
	}, 5*time.Second, 5*time.Millisecond, "single-node cluster must elect itself leader")

	// Spin up concurrent readers while the raft loop is actively writing leaseLastAck.
	var wg sync.WaitGroup
	const readers = 10
	deadline := time.Now().Add(400 * time.Millisecond)
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				_ = rc.HasLeadership()
				runtime.Gosched()
			}
		}()
	}
	wg.Wait()
}

// TestRaftConsensus_LeaseRefreshes_WhileActiveLeader verifies that leaseLastAck
// is updated by the raft loop while the node is an active leader with quorum.
func TestRaftConsensus_LeaseRefreshes_WhileActiveLeader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := FastElectionConfig()
	nodeInfo := &NodeInfo{ID: "lease-refresh-test", State: NodeStateHealthy, Role: NodeRoleFollower}
	peers := []raft.Peer{{ID: 1}}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, &cfg, "", logging.GetLogger())
	require.NoError(t, err)
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	// Wait for leadership and initial lease.
	require.Eventually(t, func() bool {
		return rc.HasLeadership()
	}, 5*time.Second, 5*time.Millisecond, "lease must be established after leader election")

	// Capture the first ack time.
	rc.mu.RLock()
	firstAck := rc.leaseLastAck
	rc.mu.RUnlock()

	// The raft loop should refresh leaseLastAck at least once within
	// a couple of HeartbeatIntervals.
	require.Eventually(t, func() bool {
		rc.mu.RLock()
		current := rc.leaseLastAck
		rc.mu.RUnlock()
		return current.After(firstAck)
	}, 5*time.Second, 5*time.Millisecond, "leaseLastAck must advance while node is active leader")
}

// TestRaftConsensus_NonLeaderNeverGetsLease is the regression test for the
// fail-open leadership check: the lease was granted from the replicated
// ClusterState.Leader field, and an empty Status().Progress map was treated as
// "single-node cluster, self is the quorum".
//
// Both conditions hold simultaneously on a *follower*: Progress is populated
// only on a leader, and ClusterState.Leader is state-machine content that
// arrives from peers in snapshots. A follower that applied a snapshot naming
// itself leader therefore refreshed its lease on every tick and reported
// HasLeadership() true indefinitely.
//
// The node here bootstraps a two-voter configuration with only one voter
// running, so it can never win an election — it is a real, permanently
// non-leading Raft node.
func TestRaftConsensus_NonLeaderNeverGetsLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	nodeInfo := &NodeInfo{ID: "non-leader", State: NodeStateHealthy, Role: NodeRoleFollower}
	// Voter 2 never starts: quorum is 2, so node 1 cannot be elected.
	peers := []raft.Peer{{ID: 1}, {ID: 2}}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, newTestClusterCfg(), "", logging.GetLogger())
	require.NoError(t, err)
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	// Give the node several election timeouts to fail to win an election.
	time.Sleep(2 * time.Second)
	require.NotEqual(t, raft.StateLeader, rc.node.Status().RaftState,
		"node must not be leader: the second voter never started")
	require.Empty(t, rc.node.Status().Progress,
		"Progress must be empty on a non-leader — this is the state the old empty-map branch treated as a single-node quorum")

	// Vector 1: a peer-supplied snapshot naming this node leader.
	// Written as raw JSON because that is what a hostile or legacy peer sends.
	hostileSnapshot := &raftpb.Snapshot{
		Data: []byte(`{"Leader":1,"Nodes":{"7":{"id":"peer-7","address":"127.0.0.1:7777"}},"Sessions":{}}`),
		Metadata: &raftpb.SnapshotMetadata{
			Index: new(uint64(5)),
			Term:  new(uint64(2)),
		},
	}
	rc.publishSnapshot(hostileSnapshot)

	rc.mu.RLock()
	snapshotLeader := rc.clusterState.Leader
	rc.mu.RUnlock()
	assert.Equal(t, uint64(0), snapshotLeader,
		"publishSnapshot must not take leadership from snapshot data")
	assert.True(t, rc.HasNode(7),
		"publishSnapshot must still install the replicated content of the snapshot")
	assert.False(t, rc.IsRaftLeader(), "a follower must not report Raft leadership after a snapshot")
	assert.False(t, rc.HasLeadership(), "a follower must never hold the leader lease")

	// Vector 2: the poisoned flag directly, covering any other path that could
	// set it (stale state, a future snapshot format, a bug in updateLeadership).
	rc.mu.Lock()
	rc.clusterState.Leader = rc.nodeID
	rc.leaseLastAck = time.Time{}
	rc.mu.Unlock()

	assert.False(t, rc.IsRaftLeader(),
		"IsRaftLeader must come from Status().RaftState, not the replicated Leader field")
	assert.False(t, rc.HasLeadership(),
		"HasLeadership must come from Status().RaftState, not the replicated Leader field")

	rc.refreshLeaseIfQuorum()
	rc.mu.RLock()
	ack := rc.leaseLastAck
	rc.mu.RUnlock()
	assert.True(t, ack.IsZero(),
		"refreshLeaseIfQuorum must fail closed on a non-leader with empty Progress")
	assert.False(t, rc.HasLeadership(), "HasLeadership must remain false after a refresh attempt")
}

// TestRaftConsensus_LeaseTracksRealPeerAcks is the regression test for the
// RecentActive-derived lease. RecentActive is only cleared once per
// check-quorum window (one ElectionTimeout), so stamping leaseLastAck =
// time.Now() whenever a quorum of voters had the flag set produced an effective
// authority window of up to 1.8 × ElectionTimeout — long enough for the
// partitioned side to still claim authority after the majority side elects a
// successor.
//
// The test builds a real two-voter configuration on a live leader, where the
// second voter's only contact is the heartbeat responses this test delivers
// through the real Process()/Step() path. It asserts the three properties the
// fix depends on:
//
//  1. No quorum ack ⇒ no lease (the added voter has RecentActive=true from
//     confchange.go:269 but has never actually been heard from).
//  2. The lease instant equals the ack instant, not the refresh instant.
//  3. The lease expires leaseDuration after that ack, and a later ack moves it.
func TestRaftConsensus_LeaseTracksRealPeerAcks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := newTestClusterCfg() // HeartbeatInterval 100ms, ElectionTimeout 1s
	leaseDuration := cfg.LeaseDuration()

	nodeInfo := &NodeInfo{ID: "ack-lease", State: NodeStateHealthy, Role: NodeRoleFollower}
	peers := []raft.Peer{{ID: 1}}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, cfg, "", logging.GetLogger())
	require.NoError(t, err)
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	require.Eventually(t, rc.HasLeadership, 10*time.Second, 10*time.Millisecond,
		"single-voter leader must hold the lease on its own ack")

	// Grow the configuration to two voters. Quorum becomes 2, so self-contact
	// alone is no longer sufficient.
	const peerID = uint64(2)
	require.NoError(t, rc.ProposeAddNode(peerID, &NodeInfo{
		ID: "ack-lease-peer", Address: "127.0.0.1:2222", State: NodeStateHealthy, Role: NodeRoleFollower,
	}))
	require.Eventually(t, func() bool {
		_, ok := rc.node.Status().Config.Voters.IDs()[peerID]
		return ok
	}, 10*time.Second, 10*time.Millisecond, "conf change must add the second voter")

	// Property 1: the new voter has never acked, so there is no quorum ack.
	rc.mu.Lock()
	rc.leaseLastAck = time.Time{}
	rc.mu.Unlock()

	rc.refreshLeaseIfQuorum()
	rc.mu.RLock()
	ack := rc.leaseLastAck
	rc.mu.RUnlock()
	require.True(t, ack.IsZero(),
		"no lease may be granted while a quorum of voters has not acked — RecentActive is not an ack")
	require.False(t, rc.HasLeadership(), "HasLeadership must be false without a quorum ack")

	// Property 2: deliver a real heartbeat response and confirm the lease is
	// stamped with the instant that response arrived.
	before := time.Now()
	require.NoError(t, rc.Process(ctx, newHeartbeatResp(peerID, rc.nodeID, rc.GetTerm())))
	after := time.Now()

	rc.refreshLeaseIfQuorum()
	rc.mu.RLock()
	firstAck := rc.leaseLastAck
	rc.mu.RUnlock()
	require.False(t, firstAck.IsZero(), "a quorum ack must grant the lease")
	assert.False(t, firstAck.Before(before), "lease instant must not predate the ack")
	assert.False(t, firstAck.After(after), "lease instant must be the ack instant, not a later refresh instant")
	assert.True(t, rc.HasLeadership(), "leader with a fresh quorum ack must hold authority")

	// The lease must not creep forward on refreshes that see no new ack — that
	// creep is exactly what stretched the authority window past the ADR-029 bound.
	time.Sleep(3 * cfg.HeartbeatInterval)
	rc.refreshLeaseIfQuorum()
	rc.mu.RLock()
	stillFirstAck := rc.leaseLastAck
	rc.mu.RUnlock()
	assert.True(t, stillFirstAck.Equal(firstAck),
		"leaseLastAck must not advance without a new quorum ack")

	// Property 3a: a later ack moves the lease forward.
	beforeSecond := time.Now()
	require.NoError(t, rc.Process(ctx, newHeartbeatResp(peerID, rc.nodeID, rc.GetTerm())))
	rc.refreshLeaseIfQuorum()
	rc.mu.RLock()
	secondAck := rc.leaseLastAck
	rc.mu.RUnlock()
	assert.False(t, secondAck.Before(beforeSecond), "a new ack must move the lease to the new ack instant")
	assert.True(t, rc.HasLeadership(), "authority continues while acks continue")

	// Property 3b: once acks stop, authority ends leaseDuration after the last
	// ack — measured from the ack, not from the last refresh.
	time.Sleep(time.Until(secondAck.Add(leaseDuration + 50*time.Millisecond)))
	assert.False(t, rc.HasLeadership(),
		"authority must end exactly leaseDuration after the last real quorum ack")
}

// TestRaftConsensus_PeerAcksBoundedToVoters is the regression test for the
// unbounded peerAcks map (CWE-770). recordPeerAck() keyed the map on
// m.GetFrom() — peer-controlled input read straight off the wire — and Process()
// records the ack before node.Step, so raft never got the chance to reject the
// message first. The only pruning lived inside refreshLeaseIfQuorum, behind its
// StateLeader early return, so a follower pruned nothing: an authenticated peer
// could flood MsgHeartbeatResp carrying distinct synthetic From IDs and grow the
// map until the controller ran out of memory, taking rc.mu on every insert.
//
// The node here bootstraps a two-voter configuration with only one voter
// running, so it is a real, permanently non-leading Raft node — the state the
// old pruning never reached.
func TestRaftConsensus_PeerAcksBoundedToVoters(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cfg := newTestClusterCfg()
	nodeInfo := &NodeInfo{ID: "ack-flood", State: NodeStateHealthy, Role: NodeRoleFollower}
	// Voter 2 never starts: quorum is 2, so node 1 can never be elected.
	peers := []raft.Peer{{ID: 1}, {ID: 2}}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, cfg, "", logging.GetLogger())
	require.NoError(t, err)
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	// Wait for the runRaft loop to publish the bootstrapped voter set.
	require.Eventually(t, func() bool {
		v := rc.voters.Load()
		if v == nil {
			return false
		}
		_, ok := (*v)[uint64(2)]
		return ok
	}, 10*time.Second, 10*time.Millisecond, "runRaft must publish the voter configuration")
	require.NotEqual(t, raft.StateLeader, rc.node.Status().RaftState,
		"node must not be leader: the second voter never started")

	// Flood the follower through the real transport entry point with responses
	// from node IDs that are not in the configuration.
	term := rc.GetTerm()
	const floodCount = 2000
	for i := uint64(100); i < 100+floodCount; i++ {
		require.NoError(t, rc.Process(ctx, newHeartbeatResp(i, rc.nodeID, term)))
		require.NoError(t, rc.Process(ctx, newAppResp(i, rc.nodeID, term)))
	}

	rc.mu.RLock()
	afterFlood := len(rc.peerAcks)
	rc.mu.RUnlock()
	assert.Equal(t, 0, afterFlood,
		"acks from node IDs outside the voter configuration must never occupy a map slot")

	// A response from a real voter is still recorded: the bound must not be
	// achieved by discarding the evidence the lease is built from.
	require.NoError(t, rc.Process(ctx, newHeartbeatResp(2, rc.nodeID, term)))
	rc.mu.RLock()
	_, voterRecorded := rc.peerAcks[2]
	afterVoterAck := len(rc.peerAcks)
	rc.mu.RUnlock()
	assert.True(t, voterRecorded, "an ack from a configured voter must still be recorded")
	assert.Equal(t, 1, afterVoterAck, "peerAcks must hold exactly the one voter ack")

	// Entries that predate a configuration change are pruned on a follower too,
	// not only on the leader path.
	rc.mu.Lock()
	rc.peerAcks[9999] = peerAck{at: time.Now(), term: term}
	rc.mu.Unlock()

	rc.refreshLeaseIfQuorum()

	rc.mu.RLock()
	_, stalePresent := rc.peerAcks[9999]
	_, voterStillPresent := rc.peerAcks[2]
	rc.mu.RUnlock()
	assert.False(t, stalePresent, "a non-voter entry must be pruned on a follower, not only on a leader")
	assert.True(t, voterStillPresent, "pruning must not drop acks from current voters")
}

// newHeartbeatResp builds the follower response a leader receives over the
// transport. Term must match the leader's current term: raft discards a stale
// response, and the lease ignores acks from a superseded term.
func newHeartbeatResp(from, to, term uint64) *raftpb.Message {
	return &raftpb.Message{
		Type: raftpb.MsgHeartbeatResp.Enum(),
		From: new(from),
		To:   new(to),
		Term: new(term),
	}
}

// newAppResp builds the other response type the lease treats as an ack.
func newAppResp(from, to, term uint64) *raftpb.Message {
	return &raftpb.Message{
		Type: raftpb.MsgAppResp.Enum(),
		From: new(from),
		To:   new(to),
		Term: new(term),
	}
}

// TestRaftConsensus_LeaseIgnoresAcksFromSupersededTerm verifies that an ack
// carrying a term other than the leader's current term is not evidence of
// contact under the current term and cannot sustain the lease.
func TestRaftConsensus_LeaseIgnoresAcksFromSupersededTerm(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	nodeInfo := &NodeInfo{ID: "stale-term-ack", State: NodeStateHealthy, Role: NodeRoleFollower}
	peers := []raft.Peer{{ID: 1}}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, newTestClusterCfg(), "", logging.GetLogger())
	require.NoError(t, err)
	defer rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup

	require.Eventually(t, rc.HasLeadership, 10*time.Second, 10*time.Millisecond,
		"single-voter leader must hold the lease on its own ack")

	const peerID = uint64(2)
	require.NoError(t, rc.ProposeAddNode(peerID, &NodeInfo{
		ID: "stale-peer", Address: "127.0.0.1:2223", State: NodeStateHealthy, Role: NodeRoleFollower,
	}))
	require.Eventually(t, func() bool {
		_, ok := rc.node.Status().Config.Voters.IDs()[peerID]
		return ok
	}, 10*time.Second, 10*time.Millisecond, "conf change must add the second voter")

	// Record an ack from a term the leader has moved past. Written straight into
	// peerAcks because raft itself would drop such a message before it reached
	// the tracker — the point is that even a recorded stale ack is not counted.
	rc.mu.Lock()
	rc.leaseLastAck = time.Time{}
	rc.peerAcks[peerID] = peerAck{at: time.Now(), term: rc.node.Status().GetTerm() - 1}
	rc.mu.Unlock()

	rc.refreshLeaseIfQuorum()

	rc.mu.RLock()
	ack := rc.leaseLastAck
	rc.mu.RUnlock()
	assert.True(t, ack.IsZero(), "an ack from a superseded term must not grant the lease")
	assert.False(t, rc.HasLeadership(), "HasLeadership must be false when the only peer ack is stale")
}
