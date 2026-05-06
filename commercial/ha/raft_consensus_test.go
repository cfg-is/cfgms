//go:build commercial

// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz
// +build commercial

package ha

import (
	"context"
	"testing"
	"time"

	"go.etcd.io/raft/v3"
	"go.etcd.io/raft/v3/raftpb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestRaftConsensus_propose_logsError(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{
		ID:    "test-node",
		State: NodeStateHealthy,
		Role:  NodeRoleFollower,
	}

	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, mock)
	require.NoError(t, err)

	// Stop the underlying raft node so that Propose returns ErrStopped.
	// The runRaft goroutine continues running (stopC and ctx not closed),
	// so it will read from proposeC, call Propose, get ErrStopped, and log.
	rc.node.Stop()

	// Send a proposal in a goroutine; the runRaft loop will try to Propose
	// on the stopped node, receive ErrStopped, and log the error.
	go func() {
		select {
		case rc.proposeC <- []byte("trigger error"):
		case <-time.After(2 * time.Second):
		}
	}()

	// Poll until the error log appears — no fixed sleep, race-detector safe.
	require.Eventually(t, func() bool {
		for _, entry := range mock.GetLogs("error") {
			if entry.Message == "Failed to propose to Raft" {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "expected 'Failed to propose to Raft' error log")
}

// TestRaftConsensus_ProposeNodeUpdate_AppliedViaRaft verifies that ProposeNodeUpdate
// encodes the command and sends it through proposeC, and that after the Raft loop
// processes the entry, GetClusterNodes returns the updated NodeInfo.
func TestRaftConsensus_ProposeNodeUpdate_AppliedViaRaft(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)

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
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, peers, mock)
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
	mock := pkgtesting.NewMockLogger(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{ID: "node-1", Address: "127.0.0.1:2000"}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, mock)
	require.NoError(t, err)
	// Stop before the deferred Stop — stopOnce makes this safe; both return nil.
	rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup
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
	mock := pkgtesting.NewMockLogger(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{ID: "node-1", Address: "127.0.0.1:3000"}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, mock)
	require.NoError(t, err)
	rc.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup
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
	mock := pkgtesting.NewMockLogger(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{ID: "node-fill", Address: "127.0.0.1:4000"}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, mock)
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
	mock := pkgtesting.NewMockLogger(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{ID: "node-add-fill", Address: "127.0.0.1:5000"}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, mock)
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
	mock := pkgtesting.NewMockLogger(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodeInfo := &NodeInfo{ID: "node-rem-fill", Address: "127.0.0.1:7000"}
	rc, err := NewRaftConsensus(ctx, 1, nodeInfo, nil, mock)
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
