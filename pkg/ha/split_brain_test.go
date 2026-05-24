// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testing/storage"
)

// TestSplitBrainDetector_ResolutionStrategies_DeferToRaft verifies that all
// three resolution strategies no longer call demoteFromLeader() directly.
// After Issue #1291, step-down is Raft-managed via CheckQuorum:true; each
// strategy returns a "raft_manages_step_down" or "raft_will_step_down" sentinel
// rather than explicitly demoting the leader.
func TestSplitBrainDetector_ResolutionStrategies_DeferToRaft(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = "test-splitbrain-node"

	logger := logging.GetLogger()
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)

	t.Cleanup(func() {
		if manager.raftConsensus != nil {
			assert.NoError(t, manager.raftConsensus.Stop())
		}
	})

	sbd, err := NewSplitBrainDetector(cfg.SplitBrain, logger, manager)
	require.NoError(t, err)

	status := &SplitBrainStatus{
		Detected: true,
		Details:  make(map[string]interface{}),
	}

	// quorum-based: returns "raft_will_step_down" (below quorum) or "maintaining_quorum"
	result := sbd.applyQuorumBasedResolution(status)
	assert.Contains(t, []string{"raft_will_step_down", "maintaining_quorum"}, result,
		"quorum-based resolution must return a Raft-deferred sentinel; got %q", result)

	// oldest-leader: returns "raft_manages_step_down" or "not_leader"
	result = sbd.applyOldestLeaderResolution(status)
	assert.Contains(t, []string{"raft_manages_step_down", "not_leader"}, result,
		"oldest-leader resolution must return a Raft-deferred sentinel; got %q", result)

	// step-down: returns "raft_manages_step_down" or "not_leader"
	result = sbd.applyStepDownResolution(status)
	assert.Contains(t, []string{"raft_manages_step_down", "not_leader"}, result,
		"step-down resolution must return a Raft-deferred sentinel; got %q", result)
}

// TestSplitBrainDetector_CheckSplitBrain_NonCluster verifies that split-brain
// detection correctly reports no split-brain when not in cluster mode.
func TestSplitBrainDetector_CheckSplitBrain_NonCluster(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = SingleServerMode

	logger := logging.GetLogger()
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)

	sbd, err := NewSplitBrainDetector(cfg.SplitBrain, logger, manager)
	require.NoError(t, err)

	ctx := context.Background()
	status, err := sbd.CheckSplitBrain(ctx)
	require.NoError(t, err)
	assert.NotNil(t, status)
	// Single server mode must not report a split-brain condition.
	assert.False(t, status.Detected, "split-brain must not be detected in single-server mode")
}

// TestAnalyzePartitions_Empty verifies that an empty node list returns nil
// (no partitions to group).
func TestAnalyzePartitions_Empty(t *testing.T) {
	var sbd splitBrainDetector
	partitions := sbd.analyzePartitions(nil, func(_, _ string) bool { return true })
	assert.Nil(t, partitions, "empty node list must return nil partitions")
}

// TestAnalyzePartitions_FullyConnected verifies that a 3-node cluster where
// every pair of nodes can reach each other yields a single partition.
func TestAnalyzePartitions_FullyConnected(t *testing.T) {
	nodes := []*NodeInfo{
		{ID: "node-alpha", Role: NodeRoleFollower},
		{ID: "node-beta", Role: NodeRoleFollower},
		{ID: "node-gamma", Role: NodeRoleLeader},
	}

	reachable := func(_, _ string) bool { return true }

	var sbd splitBrainDetector
	partitions := sbd.analyzePartitions(nodes, reachable)

	require.Len(t, partitions, 1, "fully-connected cluster must produce exactly 1 partition")
	assert.Len(t, partitions[0].Nodes, 3, "the single partition must contain all 3 nodes")
	assert.Equal(t, 1, partitions[0].LeaderClaims, "leader count must be 1")
}

// TestAnalyzePartitions_Split_2Plus1 verifies that a 3-node cluster whose
// reachability graph has two connected components yields exactly 2 partitions
// with the correct node distribution.
func TestAnalyzePartitions_Split_2Plus1(t *testing.T) {
	const (
		nodeA = "node-alpha"
		nodeB = "node-beta"
		nodeC = "node-gamma" // isolated node claiming leadership
	)

	nodes := []*NodeInfo{
		{ID: nodeA, Role: NodeRoleFollower},
		{ID: nodeB, Role: NodeRoleFollower},
		{ID: nodeC, Role: NodeRoleLeader},
	}

	// alpha ↔ beta are connected; gamma is unreachable from both
	reachable := func(from, to string) bool {
		return (from == nodeA && to == nodeB) || (from == nodeB && to == nodeA)
	}

	var sbd splitBrainDetector
	partitions := sbd.analyzePartitions(nodes, reachable)

	require.Len(t, partitions, 2, "split 2+1 must produce exactly 2 partitions")

	sizes := make([]int, len(partitions))
	leaderClaims := make([]int, len(partitions))
	for i, p := range partitions {
		sizes[i] = len(p.Nodes)
		leaderClaims[i] = p.LeaderClaims
	}
	assert.ElementsMatch(t, []int{2, 1}, sizes, "partition sizes must be 2 and 1")
	assert.ElementsMatch(t, []int{0, 1}, leaderClaims, "leader claims must be 0 and 1 across partitions")
}

// TestPerformSplitBrainCheck_PartitionDetected verifies that performSplitBrainCheck
// sets Detected=true when a network-isolated partition contains a leader claim
// and meets the MinQuorum threshold.
func TestPerformSplitBrainCheck_PartitionDetected(t *testing.T) {
	const (
		nodeA = "node-alpha"
		nodeB = "node-beta"
		nodeC = "node-gamma" // isolated; claims leadership
	)

	// Minimal Manager constructed directly so raftConsensus is nil and
	// GetClusterNodes falls back to clusterNodes map — no Raft bootstrap needed.
	manager := &Manager{
		cfg: &Config{
			Mode: ClusterMode,
			Cluster: ClusterConfig{
				MinQuorum: 1, // any partition with a leader triggers detection
			},
		},
		clusterNodes: map[string]*NodeInfo{
			nodeA: {ID: nodeA, Role: NodeRoleFollower},
			nodeB: {ID: nodeB, Role: NodeRoleFollower},
			nodeC: {ID: nodeC, Role: NodeRoleLeader},
		},
		logger: logging.GetLogger(),
	}

	// alpha ↔ beta are connected; gamma is unreachable from both
	reachable := func(from, to string) bool {
		return (from == nodeA && to == nodeB) || (from == nodeB && to == nodeA)
	}

	sbd := &splitBrainDetector{
		cfg: &SplitBrainConfig{
			Enabled:           true,
			DetectionInterval: 15 * time.Second,
		},
		logger:  logging.GetLogger(),
		manager: manager,
		currentStatus: &SplitBrainStatus{
			Detected:  false,
			Timestamp: time.Now(),
			Details:   make(map[string]interface{}),
		},
		partitionTrack:   make(map[string]*partitionInfo),
		reachabilityFunc: reachable,
	}

	status := sbd.performSplitBrainCheck()

	require.NotNil(t, status)
	assert.True(t, status.Detected,
		"split-brain must be detected when an isolated partition holds a leader claim")
	assert.Len(t, status.PartitionIDs, 2, "status must report 2 partition IDs")
	assert.Equal(t, "partition_with_quorum", status.Details["condition"],
		"detection condition must be partition_with_quorum")
}
