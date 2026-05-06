//go:build commercial

// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz
// +build commercial

package ha

import (
	"context"
	"testing"

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
			_ = manager.raftConsensus.Stop()
		}
	})

	sbd, err := NewSplitBrainDetector(cfg.SplitBrain, logger, manager)
	require.NoError(t, err)

	status := &SplitBrainStatus{
		Detected: true,
		Details:  make(map[string]interface{}),
	}

	// quorum-based: should return "raft_will_step_down" or "maintaining_quorum"
	// (not "stepped_down_no_quorum" — that old sentinel required demoteFromLeader)
	result := sbd.applyQuorumBasedResolution(status)
	assert.NotEqual(t, "stepped_down_no_quorum", result,
		"quorum-based resolution must not call demoteFromLeader; got %q", result)

	// oldest-leader: should return "raft_manages_step_down" or "not_leader"
	result = sbd.applyOldestLeaderResolution(status)
	assert.NotEqual(t, "stepped_down_not_oldest", result,
		"oldest-leader resolution must not call demoteFromLeader; got %q", result)

	// step-down: should return "raft_manages_step_down" or "not_leader"
	result = sbd.applyStepDownResolution(status)
	assert.NotEqual(t, "stepped_down_split_brain", result,
		"step-down resolution must not call demoteFromLeader; got %q", result)
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
