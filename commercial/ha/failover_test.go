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

// TestFailoverManager_electNewLeader_DeferesToRaft verifies that electNewLeader
// no longer calls promoteToLeader/demoteFromLeader but instead defers to Raft.
// After the legacy election removal (Issue #1291), electNewLeader always returns
// nil and logs that Raft is the authority.
func TestFailoverManager_electNewLeader_DeferesToRaft(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = "test-failover-raft-node"

	logger := logging.GetLogger()
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)

	t.Cleanup(func() {
		if manager.raftConsensus != nil {
			_ = manager.raftConsensus.Stop()
		}
	})

	fm, err := NewFailoverManager(cfg.Failover, logger, manager)
	require.NoError(t, err)

	ctx := context.Background()
	// electNewLeader must return nil — Raft is now the election authority.
	err = fm.electNewLeader(ctx)
	assert.NoError(t, err, "electNewLeader must defer to Raft and return nil")
}

// TestFailoverManager_executeFailover_NonClusterMode verifies that in non-cluster
// mode, executeFailover no longer calls promoteToLeader (which has been removed).
func TestFailoverManager_executeFailover_NonClusterMode(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = SingleServerMode

	logger := logging.GetLogger()
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)

	fm, err := NewFailoverManager(cfg.Failover, logger, manager)
	require.NoError(t, err)

	ctx := context.Background()

	// Should not panic (no promoteToLeader call) and should complete without error.
	err = fm.executeFailover(ctx, "test_non_cluster_failover", false)
	assert.NoError(t, err)
}
