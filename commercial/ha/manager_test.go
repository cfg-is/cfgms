//go:build commercial

// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz
// +build commercial

package ha

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/testing/storage"
)

// TestManager_ConcreteCollaboratorTypes verifies that Manager stores concrete types
// for the 4 collaborators that had single-impl interfaces eliminated (Issue #1234).
// Before the fix these fields were interface types; the sessionSync field required
// a type-assertion downcast to call Stop(). Now all four are concrete pointer types.
func TestManager_ConcreteCollaboratorTypes(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = "test-node-concrete-types"

	logger := logging.GetLogger()
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)
	require.NotNil(t, manager)

	t.Cleanup(func() {
		if manager.raftConsensus != nil {
			assert.NoError(t, manager.raftConsensus.Stop())
		}
	})

	// All four collaborators must be non-nil concrete pointers after cluster-mode init.
	require.NotNil(t, manager.sessionSync, "sessionSync must be initialized in cluster mode")
	require.NotNil(t, manager.loadBalancer, "loadBalancer must be initialized in cluster mode")
	require.NotNil(t, manager.failover, "failover must be initialized in cluster mode")
	require.NotNil(t, manager.splitBrain, "splitBrain must be initialized in cluster mode")

	// Stop() must be callable directly on the concrete *sessionSynchronizer field
	// without any type-assertion downcast — the primary smell this issue removes.
	ctx := context.Background()
	assert.NoError(t, manager.sessionSync.Stop(ctx))
}

func TestManager_initRaft_logsInitStart(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)

	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = "test-node-init-raft"

	manager, err := NewManager(cfg, mock, storageManager)
	require.NoError(t, err)
	require.NotNil(t, manager)

	t.Cleanup(func() {
		if manager.raftConsensus != nil {
			assert.NoError(t, manager.raftConsensus.Stop())
		}
	})

	debugLogs := mock.GetLogs("debug")
	require.NotEmpty(t, debugLogs, "expected debug logs from raft initialization")

	found := false
	for _, entry := range debugLogs {
		if strings.Contains(entry.Message, "RAFT_INIT") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected a debug log containing RAFT_INIT, got logs: %v", debugLogs)
}

func TestManager_SingleServerMode(t *testing.T) {
	// Create test logger
	logger := logging.GetLogger()

	// Create test storage manager
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	// Create HA config for single server mode
	cfg := DefaultConfig()
	cfg.Mode = SingleServerMode

	// Create HA manager
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Test deployment mode
	assert.Equal(t, SingleServerMode, manager.GetDeploymentMode())

	// Test that single server is always leader
	assert.True(t, manager.IsLeader())

	// Test local node info
	localNode := manager.GetLocalNode()
	assert.NotNil(t, localNode)
	assert.Equal(t, NodeRoleLeader, localNode.Role)
	assert.Equal(t, NodeStateHealthy, localNode.State)

	// Test starting and stopping
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	require.NoError(t, err)

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Test health registration
	manager.RegisterHealthCheck("test", func(ctx context.Context) error {
		return nil
	})

	// Give health check time to run
	time.Sleep(200 * time.Millisecond)

	// Get health status
	health := manager.GetHealth()
	assert.NotNil(t, health)
	assert.Equal(t, NodeStateHealthy, health.Overall)

	err = manager.Stop(ctx)
	assert.NoError(t, err)
}

func TestManager_BlueGreenMode(t *testing.T) {
	// Create test logger
	logger := logging.GetLogger()

	// Create test storage manager
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	// Create HA config for blue-green mode.
	// Node ID is required by Validate() for blue-green mode.
	cfg := DefaultConfig()
	cfg.Mode = BlueGreenMode
	cfg.Node.ID = "test-node-bluegreen"

	// Create HA manager
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Test deployment mode
	assert.Equal(t, BlueGreenMode, manager.GetDeploymentMode())

	// Test local node info
	localNode := manager.GetLocalNode()
	assert.NotNil(t, localNode)
	assert.NotEmpty(t, localNode.ID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	require.NoError(t, err)

	err = manager.Stop(ctx)
	assert.NoError(t, err)
}

func TestManager_ClusterMode(t *testing.T) {
	// Create test logger
	logger := logging.GetLogger()

	// Create test storage manager
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	// Create HA config for cluster mode.
	// Configure self as the only peer so Raft calls StartNode (new cluster) rather
	// than RestartNode (join existing), allowing the node to become leader.
	const nodeID = "test-node-cluster-mode"
	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = nodeID
	cfg.Cluster.ExpectedSize = 1
	cfg.Cluster.MinQuorum = 1
	cfg.Cluster.Discovery.Config = map[string]interface{}{
		"nodes": []interface{}{
			map[string]interface{}{
				"id":      nodeID,
				"address": "127.0.0.1:0",
			},
		},
	}

	// Create HA manager
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Raft consensus must be initialized in cluster mode
	require.NotNil(t, manager.raftConsensus)

	// Manager.Stop() also stops raftConsensus (idempotent via stopOnce).
	// Cleanup is a safety net for early-return paths.
	t.Cleanup(func() {
		assert.NoError(t, manager.raftConsensus.Stop())
	})

	// Test deployment mode
	assert.Equal(t, ClusterMode, manager.GetDeploymentMode())

	// Test local node info
	localNode := manager.GetLocalNode()
	assert.NotNil(t, localNode)
	assert.NotEmpty(t, localNode.ID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	require.NoError(t, err)

	// ProposeNodeUpdate is called during Start(). Because the construction-time seed
	// was removed, GetClusterNodes() returns the local node only after that proposal
	// is committed and applied via the Raft log. If ProposeNodeUpdate is never called,
	// this Eventually will time out and fail, proving the wiring is correct.
	var nodes []*NodeInfo
	require.Eventually(t, func() bool {
		var getErr error
		nodes, getErr = manager.GetClusterNodes()
		return getErr == nil && len(nodes) > 0
	}, 10*time.Second, 25*time.Millisecond,
		"local node must appear in GetClusterNodes via the Raft apply path after ProposeNodeUpdate")

	// IsLeader() must delegate to raftConsensus (not a cached local field)
	raftAnswer := manager.raftConsensus.IsLeader()
	managerAnswer := manager.IsLeader()
	assert.Equal(t, raftAnswer, managerAnswer,
		"Manager.IsLeader() must return the same answer as raftConsensus.IsLeader()")

	err = manager.Stop(ctx)
	assert.NoError(t, err)
}

// TestManager_IsLeader_UsesRaftConsensus verifies that Manager.IsLeader() delegates
// exclusively to raftConsensus in ClusterMode — there is no longer a cached local
// isLeader field that can diverge from the Raft state machine.
func TestManager_IsLeader_UsesRaftConsensus(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	const nodeID = "test-isleader-raft-node"
	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = nodeID
	// Configure self as peer so Raft initializes a new cluster via StartNode.
	cfg.Cluster.Discovery.Config = map[string]interface{}{
		"nodes": []interface{}{
			map[string]interface{}{
				"id":      nodeID,
				"address": "127.0.0.1:0",
			},
		},
	}

	logger := logging.GetLogger()
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)
	require.NotNil(t, manager.raftConsensus, "raftConsensus must be initialized in cluster mode")

	t.Cleanup(func() {
		_ = manager.raftConsensus.Stop()
	})

	// Immediately after construction (before any election), both should agree.
	raftAnswer := manager.raftConsensus.IsLeader()
	managerAnswer := manager.IsLeader()
	assert.Equal(t, raftAnswer, managerAnswer,
		"Manager.IsLeader() must return the Raft consensus answer, not a stale local field")
}

func TestManager_HealthChecks(t *testing.T) {
	t.Skip("Skipping due to synchronization issues in health checker - will be addressed in future PR (#1299)")
	// Create test logger
	logger := logging.GetLogger()

	// Create test storage manager
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	// Create HA manager
	cfg := DefaultConfig()
	cfg.HealthCheck.Interval = 100 * time.Millisecond
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Register test health checks with proper synchronization
	var passingCheckCalled, failingCheckCalled int32

	manager.RegisterHealthCheck("passing", func(ctx context.Context) error {
		atomic.StoreInt32(&passingCheckCalled, 1)
		return nil
	})

	manager.RegisterHealthCheck("failing", func(ctx context.Context) error {
		atomic.StoreInt32(&failingCheckCalled, 1)
		return assert.AnError
	})

	// Start manager
	err = manager.Start(ctx)
	require.NoError(t, err)

	// Wait for health checks to run
	time.Sleep(300 * time.Millisecond)

	// Verify health checks were called
	assert.Equal(t, int32(1), atomic.LoadInt32(&passingCheckCalled))
	assert.Equal(t, int32(1), atomic.LoadInt32(&failingCheckCalled))

	// Get health status
	health := manager.GetHealth()
	assert.NotNil(t, health)

	// Should have both checks
	assert.Contains(t, health.Checks, "passing")
	assert.Contains(t, health.Checks, "failing")

	// Stop manager with longer timeout to avoid deadlock
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	err = manager.Stop(stopCtx)
	assert.NoError(t, err)
}

func TestManager_ConfigValidation(t *testing.T) {
	logger := logging.GetLogger()
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	// Test invalid config
	cfg := &Config{
		Mode: ClusterMode,
		Node: NodeConfig{}, // Invalid - node ID is empty
	}

	_, err = NewManager(cfg, logger, storageManager)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "node ID is required")

	// Test invalid cluster config
	cfg = DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = "test-node-123" // Set valid node ID to test quorum validation
	cfg.Cluster.MinQuorum = 10
	cfg.Cluster.ExpectedSize = 3 // Invalid - quorum > expected size

	_, err = NewManager(cfg, logger, storageManager)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "min quorum must be between 1 and expected size")
}

func TestConfig_LoadFromEnvironment_InvalidQuorum(t *testing.T) {
	logger := logging.GetLogger()
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	t.Setenv("CFGMS_HA_MODE", "cluster")
	t.Setenv("CFGMS_NODE_ID", "test-node")
	t.Setenv("CFGMS_HA_CLUSTER_SIZE", "3")
	t.Setenv("CFGMS_HA_MIN_QUORUM", "5")

	cfg := DefaultConfig()
	require.NoError(t, cfg.LoadFromEnvironment())

	_, err = NewManager(cfg, logger, storageManager)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "quorum")
}

func TestDeploymentModeProgression(t *testing.T) {
	// This test verifies the progressive deployment model works correctly
	logger := logging.GetLogger()
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Phase 1: Single Server
	t.Run("SingleServer", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Mode = SingleServerMode

		manager, err := NewManager(cfg, logger, storageManager)
		require.NoError(t, err)

		err = manager.Start(ctx)
		require.NoError(t, err)

		// Should be leader immediately
		assert.True(t, manager.IsLeader())
		assert.Equal(t, SingleServerMode, manager.GetDeploymentMode())

		err = manager.Stop(ctx)
		assert.NoError(t, err)
	})

	// Phase 2: Blue-Green
	t.Run("BlueGreen", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Mode = BlueGreenMode
		cfg.Node.ID = "test-progression-bluegreen-node"

		manager, err := NewManager(cfg, logger, storageManager)
		require.NoError(t, err)

		err = manager.Start(ctx)
		require.NoError(t, err)

		// Should support blue-green deployment
		assert.Equal(t, BlueGreenMode, manager.GetDeploymentMode())

		err = manager.Stop(ctx)
		assert.NoError(t, err)
	})

	// Phase 3: Full Cluster
	t.Run("Cluster", func(t *testing.T) {
		const nodeID = "test-progression-cluster-node"
		cfg := DefaultConfig()
		cfg.Mode = ClusterMode
		cfg.Node.ID = nodeID
		cfg.Cluster.ExpectedSize = 1
		cfg.Cluster.MinQuorum = 1
		cfg.Cluster.Discovery.Config = map[string]interface{}{
			"nodes": []interface{}{
				map[string]interface{}{
					"id":      nodeID,
					"address": "127.0.0.1:0",
				},
			},
		}

		manager, err := NewManager(cfg, logger, storageManager)
		require.NoError(t, err)

		t.Cleanup(func() {
			if manager.raftConsensus != nil {
				_ = manager.raftConsensus.Stop()
			}
		})

		err = manager.Start(ctx)
		require.NoError(t, err)

		// Should support cluster operations
		assert.Equal(t, ClusterMode, manager.GetDeploymentMode())

		// Wait for ProposeNodeUpdate (sent during Start) to be applied via the Raft log.
		require.Eventually(t, func() bool {
			nodes, getErr := manager.GetClusterNodes()
			return getErr == nil && len(nodes) > 0
		}, 10*time.Second, 25*time.Millisecond, "local node must appear in GetClusterNodes via Raft apply path")

		err = manager.Stop(ctx)
		assert.NoError(t, err)
	})
}
