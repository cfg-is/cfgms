//go:build commercial
// +build commercial

// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testing/storage"
)

// TestManager_ConcreteCollaboratorTypes verifies that Manager stores concrete types
// for the 2 collaborators that had single-impl interfaces eliminated (Issue #1234).
// Before the fix these fields were interface types. Now both are concrete pointer types.
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

	// Both remaining collaborators must be non-nil concrete pointers after cluster-mode init.
	require.NotNil(t, manager.failover, "failover must be initialized in cluster mode")
	require.NotNil(t, manager.splitBrain, "splitBrain must be initialized in cluster mode")
}

func TestManager_initRaft_logsInitStart(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = "test-node-init-raft"

	logger := logging.GetLogger()
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)
	require.NotNil(t, manager)

	t.Cleanup(func() {
		if manager.raftConsensus != nil {
			assert.NoError(t, manager.raftConsensus.Stop())
		}
	})

	// Verify raftConsensus was initialized with the correct node ID derived from config.
	// The fnv hash of the config node ID string becomes the Raft uint64 peer ID.
	require.NotNil(t, manager.raftConsensus, "raftConsensus must be non-nil after cluster mode init")
	expectedID := hashStringToUint64(cfg.Node.ID)
	assert.Equal(t, expectedID, manager.raftConsensus.nodeID,
		"raftConsensus nodeID must be the fnv hash of the config node ID string")
}

func TestManager_SingleServerMode(t *testing.T) {
	logger := logging.GetLogger()

	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = SingleServerMode
	cfg.HealthCheck.Interval = 100 * time.Millisecond

	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)
	require.NotNil(t, manager)

	assert.Equal(t, SingleServerMode, manager.GetDeploymentMode())
	assert.True(t, manager.IsLeader())

	localNode := manager.GetLocalNode()
	assert.NotNil(t, localNode)
	assert.Equal(t, NodeRoleLeader, localNode.Role)
	assert.Equal(t, NodeStateHealthy, localNode.State)

	// Register check BEFORE Start to avoid concurrent map access.
	var checkCalled int32
	manager.RegisterHealthCheck("test", func(ctx context.Context) error {
		atomic.StoreInt32(&checkCalled, 1)
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	require.NoError(t, err)

	// Wait for health check to appear in the status map.
	require.Eventually(t, func() bool {
		h := manager.GetHealth()
		_, exists := h.Checks["test"]
		return exists
	}, 3*time.Second, 25*time.Millisecond, "test health check must appear in health status")

	assert.Equal(t, int32(1), atomic.LoadInt32(&checkCalled))

	health := manager.GetHealth()
	assert.NotNil(t, health)
	assert.Equal(t, NodeStateHealthy, health.Overall)
	assert.Contains(t, health.Checks, "test")

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
	// Use fast timing so elections complete well within the 10-second Eventually window.
	const nodeID = "test-node-cluster-mode"
	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = nodeID
	cfg.Cluster.HeartbeatInterval = 100 * time.Millisecond
	cfg.Cluster.ElectionTimeout = 1 * time.Second
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
	cfg.Cluster.HeartbeatInterval = 100 * time.Millisecond
	cfg.Cluster.ElectionTimeout = 1 * time.Second
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
		assert.NoError(t, manager.raftConsensus.Stop())
	})

	// Immediately after construction (before any election), both should agree.
	raftAnswer := manager.raftConsensus.IsLeader()
	managerAnswer := manager.IsLeader()
	assert.Equal(t, raftAnswer, managerAnswer,
		"Manager.IsLeader() must return the Raft consensus answer, not a stale local field")
}

func TestManager_HealthChecks(t *testing.T) {
	logger := logging.GetLogger()

	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.HealthCheck.Interval = 100 * time.Millisecond
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)

	var passingCheckCalled, failingCheckCalled int32

	// Register checks BEFORE Start so they are included in initializeCheckStates
	// and there is no concurrent map access between registration and first tick.
	manager.RegisterHealthCheck("passing", func(ctx context.Context) error {
		atomic.StoreInt32(&passingCheckCalled, 1)
		return nil
	})

	manager.RegisterHealthCheck("failing", func(ctx context.Context) error {
		atomic.StoreInt32(&failingCheckCalled, 1)
		return assert.AnError
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	require.NoError(t, err)

	// Poll health.Checks (the authoritative observable state) rather than the atomics:
	// the atomics are set inside performSingleHealthCheck but healthStatus is updated
	// after all checks complete, so checking atomics first races against the status update.
	require.Eventually(t, func() bool {
		h := manager.GetHealth()
		_, hasP := h.Checks["passing"]
		_, hasF := h.Checks["failing"]
		return hasP && hasF
	}, 3*time.Second, 25*time.Millisecond, "both health checks must appear in health status")

	// Once health.Checks is populated, the check functions have definitely been called.
	assert.Equal(t, int32(1), atomic.LoadInt32(&passingCheckCalled))
	assert.Equal(t, int32(1), atomic.LoadInt32(&failingCheckCalled))

	health := manager.GetHealth()
	assert.NotNil(t, health)
	assert.Contains(t, health.Checks, "passing")
	assert.Contains(t, health.Checks, "failing")

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

// TestHashStringToUint64_DistinguishesKnownPolynomialColliders verifies that the
// fnv-based hash distinguishes "Aa" and "BB", which are known colliders under the
// old polynomial hash (both produce 2112: 65*31+97 == 66*31+66).
func TestHashStringToUint64_DistinguishesKnownPolynomialColliders(t *testing.T) {
	h1 := hashStringToUint64("Aa")
	h2 := hashStringToUint64("BB")
	assert.NotEqual(t, h1, h2,
		"fnv hash must distinguish strings that collide under the old polynomial hash")
}

// TestManager_InitRaftConsensus_DuplicateNodeIDReturnsError verifies that
// initializeRaftConsensus returns a non-nil error when two configured peer nodes
// produce the same uint64 hash — surfacing misconfiguration before any silent aliasing.
func TestManager_InitRaftConsensus_DuplicateNodeIDReturnsError(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = "collision-self-node"
	cfg.Cluster.ExpectedSize = 1
	cfg.Cluster.MinQuorum = 1
	// Two peers with identical ID strings: same string → same hash → collision detected.
	cfg.Cluster.Discovery.Config = map[string]interface{}{
		"nodes": []interface{}{
			map[string]interface{}{"id": "duplicate-peer-id", "address": "127.0.0.1:9001"},
			map[string]interface{}{"id": "duplicate-peer-id", "address": "127.0.0.1:9002"},
		},
	}

	logger := logging.GetLogger()
	_, err = NewManager(cfg, logger, storageManager)
	require.Error(t, err, "NewManager must return an error when two peer IDs produce the same hash")
	assert.Contains(t, err.Error(), "collision",
		"error message must mention collision so operators understand the misconfiguration")
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
		// Fast timing so elections complete well within the 10-second Eventually window.
		cfg.Cluster.HeartbeatInterval = 100 * time.Millisecond
		cfg.Cluster.ElectionTimeout = 1 * time.Second
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
				assert.NoError(t, manager.raftConsensus.Stop())
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
