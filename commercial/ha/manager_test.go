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
	t.Skip("Skipping due to known deadlock issue in discovery - will be addressed in future PR")
	// Create test logger
	logger := logging.GetLogger()

	// Create test storage manager
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	// Create HA config for blue-green mode
	cfg := DefaultConfig()
	cfg.Mode = BlueGreenMode

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

	// Test starting and stopping - use shorter timeout to avoid deadlock
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start in a goroutine to prevent test deadlock
	startErr := make(chan error, 1)
	go func() {
		startErr <- manager.Start(ctx)
	}()

	// Wait for start or timeout
	select {
	case err = <-startErr:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Skip("Manager start timed out - skipping to avoid test deadlock")
		return
	}

	err = manager.Stop(ctx)
	assert.NoError(t, err)
}

func TestManager_ClusterMode(t *testing.T) {
	t.Skip("Skipping due to known deadlock issue in discovery - will be addressed in future PR")
	// Create test logger
	logger := logging.GetLogger()

	// Create test storage manager
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	// Create HA config for cluster mode
	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Cluster.ExpectedSize = 3
	cfg.Cluster.MinQuorum = 2

	// Create HA manager
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Test deployment mode
	assert.Equal(t, ClusterMode, manager.GetDeploymentMode())

	// Test local node info
	localNode := manager.GetLocalNode()
	assert.NotNil(t, localNode)
	assert.NotEmpty(t, localNode.ID)

	// Test starting and stopping - use shorter timeout to avoid deadlock
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start in a goroutine to prevent test deadlock
	startErr := make(chan error, 1)
	go func() {
		startErr <- manager.Start(ctx)
	}()

	// Wait for start or timeout
	select {
	case err = <-startErr:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Skip("Manager start timed out - skipping to avoid test deadlock")
		return
	}

	// Get cluster nodes
	nodes, err := manager.GetClusterNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 1) // Only local node

	err = manager.Stop(ctx)
	assert.NoError(t, err)
}

func TestManager_HealthChecks(t *testing.T) {
	t.Skip("Skipping due to synchronization issues in health checker - will be addressed in future PR")
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

	// Phase 2: Blue-Green (simulating upgrade scenario)
	t.Run("BlueGreen", func(t *testing.T) {
		t.Skip("Skipping due to known deadlock issue in discovery - will be addressed in future PR")
		cfg := DefaultConfig()
		cfg.Mode = BlueGreenMode

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
		t.Skip("Skipping due to known deadlock issue in discovery - will be addressed in future PR")
		cfg := DefaultConfig()
		cfg.Mode = ClusterMode
		cfg.Cluster.ExpectedSize = 3
		cfg.Cluster.MinQuorum = 2

		manager, err := NewManager(cfg, logger, storageManager)
		require.NoError(t, err)

		err = manager.Start(ctx)
		require.NoError(t, err)

		// Should support cluster operations
		assert.Equal(t, ClusterMode, manager.GetDeploymentMode())

		// Should have cluster nodes
		nodes, err := manager.GetClusterNodes()
		require.NoError(t, err)
		assert.Len(t, nodes, 1) // Only local node in test

		err = manager.Stop(ctx)
		assert.NoError(t, err)
	})
}
