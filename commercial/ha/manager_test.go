//go:build commercial
// +build commercial

// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	cpgrpc "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	cptypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testing/storage"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
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

	manager, err := NewManager(cfg, logging.GetLogger(), storageManager)
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

// TestManager_HealthChecks_ConcurrentRegistration verifies that calling
// RegisterHealthCheck while the health checker is running does not cause a data
// race on the healthChecks map or a deadlock between the health checker goroutine
// and Manager.Stop. Both were possible before the lock-ordering fix in health.go.
func TestManager_HealthChecks_ConcurrentRegistration(t *testing.T) {
	logger := logging.GetLogger()

	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.HealthCheck.Interval = 5 * time.Millisecond
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	require.NoError(t, err)

	// Register checks concurrently while the health-checker goroutine is running.
	// With the old code this races on healthChecks (read without m.mu in
	// performHealthChecks, write under m.mu in RegisterHealthCheck).
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			manager.RegisterHealthCheck("concurrent-check", func(ctx context.Context) error {
				return nil
			})
		}
	}()

	<-done

	// Verify that at least one performHealthChecks cycle ran while registrations
	// were in flight and picked up the concurrent-check. This confirms the data-race
	// fix actually propagates concurrent registrations to observable health state,
	// not just that the goroutine didn't crash.
	require.Eventually(t, func() bool {
		h := manager.GetHealth()
		_, exists := h.Checks["concurrent-check"]
		return exists
	}, 3*time.Second, 25*time.Millisecond, "concurrent-check must appear in health status")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	// Stop must not deadlock. The old code deadlocked when Manager.Stop held m.mu
	// and called h.Stop (needing h.mu) while the health goroutine held h.mu and
	// waited for m.mu.
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

// TestManager_GetCACertPEM_EmptyPath verifies that GetCACertPEM returns nil when
// CACertPath is empty — no CA is available and no error is surfaced to the caller.
func TestManager_GetCACertPEM_EmptyPath(t *testing.T) {
	logger := logging.GetLogger()
	sm, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = SingleServerMode
	// CACertPath intentionally left empty

	manager, err := NewManager(cfg, logger, sm)
	require.NoError(t, err)

	got := manager.GetCACertPEM()
	assert.Nil(t, got, "GetCACertPEM must return nil when CACertPath is empty")
}

// TestManager_GetCACertPEM_ValidPath verifies that GetCACertPEM returns the file
// bytes when CACertPath points to a readable file.
func TestManager_GetCACertPEM_ValidPath(t *testing.T) {
	logger := logging.GetLogger()
	sm, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	// Write a dummy CA cert PEM to a temp file.
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.pem")
	want := []byte("-----BEGIN CERTIFICATE-----\ndummy-ca-pem\n-----END CERTIFICATE-----\n")
	require.NoError(t, os.WriteFile(caPath, want, 0600))

	cfg := DefaultConfig()
	cfg.Mode = SingleServerMode
	cfg.CACertPath = caPath

	manager, err := NewManager(cfg, logger, sm)
	require.NoError(t, err)

	got := manager.GetCACertPEM()
	require.NotNil(t, got, "GetCACertPEM must return bytes when CACertPath is readable")
	assert.Equal(t, want, got, "GetCACertPEM must return exactly the file contents")
}

// TestManager_GetCACertPEM_InvalidPath verifies that GetCACertPEM returns nil (not an error)
// when CACertPath points to a non-existent file — callers get a safe nil, not a panic or error.
func TestManager_GetCACertPEM_InvalidPath(t *testing.T) {
	logger := logging.GetLogger()
	sm, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = SingleServerMode
	cfg.CACertPath = "/nonexistent/path/ca.pem"

	manager, err := NewManager(cfg, logger, sm)
	require.NoError(t, err)

	got := manager.GetCACertPEM()
	assert.Nil(t, got, "GetCACertPEM must return nil when file is unreadable")
}

// TestManager_GetCACertPEM_Concurrent verifies that GetCACertPEM is safe to call
// from multiple goroutines simultaneously (no data race on m.cfg.CACertPath).
func TestManager_GetCACertPEM_Concurrent(t *testing.T) {
	logger := logging.GetLogger()
	sm, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte("dummy-cert"), 0600))

	cfg := DefaultConfig()
	cfg.Mode = SingleServerMode
	cfg.CACertPath = caPath

	manager, err := NewManager(cfg, logger, sm)
	require.NoError(t, err)

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				pem := manager.GetCACertPEM()
				assert.NotNil(t, pem)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

// noopSender is a minimal registry.MessageSender for tests that only need a non-nil sender.
type noopSender struct{}

func (noopSender) SendMsg(_ interface{}) error { return nil }

// TestManager_SessionHooks verifies that after Manager.Start() with a real
// registry.InMemoryRegistry, firing an OnConnect event via registry.Register
// propagates through the Raft log so raftConsensus.clusterState.Sessions reflects the
// connected steward (no mocks — real Raft apply path).
func TestManager_SessionHooks(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	const nodeID = "session-hooks-node"
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

	logger := logging.GetLogger()
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)
	require.NotNil(t, manager.raftConsensus)

	t.Cleanup(func() {
		assert.NoError(t, manager.raftConsensus.Stop())
	})

	reg := registry.NewRegistry()
	manager.SetRegistry(reg)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	require.NoError(t, manager.Start(ctx))
	t.Cleanup(func() {
		assert.NoError(t, manager.Stop(ctx))
	})

	// Wait for Raft to elect a leader before firing the connect event.
	require.Eventually(t, func() bool {
		return manager.raftConsensus.IsLeader()
	}, 10*time.Second, 50*time.Millisecond, "single-node cluster must elect itself leader")

	// Fire an OnConnect event by registering a steward connection.
	conn := &registry.StewardConnection{
		StewardID: "steward-test",
		Sender:    noopSender{},
	}
	require.NoError(t, reg.Register(conn))

	// The hook fires in a goroutine; wait for the Raft apply path to complete.
	require.Eventually(t, func() bool {
		manager.raftConsensus.clusterState.mu.RLock()
		cmd, ok := manager.raftConsensus.clusterState.Sessions["steward-test"]
		manager.raftConsensus.clusterState.mu.RUnlock()
		return ok && cmd.Connected
	}, 5*time.Second, 25*time.Millisecond,
		"OnConnect hook must propagate through Raft log so clusterState.Sessions[steward-test].Connected == true")
}

// TestManager_SessionDisconnectHook verifies that the OnDisconnect hook wired in
// Manager.Start() propagates through the Raft log and removes the session entry from
// clusterState.Sessions (real Raft apply path — no mocks).
func TestManager_SessionDisconnectHook(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	const nodeID = "session-disconnect-hooks-node"
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

	logger := logging.GetLogger()
	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)
	require.NotNil(t, manager.raftConsensus)

	t.Cleanup(func() {
		assert.NoError(t, manager.raftConsensus.Stop())
	})

	reg := registry.NewRegistry()
	manager.SetRegistry(reg)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	require.NoError(t, manager.Start(ctx))
	t.Cleanup(func() {
		assert.NoError(t, manager.Stop(ctx))
	})

	require.Eventually(t, func() bool {
		return manager.raftConsensus.IsLeader()
	}, 10*time.Second, 50*time.Millisecond, "single-node cluster must elect itself leader")

	// Connect first so there is an entry to disconnect.
	conn := &registry.StewardConnection{
		StewardID: "steward-disconnect",
		Sender:    noopSender{},
	}
	require.NoError(t, reg.Register(conn))
	require.Eventually(t, func() bool {
		manager.raftConsensus.clusterState.mu.RLock()
		_, ok := manager.raftConsensus.clusterState.Sessions["steward-disconnect"]
		manager.raftConsensus.clusterState.mu.RUnlock()
		return ok
	}, 5*time.Second, 25*time.Millisecond, "connect must be applied before disconnect is triggered")

	// Trigger the OnDisconnect hook via registry.Unregister.
	reg.Unregister("steward-disconnect")

	require.Eventually(t, func() bool {
		manager.raftConsensus.clusterState.mu.RLock()
		_, ok := manager.raftConsensus.clusterState.Sessions["steward-disconnect"]
		manager.raftConsensus.clusterState.mu.RUnlock()
		return !ok
	}, 5*time.Second, 25*time.Millisecond,
		"OnDisconnect hook must propagate through Raft log and delete clusterState.Sessions[steward-disconnect]")
}

// haTestCA holds a CA and its PEM for building TLS configs in HA manager tests.
type haTestCA struct {
	ca    *cfgcert.CA
	caPEM []byte
}

func newHATestCA(t *testing.T) *haTestCA {
	t.Helper()
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS HA Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	return &haTestCA{ca: ca, caPEM: caPEM}
}

func (tc *haTestCA) serverTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	cert, err := tc.ca.GenerateServerCertificate(&cfgcert.ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	cfg, err := cfgcert.CreateServerTLSConfig(
		cert.CertificatePEM, cert.PrivateKeyPEM, tc.caPEM, tls.VersionTLS13,
	)
	require.NoError(t, err)
	cfg.NextProtos = []string{quictransport.ALPNProtocol}
	return cfg
}

func (tc *haTestCA) clientTLSConfig(t *testing.T, stewardID string) *tls.Config {
	t.Helper()
	cert, err := tc.ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   stewardID,
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	cfg, err := cfgcert.CreateClientTLSConfig(
		cert.CertificatePEM, cert.PrivateKeyPEM, tc.caPEM, "localhost", tls.VersionTLS13,
	)
	require.NoError(t, err)
	cfg.NextProtos = []string{quictransport.ALPNProtocol}
	return cfg
}

// TestManager_BecomeLeader_OrphanedSessions verifies that when handleBecomeLeader
// is called for a departed node, every steward whose session was registered to that
// node receives a CommandReconnect via a real gRPC controlPlaneProvider (no mocks).
func TestManager_BecomeLeader_OrphanedSessions(t *testing.T) {
	sm, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	// Build a Manager in single-server mode (no Raft) — we call handleBecomeLeader
	// directly, so we only need Manager's dispatch wiring, not leader election.
	cfg := DefaultConfig()
	cfg.Mode = SingleServerMode

	logger := logging.GetLogger()
	manager, err := NewManager(cfg, logger, sm)
	require.NoError(t, err)

	// Manually attach a RaftConsensus so GetSessionsForNode is available.
	// We create a minimal single-node Raft consensus just for state inspection.
	const nodeID = "test-become-leader-node"
	raftCfg := DefaultConfig()
	raftCfg.Mode = ClusterMode
	raftCfg.Node.ID = nodeID
	raftCfg.Cluster.HeartbeatInterval = 100 * time.Millisecond
	raftCfg.Cluster.ElectionTimeout = 1 * time.Second
	raftCfg.Cluster.ExpectedSize = 1
	raftCfg.Cluster.MinQuorum = 1
	raftCfg.Cluster.Discovery.Config = map[string]interface{}{
		"nodes": []interface{}{
			map[string]interface{}{"id": nodeID, "address": "127.0.0.1:0"},
		},
	}
	rc, err := NewRaftConsensus(
		context.Background(),
		hashStringToUint64(nodeID),
		&NodeInfo{ID: nodeID},
		nil,
		&raftCfg.Cluster,
		logger,
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rc.Stop() })
	manager.raftConsensus = rc

	// Populate Sessions with two stewards on "node-departed".
	const departedNodeID = "node-departed"
	rc.clusterState.mu.Lock()
	rc.clusterState.Sessions["steward-alpha"] = SessionUpdateCommand{
		StewardID: "steward-alpha",
		NodeID:    departedNodeID,
		Connected: true,
	}
	rc.clusterState.Sessions["steward-beta"] = SessionUpdateCommand{
		StewardID: "steward-beta",
		NodeID:    departedNodeID,
		Connected: true,
	}
	rc.clusterState.mu.Unlock()

	// Start a real gRPC server (controlPlaneProvider in server mode).
	tc := newHATestCA(t)
	reg := registry.NewRegistry()

	cp := cpgrpc.New(cpgrpc.ModeServer)
	require.NoError(t, cp.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, cp.Start(context.Background()))
	t.Cleanup(cp.ForceStop)

	listenAddr := cp.ListenAddr()

	// Connect two real steward clients.
	alphaReceived := make(chan *cptypes.SignedCommand, 1)
	betaReceived := make(chan *cptypes.SignedCommand, 1)

	for _, tc2 := range []struct {
		id string
		ch chan *cptypes.SignedCommand
	}{
		{"steward-alpha", alphaReceived},
		{"steward-beta", betaReceived},
	} {
		client := cpgrpc.New(cpgrpc.ModeClient)
		require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
			"mode":       "client",
			"addr":       listenAddr,
			"tls_config": tc.clientTLSConfig(t, tc2.id),
			"steward_id": tc2.id,
		}))
		require.NoError(t, client.Start(context.Background()))
		id := tc2.id
		ch := tc2.ch
		require.NoError(t, client.SubscribeCommands(context.Background(), id, func(_ context.Context, sc *cptypes.SignedCommand) error {
			select {
			case ch <- sc:
			default:
			}
			return nil
		}))
		t.Cleanup(func() { _ = client.Stop(context.Background()) })
	}

	// Wait for both stewards to appear in the registry.
	require.Eventually(t, func() bool {
		return reg.Count() == 2
	}, 10*time.Second, 25*time.Millisecond, "both stewards must connect before handleBecomeLeader")

	// Wire the control plane provider and call handleBecomeLeader.
	manager.SetControlPlaneProvider(cp)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	manager.handleBecomeLeader(ctx, departedNodeID)

	// Both stewards must receive a CommandReconnect.
	for _, pair := range []struct {
		id string
		ch chan *cptypes.SignedCommand
	}{
		{"steward-alpha", alphaReceived},
		{"steward-beta", betaReceived},
	} {
		select {
		case got := <-pair.ch:
			assert.Equal(t, cptypes.CommandReconnect, got.Command.Type,
				"steward %s must receive CommandReconnect", pair.id)
			assert.Equal(t, pair.id, got.Command.StewardID,
				"CommandReconnect must be addressed to %s", pair.id)
		case <-time.After(5 * time.Second):
			t.Fatalf("steward %s did not receive CommandReconnect within 5s", pair.id)
		}
	}
}

// TestRaftConsensus_GetSessionsForNode verifies that GetSessionsForNode returns
// only steward IDs whose Connected SessionUpdateCommand.NodeID matches the query.
func TestRaftConsensus_GetSessionsForNode(t *testing.T) {
	const nodeA = "node-a"
	const nodeB = "node-b"

	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = nodeA
	cfg.Cluster.HeartbeatInterval = 100 * time.Millisecond
	cfg.Cluster.ElectionTimeout = 1 * time.Second
	cfg.Cluster.ExpectedSize = 1
	cfg.Cluster.MinQuorum = 1

	logger := logging.GetLogger()
	rc, err := NewRaftConsensus(
		context.Background(),
		hashStringToUint64(nodeA),
		&NodeInfo{ID: nodeA},
		nil,
		&cfg.Cluster,
		logger,
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rc.Stop() })

	// Populate Sessions: two on nodeA (one connected, one disconnected), one on nodeB.
	rc.clusterState.mu.Lock()
	rc.clusterState.Sessions["steward-1"] = SessionUpdateCommand{StewardID: "steward-1", NodeID: nodeA, Connected: true}
	rc.clusterState.Sessions["steward-2"] = SessionUpdateCommand{StewardID: "steward-2", NodeID: nodeA, Connected: false}
	rc.clusterState.Sessions["steward-3"] = SessionUpdateCommand{StewardID: "steward-3", NodeID: nodeB, Connected: true}
	rc.clusterState.mu.Unlock()

	got := rc.GetSessionsForNode(nodeA)
	require.Len(t, got, 1, "only connected sessions on nodeA should be returned")
	assert.Equal(t, "steward-1", got[0])

	got = rc.GetSessionsForNode(nodeB)
	require.Len(t, got, 1)
	assert.Equal(t, "steward-3", got[0])

	got = rc.GetSessionsForNode("node-unknown")
	assert.Empty(t, got)
}

// TestManager_Start_WiresOnBecomeLeaderCallback verifies that Manager.Start() sets
// rc.onBecomeLeader on the embedded RaftConsensus so that leadership transitions
// automatically trigger handleBecomeLeader (Issue #1327).
// The test calls the callback directly rather than waiting for a real Raft election,
// which keeps it fast and deterministic while still exercising the wiring path.
func TestManager_Start_WiresOnBecomeLeaderCallback(t *testing.T) {
	sm, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	const nodeID = "test-wiring-node"
	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = nodeID
	cfg.Cluster.HeartbeatInterval = 100 * time.Millisecond
	cfg.Cluster.ElectionTimeout = 1 * time.Second
	cfg.Cluster.ExpectedSize = 1
	cfg.Cluster.MinQuorum = 1
	cfg.Cluster.Discovery.Config = map[string]interface{}{
		"nodes": []interface{}{
			map[string]interface{}{"id": nodeID, "address": "127.0.0.1:0"},
		},
	}

	logger := logging.GetLogger()
	manager, err := NewManager(cfg, logger, sm)
	require.NoError(t, err)
	require.NotNil(t, manager.raftConsensus)
	t.Cleanup(func() { _ = manager.raftConsensus.Stop() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, manager.Start(ctx))
	t.Cleanup(func() { _ = manager.Stop(ctx) })

	// After Start(), rc.onBecomeLeader must be non-nil — the callback is how
	// the Raft layer triggers failover reconnection.
	manager.raftConsensus.mu.RLock()
	cb := manager.raftConsensus.onBecomeLeader
	manager.raftConsensus.mu.RUnlock()
	require.NotNil(t, cb, "rc.onBecomeLeader must be set by Manager.Start()")

	// Wire a real control-plane provider and a RaftConsensus with a session so
	// the dispatch path can be exercised via the wired callback.
	tc := newHATestCA(t)
	reg := registry.NewRegistry()

	cp := cpgrpc.New(cpgrpc.ModeServer)
	require.NoError(t, cp.Initialize(ctx, map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": tc.serverTLSConfig(t),
		"registry":   reg,
	}))
	require.NoError(t, cp.Start(ctx))
	t.Cleanup(cp.ForceStop)

	// Connect one steward client so SendCommand has a live recipient.
	const stewardID = "wiring-steward"
	received := make(chan *cptypes.SignedCommand, 1)
	client := cpgrpc.New(cpgrpc.ModeClient)
	require.NoError(t, client.Initialize(ctx, map[string]interface{}{
		"mode":       "client",
		"addr":       cp.ListenAddr(),
		"tls_config": tc.clientTLSConfig(t, stewardID),
		"steward_id": stewardID,
	}))
	require.NoError(t, client.Start(ctx))
	require.NoError(t, client.SubscribeCommands(ctx, stewardID, func(_ context.Context, sc *cptypes.SignedCommand) error {
		select {
		case received <- sc:
		default:
		}
		return nil
	}))
	t.Cleanup(func() { _ = client.Stop(ctx) })

	require.Eventually(t, func() bool { return reg.Count() == 1 },
		5*time.Second, 25*time.Millisecond, "steward must connect before invoking callback")

	// Populate a session entry so GetSessionsForNode returns the steward.
	const departedNodeID = "departed-node"
	manager.raftConsensus.clusterState.mu.Lock()
	manager.raftConsensus.clusterState.Sessions[stewardID] = SessionUpdateCommand{
		StewardID: stewardID,
		NodeID:    departedNodeID,
		Connected: true,
	}
	manager.raftConsensus.clusterState.mu.Unlock()

	// Wire the provider and invoke the callback through the wired path.
	manager.SetControlPlaneProvider(cp)
	cb(ctx, departedNodeID)

	select {
	case got := <-received:
		assert.Equal(t, cptypes.CommandReconnect, got.Command.Type,
			"steward must receive CommandReconnect via the wired onBecomeLeader callback")
		assert.Equal(t, stewardID, got.Command.StewardID)
	case <-time.After(5 * time.Second):
		t.Fatal("steward did not receive CommandReconnect within 5s via wired callback")
	}
}
