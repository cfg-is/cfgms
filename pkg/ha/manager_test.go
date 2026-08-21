// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"

	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	cpgrpc "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	cptypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testing/storage"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// newTestCertManager creates a real cert.Manager backed by a temp dir for use in
// cluster mode tests that require a cert provider for mTLS peer transport.
func newTestCertManager(t *testing.T) *cfgcert.Manager {
	t.Helper()
	mgr, err := cfgcert.NewManager(&cfgcert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &cfgcert.CAConfig{
			Organization: "CFGMS Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)
	return mgr
}

// TestNewManager_ClusterMode_NilCertManager_Fails verifies that constructing an
// ha.Manager in ClusterMode without a cert provider returns a descriptive error
// rather than silently creating a transport that sends uncertified requests (which
// would result in silent 403 rejections from every peer's verifyPeerCN check).
func TestNewManager_ClusterMode_NilCertManager_Fails(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = "test-node-no-cert"
	cfg.Cluster.ExpectedSize = 1
	cfg.Cluster.MinQuorum = 1
	cfg.Cluster.Discovery.Config = map[string]interface{}{
		"nodes": []interface{}{
			map[string]interface{}{"id": "test-node-no-cert", "address": "127.0.0.1:0"},
		},
	}

	_, err = NewManager(cfg, logging.GetLogger(), storageManager, nil, "")
	require.Error(t, err, "cluster mode without cert manager must fail at construction")
	assert.Contains(t, err.Error(), "cert manager",
		"error must mention cert manager so operators know what is missing")
}

// TestNewManager_SingleServerMode_NilCertManager_OK verifies that constructing an
// ha.Manager in SingleServerMode with a nil cert provider succeeds — single-server
// mode never creates a peer transport, so no cert is needed.
func TestNewManager_SingleServerMode_NilCertManager_OK(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = SingleServerMode

	manager, err := NewManager(cfg, logging.GetLogger(), storageManager, nil, "")
	require.NoError(t, err, "single-server mode with nil cert manager must succeed")
	require.NotNil(t, manager)
}

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
	manager, err := NewManager(cfg, logger, storageManager, newTestCertManager(t), "")
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

	manager, err := NewManager(cfg, logging.GetLogger(), storageManager, newTestCertManager(t), "")
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

	manager, err := NewManager(cfg, logger, storageManager, nil, "")
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
	manager, err := NewManager(cfg, logger, storageManager, nil, "")
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
	manager, err := NewManager(cfg, logger, storageManager, newTestCertManager(t), "")
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

// TestManager_GetLeader_SurvivesUint64PrecisionThroughRaftLog guards against a
// regression found live during #3130: RaftCommand.Data was typed interface{},
// so applyCommand's json.Unmarshal(data, &cmd) decoded the nested node_update
// payload as map[string]interface{} — and encoding/json always decodes JSON
// numbers in an interface{} position as float64, which only has 53 bits of
// integer precision. The 64-bit FNV node-ID hashes used throughout this
// package (~10^18 magnitude) silently lost precision through that round-trip:
// ProposeNodeUpdate proposed the correct rc.nodeID, but by the time
// applyNodeUpdate re-marshaled the already-float64-rounded map back to JSON
// and unmarshaled it into the typed uint64 field, the key stored in
// clusterState.Nodes no longer matched clusterState.Leader (itself set
// directly from the raft library's uint64 SoftState.Lead, never touched by
// this bug) — so GetLeaderInfo()'s clusterState.Nodes[leaderID] lookup always
// missed, returning "leader node info not found" despite a genuinely healthy,
// agreed-upon Raft leader. Fixed by typing RaftCommand.Data as
// json.RawMessage, which defers decoding until the typed unmarshal and never
// passes through float64. This test proves GetLeader() succeeds once a
// single-node cluster elects itself leader (reproduced the failure
// deterministically pre-fix — not a timing flake).
func TestManager_GetLeader_SurvivesUint64PrecisionThroughRaftLog(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	const nodeID = "test-node-leader-precision"
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

	manager, err := NewManager(cfg, logging.GetLogger(), storageManager, newTestCertManager(t), "")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, manager.raftConsensus.Stop()) })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, manager.Start(ctx))

	require.Eventually(t, func() bool {
		nodes, getErr := manager.GetClusterNodes()
		return getErr == nil && len(nodes) > 0
	}, 10*time.Second, 25*time.Millisecond, "nodes must populate via the Raft apply path")

	require.Eventually(t, func() bool {
		leader, getErr := manager.GetLeader()
		return getErr == nil && leader != nil && leader.ID == nodeID
	}, 5*time.Second, 25*time.Millisecond,
		"GetLeader() must resolve the elected leader's NodeInfo — a uint64 precision"+
			" mismatch between clusterState.Leader and clusterState.Nodes' keys breaks this")

	require.NoError(t, manager.Stop(context.Background()))
}

// TestManager_Start_SurvivesCallerContextCancelledAfterReturn guards against a
// regression found live during #3130: server.go's Start() calls
// `ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second);
// defer cancel(); haManager.Start(ctx)` — a pattern that cancels ctx almost
// immediately (on the enclosing function's return), not after the 30s bound.
// Manager.Start() used to derive its internal m.ctx directly from that
// parameter, so every long-lived background component (the node-info
// replication goroutine, health checker, failover, split-brain detection)
// was killed within milliseconds of Start() returning — long before
// cluster-mode leader election (which takes 10s+ under real, non-test
// timings) could ever complete. GET /api/v1/ha/cluster consequently always
// returned an empty node list despite a genuinely healthy Raft quorum. This
// test reproduces the exact caller pattern (cancel the passed context
// immediately after Start() returns, not at test teardown) and proves the
// background node-info replication still completes.
func TestManager_Start_SurvivesCallerContextCancelledAfterReturn(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	const nodeID = "test-node-ctx-survives-cancel"
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

	manager, err := NewManager(cfg, logging.GetLogger(), storageManager, newTestCertManager(t), "")
	require.NoError(t, err)
	require.NotNil(t, manager)

	t.Cleanup(func() {
		assert.NoError(t, manager.raftConsensus.Stop())
	})

	// Reproduce server.go's exact pattern: a short-lived context whose cancel
	// fires on this function's return, not tied to the Manager's lifetime.
	func() {
		startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		startErr := manager.Start(startCtx)
		require.NoError(t, startErr)
	}()
	// startCtx is now cancelled — m.ctx must NOT be, or every background
	// component died before this point.

	var nodes []*NodeInfo
	require.Eventually(t, func() bool {
		var getErr error
		nodes, getErr = manager.GetClusterNodes()
		return getErr == nil && len(nodes) > 0
	}, 10*time.Second, 25*time.Millisecond,
		"node-info replication must complete even after the caller's Start(ctx) context is cancelled")

	require.NoError(t, manager.Stop(context.Background()))
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
	manager, err := NewManager(cfg, logger, storageManager, newTestCertManager(t), "")
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
	manager, err := NewManager(cfg, logger, storageManager, nil, "")
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
	manager, err := NewManager(cfg, logger, storageManager, nil, "")
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

	_, err = NewManager(cfg, logger, storageManager, nil, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "node ID is required")

	// Test invalid cluster config
	cfg = DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = "test-node-123" // Set valid node ID to test quorum validation
	cfg.Cluster.MinQuorum = 10
	cfg.Cluster.ExpectedSize = 3 // Invalid - quorum > expected size

	_, err = NewManager(cfg, logger, storageManager, nil, "")
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

	_, err = NewManager(cfg, logger, storageManager, nil, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "quorum")
}

// TestModeFromString verifies all valid mode strings (case-insensitive) and the
// error path for unrecognised values.
func TestModeFromString(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  DeploymentMode
		isErr bool
	}{
		{"single", SingleServerMode, false},
		{"Single", SingleServerMode, false},
		{"SINGLE", SingleServerMode, false},
		{"blue-green", BlueGreenMode, false},
		{"Blue-Green", BlueGreenMode, false},
		{"cluster", ClusterMode, false},
		{"CLUSTER", ClusterMode, false},
		{"", SingleServerMode, true},
		{"clustr", SingleServerMode, true},
		{"Cluster!", SingleServerMode, true},
	} {
		got, err := ModeFromString(tc.input)
		if tc.isErr {
			require.Error(t, err, "ModeFromString(%q) should return error", tc.input)
			assert.Equal(t, SingleServerMode, got, "error path must return SingleServerMode")
		} else {
			require.NoError(t, err, "ModeFromString(%q) must not error", tc.input)
			assert.Equal(t, tc.want, got, "ModeFromString(%q) wrong mode", tc.input)
		}
	}
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
	// nil certManager is acceptable here: the collision error is detected in the peer
	// dedup loop, which runs before the cert-manager check just before newRaftTransport.
	_, err = NewManager(cfg, logger, storageManager, nil, "")
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

		manager, err := NewManager(cfg, logger, storageManager, nil, "")
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

		manager, err := NewManager(cfg, logger, storageManager, nil, "")
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

		manager, err := NewManager(cfg, logger, storageManager, newTestCertManager(t), "")
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

	manager, err := NewManager(cfg, logger, sm, nil, "")
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

	manager, err := NewManager(cfg, logger, sm, nil, "")
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

	manager, err := NewManager(cfg, logger, sm, nil, "")
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

	manager, err := NewManager(cfg, logger, sm, nil, "")
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
	manager, err := NewManager(cfg, logger, storageManager, newTestCertManager(t), "")
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
	manager, err := NewManager(cfg, logger, storageManager, newTestCertManager(t), "")
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
	manager, err := NewManager(cfg, logger, sm, nil, "")
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
		"",
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
		t.Cleanup(func() { assert.NoError(t, client.Stop(context.Background())) })
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
		"",
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
	manager, err := NewManager(cfg, logger, sm, newTestCertManager(t), "")
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
	// Cleanup uses a fresh context: ctx is cancelled by the deferred cancel above,
	// which runs before t.Cleanup callbacks.
	t.Cleanup(func() { assert.NoError(t, client.Stop(context.Background())) })

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

// TestManager_TwoNodeCluster verifies that two Manager instances in cluster mode,
// each configured with the other as a peer, complete Raft leader election so that
// exactly one is IsLeader()==true within 15 seconds. Real RaftConsensus instances
// are used throughout; httptest.NewTLSServer provides the transport layer.
//
// The production HandleMessage handler requires mTLS peer-CN verification, which in
// turn requires the transport client to present a client certificate — a capability
// not yet wired into raftTransport. This test therefore routes Raft messages directly
// through RaftConsensus.Process (the same code path HandleMessage uses internally),
// bypassing only the TLS CN gate that is irrelevant to testing leader election.
func TestManager_TwoNodeCluster(t *testing.T) {
	sm1, err := storage.CreateTestStorageManager()
	require.NoError(t, err)
	sm2, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	const nodeA = "two-node-cluster-a"
	const nodeB = "two-node-cluster-b"

	// Start HTTPS test servers before creating managers so we have real listen
	// addresses to put into the discovery configs. Handlers are registered after
	// the RaftConsensus pointers are available (no race: first election tick fires
	// after HeartbeatInterval=100ms, well after the Go setup below completes).
	muxA := http.NewServeMux()
	muxB := http.NewServeMux()

	srvA := httptest.NewTLSServer(muxA)
	t.Cleanup(srvA.Close)
	addrA := strings.TrimPrefix(srvA.URL, "https://")

	srvB := httptest.NewTLSServer(muxB)
	t.Cleanup(srvB.Close)
	addrB := strings.TrimPrefix(srvB.URL, "https://")

	logger := logging.GetLogger()

	makeCfg := func(selfID, peerID, selfAddr, peerAddr string) *Config {
		cfg := DefaultConfig()
		cfg.Mode = ClusterMode
		cfg.Node.ID = selfID
		cfg.Node.ExternalAddress = selfAddr
		cfg.Cluster.HeartbeatInterval = 100 * time.Millisecond
		cfg.Cluster.ElectionTimeout = 1 * time.Second
		cfg.Cluster.ExpectedSize = 2
		cfg.Cluster.MinQuorum = 2
		cfg.Cluster.Discovery.Config = map[string]interface{}{
			"nodes": []interface{}{
				map[string]interface{}{"id": selfID, "address": selfAddr},
				map[string]interface{}{"id": peerID, "address": peerAddr},
			},
		}
		return cfg
	}

	managerA, err := NewManager(makeCfg(nodeA, nodeB, addrA, addrB), logger, sm1, newTestCertManager(t), "")
	require.NoError(t, err)
	require.NotNil(t, managerA.raftConsensus)
	t.Cleanup(func() { assert.NoError(t, managerA.raftConsensus.Stop()) })

	managerB, err := NewManager(makeCfg(nodeB, nodeA, addrB, addrA), logger, sm2, newTestCertManager(t), "")
	require.NoError(t, err)
	require.NotNil(t, managerB.raftConsensus)
	t.Cleanup(func() { assert.NoError(t, managerB.raftConsensus.Stop()) })

	rcA := managerA.raftConsensus
	rcB := managerB.raftConsensus

	// raftMessageHandler reads a binary-encoded Raft message from the request body
	// and steps it into the target RaftConsensus via Process (= node.Step). This is
	// the same operation HandleMessage performs after passing the mTLS CN gate.
	var handlerCallCount atomic.Int64
	raftMessageHandler := func(rc *RaftConsensus) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			handlerCallCount.Add(1)
			data, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				http.Error(w, readErr.Error(), http.StatusBadRequest)
				return
			}
			// v3.7.0: use proto.Unmarshal into a pointer; Process takes the pointer
			// (raftpb.Message embeds a mutex and must not be copied).
			msg := &raftpb.Message{}
			if unmarshalErr := proto.Unmarshal(data, msg); unmarshalErr != nil {
				http.Error(w, unmarshalErr.Error(), http.StatusBadRequest)
				return
			}
			if stepErr := rc.Process(r.Context(), msg); stepErr != nil {
				http.Error(w, stepErr.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		}
	}

	muxA.HandleFunc("/raft/message", raftMessageHandler(rcA))
	muxB.HandleFunc("/raft/message", raftMessageHandler(rcB))

	// Replace each transport's HTTP client with one that trusts the httptest CA.
	// All httptest.NewTLSServer instances share the same hardcoded CA, so a client
	// from either server can reach both.
	testHTTPClient := srvA.Client()
	testHTTPClient.Timeout = 3 * time.Second

	managerA.raftConsensus.transport.mu.Lock()
	managerA.raftConsensus.transport.client = testHTTPClient
	managerA.raftConsensus.transport.mu.Unlock()

	managerB.raftConsensus.transport.mu.Lock()
	managerB.raftConsensus.transport.client = testHTTPClient
	managerB.raftConsensus.transport.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	require.NoError(t, managerA.Start(ctx))
	require.NoError(t, managerB.Start(ctx))

	require.Eventually(t, func() bool {
		la, lb := managerA.IsLeader(), managerB.IsLeader()
		return (la && !lb) || (!la && lb)
	}, 15*time.Second, 50*time.Millisecond, "exactly one of the two managers must be leader")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	require.NoError(t, managerA.Stop(stopCtx))
	require.NoError(t, managerB.Stop(stopCtx))
}

// TestManager_SingleServerMode_HasLeadership_UnconditionallyTrue is the REQUIRED
// test for Decision 4 of ADR-029: SingleServerMode HasLeadership() must return true
// unconditionally, with no lease, no expiry, and no new rejection path.
func TestManager_SingleServerMode_HasLeadership_UnconditionallyTrue(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = SingleServerMode

	manager, err := NewManager(cfg, logging.GetLogger(), storageManager, nil, "")
	require.NoError(t, err)
	require.NotNil(t, manager)

	// HasLeadership must return true immediately without any lease or Raft cluster.
	assert.True(t, manager.HasLeadership(),
		"SingleServerMode HasLeadership() must be unconditionally true — no lease, no expiry")

	// GetTerm in SingleServerMode has no Raft node; it returns 0.
	assert.Equal(t, uint64(0), manager.GetTerm(),
		"SingleServerMode GetTerm() must return 0 (no Raft cluster)")

	// IsRaftLeader in SingleServerMode returns false (no Raft cluster means no
	// Raft protocol state — the node is authoritative without Raft).
	assert.False(t, manager.IsRaftLeader(),
		"SingleServerMode IsRaftLeader() must return false (no Raft node to query)")
}

// TestManager_HasLeadership_ClusterMode_DelegatesAndExpires verifies that the
// Manager's HasLeadership() delegates to RaftConsensus and respects lease expiry.
func TestManager_HasLeadership_ClusterMode_DelegatesAndExpires(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = "hasleader-cluster-test"
	cfg.Cluster = FastElectionConfig()
	// Include the node itself in discovery so StartNode bootstraps a single-node
	// cluster (not RestartNode with no voters, which never elects a leader).
	cfg.Cluster.Discovery.Config["nodes"] = []interface{}{
		map[string]interface{}{"id": "hasleader-cluster-test", "address": "127.0.0.1:0"},
	}

	manager, err := NewManager(cfg, logging.GetLogger(), storageManager, newTestCertManager(t), "")
	require.NoError(t, err)
	t.Cleanup(func() {
		if manager.raftConsensus != nil {
			manager.raftConsensus.Stop() //nolint:errcheck // Stop always returns nil; error is non-actionable in cleanup
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, manager.Start(ctx))
	// Manager.Stop aggregates component shutdown errors, so it is asserted rather
	// than discarded: a failure to shut the cluster down cleanly is a real defect.
	defer func() {
		assert.NoError(t, manager.Stop(context.Background()))
	}()

	// Wait for leadership.
	require.Eventually(t, func() bool {
		return manager.IsLeader()
	}, 10*time.Second, 20*time.Millisecond, "single-node cluster must elect itself leader")

	// HasLeadership must return true once the lease is established.
	require.Eventually(t, func() bool {
		return manager.HasLeadership()
	}, 5*time.Second, 10*time.Millisecond, "HasLeadership must be true once lease is established")

	// Expire the lease via direct field access (simulates partition).
	leaseDuration := time.Duration(float64(cfg.Cluster.ElectionTimeout) * 0.8)
	rc := manager.raftConsensus
	rc.mu.Lock()
	rc.leaseLastAck = time.Now().Add(-(leaseDuration + time.Millisecond))
	rc.mu.Unlock()

	assert.False(t, manager.HasLeadership(),
		"Manager.HasLeadership() must be false when underlying lease has expired")
	assert.True(t, manager.IsLeader(),
		"Manager.IsLeader() (protocol state) must remain true when only the lease expired")
}
