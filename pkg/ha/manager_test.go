// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/testing/storage"
)

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
	assert.True(t, manager.HasLeadership())

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

// TestManager_ClusterMode verifies that a ClusterMode manager constructs with a
// lease store auto-wired from the storage manager (the OSS composite's SQLite
// bundle supplies one), starts and acquires the cluster leadership lease as the
// sole contender, and stops cleanly.
func TestManager_ClusterMode(t *testing.T) {
	logger := logging.GetLogger()

	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	const nodeID = "test-node-cluster-mode"
	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = nodeID
	cfg.Cluster = FastElectionConfig()

	manager, err := NewManager(cfg, logger, storageManager)
	require.NoError(t, err)
	require.NotNil(t, manager)

	assert.Equal(t, ClusterMode, manager.GetDeploymentMode())

	localNode := manager.GetLocalNode()
	assert.NotNil(t, localNode)
	assert.NotEmpty(t, localNode.ID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	require.NoError(t, err)

	require.Eventually(t, manager.HasLeadership, 5*time.Second, 5*time.Millisecond,
		"single-node cluster must acquire the cluster leadership lease as the sole contender")

	err = manager.Stop(ctx)
	assert.NoError(t, err)
}

// TestManager_Start_SurvivesCallerContextCancelledAfterReturn guards against a
// regression found live during #3130: server.go's Start() calls
// `ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second);
// defer cancel(); haManager.Start(ctx)` — a pattern that cancels ctx almost
// immediately (on the enclosing function's return), not after the 30s bound.
// Manager.Start() used to derive its internal m.ctx directly from that
// parameter, so every long-lived background component (originally the node-info
// replication goroutine; today the lease-acquisition and node-registration
// loops) was killed within milliseconds of Start() returning. This test
// reproduces the exact caller pattern (cancel the passed context immediately
// after Start() returns, not at test teardown) and proves the lease-acquisition
// loop still completes.
func TestManager_Start_SurvivesCallerContextCancelledAfterReturn(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	const nodeID = "test-node-ctx-survives-cancel"
	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = nodeID
	cfg.Cluster = FastElectionConfig()

	manager, err := NewManager(cfg, logging.GetLogger(), storageManager)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Reproduce server.go's exact pattern: a short-lived context whose cancel
	// fires on this function's return, not tied to the Manager's lifetime.
	func() {
		startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		startErr := manager.Start(startCtx)
		require.NoError(t, startErr)
	}()
	// startCtx is now cancelled — m.ctx must NOT be, or the lease-acquisition
	// loop died before it ever got a chance to acquire.

	require.Eventually(t, manager.HasLeadership, 5*time.Second, 5*time.Millisecond,
		"lease acquisition must complete even after the caller's Start(ctx) context is cancelled")

	require.NoError(t, manager.Stop(context.Background()))
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
		assert.True(t, manager.HasLeadership())
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
		cfg.Cluster = FastElectionConfig()

		manager, err := NewManager(cfg, logger, storageManager)
		require.NoError(t, err)

		err = manager.Start(ctx)
		require.NoError(t, err)

		// Should support cluster operations, acquiring the lease as sole contender.
		assert.Equal(t, ClusterMode, manager.GetDeploymentMode())
		require.Eventually(t, manager.HasLeadership, 5*time.Second, 5*time.Millisecond,
			"single-node cluster must acquire the cluster leadership lease")

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

// TestManager_SingleServerMode_HasLeadership_UnconditionallyTrue is the REQUIRED
// test for Decision 4 of ADR-029: SingleServerMode HasLeadership() must return true
// unconditionally, with no lease, no expiry, and no new rejection path.
func TestManager_SingleServerMode_HasLeadership_UnconditionallyTrue(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = SingleServerMode

	manager, err := NewManager(cfg, logging.GetLogger(), storageManager)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// HasLeadership must return true immediately without any lease or shared substrate.
	assert.True(t, manager.HasLeadership(),
		"SingleServerMode HasLeadership() must be unconditionally true — no lease, no expiry")

	// GetTerm in SingleServerMode has no lease-backed authority; it returns 0.
	assert.Equal(t, uint64(0), manager.GetTerm(),
		"SingleServerMode GetTerm() must return 0 (no lease-backed authority)")
}

// newLeaseBackedClusterManager returns a ClusterMode *Manager (FastElectionConfig)
// with SetLeaseStore already called against store. It does not Start the manager.
// Used by the lease-backed HasLeadership()/GetTerm() tests below (Issue #3760,
// ADR-031 Decision 5).
func newLeaseBackedClusterManager(t *testing.T, nodeID string, store business.LeaseStore) *Manager {
	t.Helper()

	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, storageManager.Close()) })

	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = nodeID
	cfg.Node.ExternalAddress = nodeID + ".invalid:9080"
	cfg.Cluster = FastElectionConfig()

	manager, err := NewManager(cfg, logging.GetLogger(), storageManager)
	require.NoError(t, err)
	require.NoError(t, manager.SetLeaseStore(store))
	return manager
}

// TestManager_HasLeadership_ClusterMode_LeaseBackedAndExpires is the REQUIRED test
// (Issue #3760 AC) proving Manager.HasLeadership()/GetTerm() are backed by the S3
// database lease (pkg/lease, ADR-031 Decision 5): HasLeadership() becomes true once
// the lease is acquired, GetTerm() reports the lease's fencing token, and —
// critically — HasLeadership() lapses once the background renewal loop stops
// (Manager.Stop), driven purely by the lease's cached-authority SafetyMargin.
func TestManager_HasLeadership_ClusterMode_LeaseBackedAndExpires(t *testing.T) {
	store := newTestLeaseStore(t)
	manager := newLeaseBackedClusterManager(t, "lease-hasleader-test", store)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, manager.Start(ctx))

	// HasLeadership must become true once the background acquisition loop
	// (started by Start()) acquires the database lease.
	require.Eventually(t, manager.HasLeadership, 5*time.Second, 5*time.Millisecond,
		"HasLeadership must become true once the database lease is acquired")

	token := manager.GetTerm()
	assert.NotZero(t, token, "GetTerm must return the lease's fencing token once leadership is held")

	state, err := store.GetLease(context.Background(), clusterLeadershipLeaseName)
	require.NoError(t, err)
	assert.Equal(t, token, state.Token, "GetTerm must equal the lease store's own current token")
	assert.Equal(t, "lease-hasleader-test", state.HolderID)

	// Manager.Stop aggregates component shutdown errors, so it is asserted rather
	// than discarded: a failure to shut the cluster down cleanly is a real defect.
	require.NoError(t, manager.Stop(context.Background()))

	// The renewal loop has stopped, so no further TryAcquire calls extend the
	// cached authority window. Once FastElectionConfig's derived SafetyMargin
	// (160ms: 0.8 × 200ms ElectionTimeout) lapses, HasLeadership must go false.
	assert.Eventually(t, func() bool { return !manager.HasLeadership() },
		2*time.Second, 5*time.Millisecond,
		"HasLeadership must become false once the cached lease authority window lapses without renewal")
}

// TestManager_HasLeadership_MultiNode_AgreesWithLeaseCurrentHolder is the REQUIRED
// multi-node test (Issue #3760 AC) proving HasLeadership()/GetTerm() agree with the
// lease's current holder/token across two Manager instances sharing one database —
// here, one real (not mocked) flatfile business.LeaseStore, per CLAUDE.md's
// no-mocks rule and the story's "no mocks" implementation note.
func TestManager_HasLeadership_MultiNode_AgreesWithLeaseCurrentHolder(t *testing.T) {
	store := newTestLeaseStore(t)

	managerA := newLeaseBackedClusterManager(t, "lease-multi-a", store)
	managerB := newLeaseBackedClusterManager(t, "lease-multi-b", store)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, managerA.Start(ctx))
	require.NoError(t, managerB.Start(ctx))
	t.Cleanup(func() {
		assert.NoError(t, managerA.Stop(context.Background()))
		assert.NoError(t, managerB.Stop(context.Background()))
	})

	// Wait until exactly one manager reports leadership and its GetTerm() agrees
	// with the store's own current-holder token — proving Manager.HasLeadership()/
	// GetTerm() read through to the same S3 lease state, not an independent view.
	require.Eventually(t, func() bool {
		aHas, bHas := managerA.HasLeadership(), managerB.HasLeadership()
		if aHas == bHas { // both false (not yet settled) or both true (should never happen)
			return false
		}

		leader, leaderID := managerA, "lease-multi-a"
		if bHas {
			leader, leaderID = managerB, "lease-multi-b"
		}

		state, err := store.GetLease(context.Background(), clusterLeadershipLeaseName)
		if err != nil || !state.Valid {
			return false
		}
		return state.HolderID == leaderID && state.Token == leader.GetTerm()
	}, 5*time.Second, 5*time.Millisecond,
		"exactly one manager must hold leadership, and its GetTerm() must equal the lease store's current holder token")
}

// TestManager_DualAuthorityWindowBound_ThroughManager is the REQUIRED test
// (Issue #3760 AC, "Security review finding, round 2") proving that two Manager
// instances never both report HasLeadership() == true for longer than S3's derived
// SafetyMargin, exercised through Manager specifically — not just pkg/lease.Manager
// directly (see TestManager_DualAuthorityWindowBound_NoOverlapBeyondSafetyMargin in
// pkg/lease) — proving the ha.Manager wiring didn't reintroduce the dual-authority
// gap the primitive itself closed.
func TestManager_DualAuthorityWindowBound_ThroughManager(t *testing.T) {
	store := newTestLeaseStore(t)

	managerA := newLeaseBackedClusterManager(t, "dual-auth-a", store)
	managerB := newLeaseBackedClusterManager(t, "dual-auth-b", store)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, managerA.Start(ctx))
	require.NoError(t, managerB.Start(ctx))

	require.Eventually(t, func() bool {
		return managerA.HasLeadership() || managerB.HasLeadership()
	}, 5*time.Second, 5*time.Millisecond, "one of the two managers must acquire the lease")

	winner, loser := managerA, managerB
	if managerB.HasLeadership() {
		winner, loser = managerB, managerA
	}

	// Stop the winner so its renewal loop stops (simulates a crashed leader), then
	// poll both managers' HasLeadership() until the loser takes over. At every
	// sampled instant at most one may report true.
	require.NoError(t, winner.Stop(context.Background()))

	deadline := time.Now().Add(3 * time.Second)
	var loserEverAcquired bool
	for time.Now().Before(deadline) {
		winnerHas := winner.HasLeadership()
		loserHas := loser.HasLeadership()
		require.False(t, winnerHas && loserHas,
			"both managers reported HasLeadership() == true for the same cluster lease simultaneously")
		if loserHas {
			loserEverAcquired = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	assert.True(t, loserEverAcquired, "the surviving manager must eventually take over the lease")

	require.NoError(t, loser.Stop(context.Background()))
}

// TestNewManager_ClusterMode_WiresLeaseStoreFromStorageManager proves the
// leadership lease is wired by construction from the StorageManager the Manager is
// handed, with no explicit SetLeaseStore call anywhere in the test. This is the
// regression test for the substrate swap shipping without production wiring: an
// opt-in setter that the controller startup path never calls leaves
// HasLeadership() permanently false and GetTerm() permanently 0, which is a
// disabled ADR-029 Decision 5 command fence, not a degraded one.
func TestNewManager_ClusterMode_WiresLeaseStoreFromStorageManager(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, storageManager.Close()) })

	require.NotNil(t, storageManager.GetLeaseStore(),
		"the standard test storage tier must supply a LeaseStore; without one this test cannot prove the wiring")

	const nodeID = "lease-autowire-node"
	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = nodeID
	cfg.Cluster = FastElectionConfig()

	manager, err := NewManager(cfg, logging.GetLogger(), storageManager)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, manager.Start(ctx),
		"Start must succeed when the storage manager supplies a lease store")
	t.Cleanup(func() { assert.NoError(t, manager.Stop(context.Background())) })

	require.Eventually(t, manager.HasLeadership, 5*time.Second, 5*time.Millisecond,
		"HasLeadership must become true from the constructor-wired lease, with no explicit SetLeaseStore call")

	token := manager.GetTerm()
	require.NotZero(t, token,
		"GetTerm must stamp a non-zero fencing token; term 0 is read as 'unstamped' by the steward fence ratchet")

	state, err := storageManager.GetLeaseStore().GetLease(context.Background(), clusterLeadershipLeaseName)
	require.NoError(t, err)
	assert.Equal(t, token, state.Token, "GetTerm must equal the wired store's own current token")
	assert.Equal(t, nodeID, state.HolderID)
}

// TestManager_Start_ClusterMode_WithoutLeaseStore_Fails proves a cluster Manager
// refuses to start when no lease store is available, rather than degrading to a
// permanently-false HasLeadership() and a term-0 command stamp. Fail-loud, not
// fail-quiet: the operator sees a startup error naming the missing substrate.
func TestManager_Start_ClusterMode_WithoutLeaseStore_Fails(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = "no-lease-store-node"
	cfg.Cluster = FastElectionConfig()

	// nil storage manager => no lease store to wire by construction.
	manager, err := NewManager(cfg, logging.GetLogger(), nil)
	require.NoError(t, err, "construction must still succeed; the lease is a start-time precondition")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = manager.Start(ctx)
	require.Error(t, err, "Start must refuse to run without the lease that backs leadership authority")
	assert.Contains(t, err.Error(), "requires a lease store")

	// The control must be off, not silently permissive.
	assert.False(t, manager.HasLeadership(),
		"a manager that refused to start must not report leadership")
	assert.Equal(t, uint64(0), manager.GetTerm())
}

// TestManager_BlueGreenMode_NeverLeaseBackedAuthority is the regression test for the
// dual-authority hole this substrate swap opened on its first pass (security review,
// round 3). Blue-green runs the node-local storage tier, so each node's StorageManager
// supplies a lease store backed by *its own* database file. Wiring that as cluster
// leadership let blue and green each acquire "controller-cluster-leadership" against
// their own copy — both reporting HasLeadership() == true, each minting a fencing
// sequence starting at 1, with the singleton claim and the command fence silently off.
//
// Blue-green therefore gets no lease-backed authority at all: it starts (no lease is
// required of it), HasLeadership() stays false on both nodes, and GetTerm() stays 0.
func TestManager_BlueGreenMode_NeverLeaseBackedAuthority(t *testing.T) {
	newBlueGreenNode := func(nodeID string) *Manager {
		cfg := DefaultConfig()
		cfg.Mode = BlueGreenMode
		cfg.Node.ID = nodeID
		cfg.Cluster = FastElectionConfig()

		// Each node has its own store, exactly as a per-node SQLite/flat-file
		// storage tier gives it — the substrate that excludes nothing.
		storageManager, err := storage.CreateTestStorageManager()
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, storageManager.Close()) })
		require.NotNil(t, storageManager.GetLeaseStore(),
			"the node-local tier does supply a lease store; that is exactly why a non-nil check is not enough")

		manager, err := NewManager(cfg, logging.GetLogger(), storageManager)
		require.NoError(t, err)

		// An explicit wiring attempt must not grant authority either.
		require.NoError(t, manager.SetLeaseStore(newTestLeaseStore(t)),
			"SetLeaseStore is a no-op in blue-green, not an error")
		return manager
	}

	blue := newBlueGreenNode("blue-node")
	green := newBlueGreenNode("green-node")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, blue.Start(ctx), "blue-green must start without a shared lease substrate")
	require.NoError(t, green.Start(ctx))
	t.Cleanup(func() {
		assert.NoError(t, blue.Stop(context.Background()))
		assert.NoError(t, green.Stop(context.Background()))
	})

	// Sample over a window longer than a lease TTL would be, so a lease-acquisition
	// loop — if one were ever wired here — would have completed several rounds.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		require.False(t, blue.HasLeadership(),
			"blue must never report leadership from a node-local lease")
		require.False(t, green.HasLeadership(),
			"green must never report leadership from a node-local lease")
		require.Equal(t, uint64(0), blue.GetTerm(),
			"blue must stamp no fencing token; an independent per-node sequence is worse than none")
		require.Equal(t, uint64(0), green.GetTerm())
		time.Sleep(10 * time.Millisecond)
	}
}

// TestManager_SetLeaseStore_NilStoreRejectedInClusterMode proves the explicit wiring
// entry point reports a nil store as an error rather than quietly leaving the
// authority substrate unwired, and that modes without lease-backed authority are
// unaffected by what is passed.
func TestManager_SetLeaseStore_NilStoreRejectedInClusterMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = "nil-lease-store-node"
	cfg.Cluster = FastElectionConfig()

	manager, err := NewManager(cfg, logging.GetLogger(), nil)
	require.NoError(t, err)

	require.Error(t, manager.SetLeaseStore(nil),
		"SetLeaseStore(nil) must be an error in ClusterMode, where the lease is the authority source")

	// SingleServerMode needs no lease (ADR-029 Decision 4), so nil stays a no-op.
	singleCfg := DefaultConfig()
	singleCfg.Mode = SingleServerMode
	singleManager, err := NewManager(singleCfg, logging.GetLogger(), nil)
	require.NoError(t, err)
	assert.NoError(t, singleManager.SetLeaseStore(nil),
		"SingleServerMode must remain unaffected by the lease substrate")
	assert.True(t, singleManager.HasLeadership(),
		"SingleServerMode HasLeadership() must stay unconditionally true")
}

// TestManager_GetClusterNodes_FallsBackToLocalWhenNoRegistryWired verifies that
// GetClusterNodes() reports the local-only clusterNodes map (Issue #3763) whenever
// no shared node registry store is wired — SingleServerMode always, and any
// ClusterMode deployment whose storage provider does not implement
// business.NodeRegistryStoreCreator.
func TestManager_GetClusterNodes_FallsBackToLocalWhenNoRegistryWired(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = SingleServerMode

	manager, err := NewManager(cfg, logging.GetLogger(), storageManager)
	require.NoError(t, err)
	require.Nil(t, manager.nodeRegistryStore,
		"SingleServerMode must never wire a node registry store (see usesLeaseAuthority)")

	nodes, err := manager.GetClusterNodes()
	require.NoError(t, err)
	require.Len(t, nodes, 1, "fallback must report exactly the local node")
	assert.Equal(t, manager.GetLocalNode().ID, nodes[0].ID)
}

// TestManager_GetClusterNodes_UsesNodeRegistryWhenWired verifies that
// GetClusterNodes() reads through to a wired business.NodeRegistryStore (Issue
// #3763, ADR-031 Decision 5's post-Raft membership mechanism), reporting every
// live record the store has — including peers this Manager never registered
// itself.
func TestManager_GetClusterNodes_UsesNodeRegistryWhenWired(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = "registry-nodes-node"
	cfg.Cluster = FastElectionConfig()

	manager, err := NewManager(cfg, logging.GetLogger(), storageManager)
	require.NoError(t, err)

	store := newTestNodeRegistryStore(t)
	manager.nodeRegistryStore = store

	ctx := context.Background()
	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "peer-node", Address: "10.0.0.9:9080"}))

	nodes, err := manager.GetClusterNodes()
	require.NoError(t, err)

	var found bool
	for _, n := range nodes {
		if n.ID == "peer-node" {
			found = true
			assert.Equal(t, "10.0.0.9:9080", n.Address)
		}
	}
	assert.True(t, found, "GetClusterNodes must read through to the wired node registry store")
}

// TestManager_Start_ClusterMode_RegistersSelfInNodeRegistry verifies that Start()
// launches runNodeRegistration, which registers this node's own ID and address in
// the wired node registry store (Issue #3763) — the mechanism
// features/controller/server's internal-delivery node resolver depends on to
// locate this node.
func TestManager_Start_ClusterMode_RegistersSelfInNodeRegistry(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)

	const nodeID = "self-register-node"
	cfg := DefaultConfig()
	cfg.Mode = ClusterMode
	cfg.Node.ID = nodeID
	cfg.Node.ExternalAddress = "10.0.0.5:9080"
	cfg.Cluster = FastElectionConfig()

	manager, err := NewManager(cfg, logging.GetLogger(), storageManager)
	require.NoError(t, err)

	store := newTestNodeRegistryStore(t)
	manager.nodeRegistryStore = store

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, manager.Start(ctx))
	t.Cleanup(func() { assert.NoError(t, manager.Stop(context.Background())) })

	require.Eventually(t, func() bool {
		nodes, listErr := store.ListNodes(context.Background())
		if listErr != nil {
			return false
		}
		for _, n := range nodes {
			if n.ID == nodeID && n.Address == "10.0.0.5:9080" {
				return true
			}
		}
		return false
	}, 5*time.Second, 25*time.Millisecond, "runNodeRegistration must register this node's own record")
}

// TestManager_GetLeader_ClusterMode_ResolvesPeerViaNodeRegistry is the REQUIRED
// post-Raft counterpart to the deleted uint64-precision regression test: it proves
// GetLeader() resolves the cluster leadership lease's current holder to a full
// NodeInfo (Issue #3763) — including from a node that does NOT itself hold the
// lease, which is only possible by reading through the shared node registry
// rather than returning only ever-local information.
func TestManager_GetLeader_ClusterMode_ResolvesPeerViaNodeRegistry(t *testing.T) {
	leaseStore := newTestLeaseStore(t)
	registryStore := newTestNodeRegistryStore(t)

	managerA := newLeaseBackedClusterManager(t, "leader-resolve-a", leaseStore)
	managerA.nodeRegistryStore = registryStore
	managerB := newLeaseBackedClusterManager(t, "leader-resolve-b", leaseStore)
	managerB.nodeRegistryStore = registryStore

	startCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, managerA.Start(startCtx))
	require.NoError(t, managerB.Start(startCtx))
	t.Cleanup(func() {
		assert.NoError(t, managerA.Stop(context.Background()))
		assert.NoError(t, managerB.Stop(context.Background()))
	})

	// Let each manager's own runNodeRegistration loop (started by Start()) publish
	// its self-registered address before relying on it below — otherwise the
	// registry read in GetLeader() could race a self-registration that has not
	// landed yet and report an empty Address.
	require.Eventually(t, func() bool {
		nodes, listErr := registryStore.ListNodes(context.Background())
		if listErr != nil {
			return false
		}
		seen := map[string]bool{}
		for _, n := range nodes {
			seen[n.ID] = true
		}
		return seen["leader-resolve-a"] && seen["leader-resolve-b"]
	}, 5*time.Second, 25*time.Millisecond, "both managers must self-register before the leader resolution below")

	require.Eventually(t, func() bool {
		return managerA.HasLeadership() || managerB.HasLeadership()
	}, 5*time.Second, 5*time.Millisecond, "one of the two managers must acquire the lease")

	// Whichever manager holds the lease, GetLeader() called on the OTHER manager
	// must still resolve the holder's NodeInfo — proving the resolution goes
	// through the shared node registry, not just local state.
	loser, winnerID, winnerAddr := managerA, "leader-resolve-b", "leader-resolve-b.invalid:9080"
	if managerA.HasLeadership() {
		loser, winnerID, winnerAddr = managerB, "leader-resolve-a", "leader-resolve-a.invalid:9080"
	}

	var resolved *NodeInfo
	require.Eventually(t, func() bool {
		leader, getErr := loser.GetLeader()
		if getErr != nil || leader == nil || leader.ID != winnerID {
			return false
		}
		resolved = leader
		return true
	}, 5*time.Second, 25*time.Millisecond,
		"GetLeader() must resolve the lease holder's NodeInfo via the shared node registry, even from a non-holding node")
	assert.Equal(t, winnerAddr, resolved.Address,
		"the resolved NodeInfo must carry the holder's registered address")
}
