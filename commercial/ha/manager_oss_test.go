//go:build !commercial
// +build !commercial

// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors

package ha

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// mockLogger implements a minimal logger for testing
type mockLogger struct {
	entries []string
}

// Compile-time check that mockLogger implements logging.Logger
var _ logging.Logger = (*mockLogger)(nil)

func (l *mockLogger) Debug(msg string, keysAndValues ...interface{}) {
	l.entries = append(l.entries, fmt.Sprintf("DEBUG: %s", msg))
}

func (l *mockLogger) Info(msg string, keysAndValues ...interface{}) {
	l.entries = append(l.entries, fmt.Sprintf("INFO: %s", msg))
}

func (l *mockLogger) Warn(msg string, keysAndValues ...interface{}) {
	l.entries = append(l.entries, fmt.Sprintf("WARN: %s", msg))
}

func (l *mockLogger) Error(msg string, keysAndValues ...interface{}) {
	l.entries = append(l.entries, fmt.Sprintf("ERROR: %s", msg))
}

func (l *mockLogger) Fatal(msg string, keysAndValues ...interface{}) {
	l.entries = append(l.entries, fmt.Sprintf("FATAL: %s", msg))
}

func (l *mockLogger) DebugCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.entries = append(l.entries, fmt.Sprintf("DEBUG: %s", msg))
}

func (l *mockLogger) InfoCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.entries = append(l.entries, fmt.Sprintf("INFO: %s", msg))
}

func (l *mockLogger) WarnCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.entries = append(l.entries, fmt.Sprintf("WARN: %s", msg))
}

func (l *mockLogger) ErrorCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.entries = append(l.entries, fmt.Sprintf("ERROR: %s", msg))
}

func (l *mockLogger) FatalCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.entries = append(l.entries, fmt.Sprintf("FATAL: %s", msg))
}

// getTestStorageManager returns a test storage manager (using nil for simplicity)
func getTestStorageManager() *interfaces.StorageManager {
	// For OSS stub testing, we don't need a real storage manager
	// The OSS stub only calls GetConfigStore() for health checks
	// We'll use a minimal implementation
	return nil
}

// TestNewManager_DefaultConfig tests creating a manager with default config
func TestNewManager_DefaultConfig(t *testing.T) {
	logger := &mockLogger{}
	storage := getTestStorageManager()

	manager, err := NewManager(nil, logger, storage)
	require.NoError(t, err, "NewManager should not return error")
	require.NotNil(t, manager, "Manager should not be nil")

	// Verify deployment mode is always SingleServerMode
	assert.Equal(t, SingleServerMode, manager.GetDeploymentMode(), "OSS should always be SingleServerMode")

	// Verify node info is initialized
	nodeInfo := manager.GetLocalNode()
	require.NotNil(t, nodeInfo, "Node info should not be nil")
	assert.NotEmpty(t, nodeInfo.ID, "Node ID should be generated")
	assert.Equal(t, NodeStateHealthy, nodeInfo.State, "Node should start healthy")
	assert.Equal(t, NodeRoleLeader, nodeInfo.Role, "Single server should always be leader")
	assert.Equal(t, "v0.7.0-oss", nodeInfo.Version, "Version should be OSS")
}

// TestNewManager_SingleServerModeEnforcement tests that OSS enforces SingleServerMode
func TestNewManager_SingleServerModeEnforcement(t *testing.T) {
	tests := []struct {
		name          string
		requestedMode DeploymentMode
	}{
		{"BlueGreenMode_Blocked", BlueGreenMode},
		{"ClusterMode_Blocked", ClusterMode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &mockLogger{}
			storage := getTestStorageManager()

			cfg := &Config{
				Mode: tt.requestedMode,
				Node: NodeConfig{
					Region: "test-region",
				},
				HealthCheck: &HealthCheckConfig{
					Enabled:  true,
					Interval: 30 * time.Second,
					Timeout:  5 * time.Second,
				},
			}

			manager, err := NewManager(cfg, logger, storage)
			require.NoError(t, err, "NewManager should not return error")
			require.NotNil(t, manager, "Manager should not be nil")

			// Verify mode was forced to SingleServerMode
			assert.Equal(t, SingleServerMode, manager.GetDeploymentMode(),
				"OSS should force SingleServerMode regardless of requested mode")

			// Verify warning was logged
			found := false
			for _, entry := range logger.entries {
				if entry == "WARN: HA clustering is a commercial feature - forcing SingleServerMode" {
					found = true
					break
				}
			}
			assert.True(t, found, "Should log warning about commercial features")
		})
	}
}

// TestManager_StartStop tests the Start/Stop lifecycle
func TestManager_StartStop(t *testing.T) {
	logger := &mockLogger{}
	storage := getTestStorageManager()

	manager, err := NewManager(nil, logger, storage)
	require.NoError(t, err)

	ctx := context.Background()

	// Test Start
	err = manager.Start(ctx)
	assert.NoError(t, err, "Start should succeed")

	// Verify manager is started
	assert.True(t, manager.isStarted, "Manager should be marked as started")

	// Test double start (should fail)
	err = manager.Start(ctx)
	assert.Error(t, err, "Second Start should return error")
	assert.Contains(t, err.Error(), "already started", "Error should mention already started")

	// Test Stop
	err = manager.Stop(ctx)
	assert.NoError(t, err, "Stop should succeed")

	// Verify manager is stopped
	assert.False(t, manager.isStarted, "Manager should be marked as stopped")

	// Test double stop (should succeed without error)
	err = manager.Stop(ctx)
	assert.NoError(t, err, "Second Stop should not return error")
}

// TestManager_GetDeploymentMode tests deployment mode retrieval
func TestManager_GetDeploymentMode(t *testing.T) {
	logger := &mockLogger{}
	storage := getTestStorageManager()

	manager, err := NewManager(nil, logger, storage)
	require.NoError(t, err)

	mode := manager.GetDeploymentMode()
	assert.Equal(t, SingleServerMode, mode, "OSS should always return SingleServerMode")
}

// TestManager_GetLocalNode tests local node information
func TestManager_GetLocalNode(t *testing.T) {
	logger := &mockLogger{}
	storage := getTestStorageManager()

	cfg := &Config{
		Mode: SingleServerMode,
		Node: NodeConfig{
			ID:              "test-node-123",
			ExternalAddress: "192.168.1.100:8080",
			Region:          "us-west-2",
		},
		HealthCheck: &HealthCheckConfig{
			Enabled:  true,
			Interval: 30 * time.Second,
			Timeout:  5 * time.Second,
		},
	}

	manager, err := NewManager(cfg, logger, storage)
	require.NoError(t, err)

	nodeInfo := manager.GetLocalNode()
	require.NotNil(t, nodeInfo, "Node info should not be nil")

	assert.Equal(t, "test-node-123", nodeInfo.ID, "Node ID should match config")
	assert.Equal(t, "192.168.1.100:8080", nodeInfo.Address, "Node address should match config")
	assert.Equal(t, "us-west-2", nodeInfo.Region, "Node region should match config")
	assert.Equal(t, NodeStateHealthy, nodeInfo.State, "Node should be healthy")
	assert.Equal(t, NodeRoleLeader, nodeInfo.Role, "Single server should be leader")
	assert.NotZero(t, nodeInfo.LastSeen, "LastSeen should be set")
	assert.NotZero(t, nodeInfo.StartedAt, "StartedAt should be set")
}

// TestManager_GetClusterNodes tests cluster nodes retrieval (OSS returns only local node)
func TestManager_GetClusterNodes(t *testing.T) {
	logger := &mockLogger{}
	storage := getTestStorageManager()

	manager, err := NewManager(nil, logger, storage)
	require.NoError(t, err)

	nodes, err := manager.GetClusterNodes()
	assert.NoError(t, err, "GetClusterNodes should not return error")
	assert.Len(t, nodes, 1, "OSS should return exactly 1 node (local node)")

	// Verify it's the local node
	localNode := manager.GetLocalNode()
	assert.Equal(t, localNode.ID, nodes[0].ID, "Single node should be the local node")
	assert.Equal(t, localNode.Role, nodes[0].Role, "Node role should match")
}

// TestManager_IsLeader tests leader status (OSS always returns true)
func TestManager_IsLeader(t *testing.T) {
	logger := &mockLogger{}
	storage := getTestStorageManager()

	manager, err := NewManager(nil, logger, storage)
	require.NoError(t, err)

	isLeader := manager.IsLeader()
	assert.True(t, isLeader, "OSS single server should always be leader")
}

// TestManager_GetLeader tests leader node retrieval (OSS returns local node)
func TestManager_GetLeader(t *testing.T) {
	logger := &mockLogger{}
	storage := getTestStorageManager()

	manager, err := NewManager(nil, logger, storage)
	require.NoError(t, err)

	leader, err := manager.GetLeader()
	assert.NoError(t, err, "GetLeader should not return error")
	require.NotNil(t, leader, "Leader should not be nil")

	// Verify leader is the local node
	localNode := manager.GetLocalNode()
	assert.Equal(t, localNode.ID, leader.ID, "Leader should be the local node")
	assert.Equal(t, NodeRoleLeader, leader.Role, "Leader role should be NodeRoleLeader")
}

// TestManager_GetRaftTransport tests Raft transport retrieval (OSS always returns nil)
func TestManager_GetRaftTransport(t *testing.T) {
	logger := &mockLogger{}
	storage := getTestStorageManager()

	manager, err := NewManager(nil, logger, storage)
	require.NoError(t, err)

	transport := manager.GetRaftTransport()
	assert.Nil(t, transport, "OSS should always return nil for GetRaftTransport (Raft is commercial)")
}

// TestManager_RegisterHealthCheck tests health check registration
func TestManager_RegisterHealthCheck(t *testing.T) {
	logger := &mockLogger{}
	storage := getTestStorageManager()

	manager, err := NewManager(nil, logger, storage)
	require.NoError(t, err)

	// Register a passing health check
	passingCheckCalled := false
	manager.RegisterHealthCheck("test-passing", func(ctx context.Context) error {
		passingCheckCalled = true
		return nil
	})

	// Register a failing health check
	failingCheckCalled := false
	manager.RegisterHealthCheck("test-failing", func(ctx context.Context) error {
		failingCheckCalled = true
		return fmt.Errorf("test failure")
	})

	// Verify checks are registered
	assert.Len(t, manager.healthChecks, 2, "Should have 2 health checks registered")

	// Trigger health checks manually
	manager.performHealthChecks()

	// Verify checks were called
	assert.True(t, passingCheckCalled, "Passing health check should be called")
	assert.True(t, failingCheckCalled, "Failing health check should be called")

	// Verify health status
	health := manager.GetHealth()
	assert.Equal(t, NodeStateDegraded, health.Overall, "Overall health should be degraded due to failing check")
	assert.Equal(t, NodeStateHealthy, health.Checks["test-passing"], "Passing check should be healthy")
	assert.Equal(t, NodeStateDegraded, health.Checks["test-failing"], "Failing check should be degraded")
	assert.Contains(t, health.Details["test-failing"], "test failure", "Failure details should be recorded")
}

// TestManager_GetHealth tests health status retrieval
func TestManager_GetHealth(t *testing.T) {
	logger := &mockLogger{}
	storage := getTestStorageManager()

	manager, err := NewManager(nil, logger, storage)
	require.NoError(t, err)

	// Get health before starting
	health := manager.GetHealth()
	require.NotNil(t, health, "Health should not be nil")
	assert.Equal(t, NodeStateHealthy, health.Overall, "Initial health should be healthy")
	assert.NotNil(t, health.Checks, "Health checks map should not be nil")
	assert.NotNil(t, health.Details, "Health details map should not be nil")
	assert.NotZero(t, health.Timestamp, "Health timestamp should be set")
}

// TestManager_HealthCheckConcurrency tests health check execution with concurrent access
func TestManager_HealthCheckConcurrency(t *testing.T) {
	logger := &mockLogger{}
	storage := getTestStorageManager()

	manager, err := NewManager(nil, logger, storage)
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = manager.Stop(ctx)
	}()

	// Register health check
	manager.RegisterHealthCheck("concurrent-test", func(ctx context.Context) error {
		return nil
	})

	// Perform multiple concurrent health check retrievals
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				health := manager.GetHealth()
				assert.NotNil(t, health)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestManager_InterfaceCompliance tests that Manager implements ClusterManager interface
func TestManager_InterfaceCompliance(t *testing.T) {
	logger := &mockLogger{}
	storage := getTestStorageManager()

	manager, err := NewManager(nil, logger, storage)
	require.NoError(t, err)

	// Verify manager implements ClusterManager interface
	var _ ClusterManager = manager

	// Test all interface methods
	ctx := context.Background()

	// Start/Stop
	assert.NoError(t, manager.Start(ctx))
	assert.NoError(t, manager.Stop(ctx))

	// GetDeploymentMode
	mode := manager.GetDeploymentMode()
	assert.Equal(t, SingleServerMode, mode)

	// GetLocalNode
	localNode := manager.GetLocalNode()
	assert.NotNil(t, localNode)

	// GetClusterNodes
	nodes, err := manager.GetClusterNodes()
	assert.NoError(t, err)
	assert.Len(t, nodes, 1)

	// IsLeader
	assert.True(t, manager.IsLeader())

	// GetLeader
	leader, err := manager.GetLeader()
	assert.NoError(t, err)
	assert.NotNil(t, leader)

	// RegisterHealthCheck
	manager.RegisterHealthCheck("test", func(ctx context.Context) error {
		return nil
	})

	// GetHealth
	health := manager.GetHealth()
	assert.NotNil(t, health)

	// GetRaftTransport
	transport := manager.GetRaftTransport()
	assert.Nil(t, transport)
}

// TestDefaultConfig tests the default configuration
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg, "Default config should not be nil")

	assert.Equal(t, SingleServerMode, cfg.Mode, "Default mode should be SingleServerMode")
	assert.NotNil(t, cfg.HealthCheck, "Default health check config should not be nil")
	assert.True(t, cfg.HealthCheck.Enabled, "Health check should be enabled by default")
	assert.Equal(t, 30*time.Second, cfg.HealthCheck.Interval, "Default interval should be 30s")
	assert.Equal(t, 5*time.Second, cfg.HealthCheck.Timeout, "Default timeout should be 5s")
	assert.Equal(t, "default", cfg.Node.Region, "Default region should be 'default'")
}

// TestManager_HealthCheckTimeout tests health check timeout handling
func TestManager_HealthCheckTimeout(t *testing.T) {
	logger := &mockLogger{}
	storage := getTestStorageManager()

	manager, err := NewManager(nil, logger, storage)
	require.NoError(t, err)

	// Register a slow health check that exceeds timeout
	manager.RegisterHealthCheck("slow-check", func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
			return nil
		}
	})

	// Perform health check (should timeout after 5s)
	startTime := time.Now()
	manager.performHealthChecks()
	duration := time.Since(startTime)

	// Verify timeout occurred (should be ~5s, not 10s)
	assert.Less(t, duration, 8*time.Second, "Health check should timeout before 8s")

	// Verify health status shows failure
	health := manager.GetHealth()
	assert.Equal(t, NodeStateDegraded, health.Overall, "Overall health should be degraded")
	assert.Equal(t, NodeStateDegraded, health.Checks["slow-check"], "Slow check should be degraded")
	assert.Contains(t, health.Details["slow-check"], "context", "Should indicate context cancellation")
}

// TestManager_NodeInfoImmutability tests that returned NodeInfo is a copy
func TestManager_NodeInfoImmutability(t *testing.T) {
	logger := &mockLogger{}
	storage := getTestStorageManager()

	manager, err := NewManager(nil, logger, storage)
	require.NoError(t, err)

	// Get node info and try to modify it
	node1 := manager.GetLocalNode()
	originalID := node1.ID
	node1.ID = "modified-id"
	node1.State = NodeStateFailed

	// Get node info again and verify original values
	node2 := manager.GetLocalNode()
	assert.Equal(t, originalID, node2.ID, "Node ID should not be modified")
	assert.Equal(t, NodeStateHealthy, node2.State, "Node state should not be modified")
}

// TestManager_HealthStatusImmutability tests that returned HealthStatus is a copy
func TestManager_HealthStatusImmutability(t *testing.T) {
	logger := &mockLogger{}
	storage := getTestStorageManager()

	manager, err := NewManager(nil, logger, storage)
	require.NoError(t, err)

	// Register a health check
	manager.RegisterHealthCheck("test", func(ctx context.Context) error {
		return nil
	})

	manager.performHealthChecks()

	// Get health status and try to modify it
	health1 := manager.GetHealth()
	health1.Overall = NodeStateFailed
	health1.Checks["test"] = NodeStateFailed
	health1.Details["test"] = "modified"

	// Get health status again and verify original values
	health2 := manager.GetHealth()
	assert.Equal(t, NodeStateHealthy, health2.Overall, "Overall health should not be modified")
	assert.Equal(t, NodeStateHealthy, health2.Checks["test"], "Check status should not be modified")
	assert.Empty(t, health2.Details["test"], "Details should not be modified")
}
