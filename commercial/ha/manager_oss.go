//go:build !commercial
// +build !commercial

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// Manager implements the ClusterManager interface for OSS (Single Server Mode only)
// This is a minimal implementation that provides basic HA interface compliance
// without any clustering functionality. Commercial builds use the full implementation.
type Manager struct {
	mu     sync.RWMutex
	logger logging.Logger

	// Node information
	nodeInfo *NodeInfo

	// Health checks
	healthChecks map[string]HealthCheckFunc
	healthStatus *HealthStatus

	// State
	isStarted bool
	startTime time.Time
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewManager creates a new OSS HA manager (Single Server Mode only)
func NewManager(cfg *Config, logger logging.Logger, storageManager *interfaces.StorageManager) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// OSS ONLY supports SingleServerMode
	if cfg.Mode != SingleServerMode {
		logger.Warn("HA clustering is a commercial feature - forcing SingleServerMode",
			"requested_mode", cfg.Mode.String(),
			"enforced_mode", "single")
		cfg.Mode = SingleServerMode
	}

	// Generate node ID if not provided
	if cfg.Node.ID == "" {
		cfg.Node.ID = fmt.Sprintf("node-%d", time.Now().UnixNano())
	}

	// Set default node name
	if cfg.Node.Name == "" {
		cfg.Node.Name = fmt.Sprintf("controller-%s", cfg.Node.ID[:8])
	}

	// Create node info
	nodeInfo := &NodeInfo{
		ID:        cfg.Node.ID,
		Address:   cfg.Node.ExternalAddress,
		State:     NodeStateHealthy,
		Role:      NodeRoleLeader, // Single server is always the leader
		StartedAt: time.Now(),
		Version:   "v0.7.0-oss",
		Region:    cfg.Node.Region,
		Latency:   make(map[string]time.Duration),
	}

	manager := &Manager{
		logger:       logger,
		nodeInfo:     nodeInfo,
		healthChecks: make(map[string]HealthCheckFunc),
		healthStatus: &HealthStatus{
			Overall:   NodeStateHealthy,
			Checks:    make(map[string]NodeState),
			Timestamp: time.Now(),
			Details:   make(map[string]string),
		},
	}

	logger.Info("OSS HA Manager initialized (SingleServerMode only)",
		"node_id", nodeInfo.ID,
		"commercial_features", "disabled")

	return manager, nil
}

// Start begins the HA operations (minimal for OSS)
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isStarted {
		return fmt.Errorf("HA manager is already started")
	}

	m.ctx, m.cancel = context.WithCancel(ctx)
	m.startTime = time.Now()
	m.nodeInfo.StartedAt = m.startTime
	m.nodeInfo.LastSeen = m.startTime

	m.logger.Info("OSS HA Manager started (SingleServerMode)")

	m.isStarted = true

	// Start health check routine
	go m.runHealthChecks()

	return nil
}

// Stop gracefully stops the HA operations
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isStarted {
		return nil
	}

	m.logger.Info("Stopping OSS HA Manager")

	if m.cancel != nil {
		m.cancel()
	}

	m.isStarted = false
	m.logger.Info("OSS HA Manager stopped successfully")

	return nil
}

// GetDeploymentMode returns the current deployment mode (always SingleServerMode for OSS)
func (m *Manager) GetDeploymentMode() DeploymentMode {
	return SingleServerMode
}

// GetLocalNode returns information about the local node
func (m *Manager) GetLocalNode() *NodeInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create a copy to prevent modification
	nodeInfo := *m.nodeInfo
	nodeInfo.LastSeen = time.Now()
	return &nodeInfo
}

// GetClusterNodes returns information about all nodes (only local node in OSS)
func (m *Manager) GetClusterNodes() ([]*NodeInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// OSS: Only returns the local node
	nodes := []*NodeInfo{m.GetLocalNode()}
	return nodes, nil
}

// IsLeader returns true if this node is the cluster leader (always true in OSS)
func (m *Manager) IsLeader() bool {
	return true // Single server is always the leader
}

// GetLeader returns the current cluster leader node (always local node in OSS)
func (m *Manager) GetLeader() (*NodeInfo, error) {
	return m.GetLocalNode(), nil
}

// RegisterHealthCheck registers a health check function
func (m *Manager) RegisterHealthCheck(name string, check HealthCheckFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.healthChecks[name] = check
	m.logger.Debug("Health check registered", "name", name)
}

// GetHealth returns the current health status
func (m *Manager) GetHealth() *HealthStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create a copy to prevent modification
	status := &HealthStatus{
		Overall:   m.healthStatus.Overall,
		Checks:    make(map[string]NodeState),
		Timestamp: m.healthStatus.Timestamp,
		Details:   make(map[string]string),
	}

	for name, state := range m.healthStatus.Checks {
		status.Checks[name] = state
	}

	for key, value := range m.healthStatus.Details {
		status.Details[key] = value
	}

	return status
}

// GetRaftTransport returns the Raft transport (always nil in OSS)
// Raft clustering is a commercial feature
func (m *Manager) GetRaftTransport() RaftTransport {
	return nil
}

// runHealthChecks runs health checks periodically
func (m *Manager) runHealthChecks() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.performHealthChecks()
		}
	}
}

// performHealthChecks executes all registered health checks
func (m *Manager) performHealthChecks() {
	m.mu.Lock()
	defer m.mu.Unlock()

	overallHealthy := true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for name, checkFunc := range m.healthChecks {
		err := checkFunc(ctx)
		if err != nil {
			m.healthStatus.Checks[name] = NodeStateDegraded
			m.healthStatus.Details[name] = err.Error()
			overallHealthy = false
			m.logger.Warn("Health check failed", "check", name, "error", err)
		} else {
			m.healthStatus.Checks[name] = NodeStateHealthy
			delete(m.healthStatus.Details, name)
		}
	}

	if overallHealthy {
		m.healthStatus.Overall = NodeStateHealthy
	} else {
		m.healthStatus.Overall = NodeStateDegraded
	}

	m.healthStatus.Timestamp = time.Now()
	m.nodeInfo.State = m.healthStatus.Overall
	m.nodeInfo.LastSeen = time.Now()
}

// DefaultConfig returns default OSS HA configuration
func DefaultConfig() *Config {
	return &Config{
		Mode: SingleServerMode, // OSS only supports single server
		Node: NodeConfig{
			Region: "default",
		},
		HealthCheck: &HealthCheckConfig{
			Enabled:  true,
			Interval: 30 * time.Second,
			Timeout:  5 * time.Second,
		},
	}
}
