//go:build commercial

// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 CFGMS Contributors
// +build commercial

package ha

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"go.etcd.io/raft/v3"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/version"
)

// Manager implements the ClusterManager interface and coordinates all HA operations
type Manager struct {
	mu     sync.RWMutex
	cfg    *Config
	logger logging.Logger

	// Core components
	nodeInfo      *NodeInfo
	healthChecker *HealthChecker
	raftConsensus *RaftConsensus // NEW: Raft-based consensus (replaces discovery + custom election)
	discovery     Discovery      // DEPRECATED: Will be removed
	loadBalancer  LoadBalancer
	failover      FailoverManager
	splitBrain    SplitBrainDetector
	sessionSync   SessionSynchronizer

	// State management
	storageManager *interfaces.StorageManager
	isStarted      bool
	startTime      time.Time
	ctx            context.Context
	cancel         context.CancelFunc

	// Cluster state
	clusterNodes  map[string]*NodeInfo
	currentLeader string
	isLeader      bool

	// Health checks
	healthChecks map[string]HealthCheckFunc
	healthStatus *HealthStatus

	// Callbacks (reserved for future use)
	// failoverHandlers    []FailoverHandler
	// splitBrainHandlers  []SplitBrainHandler
}

// NewManager creates a new HA manager
func NewManager(cfg *Config, logger logging.Logger, storageManager *interfaces.StorageManager) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid HA configuration: %w", err)
	}

	// Load configuration from environment
	if err := cfg.LoadFromEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to load HA configuration from environment: %w", err)
	}

	// Debug logging for NodeID tracking and timing configuration
	logger.Info("DEBUG: HA Manager initialization",
		"node_id_after_env_load", cfg.Node.ID,
		"node_region", cfg.Node.Region,
		"node_timeout", cfg.Cluster.Discovery.NodeTimeout,
		"election_timeout", cfg.Cluster.ElectionTimeout,
		"heartbeat_interval", cfg.Cluster.HeartbeatInterval)

	// Generate node ID if not provided
	if cfg.Node.ID == "" {
		nodeID, err := generateNodeID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate node ID: %w", err)
		}
		cfg.Node.ID = nodeID
		logger.Info("DEBUG: Generated node ID", "generated_id", nodeID)
	}

	// Set default node name if not provided
	if cfg.Node.Name == "" {
		cfg.Node.Name = fmt.Sprintf("controller-%s", cfg.Node.ID[:8])
	}

	// Create node info
	nodeInfo := &NodeInfo{
		ID:               cfg.Node.ID,
		Address:          cfg.Node.ExternalAddress,
		State:            NodeStateHealthy,
		Role:             NodeRoleFollower,
		StartedAt:        time.Now(),
		Version:          version.Short(),
		Capabilities:     cfg.Node.Capabilities,
		Region:           cfg.Node.Region,
		AvailabilityZone: cfg.Node.AvailabilityZone,
		Coordinates:      cfg.Node.Coordinates,
		Latency:          make(map[string]time.Duration),
	}

	// Debug logging for NodeInfo creation
	logger.Info("DEBUG: Created NodeInfo",
		"node_id", nodeInfo.ID,
		"region", nodeInfo.Region,
		"address", nodeInfo.Address)

	// For single server mode, this node is always the leader
	if cfg.Mode == SingleServerMode {
		nodeInfo.Role = NodeRoleLeader
	}

	manager := &Manager{
		cfg:            cfg,
		logger:         logger,
		nodeInfo:       nodeInfo,
		storageManager: storageManager,
		clusterNodes:   make(map[string]*NodeInfo),
		healthChecks:   make(map[string]HealthCheckFunc),
		healthStatus: &HealthStatus{
			Overall:   NodeStateHealthy,
			Checks:    make(map[string]NodeState),
			Timestamp: time.Now(),
			Details:   make(map[string]string),
		},
		isLeader: cfg.Mode == SingleServerMode, // Single server is always leader
	}

	// Add this node to cluster nodes
	manager.clusterNodes[nodeInfo.ID] = nodeInfo

	// Initialize components based on deployment mode
	manager.logger.Info("DEBUG: About to call initializeComponents()...")
	if err := manager.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize HA components: %w", err)
	}
	manager.logger.Info("DEBUG: initializeComponents() completed successfully")

	manager.logger.Info("HA Manager initialized",
		"mode", cfg.GetModeString(),
		"node_id", nodeInfo.ID)

	return manager, nil
}

// Start begins the HA operations
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

	m.logger.Info("Starting HA Manager", "mode", m.cfg.GetModeString())

	// Start health checker
	m.logger.Info("DEBUG: About to start health checker...")
	if m.healthChecker != nil {
		if err := m.healthChecker.Start(m.ctx); err != nil {
			return fmt.Errorf("failed to start health checker: %w", err)
		}
	}
	m.logger.Info("DEBUG: Health checker started successfully")

	// Start components based on deployment mode
	m.logger.Info("DEBUG: About to start components based on deployment mode", "mode", m.cfg.Mode)
	switch m.cfg.Mode {
	case ClusterMode:
		m.logger.Info("DEBUG: Starting cluster mode...")
		if err := m.startClusterMode(); err != nil {
			return fmt.Errorf("failed to start cluster mode: %w", err)
		}
		m.logger.Info("DEBUG: Cluster mode started successfully")
	case BlueGreenMode:
		m.logger.Info("DEBUG: Starting blue-green mode...")
		if err := m.startBlueGreenMode(); err != nil {
			return fmt.Errorf("failed to start blue-green mode: %w", err)
		}
		m.logger.Info("DEBUG: Blue-green mode started successfully")
	case SingleServerMode:
		m.logger.Info("Running in single server mode - no additional HA components needed")
	}

	m.isStarted = true
	m.logger.Info("HA Manager started successfully")

	return nil
}

// Stop gracefully stops the HA operations
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isStarted {
		return nil
	}

	m.logger.Info("Stopping HA Manager")

	// Cancel the context to stop all background operations
	if m.cancel != nil {
		m.cancel()
	}

	// Stop all components
	var stopErrors []error

	if m.healthChecker != nil {
		if err := m.healthChecker.Stop(ctx); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("health checker stop: %w", err))
		}
	}

	if m.discovery != nil {
		if err := m.discovery.Stop(ctx); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("discovery stop: %w", err))
		}
	}

	if m.failover != nil {
		if err := m.failover.Stop(ctx); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("failover stop: %w", err))
		}
	}

	if m.splitBrain != nil {
		if err := m.splitBrain.Stop(ctx); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("split-brain detector stop: %w", err))
		}
	}

	if m.sessionSync != nil {
		if err := m.sessionSync.(*sessionSynchronizer).Stop(ctx); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("session sync stop: %w", err))
		}
	}

	m.isStarted = false

	if len(stopErrors) > 0 {
		return fmt.Errorf("errors during HA manager stop: %v", stopErrors)
	}

	m.logger.Info("HA Manager stopped successfully")
	return nil
}

// GetDeploymentMode returns the current deployment mode
func (m *Manager) GetDeploymentMode() DeploymentMode {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Mode
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

// GetClusterNodes returns information about all nodes in the cluster
func (m *Manager) GetClusterNodes() ([]*NodeInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Use Raft consensus if available (NEW)
	if m.raftConsensus != nil {
		return m.raftConsensus.GetClusterNodes(), nil
	}

	// If old discovery is available, use it (DEPRECATED)
	if m.discovery != nil {
		discoveredNodes, err := m.discovery.DiscoverNodes()
		if err != nil {
			m.logger.Warn("Failed to discover nodes, falling back to local view", "error", err)
		} else if len(discoveredNodes) > 0 {
			return discoveredNodes, nil
		}
	}

	// Fallback to local cluster nodes map
	nodes := make([]*NodeInfo, 0, len(m.clusterNodes))
	for _, node := range m.clusterNodes {
		// Create a copy to prevent modification
		nodeCopy := *node
		nodes = append(nodes, &nodeCopy)
	}

	return nodes, nil
}

// IsLeader returns true if this node is the cluster leader
func (m *Manager) IsLeader() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Use Raft consensus if available (NEW)
	if m.raftConsensus != nil {
		return m.raftConsensus.IsLeader()
	}

	// Fallback to old method (DEPRECATED)
	return m.isLeader
}

// GetLeader returns the current cluster leader node
func (m *Manager) GetLeader() (*NodeInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Use Raft consensus if available (NEW)
	if m.raftConsensus != nil {
		return m.raftConsensus.GetLeaderInfo()
	}

	// Fallback to old method (DEPRECATED)
	if m.currentLeader == "" {
		return nil, fmt.Errorf("no leader elected")
	}

	if leader, exists := m.clusterNodes[m.currentLeader]; exists {
		// Create a copy to prevent modification
		leaderCopy := *leader
		return &leaderCopy, nil
	}

	return nil, fmt.Errorf("leader node not found")
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

// GetRaftTransport returns the Raft transport for HTTP endpoint handling
func (m *Manager) GetRaftTransport() RaftTransport {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.raftConsensus == nil {
		return nil
	}

	return m.raftConsensus.transport
}

// initializeComponents initializes HA components based on deployment mode
func (m *Manager) initializeComponents() error {
	// Always initialize health checker
	m.healthChecker = NewHealthChecker(m.cfg.HealthCheck, m.logger, m)

	// Register basic health checks
	m.registerBasicHealthChecks()

	// Initialize mode-specific components
	switch m.cfg.Mode {
	case ClusterMode:
		return m.initializeClusterComponents()
	case BlueGreenMode:
		return m.initializeBlueGreenComponents()
	case SingleServerMode:
		// No additional components needed for single server mode
		return nil
	default:
		return fmt.Errorf("unsupported deployment mode: %s", m.cfg.Mode)
	}
}

// initializeClusterComponents initializes components for cluster mode
func (m *Manager) initializeClusterComponents() error {
	var err error

	// Initialize Raft consensus (replaces old discovery + custom leader election)
	m.logger.Info("DEBUG: About to initialize Raft consensus...")
	if err := m.initializeRaftConsensus(); err != nil {
		return fmt.Errorf("failed to initialize Raft consensus: %w", err)
	}
	m.logger.Info("DEBUG: Raft consensus initialization completed successfully")

	// DEPRECATED: Old discovery - kept temporarily for compatibility
	// TODO: Remove after full Raft migration
	m.logger.Info("DEBUG: About to initialize legacy discovery (deprecated)...")
	m.discovery, err = NewDiscovery(m.cfg.Cluster.Discovery, m.logger, m)
	if err != nil {
		return fmt.Errorf("failed to initialize discovery: %w", err)
	}
	m.logger.Info("DEBUG: Legacy discovery initialization completed successfully")

	// Re-enabled LoadBalancer component - Step 2 of systematic HA re-enabling
	m.logger.Info("DEBUG: About to initialize load balancer...")
	m.loadBalancer, err = NewLoadBalancer(m.cfg.LoadBalancing, m.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize load balancer: %w", err)
	}
	m.logger.Info("DEBUG: Load balancer initialization completed successfully")

	// Re-enabled FailoverManager component - Step 3 of systematic HA re-enabling
	m.logger.Info("DEBUG: About to initialize failover manager...")
	m.failover, err = NewFailoverManager(m.cfg.Failover, m.logger, m)
	if err != nil {
		return fmt.Errorf("failed to initialize failover manager: %w", err)
	}
	m.logger.Info("DEBUG: Failover manager initialization completed successfully")

	// Re-enabled SplitBrainDetector component - Step 4 of systematic HA re-enabling
	m.logger.Info("DEBUG: About to initialize split-brain detector...")
	m.splitBrain, err = NewSplitBrainDetector(m.cfg.SplitBrain, m.logger, m)
	if err != nil {
		return fmt.Errorf("failed to initialize split-brain detector: %w", err)
	}
	m.logger.Info("DEBUG: Split-brain detector initialization completed successfully")

	// Re-enabled SessionSynchronizer component - Step 5 of systematic HA re-enabling (FINAL COMPONENT!)
	m.logger.Info("DEBUG: About to initialize session synchronizer...")
	m.sessionSync, err = NewSessionSynchronizer(m.cfg.Cluster.SessionSync, m.logger, m.storageManager, m)
	if err != nil {
		return fmt.Errorf("failed to initialize session synchronizer: %w", err)
	}
	m.logger.Info("DEBUG: Session synchronizer initialization completed successfully")

	return nil
}

// initializeRaftConsensus initializes the Raft consensus layer
func (m *Manager) initializeRaftConsensus() error {
	// Parse node ID as uint64 for Raft
	// Use a simple hash of the node ID string
	nodeID := hashStringToUint64(m.nodeInfo.ID)

	log.Printf("RAFT_INIT: Starting Raft consensus initialization, node_id_string=%s, node_id_uint64=%d, node_address=%s",
		m.nodeInfo.ID, nodeID, m.nodeInfo.Address)

	// Build peer list from cluster configuration
	peers := make([]raft.Peer, 0)

	// Parse cluster nodes from config
	log.Printf("RAFT_INIT: Parsing cluster nodes from config, config_nil=%t", m.cfg.Cluster.Discovery.Config == nil)

	if clusterNodes := m.cfg.Cluster.Discovery.Config["nodes"]; clusterNodes != nil {
		log.Printf("RAFT_INIT: Found cluster nodes in config, type=%T", clusterNodes)
		// Try both []interface{} and []map[string]interface{} type assertions
		if nodes, ok := clusterNodes.([]interface{}); ok {
			log.Printf("RAFT_INIT: Cluster nodes is []interface{}, count=%d", len(nodes))
			for i, n := range nodes {
				if nodeMap, ok := n.(map[string]interface{}); ok {
					if id, ok := nodeMap["id"].(string); ok {
						peerID := hashStringToUint64(id)
						peers = append(peers, raft.Peer{
							ID:      peerID,
							Context: []byte(id), // Store original string ID
						})
						log.Printf("RAFT_INIT: Added peer to list, index=%d, peer_id_string=%s, peer_id_uint64=%d", i, id, peerID)
					}
				}
			}
		} else if nodes, ok := clusterNodes.([]map[string]interface{}); ok {
			log.Printf("RAFT_INIT: Cluster nodes is []map[string]interface{}, count=%d", len(nodes))
			for i, nodeMap := range nodes {
				if id, ok := nodeMap["id"].(string); ok {
					peerID := hashStringToUint64(id)
					peers = append(peers, raft.Peer{
						ID:      peerID,
						Context: []byte(id), // Store original string ID
					})
					log.Printf("RAFT_INIT: Added peer to list, index=%d, peer_id_string=%s, peer_id_uint64=%d", i, id, peerID)
				}
			}
		} else {
			log.Printf("RAFT_INIT: Cluster nodes has unexpected type: %T", clusterNodes)
		}
	} else {
		log.Printf("RAFT_INIT: No cluster nodes found in config")
	}

	// Create Raft consensus
	var err error
	m.raftConsensus, err = NewRaftConsensus(context.Background(), nodeID, m.nodeInfo, peers, m.logger)
	if err != nil {
		return fmt.Errorf("failed to create Raft consensus: %w", err)
	}

	// Create and attach transport
	transport := newRaftTransport(nodeID, m.nodeInfo.Address, m.raftConsensus)
	m.raftConsensus.transport = transport

	// Add peer addresses to transport
	log.Printf("RAFT_INIT: Configuring peer addresses for transport")
	peerCount := 0
	if clusterNodes := m.cfg.Cluster.Discovery.Config["nodes"]; clusterNodes != nil {
		// Try both []interface{} and []map[string]interface{} type assertions
		if nodes, ok := clusterNodes.([]interface{}); ok {
			log.Printf("RAFT_INIT: Processing peer addresses ([]interface{}), total_nodes=%d", len(nodes))
			for i, n := range nodes {
				if nodeMap, ok := n.(map[string]interface{}); ok {
					if id, ok := nodeMap["id"].(string); ok {
						if addr, ok := nodeMap["address"].(string); ok {
							peerID := hashStringToUint64(id)
							if peerID != nodeID { // Don't add self
								transport.AddPeer(peerID, addr)
								peerCount++
								log.Printf("RAFT_INIT: Added peer address to transport, index=%d, peer_id_string=%s, peer_id_uint64=%d, address=%s",
									i, id, peerID, addr)
							} else {
								log.Printf("RAFT_INIT: Skipped self in peer list, node_id=%s", id)
							}
						} else {
							log.Printf("RAFT_INIT: Node missing address, index=%d, node_id=%s", i, id)
						}
					}
				}
			}
		} else if nodes, ok := clusterNodes.([]map[string]interface{}); ok {
			log.Printf("RAFT_INIT: Processing peer addresses ([]map), total_nodes=%d", len(nodes))
			for i, nodeMap := range nodes {
				if id, ok := nodeMap["id"].(string); ok {
					if addr, ok := nodeMap["address"].(string); ok {
						peerID := hashStringToUint64(id)
						if peerID != nodeID { // Don't add self
							transport.AddPeer(peerID, addr)
							peerCount++
							log.Printf("RAFT_INIT: Added peer address to transport, index=%d, peer_id_string=%s, peer_id_uint64=%d, address=%s",
								i, id, peerID, addr)
						} else {
							log.Printf("RAFT_INIT: Skipped self in peer list, node_id=%s", id)
						}
					} else {
						log.Printf("RAFT_INIT: Node missing address, index=%d, node_id=%s", i, id)
					}
				}
			}
		}
	}

	log.Printf("RAFT_INIT: Raft consensus initialized, node_id=%d, total_peers=%d, configured_peer_addresses=%d",
		nodeID, len(peers), peerCount)

	return nil
}

// hashStringToUint64 converts a string to a deterministic uint64
func hashStringToUint64(s string) uint64 {
	var hash uint64
	for i := 0; i < len(s); i++ {
		hash = hash*31 + uint64(s[i])
	}
	return hash
}

// initializeBlueGreenComponents initializes components for blue-green mode
func (m *Manager) initializeBlueGreenComponents() error {
	// For blue-green mode, we need minimal components
	var err error

	// Initialize a simple discovery for blue-green pair
	m.discovery, err = NewDiscovery(m.cfg.Cluster.Discovery, m.logger, m)
	if err != nil {
		return fmt.Errorf("failed to initialize discovery for blue-green: %w", err)
	}

	return nil
}

// startClusterMode starts components for cluster mode
func (m *Manager) startClusterMode() error {
	m.logger.Info("DEBUG: Starting cluster mode components...")

	// Start Raft consensus (NEW - replaces old leader election)
	if m.raftConsensus != nil {
		m.logger.Info("DEBUG: About to start Raft consensus...")
		if err := m.raftConsensus.Start(); err != nil {
			return fmt.Errorf("failed to start Raft consensus: %w", err)
		}
		m.logger.Info("DEBUG: Raft consensus started successfully")
	}

	// DEPRECATED: Old discovery - will be removed
	if m.discovery != nil {
		m.logger.Info("DEBUG: About to start legacy discovery component (deprecated)...")
		if err := m.discovery.Start(m.ctx); err != nil {
			return fmt.Errorf("failed to start discovery: %w", err)
		}
		m.logger.Info("DEBUG: Legacy discovery component started successfully")
	} else {
		m.logger.Info("DEBUG: Discovery component is nil (disabled), skipping start")
	}

	if m.failover != nil {
		m.logger.Info("DEBUG: About to start failover manager component...")
		if err := m.failover.Start(m.ctx); err != nil {
			return fmt.Errorf("failed to start failover manager: %w", err)
		}
		m.logger.Info("DEBUG: Failover manager component started successfully")
	} else {
		m.logger.Info("DEBUG: Failover manager component is nil (disabled), skipping start")
	}

	if m.splitBrain != nil {
		m.logger.Info("DEBUG: About to start split-brain detector component...")
		if err := m.splitBrain.Start(m.ctx); err != nil {
			return fmt.Errorf("failed to start split-brain detector: %w", err)
		}
		m.logger.Info("DEBUG: Split-brain detector component started successfully")
	} else {
		m.logger.Info("DEBUG: Split-brain detector component is nil (disabled), skipping start")
	}

	if m.sessionSync != nil {
		m.logger.Info("DEBUG: Session synchronizer component enabled and ready")
	} else {
		m.logger.Info("DEBUG: Session synchronizer component is nil (disabled), skipping")
	}

	// Perform initial leader election for cluster mode
	m.logger.Info("DEBUG: Starting initial leader election...")
	go m.performInitialLeaderElection()

	m.logger.Info("DEBUG: All cluster mode components started successfully")
	return nil
}

// startBlueGreenMode starts components for blue-green mode
func (m *Manager) startBlueGreenMode() error {
	if m.discovery != nil {
		if err := m.discovery.Start(m.ctx); err != nil {
			return fmt.Errorf("failed to start discovery for blue-green: %w", err)
		}
	}

	return nil
}

// registerBasicHealthChecks registers basic health checks
func (m *Manager) registerBasicHealthChecks() {
	// Register storage health check
	m.RegisterHealthCheck("storage", func(ctx context.Context) error {
		store := m.storageManager.GetConfigStore()
		if store == nil {
			return fmt.Errorf("config store not available")
		}
		return nil
	})

	// Register memory health check
	m.RegisterHealthCheck("memory", func(ctx context.Context) error {
		// Simple memory health check - could be enhanced with actual memory monitoring
		return nil
	})

	// Register disk health check
	m.RegisterHealthCheck("disk", func(ctx context.Context) error {
		// Simple disk health check - could be enhanced with actual disk space monitoring
		return nil
	})
}

// generateNodeID generates a unique node ID
func generateNodeID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// updateNodeState updates the state of a cluster node (reserved for future use)
// func (m *Manager) updateNodeState(nodeID string, state NodeState) {
// 	m.mu.Lock()
// 	defer m.mu.Unlock()
//
// 	if node, exists := m.clusterNodes[nodeID]; exists {
// 		node.State = state
// 		node.LastSeen = time.Now()
// 		m.logger.Debug("Node state updated", "node_id", nodeID, "state", state.String())
// 	}
// }

// promoteToLeader promotes this node to leader
func (m *Manager) promoteToLeader() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isLeader {
		m.isLeader = true
		m.nodeInfo.Role = NodeRoleLeader
		m.currentLeader = m.nodeInfo.ID
		m.logger.Info("Node promoted to leader", "node_id", m.nodeInfo.ID)
	}
}

// demoteFromLeader demotes this node from leader
func (m *Manager) demoteFromLeader() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isLeader {
		m.isLeader = false
		m.nodeInfo.Role = NodeRoleFollower
		m.logger.Info("Node demoted from leader", "node_id", m.nodeInfo.ID)
	}
}

// performInitialLeaderElection performs the initial leader election for cluster mode
// triggerLeaderElection triggers a new leader election with available nodes
func (m *Manager) triggerLeaderElection(reason string) {
	m.logger.Info("Triggering leader election", "reason", reason)

	// Get current cluster nodes
	nodes, err := m.GetClusterNodes()
	if err != nil {
		m.logger.Error("Failed to get cluster nodes for election", "error", err)
		return
	}

	// Collect healthy candidates
	var candidates []*NodeInfo
	for _, node := range nodes {
		if node.State == NodeStateHealthy {
			candidates = append(candidates, node)
		}
	}

	if len(candidates) == 0 {
		m.logger.Warn("No healthy candidates for leader election")
		// As fallback, promote self if no other nodes found
		localNode := m.GetLocalNode()
		m.logger.Info("No other candidates found, promoting self as leader", "node_id", localNode.ID)
		m.promoteToLeader()
		return
	}

	// Find the candidate with the lowest ID (lexicographically) - deterministic election
	var chosenLeader *NodeInfo
	for _, candidate := range candidates {
		if chosenLeader == nil || candidate.ID < chosenLeader.ID {
			chosenLeader = candidate
		}
	}

	if chosenLeader == nil {
		m.logger.Error("Failed to select leader from candidates")
		return
	}

	localNode := m.GetLocalNode()
	m.logger.Info("Leader election result",
		"chosen_leader", chosenLeader.ID,
		"local_node", localNode.ID,
		"total_candidates", len(candidates),
		"reason", reason)

	if chosenLeader.ID == localNode.ID {
		// This node should become the leader
		m.logger.Info("Local node selected as new leader", "node_id", localNode.ID)
		m.promoteToLeader()
	} else {
		// Another node should be the leader
		m.logger.Info("Remote node selected as new leader",
			"leader_id", chosenLeader.ID,
			"local_id", localNode.ID)

		m.mu.Lock()
		m.currentLeader = chosenLeader.ID
		m.mu.Unlock()
	}
}

func (m *Manager) performInitialLeaderElection() {
	m.logger.Info("DEBUG: Starting initial leader election process...")

	// Wait for discovery to find other nodes in the cluster
	// We need to wait until we can see other cluster members before electing a leader
	const maxRetries = 30 // Max wait time is 60 seconds (30 * 2s)
	const retryDelay = 2 * time.Second

	// Get expected node count - default for 3-node test cluster
	expectedNodes := 3

	m.logger.Info("DEBUG: Waiting for node discovery before leader election",
		"expected_nodes", expectedNodes,
		"max_wait_time", maxRetries*int(retryDelay.Seconds()))

	var nodes []*NodeInfo
	var err error

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Check if any leader is already elected by another node
		m.mu.RLock()
		hasLeader := m.currentLeader != ""
		m.mu.RUnlock()

		if hasLeader {
			m.logger.Info("DEBUG: Leader already exists, skipping initial election")
			return
		}

		// Try to get cluster nodes
		nodes, err = m.GetClusterNodes()
		if err != nil {
			m.logger.Warn("Failed to get cluster nodes, retrying...", "error", err, "attempt", attempt+1)
			time.Sleep(retryDelay)
			continue
		}

		// Count healthy nodes
		healthyNodes := 0
		for _, node := range nodes {
			if node.State == NodeStateHealthy {
				healthyNodes++
			}
		}

		m.logger.Debug("DEBUG: Discovery progress",
			"discovered_nodes", len(nodes),
			"healthy_nodes", healthyNodes,
			"expected_nodes", expectedNodes,
			"attempt", attempt+1)

		// If we've discovered enough nodes (at least 2 for a 3-node cluster), proceed with election
		minNodesForElection := (expectedNodes + 1) / 2 // Majority of expected nodes
		if healthyNodes >= minNodesForElection {
			m.logger.Info("DEBUG: Sufficient nodes discovered for leader election",
				"healthy_nodes", healthyNodes,
				"min_required", minNodesForElection)
			break
		}

		time.Sleep(retryDelay)
	}

	// Final check for existing leader after discovery wait
	m.mu.RLock()
	hasLeader := m.currentLeader != ""
	m.mu.RUnlock()

	if hasLeader {
		m.logger.Info("DEBUG: Leader already exists after discovery wait, skipping election")
		return
	}

	// Use the common election logic
	m.triggerLeaderElection("initial_election")
}

// getExternalAddress determines the external address for the node (reserved for future use)
// func getExternalAddress() string {
// 	// Try to get the external address from the configuration or environment
// 	if addr := os.Getenv("CFGMS_HA_EXTERNAL_ADDRESS"); addr != "" {
// 		return addr
// 	}
//
// 	// Fallback to detecting the local IP address
// 	conn, err := net.Dial("udp", "8.8.8.8:80")
// 	if err != nil {
// 		return "127.0.0.1:8080" // Default fallback
// 	}
// 	defer func() { _ = conn.Close() }()
//
// 	localAddr := conn.LocalAddr().(*net.UDPAddr)
// 	return fmt.Sprintf("%s:8080", localAddr.IP.String()) // Assume default port
// }
