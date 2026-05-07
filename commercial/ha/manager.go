//go:build commercial
// +build commercial

// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.etcd.io/raft/v3"

	"github.com/cfgis/cfgms/features/config/signature"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	cptypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/transport/registry"
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
	raftConsensus *RaftConsensus
	failover      *failoverManager
	splitBrain    *splitBrainDetector

	// State management
	storageManager *interfaces.StorageManager
	isStarted      bool
	startTime      time.Time
	ctx            context.Context
	cancel         context.CancelFunc

	// Session registry for steward connect/disconnect replication
	registry registry.Registry

	// controlPlaneProvider is used to dispatch reconnect commands to orphaned
	// stewards when this node becomes the Raft leader after a failover.
	controlPlaneProvider cpinterfaces.ControlPlaneProvider

	// signer, if set, signs reconnect commands before dispatch so stewards in
	// secured mode can authenticate them.
	signer signature.Signer

	// Cluster state
	clusterNodes map[string]*NodeInfo

	// Health checks
	healthChecks map[string]HealthCheckFunc
	healthStatus *HealthStatus
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

	// Generate node ID if not provided
	if cfg.Node.ID == "" {
		nodeID, err := generateNodeID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate node ID: %w", err)
		}
		cfg.Node.ID = nodeID
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
	}

	// Add this node to cluster nodes
	manager.clusterNodes[nodeInfo.ID] = nodeInfo

	// Initialize components based on deployment mode
	if err := manager.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize HA components: %w", err)
	}

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

	// Start health checker with a snapshot of currently-registered checks.
	// m.mu is held here so the snapshot is consistent with the map state.
	if m.healthChecker != nil {
		checkSnapshot := make(map[string]HealthCheckFunc, len(m.healthChecks))
		for name, fn := range m.healthChecks {
			checkSnapshot[name] = fn
		}
		if err := m.healthChecker.Start(m.ctx, checkSnapshot); err != nil {
			return fmt.Errorf("failed to start health checker: %w", err)
		}
	}

	switch m.cfg.Mode {
	case ClusterMode:
		if err := m.startClusterMode(); err != nil {
			return fmt.Errorf("failed to start cluster mode: %w", err)
		}
	case BlueGreenMode:
		if err := m.startBlueGreenMode(); err != nil {
			return fmt.Errorf("failed to start blue-green mode: %w", err)
		}
	case SingleServerMode:
		m.logger.Info("Running in single server mode - no additional HA components needed")
	}

	// Register session hooks so steward connect/disconnect events are replicated
	// through the Raft log when running in cluster mode.
	if m.raftConsensus != nil && m.registry != nil {
		rc := m.raftConsensus
		nodeID := m.nodeInfo.ID
		m.registry.OnConnect(func(stewardID string) {
			if err := rc.ProposeSessionUpdate(stewardID, nodeID, true); err != nil {
				m.logger.Warn("Failed to propose session connect",
					"steward_id", logging.SanitizeLogValue(stewardID), "error", err)
			}
		})
		m.registry.OnDisconnect(func(stewardID string) {
			if err := rc.ProposeSessionUpdate(stewardID, nodeID, false); err != nil {
				m.logger.Warn("Failed to propose session disconnect",
					"steward_id", logging.SanitizeLogValue(stewardID), "error", err)
			}
		})
	}

	// Wire the onBecomeLeader callback so the Raft consensus layer notifies the
	// manager when leadership transitions — the manager then dispatches reconnect
	// commands to stewards orphaned by the departed leader.
	if m.raftConsensus != nil {
		rc := m.raftConsensus
		rc.onBecomeLeader = func(ctx context.Context, departedNodeID string) {
			go m.handleBecomeLeader(ctx, departedNodeID)
		}
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

	if m.raftConsensus != nil {
		if err := m.raftConsensus.Stop(); err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("raft consensus stop: %w", err))
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

// GetCACertPEM returns the CA certificate PEM bytes for HA peer verification.
// Returns nil when CACertPath is empty or the file cannot be read; logs a warning
// on read failure so operators can detect misconfiguration.
// Safe to call concurrently.
func (m *Manager) GetCACertPEM() []byte {
	m.mu.RLock()
	path := m.cfg.CACertPath
	m.mu.RUnlock()

	if path == "" {
		return nil
	}

	// #nosec G304 -- certificate paths are operator-controlled configuration values
	certPEM, err := os.ReadFile(path)
	if err != nil {
		m.logger.Warn("Failed to read HA CA certificate", "path", path, "error", err)
		return nil
	}
	return certPEM
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

	// Use Raft consensus as the single source of truth for cluster membership
	if m.raftConsensus != nil {
		return m.raftConsensus.GetClusterNodes(), nil
	}

	// Fallback to local cluster nodes map (for SingleServerMode)
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

	// Single server mode is always the leader
	if m.cfg.Mode == SingleServerMode {
		return true
	}

	// Raft consensus is the sole authority for leadership
	if m.raftConsensus != nil {
		return m.raftConsensus.IsLeader()
	}

	return false
}

// GetLeader returns the current cluster leader node
func (m *Manager) GetLeader() (*NodeInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Single server mode: local node is always the leader
	if m.cfg.Mode == SingleServerMode {
		nodeInfo := *m.nodeInfo
		return &nodeInfo, nil
	}

	// Raft consensus is the sole authority for leadership
	if m.raftConsensus != nil {
		return m.raftConsensus.GetLeaderInfo()
	}

	return nil, fmt.Errorf("no leader elected")
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
	rc := m.raftConsensus
	m.mu.RUnlock()

	if rc == nil {
		return nil
	}

	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.transport
}

// SetRegistry wires the active-steward connection registry so that connect and
// disconnect events are replicated through the Raft log (Issue #1326).
// Call this after NewManager returns but before Start is called.
func (m *Manager) SetRegistry(r registry.Registry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registry = r
}

// SetControlPlaneProvider wires the control-plane provider so that reconnect
// commands can be dispatched to orphaned stewards on leadership transition.
// Call this after NewManager returns but before Start is called.
func (m *Manager) SetControlPlaneProvider(p cpinterfaces.ControlPlaneProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.controlPlaneProvider = p
}

// SetSigner wires a command signer so that reconnect commands are cryptographically
// signed before dispatch. Call this after NewManager returns but before Start is called.
// When nil (the default), commands are sent unsigned — only suitable for clusters
// where stewards have not configured a command verifier.
func (m *Manager) SetSigner(s signature.Signer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signer = s
}

// handleBecomeLeader dispatches CommandReconnect to every steward whose session
// was registered to departedNodeID so they re-establish their ControlChannel
// against the new leader. Runs in a goroutine to avoid blocking the Raft loop.
func (m *Manager) handleBecomeLeader(ctx context.Context, departedNodeID string) {
	if departedNodeID == "" {
		return
	}

	m.mu.RLock()
	cp := m.controlPlaneProvider
	rc := m.raftConsensus
	signer := m.signer
	m.mu.RUnlock()

	if cp == nil || rc == nil {
		return
	}

	stewardIDs := rc.GetSessionsForNode(departedNodeID)
	m.logger.Info("Became leader, dispatching reconnect to orphaned stewards",
		"departed_node_id", logging.SanitizeLogValue(departedNodeID),
		"steward_count", len(stewardIDs))

	for _, stewardID := range stewardIDs {
		cmd := &cptypes.SignedCommand{
			Command: cptypes.Command{
				ID:        uuid.New().String(),
				Type:      cptypes.CommandReconnect,
				StewardID: stewardID,
				Timestamp: time.Now(),
			},
		}
		if signer != nil {
			signingBytes, err := cptypes.CommandSigningBytes(&cmd.Command, nil)
			if err != nil {
				m.logger.Warn("Failed to compute signing bytes for reconnect command",
					"steward_id", logging.SanitizeLogValue(stewardID), "error", err)
				continue
			}
			sig, err := signer.Sign(signingBytes)
			if err != nil {
				m.logger.Warn("Failed to sign reconnect command",
					"steward_id", logging.SanitizeLogValue(stewardID), "error", err)
				continue
			}
			cmd.Signature = sig
		}
		if err := cp.SendCommand(ctx, cmd); err != nil {
			m.logger.Warn("Failed to send reconnect command to orphaned steward",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", err)
		} else {
			m.logger.Info("Dispatched reconnect command to orphaned steward",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"command_id", cmd.Command.ID)
		}
	}
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

	// Initialize Raft consensus (sole source of truth for membership and leader election)
	if err := m.initializeRaftConsensus(); err != nil {
		return fmt.Errorf("failed to initialize Raft consensus: %w", err)
	}

	m.failover, err = NewFailoverManager(m.cfg.Failover, m.logger, m)
	if err != nil {
		return fmt.Errorf("failed to initialize failover manager: %w", err)
	}

	m.splitBrain, err = NewSplitBrainDetector(m.cfg.SplitBrain, m.logger, m)
	if err != nil {
		return fmt.Errorf("failed to initialize split-brain detector: %w", err)
	}

	return nil
}

// initializeRaftConsensus initializes the Raft consensus layer
func (m *Manager) initializeRaftConsensus() error {
	// Parse node ID as uint64 for Raft
	// Use a simple hash of the node ID string
	nodeID := hashStringToUint64(m.nodeInfo.ID)

	m.logger.Debug("Starting Raft consensus initialization",
		"node_id_string", m.nodeInfo.ID, "node_id_uint64", nodeID, "node_address", m.nodeInfo.Address)

	// Build peer list from cluster configuration
	peers := make([]raft.Peer, 0)

	// Parse cluster nodes from config
	m.logger.Debug("Parsing cluster nodes from config", "config_nil", m.cfg.Cluster.Discovery.Config == nil)

	// seenHashes guards against node ID hash collisions before they can silently alias
	// two distinct nodes to the same Raft peer ID.
	seenHashes := make(map[uint64]string) // hash → original string ID

	if clusterNodes := m.cfg.Cluster.Discovery.Config["nodes"]; clusterNodes != nil {
		m.logger.Debug("Found cluster nodes in config", "type", fmt.Sprintf("%T", clusterNodes))
		// Try both []interface{} and []map[string]interface{} type assertions
		if nodes, ok := clusterNodes.([]interface{}); ok {
			m.logger.Debug("Cluster nodes is []interface{}", "count", len(nodes))
			for i, n := range nodes {
				if nodeMap, ok := n.(map[string]interface{}); ok {
					if id, ok := nodeMap["id"].(string); ok {
						peerID := hashStringToUint64(id)
						if existing, dup := seenHashes[peerID]; dup {
							return fmt.Errorf("node ID hash collision: %q and %q both hash to %d", existing, id, peerID)
						}
						seenHashes[peerID] = id
						peers = append(peers, raft.Peer{
							ID:      peerID,
							Context: []byte(id), // Store original string ID
						})
						m.logger.Debug("Added peer to list", "index", i, "peer_id_string", id, "peer_id_uint64", peerID)
					}
				}
			}
		} else if nodes, ok := clusterNodes.([]map[string]interface{}); ok {
			m.logger.Debug("Cluster nodes is []map[string]interface{}", "count", len(nodes))
			for i, nodeMap := range nodes {
				if id, ok := nodeMap["id"].(string); ok {
					peerID := hashStringToUint64(id)
					if existing, dup := seenHashes[peerID]; dup {
						return fmt.Errorf("node ID hash collision: %q and %q both hash to %d", existing, id, peerID)
					}
					seenHashes[peerID] = id
					peers = append(peers, raft.Peer{
						ID:      peerID,
						Context: []byte(id), // Store original string ID
					})
					m.logger.Debug("Added peer to list", "index", i, "peer_id_string", id, "peer_id_uint64", peerID)
				}
			}
		} else {
			m.logger.Debug("Cluster nodes has unexpected type", "type", fmt.Sprintf("%T", clusterNodes))
		}
	} else {
		m.logger.Debug("No cluster nodes found in config")
	}

	// Create Raft consensus
	var err error
	m.raftConsensus, err = NewRaftConsensus(context.Background(), nodeID, m.nodeInfo, peers, &m.cfg.Cluster, m.logger)
	if err != nil {
		return fmt.Errorf("failed to create Raft consensus: %w", err)
	}

	// Load CA certificate for TLS validation between cluster nodes
	var caCertPEM []byte
	if m.cfg.CACertPath != "" {
		var readErr error
		caCertPEM, readErr = os.ReadFile(m.cfg.CACertPath)
		if readErr != nil {
			m.logger.Warn("Failed to read CA cert", "path", m.cfg.CACertPath, "error", readErr)
		}
	}

	// Collect allowed peer CNs for mTLS verification on /raft/message.
	// The local node's own CN is included first so single-node loopback messages
	// are accepted without requiring a second allowlist entry.
	allowedCNs := []string{m.nodeInfo.ID}
	if clusterNodes := m.cfg.Cluster.Discovery.Config["nodes"]; clusterNodes != nil {
		if nodes, ok := clusterNodes.([]interface{}); ok {
			for _, n := range nodes {
				if nodeMap, ok := n.(map[string]interface{}); ok {
					if id, ok := nodeMap["id"].(string); ok && id != m.nodeInfo.ID {
						allowedCNs = append(allowedCNs, id)
					}
				}
			}
		} else if nodes, ok := clusterNodes.([]map[string]interface{}); ok {
			for _, nodeMap := range nodes {
				if id, ok := nodeMap["id"].(string); ok && id != m.nodeInfo.ID {
					allowedCNs = append(allowedCNs, id)
				}
			}
		}
	}

	// Create and attach transport
	transport := newRaftTransport(nodeID, m.nodeInfo.Address, m.raftConsensus, caCertPEM, allowedCNs, m.logger)
	m.raftConsensus.SetTransport(transport)

	// Add peer addresses to transport
	m.logger.Debug("Configuring peer addresses for transport")
	peerCount := 0
	if clusterNodes := m.cfg.Cluster.Discovery.Config["nodes"]; clusterNodes != nil {
		// Try both []interface{} and []map[string]interface{} type assertions
		if nodes, ok := clusterNodes.([]interface{}); ok {
			m.logger.Debug("Processing peer addresses ([]interface{})", "total_nodes", len(nodes))
			for i, n := range nodes {
				if nodeMap, ok := n.(map[string]interface{}); ok {
					if id, ok := nodeMap["id"].(string); ok {
						if addr, ok := nodeMap["address"].(string); ok {
							peerID := hashStringToUint64(id)
							if peerID != nodeID { // Don't add self
								transport.AddPeer(peerID, addr)
								peerCount++
								m.logger.Debug("Added peer address to transport",
									"index", i, "peer_id_string", id, "peer_id_uint64", peerID, "address", addr)
							} else {
								m.logger.Debug("Skipped self in peer list", "node_id", id)
							}
						} else {
							m.logger.Debug("Node missing address", "index", i, "node_id", id)
						}
					}
				}
			}
		} else if nodes, ok := clusterNodes.([]map[string]interface{}); ok {
			m.logger.Debug("Processing peer addresses ([]map)", "total_nodes", len(nodes))
			for i, nodeMap := range nodes {
				if id, ok := nodeMap["id"].(string); ok {
					if addr, ok := nodeMap["address"].(string); ok {
						peerID := hashStringToUint64(id)
						if peerID != nodeID { // Don't add self
							transport.AddPeer(peerID, addr)
							peerCount++
							m.logger.Debug("Added peer address to transport",
								"index", i, "peer_id_string", id, "peer_id_uint64", peerID, "address", addr)
						} else {
							m.logger.Debug("Skipped self in peer list", "node_id", id)
						}
					} else {
						m.logger.Debug("Node missing address", "index", i, "node_id", id)
					}
				}
			}
		}
	}

	m.logger.Debug("Raft consensus initialized",
		"node_id", nodeID, "total_peers", len(peers), "configured_peer_addresses", peerCount)

	return nil
}

// hashStringToUint64 converts a string to a deterministic uint64 using FNV-1a 64-bit.
// FNV-1a has negligible collision probability for the node-count range (3–50 nodes)
// and avoids the aliasing risk of the old polynomial (31-based) hash.
func hashStringToUint64(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// initializeBlueGreenComponents initializes components for blue-green mode.
// Discovery has been removed; blue-green mode requires no additional components.
func (m *Manager) initializeBlueGreenComponents() error {
	return nil
}

// startClusterMode starts components for cluster mode
func (m *Manager) startClusterMode() error {
	// Start Raft consensus (sole authority for membership and leader election)
	if m.raftConsensus != nil {
		if err := m.raftConsensus.Start(); err != nil {
			return fmt.Errorf("failed to start Raft consensus: %w", err)
		}

		// Replicate local node metadata through the Raft log once a leader exists.
		// Proposals sent before leader election are dropped, so we wait for
		// leaderElectedC (closed by the Raft loop on first leader detection)
		// before calling ProposeNodeUpdate. The goroutine is bounded by m.ctx.
		rc := m.raftConsensus
		nodeInfo := m.nodeInfo
		go func() {
			select {
			case <-rc.leaderElectedC:
				if err := rc.ProposeNodeUpdate(nodeInfo); err != nil {
					m.logger.Warn("Failed to propose initial node update", "error", err)
				}
			case <-m.ctx.Done():
				return
			}
		}()

		// Propose add-node ConfChanges for each peer known at startup.
		// These are non-critical (initial membership is bootstrapped via StartNode);
		// failures are logged but do not block cluster startup.
		localNodeID := hashStringToUint64(m.nodeInfo.ID)
		if nodes := m.cfg.Cluster.Discovery.Config["nodes"]; nodes != nil {
			if nodeList, ok := nodes.([]interface{}); ok {
				for _, n := range nodeList {
					nodeMap, ok := n.(map[string]interface{})
					if !ok {
						continue
					}
					id, ok := nodeMap["id"].(string)
					if !ok {
						continue
					}
					peerID := hashStringToUint64(id)
					if peerID == localNodeID {
						continue
					}
					addr, _ := nodeMap["address"].(string)
					peerInfo := &NodeInfo{ID: id, Address: addr}
					if err := m.raftConsensus.ProposeAddNode(peerID, peerInfo); err != nil {
						m.logger.Warn("Failed to propose add-node for peer", "peer_id", peerID, "error", err)
					}
				}
			}
		}
	}

	if m.failover != nil {
		if err := m.failover.Start(m.ctx); err != nil {
			return fmt.Errorf("failed to start failover manager: %w", err)
		}
	}

	if m.splitBrain != nil {
		if err := m.splitBrain.Start(m.ctx); err != nil {
			return fmt.Errorf("failed to start split-brain detector: %w", err)
		}
	}

	return nil
}

// startBlueGreenMode starts components for blue-green mode.
// Discovery has been removed; blue-green mode starts with no additional components.
func (m *Manager) startBlueGreenMode() error {
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
