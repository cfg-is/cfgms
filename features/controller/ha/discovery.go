package ha

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// Discovery interface for node discovery
type Discovery interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	DiscoverNodes() ([]*NodeInfo, error)
	RegisterNode(node *NodeInfo) error
	UnregisterNode(nodeID string) error
}

// staticDiscovery implements Discovery for static node configuration
type staticDiscovery struct {
	mu       sync.RWMutex
	cfg      *DiscoveryConfig
	logger   logging.Logger
	manager  *Manager
	nodes    map[string]*NodeInfo
	ctx      context.Context
	cancel   context.CancelFunc
	started  bool
}

// NewDiscovery creates a new Discovery instance based on configuration
func NewDiscovery(cfg *DiscoveryConfig, logger logging.Logger, manager *Manager) (Discovery, error) {
	if cfg == nil {
		return nil, fmt.Errorf("discovery configuration is required")
	}

	switch strings.ToLower(cfg.Method) {
	case "static":
		return newStaticDiscovery(cfg, logger, manager)
	case "geographic":
		return newGeographicDiscovery(cfg, logger, manager)
	default:
		return nil, fmt.Errorf("unsupported discovery method: %s", cfg.Method)
	}
}

// newStaticDiscovery creates a new static discovery instance
func newStaticDiscovery(cfg *DiscoveryConfig, logger logging.Logger, manager *Manager) (*staticDiscovery, error) {
	return &staticDiscovery{
		cfg:     cfg,
		logger:  logger,
		manager: manager,
		nodes:   make(map[string]*NodeInfo),
	}, nil
}

// Start begins the discovery process
func (d *staticDiscovery) Start(ctx context.Context) error {
	d.logger.Info("DEBUG: Entering staticDiscovery.Start()")
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.started {
		return fmt.Errorf("discovery is already started")
	}

	d.logger.Info("DEBUG: About to set up context and mark as started")
	d.ctx, d.cancel = context.WithCancel(ctx)
	d.started = true

	// Register local node by getting it safely
	d.logger.Info("DEBUG: About to get local node from manager")
	localNode := d.manager.GetLocalNode()
	if localNode != nil {
		d.logger.Info("DEBUG: Got local node, adding to nodes map", "node_id", localNode.ID)
		d.nodes[localNode.ID] = localNode
	} else {
		d.logger.Warn("DEBUG: Local node is nil")
	}

	// Load static nodes from configuration
	d.logger.Info("DEBUG: About to load static nodes from configuration")
	if err := d.loadStaticNodes(); err != nil {
		d.logger.Warn("Failed to load static nodes", "error", err)
	}
	d.logger.Info("DEBUG: Static nodes loaded successfully")

	// Start periodic discovery if interval is configured
	d.logger.Info("DEBUG: About to start periodic discovery", "interval", d.cfg.Interval)
	if d.cfg.Interval > 0 {
		go d.periodicDiscovery()
	}

	d.logger.Info("Static discovery started",
		"interval", d.cfg.Interval,
		"node_timeout", d.cfg.NodeTimeout)

	d.logger.Info("DEBUG: Exiting staticDiscovery.Start() successfully")
	return nil
}

// Stop stops the discovery process
func (d *staticDiscovery) Stop(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.started {
		return nil
	}

	if d.cancel != nil {
		d.cancel()
	}

	d.started = false
	d.logger.Info("Static discovery stopped")

	return nil
}

// DiscoverNodes returns the list of discovered nodes
func (d *staticDiscovery) DiscoverNodes() ([]*NodeInfo, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	nodes := make([]*NodeInfo, 0, len(d.nodes))
	for _, node := range d.nodes {
		// Filter out nodes that have timed out
		if time.Since(node.LastSeen) <= d.cfg.NodeTimeout {
			// Create a copy to prevent modification
			nodeCopy := *node
			nodes = append(nodes, &nodeCopy)
		}
	}

	return nodes, nil
}

// RegisterNode registers a new node
func (d *staticDiscovery) RegisterNode(node *NodeInfo) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if node == nil {
		return fmt.Errorf("node cannot be nil")
	}

	if node.ID == "" {
		return fmt.Errorf("node ID cannot be empty")
	}

	node.LastSeen = time.Now()
	d.nodes[node.ID] = node

	d.logger.Debug("Node registered",
		"node_id", node.ID,
		"address", node.Address,
		"state", node.State.String())

	return nil
}

// UnregisterNode unregisters a node
func (d *staticDiscovery) UnregisterNode(nodeID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if nodeID == "" {
		return fmt.Errorf("node ID cannot be empty")
	}

	delete(d.nodes, nodeID)

	d.logger.Debug("Node unregistered", "node_id", nodeID)

	return nil
}

// loadStaticNodes loads static node configuration
func (d *staticDiscovery) loadStaticNodes() error {
	d.logger.Info("DEBUG: Entering loadStaticNodes()")
	// Check for static nodes in configuration
	if staticNodes, ok := d.cfg.Config["nodes"].([]interface{}); ok {
		d.logger.Info("DEBUG: Found static nodes in configuration", "count", len(staticNodes))
		for i, nodeData := range staticNodes {
			d.logger.Info("DEBUG: Processing static node", "index", i)
			if nodeMap, ok := nodeData.(map[string]interface{}); ok {
				d.logger.Info("DEBUG: About to parse node from config", "data", nodeMap)
				node, err := d.parseNodeFromConfig(nodeMap)
				if err != nil {
					d.logger.Warn("Failed to parse static node", "error", err, "data", nodeMap)
					continue
				}

				d.logger.Info("DEBUG: About to register static node", "node_id", node.ID)
				if err := d.RegisterNode(node); err != nil {
					d.logger.Warn("Failed to register static node", "error", err, "node_id", node.ID)
				}
				d.logger.Info("DEBUG: Static node registered successfully", "node_id", node.ID)
			}
		}
	} else {
		d.logger.Info("DEBUG: No static nodes found in configuration")
	}

	d.logger.Info("DEBUG: Exiting loadStaticNodes() successfully")
	return nil
}

// parseNodeFromConfig parses a node from configuration data
func (d *staticDiscovery) parseNodeFromConfig(nodeMap map[string]interface{}) (*NodeInfo, error) {
	node := &NodeInfo{
		State:     NodeStateUnknown,
		Role:      NodeRoleFollower,
		LastSeen:  time.Now(),
		StartedAt: time.Now(),
	}

	if id, ok := nodeMap["id"].(string); ok {
		node.ID = id
	} else {
		return nil, fmt.Errorf("node ID is required")
	}

	if address, ok := nodeMap["address"].(string); ok {
		node.Address = address
	} else {
		return nil, fmt.Errorf("node address is required")
	}

	if version, ok := nodeMap["version"].(string); ok {
		node.Version = version
	}

	if capabilities, ok := nodeMap["capabilities"].([]interface{}); ok {
		for _, cap := range capabilities {
			if capStr, ok := cap.(string); ok {
				node.Capabilities = append(node.Capabilities, capStr)
			}
		}
	}

	return node, nil
}

// periodicDiscovery runs periodic discovery
func (d *staticDiscovery) periodicDiscovery() {
	ticker := time.NewTicker(d.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.performDiscovery()
		}
	}
}

// performDiscovery performs a discovery cycle
func (d *staticDiscovery) performDiscovery() {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	timeoutNodes := make([]string, 0)

	// Check for timed out nodes
	for nodeID, node := range d.nodes {
		if nodeID != d.manager.nodeInfo.ID && // Don't timeout local node
			now.Sub(node.LastSeen) > d.cfg.NodeTimeout {
			timeoutNodes = append(timeoutNodes, nodeID)
		}
	}

	// Remove timed out nodes
	for _, nodeID := range timeoutNodes {
		delete(d.nodes, nodeID)
		d.logger.Debug("Node timed out and removed", "node_id", nodeID)
	}

	// Update local node timestamp
	if localNode, exists := d.nodes[d.manager.nodeInfo.ID]; exists {
		localNode.LastSeen = now
	}

	d.logger.Debug("Discovery cycle completed",
		"total_nodes", len(d.nodes),
		"timed_out_nodes", len(timeoutNodes))
}

// geographicDiscovery implements Discovery with geographic awareness
type geographicDiscovery struct {
	*staticDiscovery
	geoConfig *GeographicDiscoveryConfig
}

// newGeographicDiscovery creates a new geographic discovery instance
func newGeographicDiscovery(cfg *DiscoveryConfig, logger logging.Logger, manager *Manager) (*geographicDiscovery, error) {
	staticDisc, err := newStaticDiscovery(cfg, logger, manager)
	if err != nil {
		return nil, err
	}

	geoConfig := cfg.Geographic
	if geoConfig == nil {
		// Use default geographic config
		geoConfig = &GeographicDiscoveryConfig{
			EnableRegionAffinity:         true,
			CrossRegionTimeoutMultiplier: 2.0,
			MaxCrossRegionLatency:        500 * time.Millisecond,
			LatencyCheckInterval:         60 * time.Second,
			RegionalWeights:              make(map[string]float64),
		}
	}

	return &geographicDiscovery{
		staticDiscovery: staticDisc,
		geoConfig:       geoConfig,
	}, nil
}

// Start begins the geographic discovery process
func (d *geographicDiscovery) Start(ctx context.Context) error {
	if err := d.staticDiscovery.Start(ctx); err != nil {
		return err
	}

	// Start latency monitoring if enabled
	if d.geoConfig.LatencyCheckInterval > 0 {
		go d.periodicLatencyCheck()
	}

	d.logger.Info("Geographic discovery started",
		"enable_region_affinity", d.geoConfig.EnableRegionAffinity,
		"max_cross_region_latency", d.geoConfig.MaxCrossRegionLatency,
		"latency_check_interval", d.geoConfig.LatencyCheckInterval)

	return nil
}

// DiscoverNodes returns nodes with geographic filtering and prioritization
func (d *geographicDiscovery) DiscoverNodes() ([]*NodeInfo, error) {
	// Get base nodes from static discovery
	nodes, err := d.staticDiscovery.DiscoverNodes()
	if err != nil {
		return nil, err
	}

	// Apply geographic filtering and sorting
	if d.geoConfig.EnableRegionAffinity {
		nodes = d.applyGeographicFiltering(nodes)
	}

	return nodes, nil
}

// applyGeographicFiltering applies geographic filtering and prioritization
func (d *geographicDiscovery) applyGeographicFiltering(nodes []*NodeInfo) []*NodeInfo {
	if len(nodes) <= 1 {
		return nodes
	}

	localNode := d.manager.GetLocalNode()
	if localNode == nil || localNode.Region == "" {
		return nodes // No geographic info available
	}

	// Separate nodes by region
	sameRegionNodes := make([]*NodeInfo, 0)
	crossRegionNodes := make([]*NodeInfo, 0)

	for _, node := range nodes {
		if node.Region == localNode.Region {
			sameRegionNodes = append(sameRegionNodes, node)
		} else {
			// Check cross-region latency constraints
			if d.isAcceptableLatency(node, localNode) {
				crossRegionNodes = append(crossRegionNodes, node)
			}
		}
	}

	// Prioritize same-region nodes, then cross-region
	result := make([]*NodeInfo, 0, len(nodes))
	result = append(result, sameRegionNodes...)
	result = append(result, crossRegionNodes...)

	return result
}

// isAcceptableLatency checks if cross-region latency is acceptable
func (d *geographicDiscovery) isAcceptableLatency(node, localNode *NodeInfo) bool {
	if d.geoConfig.MaxCrossRegionLatency <= 0 {
		return true // No latency constraint
	}

	if localNode.Latency == nil {
		return true // No latency data yet
	}

	latency, exists := localNode.Latency[node.ID]
	if !exists {
		return true // No latency data for this node yet
	}

	return latency <= d.geoConfig.MaxCrossRegionLatency
}

// periodicLatencyCheck performs periodic latency measurements
func (d *geographicDiscovery) periodicLatencyCheck() {
	ticker := time.NewTicker(d.geoConfig.LatencyCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.performLatencyChecks()
		}
	}
}

// performLatencyChecks measures latency to other nodes
func (d *geographicDiscovery) performLatencyChecks() {
	d.mu.RLock()
	nodes := make([]*NodeInfo, 0, len(d.nodes))
	for _, node := range d.nodes {
		nodes = append(nodes, node)
	}
	d.mu.RUnlock()

	localNode := d.manager.GetLocalNode()
	if localNode == nil {
		return
	}

	for _, node := range nodes {
		if node.ID == localNode.ID {
			continue // Skip self
		}

		// Simple ping-like latency check (could be enhanced with actual ping)
		startTime := time.Now()

		// For now, simulate latency based on region
		// In production, this would be actual network measurement
		latency := d.estimateLatency(localNode, node)

		// Update latency in local node
		d.manager.mu.Lock()
		if d.manager.nodeInfo.Latency == nil {
			d.manager.nodeInfo.Latency = make(map[string]time.Duration)
		}
		d.manager.nodeInfo.Latency[node.ID] = latency
		d.manager.mu.Unlock()

		d.logger.Debug("Latency measured",
			"target_node", node.ID,
			"latency", latency,
			"measurement_time", time.Since(startTime))
	}
}

// estimateLatency provides rough latency estimates based on geographic regions
func (d *geographicDiscovery) estimateLatency(localNode, targetNode *NodeInfo) time.Duration {
	// Base latencies for different region pairs (rough estimates)
	if localNode.Region == targetNode.Region {
		// Same region: 5-20ms
		return 10 * time.Millisecond
	}

	// Cross-region estimates (US-centric)
	regionPairs := map[string]map[string]time.Duration{
		"us-east": {
			"us-central": 50 * time.Millisecond,
			"us-west":    100 * time.Millisecond,
		},
		"us-central": {
			"us-east": 50 * time.Millisecond,
			"us-west":  60 * time.Millisecond,
		},
		"us-west": {
			"us-east":    100 * time.Millisecond,
			"us-central": 60 * time.Millisecond,
		},
	}

	if fromRegion, exists := regionPairs[localNode.Region]; exists {
		if latency, exists := fromRegion[targetNode.Region]; exists {
			return latency
		}
	}

	// Default cross-region latency
	return 150 * time.Millisecond
}