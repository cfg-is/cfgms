//go:build commercial
// +build commercial

package ha

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/cert"
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
	log.Printf("DISCOVERY_START: Entering staticDiscovery.Start()")
	d.mu.Lock()

	if d.started {
		d.mu.Unlock()
		return fmt.Errorf("discovery is already started")
	}

	log.Printf("DISCOVERY_START: About to set up context and mark as started")
	// TEMP FIX: Use Background context to prevent immediate cancellation
	// TODO: Investigate why parent context is getting cancelled
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.started = true

	// Register local node - avoid deadlock by accessing nodeInfo directly
	log.Printf("DISCOVERY_START: About to get local node info directly")
	// Access nodeInfo directly to avoid GetLocalNode() deadlock during startup
	nodeInfo := *d.manager.nodeInfo  // Create a copy
	nodeInfo.LastSeen = time.Now()
	log.Printf("DISCOVERY_START: Got local node info, adding to nodes map, node_id=%s", nodeInfo.ID)
	d.nodes[nodeInfo.ID] = &nodeInfo

	d.mu.Unlock() // Release lock before calling loadStaticNodes which needs to acquire it

	// Load static nodes from configuration
	log.Printf("DISCOVERY_START: About to load static nodes from configuration")
	if err := d.loadStaticNodes(); err != nil {
		log.Printf("DISCOVERY_START: Failed to load static nodes: %v", err)
	}
	log.Printf("DISCOVERY_START: Static nodes loaded successfully, total_nodes=%d", len(d.nodes))

	// Start periodic discovery if interval is configured
	log.Printf("DISCOVERY_START: About to start periodic discovery, interval=%v", d.cfg.Interval)
	if d.cfg.Interval > 0 {
		go d.periodicDiscovery()
	}

	log.Printf("DISCOVERY_START: Static discovery started, interval=%v, node_timeout=%v", d.cfg.Interval, d.cfg.NodeTimeout)

	log.Printf("DISCOVERY_START: Exiting staticDiscovery.Start() successfully")
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
	log.Printf("LOAD_STATIC: Entering loadStaticNodes()")
	log.Printf("LOAD_STATIC: Discovery config contents: %+v, len=%d", d.cfg.Config, len(d.cfg.Config))

	// Check for static nodes in configuration
	// Handle both []interface{} and []map[string]interface{} types
	var staticNodes []map[string]interface{}
	if nodes, ok := d.cfg.Config["nodes"].([]map[string]interface{}); ok {
		staticNodes = nodes
	} else if nodes, ok := d.cfg.Config["nodes"].([]interface{}); ok {
		// Convert []interface{} to []map[string]interface{}
		for _, node := range nodes {
			if nodeMap, ok := node.(map[string]interface{}); ok {
				staticNodes = append(staticNodes, nodeMap)
			}
		}
	}

	if len(staticNodes) > 0 {
		log.Printf("LOAD_STATIC: Found static nodes in configuration, count=%d", len(staticNodes))
		for i, nodeMap := range staticNodes {
			log.Printf("LOAD_STATIC: Processing static node, index=%d, data=%+v", i, nodeMap)
			node, err := d.parseNodeFromConfig(nodeMap)
			if err != nil {
				log.Printf("LOAD_STATIC: Failed to parse static node: %v, data=%+v", err, nodeMap)
				continue
			}

			log.Printf("LOAD_STATIC: About to register static node, node_id=%s", node.ID)
			if err := d.RegisterNode(node); err != nil {
				log.Printf("LOAD_STATIC: Failed to register static node: %v, node_id=%s", err, node.ID)
			}
			log.Printf("LOAD_STATIC: Static node registered successfully, node_id=%s", node.ID)
		}
	} else {
		log.Printf("LOAD_STATIC: No static nodes found in configuration")
	}

	log.Printf("LOAD_STATIC: Exiting loadStaticNodes() successfully")
	return nil
}

// parseNodeFromConfig parses a node from configuration data
func (d *staticDiscovery) parseNodeFromConfig(nodeMap map[string]interface{}) (*NodeInfo, error) {
	node := &NodeInfo{
		State:     NodeStateHealthy, // Static nodes from config are assumed healthy
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
	log.Printf("PERIODIC_DISCOVERY: Goroutine started, interval=%v", d.cfg.Interval)
	ticker := time.NewTicker(d.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			log.Printf("PERIODIC_DISCOVERY: Context cancelled, exiting")
			return
		case <-ticker.C:
			log.Printf("PERIODIC_DISCOVERY: Ticker fired, calling performDiscovery()")
			d.performDiscovery()
		}
	}
}

// checkNodeHealth performs a simple HTTP health check on a node
func (d *staticDiscovery) checkNodeHealth(node *NodeInfo) bool {
	if node.Address == "" {
		return false
	}

	// Simple HTTP GET to check if node is responding
	// Use HTTPS with basic TLS config from pkg/cert
	// TODO: Add proper certificate validation with cert manager
	tlsConfig, err := cert.CreateBasicTLSConfig(nil, nil, tls.VersionTLS12)
	if err != nil {
		return err
	}
	tlsConfig.InsecureSkipVerify = true // TODO: Remove after implementing proper cert validation

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	url := fmt.Sprintf("https://%s/healthz", node.Address)
	resp, err := client.Get(url)
	if err != nil {
		// Check if it's a TLS handshake error - means server is up but requires client cert
		if strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "certificate") {
			log.Printf("HEALTH_CHECK: Node up (TLS handshake), node_id=%s, address=%s", node.ID, node.Address)
			return true // Server is up, just needs mTLS
		}
		log.Printf("HEALTH_CHECK: Node unreachable, node_id=%s, address=%s, error=%v", node.ID, node.Address, err)
		return false
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("HEALTH_CHECK: Failed to close response body, node_id=%s, error=%v", node.ID, err)
		}
	}()

	isHealthy := resp.StatusCode == 200 || resp.StatusCode == 404 || resp.StatusCode == 401 // Any response means server is up
	log.Printf("HEALTH_CHECK: Node checked, node_id=%s, address=%s, status=%d, healthy=%v",
		node.ID, node.Address, resp.StatusCode, isHealthy)
	return isHealthy
}

// performDiscovery performs a discovery cycle
func (d *staticDiscovery) performDiscovery() {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	timeoutThreshold := now.Add(-d.cfg.NodeTimeout)

	// Check for nodes that have timed out and trigger election if leader times out
	localNode := d.manager.GetLocalNode()
	currentLeader, _ := d.manager.GetLeader()

	for nodeID, node := range d.nodes {
		// Always keep local node alive
		if localNode != nil && nodeID == localNode.ID {
			node.LastSeen = now
			continue
		}

		// Check if remote node is healthy
		if d.checkNodeHealth(node) {
			// Node is reachable, update LastSeen
			node.LastSeen = now
		}
		// If health check fails, don't update LastSeen - let it timeout

		// Check if node has timed out
		if node.LastSeen.Before(timeoutThreshold) {
			log.Printf("DISCOVERY_CYCLE: Node timed out, node_id=%s, last_seen=%v, timeout_threshold=%v",
				nodeID, node.LastSeen, timeoutThreshold)

			// If the timed-out node is the leader, trigger election
			if currentLeader != nil && nodeID == currentLeader.ID {
				log.Printf("DISCOVERY_CYCLE: Leader has timed out, triggering election, leader_id=%s", nodeID)
				go d.manager.triggerLeaderElection("leader timeout detected")
			}
		}
	}

	log.Printf("DISCOVERY_CYCLE: Discovery cycle completed, total_nodes=%d", len(d.nodes))
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