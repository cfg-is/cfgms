//go:build commercial

// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 CFGMS Contributors
// +build commercial

package ha

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/cfgis/cfgms/pkg/logging"
)

// loadBalancer implements LoadBalancer interface
type loadBalancer struct {
	mu       sync.RWMutex
	cfg      *LoadBalancingConfig
	logger   logging.Logger
	strategy LoadBalancingStrategy

	// Node tracking
	nodes           map[string]*nodeStats
	healthyNodes    []*NodeInfo
	roundRobinIndex int64

	// Connection tracking
	totalConnections int64
}

// nodeStats tracks statistics for a node
type nodeStats struct {
	nodeInfo     *NodeInfo
	connections  int64
	healthScore  float64
	weight       float64
	lastSelected int64 // Unix timestamp
}

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(cfg *LoadBalancingConfig, logger logging.Logger) (LoadBalancer, error) {
	if cfg == nil {
		cfg = &LoadBalancingConfig{
			Strategy: HealthBasedStrategy,
			HealthBased: &HealthBasedConfig{
				MinHealthScore:     0.7,
				HealthWeightFactor: 1.0,
			},
			ConnectionBased: &ConnectionBasedConfig{
				MaxConnectionsPerNode: 1000,
				ConnectionThreshold:   0.8,
			},
		}
	}

	return &loadBalancer{
		cfg:      cfg,
		logger:   logger,
		strategy: cfg.Strategy,
		nodes:    make(map[string]*nodeStats),
	}, nil
}

// GetNextNode returns the next node for load balancing
func (lb *loadBalancer) GetNextNode() (*NodeInfo, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if len(lb.healthyNodes) == 0 {
		return nil, fmt.Errorf("no healthy nodes available")
	}

	switch lb.strategy {
	case RoundRobinStrategy:
		return lb.getNextRoundRobin()
	case LeastConnectionsStrategy:
		return lb.getNextLeastConnections()
	case HealthBasedStrategy:
		return lb.getNextHealthBased()
	case GeographicStrategy:
		return lb.getNextGeographic()
	default:
		return nil, fmt.Errorf("unsupported load balancing strategy: %s", lb.strategy)
	}
}

// UpdateNodeHealth updates the health status of a node
func (lb *loadBalancer) UpdateNodeHealth(nodeID string, health *HealthStatus) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	stats, exists := lb.nodes[nodeID]
	if !exists {
		return fmt.Errorf("node not found: %s", nodeID)
	}

	// Calculate health score based on overall health state
	healthScore := lb.calculateHealthScore(health.Overall)
	stats.healthScore = healthScore

	// Update node state
	stats.nodeInfo.State = health.Overall

	// Recalculate weights if using health-based strategy
	if lb.strategy == HealthBasedStrategy {
		lb.recalculateWeights()
	}

	// Update healthy nodes list
	lb.updateHealthyNodesList()

	lb.logger.Debug("Node health updated",
		"node_id", nodeID,
		"health_score", healthScore,
		"state", health.Overall.String())

	return nil
}

// RemoveNode removes a node from load balancing
func (lb *loadBalancer) RemoveNode(nodeID string) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if _, exists := lb.nodes[nodeID]; !exists {
		return fmt.Errorf("node not found: %s", nodeID)
	}

	delete(lb.nodes, nodeID)
	lb.updateHealthyNodesList()

	lb.logger.Info("Node removed from load balancer", "node_id", nodeID)

	return nil
}

// GetLoadBalancingStrategy returns the current strategy
func (lb *loadBalancer) GetLoadBalancingStrategy() LoadBalancingStrategy {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	return lb.strategy
}

// AddNode adds a node to the load balancer
func (lb *loadBalancer) AddNode(nodeInfo *NodeInfo) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if nodeInfo == nil {
		return fmt.Errorf("node info cannot be nil")
	}

	if nodeInfo.ID == "" {
		return fmt.Errorf("node ID cannot be empty")
	}

	stats := &nodeStats{
		nodeInfo:    nodeInfo,
		healthScore: lb.calculateHealthScore(nodeInfo.State),
		weight:      1.0,
	}

	lb.nodes[nodeInfo.ID] = stats

	// Recalculate weights if using health-based strategy
	if lb.strategy == HealthBasedStrategy {
		lb.recalculateWeights()
	}

	lb.updateHealthyNodesList()

	lb.logger.Info("Node added to load balancer",
		"node_id", nodeInfo.ID,
		"address", nodeInfo.Address,
		"state", nodeInfo.State.String())

	return nil
}

// getNextRoundRobin implements round-robin load balancing
func (lb *loadBalancer) getNextRoundRobin() (*NodeInfo, error) {
	if len(lb.healthyNodes) == 0 {
		return nil, fmt.Errorf("no healthy nodes available")
	}

	index := atomic.AddInt64(&lb.roundRobinIndex, 1) % int64(len(lb.healthyNodes))
	node := lb.healthyNodes[index]

	// Update connection count
	if stats, exists := lb.nodes[node.ID]; exists {
		atomic.AddInt64(&stats.connections, 1)
		atomic.AddInt64(&lb.totalConnections, 1)
	}

	lb.logger.Debug("Round-robin selection", "node_id", node.ID, "index", index)

	return node, nil
}

// getNextLeastConnections implements least-connections load balancing
func (lb *loadBalancer) getNextLeastConnections() (*NodeInfo, error) {
	if len(lb.healthyNodes) == 0 {
		return nil, fmt.Errorf("no healthy nodes available")
	}

	var selectedNode *NodeInfo
	var minConnections int64 = math.MaxInt64

	for _, node := range lb.healthyNodes {
		if stats, exists := lb.nodes[node.ID]; exists {
			connections := atomic.LoadInt64(&stats.connections)
			if connections < minConnections {
				minConnections = connections
				selectedNode = node
			}
		}
	}

	if selectedNode == nil {
		// Fallback to first node
		selectedNode = lb.healthyNodes[0]
	}

	// Update connection count
	if stats, exists := lb.nodes[selectedNode.ID]; exists {
		atomic.AddInt64(&stats.connections, 1)
		atomic.AddInt64(&lb.totalConnections, 1)
	}

	lb.logger.Debug("Least-connections selection",
		"node_id", selectedNode.ID,
		"connections", minConnections)

	return selectedNode, nil
}

// getNextHealthBased implements health-based load balancing
func (lb *loadBalancer) getNextHealthBased() (*NodeInfo, error) {
	if len(lb.healthyNodes) == 0 {
		return nil, fmt.Errorf("no healthy nodes available")
	}

	// Filter nodes that meet minimum health score
	eligibleNodes := make([]*NodeInfo, 0)
	for _, node := range lb.healthyNodes {
		if stats, exists := lb.nodes[node.ID]; exists {
			if stats.healthScore >= lb.cfg.HealthBased.MinHealthScore {
				eligibleNodes = append(eligibleNodes, node)
			}
		}
	}

	if len(eligibleNodes) == 0 {
		// No nodes meet minimum health, use all healthy nodes
		eligibleNodes = lb.healthyNodes
	}

	// Select node based on weighted health score
	var selectedNode *NodeInfo
	var maxWeightedScore float64

	for _, node := range eligibleNodes {
		if stats, exists := lb.nodes[node.ID]; exists {
			// Calculate weighted score considering health and current load
			connections := atomic.LoadInt64(&stats.connections)
			loadFactor := 1.0
			if lb.cfg.ConnectionBased.MaxConnectionsPerNode > 0 {
				loadFactor = 1.0 - (float64(connections) / float64(lb.cfg.ConnectionBased.MaxConnectionsPerNode))
				if loadFactor < 0.1 {
					loadFactor = 0.1 // Don't completely exclude overloaded nodes
				}
			}

			weightedScore := stats.healthScore * stats.weight * loadFactor

			if weightedScore > maxWeightedScore {
				maxWeightedScore = weightedScore
				selectedNode = node
			}
		}
	}

	if selectedNode == nil {
		// Fallback to first eligible node
		selectedNode = eligibleNodes[0]
	}

	// Update connection count
	if stats, exists := lb.nodes[selectedNode.ID]; exists {
		atomic.AddInt64(&stats.connections, 1)
		atomic.AddInt64(&lb.totalConnections, 1)
	}

	lb.logger.Debug("Health-based selection",
		"node_id", selectedNode.ID,
		"weighted_score", maxWeightedScore)

	return selectedNode, nil
}

// calculateHealthScore converts NodeState to a numeric health score
func (lb *loadBalancer) calculateHealthScore(state NodeState) float64 {
	switch state {
	case NodeStateHealthy:
		return 1.0
	case NodeStateDegraded:
		return 0.7
	case NodeStateFailed:
		return 0.0
	case NodeStateOffline:
		return 0.0
	default:
		return 0.5 // Unknown state
	}
}

// recalculateWeights recalculates node weights for health-based load balancing
func (lb *loadBalancer) recalculateWeights() {
	totalHealthScore := 0.0
	healthyCount := 0

	// Calculate total health score
	for _, stats := range lb.nodes {
		if stats.healthScore > 0 {
			totalHealthScore += stats.healthScore
			healthyCount++
		}
	}

	if totalHealthScore == 0 || healthyCount == 0 {
		return
	}

	// Calculate weights based on relative health scores
	for _, stats := range lb.nodes {
		if stats.healthScore > 0 {
			stats.weight = (stats.healthScore / totalHealthScore) * float64(healthyCount)
			stats.weight *= lb.cfg.HealthBased.HealthWeightFactor
		} else {
			stats.weight = 0.0
		}
	}
}

// updateHealthyNodesList updates the list of healthy nodes
func (lb *loadBalancer) updateHealthyNodesList() {
	lb.healthyNodes = make([]*NodeInfo, 0)

	for _, stats := range lb.nodes {
		if stats.nodeInfo.State == NodeStateHealthy || stats.nodeInfo.State == NodeStateDegraded {
			lb.healthyNodes = append(lb.healthyNodes, stats.nodeInfo)
		}
	}

	// Sort nodes by ID for consistent ordering in round-robin
	sort.Slice(lb.healthyNodes, func(i, j int) bool {
		return lb.healthyNodes[i].ID < lb.healthyNodes[j].ID
	})

	lb.logger.Debug("Healthy nodes list updated",
		"healthy_count", len(lb.healthyNodes),
		"total_count", len(lb.nodes))
}

// GetNodeStats returns statistics for all nodes
func (lb *loadBalancer) GetNodeStats() map[string]*NodeStats {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	stats := make(map[string]*NodeStats)
	for nodeID, nodeStats := range lb.nodes {
		stats[nodeID] = &NodeStats{
			NodeID:       nodeID,
			Connections:  atomic.LoadInt64(&nodeStats.connections),
			HealthScore:  nodeStats.healthScore,
			Weight:       nodeStats.weight,
			LastSelected: nodeStats.lastSelected,
		}
	}

	return stats
}

// NodeStats represents statistics for a node
type NodeStats struct {
	NodeID       string  `json:"node_id"`
	Connections  int64   `json:"connections"`
	HealthScore  float64 `json:"health_score"`
	Weight       float64 `json:"weight"`
	LastSelected int64   `json:"last_selected"`
}

// ReleaseConnection decrements the connection count for a node
func (lb *loadBalancer) ReleaseConnection(nodeID string) error {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	stats, exists := lb.nodes[nodeID]
	if !exists {
		return fmt.Errorf("node not found: %s", nodeID)
	}

	if atomic.LoadInt64(&stats.connections) > 0 {
		atomic.AddInt64(&stats.connections, -1)
		atomic.AddInt64(&lb.totalConnections, -1)
	}

	return nil
}

// GetTotalConnections returns the total number of connections
func (lb *loadBalancer) GetTotalConnections() int64 {
	return atomic.LoadInt64(&lb.totalConnections)
}

// getNextGeographic implements geographic-aware load balancing
func (lb *loadBalancer) getNextGeographic() (*NodeInfo, error) {
	if len(lb.healthyNodes) == 0 {
		return nil, fmt.Errorf("no healthy nodes available")
	}

	if lb.cfg.Geographic == nil {
		// Fallback to health-based if no geographic config
		return lb.getNextHealthBased()
	}

	// Get local node info for geographic context
	localNode := lb.getLocalNodeInfo()
	if localNode == nil || localNode.Region == "" {
		// No geographic context, fallback to health-based
		return lb.getNextHealthBased()
	}

	// Separate nodes by region affinity
	sameRegionNodes := make([]*NodeInfo, 0)
	crossRegionNodes := make([]*NodeInfo, 0)

	for _, node := range lb.healthyNodes {
		if lb.cfg.Geographic.EnableRegionAffinity && node.Region == localNode.Region {
			sameRegionNodes = append(sameRegionNodes, node)
		} else {
			// Check if cross-region node meets latency requirements
			if lb.isAcceptableLatency(node, localNode) {
				crossRegionNodes = append(crossRegionNodes, node)
			}
		}
	}

	// Select from preferred region first, then cross-region if needed
	candidateNodes := sameRegionNodes
	if len(candidateNodes) == 0 && lb.cfg.Geographic.CrossRegionFallback {
		candidateNodes = crossRegionNodes
	}

	if len(candidateNodes) == 0 {
		// No acceptable nodes, use all healthy nodes as fallback
		candidateNodes = lb.healthyNodes
	}

	// Apply geographic scoring to candidate nodes
	return lb.selectBestGeographicNode(candidateNodes, localNode)
}

// getLocalNodeInfo gets information about the local node (simplified)
func (lb *loadBalancer) getLocalNodeInfo() *NodeInfo {
	// In a real implementation, this would get the actual local node info
	// For now, we'll try to find a local node or return nil
	for _, stats := range lb.nodes {
		if stats.nodeInfo.Role == NodeRoleLeader {
			return stats.nodeInfo
		}
	}
	return nil
}

// isAcceptableLatency checks if a node meets latency requirements
func (lb *loadBalancer) isAcceptableLatency(node, localNode *NodeInfo) bool {
	if lb.cfg.Geographic.MaxLatencyThreshold <= 0 {
		return true // No latency constraints
	}

	if localNode.Latency == nil {
		return true // No latency data yet
	}

	latency, exists := localNode.Latency[node.ID]
	if !exists {
		return true // No latency data for this node yet
	}

	return latency <= lb.cfg.Geographic.MaxLatencyThreshold
}

// selectBestGeographicNode selects the best node from candidates using geographic scoring
func (lb *loadBalancer) selectBestGeographicNode(candidates []*NodeInfo, localNode *NodeInfo) (*NodeInfo, error) {
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no candidate nodes available")
	}

	if len(candidates) == 1 {
		selectedNode := candidates[0]
		lb.updateConnectionCount(selectedNode.ID)
		return selectedNode, nil
	}

	var selectedNode *NodeInfo
	var maxScore float64

	for _, node := range candidates {
		score := lb.calculateGeographicScore(node, localNode)
		if score > maxScore {
			maxScore = score
			selectedNode = node
		}
	}

	if selectedNode == nil {
		selectedNode = candidates[0] // Fallback
	}

	lb.updateConnectionCount(selectedNode.ID)

	lb.logger.Debug("Geographic selection",
		"node_id", selectedNode.ID,
		"region", selectedNode.Region,
		"score", maxScore)

	return selectedNode, nil
}

// calculateGeographicScore calculates a composite score for geographic load balancing
func (lb *loadBalancer) calculateGeographicScore(node, localNode *NodeInfo) float64 {
	stats, exists := lb.nodes[node.ID]
	if !exists {
		return 0.0
	}

	score := 0.0

	// Health score component (40% of total)
	healthComponent := stats.healthScore * 0.4

	// Connection load component (30% of total)
	connections := atomic.LoadInt64(&stats.connections)
	loadComponent := 0.3
	if lb.cfg.ConnectionBased.MaxConnectionsPerNode > 0 {
		loadFactor := 1.0 - (float64(connections) / float64(lb.cfg.ConnectionBased.MaxConnectionsPerNode))
		if loadFactor < 0 {
			loadFactor = 0
		}
		loadComponent = loadFactor * 0.3
	}

	// Geographic component (30% of total)
	geoComponent := lb.calculateGeographicComponent(node, localNode)

	score = healthComponent + loadComponent + geoComponent

	return score
}

// calculateGeographicComponent calculates the geographic preference component
func (lb *loadBalancer) calculateGeographicComponent(node, localNode *NodeInfo) float64 {
	geoScore := 0.0

	// Region affinity bonus
	if lb.cfg.Geographic.EnableRegionAffinity && node.Region == localNode.Region {
		geoScore += lb.cfg.Geographic.RegionAffinityWeight * 0.2 // 20% max for region affinity
	}

	// Latency component
	if localNode.Latency != nil {
		if latency, exists := localNode.Latency[node.ID]; exists {
			// Convert latency to score (lower latency = higher score)
			latencyMs := float64(latency.Milliseconds())
			if latencyMs > 0 {
				// Normalize latency score (assuming 200ms is baseline)
				latencyScore := math.Max(0, 1.0-(latencyMs/200.0)) * lb.cfg.Geographic.LatencyWeightFactor
				geoScore += latencyScore * 0.1 // 10% max for latency
			}
		}
	}

	// Regional capacity weights
	if lb.cfg.Geographic.RegionalCapacityWeights != nil {
		if weight, exists := lb.cfg.Geographic.RegionalCapacityWeights[node.Region]; exists {
			geoScore += weight * 0.05 // 5% max for regional weights
		}
	}

	return geoScore
}

// updateConnectionCount increments connection count for a node
func (lb *loadBalancer) updateConnectionCount(nodeID string) {
	if stats, exists := lb.nodes[nodeID]; exists {
		atomic.AddInt64(&stats.connections, 1)
		atomic.AddInt64(&lb.totalConnections, 1)
	}
}
