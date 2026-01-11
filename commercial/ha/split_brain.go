//go:build commercial

// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz
// +build commercial

package ha

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// splitBrainDetector implements SplitBrainDetector interface
type splitBrainDetector struct {
	mu      sync.RWMutex
	cfg     *SplitBrainConfig
	logger  logging.Logger
	manager *Manager
	ctx     context.Context
	cancel  context.CancelFunc
	started bool

	// Split-brain detection state
	handlers       []SplitBrainHandler
	lastDetection  time.Time
	currentStatus  *SplitBrainStatus
	partitionTrack map[string]*partitionInfo
}

// partitionInfo tracks information about a network partition
type partitionInfo struct {
	ID           string
	Nodes        []string
	FirstSeen    time.Time
	LastSeen     time.Time
	LeaderClaims int
}

// NewSplitBrainDetector creates a new split-brain detector
func NewSplitBrainDetector(cfg *SplitBrainConfig, logger logging.Logger, manager *Manager) (SplitBrainDetector, error) {
	if cfg == nil {
		cfg = &SplitBrainConfig{
			Enabled:            true,
			DetectionInterval:  15 * time.Second,
			QuorumInterval:     30 * time.Second,
			ResolutionStrategy: "quorum-based",
		}
	}

	return &splitBrainDetector{
		cfg:     cfg,
		logger:  logger,
		manager: manager,
		currentStatus: &SplitBrainStatus{
			Detected:  false,
			Timestamp: time.Now(),
			Details:   make(map[string]interface{}),
		},
		partitionTrack: make(map[string]*partitionInfo),
	}, nil
}

// Start begins split-brain detection
func (sbd *splitBrainDetector) Start(ctx context.Context) error {
	sbd.mu.Lock()
	defer sbd.mu.Unlock()

	if !sbd.cfg.Enabled {
		sbd.logger.Info("Split-brain detection is disabled")
		return nil
	}

	if sbd.started {
		return fmt.Errorf("split-brain detector is already started")
	}

	sbd.ctx, sbd.cancel = context.WithCancel(ctx)
	sbd.started = true

	// Start periodic detection
	go sbd.periodicDetection()

	// Start quorum validation
	go sbd.periodicQuorumValidation()

	sbd.logger.Info("Split-brain detector started",
		"detection_interval", sbd.cfg.DetectionInterval,
		"quorum_interval", sbd.cfg.QuorumInterval,
		"resolution_strategy", sbd.cfg.ResolutionStrategy)

	return nil
}

// Stop stops split-brain detection
func (sbd *splitBrainDetector) Stop(ctx context.Context) error {
	sbd.mu.Lock()
	defer sbd.mu.Unlock()

	if !sbd.started {
		return nil
	}

	if sbd.cancel != nil {
		sbd.cancel()
	}

	sbd.started = false
	sbd.logger.Info("Split-brain detector stopped")

	return nil
}

// CheckSplitBrain checks for split-brain conditions
func (sbd *splitBrainDetector) CheckSplitBrain(ctx context.Context) (*SplitBrainStatus, error) {
	sbd.mu.RLock()
	defer sbd.mu.RUnlock()

	// Perform immediate split-brain check
	status := sbd.performSplitBrainCheck()

	// Return a copy to prevent modification
	statusCopy := *status
	statusCopy.Details = make(map[string]interface{})
	for k, v := range status.Details {
		statusCopy.Details[k] = v
	}

	return &statusCopy, nil
}

// RegisterSplitBrainHandler registers a handler for split-brain events
func (sbd *splitBrainDetector) RegisterSplitBrainHandler(handler SplitBrainHandler) {
	sbd.mu.Lock()
	defer sbd.mu.Unlock()

	sbd.handlers = append(sbd.handlers, handler)
	sbd.logger.Debug("Split-brain handler registered")
}

// periodicDetection performs periodic split-brain detection
func (sbd *splitBrainDetector) periodicDetection() {
	ticker := time.NewTicker(sbd.cfg.DetectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sbd.ctx.Done():
			return
		case <-ticker.C:
			sbd.performPeriodicCheck()
		}
	}
}

// periodicQuorumValidation performs periodic quorum validation
func (sbd *splitBrainDetector) periodicQuorumValidation() {
	ticker := time.NewTicker(sbd.cfg.QuorumInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sbd.ctx.Done():
			return
		case <-ticker.C:
			sbd.performQuorumValidation()
		}
	}
}

// performPeriodicCheck performs a periodic split-brain check
func (sbd *splitBrainDetector) performPeriodicCheck() {
	sbd.mu.Lock()
	defer sbd.mu.Unlock()

	status := sbd.performSplitBrainCheck()
	oldStatus := sbd.currentStatus.Detected

	sbd.currentStatus = status
	sbd.lastDetection = time.Now()

	// Handle status changes
	if status.Detected && !oldStatus {
		sbd.handleSplitBrainDetected(status)
	} else if !status.Detected && oldStatus {
		sbd.handleSplitBrainResolved(status)
	}
}

// performSplitBrainCheck performs the actual split-brain detection logic
func (sbd *splitBrainDetector) performSplitBrainCheck() *SplitBrainStatus {
	status := &SplitBrainStatus{
		Detected:  false,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Only check for split-brain in cluster mode
	if sbd.manager.cfg.Mode != ClusterMode {
		status.Details["mode"] = sbd.manager.cfg.Mode.String()
		status.Details["reason"] = "split-brain detection only applies to cluster mode"
		return status
	}

	// Get cluster nodes
	nodes, err := sbd.manager.GetClusterNodes()
	if err != nil {
		status.Details["error"] = fmt.Sprintf("failed to get cluster nodes: %v", err)
		return status
	}

	// Count leaders and analyze partitions
	leaderCount := 0
	partitions := sbd.analyzePartitions(nodes)

	for _, node := range nodes {
		if node.Role == NodeRoleLeader {
			leaderCount++
		}
	}

	status.Details["total_nodes"] = len(nodes)
	status.Details["leader_count"] = leaderCount
	status.Details["partitions"] = len(partitions)

	// Split-brain conditions:
	// 1. Multiple leaders
	// 2. Network partitions with separate quorums
	// 3. Quorum loss with multiple claiming leadership

	if leaderCount > 1 {
		status.Detected = true
		status.PartitionIDs = sbd.getPartitionIDs(partitions)
		status.Details["condition"] = "multiple_leaders"
		status.Details["leader_nodes"] = sbd.getLeaderNodes(nodes)
	} else if len(partitions) > 1 {
		// Check if partitions have independent quorums
		for _, partition := range partitions {
			if partition.LeaderClaims > 0 && len(partition.Nodes) >= sbd.manager.cfg.Cluster.MinQuorum {
				status.Detected = true
				status.PartitionIDs = sbd.getPartitionIDs(partitions)
				status.Details["condition"] = "partition_with_quorum"
				break
			}
		}
	}

	// Update partition tracking
	sbd.updatePartitionTracking(partitions)

	return status
}

// analyzePartitions analyzes the cluster for potential network partitions
func (sbd *splitBrainDetector) analyzePartitions(nodes []*NodeInfo) []*partitionInfo {
	// Simple partition detection based on node connectivity
	// In a production implementation, this would use more sophisticated
	// network connectivity analysis

	partitions := make([]*partitionInfo, 0)
	processed := make(map[string]bool)

	for _, node := range nodes {
		if processed[node.ID] {
			continue
		}

		partition := &partitionInfo{
			ID:        fmt.Sprintf("partition-%s", node.ID[:8]),
			Nodes:     []string{node.ID},
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}

		if node.Role == NodeRoleLeader {
			partition.LeaderClaims = 1
		}

		// For now, each node is in its own partition
		// This is a simplified implementation
		processed[node.ID] = true
		partitions = append(partitions, partition)
	}

	return partitions
}

// performQuorumValidation performs quorum validation
func (sbd *splitBrainDetector) performQuorumValidation() {
	sbd.mu.Lock()
	defer sbd.mu.Unlock()

	nodes, err := sbd.manager.GetClusterNodes()
	if err != nil {
		sbd.logger.Warn("Failed to get cluster nodes for quorum validation", "error", err)
		return
	}

	healthyNodes := 0
	for _, node := range nodes {
		if node.State == NodeStateHealthy || node.State == NodeStateDegraded {
			healthyNodes++
		}
	}

	requiredQuorum := sbd.manager.cfg.Cluster.MinQuorum
	hasQuorum := healthyNodes >= requiredQuorum

	sbd.logger.Debug("Quorum validation",
		"healthy_nodes", healthyNodes,
		"required_quorum", requiredQuorum,
		"has_quorum", hasQuorum)

	// If we don't have quorum and we're the leader, step down
	if !hasQuorum && sbd.manager.IsLeader() {
		sbd.logger.Warn("Quorum lost, stepping down as leader")
		sbd.manager.demoteFromLeader()

		// Notify handlers
		status := &SplitBrainStatus{
			Detected:   true,
			Timestamp:  time.Now(),
			Resolution: "stepped_down_no_quorum",
			Details: map[string]interface{}{
				"healthy_nodes":   healthyNodes,
				"required_quorum": requiredQuorum,
				"action":          "step_down",
			},
		}

		sbd.handleSplitBrainDetected(status)
	}
}

// handleSplitBrainDetected handles split-brain detection
func (sbd *splitBrainDetector) handleSplitBrainDetected(status *SplitBrainStatus) {
	sbd.logger.Warn("Split-brain condition detected",
		"condition", status.Details["condition"],
		"partitions", len(status.PartitionIDs),
		"resolution_strategy", sbd.cfg.ResolutionStrategy)

	// Apply resolution strategy
	resolution := sbd.applySplitBrainResolution(status)
	status.Resolution = resolution

	// Notify handlers
	for _, handler := range sbd.handlers {
		if err := handler.OnSplitBrainDetected(status); err != nil {
			sbd.logger.Warn("Split-brain detection handler failed", "error", err)
		}
	}
}

// handleSplitBrainResolved handles split-brain resolution
func (sbd *splitBrainDetector) handleSplitBrainResolved(status *SplitBrainStatus) {
	sbd.logger.Info("Split-brain condition resolved",
		"resolution", status.Resolution)

	// Notify handlers
	for _, handler := range sbd.handlers {
		if err := handler.OnSplitBrainResolved(status); err != nil {
			sbd.logger.Warn("Split-brain resolution handler failed", "error", err)
		}
	}
}

// applySplitBrainResolution applies the configured resolution strategy
func (sbd *splitBrainDetector) applySplitBrainResolution(status *SplitBrainStatus) string {
	switch sbd.cfg.ResolutionStrategy {
	case "quorum-based":
		return sbd.applyQuorumBasedResolution(status)
	case "oldest-leader":
		return sbd.applyOldestLeaderResolution(status)
	case "step-down":
		return sbd.applyStepDownResolution(status)
	default:
		sbd.logger.Warn("Unknown resolution strategy", "strategy", sbd.cfg.ResolutionStrategy)
		return "no_action"
	}
}

// applyQuorumBasedResolution applies quorum-based resolution
func (sbd *splitBrainDetector) applyQuorumBasedResolution(status *SplitBrainStatus) string {
	nodes, err := sbd.manager.GetClusterNodes()
	if err != nil {
		return "error_getting_nodes"
	}

	healthyNodes := 0
	for _, node := range nodes {
		if node.State == NodeStateHealthy || node.State == NodeStateDegraded {
			healthyNodes++
		}
	}

	// If we don't have quorum, step down if we're leader
	if healthyNodes < sbd.manager.cfg.Cluster.MinQuorum && sbd.manager.IsLeader() {
		sbd.manager.demoteFromLeader()
		return "stepped_down_no_quorum"
	}

	return "maintaining_quorum"
}

// applyOldestLeaderResolution applies oldest leader resolution
func (sbd *splitBrainDetector) applyOldestLeaderResolution(status *SplitBrainStatus) string {
	// Find the oldest leader and step down if we're not it
	// This is a simplified implementation
	if sbd.manager.IsLeader() {
		// For now, always step down - in production, would compare node start times
		sbd.manager.demoteFromLeader()
		return "stepped_down_not_oldest"
	}

	return "not_leader"
}

// applyStepDownResolution applies step-down resolution
func (sbd *splitBrainDetector) applyStepDownResolution(status *SplitBrainStatus) string {
	if sbd.manager.IsLeader() {
		sbd.manager.demoteFromLeader()
		return "stepped_down_split_brain"
	}

	return "not_leader"
}

// Helper functions

func (sbd *splitBrainDetector) getPartitionIDs(partitions []*partitionInfo) []string {
	ids := make([]string, len(partitions))
	for i, partition := range partitions {
		ids[i] = partition.ID
	}
	return ids
}

func (sbd *splitBrainDetector) getLeaderNodes(nodes []*NodeInfo) []string {
	leaders := make([]string, 0)
	for _, node := range nodes {
		if node.Role == NodeRoleLeader {
			leaders = append(leaders, node.ID)
		}
	}
	return leaders
}

func (sbd *splitBrainDetector) updatePartitionTracking(partitions []*partitionInfo) {
	now := time.Now()

	// Update existing partitions and add new ones
	for _, partition := range partitions {
		if existing, exists := sbd.partitionTrack[partition.ID]; exists {
			existing.LastSeen = now
			existing.Nodes = partition.Nodes
			existing.LeaderClaims = partition.LeaderClaims
		} else {
			partition.FirstSeen = now
			partition.LastSeen = now
			sbd.partitionTrack[partition.ID] = partition
		}
	}

	// Remove old partitions
	for id, partition := range sbd.partitionTrack {
		if now.Sub(partition.LastSeen) > sbd.cfg.DetectionInterval*3 {
			delete(sbd.partitionTrack, id)
		}
	}
}
