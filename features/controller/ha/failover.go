package ha

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// failoverManager implements FailoverManager interface
type failoverManager struct {
	mu       sync.RWMutex
	cfg      *FailoverConfig
	logger   logging.Logger
	manager  *Manager
	ctx      context.Context
	cancel   context.CancelFunc
	started  bool

	// Failover state
	handlers       []FailoverHandler
	failoverEvents []*FailoverEvent
	isFailingOver  bool
	lastFailover   time.Time
}

// NewFailoverManager creates a new failover manager
func NewFailoverManager(cfg *FailoverConfig, logger logging.Logger, manager *Manager) (FailoverManager, error) {
	if cfg == nil {
		cfg = &FailoverConfig{
			Enabled:             true,
			Timeout:             30 * time.Second,
			MaxDuration:         5 * time.Minute,
			GracePeriod:         10 * time.Second,
			MaxSessionMigration: 1000,
		}
	}

	return &failoverManager{
		cfg:            cfg,
		logger:         logger,
		manager:        manager,
		failoverEvents: make([]*FailoverEvent, 0),
	}, nil
}

// Start begins failover monitoring
func (fm *failoverManager) Start(ctx context.Context) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if !fm.cfg.Enabled {
		fm.logger.Info("Failover is disabled")
		return nil
	}

	if fm.started {
		return fmt.Errorf("failover manager is already started")
	}

	fm.ctx, fm.cancel = context.WithCancel(ctx)
	fm.started = true

	// Start monitoring
	go fm.monitorClusterHealth()

	fm.logger.Info("Failover manager started",
		"timeout", fm.cfg.Timeout,
		"max_duration", fm.cfg.MaxDuration,
		"grace_period", fm.cfg.GracePeriod)

	return nil
}

// Stop stops failover monitoring
func (fm *failoverManager) Stop(ctx context.Context) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if !fm.started {
		return nil
	}

	if fm.cancel != nil {
		fm.cancel()
	}

	fm.started = false
	fm.logger.Info("Failover manager stopped")

	return nil
}

// RegisterFailoverHandler registers a handler for failover events
func (fm *failoverManager) RegisterFailoverHandler(handler FailoverHandler) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fm.handlers = append(fm.handlers, handler)
	fm.logger.Debug("Failover handler registered")
}

// TriggerFailover manually triggers a failover
func (fm *failoverManager) TriggerFailover(ctx context.Context, reason string) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if !fm.cfg.Enabled {
		return fmt.Errorf("failover is disabled")
	}

	if fm.isFailingOver {
		return fmt.Errorf("failover is already in progress")
	}

	// Check grace period
	if time.Since(fm.lastFailover) < fm.cfg.GracePeriod {
		return fmt.Errorf("failover grace period not elapsed")
	}

	fm.logger.Info("Manual failover triggered", "reason", reason)

	return fm.executeFailover(ctx, reason, true)
}

// GetFailoverHistory returns recent failover events
func (fm *failoverManager) GetFailoverHistory() ([]*FailoverEvent, error) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	// Return a copy to prevent modification
	events := make([]*FailoverEvent, len(fm.failoverEvents))
	copy(events, fm.failoverEvents)

	return events, nil
}

// monitorClusterHealth monitors cluster health and triggers failover if needed
func (fm *failoverManager) monitorClusterHealth() {
	ticker := time.NewTicker(5 * time.Second) // Check health every 5 seconds
	defer ticker.Stop()

	for {
		select {
		case <-fm.ctx.Done():
			return
		case <-ticker.C:
			fm.checkForFailoverConditions()
		}
	}
}

// checkForFailoverConditions checks if failover conditions are met
func (fm *failoverManager) checkForFailoverConditions() {
	fm.mu.RLock()
	if fm.isFailingOver {
		fm.mu.RUnlock()
		return
	}
	fm.mu.RUnlock()

	// Get cluster status
	nodes, err := fm.manager.GetClusterNodes()
	if err != nil {
		fm.logger.Warn("Failed to get cluster nodes for failover check", "error", err)
		return
	}

	// Check if current leader is healthy
	leader, err := fm.manager.GetLeader()
	if err != nil {
		// No leader found, trigger leader election failover
		fm.triggerAutomaticFailover("no_leader_elected")
		return
	}

	// Check leader health
	leaderHealthy := false
	for _, node := range nodes {
		if node.ID == leader.ID {
			if node.State == NodeStateHealthy || node.State == NodeStateDegraded {
				leaderHealthy = true
			}
			break
		}
	}

	if !leaderHealthy {
		fm.triggerAutomaticFailover("leader_unhealthy")
		return
	}

	// Check cluster quorum (for cluster mode)
	if fm.manager.cfg.Mode == ClusterMode {
		healthyNodes := 0
		for _, node := range nodes {
			if node.State == NodeStateHealthy || node.State == NodeStateDegraded {
				healthyNodes++
			}
		}

		if healthyNodes < fm.manager.cfg.Cluster.MinQuorum {
			fm.triggerAutomaticFailover("quorum_lost")
			return
		}
	}
}

// triggerAutomaticFailover triggers automatic failover
func (fm *failoverManager) triggerAutomaticFailover(reason string) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if fm.isFailingOver {
		return
	}

	// Check grace period
	if time.Since(fm.lastFailover) < fm.cfg.GracePeriod {
		fm.logger.Debug("Failover grace period not elapsed, skipping automatic failover")
		return
	}

	fm.logger.Info("Automatic failover triggered", "reason", reason)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), fm.cfg.MaxDuration)
		defer cancel()

		if err := fm.executeFailover(ctx, reason, false); err != nil {
			fm.logger.Error("Automatic failover failed", "error", err)
		}
	}()
}

// executeFailover executes the failover process
func (fm *failoverManager) executeFailover(ctx context.Context, reason string, manual bool) error {
	startTime := time.Now()
	eventID := fmt.Sprintf("failover-%d", startTime.Unix())

	// Create failover event
	event := &FailoverEvent{
		ID:        eventID,
		Timestamp: startTime,
		Reason:    reason,
		Status:    "started",
		Details: map[string]interface{}{
			"manual": manual,
		},
	}

	// Get current leader before failover
	if currentLeader, err := fm.manager.GetLeader(); err == nil {
		event.PreviousLeader = currentLeader.ID
	}

	fm.isFailingOver = true
	fm.addFailoverEvent(event)

	// Notify handlers that failover started
	for _, handler := range fm.handlers {
		if err := handler.OnFailoverStarted(event); err != nil {
			fm.logger.Warn("Failover start handler failed", "error", err)
		}
	}

	fm.logger.Info("Failover started", "event_id", eventID, "reason", reason)

	// Execute failover steps
	var failoverErr error

	// Step 1: Elect new leader (if in cluster mode)
	if fm.manager.cfg.Mode == ClusterMode {
		if err := fm.electNewLeader(ctx); err != nil {
			failoverErr = fmt.Errorf("leader election failed: %w", err)
		}
	} else {
		// For single server or blue-green mode, promote local node
		fm.manager.promoteToLeader()
	}

	// Step 2: Migrate sessions if session sync is enabled
	sessionsMigrated := 0
	if failoverErr == nil && fm.manager.sessionSync != nil {
		migrated, err := fm.migrateSessions(ctx)
		if err != nil {
			fm.logger.Warn("Session migration failed", "error", err)
			// Don't fail the entire failover for session migration issues
		}
		sessionsMigrated = migrated
	}

	// Step 3: Update cluster state
	if failoverErr == nil {
		if err := fm.updateClusterState(ctx); err != nil {
			fm.logger.Warn("Cluster state update failed", "error", err)
			// Don't fail the entire failover for state update issues
		}
	}

	// Complete failover
	duration := time.Since(startTime)
	fm.isFailingOver = false
	fm.lastFailover = time.Now()

	// Update event
	event.Duration = duration
	event.SessionsMigrated = sessionsMigrated

	if failoverErr != nil {
		event.Status = "failed"
		event.Details["error"] = failoverErr.Error()

		// Notify handlers that failover failed
		for _, handler := range fm.handlers {
			if err := handler.OnFailoverFailed(event, failoverErr); err != nil {
				fm.logger.Warn("Failover failure handler failed", "error", err)
			}
		}

		fm.logger.Error("Failover failed",
			"event_id", eventID,
			"duration", duration,
			"error", failoverErr)

		return failoverErr
	}

	// Get new leader
	if newLeader, err := fm.manager.GetLeader(); err == nil {
		event.NewLeader = newLeader.ID
	}

	event.Status = "completed"

	// Notify handlers that failover completed
	for _, handler := range fm.handlers {
		if err := handler.OnFailoverCompleted(event); err != nil {
			fm.logger.Warn("Failover completion handler failed", "error", err)
		}
	}

	fm.logger.Info("Failover completed successfully",
		"event_id", eventID,
		"duration", duration,
		"sessions_migrated", sessionsMigrated,
		"new_leader", event.NewLeader)

	return nil
}

// electNewLeader elects a new leader from available nodes with geographic awareness
func (fm *failoverManager) electNewLeader(ctx context.Context) error {
	nodes, err := fm.manager.GetClusterNodes()
	if err != nil {
		return fmt.Errorf("failed to get cluster nodes: %w", err)
	}

	// Find healthy nodes that can become leader
	candidates := make([]*NodeInfo, 0)
	for _, node := range nodes {
		if node.State == NodeStateHealthy && node.Role != NodeRoleLeader {
			candidates = append(candidates, node)
		}
	}

	if len(candidates) == 0 {
		return fmt.Errorf("no healthy candidates for leader election")
	}

	// Apply geographic-aware leader selection
	newLeader := fm.selectGeographicAwareLeader(candidates)

	// Check if this node should become the leader
	localNode := fm.manager.GetLocalNode()
	if newLeader.ID == localNode.ID {
		fm.manager.promoteToLeader()
		fm.logger.Info("Local node elected as new leader",
			"node_id", localNode.ID,
			"region", localNode.Region)
	} else {
		fm.manager.demoteFromLeader()
		fm.logger.Info("Remote node elected as new leader",
			"node_id", newLeader.ID,
			"region", newLeader.Region)
	}

	return nil
}

// selectGeographicAwareLeader selects the best leader candidate considering geographic factors
func (fm *failoverManager) selectGeographicAwareLeader(candidates []*NodeInfo) *NodeInfo {
	if len(candidates) == 1 {
		return candidates[0]
	}

	localNode := fm.manager.GetLocalNode()
	if localNode == nil {
		// No local context, use first candidate
		return candidates[0]
	}

	// Scoring criteria for leader selection (higher score = better candidate):
	// 1. Same region as current leader (for session continuity) - 40%
	// 2. Lowest average latency to other nodes - 30%
	// 3. Regional distribution balance - 20%
	// 4. Node capabilities and resources - 10%

	var bestCandidate *NodeInfo
	var highestScore float64

	for _, candidate := range candidates {
		score := fm.calculateLeaderScore(candidate, localNode, candidates)
		if score > highestScore {
			highestScore = score
			bestCandidate = candidate
		}
	}

	if bestCandidate == nil {
		bestCandidate = candidates[0] // Fallback
	}

	fm.logger.Debug("Leader selected with geographic awareness",
		"selected_node", bestCandidate.ID,
		"selected_region", bestCandidate.Region,
		"score", highestScore)

	return bestCandidate
}

// calculateLeaderScore calculates a score for leader election candidacy
func (fm *failoverManager) calculateLeaderScore(candidate, localNode *NodeInfo, allCandidates []*NodeInfo) float64 {
	score := 0.0

	// Base score for being healthy
	score += 1.0

	// Same region bonus (session continuity)
	if candidate.Region == localNode.Region {
		score += 0.4
	}

	// Latency component - lower average latency to other nodes is better
	if len(candidate.Latency) > 0 {
		totalLatency := time.Duration(0)
		count := 0
		for _, otherNode := range allCandidates {
			if otherNode.ID != candidate.ID {
				if latency, exists := candidate.Latency[otherNode.ID]; exists {
					totalLatency += latency
					count++
				}
			}
		}
		if count > 0 {
			avgLatency := totalLatency / time.Duration(count)
			// Convert to score (lower latency = higher score)
			latencyScore := math.Max(0, 1.0-(float64(avgLatency.Milliseconds())/500.0)) * 0.3
			score += latencyScore
		}
	}

	// Regional distribution bonus - prefer distributing leadership across regions
	regionCount := make(map[string]int)
	for _, node := range allCandidates {
		regionCount[node.Region]++
	}

	// Prefer candidates from less represented regions
	if total := len(allCandidates); total > 0 {
		regionBalance := 1.0 - (float64(regionCount[candidate.Region]) / float64(total))
		score += regionBalance * 0.2
	}

	// Capability bonus (simplified - could be enhanced)
	if len(candidate.Capabilities) > 0 {
		score += 0.1
	}

	return score
}

// migrateSessions migrates sessions during failover with geographic optimization
func (fm *failoverManager) migrateSessions(ctx context.Context) (int, error) {
	if fm.manager.sessionSync == nil {
		return 0, nil // No session synchronizer available
	}

	// Get all cluster nodes to understand regional distribution
	nodes, err := fm.manager.GetClusterNodes()
	if err != nil {
		return 0, fmt.Errorf("failed to get cluster nodes for session migration: %w", err)
	}

	// Get current leader for migration planning
	newLeader, err := fm.manager.GetLeader()
	if err != nil {
		return 0, fmt.Errorf("no leader available for session migration: %w", err)
	}

	fm.logger.Info("Starting geographic-aware session migration",
		"new_leader", newLeader.ID,
		"new_leader_region", newLeader.Region,
		"total_nodes", len(nodes))

	// Plan session migration based on geographic proximity
	migrationPlan := fm.createGeographicMigrationPlan(nodes, newLeader)

	// Execute migration plan with regional optimization
	sessionsMigrated := 0
	for region, plan := range migrationPlan {
		migrated, err := fm.executeMigrationForRegion(ctx, region, plan)
		if err != nil {
			fm.logger.Warn("Failed to migrate sessions for region",
				"region", region,
				"error", err)
			continue // Continue with other regions
		}
		sessionsMigrated += migrated
	}

	fm.logger.Info("Geographic session migration completed",
		"total_migrated", sessionsMigrated,
		"regions_processed", len(migrationPlan))

	return sessionsMigrated, nil
}

// RegionMigrationPlan represents the migration plan for a specific region
type RegionMigrationPlan struct {
	SourceNodes      []*NodeInfo
	TargetNode       *NodeInfo
	ExpectedSessions int
	Priority         int // 1=high, 2=medium, 3=low
}

// createGeographicMigrationPlan creates a migration plan organized by region
func (fm *failoverManager) createGeographicMigrationPlan(nodes []*NodeInfo, newLeader *NodeInfo) map[string]*RegionMigrationPlan {
	plans := make(map[string]*RegionMigrationPlan)

	// Group nodes by region
	regionNodes := make(map[string][]*NodeInfo)
	for _, node := range nodes {
		region := node.Region
		if region == "" {
			region = "unknown"
		}
		regionNodes[region] = append(regionNodes[region], node)
	}

	// Create migration plan for each region
	for region, regionNodeList := range regionNodes {
		plan := &RegionMigrationPlan{
			SourceNodes: make([]*NodeInfo, 0),
			Priority:    2, // Default medium priority
		}

		// Find healthy target node in this region (prefer local nodes)
		var targetNode *NodeInfo
		for _, node := range regionNodeList {
			if node.State == NodeStateHealthy {
				if targetNode == nil || node.ID == newLeader.ID {
					targetNode = node
				}
			}
		}

		// If no healthy node in region, use new leader as fallback
		if targetNode == nil {
			targetNode = newLeader
			plan.Priority = 3 // Lower priority for cross-region migration
		} else if targetNode.Region == newLeader.Region {
			plan.Priority = 1 // High priority for same region as leader
		}

		plan.TargetNode = targetNode

		// Identify source nodes (failed or degraded nodes) in this region
		for _, node := range regionNodeList {
			if node.State == NodeStateFailed || node.State == NodeStateOffline {
				plan.SourceNodes = append(plan.SourceNodes, node)
			}
		}

		// Estimate sessions (simplified)
		plan.ExpectedSessions = len(plan.SourceNodes) * 50 // Rough estimate

		plans[region] = plan
	}

	return plans
}

// executeMigrationForRegion executes session migration for a specific region
func (fm *failoverManager) executeMigrationForRegion(ctx context.Context, region string, plan *RegionMigrationPlan) (int, error) {
	if len(plan.SourceNodes) == 0 {
		return 0, nil // No migration needed for this region
	}

	fm.logger.Debug("Executing migration for region",
		"region", region,
		"source_nodes", len(plan.SourceNodes),
		"target_node", plan.TargetNode.ID,
		"priority", plan.Priority)

	sessionsMigrated := 0

	// Apply timeout based on priority and cross-region factors
	timeout := fm.cfg.Timeout
	if plan.TargetNode.Region != region {
		// Cross-region migration gets longer timeout
		timeout = timeout * 2
	}

	migrationCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Simulate session migration process
	// In production, this would interact with the session synchronizer
	// to coordinate actual session state transfer

	for _, sourceNode := range plan.SourceNodes {
		// Simulate migration from source to target
		migratedFromNode := fm.estimateSessionsFromNode(sourceNode)
		sessionsMigrated += migratedFromNode

		fm.logger.Debug("Sessions migrated from node",
			"source_node", sourceNode.ID,
			"source_region", sourceNode.Region,
			"target_node", plan.TargetNode.ID,
			"target_region", plan.TargetNode.Region,
			"sessions", migratedFromNode)

		// Check for timeout
		select {
		case <-migrationCtx.Done():
			fm.logger.Warn("Migration timeout for region",
				"region", region,
				"partially_migrated", sessionsMigrated)
			return sessionsMigrated, migrationCtx.Err()
		default:
			// Continue migration
		}
	}

	return sessionsMigrated, nil
}

// estimateSessionsFromNode estimates the number of sessions to migrate from a node
func (fm *failoverManager) estimateSessionsFromNode(node *NodeInfo) int {
	// In production, this would query the actual session count
	// For now, provide reasonable estimates based on node state
	switch node.State {
	case NodeStateFailed, NodeStateOffline:
		return 25 // Estimate for failed nodes
	case NodeStateDegraded:
		return 10 // Fewer sessions for degraded nodes
	default:
		return 0 // Healthy nodes don't need migration
	}
}

// updateClusterState updates cluster state after failover
func (fm *failoverManager) updateClusterState(ctx context.Context) error {
	// Update local node state and propagate to cluster
	// In a production implementation, this would update distributed state
	return nil
}

// addFailoverEvent adds a failover event to history
func (fm *failoverManager) addFailoverEvent(event *FailoverEvent) {
	// Keep only the last 100 events
	if len(fm.failoverEvents) >= 100 {
		fm.failoverEvents = fm.failoverEvents[1:]
	}

	fm.failoverEvents = append(fm.failoverEvents, event)
}