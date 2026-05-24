// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

type failoverManager struct {
	mu      sync.RWMutex
	cfg     *FailoverConfig
	logger  logging.Logger
	manager *Manager
	ctx     context.Context
	cancel  context.CancelFunc
	started bool

	// Failover state
	handlers       []FailoverHandler
	failoverEvents []*FailoverEvent
	isFailingOver  bool
	lastFailover   time.Time
}

// NewFailoverManager creates a new failover manager
func NewFailoverManager(cfg *FailoverConfig, logger logging.Logger, manager *Manager) (*failoverManager, error) {
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

	// Elect new leader (if in cluster mode)
	if fm.manager.cfg.Mode == ClusterMode {
		if err := fm.electNewLeader(ctx); err != nil {
			failoverErr = fmt.Errorf("leader election failed: %w", err)
		}
	} else {
		// For single server or blue-green mode, the local node is always the leader.
		fm.logger.Info("Non-cluster mode failover: local node is leader by default")
	}

	sessionsMigrated := 0

	// Update cluster state after leader election
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

// electNewLeader defers to Raft consensus for leader election.
// Raft is the sole authority for leader election; explicit promote/demote calls
// have been removed. The Raft protocol (CheckQuorum, PreVote) handles step-down
// and promotion automatically.
func (fm *failoverManager) electNewLeader(ctx context.Context) error {
	fm.logger.Info("Leader election deferred to Raft consensus — Raft is the sole election authority")
	return nil
}

// updateClusterState updates cluster state after failover
func (fm *failoverManager) updateClusterState(ctx context.Context) error {
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
