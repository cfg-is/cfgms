// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// HealthChecker manages health checking for the HA system
type HealthChecker struct {
	mu      sync.RWMutex
	cfg     *HealthCheckConfig
	logger  logging.Logger
	manager *Manager
	ctx     context.Context
	cancel  context.CancelFunc
	started bool

	// Health check state
	checkStates map[string]*healthCheckState
}

// healthCheckState tracks the state of a specific health check
type healthCheckState struct {
	name            string
	consecutiveOK   int
	consecutiveFail int
	lastCheck       time.Time
	lastResult      error
	currentState    NodeState
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(cfg *HealthCheckConfig, logger logging.Logger, manager *Manager) *HealthChecker {
	if cfg == nil {
		cfg = &HealthCheckConfig{
			Interval:         10 * time.Second,
			Timeout:          5 * time.Second,
			FailureThreshold: 3,
			SuccessThreshold: 2,
			EnableInternal:   true,
			EnableExternal:   true,
		}
	}

	return &HealthChecker{
		cfg:         cfg,
		logger:      logger,
		manager:     manager,
		checkStates: make(map[string]*healthCheckState),
	}
}

// Start begins health checking. initialChecks is a snapshot of the checks
// registered at the time Start is called; the caller must hold m.mu while
// building the snapshot to ensure it is consistent with what Manager.Start
// records before launching this goroutine.
func (h *HealthChecker) Start(ctx context.Context, initialChecks map[string]HealthCheckFunc) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.started {
		return fmt.Errorf("health checker is already started")
	}

	h.ctx, h.cancel = context.WithCancel(ctx)
	h.started = true

	// Initialize health check states from the caller-supplied snapshot.
	// Using a parameter (rather than reading h.manager.healthChecks directly)
	// avoids acquiring m.mu here, which would deadlock because Manager.Start
	// already holds m.mu when it calls this method.
	h.initializeCheckStates(initialChecks)

	// Start periodic health checking
	go h.periodicHealthCheck()

	h.logger.Info("Health checker started",
		"interval", h.cfg.Interval,
		"timeout", h.cfg.Timeout,
		"failure_threshold", h.cfg.FailureThreshold,
		"success_threshold", h.cfg.SuccessThreshold)

	return nil
}

// Stop stops health checking
func (h *HealthChecker) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.started {
		return nil
	}

	if h.cancel != nil {
		h.cancel()
	}

	h.started = false
	h.logger.Info("Health checker stopped")

	return nil
}

// initializeCheckStates seeds h.checkStates from a caller-supplied snapshot.
// Never reads h.manager.healthChecks directly — the snapshot is taken by
// Manager.Start under m.mu, making the dependency on that lock explicit.
func (h *HealthChecker) initializeCheckStates(checks map[string]HealthCheckFunc) {
	for name := range checks {
		h.checkStates[name] = &healthCheckState{
			name:         name,
			currentState: NodeStateHealthy,
			lastCheck:    time.Now(),
		}
	}
}

// periodicHealthCheck runs periodic health checks
func (h *HealthChecker) periodicHealthCheck() {
	ticker := time.NewTicker(h.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.performHealthChecks()
		}
	}
}

// performHealthChecks performs all registered health checks.
//
// Lock ordering: h.mu and m.mu must never be held simultaneously.
// Manager.Stop holds m.mu then calls h.Stop (which needs h.mu); holding
// both in the opposite order here causes a deadlock. Instead:
//  1. Copy healthChecks under m.mu.RLock (no h.mu).
//  2. Run checks and update h.checkStates under h.mu (no m.mu).
//  3. Publish results under m.mu.Lock (no h.mu).
func (h *HealthChecker) performHealthChecks() {
	// Step 1: snapshot the registered checks without holding h.mu.
	// RegisterHealthCheck writes healthChecks under m.mu.Lock, so we must
	// read it under m.mu.RLock to avoid a data race.
	h.manager.mu.RLock()
	checkFuncs := make(map[string]HealthCheckFunc, len(h.manager.healthChecks))
	for name, fn := range h.manager.healthChecks {
		checkFuncs[name] = fn
	}
	h.manager.mu.RUnlock()

	// Step 2: execute checks and update h.checkStates under h.mu only.
	checkResults := make(map[string]NodeState)
	overallState := NodeStateHealthy

	h.mu.Lock()
	for name, checkFunc := range checkFuncs {
		state := h.performSingleHealthCheck(name, checkFunc)
		checkResults[name] = state

		if state == NodeStateFailed {
			overallState = NodeStateFailed
		} else if state == NodeStateDegraded && overallState == NodeStateHealthy {
			overallState = NodeStateDegraded
		}
	}
	h.mu.Unlock()

	// Step 3: publish results under m.mu only (h.mu already released).
	h.manager.mu.Lock()
	h.manager.healthStatus = &HealthStatus{
		Overall:   overallState,
		Checks:    checkResults,
		Timestamp: time.Now(),
		Details:   make(map[string]string),
	}
	h.manager.nodeInfo.State = overallState
	h.manager.mu.Unlock()

	h.logger.Debug("Health check completed",
		"overall_state", overallState.String(),
		"checks_count", len(checkResults))
}

// performSingleHealthCheck performs a single health check
func (h *HealthChecker) performSingleHealthCheck(name string, checkFunc HealthCheckFunc) NodeState {
	// Get or create check state
	state, exists := h.checkStates[name]
	if !exists {
		state = &healthCheckState{
			name:         name,
			currentState: NodeStateHealthy,
		}
		h.checkStates[name] = state
	}

	// Create timeout context for health check
	checkCtx, cancel := context.WithTimeout(h.ctx, h.cfg.Timeout)
	defer cancel()

	// Perform the health check
	state.lastCheck = time.Now()
	err := checkFunc(checkCtx)
	state.lastResult = err

	// Update consecutive counters
	if err == nil {
		state.consecutiveOK++
		state.consecutiveFail = 0
	} else {
		state.consecutiveFail++
		state.consecutiveOK = 0
	}

	// Determine new state based on thresholds
	newState := h.determineHealthState(state)

	// Log state changes
	if newState != state.currentState {
		h.logger.Info("Health check state changed",
			"check_name", name,
			"old_state", state.currentState.String(),
			"new_state", newState.String(),
			"consecutive_ok", state.consecutiveOK,
			"consecutive_fail", state.consecutiveFail,
			"error", err)
	}

	state.currentState = newState
	return newState
}

// determineHealthState determines the health state based on consecutive results
func (h *HealthChecker) determineHealthState(state *healthCheckState) NodeState {
	// If we have enough consecutive successes, mark as healthy
	if state.consecutiveOK >= h.cfg.SuccessThreshold {
		return NodeStateHealthy
	}

	// If we have enough consecutive failures, mark as failed
	if state.consecutiveFail >= h.cfg.FailureThreshold {
		return NodeStateFailed
	}

	// If we're currently healthy but have some failures, mark as degraded
	if state.currentState == NodeStateHealthy && state.consecutiveFail > 0 {
		return NodeStateDegraded
	}

	// Keep current state if no threshold is reached
	return state.currentState
}

// GetHealthCheckStates returns the current health check states
func (h *HealthChecker) GetHealthCheckStates() map[string]*healthCheckState {
	h.mu.RLock()
	defer h.mu.RUnlock()

	states := make(map[string]*healthCheckState)
	for name, state := range h.checkStates {
		// Create a copy to prevent modification
		stateCopy := *state
		states[name] = &stateCopy
	}

	return states
}

// GetOverallHealth returns the overall health status
func (h *HealthChecker) GetOverallHealth() NodeState {
	h.mu.RLock()
	defer h.mu.RUnlock()

	overallState := NodeStateHealthy
	for _, state := range h.checkStates {
		if state.currentState == NodeStateFailed {
			return NodeStateFailed
		} else if state.currentState == NodeStateDegraded && overallState == NodeStateHealthy {
			overallState = NodeStateDegraded
		}
	}

	return overallState
}
