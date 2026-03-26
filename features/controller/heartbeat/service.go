// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package heartbeat provides heartbeat monitoring for steward connections.
//
// This service monitors steward heartbeats via the ControlPlaneProvider and provides
// failover detection with <15 second detection time as required by Story #198.
//
// Story #363: Uses ControlPlaneProvider abstraction for transport-agnostic heartbeat monitoring.
package heartbeat

import (
	"context"
	"fmt"
	"sync"
	"time"

	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// StewardStatus represents the current status of a steward.
type StewardStatus struct {
	StewardID      string
	LastHeartbeat  time.Time
	Status         string
	Healthy        bool
	Metrics        map[string]string
	MissedBeats    int
	ConnectedSince time.Time
}

// StatusChangeCallback is called when a steward's status changes.
type StatusChangeCallback func(stewardID string, healthy bool, status StewardStatus)

// Service monitors steward heartbeats via the ControlPlaneProvider.
type Service struct {
	mu sync.RWMutex

	// Control plane provider for heartbeat subscriptions (Story #363)
	controlPlane controlplaneInterfaces.ControlPlaneProvider

	// Steward status tracking
	stewards map[string]*StewardStatus

	// Configuration
	heartbeatTimeout time.Duration // Time before marking steward as unhealthy
	checkInterval    time.Duration // How often to check for timeouts

	// Callbacks
	onStatusChange StatusChangeCallback

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	logger logging.Logger
}

// Config holds heartbeat service configuration.
type Config struct {
	// ControlPlane is the control plane provider for heartbeat subscriptions (Story #363)
	ControlPlane controlplaneInterfaces.ControlPlaneProvider

	// HeartbeatTimeout is how long to wait before marking a steward unhealthy
	// Default: 15 seconds (Story #198 requirement)
	HeartbeatTimeout time.Duration

	// CheckInterval is how often to check for stale heartbeats
	// Default: 5 seconds
	CheckInterval time.Duration

	// OnStatusChange callback for status changes
	OnStatusChange StatusChangeCallback

	// Logger for service logging
	Logger logging.Logger
}

// New creates a new heartbeat monitoring service.
func New(cfg *Config) (*Service, error) {
	if cfg.ControlPlane == nil {
		return nil, fmt.Errorf("control plane provider is required")
	}

	heartbeatTimeout := cfg.HeartbeatTimeout
	if heartbeatTimeout == 0 {
		heartbeatTimeout = 15 * time.Second // Story #198 requirement: <15s failover detection
	}

	checkInterval := cfg.CheckInterval
	if checkInterval == 0 {
		checkInterval = 5 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Service{
		controlPlane:     cfg.ControlPlane,
		stewards:         make(map[string]*StewardStatus),
		heartbeatTimeout: heartbeatTimeout,
		checkInterval:    checkInterval,
		onStatusChange:   cfg.OnStatusChange,
		ctx:              ctx,
		cancel:           cancel,
		logger:           cfg.Logger,
	}, nil
}

// Start begins monitoring heartbeats.
func (s *Service) Start(ctx context.Context) error {
	s.logger.Info("Starting heartbeat monitoring service",
		"timeout", s.heartbeatTimeout,
		"check_interval", s.checkInterval)

	// Subscribe to heartbeats via control plane provider (Story #363)
	// Uses new topic pattern: cfgms/heartbeats/+ instead of cfgms/steward/+/heartbeat
	if err := s.controlPlane.SubscribeHeartbeats(ctx, s.handleHeartbeatFromProvider); err != nil {
		return fmt.Errorf("failed to subscribe to heartbeats: %w", err)
	}

	// Note: Will/LWT messages are no longer subscribed separately.
	// Steward disconnection is detected via heartbeat timeout in monitorHeartbeats().

	// Start background checker for stale heartbeats
	go s.monitorHeartbeats()

	s.logger.Info("Heartbeat monitoring service started")
	return nil
}

// Stop stops the heartbeat monitoring service.
func (s *Service) Stop(ctx context.Context) error {
	s.logger.Info("Stopping heartbeat monitoring service")
	s.cancel()

	// Provider cleanup is handled by the provider's Stop method
	return nil
}

// handleHeartbeatFromProvider processes incoming heartbeats from the ControlPlaneProvider.
// Story #363: Processes typed heartbeat messages from ControlPlaneProvider.
func (s *Service) handleHeartbeatFromProvider(ctx context.Context, hb *controlplaneTypes.Heartbeat) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	status, exists := s.stewards[hb.StewardID]
	if !exists {
		// New steward
		status = &StewardStatus{
			StewardID:      hb.StewardID,
			ConnectedSince: time.Now(),
		}
		s.stewards[hb.StewardID] = status
		s.logger.Info("New steward registered", "steward_id", hb.StewardID)
	}

	previouslyHealthy := status.Healthy

	// Update status
	status.LastHeartbeat = hb.Timestamp
	status.Status = string(hb.Status)

	// Convert metrics from map[string]interface{} to map[string]string
	if hb.Metrics != nil {
		metrics := make(map[string]string, len(hb.Metrics))
		for k, v := range hb.Metrics {
			metrics[k] = fmt.Sprintf("%v", v)
		}
		status.Metrics = metrics
	}

	status.MissedBeats = 0
	status.Healthy = true

	// Trigger callback if status changed
	if !previouslyHealthy && s.onStatusChange != nil {
		s.onStatusChange(hb.StewardID, true, *status)
	}

	return nil
}

// monitorHeartbeats runs in the background checking for stale heartbeats.
func (s *Service) monitorHeartbeats() {
	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.checkStaleHeartbeats()
		}
	}
}

// checkStaleHeartbeats checks for stewards with stale heartbeats.
func (s *Service) checkStaleHeartbeats() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for stewardID, status := range s.stewards {
		if status.Healthy {
			timeSinceLastBeat := now.Sub(status.LastHeartbeat)
			if timeSinceLastBeat > s.heartbeatTimeout {
				// Mark as unhealthy
				status.Healthy = false
				status.MissedBeats++
				status.Status = "timeout"

				s.logger.Warn("Steward heartbeat timeout",
					"steward_id", stewardID,
					"last_heartbeat", status.LastHeartbeat,
					"timeout", timeSinceLastBeat)

				if s.onStatusChange != nil {
					s.onStatusChange(stewardID, false, *status)
				}
			}
		}
	}
}

// GetStatus returns the current status of a steward.
func (s *Service) GetStatus(stewardID string) (*StewardStatus, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status, exists := s.stewards[stewardID]
	if !exists {
		return nil, false
	}

	// Return a copy to prevent race conditions
	statusCopy := *status
	return &statusCopy, true
}

// GetAllStatuses returns the status of all stewards.
func (s *Service) GetAllStatuses() map[string]StewardStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	statuses := make(map[string]StewardStatus, len(s.stewards))
	for id, status := range s.stewards {
		statuses[id] = *status
	}

	return statuses
}

// GetHealthyStewards returns a list of healthy steward IDs.
func (s *Service) GetHealthyStewards() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var healthy []string
	for id, status := range s.stewards {
		if status.Healthy {
			healthy = append(healthy, id)
		}
	}

	return healthy
}

// GetUnhealthyStewards returns a list of unhealthy steward IDs.
func (s *Service) GetUnhealthyStewards() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var unhealthy []string
	for id, status := range s.stewards {
		if !status.Healthy {
			unhealthy = append(unhealthy, id)
		}
	}

	return unhealthy
}
