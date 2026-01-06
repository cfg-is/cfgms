// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package heartbeat provides MQTT-based heartbeat monitoring for steward connections.
//
// This service monitors steward heartbeats via MQTT and provides failover detection
// with <15 second detection time as required by Story #198.
package heartbeat

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	mqttInterfaces "github.com/cfgis/cfgms/pkg/mqtt/interfaces"
)

// HeartbeatMessage represents a steward heartbeat message.
type HeartbeatMessage struct {
	StewardID string            `json:"steward_id"`
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Metrics   map[string]string `json:"metrics,omitempty"`
}

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

// Service monitors steward heartbeats via MQTT.
type Service struct {
	mu sync.RWMutex

	// MQTT broker for subscriptions
	broker mqttInterfaces.Broker

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
	// Broker is the MQTT broker to use for subscriptions
	Broker mqttInterfaces.Broker

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
	if cfg.Broker == nil {
		return nil, fmt.Errorf("MQTT broker is required")
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
		broker:           cfg.Broker,
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

	// Subscribe to all steward heartbeat topics
	heartbeatTopic := "cfgms/steward/+/heartbeat"
	if err := s.broker.Subscribe(ctx, heartbeatTopic, 1, s.handleHeartbeat); err != nil {
		return fmt.Errorf("failed to subscribe to heartbeat topic: %w", err)
	}

	// Subscribe to steward will messages (for disconnect detection)
	willTopic := "cfgms/steward/+/will"
	if err := s.broker.Subscribe(ctx, willTopic, 1, s.handleWill); err != nil {
		return fmt.Errorf("failed to subscribe to will topic: %w", err)
	}

	// Start background checker for stale heartbeats
	go s.monitorHeartbeats()

	s.logger.Info("Heartbeat monitoring service started")
	return nil
}

// Stop stops the heartbeat monitoring service.
func (s *Service) Stop(ctx context.Context) error {
	s.logger.Info("Stopping heartbeat monitoring service")
	s.cancel()

	// Unsubscribe from topics
	_ = s.broker.Unsubscribe(ctx, "cfgms/steward/+/heartbeat")
	_ = s.broker.Unsubscribe(ctx, "cfgms/steward/+/will")

	return nil
}

// handleHeartbeat processes incoming heartbeat messages.
func (s *Service) handleHeartbeat(topic string, payload []byte, qos byte, retained bool) error {
	var msg HeartbeatMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		s.logger.Warn("Failed to parse heartbeat message", "error", err, "payload", string(payload))
		return fmt.Errorf("failed to parse heartbeat: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	status, exists := s.stewards[msg.StewardID]
	if !exists {
		// New steward
		status = &StewardStatus{
			StewardID:      msg.StewardID,
			ConnectedSince: time.Now(),
		}
		s.stewards[msg.StewardID] = status
		s.logger.Info("New steward registered", "steward_id", msg.StewardID)
	}

	previouslyHealthy := status.Healthy

	// Update status
	status.LastHeartbeat = msg.Timestamp
	status.Status = msg.Status
	status.Metrics = msg.Metrics
	status.MissedBeats = 0
	status.Healthy = true

	// Trigger callback if status changed
	if !previouslyHealthy && s.onStatusChange != nil {
		s.onStatusChange(msg.StewardID, true, *status)
	}

	return nil
}

// handleWill processes last will messages (steward disconnected).
func (s *Service) handleWill(topic string, payload []byte, qos byte, retained bool) error {
	var msg HeartbeatMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		s.logger.Warn("Failed to parse will message", "error", err)
		return fmt.Errorf("failed to parse will message: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	status, exists := s.stewards[msg.StewardID]
	if exists {
		status.Healthy = false
		status.Status = "disconnected"

		s.logger.Warn("Steward disconnected (will message)", "steward_id", msg.StewardID)

		if s.onStatusChange != nil {
			s.onStatusChange(msg.StewardID, false, *status)
		}
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
