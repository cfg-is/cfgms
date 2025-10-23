// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package commands provides MQTT command publishing for controller operations.
//
// This package implements the command publisher that sends MQTT commands
// to stewards (Story #198).
package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/pkg/logging"
	mqttInterfaces "github.com/cfgis/cfgms/pkg/mqtt/interfaces"
	mqttTypes "github.com/cfgis/cfgms/pkg/mqtt/types"
)

// Publisher publishes commands to stewards via MQTT.
type Publisher struct {
	mu sync.RWMutex

	// MQTT broker for publishing
	broker mqttInterfaces.Broker

	// Command tracking
	pending map[string]*pendingCommand

	// Logger
	logger logging.Logger
}

// pendingCommand tracks a command awaiting response.
type pendingCommand struct {
	CommandID   string
	StewardID   string
	Type        mqttTypes.CommandType
	SentAt      time.Time
	Timeout     time.Duration
	OnComplete  func(status mqttTypes.StatusUpdate)
	OnTimeout   func()
	cancelTimer *time.Timer
}

// Config holds command publisher configuration.
type Config struct {
	// Broker is the MQTT broker to use for publishing
	Broker mqttInterfaces.Broker

	// Logger for command logging
	Logger logging.Logger
}

// New creates a new command publisher.
func New(cfg *Config) (*Publisher, error) {
	if cfg.Broker == nil {
		return nil, fmt.Errorf("MQTT broker is required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	return &Publisher{
		broker:  cfg.Broker,
		pending: make(map[string]*pendingCommand),
		logger:  cfg.Logger,
	}, nil
}

// PublishCommand publishes a command to a specific steward.
func (p *Publisher) PublishCommand(ctx context.Context, stewardID string, cmdType mqttTypes.CommandType, params map[string]interface{}) (string, error) {
	// Generate unique command ID
	commandID := uuid.New().String()

	// Create command message
	cmd := mqttTypes.Command{
		CommandID: commandID,
		Type:      cmdType,
		Timestamp: time.Now(),
		Params:    params,
	}

	payload, err := json.Marshal(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to marshal command: %w", err)
	}

	// Publish to steward's command topic
	topic := fmt.Sprintf("cfgms/steward/%s/commands", stewardID)
	if err := p.broker.Publish(ctx, topic, payload, 1, false); err != nil {
		return "", fmt.Errorf("failed to publish command: %w", err)
	}

	p.logger.Info("Published command to steward",
		"command_id", commandID,
		"steward_id", stewardID,
		"type", cmdType)

	return commandID, nil
}

// PublishCommandWithCallback publishes a command and waits for completion status.
func (p *Publisher) PublishCommandWithCallback(
	ctx context.Context,
	stewardID string,
	cmdType mqttTypes.CommandType,
	params map[string]interface{},
	timeout time.Duration,
	onComplete func(status mqttTypes.StatusUpdate),
	onTimeout func(),
) (string, error) {
	commandID, err := p.PublishCommand(ctx, stewardID, cmdType, params)
	if err != nil {
		return "", err
	}

	// Track pending command
	timer := time.AfterFunc(timeout, func() {
		p.handleCommandTimeout(commandID)
	})

	p.mu.Lock()
	p.pending[commandID] = &pendingCommand{
		CommandID:   commandID,
		StewardID:   stewardID,
		Type:        cmdType,
		SentAt:      time.Now(),
		Timeout:     timeout,
		OnComplete:  onComplete,
		OnTimeout:   onTimeout,
		cancelTimer: timer,
	}
	p.mu.Unlock()

	return commandID, nil
}

// HandleStatusUpdate processes a status update from a steward.
func (p *Publisher) HandleStatusUpdate(topic string, payload []byte, qos byte, retained bool) error {
	var status mqttTypes.StatusUpdate
	if err := json.Unmarshal(payload, &status); err != nil {
		p.logger.Error("Failed to parse status update", "error", err)
		return fmt.Errorf("failed to parse status update: %w", err)
	}

	// Check if this relates to a pending command
	if status.CommandID != "" {
		p.mu.Lock()
		pending, exists := p.pending[status.CommandID]
		if exists {
			// Cancel timeout timer
			if pending.cancelTimer != nil {
				pending.cancelTimer.Stop()
			}

			// Remove from pending if command completed or failed
			if status.Event == mqttTypes.EventCommandCompleted || status.Event == mqttTypes.EventCommandFailed {
				delete(p.pending, status.CommandID)
			}
		}
		p.mu.Unlock()

		// Call completion callback if exists
		if exists && pending.OnComplete != nil {
			pending.OnComplete(status)
		}
	}

	// Log status update
	p.logger.Info("Received status update from steward",
		"steward_id", status.StewardID,
		"event", status.Event,
		"command_id", status.CommandID)

	return nil
}

// handleCommandTimeout handles command timeout.
func (p *Publisher) handleCommandTimeout(commandID string) {
	p.mu.Lock()
	pending, exists := p.pending[commandID]
	if exists {
		delete(p.pending, commandID)
	}
	p.mu.Unlock()

	if exists {
		p.logger.Warn("Command timed out",
			"command_id", commandID,
			"steward_id", pending.StewardID,
			"type", pending.Type,
			"timeout", pending.Timeout)

		if pending.OnTimeout != nil {
			pending.OnTimeout()
		}
	}
}

// Start subscribes to status update topics from all stewards.
func (p *Publisher) Start(ctx context.Context) error {
	// Subscribe to status updates from all stewards
	statusTopic := "cfgms/steward/+/status"
	if err := p.broker.Subscribe(ctx, statusTopic, 1, p.HandleStatusUpdate); err != nil {
		return fmt.Errorf("failed to subscribe to status updates: %w", err)
	}

	p.logger.Info("Command publisher started", "status_topic", statusTopic)
	return nil
}

// Stop unsubscribes from topics and cleans up.
func (p *Publisher) Stop(ctx context.Context) error {
	// Unsubscribe from status updates
	if err := p.broker.Unsubscribe(ctx, "cfgms/steward/+/status"); err != nil {
		p.logger.Warn("Failed to unsubscribe from status updates", "error", err)
	}

	// Cancel all pending command timers
	p.mu.Lock()
	for _, pending := range p.pending {
		if pending.cancelTimer != nil {
			pending.cancelTimer.Stop()
		}
	}
	p.pending = make(map[string]*pendingCommand)
	p.mu.Unlock()

	p.logger.Info("Command publisher stopped")
	return nil
}

// GetPendingCommands returns a list of pending command IDs.
func (p *Publisher) GetPendingCommands() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	commands := make([]string, 0, len(p.pending))
	for cmdID := range p.pending {
		commands = append(commands, cmdID)
	}

	return commands
}

// TriggerQUICConnection sends a connect_quic command to a steward.
func (p *Publisher) TriggerQUICConnection(ctx context.Context, stewardID string, quicAddress string, sessionID string) (string, error) {
	params := map[string]interface{}{
		"quic_address": quicAddress,
		"session_id":   sessionID,
	}

	commandID, err := p.PublishCommand(ctx, stewardID, mqttTypes.CommandConnectQUIC, params)
	if err != nil {
		return "", fmt.Errorf("failed to trigger QUIC connection: %w", err)
	}

	p.logger.Info("Triggered QUIC connection",
		"steward_id", stewardID,
		"quic_address", quicAddress,
		"session_id", sessionID,
		"command_id", commandID)

	return commandID, nil
}

// TriggerConfigSync sends a sync_config command to a steward.
func (p *Publisher) TriggerConfigSync(ctx context.Context, stewardID string) (string, error) {
	commandID, err := p.PublishCommand(ctx, stewardID, mqttTypes.CommandSyncConfig, nil)
	if err != nil {
		return "", fmt.Errorf("failed to trigger config sync: %w", err)
	}

	p.logger.Info("Triggered config sync",
		"steward_id", stewardID,
		"command_id", commandID)

	return commandID, nil
}

// TriggerDNASync sends a sync_dna command to a steward.
func (p *Publisher) TriggerDNASync(ctx context.Context, stewardID string) (string, error) {
	commandID, err := p.PublishCommand(ctx, stewardID, mqttTypes.CommandSyncDNA, nil)
	if err != nil {
		return "", fmt.Errorf("failed to trigger DNA sync: %w", err)
	}

	p.logger.Info("Triggered DNA sync",
		"steward_id", stewardID,
		"command_id", commandID)

	return commandID, nil
}
