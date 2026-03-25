// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package commands provides command publishing for controller operations.
//
// This package implements the command publisher that sends commands
// to stewards via the ControlPlaneProvider abstraction (Story #198, Story #363).
package commands

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Publisher publishes commands to stewards via the ControlPlaneProvider.
type Publisher struct {
	mu sync.RWMutex

	// Control plane provider for command publishing (Story #363)
	controlPlane controlplaneInterfaces.ControlPlaneProvider

	// Command tracking
	pending map[string]*pendingCommand

	// Logger
	logger logging.Logger
}

// pendingCommand tracks a command awaiting response.
type pendingCommand struct {
	CommandID   string
	StewardID   string
	Type        controlplaneTypes.CommandType
	SentAt      time.Time
	Timeout     time.Duration
	OnComplete  func(event *controlplaneTypes.Event)
	OnTimeout   func()
	cancelTimer *time.Timer
}

// Config holds command publisher configuration.
type Config struct {
	// ControlPlane is the control plane provider for command publishing (Story #363)
	ControlPlane controlplaneInterfaces.ControlPlaneProvider

	// Logger for command logging
	Logger logging.Logger
}

// New creates a new command publisher.
func New(cfg *Config) (*Publisher, error) {
	if cfg.ControlPlane == nil {
		return nil, fmt.Errorf("control plane provider is required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	return &Publisher{
		controlPlane: cfg.ControlPlane,
		pending:      make(map[string]*pendingCommand),
		logger:       cfg.Logger,
	}, nil
}

// PublishCommand publishes a command to a specific steward.
// Story #363: Uses ControlPlaneProvider.SendCommand() for delivery.
func (p *Publisher) PublishCommand(ctx context.Context, stewardID string, cmdType controlplaneTypes.CommandType, params map[string]interface{}) (string, error) {
	// Generate unique command ID
	commandID := uuid.New().String()

	// Create command message using control plane types
	cmd := &controlplaneTypes.Command{
		ID:        commandID,
		Type:      cmdType,
		StewardID: stewardID,
		Timestamp: time.Now(),
		Params:    params,
	}

	// Send via control plane provider (publishes to cfgms/commands/{stewardID})
	if err := p.controlPlane.SendCommand(ctx, cmd); err != nil {
		return "", fmt.Errorf("failed to send command: %w", err)
	}

	p.logger.Info("Sent command to steward",
		"command_id", commandID,
		"steward_id", stewardID,
		"type", cmdType)

	return commandID, nil
}

// PublishCommandWithCallback publishes a command and waits for completion event.
func (p *Publisher) PublishCommandWithCallback(
	ctx context.Context,
	stewardID string,
	cmdType controlplaneTypes.CommandType,
	params map[string]interface{},
	timeout time.Duration,
	onComplete func(event *controlplaneTypes.Event),
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

// HandleEventUpdate processes an event from a steward via the ControlPlaneProvider.
// Story #363: Replaces HandleStatusUpdate via ControlPlaneProvider events.
func (p *Publisher) HandleEventUpdate(ctx context.Context, event *controlplaneTypes.Event) error {
	// Check if this relates to a pending command
	if event.CommandID != "" {
		p.mu.Lock()
		pending, exists := p.pending[event.CommandID]
		if exists {
			// Cancel timeout timer
			if pending.cancelTimer != nil {
				pending.cancelTimer.Stop()
			}

			// Remove from pending if command completed or failed
			if event.Type == controlplaneTypes.EventCommandCompleted || event.Type == controlplaneTypes.EventCommandFailed {
				delete(p.pending, event.CommandID)
			}
		}
		p.mu.Unlock()

		// Call completion callback if exists
		if exists && pending.OnComplete != nil {
			pending.OnComplete(event)
		}
	}

	// Log event
	p.logger.Info("Received event from steward",
		"steward_id", event.StewardID,
		"event_type", event.Type,
		"command_id", event.CommandID)

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

// Start subscribes to event updates from all stewards via ControlPlaneProvider.
// Story #363: Uses SubscribeEvents() via ControlPlaneProvider.
func (p *Publisher) Start(ctx context.Context) error {
	// Subscribe to command-related events from stewards
	// Filter for command completion/failure events
	filter := &controlplaneTypes.EventFilter{
		EventTypes: []controlplaneTypes.EventType{
			controlplaneTypes.EventCommandReceived,
			controlplaneTypes.EventCommandCompleted,
			controlplaneTypes.EventCommandFailed,
		},
	}
	if err := p.controlPlane.SubscribeEvents(ctx, filter, p.HandleEventUpdate); err != nil {
		return fmt.Errorf("failed to subscribe to events: %w", err)
	}

	p.logger.Info("Command publisher started", "event_types", "command_received,command_completed,command_failed")
	return nil
}

// Stop cleans up pending commands.
// Story #363: Provider cleanup is handled by the provider's Stop method.
func (p *Publisher) Stop(ctx context.Context) error {
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

// TriggerConfigSync sends a sync_config command to a steward.
func (p *Publisher) TriggerConfigSync(ctx context.Context, stewardID string) (string, error) {
	commandID, err := p.PublishCommand(ctx, stewardID, controlplaneTypes.CommandSyncConfig, nil)
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
	commandID, err := p.PublishCommand(ctx, stewardID, controlplaneTypes.CommandSyncDNA, nil)
	if err != nil {
		return "", fmt.Errorf("failed to trigger DNA sync: %w", err)
	}

	p.logger.Info("Triggered DNA sync",
		"steward_id", stewardID,
		"command_id", commandID)

	return commandID, nil
}
