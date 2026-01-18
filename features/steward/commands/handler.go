// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package commands provides MQTT command handling for steward operations.
//
// This package implements the command handler that processes MQTT commands
// from the controller and executes appropriate actions (Story #198).
package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	mqttTypes "github.com/cfgis/cfgms/pkg/mqtt/types"
)

// Handler processes MQTT commands from the controller.
type Handler struct {
	mu sync.RWMutex

	// Steward identification
	stewardID string

	// Command handlers
	handlers map[mqttTypes.CommandType]CommandFunc

	// Status callback for reporting back to controller
	onStatus StatusCallback

	// Logger
	logger logging.Logger

	// Execution tracking
	executing map[string]*executionContext
}

// CommandFunc is a function that handles a specific command type.
type CommandFunc func(ctx context.Context, cmd mqttTypes.Command) error

// StatusCallback is called when status updates should be sent to controller.
type StatusCallback func(status mqttTypes.StatusUpdate)

// executionContext tracks command execution state.
type executionContext struct {
	CommandID string
	StartTime time.Time
	Cancel    context.CancelFunc
}

// Config holds command handler configuration.
type Config struct {
	// StewardID identifies this steward
	StewardID string

	// OnStatus callback for status updates
	OnStatus StatusCallback

	// Logger for command execution logging
	Logger logging.Logger
}

// New creates a new command handler.
func New(cfg *Config) (*Handler, error) {
	if cfg.StewardID == "" {
		return nil, fmt.Errorf("steward ID is required")
	}
	if cfg.OnStatus == nil {
		return nil, fmt.Errorf("status callback is required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	return &Handler{
		stewardID: cfg.StewardID,
		handlers:  make(map[mqttTypes.CommandType]CommandFunc),
		onStatus:  cfg.OnStatus,
		logger:    cfg.Logger,
		executing: make(map[string]*executionContext),
	}, nil
}

// RegisterHandler registers a handler function for a specific command type.
func (h *Handler) RegisterHandler(cmdType mqttTypes.CommandType, handler CommandFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handlers[cmdType] = handler
	h.logger.Info("Registered command handler", "type", cmdType)
}

// HandleCommand processes an incoming MQTT command message.
func (h *Handler) HandleCommand(topic string, payload []byte) error {
	h.logger.Debug("Received command message", "topic", topic, "size", len(payload))

	var cmd mqttTypes.Command
	if err := json.Unmarshal(payload, &cmd); err != nil {
		h.logger.Error("Failed to parse command", "error", err, "payload", string(payload))
		return fmt.Errorf("failed to parse command: %w", err)
	}

	// Send command received status
	h.sendStatus(mqttTypes.StatusUpdate{
		StewardID: h.stewardID,
		Timestamp: time.Now(),
		Event:     mqttTypes.EventCommandReceived,
		CommandID: cmd.CommandID,
		Details: map[string]interface{}{
			"command_type": string(cmd.Type),
		},
	})

	// Execute command in background
	go h.executeCommand(cmd)

	return nil
}

// executeCommand executes a command with timeout and error handling.
func (h *Handler) executeCommand(cmd mqttTypes.Command) {
	h.logger.Info("Executing command",
		"command_id", cmd.CommandID,
		"type", cmd.Type,
		"timestamp", cmd.Timestamp)

	// Create execution context with timeout
	timeout := 30 * time.Second
	if timeoutVal, ok := cmd.Params["timeout_seconds"].(float64); ok {
		timeout = time.Duration(timeoutVal) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Track execution
	h.mu.Lock()
	h.executing[cmd.CommandID] = &executionContext{
		CommandID: cmd.CommandID,
		StartTime: time.Now(),
		Cancel:    cancel,
	}
	h.mu.Unlock()

	// Clean up execution tracking
	defer func() {
		h.mu.Lock()
		delete(h.executing, cmd.CommandID)
		h.mu.Unlock()
	}()

	// Get handler for this command type
	h.mu.RLock()
	handler, exists := h.handlers[cmd.Type]
	h.mu.RUnlock()

	if !exists {
		h.logger.Error("No handler registered for command type",
			"command_id", cmd.CommandID,
			"type", cmd.Type)

		h.sendStatus(mqttTypes.StatusUpdate{
			StewardID: h.stewardID,
			Timestamp: time.Now(),
			Event:     mqttTypes.EventCommandFailed,
			CommandID: cmd.CommandID,
			Details: map[string]interface{}{
				"error": fmt.Sprintf("no handler for command type: %s", cmd.Type),
			},
		})
		return
	}

	// Execute handler
	startTime := time.Now()
	err := handler(ctx, cmd)
	executionTime := time.Since(startTime)

	if err != nil {
		h.logger.Error("Command execution failed",
			"command_id", cmd.CommandID,
			"type", cmd.Type,
			"error", err.Error(),
			"execution_time", executionTime)

		h.sendStatus(mqttTypes.StatusUpdate{
			StewardID: h.stewardID,
			Timestamp: time.Now(),
			Event:     mqttTypes.EventCommandFailed,
			CommandID: cmd.CommandID,
			Details: map[string]interface{}{
				"error":             err.Error(),
				"execution_time_ms": executionTime.Milliseconds(),
			},
		})
		return
	}

	h.logger.Info("Command completed successfully",
		"command_id", cmd.CommandID,
		"type", cmd.Type,
		"execution_time", executionTime)

	h.sendStatus(mqttTypes.StatusUpdate{
		StewardID: h.stewardID,
		Timestamp: time.Now(),
		Event:     mqttTypes.EventCommandCompleted,
		CommandID: cmd.CommandID,
		Details: map[string]interface{}{
			"execution_time_ms": executionTime.Milliseconds(),
		},
	})
}

// sendStatus sends a status update via the callback.
func (h *Handler) sendStatus(status mqttTypes.StatusUpdate) {
	if h.onStatus != nil {
		h.onStatus(status)
	}
}

// CancelCommand cancels a running command by its ID.
func (h *Handler) CancelCommand(commandID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	exec, exists := h.executing[commandID]
	if !exists {
		return fmt.Errorf("command not found or already completed: %s", commandID)
	}

	exec.Cancel()
	h.logger.Info("Command cancelled", "command_id", commandID)

	return nil
}

// GetExecutingCommands returns a list of currently executing command IDs.
func (h *Handler) GetExecutingCommands() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	commands := make([]string, 0, len(h.executing))
	for cmdID := range h.executing {
		commands = append(commands, cmdID)
	}

	return commands
}
