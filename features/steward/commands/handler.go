// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package commands provides command handling for steward operations.
//
// This package implements the command handler that processes commands
// from the controller and executes appropriate actions (Story #198).
//
// Story #665: Command dispatch state is now persisted to a CommandStore so that
// executing/completed/failed status survives a process restart. The in-memory
// executing map retains only the context.CancelFunc needed for in-flight
// cancellation; all durable state is in the store.
package commands

import (
	"context"
	"fmt"
	"sync"
	"time"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Handler processes control plane commands from the controller.
type Handler struct {
	mu sync.RWMutex

	// Steward identification
	stewardID string

	// Command handlers
	handlers map[cpTypes.CommandType]CommandFunc

	// Status callback for reporting back to controller via events
	onStatus StatusCallback

	// Logger
	logger logging.Logger

	// CommandStore for durable command dispatch state (Story #665).
	// When nil the handler operates without persistence (in-memory only).
	store business.CommandStore

	// Execution tracking — holds only the CancelFunc for in-flight cancellation.
	// Durable state (status, timestamps, result) lives in the CommandStore.
	executing map[string]*executionContext

	// wg tracks in-flight executeCommand goroutines to support graceful shutdown
	// and deterministic test synchronization.
	wg sync.WaitGroup
}

// CommandFunc is a function that handles a specific command type.
type CommandFunc func(ctx context.Context, cmd *cpTypes.Command) error

// StatusCallback is called when status events should be published to controller.
type StatusCallback func(ctx context.Context, event *cpTypes.Event)

// executionContext tracks in-flight cancellation only.
// All durable command state is written to the CommandStore.
type executionContext struct {
	Cancel context.CancelFunc
}

// Config holds command handler configuration.
type Config struct {
	// StewardID identifies this steward
	StewardID string

	// OnStatus callback for status updates
	OnStatus StatusCallback

	// Logger for command execution logging
	Logger logging.Logger

	// Store is the durable command dispatch state backend (Story #665).
	// When nil, state transitions are not persisted across restarts.
	Store business.CommandStore
}

// New creates a new command handler and, when a CommandStore is configured,
// sweeps any commands left in "executing" state from a previous run and marks
// them as failed with reason "controller_restart".
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

	h := &Handler{
		stewardID: cfg.StewardID,
		handlers:  make(map[cpTypes.CommandType]CommandFunc),
		onStatus:  cfg.OnStatus,
		logger:    cfg.Logger,
		store:     cfg.Store,
		executing: make(map[string]*executionContext),
	}

	// Startup sweep: flip stale "executing" records from a previous run to "failed".
	if cfg.Store != nil {
		if err := h.sweepStaleExecutingCommands(context.Background()); err != nil {
			// Log but do not abort startup — stale records do not block operation.
			cfg.Logger.Error("Failed to sweep stale executing commands on startup",
				"error", err)
		}
	}

	return h, nil
}

// Wait blocks until all in-flight executeCommand goroutines have finished.
// Useful for graceful shutdown and deterministic test synchronization.
func (h *Handler) Wait() {
	h.wg.Wait()
}

// sweepStaleExecutingCommands marks commands that were left in "executing" state
// (from a crashed or restarted process) as "failed" with error "controller_restart".
func (h *Handler) sweepStaleExecutingCommands(ctx context.Context) error {
	stale, err := h.store.ListCommandsByStatus(ctx, business.CommandStatusExecuting)
	if err != nil {
		return fmt.Errorf("listing stale executing commands: %w", err)
	}

	for _, cmd := range stale {
		if err := h.store.UpdateCommandStatus(ctx, cmd.ID,
			business.CommandStatusFailed, nil, "controller_restart"); err != nil {
			h.logger.Error("Failed to mark stale command as failed",
				"command_id", cmd.ID,
				"error", err)
		} else {
			h.logger.Info("Marked stale executing command as failed (controller_restart)",
				"command_id", cmd.ID)
		}
	}
	return nil
}

// RegisterHandler registers a handler function for a specific command type.
func (h *Handler) RegisterHandler(cmdType cpTypes.CommandType, handler CommandFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handlers[cmdType] = handler
	h.logger.Info("Registered command handler", "type", cmdType)
}

// HandleCommand processes an incoming control plane command.
// Story #363: Now receives a pre-deserialized command from the ControlPlaneProvider
// instead of raw topic/payload from the transport layer.
func (h *Handler) HandleCommand(ctx context.Context, cmd *cpTypes.Command) error {
	h.logger.Debug("Received command", "id", cmd.ID, "type", cmd.Type)

	// Persist incoming command record (Story #665).
	if h.store != nil {
		record := &business.CommandRecord{
			ID:        cmd.ID,
			Type:      string(cmd.Type),
			StewardID: h.stewardID, // raw value — SanitizeLogValue is for log output only
			IssuedAt:  cmd.Timestamp,
		}
		if err := h.store.CreateCommandRecord(ctx, record); err != nil {
			h.logger.Error("Failed to persist incoming command record",
				"command_id", cmd.ID,
				"error", err)
			// Do not abort — command execution continues without durable record.
		}
	}

	// Send command received event
	h.sendStatus(ctx, &cpTypes.Event{
		ID:        fmt.Sprintf("evt_%d", time.Now().UnixNano()),
		Type:      cpTypes.EventCommandReceived,
		StewardID: h.stewardID,
		CommandID: cmd.ID,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"command_type": string(cmd.Type),
		},
	})

	// Execute command in background; wg.Done is called inside executeCommand.
	h.wg.Add(1)
	go h.executeCommand(cmd)

	return nil
}

// executeCommand executes a command with timeout and error handling.
func (h *Handler) executeCommand(cmd *cpTypes.Command) {
	defer h.wg.Done()

	h.logger.Info("Executing command",
		"command_id", cmd.ID,
		"type", cmd.Type,
		"timestamp", cmd.Timestamp)

	// Create execution context with timeout
	timeout := 30 * time.Second
	if timeoutVal, ok := cmd.Params["timeout_seconds"].(float64); ok {
		timeout = time.Duration(timeoutVal) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Track in-flight cancellation (CancelFunc only — not persisted).
	h.mu.Lock()
	h.executing[cmd.ID] = &executionContext{Cancel: cancel}
	h.mu.Unlock()

	// Transition to executing state in the store.
	if h.store != nil {
		if err := h.store.UpdateCommandStatus(ctx, cmd.ID,
			business.CommandStatusExecuting, nil, ""); err != nil {
			h.logger.Error("Failed to update command status to executing",
				"command_id", cmd.ID,
				"error", err)
		}
	}

	// Clean up in-flight tracking on exit.
	defer func() {
		h.mu.Lock()
		delete(h.executing, cmd.ID)
		h.mu.Unlock()
	}()

	// Get handler for this command type
	h.mu.RLock()
	handler, exists := h.handlers[cmd.Type]
	h.mu.RUnlock()

	if !exists {
		h.logger.Error("No handler registered for command type",
			"command_id", cmd.ID,
			"type", cmd.Type)

		if h.store != nil {
			if err := h.store.UpdateCommandStatus(ctx, cmd.ID, business.CommandStatusFailed, nil,
				fmt.Sprintf("no handler for command type: %s", cmd.Type)); err != nil {
				h.logger.Error("Failed to update command status to failed (no handler)",
					"command_id", cmd.ID,
					"error", err)
			}
		}

		h.sendStatus(ctx, &cpTypes.Event{
			ID:        fmt.Sprintf("evt_%d", time.Now().UnixNano()),
			Type:      cpTypes.EventCommandFailed,
			StewardID: h.stewardID,
			CommandID: cmd.ID,
			Timestamp: time.Now(),
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
			"command_id", cmd.ID,
			"type", cmd.Type,
			"error", err.Error(),
			"execution_time", executionTime)

		if h.store != nil {
			if storeErr := h.store.UpdateCommandStatus(ctx, cmd.ID,
				business.CommandStatusFailed, nil, err.Error()); storeErr != nil {
				h.logger.Error("Failed to update command status to failed",
					"command_id", cmd.ID,
					"error", storeErr)
			}
		}

		h.sendStatus(ctx, &cpTypes.Event{
			ID:        fmt.Sprintf("evt_%d", time.Now().UnixNano()),
			Type:      cpTypes.EventCommandFailed,
			StewardID: h.stewardID,
			CommandID: cmd.ID,
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"error":             err.Error(),
				"execution_time_ms": executionTime.Milliseconds(),
			},
		})
		return
	}

	h.logger.Info("Command completed successfully",
		"command_id", cmd.ID,
		"type", cmd.Type,
		"execution_time", executionTime)

	if h.store != nil {
		result := map[string]interface{}{
			"execution_time_ms": executionTime.Milliseconds(),
		}
		if storeErr := h.store.UpdateCommandStatus(ctx, cmd.ID,
			business.CommandStatusCompleted, result, ""); storeErr != nil {
			h.logger.Error("Failed to update command status to completed",
				"command_id", cmd.ID,
				"error", storeErr)
		}
	}

	h.sendStatus(ctx, &cpTypes.Event{
		ID:        fmt.Sprintf("evt_%d", time.Now().UnixNano()),
		Type:      cpTypes.EventCommandCompleted,
		StewardID: h.stewardID,
		CommandID: cmd.ID,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"execution_time_ms": executionTime.Milliseconds(),
		},
	})
}

// sendStatus publishes a status event via the callback.
func (h *Handler) sendStatus(ctx context.Context, event *cpTypes.Event) {
	if h.onStatus != nil {
		h.onStatus(ctx, event)
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
