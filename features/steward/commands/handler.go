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
//
// Story #919: Commands are authenticated before dispatch. Every SignedCommand
// is verified for signature, replay, StewardID, and Params size.
package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/config/signature"
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

	// Story #919: command authentication fields.

	// verifier validates the cryptographic signature on each SignedCommand.
	// When nil, signature verification is skipped (unsecured/transitional mode).
	verifier signature.Verifier

	// replayWindow is the maximum age of a command timestamp before it is
	// rejected as a potential replay.
	replayWindow time.Duration

	// replayCache detects duplicate command IDs within the replay window.
	replayCache *ttlReplayCache

	// maxParamsBytes is the maximum allowed JSON-serialized size of Command.Params.
	maxParamsBytes int
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

	// Verifier validates command signatures (Story #919).
	// When nil, signature verification is skipped.
	Verifier signature.Verifier

	// ReplayWindow is the maximum age of an accepted command timestamp.
	// Defaults to 5 minutes when zero.
	ReplayWindow time.Duration

	// MaxParamsBytes is the maximum JSON-serialized size of Command.Params.
	// Defaults to 65536 (64 KiB) when zero.
	MaxParamsBytes int
}

const (
	defaultReplayWindow  = 5 * time.Minute
	defaultMaxParamBytes = 64 * 1024
)

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

	replayWindow := cfg.ReplayWindow
	if replayWindow == 0 {
		replayWindow = defaultReplayWindow
	}
	maxParamsBytes := cfg.MaxParamsBytes
	if maxParamsBytes == 0 {
		maxParamsBytes = defaultMaxParamBytes
	}

	h := &Handler{
		stewardID:      cfg.StewardID,
		handlers:       make(map[cpTypes.CommandType]CommandFunc),
		onStatus:       cfg.OnStatus,
		logger:         cfg.Logger,
		store:          cfg.Store,
		executing:      make(map[string]*executionContext),
		verifier:       cfg.Verifier,
		replayWindow:   replayWindow,
		replayCache:    newReplayCache(replayWindow),
		maxParamsBytes: maxParamsBytes,
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

// HandleCommand processes an incoming signed command from the controller.
//
// Story #919: Before dispatching, the command is authenticated:
//  1. Signature is verified against CommandSigningBytes(cmd, rawParams) when a verifier is configured.
//  2. signed.Command.StewardID must match this handler's steward identity.
//  3. signed.Command.Timestamp must be within the configured replay window.
//  4. signed.Command.ID must not already be present in the replay cache (dedup).
//  5. json.Marshal(signed.Command.Params) must not exceed maxParamsBytes.
func (h *Handler) HandleCommand(ctx context.Context, signed *cpTypes.SignedCommand) error {
	if signed == nil {
		return ErrUnauthenticatedCommand
	}

	cmd := &signed.Command

	// 1. Signature verification (only when a verifier is configured).
	if h.verifier != nil {
		if signed.Signature == nil {
			return ErrUnauthenticatedCommand
		}
		// Use the proto-wire string map (RawParams) when available so the canonical
		// bytes match what the controller signed. Fall back to InterfaceParamsToStringMap
		// for commands created without a proto round-trip (e.g. tests).
		rawParams := signed.RawParams
		if rawParams == nil {
			rawParams = cpTypes.InterfaceParamsToStringMap(cmd.Params)
		}
		cmdBytes, err := cpTypes.CommandSigningBytes(cmd, rawParams)
		if err != nil {
			return fmt.Errorf("marshal command for verification: %w", err)
		}
		if err := h.verifier.Verify(cmdBytes, signed.Signature); err != nil {
			return fmt.Errorf("%w: %v", ErrUnauthenticatedCommand, err)
		}
	}

	// 2. StewardID match.
	if cmd.StewardID != h.stewardID {
		return ErrWrongSteward
	}

	// 3. Timestamp freshness.
	if time.Since(cmd.Timestamp) > h.replayWindow {
		return ErrCommandReplay
	}

	// 4. Replay deduplication.
	if !h.replayCache.Add(cmd.ID) {
		return ErrCommandReplay
	}

	// 5. Params size bound.
	if len(cmd.Params) > 0 {
		paramBytes, err := json.Marshal(cmd.Params)
		if err != nil {
			return fmt.Errorf("%w: invalid params", ErrParamsTooLarge)
		}
		if len(paramBytes) > h.maxParamsBytes {
			return ErrParamsTooLarge
		}
	}

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
