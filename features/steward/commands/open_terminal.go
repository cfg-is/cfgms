// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"fmt"

	"github.com/cfgis/cfgms/features/terminal/shell"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TerminalDialer opens a bidirectional Terminal RPC stream to the controller
// and bridges it to a local PTY for the duration of the session.
// Implemented by client.TerminalBridge.
type TerminalDialer interface {
	Dial(ctx context.Context, sessionID, shellStr string, cols, rows int) error
}

// RegisterOpenTerminalHandler registers the open_terminal command handler on h.
// dialer opens the Terminal RPC stream and bridges it to a PTY; it is created
// by the client package and injected here so the commands package does not import
// the transport client directly.
func (h *Handler) RegisterOpenTerminalHandler(dialer TerminalDialer) {
	h.RegisterHandler(cpTypes.CommandOpenTerminal, func(ctx context.Context, cmd *cpTypes.Command) error {
		return h.handleOpenTerminal(ctx, cmd, dialer)
	})
}

// handleOpenTerminal validates params and starts the terminal bridge in a background
// goroutine. It returns an error synchronously when the shell param is not in the
// platform allowlist, ensuring shell.Factory is never invoked on an untrusted string.
// On success the command completes immediately and the bridge runs independently.
func (h *Handler) handleOpenTerminal(ctx context.Context, cmd *cpTypes.Command, dialer TerminalDialer) error {
	sessionID, _ := cmd.Params["session_id"].(string)
	shellStr, _ := cmd.Params["shell"].(string)

	var cols, rows int
	if c, ok := cmd.Params["cols"].(float64); ok && c > 0 {
		cols = int(c)
	}
	if r, ok := cmd.Params["rows"].(float64); ok && r > 0 {
		rows = int(r)
	}
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}

	// Fall back to platform default when caller omits the shell param.
	if shellStr == "" {
		shellStr = shell.GetDefaultShell()
	}

	// Validate against the platform allowlist BEFORE touching shell.Factory.
	// An arbitrary string from Command.params must never reach CreateExecutor.
	if !isAllowedShell(shellStr) {
		h.logger.Warn("open_terminal: rejected non-allowlisted shell param",
			"command_id", cmd.ID,
			"session_id", logging.SanitizeLogValue(sessionID))
		return fmt.Errorf("open_terminal: unsupported shell %q", shellStr)
	}

	h.logger.Info("open_terminal: starting bridge",
		"command_id", cmd.ID,
		"session_id", logging.SanitizeLogValue(sessionID),
		"shell", shellStr,
		"cols", cols,
		"rows", rows)

	// Run the bridge in a background goroutine; the command itself returns
	// immediately (EventCommandCompleted) while the PTY session runs as long as
	// the stream stays open. The bridge is responsible for its own teardown.
	// #nosec G118 -- the authenticated terminal stream intentionally outlives
	// command receipt and dialer.Dial owns teardown when the stream closes.
	go func() {
		if err := dialer.Dial(context.Background(), sessionID, shellStr, cols, rows); err != nil {
			h.logger.Error("open_terminal: bridge exited with error",
				"session_id", logging.SanitizeLogValue(sessionID),
				"error", err)
		}
		h.logger.Info("open_terminal: bridge closed", "session_id", logging.SanitizeLogValue(sessionID))
	}()

	return nil
}

// isAllowedShell returns true when s is in the platform-specific shell allowlist
// enforced by features/terminal/shell.GetSupportedShells.
func isAllowedShell(s string) bool {
	for _, allowed := range shell.GetSupportedShells() {
		if s == allowed {
			return true
		}
	}
	return false
}
