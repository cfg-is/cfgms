// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/modules/script"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

const (
	scriptPreviewMaxBytes   = 4096
	defaultScriptTimeoutSec = 900 // 15 minutes
)

// RegisterExecuteScriptHandler registers the built-in execute_script command handler on h.
// The handler extracts script params, invokes the script module executor, and publishes
// EventScriptCompleted (carrying exit code, duration, and bounded previews) or
// EventCommandFailed when the executor itself cannot run.
func (h *Handler) RegisterExecuteScriptHandler() {
	h.RegisterHandler(cpTypes.CommandExecuteScript, func(ctx context.Context, cmd *cpTypes.Command) error {
		return h.handleExecuteScript(ctx, cmd)
	})
}

// handleExecuteScript is the CommandFunc implementation for CommandExecuteScript.
// It always returns nil — the command outcome is communicated via onStatus events
// so that executeCommand does not emit a redundant EventCommandFailed.
func (h *Handler) handleExecuteScript(ctx context.Context, cmd *cpTypes.Command) error {
	// Extract params via type assertion per spec; zero-value on missing key is intentional.
	scriptContentB64, _ := cmd.Params["script_content"].(string)
	shellStr, _ := cmd.Params["shell"].(string)
	executionID, _ := cmd.Params["execution_id"].(string)
	executionContextStr, _ := cmd.Params["execution_context"].(string)

	// Decode base64 script content — content is NEVER stored in a variable that gets logged.
	contentBytes, err := base64.StdEncoding.DecodeString(scriptContentB64)
	if err != nil {
		h.logger.Error("execute_script: invalid script_content encoding",
			"command_id", cmd.ID,
			"execution_id", executionID,
			"error", err)
		h.sendStatus(ctx, &cpTypes.Event{
			ID:        newEventID(),
			Type:      cpTypes.EventCommandFailed,
			StewardID: h.stewardID,
			CommandID: cmd.ID,
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"execution_id": executionID,
				"error":        "invalid script_content encoding: " + err.Error(),
			},
		})
		return nil
	}

	// Extract timeout; default to 15 minutes per spec.
	timeoutSecs := float64(defaultScriptTimeoutSec)
	if ts, ok := cmd.Params["timeout_seconds"].(float64); ok && ts > 0 {
		timeoutSecs = ts
	}
	timeout := time.Duration(timeoutSecs) * time.Second

	// Map execution_context param to script.ExecutionContext.
	execCtx := script.ExecutionContextSystem
	if executionContextStr == string(script.ExecutionContextLoggedInUser) {
		execCtx = script.ExecutionContextLoggedInUser
	}

	cfg := &script.ScriptConfig{
		Content:          string(contentBytes), // content is placed only in ScriptConfig, never logged
		Shell:            script.ShellType(shellStr),
		Timeout:          timeout,
		ExecutionContext: execCtx,
		SigningPolicy:    script.SigningPolicyNone, // signature verification is deferred (S3)
	}

	// Log only non-sensitive correlation data: SHA-256 prefix + byte length, never content.
	contentHash := sha256.Sum256(contentBytes)
	h.logger.Info("execute_script: starting",
		"command_id", cmd.ID,
		"execution_id", executionID,
		"shell", shellStr,
		"content_sha256_prefix", fmt.Sprintf("%x", contentHash[:4]),
		"content_bytes", len(contentBytes),
		"timeout_seconds", int(timeoutSecs))

	// Derive a timeout context; ctx carries the connection-lifetime deadline so the
	// outer deadline still cancels first when it is shorter.
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	executor := script.NewExecutor(cfg)
	result, execErr := executor.Execute(timeoutCtx)

	if execErr != nil {
		h.logger.Error("execute_script: executor failed",
			"command_id", cmd.ID,
			"execution_id", executionID,
			"error", execErr)
		h.sendStatus(ctx, &cpTypes.Event{
			ID:        newEventID(),
			Type:      cpTypes.EventCommandFailed,
			StewardID: h.stewardID,
			CommandID: cmd.ID,
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"execution_id": executionID,
				"error":        execErr.Error(),
			},
		})
		return nil
	}

	// Truncate previews to cap; excess bytes are silently dropped.
	// stdout_preview and stderr_preview are NEVER logged — only byte counts are.
	stdoutPreview := truncatePreview(result.Stdout, scriptPreviewMaxBytes)
	stderrPreview := truncatePreview(result.Stderr, scriptPreviewMaxBytes)

	h.logger.Info("execute_script: completed",
		"command_id", cmd.ID,
		"execution_id", executionID,
		"exit_code", result.ExitCode,
		"duration_ms", result.Duration.Milliseconds(),
		"stdout_bytes", len(result.Stdout),
		"stderr_bytes", len(result.Stderr))

	h.sendStatus(ctx, &cpTypes.Event{
		ID:        newEventID(),
		Type:      cpTypes.EventScriptCompleted,
		StewardID: h.stewardID,
		CommandID: cmd.ID,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"execution_id":   executionID,
			"exit_code":      result.ExitCode,
			"duration_ms":    result.Duration.Milliseconds(),
			"stdout_preview": stdoutPreview,
			"stderr_preview": stderrPreview,
		},
	})
	return nil
}

// truncatePreview returns at most maxBytes bytes of s; excess is silently dropped.
func truncatePreview(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	return s[:maxBytes]
}

// newEventID returns a monotonic event identifier.
func newEventID() string {
	return fmt.Sprintf("evt_%d", time.Now().UnixNano())
}
