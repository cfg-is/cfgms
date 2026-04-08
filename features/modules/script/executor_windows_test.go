// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package script

// This file is compiled only on Windows (Go filename convention: _windows.go suffix).

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDetectLoggedInUser_Windows_Behavior verifies that detectLoggedInUser either
// returns a non-empty username or ErrNoUserLoggedIn. Both are valid depending on
// whether an interactive console session is active.
func TestDetectLoggedInUser_Windows_Behavior(t *testing.T) {
	user, err := detectLoggedInUser()
	if err != nil {
		assert.ErrorIs(t, err, ErrNoUserLoggedIn,
			"should return ErrNoUserLoggedIn when no console session is active; got: %v", err)
		assert.Empty(t, user)
	} else {
		assert.NotEmpty(t, user, "detected user must not be empty")
	}
}

// TestGetActiveConsoleSessionID_Behavior verifies getActiveConsoleSessionID returns
// either a valid session ID or ErrNoUserLoggedIn.
func TestGetActiveConsoleSessionID_Behavior(t *testing.T) {
	sessionID, err := getActiveConsoleSessionID()
	if err != nil {
		assert.ErrorIs(t, err, ErrNoUserLoggedIn)
	} else {
		assert.NotEqual(t, activeConsoleSessionNone, sessionID,
			"returned session ID must not be the sentinel value")
	}
}

// TestApplyExecutionContext_Windows_SystemPassesThrough verifies that the system
// execution context returns the original cmd pointer unchanged.
func TestApplyExecutionContext_Windows_SystemPassesThrough(t *testing.T) {
	ctx := context.Background()
	config := &ScriptConfig{
		Content:          "echo hello",
		Shell:            ShellPowerShell,
		Timeout:          5 * time.Second,
		ExecutionContext: ExecutionContextSystem,
	}

	original := exec.CommandContext(ctx, "powershell.exe", "-Command", "echo hello")
	cmd, user, cleanup, err := applyExecutionContext(ctx, config, original)
	require.NoError(t, err)
	cleanup()

	assert.Same(t, original, cmd, "system context must return the original cmd pointer")
	assert.Empty(t, user, "system context must not set an actual user")
}

// TestApplyExecutionContext_Windows_LoggedInUser_NoUser verifies that ErrNoUserLoggedIn
// is returned when no interactive console session is present.
func TestApplyExecutionContext_Windows_LoggedInUser_NoUser(t *testing.T) {
	// Skip if a user IS logged in — the no-session path cannot be tested then.
	if _, err := detectLoggedInUser(); err == nil {
		t.Skip("an interactive user is logged in; skipping no-user error path test")
	}

	ctx := context.Background()
	config := &ScriptConfig{
		Content:          "echo hello",
		Shell:            ShellPowerShell,
		Timeout:          5 * time.Second,
		ExecutionContext: ExecutionContextLoggedInUser,
	}

	original := exec.CommandContext(ctx, "powershell.exe", "-Command", "echo hello")
	_, _, cleanup, err := applyExecutionContext(ctx, config, original)
	cleanup()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoUserLoggedIn,
		"must propagate ErrNoUserLoggedIn so the caller can queue for retry")
}

// TestApplyExecutionContext_Windows_LoggedInUser_WithUser verifies that when a console
// session is active, applyExecutionContext attaches the user token to SysProcAttr and
// returns the correct username. Skipped in headless CI environments.
func TestApplyExecutionContext_Windows_LoggedInUser_WithUser(t *testing.T) {
	user, err := detectLoggedInUser()
	if err != nil {
		t.Skip("no interactive console session; skipping token-acquisition test")
	}

	ctx := context.Background()
	config := &ScriptConfig{
		Content:          "echo hello",
		Shell:            ShellPowerShell,
		Timeout:          5 * time.Second,
		ExecutionContext: ExecutionContextLoggedInUser,
	}

	original := exec.CommandContext(ctx, "powershell.exe", "-Command", "echo hello")
	cmd, actualUser, cleanup, err := applyExecutionContext(ctx, config, original)
	require.NoError(t, err)
	cleanup()

	assert.Equal(t, user, actualUser, "actualUser must match the detected console user")
	require.NotNil(t, cmd)

	// The same cmd pointer is returned (SysProcAttr is set in-place on Windows,
	// unlike Unix which builds a new sudo-wrapper command).
	assert.Same(t, original, cmd, "Windows applyExecutionContext modifies SysProcAttr in-place")

	// Token must be set on SysProcAttr; a non-zero token confirms the WTS path was taken.
	require.NotNil(t, cmd.SysProcAttr, "SysProcAttr must be non-nil after token attachment")
	assert.NotZero(t, cmd.SysProcAttr.Token, "Token must be set to the active console session token")
}
