// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package script

// This file is compiled only on Windows (Go filename convention: _windows.go suffix).

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWTSGetActiveConsoleSessionId_FindsInKernel32 verifies that
// WTSGetActiveConsoleSessionId is loadable from kernel32.dll (not wtsapi32.dll).
// This test always runs regardless of whether a console session is active, providing
// CI-safe regression coverage for the DLL fix.
func TestWTSGetActiveConsoleSessionId_FindsInKernel32(t *testing.T) {
	err := procWTSGetActiveConsoleSessionId.Find()
	require.NoError(t, err, "WTSGetActiveConsoleSessionId must be found in kernel32.dll")
}

// TestParseActiveSessionID_SentinelReturnsNoUser verifies that the sentinel value
// 0xFFFFFFFF maps to ErrNoUserLoggedIn. Pure function; no WTS API call needed.
func TestParseActiveSessionID_SentinelReturnsNoUser(t *testing.T) {
	id, err := parseActiveSessionID(uintptr(activeConsoleSessionNone))
	require.ErrorIs(t, err, ErrNoUserLoggedIn)
	assert.Zero(t, id)
}

// TestParseActiveSessionID_ValidIDPassesThrough verifies that a non-sentinel session ID
// is returned unchanged. Pure function; no WTS API call needed.
func TestParseActiveSessionID_ValidIDPassesThrough(t *testing.T) {
	const testSessionID uint32 = 1
	id, err := parseActiveSessionID(uintptr(testSessionID))
	require.NoError(t, err)
	assert.Equal(t, testSessionID, id)
}

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
// is returned when no interactive console session is present. Uses test hook injection so
// this test is environment-independent and always runs in CI.
func TestApplyExecutionContext_Windows_LoggedInUser_NoUser(t *testing.T) {
	// Inject a no-session error without calling the real WTS API.
	old := windowsGetSessionID
	windowsGetSessionID = func() (uint32, error) { return 0, ErrNoUserLoggedIn }
	defer func() { windowsGetSessionID = old }()

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
// When SE_TCB_NAME privilege is unavailable, falls back to validating system-context
// so the test always exercises a real code path.
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
	if err != nil && strings.Contains(err.Error(), "WTSQueryUserToken failed") {
		// WTSQueryUserToken requires SE_TCB_NAME privilege, which is typically
		// unavailable in CI runners (e.g., GitHub Actions runneradmin).
		// Fall back to validating the system-context path instead.
		cleanup()
		t.Logf("user-token acquisition failed (%v); falling back to system-context validation", err)

		sysConfig := &ScriptConfig{
			Content:          "echo hello",
			Shell:            ShellPowerShell,
			Timeout:          5 * time.Second,
			ExecutionContext: ExecutionContextSystem,
		}
		sysOriginal := exec.CommandContext(ctx, "powershell.exe", "-Command", "echo hello")
		sysCmd, sysUser, sysCleanup, sysErr := applyExecutionContext(ctx, sysConfig, sysOriginal)
		defer sysCleanup()

		require.NoError(t, sysErr, "system-context fallback must not error")
		assert.Same(t, sysOriginal, sysCmd, "system context must return the original cmd pointer")
		assert.Empty(t, sysUser, "system context must not set an actual user")
		return
	}
	require.NoError(t, err, "unexpected error from applyExecutionContext")
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
