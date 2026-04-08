// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build !windows

package script

import (
	"context"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDetectLoggedInUser_Behavior verifies that detectLoggedInUser either returns a
// non-empty username or ErrNoUserLoggedIn. Both outcomes are valid depending on whether
// the test is run in a graphical session or a headless CI environment.
func TestDetectLoggedInUser_Behavior(t *testing.T) {
	user, err := detectLoggedInUser()
	if err != nil {
		assert.ErrorIs(t, err, ErrNoUserLoggedIn,
			"detectLoggedInUser should return ErrNoUserLoggedIn when no user is logged in; got: %v", err)
		assert.Empty(t, user)
	} else {
		assert.NotEmpty(t, user, "detected user should not be empty string")
	}
}

// TestDetectLinuxUserViaLoginctl_Behavior verifies loginctl-based detection on Linux.
// On non-Linux platforms the test is skipped.
func TestDetectLinuxUserViaLoginctl_Behavior(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("loginctl test is Linux-only")
	}

	user, err := detectLinuxUserViaLoginctl()
	if err != nil {
		// Both ErrNoUserLoggedIn (no active graphical sessions) and a wrapped error
		// (loginctl not installed) are valid in a headless CI environment.
		// The invariant we verify: when an error occurs, the username must be empty.
		assert.Empty(t, user, "username must be empty when an error is returned")
	} else {
		assert.NotEmpty(t, user)
	}
}

// TestDetectLinuxUserViaWho_Behavior verifies `who`-based detection on Linux.
func TestDetectLinuxUserViaWho_Behavior(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("who test is Linux-only")
	}

	user, err := detectLinuxUserViaWho()
	if err != nil {
		assert.ErrorIs(t, err, ErrNoUserLoggedIn)
		assert.Empty(t, user)
	} else {
		assert.NotEmpty(t, user)
	}
}

// TestDetectMacOSConsoleUser_Behavior verifies macOS console user detection.
func TestDetectMacOSConsoleUser_Behavior(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS console test is darwin-only")
	}

	user, err := detectMacOSConsoleUser()
	if err != nil {
		assert.ErrorIs(t, err, ErrNoUserLoggedIn)
		assert.Empty(t, user)
	} else {
		assert.NotEmpty(t, user)
	}
}

// TestApplyExecutionContext_SystemPassesThrough verifies that the system execution
// context returns the original cmd pointer unchanged with an empty actualUser.
func TestApplyExecutionContext_SystemPassesThrough(t *testing.T) {
	ctx := context.Background()
	config := &ScriptConfig{
		Content:          "echo hello",
		Shell:            ShellBash,
		Timeout:          5 * time.Second,
		ExecutionContext: ExecutionContextSystem,
	}

	original := exec.CommandContext(ctx, "/bin/echo", "hello")
	cmd, user, cleanup, err := applyExecutionContext(ctx, config, original)
	require.NoError(t, err)
	cleanup()

	assert.Same(t, original, cmd, "system context must return the original cmd pointer")
	assert.Empty(t, user, "system context must not set an actual user")
}

// TestApplyExecutionContext_LoggedInUser_NoUser verifies that ErrNoUserLoggedIn is
// propagated when no interactive user is present. Skipped when a user IS logged in.
func TestApplyExecutionContext_LoggedInUser_NoUser(t *testing.T) {
	// Skip if a user is actually logged in — the retry-signal path cannot be exercised.
	if _, err := detectLoggedInUser(); err == nil {
		t.Skip("an interactive user is logged in; skipping no-user error path test")
	}

	ctx := context.Background()
	config := &ScriptConfig{
		Content:          "echo hello",
		Shell:            ShellBash,
		Timeout:          5 * time.Second,
		ExecutionContext: ExecutionContextLoggedInUser,
	}

	original := exec.CommandContext(ctx, "/bin/echo", "hello")
	_, _, cleanup, err := applyExecutionContext(ctx, config, original)
	cleanup()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoUserLoggedIn,
		"must propagate ErrNoUserLoggedIn so the caller can queue for retry")
}

// TestApplyExecutionContext_LoggedInUser_WithUser verifies the sudo wrapper is built
// correctly when a user IS logged in. Skipped in headless CI environments.
func TestApplyExecutionContext_LoggedInUser_WithUser(t *testing.T) {
	user, err := detectLoggedInUser()
	if err != nil {
		t.Skip("no interactive user logged in; skipping sudo-wrapper construction test")
	}

	ctx := context.Background()
	config := &ScriptConfig{
		Content:          "echo hello",
		Shell:            ShellBash,
		Timeout:          5 * time.Second,
		ExecutionContext: ExecutionContextLoggedInUser,
	}

	original := exec.CommandContext(ctx, "/bin/echo", "hello")
	cmd, actualUser, cleanup, err := applyExecutionContext(ctx, config, original)
	require.NoError(t, err)
	cleanup()

	assert.Equal(t, user, actualUser, "actualUser must match the detected user")
	require.NotNil(t, cmd)

	// The returned command must be a sudo invocation, not the original cmd.
	assert.NotSame(t, original, cmd, "logged_in_user context must return a new (sudo) cmd")
	require.NotEmpty(t, cmd.Args)
	assert.Equal(t, "sudo", cmd.Args[0], "command must be wrapped with sudo")

	// sudo args: -u <user> -- /bin/echo hello
	require.GreaterOrEqual(t, len(cmd.Args), 5)
	assert.Equal(t, "-u", cmd.Args[1])
	assert.Equal(t, user, cmd.Args[2])
	assert.Equal(t, "--", cmd.Args[3])
}
