// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build !windows

package script

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// detectLoggedInUser detects the currently logged-in console user on Unix systems.
// Returns ErrNoUserLoggedIn if no interactive user is currently logged in.
// The caller should queue execution for retry when ErrNoUserLoggedIn is returned.
func detectLoggedInUser() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return detectMacOSConsoleUser()
	case "linux":
		return detectLinuxConsoleUser()
	default:
		return "", fmt.Errorf("logged_in_user execution context not supported on %s", runtime.GOOS)
	}
}

// detectMacOSConsoleUser returns the owner of /dev/console, which is the currently
// logged-in graphical user on macOS. Returns ErrNoUserLoggedIn if no user is at the console.
func detectMacOSConsoleUser() (string, error) {
	// stat -f '%Su' /dev/console prints the username of the device owner.
	// When no GUI user is logged in, the owner is "root".
	// #nosec G204 - all arguments are hardcoded constants, not user input
	out, err := exec.Command("stat", "-f", "%Su", "/dev/console").Output()
	if err != nil {
		return "", fmt.Errorf("failed to query macOS console user: %w", err)
	}

	user := strings.TrimSpace(string(out))
	if user == "" || user == "root" {
		return "", ErrNoUserLoggedIn
	}

	return user, nil
}

// detectLinuxConsoleUser returns the name of the logged-in user on Linux.
// Tries loginctl first for graphical sessions; falls back to the `who` command.
func detectLinuxConsoleUser() (string, error) {
	if user, err := detectLinuxUserViaLoginctl(); err == nil {
		return user, nil
	}
	return detectLinuxUserViaWho()
}

// detectLinuxUserViaLoginctl queries loginctl for the first non-root active session user.
// loginctl list-sessions --no-legend outputs: SESSION  UID  USER  SEAT  TTY
func detectLinuxUserViaLoginctl() (string, error) {
	// #nosec G204 - all arguments are hardcoded constants, not user input
	out, err := exec.Command("loginctl", "list-sessions", "--no-legend").Output()
	if err != nil {
		return "", fmt.Errorf("loginctl not available: %w", err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] != "" && fields[2] != "root" {
			return fields[2], nil
		}
	}

	return "", ErrNoUserLoggedIn
}

// detectLinuxUserViaWho queries the `who` command for the first non-root logged-in user.
// `who` output format: USERNAME  TTY  DATE TIME ...
func detectLinuxUserViaWho() (string, error) {
	// #nosec G204 - all arguments are hardcoded constants, not user input
	out, err := exec.Command("who").Output()
	if err != nil {
		return "", fmt.Errorf("who command failed: %w", err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 1 && fields[0] != "" && fields[0] != "root" {
			return fields[0], nil
		}
	}

	return "", ErrNoUserLoggedIn
}

// unixDetectLoggedInUser is a test hook; override in tests to inject user detection
// errors without calling the real OS utilities (loginctl/who/stat).
var unixDetectLoggedInUser = detectLoggedInUser

// applyExecutionContext returns a (potentially modified) command configured to run
// under the execution context specified in config, the actual OS user the script will
// run as (empty for system context), a cleanup function (no-op on Unix), and any error.
//
// For logged_in_user context, the original command is wrapped with
// `sudo -u <user> -- <program> <args...>`. ErrNoUserLoggedIn is returned when no
// interactive user is detected; the caller should queue for retry.
func applyExecutionContext(ctx context.Context, config *ScriptConfig, cmd *exec.Cmd) (*exec.Cmd, string, func(), error) {
	noCleanup := func() {}

	if config.ExecutionContext != ExecutionContextLoggedInUser {
		return cmd, "", noCleanup, nil
	}

	user, err := unixDetectLoggedInUser()
	if err != nil {
		return nil, "", noCleanup, err
	}

	// Wrap the original command with `sudo -u <user> -- <original program and args>`
	// cmd.Args[0] is always the program name (equal to cmd.Path).
	sudoArgs := make([]string, 0, len(cmd.Args)+3)
	sudoArgs = append(sudoArgs, "-u", user, "--")
	sudoArgs = append(sudoArgs, cmd.Args...)

	// #nosec G204 - user is detected via system utilities (loginctl/who/stat); it is not
	// derived from user-controlled input. sudo is a fixed executable path.
	newCmd := exec.CommandContext(ctx, "sudo", sudoArgs...)
	// Dir and Env are deliberately NOT copied here: the caller sets them on the returned
	// command after applyExecutionContext returns, so they land on the sudo wrapper.

	return newCmd, user, noCleanup, nil
}
