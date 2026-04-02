// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build linux

package service

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// linuxExecutor manages OS services via systemctl on Linux systems.
type linuxExecutor struct{}

func newExecutor() serviceExecutor {
	return &linuxExecutor{}
}

// getState queries systemctl for the current running and enabled state.
// A non-existent service is treated as stopped and disabled (not an error),
// matching how other modules report absent resources.
func (e *linuxExecutor) getState(name string) (serviceState, error) {
	running, err := systemctlIsActive(name)
	if err != nil {
		return serviceState{}, err
	}

	enabled, err := systemctlIsEnabled(name)
	if err != nil {
		return serviceState{}, err
	}

	return serviceState{Running: running, Enabled: enabled}, nil
}

// setState applies the desired running and enabled states via systemctl.
// Operations are applied in the order: enable/disable first, then start/stop,
// which matches systemd best practices for service lifecycle management.
func (e *linuxExecutor) setState(name string, desiredRunning bool, desiredEnabled bool) error {
	if desiredEnabled {
		if out, err := exec.Command("systemctl", "enable", name).CombinedOutput(); err != nil { // #nosec G204 - name validated by caller
			return fmt.Errorf("systemctl enable %s: %w (output: %s)", name, err, strings.TrimSpace(string(out)))
		}
	} else {
		if out, err := exec.Command("systemctl", "disable", name).CombinedOutput(); err != nil { // #nosec G204 - name validated by caller
			return fmt.Errorf("systemctl disable %s: %w (output: %s)", name, err, strings.TrimSpace(string(out)))
		}
	}

	if desiredRunning {
		if out, err := exec.Command("systemctl", "start", name).CombinedOutput(); err != nil { // #nosec G204 - name validated by caller
			return fmt.Errorf("systemctl start %s: %w (output: %s)", name, err, strings.TrimSpace(string(out)))
		}
	} else {
		if out, err := exec.Command("systemctl", "stop", name).CombinedOutput(); err != nil { // #nosec G204 - name validated by caller
			return fmt.Errorf("systemctl stop %s: %w (output: %s)", name, err, strings.TrimSpace(string(out)))
		}
	}

	return nil
}

// systemctlIsActive returns true if the named unit is in the "active" state.
// Exit codes from is-active are meaningful: 0=active, 3=inactive/failed/unknown.
// Any other error (e.g., systemd not running) is propagated as an error.
func systemctlIsActive(name string) (bool, error) {
	cmd := exec.Command("systemctl", "is-active", name) // #nosec G204 - name validated by caller
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// is-active exits non-zero for inactive/failed/unknown — these are valid states.
			switch output {
			case "inactive", "failed", "activating", "deactivating", "unknown":
				return false, nil
			}
			// Any other non-zero exit (e.g., systemd not running) is an actual error.
			return false, fmt.Errorf("systemctl is-active %s: %w (output: %s)", name, err, output)
		}
		return false, fmt.Errorf("failed to run systemctl: %w", err)
	}

	return output == "active", nil
}

// systemctlIsEnabled returns true if the named unit is configured to start on boot.
// Exit codes from is-enabled: 0=enabled, 1=disabled or not-found.
// Non-zero for "disabled"/"static"/"masked" is normal; other errors are propagated.
func systemctlIsEnabled(name string) (bool, error) {
	cmd := exec.Command("systemctl", "is-enabled", name) // #nosec G204 - name validated by caller
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// is-enabled exits non-zero for disabled/static/masked/not-found — valid states.
			switch output {
			case "disabled", "static", "masked", "indirect", "not-found", "bad":
				return false, nil
			}
			// Any other non-zero exit indicates systemd is not available.
			return false, fmt.Errorf("systemctl is-enabled %s: %w (output: %s)", name, err, output)
		}
		return false, fmt.Errorf("failed to run systemctl: %w", err)
	}

	return output == "enabled", nil
}
