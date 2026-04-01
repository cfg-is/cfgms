// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build darwin

package service

import (
	"fmt"
	"os/exec"
	"strings"
)

// darwinExecutor manages OS services via launchctl on macOS systems.
type darwinExecutor struct{}

func newExecutor() serviceExecutor {
	return &darwinExecutor{}
}

// getState queries launchctl for the current running and enabled state.
// On macOS, a loaded service is considered "enabled"; a running PID means "running".
func (e *darwinExecutor) getState(name string) (serviceState, error) {
	// launchctl list outputs: PID  Status  Label
	// A positive PID in column 1 means the service is running.
	out, err := exec.Command("launchctl", "list", name).CombinedOutput() // #nosec G204 - name validated by caller
	output := strings.TrimSpace(string(out))

	if err != nil {
		// launchctl list exits non-zero when the service is not loaded.
		if strings.Contains(output, "Could not find service") ||
			strings.Contains(output, "No such process") {
			return serviceState{Running: false, Enabled: false}, nil
		}
		return serviceState{}, fmt.Errorf("launchctl list %s: %w (output: %s)", name, err, output)
	}

	// Output format: "{ ... \"PID\" = <pid>; ... }"
	// If PID is present and non-zero, the service is running.
	running := strings.Contains(output, "\"PID\"") && !strings.Contains(output, "\"PID\" = 0;")
	// A successfully listed service is loaded (enabled).
	enabled := true

	return serviceState{Running: running, Enabled: enabled}, nil
}

// setState applies the desired running and enabled states via launchctl.
func (e *darwinExecutor) setState(name string, desiredRunning bool, desiredEnabled bool) error {
	current, err := e.getState(name)
	if err != nil {
		return err
	}

	if desiredEnabled && !current.Enabled {
		if out, err := exec.Command("launchctl", "load", "-w", name).CombinedOutput(); err != nil { // #nosec G204 - name validated by caller
			return fmt.Errorf("launchctl load %s: %w (output: %s)", name, err, strings.TrimSpace(string(out)))
		}
	} else if !desiredEnabled && current.Enabled {
		if out, err := exec.Command("launchctl", "unload", "-w", name).CombinedOutput(); err != nil { // #nosec G204 - name validated by caller
			return fmt.Errorf("launchctl unload %s: %w (output: %s)", name, err, strings.TrimSpace(string(out)))
		}
	}

	if desiredRunning && !current.Running {
		if out, err := exec.Command("launchctl", "start", name).CombinedOutput(); err != nil { // #nosec G204 - name validated by caller
			return fmt.Errorf("launchctl start %s: %w (output: %s)", name, err, strings.TrimSpace(string(out)))
		}
	} else if !desiredRunning && current.Running {
		if out, err := exec.Command("launchctl", "stop", name).CombinedOutput(); err != nil { // #nosec G204 - name validated by caller
			return fmt.Errorf("launchctl stop %s: %w (output: %s)", name, err, strings.TrimSpace(string(out)))
		}
	}

	return nil
}
