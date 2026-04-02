// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import (
	"fmt"
	"os/exec"
	"strings"
)

// windowsExecutor manages OS services via sc.exe on Windows systems.
type windowsExecutor struct{}

func newExecutor() serviceExecutor {
	return &windowsExecutor{}
}

// getState queries the Windows Service Control Manager for the service state.
func (e *windowsExecutor) getState(name string) (serviceState, error) {
	// sc query returns SERVICE_STOPPED, SERVICE_RUNNING, etc.
	out, err := exec.Command("sc", "query", name).CombinedOutput() // #nosec G204 - name validated by caller
	output := strings.TrimSpace(string(out))

	if err != nil {
		// sc query exits non-zero when the service doesn't exist.
		if strings.Contains(output, "does not exist") ||
			strings.Contains(output, "1060") { // ERROR_SERVICE_DOES_NOT_EXIST
			return serviceState{Running: false, Enabled: false}, nil
		}
		return serviceState{}, fmt.Errorf("sc query %s: %w (output: %s)", name, err, output)
	}

	running := strings.Contains(output, "RUNNING")

	// Check start type via sc qc (query configuration).
	out, err = exec.Command("sc", "qc", name).CombinedOutput() // #nosec G204 - name validated by caller
	if err != nil {
		return serviceState{}, fmt.Errorf("sc qc %s: %w (output: %s)", name, err, strings.TrimSpace(string(out)))
	}
	// AUTO_START means enabled (starts on boot); DEMAND_START/DISABLED means not auto.
	enabled := strings.Contains(string(out), "AUTO_START")

	return serviceState{Running: running, Enabled: enabled}, nil
}

// setState applies the desired running and enabled states via sc.exe.
func (e *windowsExecutor) setState(name string, desiredRunning bool, desiredEnabled bool) error {
	startType := "demand"
	if desiredEnabled {
		startType = "auto"
	}
	if out, err := exec.Command("sc", "config", name, "start=", startType).CombinedOutput(); err != nil { // #nosec G204 - name validated by caller
		return fmt.Errorf("sc config %s start=%s: %w (output: %s)", name, startType, err, strings.TrimSpace(string(out)))
	}

	if desiredRunning {
		if out, err := exec.Command("sc", "start", name).CombinedOutput(); err != nil { // #nosec G204 - name validated by caller
			output := strings.TrimSpace(string(out))
			// Ignore "already running" error (1056 = ERROR_SERVICE_ALREADY_RUNNING).
			if !strings.Contains(output, "1056") {
				return fmt.Errorf("sc start %s: %w (output: %s)", name, err, output)
			}
		}
	} else {
		if out, err := exec.Command("sc", "stop", name).CombinedOutput(); err != nil { // #nosec G204 - name validated by caller
			output := strings.TrimSpace(string(out))
			// Ignore "not started" error (1062 = ERROR_SERVICE_NOT_ACTIVE).
			if !strings.Contains(output, "1062") {
				return fmt.Errorf("sc stop %s: %w (output: %s)", name, err, output)
			}
		}
	}

	return nil
}
