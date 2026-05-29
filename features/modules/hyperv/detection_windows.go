// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// windowsHypervDetector checks whether the local Windows host has Hyper-V
// enabled by running Get-VMHost via PowerShell. Results are cached for 5
// minutes to avoid repeated PowerShell invocations on every module operation.
type windowsHypervDetector struct {
	mu           sync.Mutex
	cachedResult bool
	cacheExpiry  time.Time
}

// psRunFn executes the Get-VMHost powershell command and returns combined output.
// Overridden in tests to avoid invoking a real powershell.exe.
var psRunFn = func(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "powershell.exe", "-NonInteractive", "-Command", "Get-VMHost | ConvertTo-Json").CombinedOutput()
}

// isSoftError returns true for cmdlet-not-found and access-denied failures,
// which indicate Hyper-V is not installed or accessible. All other errors are
// propagated to the caller.
func isSoftError(output []byte) bool {
	text := strings.ToLower(string(output))
	return strings.Contains(text, "commandnotfoundexception") ||
		strings.Contains(text, "is not recognized") ||
		strings.Contains(text, "access is denied") ||
		strings.Contains(text, "access denied")
}

// IsHypervHost runs Get-VMHost. Cmdlet-not-found and access-denied failures
// are soft failures that return (false, nil). Other exec errors return (false, err).
func (d *windowsHypervDetector) IsHypervHost(ctx context.Context) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if time.Now().Before(d.cacheExpiry) {
		return d.cachedResult, nil
	}

	output, err := psRunFn(ctx)
	if err != nil {
		if isSoftError(output) {
			return false, nil
		}
		return false, err
	}

	d.cachedResult = true
	d.cacheExpiry = time.Now().Add(5 * time.Minute)
	return true, nil
}

func newDefaultDetector() HypervDetector {
	return &windowsHypervDetector{}
}

// NewDefaultDetector returns the platform-appropriate HypervDetector for
// production use. Called by the steward module factory.
func NewDefaultDetector() HypervDetector {
	return newDefaultDetector()
}
