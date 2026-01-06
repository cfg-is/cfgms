// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package package_module

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
)

// NewPackageManager creates a new package manager based on the current platform
func NewPackageManager(ctx context.Context) (PackageManager, error) {
	switch runtime.GOOS {
	case "windows":
		// Check if winget is available
		if _, err := exec.CommandContext(ctx, "winget", "--version").Output(); err == nil {
			return newWingetManager(), nil
		}
		// Check if chocolatey is available
		if _, err := exec.CommandContext(ctx, "choco", "--version").Output(); err == nil {
			return newChocolateyManager(), nil
		}
		return nil, fmt.Errorf("no supported package manager found on Windows")

	case "darwin":
		// Check if Homebrew is available
		if _, err := exec.CommandContext(ctx, "brew", "--version").Output(); err == nil {
			return newHomebrewManager(), nil
		}
		return nil, fmt.Errorf("homebrew not found on macOS")

	case "linux":
		// Check for Linux package managers in order of preference
		if _, err := exec.CommandContext(ctx, "apt-get", "--version").Output(); err == nil {
			return newAptManager(), nil
		}
		if _, err := exec.CommandContext(ctx, "dnf", "--version").Output(); err == nil {
			return newDnfManager(), nil
		}
		if _, err := exec.CommandContext(ctx, "yum", "--version").Output(); err == nil {
			return newYumManager(), nil
		}
		if _, err := exec.CommandContext(ctx, "pacman", "--version").Output(); err == nil {
			return newPacmanManager(), nil
		}
		return nil, fmt.Errorf("no supported package manager found on Linux")

	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
