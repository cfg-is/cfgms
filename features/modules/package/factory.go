// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
)

// NewPackageManager creates a new package manager based on the current platform
func NewPackageManager(ctx context.Context) (PackageManager, error) {
	switch runtime.GOOS {
	case "windows":
		// Check if winget is available on PATH (interactive users get the
		// app-execution alias).
		if _, err := exec.CommandContext(ctx, "winget", "--version").Output(); err == nil {
			return newWingetManager(), nil
		}
		// SYSTEM/service contexts (the steward runs as LocalSystem; CI runner
		// services run as NETWORK SERVICE) have no user profile and therefore
		// no winget app-execution alias — resolve the packaged binary directly
		// from WindowsApps: a declared path to a Microsoft-signed binary
		// (predictable admin tooling per the threat model).
		if bin, ok := resolveWingetFullPath(ctx); ok {
			return newWingetManagerWithPath(bin), nil
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

// resolveWingetFullPath locates the packaged winget.exe under the WindowsApps
// store for contexts where the per-user app-execution alias is unavailable
// (SYSTEM, service accounts). Candidates are probed newest-first with a
// --version execution so a stale leftover package directory is never selected.
func resolveWingetFullPath(ctx context.Context) (string, bool) {
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		return "", false
	}
	for _, bin := range wingetCandidates(programFiles) {
		if _, err := exec.CommandContext(ctx, bin, "--version").Output(); err == nil {
			return bin, true
		}
	}
	return "", false
}

// wingetCandidates returns fully qualified winget.exe candidate paths under
// the given Program Files root, newest package version first. The glob is
// pinned to the DesktopAppInstaller x64 package family
// (Microsoft.DesktopAppInstaller_<version>_x64__8wekyb3d8bbwe) so no other
// publisher's directory can match.
func wingetCandidates(programFiles string) []string {
	pattern := filepath.Join(programFiles, "WindowsApps", "Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe", "winget.exe")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}
	// Glob output is lexically sorted ascending; newest package last. Reverse
	// so the newest version is probed first.
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	return matches
}
