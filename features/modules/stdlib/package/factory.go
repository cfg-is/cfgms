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
	"strconv"
	"strings"
)

// NewPackageManager creates a new package manager based on the current platform
func NewPackageManager(ctx context.Context) (PackageManager, error) {
	switch runtime.GOOS {
	case "windows":
		// resolveWinget checks the PATH app-execution alias (interactive
		// users) then the packaged WindowsApps binary for SYSTEM/service
		// contexts (the steward runs as LocalSystem; CI runner services run
		// as NETWORK SERVICE, neither has a user profile / alias) — a
		// declared path to a Microsoft-signed binary (predictable admin
		// tooling per the threat model).
		if bin, ok := resolveWinget(ctx); ok {
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

// resolveWinget locates a working winget.exe invocation path: the bare
// command first (PATH app-execution alias, interactive users), then the
// packaged WindowsApps binary (SYSTEM/service contexts). Used by the
// provider registry's winget probe/constructor and by NewPackageManager.
func resolveWinget(ctx context.Context) (string, bool) {
	cmd := exec.CommandContext(ctx, "winget", "--version")
	cmd.Env = wingetAugmentedEnv("winget")
	if _, err := cmd.Output(); err == nil {
		return "winget", true
	}
	return resolveWingetFullPath(ctx)
}

// resolveWingetFullPath locates the packaged winget.exe under the WindowsApps
// store for contexts where the per-user app-execution alias is unavailable
// (SYSTEM, service accounts). Candidates are probed newest-first with a
// --version execution (using the augmented PATH so the MSIX framework DLLs
// resolve — see wingetAugmentedEnv) so a stale leftover package directory is
// never selected.
func resolveWingetFullPath(ctx context.Context) (string, bool) {
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		return "", false
	}
	for _, bin := range wingetCandidates(programFiles) {
		// #nosec G204 -- candidates are fully-qualified winget.exe paths under
		// ProgramFiles/WindowsApps and the sole argument is a fixed probe flag.
		cmd := exec.CommandContext(ctx, bin, "--version")
		cmd.Env = wingetAugmentedEnv(bin)
		if _, err := cmd.Output(); err == nil {
			return bin, true
		}
	}
	return "", false
}

// wingetCandidates returns fully qualified winget.exe candidate paths under
// the given Program Files root, newest package version first. The glob is
// pinned to the DesktopAppInstaller x64 package family
// (Microsoft.DesktopAppInstaller_<version>_x64__8wekyb3d8bbwe) so no other
// publisher's directory can match. Ordering compares the dotted package
// version numerically — a lexical sort would order 1.9.x above 1.10.x.
func wingetCandidates(programFiles string) []string {
	pattern := filepath.Join(programFiles, "WindowsApps", "Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe", "winget.exe")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}
	sort.SliceStable(matches, func(i, j int) bool {
		return compareVersionSlices(wingetPackageVersion(matches[i]), wingetPackageVersion(matches[j])) > 0
	})
	return matches
}

// wingetPackageVersion extracts the dotted package version from a candidate
// path's package directory name (Microsoft.DesktopAppInstaller_<ver>_x64__…)
// as numeric segments. Unparseable segments end the version (best effort — the
// --version probe in resolveWingetFullPath remains the correctness gate).
func wingetPackageVersion(candidate string) []int {
	dir := filepath.Base(filepath.Dir(candidate))
	parts := strings.Split(dir, "_")
	if len(parts) < 2 {
		return nil
	}
	segs := strings.Split(parts[1], ".")
	version := make([]int, 0, len(segs))
	for _, s := range segs {
		n, err := strconv.Atoi(s)
		if err != nil {
			break
		}
		version = append(version, n)
	}
	return version
}

// compareVersionSlices numerically compares two version-segment slices;
// missing segments compare as zero (1.29 == 1.29.0).
func compareVersionSlices(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			if av > bv {
				return 1
			}
			return -1
		}
	}
	return 0
}
