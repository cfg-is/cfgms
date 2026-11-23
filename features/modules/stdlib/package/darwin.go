// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"fmt"
	"strings"
)

// Homebrew install locations. The steward never resolves brew through PATH:
// the Apple silicon prefix is not on launchd's default PATH and module
// processes inherit a minimal environment, so the binary is located by its
// fixed per-architecture path.
const (
	brewBinArm64  = "/opt/homebrew/bin/brew"
	brewRepoArm64 = "/opt/homebrew"
	brewBinAmd64  = "/usr/local/bin/brew"
	// On Intel /usr/local itself is root-owned; the Homebrew repository
	// directory is the one the installing user owns.
	brewRepoAmd64 = "/usr/local/Homebrew"
)

// brewLocation is where Homebrew lives for one architecture.
type brewLocation struct {
	// BinPath is the fixed path of the brew executable (a symlink into the
	// repository on both architectures).
	BinPath string
	// RepoDir is the Homebrew repository directory whose owner is the
	// prefix owner brew runs as.
	RepoDir string
}

// brewLocationFor returns the fixed Homebrew locations for goarch. It is pure
// so both architectures are testable on any host.
func brewLocationFor(goarch string) (brewLocation, error) {
	switch goarch {
	case "arm64":
		return brewLocation{BinPath: brewBinArm64, RepoDir: brewRepoArm64}, nil
	case "amd64":
		return brewLocation{BinPath: brewBinAmd64, RepoDir: brewRepoAmd64}, nil
	default:
		return brewLocation{}, fmt.Errorf("homebrew: unsupported architecture %q (supported: arm64, amd64)", goarch)
	}
}

// homebrewManager implements PackageManager for Homebrew
type homebrewManager struct{}

func newHomebrewManager() PackageManager {
	return &homebrewManager{}
}

func (m *homebrewManager) Install(ctx context.Context, name, version string) error {
	// Homebrew has no generic version pin. A versioned formula is declared by
	// name (for example "python@3.12") with version: latest, so a pin is
	// rejected rather than silently installing a different version.
	if version != "latest" {
		return fmt.Errorf("brew: %w: cannot install %s at version %q (declare the versioned formula name, for example python@3.12, with version: latest)",
			ErrVersionPinUnsupported, name, version)
	}
	// #nosec G204 -- Configure validates the package name and rejects leading
	// dashes; the name is one argv to the fixed brew executable without a shell.
	cmd, err := newBrewCmd(ctx, "install", name)
	if err != nil {
		return err
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *homebrewManager) Remove(ctx context.Context, name string) error {
	// #nosec G204 -- name passed validatePackageName (including leading-dash
	// rejection) and is a single argv to the fixed brew executable.
	cmd, err := newBrewCmd(ctx, "uninstall", name)
	if err != nil {
		return err
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *homebrewManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
	// #nosec G204 -- the fixed brew command receives a validated package name as
	// one argv; no shell parsing occurs.
	cmd, err := newBrewCmd(ctx, "list", "--versions", name)
	if err != nil {
		return "", err
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get version for package %s: %w\nOutput: %s", name, err, string(output))
	}

	// Parse output like "package 1.2.3"
	parts := strings.Fields(string(output))
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid output format for package %s: %s", name, string(output))
	}

	return parts[1], nil
}

func (m *homebrewManager) ListInstalled(ctx context.Context) (map[string]string, error) {
	cmd, err := newBrewCmd(ctx, "list", "--versions")
	if err != nil {
		return nil, err
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list installed packages: %w\nOutput: %s", err, string(output))
	}

	result := make(map[string]string)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		result[parts[0]] = parts[1]
	}

	return result, nil
}

func (m *homebrewManager) GetVersion(ctx context.Context, name string) (string, error) {
	// #nosec G204 -- the fixed brew command receives a validated package name as
	// one argv; no shell parsing occurs.
	cmd, err := newBrewCmd(ctx, "list", "--versions", name)
	if err != nil {
		return "", err
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("brew list failed: %v, output: %s", err, string(output))
	}

	// Parse version from output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, name) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}
	return "", fmt.Errorf("version not found in brew output")
}

func (m *homebrewManager) IsInstalled(ctx context.Context, name string) (bool, error) {
	// #nosec G204 -- name is validated before manager dispatch and is passed as
	// one argv to the fixed brew executable.
	cmd, err := newBrewCmd(ctx, "list", name)
	if err != nil {
		return false, err
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If the error is "No such keg", the package is not installed
		if strings.Contains(string(output), "No such keg") {
			return false, nil
		}
		return false, fmt.Errorf("brew list failed: %v, output: %s", err, string(output))
	}
	return true, nil
}

func (m *homebrewManager) Update(ctx context.Context, name string) error {
	// #nosec G204 -- name is validated before manager dispatch and is passed as
	// one argv to the fixed brew executable.
	cmd, err := newBrewCmd(ctx, "upgrade", name)
	if err != nil {
		return err
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("brew upgrade failed: %v, output: %s", err, string(output))
	}
	return nil
}

func (m *homebrewManager) Name() string {
	return "brew"
}

func (m *homebrewManager) IsValidManager(name string) bool {
	return name == "brew"
}
