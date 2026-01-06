// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package package_module

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// homebrewManager implements PackageManager for Homebrew
type homebrewManager struct{}

func newHomebrewManager() PackageManager {
	return &homebrewManager{}
}

func (m *homebrewManager) Install(ctx context.Context, name, version string) error {
	cmd := exec.CommandContext(ctx, "brew", "install", name)
	if version != "latest" {
		cmd.Args = append(cmd.Args, version)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *homebrewManager) Remove(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, "brew", "uninstall", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *homebrewManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
	cmd := exec.CommandContext(ctx, "brew", "list", "--versions", name)
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
	cmd := exec.CommandContext(ctx, "brew", "list", "--versions")
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
	cmd := exec.CommandContext(ctx, "brew", "list", "--versions", name)
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
	cmd := exec.CommandContext(ctx, "brew", "list", name)
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
	cmd := exec.CommandContext(ctx, "brew", "upgrade", name)
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
