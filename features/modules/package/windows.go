// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// wingetManager implements PackageManager for Windows Package Manager (winget)
type wingetManager struct{}

func newWingetManager() PackageManager {
	return &wingetManager{}
}

func (m *wingetManager) Install(ctx context.Context, name, version string) error {
	cmd := exec.CommandContext(ctx, "winget", "install", "--accept-source-agreements", "--accept-package-agreements", name)
	if version != "latest" {
		cmd.Args = append(cmd.Args, "--version", version)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *wingetManager) Remove(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, "winget", "uninstall", "--accept-source-agreements", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *wingetManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
	cmd := exec.CommandContext(ctx, "winget", "list", "--name", name, "--accept-source-agreements")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get version for package %s: %w\nOutput: %s", name, err, string(output))
	}

	// Parse output to find version
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, name) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}

	return "", fmt.Errorf("version not found for package %s", name)
}

func (m *wingetManager) ListInstalled(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "winget", "list", "--accept-source-agreements")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list installed packages: %w\nOutput: %s", err, string(output))
	}

	result := make(map[string]string)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "Name") || strings.HasPrefix(line, "---") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			result[parts[0]] = parts[1]
		}
	}

	return result, nil
}

func (m *wingetManager) Name() string {
	return "winget"
}

func (m *wingetManager) IsValidManager(name string) bool {
	return name == "winget"
}

// chocolateyManager implements PackageManager for Chocolatey
type chocolateyManager struct{}

func newChocolateyManager() PackageManager {
	return &chocolateyManager{}
}

func (m *chocolateyManager) Install(ctx context.Context, name, version string) error {
	cmd := exec.CommandContext(ctx, "choco", "install", "-y", name)
	if version != "latest" {
		cmd.Args = append(cmd.Args, "--version", version)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *chocolateyManager) Remove(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, "choco", "uninstall", "-y", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *chocolateyManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
	cmd := exec.CommandContext(ctx, "choco", "list", "--local-only", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get version for package %s: %w\nOutput: %s", name, err, string(output))
	}

	// Parse output to find version
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, name) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}

	return "", fmt.Errorf("version not found for package %s", name)
}

func (m *chocolateyManager) ListInstalled(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "choco", "list", "--local-only")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list installed packages: %w\nOutput: %s", err, string(output))
	}

	result := make(map[string]string)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "Chocolatey") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			result[parts[0]] = parts[1]
		}
	}

	return result, nil
}

func (m *chocolateyManager) GetVersion(ctx context.Context, name string) (string, error) {
	cmd := exec.CommandContext(ctx, "choco", "list", "--local-only", "--exact", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("choco list failed: %v, output: %s", err, string(output))
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
	return "", fmt.Errorf("version not found in choco output")
}

func (m *chocolateyManager) IsInstalled(ctx context.Context, name string) (bool, error) {
	cmd := exec.CommandContext(ctx, "choco", "list", "--local-only", "--exact", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("choco list failed: %v, output: %s", err, string(output))
	}
	return strings.Contains(string(output), name), nil
}

func (m *chocolateyManager) Update(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, "choco", "upgrade", "-y", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("choco upgrade failed: %v, output: %s", err, string(output))
	}
	return nil
}

func (m *chocolateyManager) Name() string {
	return "choco"
}

func (m *chocolateyManager) IsValidManager(name string) bool {
	return name == "choco"
}
