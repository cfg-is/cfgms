// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package package_module

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// aptManager implements PackageManager for APT (Debian/Ubuntu)
type aptManager struct{}

func newAptManager() PackageManager {
	return &aptManager{}
}

func (m *aptManager) Install(ctx context.Context, name, version string) error {
	cmd := exec.CommandContext(ctx, "apt-get", "install", "-y", name)
	if version != "latest" {
		cmd.Args = append(cmd.Args, "="+version)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *aptManager) Remove(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, "apt-get", "remove", "-y", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *aptManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Version}", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get version for package %s: %w\nOutput: %s", name, err, string(output))
	}
	return strings.TrimSpace(string(output)), nil
}

func (m *aptManager) ListInstalled(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\n")
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
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			continue
		}
		result[parts[0]] = parts[1]
	}

	return result, nil
}

func (m *aptManager) Name() string {
	return "apt"
}

func (m *aptManager) IsValidManager(name string) bool {
	return name == "apt"
}

// dnfManager implements PackageManager for DNF (Fedora/RHEL 8+)
type dnfManager struct{}

func newDnfManager() PackageManager {
	return &dnfManager{}
}

func (m *dnfManager) Install(ctx context.Context, name, version string) error {
	cmd := exec.CommandContext(ctx, "dnf", "install", "-y", name)
	if version != "latest" {
		cmd.Args = append(cmd.Args, "-"+version)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *dnfManager) Remove(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, "dnf", "remove", "-y", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *dnfManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
	cmd := exec.CommandContext(ctx, "rpm", "-q", "--qf", "%{VERSION}", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get version for package %s: %w\nOutput: %s", name, err, string(output))
	}
	return strings.TrimSpace(string(output)), nil
}

func (m *dnfManager) ListInstalled(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n")
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
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			continue
		}
		result[parts[0]] = parts[1]
	}

	return result, nil
}

func (m *dnfManager) Name() string {
	return "dnf"
}

func (m *dnfManager) IsValidManager(name string) bool {
	return name == "dnf"
}

// yumManager implements PackageManager for YUM (RHEL 7 and older)
type yumManager struct{}

func newYumManager() PackageManager {
	return &yumManager{}
}

func (m *yumManager) Install(ctx context.Context, name, version string) error {
	cmd := exec.CommandContext(ctx, "yum", "install", "-y", name)
	if version != "latest" {
		cmd.Args = append(cmd.Args, "-"+version)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *yumManager) Remove(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, "yum", "remove", "-y", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *yumManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
	cmd := exec.CommandContext(ctx, "rpm", "-q", "--qf", "%{VERSION}", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get version for package %s: %w\nOutput: %s", name, err, string(output))
	}
	return strings.TrimSpace(string(output)), nil
}

func (m *yumManager) ListInstalled(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n")
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
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			continue
		}
		result[parts[0]] = parts[1]
	}

	return result, nil
}

func (m *yumManager) Name() string {
	return "yum"
}

func (m *yumManager) IsValidManager(name string) bool {
	return name == "yum"
}

// pacmanManager implements PackageManager for Pacman (Arch Linux)
type pacmanManager struct{}

func newPacmanManager() PackageManager {
	return &pacmanManager{}
}

func (m *pacmanManager) Install(ctx context.Context, name, version string) error {
	cmd := exec.CommandContext(ctx, "pacman", "-S", "--noconfirm", name)
	if version != "latest" {
		cmd.Args = append(cmd.Args, "="+version)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *pacmanManager) Remove(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, "pacman", "-R", "--noconfirm", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *pacmanManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
	cmd := exec.CommandContext(ctx, "pacman", "-Q", name)
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

func (m *pacmanManager) ListInstalled(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "pacman", "-Q")
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

func (m *pacmanManager) Name() string {
	return "pacman"
}

func (m *pacmanManager) IsValidManager(name string) bool {
	return name == "pacman"
}
