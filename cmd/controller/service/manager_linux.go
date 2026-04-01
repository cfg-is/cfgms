// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	linuxInstallPath = "/usr/local/bin/cfgms-controller"
	linuxSystemdUnit = "/etc/systemd/system/cfgms-controller.service"
	linuxServiceName = "cfgms-controller"
)

func newManager(binaryPath string) Manager {
	return &linuxManager{binaryPath: binaryPath}
}

type linuxManager struct {
	binaryPath string
}

func (m *linuxManager) InstallPath() string { return linuxInstallPath }

func (m *linuxManager) IsElevated() bool {
	return os.Getuid() == 0
}

// Install copies the binary to /usr/local/bin, writes the systemd unit, and
// enables/starts the service. Running Install on an already-installed service
// stops it first, replaces the binary, then restarts.
func (m *linuxManager) Install(configPath string) error {
	if err := validateConfigPath(configPath); err != nil {
		return err
	}
	if !m.IsElevated() {
		return fmt.Errorf("install requires root privileges: re-run with sudo")
	}

	// Stop existing service if running (idempotent: ignore failure if not running).
	_ = exec.Command("systemctl", "stop", linuxServiceName).Run()

	fmt.Printf("Installing to %s...\n", linuxInstallPath)
	if err := copyBinary(m.binaryPath, linuxInstallPath); err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}

	fmt.Println("Writing systemd unit...")
	unit := generateSystemdUnit(configPath)
	if err := os.WriteFile(linuxSystemdUnit, []byte(unit), 0644); err != nil {
		return fmt.Errorf("failed to write systemd unit %s: %w", linuxSystemdUnit, err)
	}

	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload failed: %w\n%s", err, out)
	}

	fmt.Println("Enabling and starting service...")
	if out, err := exec.Command("systemctl", "enable", "--now", linuxServiceName).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable --now %s failed: %w\n%s", linuxServiceName, err, out)
	}

	fmt.Printf("\nDone. CFGMS Controller installed and running.\n")
	fmt.Printf("  Service name: %s\n", linuxServiceName)
	fmt.Printf("  Config:  %s\n", configPath)
	fmt.Printf("  Status:  cfgms-controller status\n")
	fmt.Printf("  Remove:  cfgms-controller uninstall\n")
	return nil
}

// Uninstall stops and removes the systemd service. If purge is true the
// installed binary is also removed.
func (m *linuxManager) Uninstall(purge bool) error {
	if !m.IsElevated() {
		return fmt.Errorf("uninstall requires root privileges: re-run with sudo")
	}

	fmt.Println("Stopping service...")
	// Ignore stop error — service may already be stopped.
	_ = exec.Command("systemctl", "stop", linuxServiceName).Run()

	fmt.Println("Disabling service...")
	// Ignore disable error — service may not be enabled.
	_ = exec.Command("systemctl", "disable", linuxServiceName).Run()

	if _, err := os.Stat(linuxSystemdUnit); err == nil {
		fmt.Printf("Removing %s...\n", linuxSystemdUnit)
		if err := os.Remove(linuxSystemdUnit); err != nil {
			return fmt.Errorf("failed to remove systemd unit: %w", err)
		}
	}

	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload failed: %w\n%s", err, out)
	}

	if purge {
		if _, err := os.Stat(linuxInstallPath); err == nil {
			fmt.Printf("Removing %s...\n", linuxInstallPath)
			if err := os.Remove(linuxInstallPath); err != nil {
				return fmt.Errorf("failed to remove binary: %w", err)
			}
		}
	}

	fmt.Println("CFGMS Controller uninstalled.")
	return nil
}

// Status returns the current state of the systemd service without requiring
// elevated privileges.
func (m *linuxManager) Status() (*ServiceStatus, error) {
	status := &ServiceStatus{
		ServiceName: linuxServiceName,
		InstallPath: linuxInstallPath,
	}

	// Service is installed if the unit file exists.
	unitContent, err := os.ReadFile(linuxSystemdUnit)
	if err == nil {
		status.Installed = true
		status.ConfigPath = configPathFromUnit(string(unitContent))
	}

	// Check if active via systemctl is-active (exit 0 = active).
	out, err := exec.Command("systemctl", "is-active", linuxServiceName).Output()
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		status.Running = true
	}

	return status, nil
}

// generateSystemdUnit returns a systemd unit that runs cfgms-controller with the
// given config path. Restart=always and RestartSec=10 ensure the controller
// recovers from transient failures.
func generateSystemdUnit(configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=CFGMS Controller
Documentation=https://docs.cfg.is/controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s --config "%s"
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cfgms-controller

[Install]
WantedBy=multi-user.target
`, linuxInstallPath, configPath)
}

// configPathFromUnit extracts the --config argument from a systemd unit file.
// Returns an empty string if the argument cannot be found.
func configPathFromUnit(content string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "ExecStart=") {
			continue
		}
		idx := strings.Index(trimmed, `--config "`)
		if idx == -1 {
			continue
		}
		rest := trimmed[idx+len(`--config "`):]
		end := strings.Index(rest, `"`)
		if end == -1 {
			continue
		}
		return rest[:end]
	}
	return ""
}
