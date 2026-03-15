// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build linux

package service

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

const (
	linuxInstallPath = "/usr/local/bin/cfgms-steward"
	linuxSystemdUnit = "/etc/systemd/system/cfgms-steward.service"
	linuxServiceName = "cfgms-steward"
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
func (m *linuxManager) Install(token string) error {
	if err := validateToken(token); err != nil {
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
	unit := generateSystemdUnit(token)
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

	fmt.Printf("\nDone. CFGMS Steward installed and running.\n")
	fmt.Printf("  Service name: %s\n", linuxServiceName)
	fmt.Printf("  Status:  cfgms-steward status\n")
	fmt.Printf("  Remove:  cfgms-steward uninstall\n")
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

	fmt.Println("CFGMS Steward uninstalled.")
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
	if _, err := os.Stat(linuxSystemdUnit); err == nil {
		status.Installed = true
	}

	// Check if active via systemctl is-active (exit 0 = active).
	out, err := exec.Command("systemctl", "is-active", linuxServiceName).Output()
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		status.Running = true
	}

	return status, nil
}

// generateSystemdUnit returns a systemd unit that runs cfgms-steward with the
// given registration token. Restart=always and RestartSec=10 ensure the steward
// recovers from transient failures.
//
// Security note: the token appears in the unit file (readable by root). This
// mirrors the behaviour of --regtoken in ps output. The token is a one-time
// registration credential — after registration the steward uses mTLS certs.
func generateSystemdUnit(token string) string {
	return fmt.Sprintf(`[Unit]
Description=CFGMS Steward
Documentation=https://docs.cfg.is/steward
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s --regtoken %s
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cfgms-steward

[Install]
WantedBy=multi-user.target
`, linuxInstallPath, token)
}

// copyBinary copies src to dst with execute permissions.
func copyBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	// Write to a temp file first to make the replacement atomic.
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}

	return os.Rename(tmp, dst)
}
