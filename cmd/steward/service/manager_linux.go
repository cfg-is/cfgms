// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	linuxInstallPath = "/usr/local/bin/cfgms-steward"
	linuxSystemdUnit = "/etc/systemd/system/cfgms-steward.service"
	linuxServiceName = "cfgms-steward"
	linuxCACertPath  = "/etc/cfgms/controller-ca.crt"
)

// platformCACertPath returns the path where the CA cert is written, respecting
// CFGMS_INSTALL_PREFIX for test isolation.
func platformCACertPath() string {
	if prefix := os.Getenv("CFGMS_INSTALL_PREFIX"); prefix != "" {
		return filepath.Join(prefix, linuxCACertPath)
	}
	return linuxCACertPath
}

func newManager(binaryPath string) Manager {
	return &linuxManager{binaryPath: binaryPath}
}

type linuxManager struct {
	binaryPath string
}

func (m *linuxManager) IsElevated() bool {
	return os.Getuid() == 0
}

// Install copies the binary to /usr/local/bin, writes the systemd unit, and
// enables/starts the service. Running Install on an already-installed service
// stops it first, replaces the binary, then restarts.
//
// If caCertPEM is non-empty, the CA cert is written to the platform-standard
// path before the service is registered. When expectedFingerprint is also
// non-empty, fingerprint verification runs first — a mismatch returns an error
// without any disk writes or service changes.
func (m *linuxManager) Install(token, caCertPEM, expectedFingerprint string) error {
	if err := validateToken(token); err != nil {
		return err
	}
	// Verify fingerprint before any privileged operations so the caller gets a
	// clear error without needing to undo partial changes.
	if caCertPEM != "" && expectedFingerprint != "" {
		if err := verifyCACertFingerprint(caCertPEM, expectedFingerprint); err != nil {
			return err
		}
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

	// Write CA cert before registering the service so the service finds it on first start.
	if caCertPEM != "" {
		fmt.Printf("Writing CA cert to %s...\n", platformCACertPath())
		if err := writeCACert(caCertPEM, platformCACertPath()); err != nil {
			return fmt.Errorf("failed to write CA cert: %w", err)
		}
	}

	fmt.Println("Writing systemd unit...")
	unit := generateSystemdUnit(token)
	if err := writeSystemdUnit(linuxSystemdUnit, []byte(unit)); err != nil {
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

// writeSystemdUnit writes a systemd unit file to path.
// 0600: owner rw (root only); systemd reads unit files as root, group read is unnecessary
// and would expose the registration token to group members.
func writeSystemdUnit(path string, content []byte) error {
	return os.WriteFile(path, content, 0600)
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
ExecStart=%s --regtoken "%s"
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cfgms-steward

[Install]
WantedBy=multi-user.target
`, linuxInstallPath, token)
}
