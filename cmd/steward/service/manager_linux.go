// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cfgis/cfgms/pkg/version"
)

const (
	// linuxLauncherPath is where the launcher binary is installed. The steward's
	// push-upgrade handler execs "cfgms-launcher swap" at this exact path
	// (features/steward/client launcherPath()), so a launcher-managed install is
	// what makes a Linux steward upgradeable via the control plane. It must not change.
	linuxLauncherPath = "/usr/local/bin/cfgms-launcher"
	// linuxLauncherRoot is the launcher install root holding versions/ and
	// state.json. Matches the launcher's defaultRoot() on Linux.
	linuxLauncherRoot = "/opt/cfgms"
	// linuxLauncherBinaryName is the launcher binary as shipped in the install
	// bundle, expected alongside the cfgms-steward binary being installed.
	linuxLauncherBinaryName = "cfgms-steward-launcher"
	// linuxInstallPath is the legacy bare-steward binary path. Retained only so
	// Uninstall(purge) also cleans up pre-launcher (direct-service) installs.
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
// When controllerURL is non-empty, it is embedded in ExecStart as --controller-url.
// If caCertPEM is non-empty, the CA cert is written to the platform-standard
// path before the service is registered. When expectedFingerprint is also
// non-empty, fingerprint verification runs first — a mismatch returns an error
// without any disk writes or service changes.
func (m *linuxManager) Install(token, controllerURL, caCertPEM, expectedFingerprint string) error {
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

	// A launcher-managed install (steward supervised by cfgms-launcher, staged
	// under /opt/cfgms/versions/) is what makes the steward upgradeable via the
	// control plane: the push-upgrade handler execs "cfgms-launcher swap" and
	// requires the launcher at linuxLauncherPath. A bare direct-service steward
	// cannot be push-upgraded. The launcher binary ships alongside the steward
	// binary in the install bundle.
	launcherSrc := filepath.Join(filepath.Dir(m.binaryPath), linuxLauncherBinaryName)
	if _, err := os.Stat(launcherSrc); err != nil {
		return fmt.Errorf("launcher binary %q not found next to the steward binary: %w\n"+
			"  a launcher-managed install requires %s in the install bundle",
			launcherSrc, err, linuxLauncherBinaryName)
	}

	ver := version.Short()

	fmt.Printf("Installing launcher to %s...\n", linuxLauncherPath)
	if err := copyBinary(launcherSrc, linuxLauncherPath); err != nil {
		return fmt.Errorf("failed to install launcher: %w", err)
	}

	// Bootstrap the launcher layout: stage the steward binary as the current
	// version under /opt/cfgms/versions/<ver>/ and record it in state.json. This
	// reuses the launcher's own "swap" surface, so the on-disk layout is identical
	// to what a subsequent push-upgrade produces.
	fmt.Printf("Staging steward %s under %s...\n", ver, linuxLauncherRoot)
	if out, err := exec.Command(linuxLauncherPath, "swap", "--root", linuxLauncherRoot, ver, m.binaryPath).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stage steward binary via launcher: %w\n%s", err, out)
	}

	// Write CA cert before registering the service so the service finds it on first start.
	if caCertPEM != "" {
		fmt.Printf("Writing CA cert to %s...\n", platformCACertPath())
		if err := writeCACert(caCertPEM, platformCACertPath()); err != nil {
			return fmt.Errorf("failed to write CA cert: %w", err)
		}
	}

	fmt.Println("Writing systemd unit...")
	unit := generateSystemdUnit(token, controllerURL)
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
		// Launcher binary + layout (versions/, state.json) for launcher-managed installs.
		if _, err := os.Stat(linuxLauncherPath); err == nil {
			fmt.Printf("Removing %s...\n", linuxLauncherPath)
			if err := os.Remove(linuxLauncherPath); err != nil {
				return fmt.Errorf("failed to remove launcher: %w", err)
			}
		}
		if _, err := os.Stat(linuxLauncherRoot); err == nil {
			fmt.Printf("Removing %s...\n", linuxLauncherRoot)
			if err := os.RemoveAll(linuxLauncherRoot); err != nil {
				return fmt.Errorf("failed to remove launcher root: %w", err)
			}
		}
		// Legacy bare-steward binary (pre-launcher direct-service installs).
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
		InstallPath: linuxLauncherPath,
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
// given registration token. When controllerURL is non-empty, --controller-url is
// appended to ExecStart so the steward connects to the specified controller.
// Restart=always and RestartSec=10 ensure the steward recovers from transient failures.
//
// Security note: the token appears in the unit file (readable by root). This
// mirrors the behaviour of --regtoken in ps output. The token is a one-time
// registration credential — after registration the steward uses mTLS certs.
func generateSystemdUnit(token, controllerURL string) string {
	// The launcher supervises the steward and forwards --child-args to it. Args
	// are space-separated (the launcher splits on whitespace); the registration
	// token is validated to be free of spaces/quotes, so no per-arg quoting is
	// needed inside the child-args string.
	childArgs := fmt.Sprintf(`--regtoken %s`, token)
	if controllerURL != "" {
		childArgs += fmt.Sprintf(` --controller-url %s`, controllerURL)
	}
	execStart := fmt.Sprintf(`%s run --root %s --child-args "%s"`, linuxLauncherPath, linuxLauncherRoot, childArgs)
	return fmt.Sprintf(`[Unit]
Description=CFGMS Steward
Documentation=https://docs.cfg.is/steward
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cfgms-steward

[Install]
WantedBy=multi-user.target
`, execStart)
}
