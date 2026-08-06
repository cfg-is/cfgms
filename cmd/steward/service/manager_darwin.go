// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build darwin

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
	// darwinLauncherPath is where the launcher binary is installed. The steward's
	// push-upgrade handler execs "cfgms-launcher swap" at this exact path
	// (features/steward/client launcherPath()), so a launcher-managed install is
	// what makes a macOS steward upgradeable via the control plane. It must not change.
	darwinLauncherPath = "/usr/local/bin/cfgms-launcher"
	// darwinLauncherRoot is the launcher install root holding versions/ and
	// state.json. Matches the launcher's defaultRoot() on macOS (non-Windows default).
	darwinLauncherRoot = "/opt/cfgms"
	// darwinLauncherBinaryName is the launcher binary as shipped in the install
	// bundle, expected alongside the cfgms-steward binary being installed.
	darwinLauncherBinaryName = "cfgms-steward-launcher"
	// darwinInstallPath is the legacy bare-steward binary path. Retained only so
	// Uninstall(purge) also cleans up pre-launcher (direct-service) installs.
	darwinInstallPath = "/usr/local/bin/cfgms-steward"
	darwinPlistPath   = "/Library/LaunchDaemons/com.cfgms.steward.plist"
	darwinServiceName = "com.cfgms.steward"
	darwinCACertPath  = "/etc/cfgms/controller-ca.crt"
)

// platformCACertPath returns the path where the CA cert is written, respecting
// CFGMS_INSTALL_PREFIX for test isolation.
func platformCACertPath() string {
	if prefix := os.Getenv("CFGMS_INSTALL_PREFIX"); prefix != "" {
		return filepath.Join(prefix, darwinCACertPath)
	}
	return darwinCACertPath
}

func newManager(binaryPath string) Manager {
	return &darwinManager{binaryPath: binaryPath}
}

type darwinManager struct {
	binaryPath string
}

func (m *darwinManager) IsElevated() bool {
	return os.Getuid() == 0
}

// Install copies the launcher and steward to their installed locations, stages
// the steward under the launcher's versioned layout, writes the launchd plist,
// and loads it via launchctl. If already installed, the existing daemon is
// unloaded first, the binaries are replaced, then the daemon is reloaded.
//
// When controllerURL is non-empty, it is embedded in ProgramArguments as
// --controller-url. If caCertPEM is non-empty, the CA cert is written to the
// platform-standard path before the daemon is loaded. When expectedFingerprint is
// also non-empty, fingerprint verification runs first — a mismatch returns an
// error without any disk writes or service changes.
func (m *darwinManager) Install(token, controllerURL, caCertPEM, expectedFingerprint string) error {
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

	// A launcher-managed install (steward supervised by cfgms-launcher, staged
	// under /opt/cfgms/versions/) is what makes the steward upgradeable via the
	// control plane: the push-upgrade handler execs "cfgms-launcher swap" and
	// requires the launcher at darwinLauncherPath. A bare direct-service steward
	// cannot be push-upgraded. The launcher binary ships alongside the steward
	// binary in the install bundle.
	launcherSrc := filepath.Join(filepath.Dir(m.binaryPath), darwinLauncherBinaryName)
	if _, err := os.Stat(launcherSrc); err != nil {
		return fmt.Errorf("launcher binary %q not found next to the steward binary: %w\n"+
			"  a launcher-managed install requires %s in the install bundle",
			launcherSrc, err, darwinLauncherBinaryName)
	}

	if !m.IsElevated() {
		return fmt.Errorf("install requires root privileges: re-run with sudo")
	}

	// Unload existing daemon if present (idempotent — ignore failure).
	if _, err := os.Stat(darwinPlistPath); err == nil {
		fmt.Println("Unloading existing daemon...")
		_ = exec.Command("launchctl", "unload", darwinPlistPath).Run()
	}

	ver := version.Short()

	fmt.Printf("Installing launcher to %s...\n", darwinLauncherPath)
	if err := copyBinary(launcherSrc, darwinLauncherPath); err != nil {
		return fmt.Errorf("failed to install launcher: %w", err)
	}

	// Bootstrap the launcher layout: stage the steward binary as the current
	// version under /opt/cfgms/versions/<ver>/ and record it in state.json. This
	// reuses the launcher's own "swap" surface, so the on-disk layout is identical
	// to what a subsequent push-upgrade produces.
	fmt.Printf("Staging steward %s under %s...\n", ver, darwinLauncherRoot)
	if out, err := exec.Command(darwinLauncherPath, "swap", "--root", darwinLauncherRoot, ver, m.binaryPath).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stage steward binary via launcher: %w\n%s", err, out)
	}

	// Write CA cert before loading the daemon so the service finds it on first start.
	if caCertPEM != "" {
		fmt.Printf("Writing CA cert to %s...\n", platformCACertPath())
		if err := writeCACert(caCertPEM, platformCACertPath()); err != nil {
			return fmt.Errorf("failed to write CA cert: %w", err)
		}
	}

	fmt.Println("Writing launchd plist...")
	plist := generateLaunchdPlist(token, controllerURL)
	if err := os.WriteFile(darwinPlistPath, []byte(plist), 0644); err != nil {
		return fmt.Errorf("failed to write plist %s: %w", darwinPlistPath, err)
	}

	fmt.Println("Loading launchd daemon...")
	if out, err := exec.Command("launchctl", "load", darwinPlistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl load failed: %w\n%s", err, out)
	}

	fmt.Printf("\nDone. CFGMS Steward installed and running.\n")
	fmt.Printf("  Service name: %s\n", darwinServiceName)
	fmt.Printf("  Status:  cfgms-steward status\n")
	fmt.Printf("  Remove:  cfgms-steward uninstall\n")
	return nil
}

// Uninstall unloads and removes the launchd daemon. If purge is true the
// installed launcher binary and its versioned staging layout are also removed,
// along with the legacy bare-steward binary for pre-launcher installs.
func (m *darwinManager) Uninstall(purge bool) error {
	if !m.IsElevated() {
		return fmt.Errorf("uninstall requires root privileges: re-run with sudo")
	}

	if _, err := os.Stat(darwinPlistPath); err == nil {
		fmt.Println("Unloading daemon...")
		_ = exec.Command("launchctl", "unload", darwinPlistPath).Run()

		fmt.Printf("Removing %s...\n", darwinPlistPath)
		if err := os.Remove(darwinPlistPath); err != nil {
			return fmt.Errorf("failed to remove plist: %w", err)
		}
	} else {
		fmt.Println("Daemon plist not found — nothing to remove.")
	}

	if purge {
		// Launcher binary + layout (versions/, state.json) for launcher-managed installs.
		if _, err := os.Stat(darwinLauncherPath); err == nil {
			fmt.Printf("Removing %s...\n", darwinLauncherPath)
			if err := os.Remove(darwinLauncherPath); err != nil {
				return fmt.Errorf("failed to remove launcher: %w", err)
			}
		}
		if _, err := os.Stat(darwinLauncherRoot); err == nil {
			fmt.Printf("Removing %s...\n", darwinLauncherRoot)
			if err := os.RemoveAll(darwinLauncherRoot); err != nil {
				return fmt.Errorf("failed to remove launcher root: %w", err)
			}
		}
		// Legacy bare-steward binary (pre-launcher direct-service installs).
		if _, err := os.Stat(darwinInstallPath); err == nil {
			fmt.Printf("Removing %s...\n", darwinInstallPath)
			if err := os.Remove(darwinInstallPath); err != nil {
				return fmt.Errorf("failed to remove binary: %w", err)
			}
		}
	}

	fmt.Println("CFGMS Steward uninstalled.")
	return nil
}

// Status returns the current state of the launchd daemon without requiring
// elevated privileges.
func (m *darwinManager) Status() (*ServiceStatus, error) {
	status := &ServiceStatus{
		ServiceName: darwinServiceName,
		InstallPath: darwinLauncherPath,
	}

	// Installed if the plist exists.
	if _, err := os.Stat(darwinPlistPath); err == nil {
		status.Installed = true
	}

	// Check if running via launchctl list.
	out, err := exec.Command("launchctl", "list", darwinServiceName).Output()
	if err == nil && !strings.Contains(string(out), "Could not find service") {
		status.Running = true
	}

	return status, nil
}

// generateLaunchdPlist returns a macOS launchd plist for the steward daemon.
// When controllerURL is non-empty, --controller-url is appended to childArgs.
// The launcher supervises the steward and forwards --child-args to it.
// KeepAlive ensures the daemon restarts on exit; RunAtLoad starts it immediately.
//
// Security note: the token appears in the plist (readable by root only for
// LaunchDaemons). The token is a one-time registration credential — after
// first registration the steward authenticates via mTLS certificates.
func generateLaunchdPlist(token, controllerURL string) string {
	// The launcher supervises the steward and forwards --child-args to it. Args
	// are space-separated (the launcher splits on whitespace); the registration
	// token is validated to be free of spaces/quotes, so no per-arg quoting is
	// needed inside the child-args string.
	childArgs := fmt.Sprintf(`--regtoken %s`, token)
	if controllerURL != "" {
		childArgs += fmt.Sprintf(` --controller-url %s`, controllerURL)
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>run</string>
    <string>--root</string>
    <string>%s</string>
    <string>--child-args</string>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>EnvironmentVariables</key>
  <dict>
    <key>CFGMS_LOG_DIR</key>
    <string>/usr/local/var/log/cfgms</string>
    <key>CFGMS_SECURITY_PROFILE</key>
    <string>public-beta</string>
  </dict>
  <key>StandardOutPath</key>
  <string>/var/log/cfgms-steward.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/cfgms-steward.log</string>
</dict>
</plist>
`, darwinServiceName, darwinLauncherPath, darwinLauncherRoot, childArgs)
}
