// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build darwin

package service

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

const (
	darwinInstallPath = "/usr/local/bin/cfgms-steward"
	darwinPlistPath   = "/Library/LaunchDaemons/com.cfgms.steward.plist"
	darwinServiceName = "com.cfgms.steward"
)

func newManager(binaryPath string) Manager {
	return &darwinManager{binaryPath: binaryPath}
}

type darwinManager struct {
	binaryPath string
}

func (m *darwinManager) InstallPath() string { return darwinInstallPath }

func (m *darwinManager) IsElevated() bool {
	return os.Getuid() == 0
}

// Install copies the binary to /usr/local/bin, writes the launchd plist, and
// loads it via launchctl. If already installed, the existing daemon is unloaded
// first, the binary replaced, then reloaded.
func (m *darwinManager) Install(token string) error {
	if err := validateToken(token); err != nil {
		return err
	}
	if !m.IsElevated() {
		return fmt.Errorf("install requires root privileges: re-run with sudo")
	}

	// Unload existing daemon if present (idempotent — ignore failure).
	if _, err := os.Stat(darwinPlistPath); err == nil {
		fmt.Println("Unloading existing daemon...")
		_ = exec.Command("launchctl", "unload", darwinPlistPath).Run()
	}

	fmt.Printf("Installing to %s...\n", darwinInstallPath)
	if err := copyBinary(m.binaryPath, darwinInstallPath); err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}

	fmt.Println("Writing launchd plist...")
	plist := generateLaunchdPlist(token)
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
// installed binary is also removed.
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
		InstallPath: darwinInstallPath,
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
// KeepAlive ensures the daemon restarts on exit; RunAtLoad starts it immediately.
//
// Security note: the token appears in the plist (readable by root only for
// LaunchDaemons). The token is a one-time registration credential — after
// first registration the steward authenticates via mTLS certificates.
func generateLaunchdPlist(token string) string {
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
    <string>--regtoken</string>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/cfgms-steward.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/cfgms-steward.log</string>
</dict>
</plist>
`, darwinServiceName, darwinInstallPath, token)
}

// copyBinary copies src to dst atomically using a temp file.
func copyBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

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
