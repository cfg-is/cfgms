// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	darwinInstallPath = "/usr/local/bin/cfgms-controller"
	darwinPlistPath   = "/Library/LaunchDaemons/com.cfgms.controller.plist"
	darwinServiceName = "com.cfgms.controller"
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
func (m *darwinManager) Install(configPath string) error {
	if err := validateConfigPath(configPath); err != nil {
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
	plist := generateLaunchdPlist(configPath)
	if err := os.WriteFile(darwinPlistPath, []byte(plist), 0644); err != nil {
		return fmt.Errorf("failed to write plist %s: %w", darwinPlistPath, err)
	}

	fmt.Println("Loading launchd daemon...")
	if out, err := exec.Command("launchctl", "load", darwinPlistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl load failed: %w\n%s", err, out)
	}

	fmt.Printf("\nDone. CFGMS Controller installed and running.\n")
	fmt.Printf("  Service name: %s\n", darwinServiceName)
	fmt.Printf("  Config:  %s\n", configPath)
	fmt.Printf("  Status:  cfgms-controller status\n")
	fmt.Printf("  Remove:  cfgms-controller uninstall\n")
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

	fmt.Println("CFGMS Controller uninstalled.")
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
	plistContent, err := os.ReadFile(darwinPlistPath)
	if err == nil {
		status.Installed = true
		status.ConfigPath = configPathFromPlist(string(plistContent))
	}

	// Check if running via launchctl list.
	out, err := exec.Command("launchctl", "list", darwinServiceName).Output()
	if err == nil && !strings.Contains(string(out), "Could not find service") {
		status.Running = true
	}

	return status, nil
}

// generateLaunchdPlist returns a macOS launchd plist for the controller daemon.
// KeepAlive ensures the daemon restarts on exit; RunAtLoad starts it immediately.
func generateLaunchdPlist(configPath string) string {
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
    <string>--config</string>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/cfgms-controller.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/cfgms-controller.log</string>
</dict>
</plist>
`, darwinServiceName, darwinInstallPath, configPath)
}

// configPathFromPlist extracts the --config argument from a launchd plist.
// Returns an empty string if the argument cannot be found.
func configPathFromPlist(content string) string {
	idx := strings.Index(content, "<string>--config</string>")
	if idx == -1 {
		return ""
	}
	rest := content[idx+len("<string>--config</string>"):]
	start := strings.Index(rest, "<string>")
	if start == -1 {
		return ""
	}
	rest = rest[start+len("<string>"):]
	end := strings.Index(rest, "</string>")
	if end == -1 {
		return ""
	}
	return rest[:end]
}
