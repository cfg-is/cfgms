// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	windowsInstallDir  = `C:\Program Files\CFGMS`
	windowsInstallPath = `C:\Program Files\CFGMS\cfgms-steward.exe`
	windowsServiceName = "CFGMSSteward"
	windowsDisplayName = "CFGMS Steward"
	windowsDescription = "CFGMS endpoint configuration management agent"
)

func newManager(binaryPath string) Manager {
	return &windowsManager{binaryPath: binaryPath}
}

type windowsManager struct {
	binaryPath string
}

func (m *windowsManager) InstallPath() string { return windowsInstallPath }

// IsElevated returns true if the current process has Administrator privileges.
// It checks by attempting to open the service control manager, which requires
// Administrator — the canonical check without additional packages.
func (m *windowsManager) IsElevated() bool {
	scm, err := mgr.Connect()
	if err != nil {
		return false
	}
	scm.Disconnect()
	return true
}

// Install copies the binary to C:\Program Files\CFGMS\, creates a Windows
// service configured to start automatically with failure-restart recovery,
// and starts it. If the service already exists it is stopped, the binary
// replaced, and the service restarted.
//
// Uses the native Windows Service API via golang.org/x/sys/windows/svc/mgr.
// Does NOT shell out to sc.exe.
func (m *windowsManager) Install(token string) error {
	if err := validateToken(token); err != nil {
		return err
	}
	if !m.IsElevated() {
		return fmt.Errorf("install requires Administrator privileges: right-click the binary and select 'Run as administrator'")
	}

	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows Service Control Manager: %w", err)
	}
	defer scm.Disconnect()

	// Stop and delete existing service to allow binary replacement (idempotent).
	if existing, err := scm.OpenService(windowsServiceName); err == nil {
		fmt.Println("Stopping existing service...")
		_, _ = existing.Control(svc.Stop)
		// Allow the service process to exit before replacing the binary.
		time.Sleep(2 * time.Second)
		fmt.Println("Removing existing service definition...")
		if err := existing.Delete(); err != nil {
			existing.Close()
			return fmt.Errorf("failed to delete existing service: %w", err)
		}
		existing.Close()
	}

	// Create install directory.
	if err := os.MkdirAll(windowsInstallDir, 0755); err != nil {
		return fmt.Errorf("failed to create install directory %s: %w", windowsInstallDir, err)
	}

	fmt.Printf("Installing to %s...\n", windowsInstallPath)
	if err := copyBinary(m.binaryPath, windowsInstallPath); err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}

	fmt.Println("Registering Windows service...")
	newSvc, err := scm.CreateService(
		windowsServiceName,
		windowsInstallPath,
		mgr.Config{
			StartType:   mgr.StartAutomatic,
			DisplayName: windowsDisplayName,
			Description: windowsDescription,
		},
		// Arguments appended to the binary path; received as os.Args on service start.
		"--regtoken", token,
	)
	if err != nil {
		return fmt.Errorf("failed to create Windows service: %w", err)
	}
	defer newSvc.Close()

	// Configure automatic restart on failure (3 escalating delays, 1-day reset).
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}
	if err := newSvc.SetRecoveryActions(recoveryActions, 86400); err != nil {
		// Non-fatal: service still works without recovery options.
		fmt.Printf("Warning: could not set service recovery options: %v\n", err)
	}

	fmt.Println("Starting service...")
	if err := newSvc.Start(); err != nil {
		return fmt.Errorf("failed to start Windows service: %w", err)
	}

	fmt.Printf("\nDone. CFGMS Steward installed and running.\n")
	fmt.Printf("  Service name: %s\n", windowsServiceName)
	fmt.Printf("  Status:  cfgms-steward status\n")
	fmt.Printf("  Remove:  cfgms-steward uninstall\n")
	return nil
}

// Uninstall stops and removes the Windows service. If purge is true the
// installed binary at windowsInstallPath is also deleted.
func (m *windowsManager) Uninstall(purge bool) error {
	if !m.IsElevated() {
		return fmt.Errorf("uninstall requires Administrator privileges: right-click the binary and select 'Run as administrator'")
	}

	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows Service Control Manager: %w", err)
	}
	defer scm.Disconnect()

	existing, err := scm.OpenService(windowsServiceName)
	if err != nil {
		fmt.Println("Service not registered — nothing to remove.")
	} else {
		fmt.Println("Stopping service...")
		_, _ = existing.Control(svc.Stop)
		time.Sleep(2 * time.Second)

		fmt.Println("Removing service definition...")
		if err := existing.Delete(); err != nil {
			existing.Close()
			return fmt.Errorf("failed to delete service: %w", err)
		}
		existing.Close()
	}

	if purge {
		if _, err := os.Stat(windowsInstallPath); err == nil {
			fmt.Printf("Removing %s...\n", windowsInstallPath)
			if err := os.Remove(windowsInstallPath); err != nil {
				return fmt.Errorf("failed to remove binary: %w", err)
			}
		}
	}

	fmt.Println("CFGMS Steward uninstalled.")
	return nil
}

// Status returns the current service state without requiring elevated privileges.
func (m *windowsManager) Status() (*ServiceStatus, error) {
	status := &ServiceStatus{
		ServiceName: windowsServiceName,
		InstallPath: windowsInstallPath,
	}

	scm, err := mgr.Connect()
	if err != nil {
		// Cannot connect to SCM — report not installed.
		return status, nil
	}
	defer scm.Disconnect()

	existing, err := scm.OpenService(windowsServiceName)
	if err != nil {
		// Service not registered.
		return status, nil
	}
	defer existing.Close()

	status.Installed = true

	q, err := existing.Query()
	if err != nil {
		return status, nil
	}
	status.Running = q.State == svc.Running

	return status, nil
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
