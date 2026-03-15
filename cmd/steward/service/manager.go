// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// Package service provides OS service management for the cfgms-steward binary.
// It supports Linux (systemd), Windows (native service API), and macOS (launchd).
//
// Platform-specific implementations are separated by build tags:
//   - manager_linux.go (//go:build linux)
//   - manager_windows.go (//go:build windows)
//   - manager_darwin.go (//go:build darwin)
//   - manager_stub.go (//go:build !linux && !windows && !darwin)
package service

// ServiceStatus describes the current observed state of the steward OS service.
type ServiceStatus struct {
	// Installed is true if the service has been registered with the OS.
	Installed bool
	// Running is true if the service is currently active/running.
	Running bool
	// ServiceName is the OS-level service identifier.
	ServiceName string
	// InstallPath is the path where the binary is installed.
	InstallPath string
}

// Manager manages the steward OS service lifecycle.
// Each platform provides its own implementation via the newManager factory.
type Manager interface {
	// Install copies the binary to the platform-standard location and registers
	// the OS service configured to start automatically with --regtoken token.
	// Install is idempotent: if the service already exists it is stopped, the
	// binary replaced, and the service restarted.
	// Requires elevated privileges (root on Linux/macOS, Administrator on Windows).
	Install(token string) error

	// Uninstall stops and removes the OS service definition.
	// If purge is true the installed binary is also deleted.
	// Requires elevated privileges.
	Uninstall(purge bool) error

	// Status returns the current state of the OS service.
	// Does not require elevated privileges.
	Status() (*ServiceStatus, error)

	// IsElevated returns true if the current process has the privileges
	// required to install or uninstall the service.
	IsElevated() bool

	// InstallPath returns the platform-standard path the binary will be
	// copied to during Install.
	InstallPath() string
}

// New returns the platform-specific Manager for the current OS.
// binaryPath should be the path returned by os.Executable().
func New(binaryPath string) Manager {
	return newManager(binaryPath)
}
