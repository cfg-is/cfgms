// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package service

// serviceState holds the observed current state of an OS service.
type serviceState struct {
	Running bool
	Enabled bool
}

// serviceExecutor is the platform-specific backend for OS service operations.
// Each platform (Linux, Windows, macOS) provides its own implementation via
// build tags. Unsupported platforms use the stub implementation that returns
// ErrUnsupportedPlatform.
type serviceExecutor interface {
	// getState returns the current running and enabled state of the named service.
	// If the service does not exist on the system, it returns (false, false, nil).
	getState(name string) (serviceState, error)

	// setState applies the desired running state and boot-enable configuration
	// to the named service. It is idempotent: calling setState when the service
	// is already in the desired state is a no-op.
	setState(name string, desiredRunning bool, desiredEnabled bool) error
}
