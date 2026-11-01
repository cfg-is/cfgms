// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package hostname

// hostnameState holds the observed current identity configuration of the host.
type hostnameState struct {
	// Hostname is the system/computer name of the host.
	Hostname string
	// Workgroup is the Windows workgroup name. Empty on Linux and macOS.
	Workgroup string
}

// hostnameExecutor is the platform-specific backend for host identity configuration.
// Each platform (Linux, Windows, macOS) provides its own implementation via
// build tags. Unsupported platforms use the stub implementation that returns
// ErrUnsupportedPlatform.
type hostnameExecutor interface {
	// getState returns the current hostname (and workgroup on Windows) of the host.
	getState() (hostnameState, error)

	// setState applies the desired hostname (and workgroup on Windows). It is
	// idempotent: calling setState when the host is already in the desired
	// state is a no-op.
	setState(desired hostnameState) error
}
