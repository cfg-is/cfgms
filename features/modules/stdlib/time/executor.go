// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package timemodule

// timeState holds the observed current time configuration of the host.
type timeState struct {
	// Timezone is the IANA timezone identifier (e.g. "UTC", "America/Chicago").
	Timezone string
	// NTPServers is the list of NTP server addresses, always sorted for determinism.
	NTPServers []string
	// NTPSyncEnabled indicates whether automatic NTP synchronisation is configured.
	NTPSyncEnabled bool
}

// timeExecutor is the platform-specific backend for host time configuration.
// Each platform (Linux, Windows, macOS) provides its own implementation via
// build tags. Unsupported platforms use the stub implementation that returns
// ErrUnsupportedPlatform.
type timeExecutor interface {
	// getState returns the current timezone and NTP configuration of the host.
	// NTPServers in the returned state are always sorted for determinism.
	getState() (timeState, error)

	// setState applies the desired timezone and NTP configuration. It is
	// idempotent: calling setState when the host is already in the desired
	// state is a no-op.
	setState(desired timeState) error
}
