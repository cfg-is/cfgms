// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package interfaces defines the pluggable maintenance gate abstraction for CFGMS.
//
// The gate is the central reboot-gating primitive: any module that can trigger a
// host reboot consults the gate before doing so (ADR-026 decision 6). The interface
// is deviceID-scoped so a single implementation can serve a fleet without keeping
// per-device state inside the gate itself.
package interfaces

import (
	"context"
	"time"
)

// Gate is the pluggable interface any reboot-capable module consults before
// triggering a host reboot.
//
// ADR-026 decision 6 is explicit: there is no emergency-override method on
// this interface. No ForceReboot or similar escape hatch exists on the
// declarative path.
type Gate interface {
	// CanReboot reports whether deviceID may reboot at the current instant.
	// Returns true when no reboot_window is declared (ungated — correct, not
	// fail-open), and false when the current time falls outside the window.
	CanReboot(ctx context.Context, deviceID string) (bool, error)

	// NextWindow returns the next instant at which deviceID may reboot.
	// Returns a zero time.Time when no window is declared (ungated devices
	// may reboot at any time; there is no "next" window to report).
	NextWindow(ctx context.Context, deviceID string) (time.Time, error)
}
