// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package steward provides the steward-side reboot Gate backed by the resolved
// reboot_window from the steward's synced configuration (ADR-026 story 3).
package steward

import (
	"context"
	"fmt"
	"time"

	maintinterfaces "github.com/cfgis/cfgms/pkg/maintenance/interfaces"
	maintenanceschedule "github.com/cfgis/cfgms/pkg/maintenance/schedule"
)

// Gate is the steward-side reboot gate. It is constructed from the resolved
// reboot_window config that the steward received in its synced StewardConfig
// and is consulted by any module that can trigger a host reboot (ADR-026 §6).
//
// A nil or empty Schedules list means no window is declared: CanReboot returns
// true unconditionally and NextWindow returns a zero time. This is the correct
// behavior for a device that never declared a window — it is not the fail-open
// bug; it is the intended ungated behavior.
type Gate struct {
	cfg      *maintenanceschedule.Config
	loc      *time.Location
	deviceID string
	now      func() time.Time
}

// Compile-time check: *Gate implements maintinterfaces.Gate.
var _ maintinterfaces.Gate = (*Gate)(nil)

// Config carries the constructor parameters for a steward Gate.
type Config struct {
	// Window is the resolved reboot_window config from StewardConfig.Steward.RebootWindow.
	// A nil pointer or empty Schedules means no window is declared (ungated).
	Window *maintenanceschedule.Config

	// Timezone is the resolved IANA timezone name for the window, as returned by
	// pkg/config.ResolveRebootWindowTimezone. An empty string or "device" both mean
	// "use the host's local zone" — the gate substitutes time.Local in both cases.
	Timezone string

	// DeviceID is the steward's own registered identity (cfg.Steward.ID). Used as
	// the lookup key for CanReboot/NextWindow — the steward gate is device-scoped.
	DeviceID string

	// Now, when non-nil, overrides the host clock. Used in tests to pin the current
	// time without modifying global state. Leave nil in production.
	Now func() time.Time
}

// New constructs a steward-side Gate from the provided Config.
// Returns an error only when Timezone is a non-empty, non-"device" string that
// cannot be resolved to an IANA location.
func New(cfg Config) (*Gate, error) {
	loc, err := resolveLocation(cfg.Timezone)
	if err != nil {
		return nil, fmt.Errorf("maintenance gate: %w", err)
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	return &Gate{
		cfg:      cfg.Window,
		loc:      loc,
		deviceID: cfg.DeviceID,
		now:      now,
	}, nil
}

// CanReboot reports whether the gate's device may reboot at the current instant.
//
// When no reboot_window is declared (nil config or empty Schedules), returns true:
// the device is ungated and may always reboot. This is correct behavior, not the
// fail-open bug — a device that never declared a window has nothing to gate against.
//
// The deviceID parameter is accepted for interface compliance and future multi-device
// gate implementations; this single-device gate only serves its own device.
func (g *Gate) CanReboot(_ context.Context, _ string) (bool, error) {
	if g.cfg == nil || len(g.cfg.Schedules) == 0 {
		return true, nil
	}

	now := g.now().In(g.loc)
	for _, s := range g.cfg.Schedules {
		if maintenanceschedule.InWindow(now, s) {
			return true, nil
		}
	}
	return false, nil
}

// NextWindow returns the next instant at which the gate's device may reboot.
//
// Returns a zero time.Time when no window is declared (ungated devices may reboot
// at any time; there is no "next" window to report).
//
// When multiple schedules are declared, returns the earliest upcoming window start
// across all of them.
func (g *Gate) NextWindow(_ context.Context, _ string) (time.Time, error) {
	if g.cfg == nil || len(g.cfg.Schedules) == 0 {
		return time.Time{}, nil
	}

	now := g.now().In(g.loc)
	var earliest time.Time
	for _, s := range g.cfg.Schedules {
		next := maintenanceschedule.NextOccurrence(now, s)
		if next.IsZero() {
			continue
		}
		if earliest.IsZero() || next.Before(earliest) {
			earliest = next
		}
	}
	return earliest, nil
}

// resolveLocation converts a resolved timezone string into a *time.Location.
// An empty string or "device" both map to time.Local (the host's own zone).
// Any other non-empty string is loaded via time.LoadLocation.
func resolveLocation(tz string) (*time.Location, error) {
	if tz == "" || tz == "device" {
		return time.Local, nil
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return nil, fmt.Errorf("cannot load timezone %q: %w", tz, err)
	}
	return loc, nil
}
