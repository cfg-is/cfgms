// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package interfaces_test contains protocol-agnostic contract tests for the Gate interface.
//
// # Usage by Gate Implementors
//
// Call RunGateContractTests from within a test in this package, providing a factory
// that constructs the three fixture gates. See TestGate_StewardContractSuite below
// for the reference implementation.
package interfaces_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	maintinterfaces "github.com/cfgis/cfgms/pkg/maintenance/interfaces"
	stewardgate "github.com/cfgis/cfgms/pkg/maintenance/providers/steward"
	maintenanceschedule "github.com/cfgis/cfgms/pkg/maintenance/schedule"
)

// GateContractFixture carries the three Gate instances the contract suite needs.
type GateContractFixture struct {
	// Ungated is a Gate with no reboot_window declared. CanReboot must always return true.
	Ungated maintinterfaces.Gate

	// InsideWindow is a Gate whose internal clock is set to a moment inside the
	// declared reboot_window. CanReboot must return true.
	InsideWindow maintinterfaces.Gate

	// OutsideWindow is a Gate whose internal clock is set to a moment outside the
	// declared reboot_window. CanReboot must return false and NextWindow must return
	// a non-zero future time.
	OutsideWindow maintinterfaces.Gate
}

// GateFixtureFactory creates a GateContractFixture for the contract suite.
type GateFixtureFactory func(t *testing.T) GateContractFixture

// RunGateContractTests runs the full Gate interface contract suite.
func RunGateContractTests(t *testing.T, factory GateFixtureFactory) {
	t.Helper()
	const deviceID = "contract-device-0"

	fix := factory(t)

	t.Run("UngatedAlwaysCanReboot", func(t *testing.T) {
		can, err := fix.Ungated.CanReboot(context.Background(), deviceID)
		require.NoError(t, err)
		assert.True(t, can,
			"device with no declared reboot_window must always return CanReboot=true")
	})

	t.Run("UngatedNextWindowIsZero", func(t *testing.T) {
		next, err := fix.Ungated.NextWindow(context.Background(), deviceID)
		require.NoError(t, err)
		assert.True(t, next.IsZero(),
			"ungated device has no window to report; NextWindow must return zero time")
	})

	t.Run("WindowedInsideCanReboot", func(t *testing.T) {
		can, err := fix.InsideWindow.CanReboot(context.Background(), deviceID)
		require.NoError(t, err)
		assert.True(t, can,
			"current time inside declared window must return CanReboot=true")
	})

	t.Run("WindowedOutsideCannotReboot", func(t *testing.T) {
		can, err := fix.OutsideWindow.CanReboot(context.Background(), deviceID)
		require.NoError(t, err)
		assert.False(t, can,
			"current time outside declared window must return CanReboot=false")
	})

	t.Run("WindowedOutsideNextWindowIsNonZero", func(t *testing.T) {
		next, err := fix.OutsideWindow.NextWindow(context.Background(), deviceID)
		require.NoError(t, err)
		assert.False(t, next.IsZero(),
			"gate outside window must report a non-zero next-window time")
	})

	t.Run("ContextCancellationNoPanic", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		// Must not panic — implementations may ignore the cancelled ctx for cheap in-memory checks.
		assert.NotPanics(t, func() {
			_, _ = fix.Ungated.CanReboot(ctx, deviceID)
		})
	})
}

// =============================================================================
// Top-level test: run full suite against the steward Gate implementation
// =============================================================================

// weeklyMondayWindowCfg returns a Config with a single weekly window: Monday 02:00–04:00 UTC.
func weeklyMondayWindowCfg() *maintenanceschedule.Config {
	return &maintenanceschedule.Config{
		Timezone: "UTC",
		Schedules: []maintenanceschedule.Schedule{
			{
				Freq:  maintenanceschedule.FreqWeekly,
				Days:  []time.Weekday{time.Monday},
				Start: maintenanceschedule.TimeOfDay{Hour: 2, Minute: 0},
				End:   maintenanceschedule.TimeOfDay{Hour: 4, Minute: 0},
			},
		},
	}
}

// monday3amUTC is inside the weeklyMondayWindow (Mon 03:00 UTC).
var monday3amUTC = time.Date(2026, time.January, 5, 3, 0, 0, 0, time.UTC)

// tuesday3amUTC is outside the weeklyMondayWindow (Tue 03:00 UTC).
var tuesday3amUTC = time.Date(2026, time.January, 6, 3, 0, 0, 0, time.UTC)

// TestGate_StewardContractSuite runs all Gate contract tests against the steward
// Gate implementation.
func TestGate_StewardContractSuite(t *testing.T) {
	RunGateContractTests(t, func(t *testing.T) GateContractFixture {
		t.Helper()

		ungated, err := stewardgate.New(stewardgate.Config{
			Window:   nil,
			Timezone: "UTC",
			DeviceID: "contract-device-0",
			Now:      func() time.Time { return tuesday3amUTC },
		})
		require.NoError(t, err)

		inside, err := stewardgate.New(stewardgate.Config{
			Window:   weeklyMondayWindowCfg(),
			Timezone: "UTC",
			DeviceID: "contract-device-0",
			Now:      func() time.Time { return monday3amUTC },
		})
		require.NoError(t, err)

		outside, err := stewardgate.New(stewardgate.Config{
			Window:   weeklyMondayWindowCfg(),
			Timezone: "UTC",
			DeviceID: "contract-device-0",
			Now:      func() time.Time { return tuesday3amUTC },
		})
		require.NoError(t, err)

		return GateContractFixture{
			Ungated:       ungated,
			InsideWindow:  inside,
			OutsideWindow: outside,
		}
	})
}
