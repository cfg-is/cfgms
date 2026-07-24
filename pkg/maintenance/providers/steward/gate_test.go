// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package steward_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stewardgate "github.com/cfgis/cfgms/pkg/maintenance/providers/steward"
	maintenanceschedule "github.com/cfgis/cfgms/pkg/maintenance/schedule"
)

// weeklyMondayWindow returns a schedule.Config with a single weekly window:
// Monday 02:00–04:00 UTC.
func weeklyMondayWindow() *maintenanceschedule.Config {
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

// monday3am is a time known to be inside the weeklyMondayWindow (Mon 03:00 UTC).
var monday3am = time.Date(2026, time.January, 5, 3, 0, 0, 0, time.UTC)

// tuesday3am is a time known to be outside the weeklyMondayWindow (Tue 03:00 UTC).
var tuesday3am = time.Date(2026, time.January, 6, 3, 0, 0, 0, time.UTC)

func TestNew_InvalidTimezone(t *testing.T) {
	_, err := stewardgate.New(stewardgate.Config{
		Window:   weeklyMondayWindow(),
		Timezone: "Not/A/Real/Zone",
		DeviceID: "test-device",
		Now:      func() time.Time { return tuesday3am },
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timezone")
}

func TestNew_DeviceTimezoneUsesLocal(t *testing.T) {
	g, err := stewardgate.New(stewardgate.Config{
		Window:   weeklyMondayWindow(),
		Timezone: "device",
		DeviceID: "test-device",
		Now:      func() time.Time { return time.Now() },
	})
	require.NoError(t, err)
	assert.NotNil(t, g)
}

func TestNew_EmptyTimezoneUsesLocal(t *testing.T) {
	g, err := stewardgate.New(stewardgate.Config{
		Window:   weeklyMondayWindow(),
		Timezone: "",
		DeviceID: "test-device",
		Now:      func() time.Time { return time.Now() },
	})
	require.NoError(t, err)
	assert.NotNil(t, g)
}

func TestCanReboot_NilConfig_ReturnsTrue(t *testing.T) {
	g, err := stewardgate.New(stewardgate.Config{
		Window:   nil,
		Timezone: "UTC",
		DeviceID: "test-device",
		Now:      func() time.Time { return tuesday3am },
	})
	require.NoError(t, err)

	can, err := g.CanReboot(context.Background(), "test-device")
	require.NoError(t, err)
	assert.True(t, can, "nil window config must return CanReboot=true (ungated)")
}

func TestCanReboot_EmptySchedules_ReturnsTrue(t *testing.T) {
	g, err := stewardgate.New(stewardgate.Config{
		Window:   &maintenanceschedule.Config{Timezone: "UTC", Schedules: nil},
		Timezone: "UTC",
		DeviceID: "test-device",
		Now:      func() time.Time { return tuesday3am },
	})
	require.NoError(t, err)

	can, err := g.CanReboot(context.Background(), "test-device")
	require.NoError(t, err)
	assert.True(t, can, "empty Schedules list must return CanReboot=true (ungated)")
}

func TestCanReboot_InsideWindow_ReturnsTrue(t *testing.T) {
	g, err := stewardgate.New(stewardgate.Config{
		Window:   weeklyMondayWindow(),
		Timezone: "UTC",
		DeviceID: "test-device",
		Now:      func() time.Time { return monday3am },
	})
	require.NoError(t, err)

	can, err := g.CanReboot(context.Background(), "test-device")
	require.NoError(t, err)
	assert.True(t, can, "time inside window must return CanReboot=true")
}

func TestCanReboot_OutsideWindow_ReturnsFalse(t *testing.T) {
	g, err := stewardgate.New(stewardgate.Config{
		Window:   weeklyMondayWindow(),
		Timezone: "UTC",
		DeviceID: "test-device",
		Now:      func() time.Time { return tuesday3am },
	})
	require.NoError(t, err)

	can, err := g.CanReboot(context.Background(), "test-device")
	require.NoError(t, err)
	assert.False(t, can, "time outside window must return CanReboot=false")
}

func TestNextWindow_NilConfig_ReturnsZero(t *testing.T) {
	g, err := stewardgate.New(stewardgate.Config{
		Window:   nil,
		Timezone: "UTC",
		DeviceID: "test-device",
		Now:      func() time.Time { return tuesday3am },
	})
	require.NoError(t, err)

	next, err := g.NextWindow(context.Background(), "test-device")
	require.NoError(t, err)
	assert.True(t, next.IsZero(), "nil window config must return zero NextWindow (ungated)")
}

func TestNextWindow_OutsideWindow_ReturnsNextMonday(t *testing.T) {
	g, err := stewardgate.New(stewardgate.Config{
		Window:   weeklyMondayWindow(),
		Timezone: "UTC",
		DeviceID: "test-device",
		Now:      func() time.Time { return tuesday3am },
	})
	require.NoError(t, err)

	next, err := g.NextWindow(context.Background(), "test-device")
	require.NoError(t, err)
	assert.False(t, next.IsZero(), "outside window must return non-zero next window")
	// tuesday3am is 2026-01-06: next window should be the following Monday 2026-01-12 02:00 UTC.
	expected := time.Date(2026, time.January, 12, 2, 0, 0, 0, time.UTC)
	assert.Equal(t, expected, next, "NextWindow must return the start of the next weekly window")
}

func TestNextWindow_MultipleSchedules_ReturnsEarliest(t *testing.T) {
	cfg := &maintenanceschedule.Config{
		Timezone: "UTC",
		Schedules: []maintenanceschedule.Schedule{
			{
				// Monday 02:00-04:00
				Freq:  maintenanceschedule.FreqWeekly,
				Days:  []time.Weekday{time.Monday},
				Start: maintenanceschedule.TimeOfDay{Hour: 2, Minute: 0},
				End:   maintenanceschedule.TimeOfDay{Hour: 4, Minute: 0},
			},
			{
				// Wednesday 02:00-04:00
				Freq:  maintenanceschedule.FreqWeekly,
				Days:  []time.Weekday{time.Wednesday},
				Start: maintenanceschedule.TimeOfDay{Hour: 2, Minute: 0},
				End:   maintenanceschedule.TimeOfDay{Hour: 4, Minute: 0},
			},
		},
	}

	// tuesday3am is 2026-01-06: next window across both schedules is Wed 2026-01-07 02:00 UTC
	// (before Monday 2026-01-12 02:00 UTC).
	g, err := stewardgate.New(stewardgate.Config{
		Window:   cfg,
		Timezone: "UTC",
		DeviceID: "test-device",
		Now:      func() time.Time { return tuesday3am },
	})
	require.NoError(t, err)

	next, err := g.NextWindow(context.Background(), "test-device")
	require.NoError(t, err)
	expected := time.Date(2026, time.January, 7, 2, 0, 0, 0, time.UTC) // Wednesday
	assert.Equal(t, expected, next, "NextWindow must return the earliest across multiple schedules")
}
