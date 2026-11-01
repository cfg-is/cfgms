// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package patch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	stewardgate "github.com/cfgis/cfgms/pkg/maintenance/providers/steward"
	maintenanceschedule "github.com/cfgis/cfgms/pkg/maintenance/schedule"
)

// weeklyMondayWindowCfgForPatch returns a Config with a weekly window: Monday 02:00–04:00 UTC.
func weeklyMondayWindowCfgForPatch() *maintenanceschedule.Config {
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

// insideWindowTime is a Monday at 03:00 UTC — inside the window.
var insideWindowTime = time.Date(2026, time.January, 5, 3, 0, 0, 0, time.UTC)

// outsideWindowTime is a Tuesday at 03:00 UTC — outside the window.
var outsideWindowTime = time.Date(2026, time.January, 6, 3, 0, 0, 0, time.UTC)

// patchCfgWithWindow returns a Config whose maintenance.window field is set.
// A non-empty maintenance.window causes Set() to consult the window manager.
func patchCfgWithWindow() *Config {
	return &Config{
		PatchType: "security",
		TestMode:  true,
		Maintenance: struct {
			Window   string        `yaml:"window"`
			Schedule string        `yaml:"schedule"`
			Duration time.Duration `yaml:"duration"`
			Timezone string        `yaml:"timezone"`
		}{
			Window: "weekly_monday_2am",
		},
	}
}

// TestGateWindowAdapter_OutsideWindow_DeniesSet verifies that a patch Set call
// is denied when the current time falls outside the declared reboot_window.
// This test uses the real GateWindowAdapter (not the test-only InMemoryWindowManager).
func TestGateWindowAdapter_OutsideWindow_DeniesSet(t *testing.T) {
	gate, err := stewardgate.New(stewardgate.Config{
		Window:   weeklyMondayWindowCfgForPatch(),
		Timezone: "UTC",
		DeviceID: "test-steward",
		Now:      func() time.Time { return outsideWindowTime },
	})
	require.NoError(t, err)

	m, err := NewPatchModule(NewInMemoryPatchManager())
	require.NoError(t, err)
	m.SetWindowManager(NewGateWindowAdapter(gate, "test-steward"))
	m.SetDeviceID("test-steward")

	setErr := m.Set(context.Background(), "system", patchCfgWithWindow())
	require.Error(t, setErr, "Set must fail when outside the reboot_window")
	assert.ErrorIs(t, setErr, ErrMaintenanceWindowNotActive,
		"denied Set must surface ErrMaintenanceWindowNotActive")
}

// TestGateWindowAdapter_InsideWindow_AllowsSet verifies that a patch Set call
// proceeds when the current time falls inside the declared reboot_window.
// This test uses the real GateWindowAdapter (not the test-only InMemoryWindowManager).
func TestGateWindowAdapter_InsideWindow_AllowsSet(t *testing.T) {
	gate, err := stewardgate.New(stewardgate.Config{
		Window:   weeklyMondayWindowCfgForPatch(),
		Timezone: "UTC",
		DeviceID: "test-steward",
		Now:      func() time.Time { return insideWindowTime },
	})
	require.NoError(t, err)

	m, err := NewPatchModule(NewInMemoryPatchManager())
	require.NoError(t, err)
	m.SetWindowManager(NewGateWindowAdapter(gate, "test-steward"))
	m.SetDeviceID("test-steward")

	setErr := m.Set(context.Background(), "system", patchCfgWithWindow())
	// Inside window: the window check passes. The InMemoryPatchManager uses TestMode=true
	// so InstallPatches does not mutate state, reboot is not required, and Set succeeds.
	assert.NoError(t, setErr, "Set must succeed when inside the reboot_window")
}

// TestGateWindowAdapter_OutsideWindow_ReturnsStatusDeferred verifies that a Set
// call denied by the window returns a *modules.RebootDeferredError so the executor
// classifies the resource as StatusDeferred (not StatusFailed). The NextWindow
// field must be non-zero because the Gate can compute the next Monday 02:00 window.
func TestGateWindowAdapter_OutsideWindow_ReturnsStatusDeferred(t *testing.T) {
	gate, err := stewardgate.New(stewardgate.Config{
		Window:   weeklyMondayWindowCfgForPatch(),
		Timezone: "UTC",
		DeviceID: "test-steward",
		Now:      func() time.Time { return outsideWindowTime },
	})
	require.NoError(t, err)

	m, err := NewPatchModule(NewInMemoryPatchManager())
	require.NoError(t, err)
	m.SetWindowManager(NewGateWindowAdapter(gate, "test-steward"))
	m.SetDeviceID("test-steward")

	setErr := m.Set(context.Background(), "system", patchCfgWithWindow())
	require.Error(t, setErr)

	var re *modules.RebootDeferredError
	assert.True(t, errors.As(setErr, &re),
		"denied Set must wrap *modules.RebootDeferredError for StatusDeferred classification")
	assert.False(t, re.NextWindow.IsZero(),
		"NextWindow must be populated when the Gate can compute the next window")
}

// TestGateWindowAdapter_NilManager_DeniesSet verifies that Set is denied (fail-closed)
// when no window manager is configured and the config declares a maintenance.window.
func TestGateWindowAdapter_NilManager_DeniesSet(t *testing.T) {
	m, err := NewPatchModule(NewInMemoryPatchManager())
	require.NoError(t, err)
	// No SetWindowManager call — windowManager is nil.

	setErr := m.Set(context.Background(), "system", patchCfgWithWindow())
	require.Error(t, setErr, "Set with maintenance.window and nil window manager must fail (fail-closed)")
	assert.ErrorIs(t, setErr, ErrMaintenanceWindowNotActive,
		"fail-closed denial must surface ErrMaintenanceWindowNotActive")
}

// TestGateWindowAdapter_CanReboot delegates to the underlying Gate.
func TestGateWindowAdapter_CanReboot(t *testing.T) {
	outsideGate, err := stewardgate.New(stewardgate.Config{
		Window:   weeklyMondayWindowCfgForPatch(),
		Timezone: "UTC",
		DeviceID: "d",
		Now:      func() time.Time { return outsideWindowTime },
	})
	require.NoError(t, err)

	insideGate, err := stewardgate.New(stewardgate.Config{
		Window:   weeklyMondayWindowCfgForPatch(),
		Timezone: "UTC",
		DeviceID: "d",
		Now:      func() time.Time { return insideWindowTime },
	})
	require.NoError(t, err)

	outside := NewGateWindowAdapter(outsideGate, "d")
	inside := NewGateWindowAdapter(insideGate, "d")

	can, err := outside.CanReboot(context.Background(), "d")
	require.NoError(t, err)
	assert.False(t, can, "CanReboot must return false outside the window")

	can, err = inside.CanReboot(context.Background(), "d")
	require.NoError(t, err)
	assert.True(t, can, "CanReboot must return true inside the window")
}

// TestGateWindowAdapter_GetNextWindow returns a non-zero time when outside the window.
func TestGateWindowAdapter_GetNextWindow(t *testing.T) {
	gate, err := stewardgate.New(stewardgate.Config{
		Window:   weeklyMondayWindowCfgForPatch(),
		Timezone: "UTC",
		DeviceID: "d",
		Now:      func() time.Time { return outsideWindowTime },
	})
	require.NoError(t, err)

	adapter := NewGateWindowAdapter(gate, "d")
	next, err := adapter.GetNextWindow(context.Background(), "d")
	require.NoError(t, err)
	assert.False(t, next.IsZero(), "GetNextWindow must return a non-zero time when outside the window")
}
