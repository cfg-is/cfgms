// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package maintenance_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/maintenance"
)

func TestDefaultPolicy(t *testing.T) {
	policy := maintenance.DefaultPolicy()

	assert.False(t, policy.Enabled, "Should be disabled by default for backwards compatibility")
	assert.Equal(t, "allow", policy.DefaultAction, "Default action should be allow")
	assert.True(t, policy.EmergencyBypass, "Emergency bypass should be enabled")
	assert.Equal(t, 1, len(policy.Windows), "Should have one default window")
	assert.Equal(t, "sunday_3am", policy.Windows[0].Schedule, "Default window should be Sunday 3am")
}

func TestManager_CanReboot_WindowsDisabled(t *testing.T) {
	policy := maintenance.Policy{
		Enabled:       false,
		DefaultAction: "deny", // Even with deny, should allow when disabled
	}
	manager := maintenance.NewManager(policy, nil)

	ctx := context.Background()
	canReboot, err := manager.CanReboot(ctx, "device-1")

	require.NoError(t, err)
	assert.True(t, canReboot, "Should allow reboot when maintenance windows are disabled")
}

func TestManager_CanReboot_DefaultActionAllow(t *testing.T) {
	policy := maintenance.Policy{
		Enabled:       true,
		DefaultAction: "allow",
		Windows:       []maintenance.Window{},
	}
	manager := maintenance.NewManager(policy, nil)

	ctx := context.Background()
	canReboot, err := manager.CanReboot(ctx, "device-1")

	require.NoError(t, err)
	assert.True(t, canReboot, "Should allow reboot with 'allow' default action")
}

func TestManager_CanReboot_DefaultActionDeny(t *testing.T) {
	policy := maintenance.Policy{
		Enabled:       true,
		DefaultAction: "deny",
		Windows:       []maintenance.Window{},
	}
	manager := maintenance.NewManager(policy, nil)

	ctx := context.Background()
	canReboot, err := manager.CanReboot(ctx, "device-1")

	require.NoError(t, err)
	assert.False(t, canReboot, "Should deny reboot with 'deny' default action outside window")
}

func TestManager_CanReboot_DefaultActionDefer(t *testing.T) {
	policy := maintenance.Policy{
		Enabled:       true,
		DefaultAction: "defer",
		Windows:       []maintenance.Window{},
	}
	manager := maintenance.NewManager(policy, nil)

	ctx := context.Background()
	canReboot, err := manager.CanReboot(ctx, "device-1")

	require.NoError(t, err)
	assert.False(t, canReboot, "Should defer reboot with 'defer' default action outside window")
}

func TestManager_IsInWindow_NoWindows(t *testing.T) {
	policy := maintenance.Policy{
		Enabled: true,
		Windows: []maintenance.Window{},
	}
	manager := maintenance.NewManager(policy, nil)

	ctx := context.Background()
	inWindow, err := manager.IsInWindow(ctx, "device-1")

	require.NoError(t, err)
	assert.False(t, inWindow, "Should not be in window when no windows configured")
}

func TestManager_IsInWindow_WithSchedule(t *testing.T) {
	// Create a mock parser that always returns true
	mockParser := &mockScheduleParser{
		isInSchedule: true,
	}

	policy := maintenance.Policy{
		Enabled: true,
		Windows: []maintenance.Window{
			{
				Schedule: "test_schedule",
				Duration: 2 * time.Hour,
			},
		},
	}
	manager := maintenance.NewManager(policy, mockParser)

	ctx := context.Background()
	inWindow, err := manager.IsInWindow(ctx, "device-1")

	require.NoError(t, err)
	assert.True(t, inWindow, "Should be in window when parser returns true")
}

func TestManager_GetNextWindow_NoWindows(t *testing.T) {
	policy := maintenance.Policy{
		Enabled: true,
		Windows: []maintenance.Window{},
	}
	manager := maintenance.NewManager(policy, nil)

	ctx := context.Background()
	_, err := manager.GetNextWindow(ctx, "device-1")

	assert.Error(t, err, "Should return error when no windows configured")
}

func TestManager_GetNextWindow_WithSchedule(t *testing.T) {
	expectedTime := time.Now().Add(24 * time.Hour)
	mockParser := &mockScheduleParser{
		nextTime: expectedTime,
	}

	policy := maintenance.Policy{
		Enabled: true,
		Windows: []maintenance.Window{
			{
				Schedule: "test_schedule",
				Duration: 2 * time.Hour,
			},
		},
	}
	manager := maintenance.NewManager(policy, mockParser)

	ctx := context.Background()
	nextWindow, err := manager.GetNextWindow(ctx, "device-1")

	require.NoError(t, err)
	assert.Equal(t, expectedTime, nextWindow, "Should return next window time from parser")
}

func TestManager_CanPerformMaintenance(t *testing.T) {
	policy := maintenance.Policy{
		Enabled:       true,
		DefaultAction: "deny",
	}
	manager := maintenance.NewManager(policy, nil)

	ctx := context.Background()
	canMaintain, err := manager.CanPerformMaintenance(ctx, "device-1")

	require.NoError(t, err)
	// CanPerformMaintenance should follow the same rules as CanReboot
	assert.False(t, canMaintain, "Should deny maintenance with 'deny' default action")
}

func TestDefaultParser_Daily2AM(t *testing.T) {
	policy := maintenance.Policy{
		Enabled: true,
		Windows: []maintenance.Window{
			{
				Schedule: "daily_2am",
				Duration: 2 * time.Hour,
				Timezone: "UTC",
			},
		},
	}
	manager := maintenance.NewManager(policy, nil)

	ctx := context.Background()

	// Test getting next window
	nextWindow, err := manager.GetNextWindow(ctx, "device-1")
	require.NoError(t, err)
	assert.Equal(t, 2, nextWindow.Hour(), "Next window should be at 2am")
}

func TestDefaultParser_Sunday3AM(t *testing.T) {
	policy := maintenance.Policy{
		Enabled: true,
		Windows: []maintenance.Window{
			{
				Schedule: "sunday_3am",
				Duration: 2 * time.Hour,
				Timezone: "UTC",
			},
		},
	}
	manager := maintenance.NewManager(policy, nil)

	ctx := context.Background()

	// Test getting next window
	nextWindow, err := manager.GetNextWindow(ctx, "device-1")
	require.NoError(t, err)
	assert.Equal(t, time.Sunday, nextWindow.Weekday(), "Next window should be on Sunday")
	assert.Equal(t, 3, nextWindow.Hour(), "Next window should be at 3am")
}

func TestManager_CanReboot_InWindow(t *testing.T) {
	mockParser := &mockScheduleParser{
		isInSchedule: true, // Simulate being in a window
	}

	policy := maintenance.Policy{
		Enabled:       true,
		DefaultAction: "deny", // Even with deny, should allow inside window
		Windows: []maintenance.Window{
			{
				Schedule: "test_schedule",
				Duration: 2 * time.Hour,
			},
		},
	}
	manager := maintenance.NewManager(policy, mockParser)

	ctx := context.Background()
	canReboot, err := manager.CanReboot(ctx, "device-1")

	require.NoError(t, err)
	assert.True(t, canReboot, "Should allow reboot when inside maintenance window")
}

// mockScheduleParser is a mock implementation of ScheduleParser for testing
type mockScheduleParser struct {
	isInSchedule bool
	nextTime     time.Time
	err          error
}

func (m *mockScheduleParser) Parse(schedule string, timezone string) (time.Time, error) {
	if m.err != nil {
		return time.Time{}, m.err
	}
	if !m.nextTime.IsZero() {
		return m.nextTime, nil
	}
	return time.Now().Add(24 * time.Hour), nil
}

func (m *mockScheduleParser) IsInSchedule(schedule string, timezone string, now time.Time) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	return m.isInSchedule, nil
}
