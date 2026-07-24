// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package stewardtypes

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	maintenanceschedule "github.com/cfgis/cfgms/pkg/maintenance/schedule"
)

// TestStewardSettings_RebootWindowYAMLRoundTrip verifies that a StewardConfig
// containing a RebootWindow round-trips through yaml.Marshal / yaml.Unmarshal
// without data loss.
func TestStewardSettings_RebootWindowYAMLRoundTrip(t *testing.T) {
	nth := 1
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:   "test-steward",
			Mode: ModeController,
			RebootWindow: &maintenanceschedule.Config{
				Timezone: "America/New_York",
				Schedules: []maintenanceschedule.Schedule{
					{
						Freq:  maintenanceschedule.FreqWeekly,
						Days:  []time.Weekday{time.Monday, time.Thursday},
						Start: maintenanceschedule.TimeOfDay{Hour: 2, Minute: 0},
						End:   maintenanceschedule.TimeOfDay{Hour: 4, Minute: 0},
					},
					{
						Freq:    maintenanceschedule.FreqMonthly,
						Weekday: time.Saturday,
						Nth:     &nth,
						Start:   maintenanceschedule.TimeOfDay{Hour: 22, Minute: 0},
						End:     maintenanceschedule.TimeOfDay{EndOfDay: true},
					},
				},
			},
			TenantDefaultTimezone: "Europe/London",
		},
	}

	data, err := yaml.Marshal(cfg)
	require.NoError(t, err, "yaml.Marshal must not fail on a StewardConfig with RebootWindow")

	var got StewardConfig
	require.NoError(t, yaml.Unmarshal(data, &got), "yaml.Unmarshal must not fail on the marshaled output")

	require.NotNil(t, got.Steward.RebootWindow, "RebootWindow must survive the round-trip")
	assert.Equal(t, "America/New_York", got.Steward.RebootWindow.Timezone)
	require.Len(t, got.Steward.RebootWindow.Schedules, 2)

	weekly := got.Steward.RebootWindow.Schedules[0]
	assert.Equal(t, maintenanceschedule.FreqWeekly, weekly.Freq)
	assert.Equal(t, []time.Weekday{time.Monday, time.Thursday}, weekly.Days)
	assert.Equal(t, maintenanceschedule.TimeOfDay{Hour: 2, Minute: 0}, weekly.Start)
	assert.Equal(t, maintenanceschedule.TimeOfDay{Hour: 4, Minute: 0}, weekly.End)

	monthly := got.Steward.RebootWindow.Schedules[1]
	assert.Equal(t, maintenanceschedule.FreqMonthly, monthly.Freq)
	assert.Equal(t, time.Saturday, monthly.Weekday)
	require.NotNil(t, monthly.Nth)
	assert.Equal(t, 1, *monthly.Nth)
	assert.True(t, monthly.End.EndOfDay)

	assert.Equal(t, "Europe/London", got.Steward.TenantDefaultTimezone)
}

// TestStewardSettings_RebootWindowNilOmitted verifies that a nil RebootWindow
// is omitted from the YAML output and does not appear as a key.
func TestStewardSettings_RebootWindowNilOmitted(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{ID: "test-steward", Mode: ModeStandalone},
	}

	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "reboot_window",
		"nil RebootWindow must not appear in marshaled YAML")
}

// TestValidateConfiguration_RejectsBadRebootWindow verifies that a StewardConfig
// with an invalid RebootWindow (empty schedules list) fails ValidateConfiguration
// with a descriptive error referencing reboot_window.
func TestValidateConfiguration_RejectsBadRebootWindow(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:   "test-steward",
			Mode: ModeStandalone,
			RebootWindow: &maintenanceschedule.Config{
				Timezone:  "America/New_York",
				Schedules: []maintenanceschedule.Schedule{}, // empty — invalid
			},
		},
	}

	err := ValidateConfiguration(cfg)
	require.Error(t, err, "empty RebootWindow.Schedules must fail validation")
	assert.Contains(t, err.Error(), "reboot_window",
		"error must reference reboot_window to help operators identify the offending field")
}

// TestValidateConfiguration_AcceptsNilRebootWindow verifies that a nil RebootWindow
// does not trigger any validation error.
func TestValidateConfiguration_AcceptsNilRebootWindow(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:           "test-steward",
			Mode:         ModeStandalone,
			RebootWindow: nil,
		},
	}

	assert.NoError(t, ValidateConfiguration(cfg),
		"nil RebootWindow must not cause a validation error")
}

// TestValidateConfiguration_RejectsInvalidTimezoneInRebootWindow verifies that an
// unknown IANA timezone name in RebootWindow.Timezone causes a validation error.
func TestValidateConfiguration_RejectsInvalidTimezoneInRebootWindow(t *testing.T) {
	nth := 1
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:   "test-steward",
			Mode: ModeStandalone,
			RebootWindow: &maintenanceschedule.Config{
				Timezone: "Not/A/Real/Zone",
				Schedules: []maintenanceschedule.Schedule{
					{
						Freq:    maintenanceschedule.FreqMonthly,
						Weekday: time.Wednesday,
						Nth:     &nth,
						Start:   maintenanceschedule.TimeOfDay{Hour: 2, Minute: 0},
						End:     maintenanceschedule.TimeOfDay{Hour: 4, Minute: 0},
					},
				},
			},
		},
	}

	err := ValidateConfiguration(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reboot_window")
}
