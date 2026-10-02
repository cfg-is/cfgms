// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package schedule

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func ptr(i int) *int { return &i }

// TestValidate_NilConfig verifies that Validate rejects a nil pointer.
func TestValidate_NilConfig(t *testing.T) {
	err := Validate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

// TestValidate_EmptySchedules verifies that an empty schedule list is rejected.
func TestValidate_EmptySchedules(t *testing.T) {
	err := Validate(&Config{Schedules: []Schedule{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schedules")
}

// TestValidate_BadTimezone verifies that an unknown IANA timezone is rejected.
func TestValidate_BadTimezone(t *testing.T) {
	err := Validate(&Config{
		Timezone: "Not/Real/Zone",
		Schedules: []Schedule{
			{Freq: FreqWeekly, Days: []time.Weekday{time.Monday},
				Start: TimeOfDay{Hour: 2}, End: TimeOfDay{Hour: 4}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timezone")
}

// TestValidate_DeviceTimezone verifies that the literal "device" timezone passes.
func TestValidate_DeviceTimezone(t *testing.T) {
	err := Validate(&Config{
		Timezone: "device",
		Schedules: []Schedule{
			{Freq: FreqWeekly, Days: []time.Weekday{time.Monday},
				Start: TimeOfDay{Hour: 2}, End: TimeOfDay{Hour: 4}},
		},
	})
	assert.NoError(t, err)
}

// TestValidate_InvalidFreq covers the invalid-Freq branch in validateParsedSchedule.
func TestValidate_InvalidFreq(t *testing.T) {
	err := Validate(&Config{
		Schedules: []Schedule{
			{Freq: Freq("quarterly"), Days: []time.Weekday{time.Monday},
				Start: TimeOfDay{Hour: 2}, End: TimeOfDay{Hour: 4}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "freq")
}

// TestValidate_WeeklyWithNth covers FreqWeekly+Nth rejection.
func TestValidate_WeeklyWithNth(t *testing.T) {
	err := Validate(&Config{
		Schedules: []Schedule{
			{Freq: FreqWeekly, Days: []time.Weekday{time.Monday},
				Nth:   ptr(1),
				Start: TimeOfDay{Hour: 2}, End: TimeOfDay{Hour: 4}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nth")
}

// TestValidate_WeeklyWithAfter covers FreqWeekly+After rejection.
func TestValidate_WeeklyWithAfter(t *testing.T) {
	err := Validate(&Config{
		Schedules: []Schedule{
			{Freq: FreqWeekly, Days: []time.Weekday{time.Monday},
				After: &Anchor{Weekday: time.Wednesday, Nth: 1},
				Start: TimeOfDay{Hour: 2}, End: TimeOfDay{Hour: 4}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "monthly")
}

// TestValidate_WeeklyWithBefore covers FreqWeekly+Before rejection.
func TestValidate_WeeklyWithBefore(t *testing.T) {
	err := Validate(&Config{
		Schedules: []Schedule{
			{Freq: FreqWeekly, Days: []time.Weekday{time.Monday},
				Before: &Anchor{Weekday: time.Wednesday, Nth: 1},
				Start:  TimeOfDay{Hour: 2}, End: TimeOfDay{Hour: 4}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "monthly")
}

// TestValidate_MonthlyWithDays covers FreqMonthly+Days rejection.
func TestValidate_MonthlyWithDays(t *testing.T) {
	err := Validate(&Config{
		Schedules: []Schedule{
			{Freq: FreqMonthly, Weekday: time.Wednesday,
				Nth:   ptr(1),
				Days:  []time.Weekday{time.Monday},
				Start: TimeOfDay{Hour: 2}, End: TimeOfDay{Hour: 4}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "days")
}

// TestValidate_MonthlyMissingAnchor covers FreqMonthly with zero anchors (anchorCount==0).
func TestValidate_MonthlyMissingAnchor(t *testing.T) {
	err := Validate(&Config{
		Schedules: []Schedule{
			{Freq: FreqMonthly, Weekday: time.Wednesday,
				Start: TimeOfDay{Hour: 2}, End: TimeOfDay{Hour: 4}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "monthly")
}

// TestValidate_MonthlyMultipleAnchors covers FreqMonthly with anchorCount>1.
func TestValidate_MonthlyMultipleAnchors(t *testing.T) {
	err := Validate(&Config{
		Schedules: []Schedule{
			{Freq: FreqMonthly, Weekday: time.Wednesday,
				Nth:   ptr(1),
				After: &Anchor{Weekday: time.Monday, Nth: 2},
				Start: TimeOfDay{Hour: 2}, End: TimeOfDay{Hour: 4}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "monthly")
}

// TestValidate_ValidWeekly verifies a well-formed weekly config passes.
func TestValidate_ValidWeekly(t *testing.T) {
	err := Validate(&Config{
		Timezone: "America/New_York",
		Schedules: []Schedule{
			{Freq: FreqWeekly, Days: []time.Weekday{time.Monday, time.Thursday},
				Start: TimeOfDay{Hour: 2}, End: TimeOfDay{Hour: 4}},
		},
	})
	assert.NoError(t, err)
}

// TestValidate_ValidMonthlyNth verifies a well-formed monthly (nth) config passes.
func TestValidate_ValidMonthlyNth(t *testing.T) {
	err := Validate(&Config{
		Schedules: []Schedule{
			{Freq: FreqMonthly, Weekday: time.Saturday, Nth: ptr(1),
				Start: TimeOfDay{Hour: 22}, End: TimeOfDay{EndOfDay: true}},
		},
	})
	assert.NoError(t, err)
}

// TestValidate_ValidMonthlyAfter verifies a well-formed monthly (after) config passes.
func TestValidate_ValidMonthlyAfter(t *testing.T) {
	err := Validate(&Config{
		Schedules: []Schedule{
			{Freq: FreqMonthly, Weekday: time.Tuesday,
				After: &Anchor{Weekday: time.Monday, Nth: 2},
				Start: TimeOfDay{Hour: 3}, End: TimeOfDay{Hour: 5}},
		},
	})
	assert.NoError(t, err)
}

// TestUnmarshalYAML_ErrorPath verifies that an invalid reboot_window YAML block causes
// UnmarshalYAML to return the Parse error rather than silently producing a zero Config.
func TestUnmarshalYAML_ErrorPath(t *testing.T) {
	// A Config node with an empty schedules list must fail Parse and surface via UnmarshalYAML.
	invalidYAML := []byte(`timezone: "America/New_York"
schedules: []
`)
	var cfg Config
	err := yaml.Unmarshal(invalidYAML, &cfg)
	require.Error(t, err, "UnmarshalYAML must propagate Parse errors for invalid YAML blocks")
	assert.Contains(t, err.Error(), "schedules")
}

// TestMarshalUnmarshal_RoundTrip verifies that MarshalYAML → UnmarshalYAML preserves
// the full Config value for both weekly and monthly (after/before/nth) shapes.
func TestMarshalUnmarshal_RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{
			name: "weekly",
			cfg: Config{
				Timezone: "America/Chicago",
				Schedules: []Schedule{
					{Freq: FreqWeekly, Days: []time.Weekday{time.Monday, time.Thursday},
						Start: TimeOfDay{Hour: 2}, End: TimeOfDay{Hour: 4}},
				},
			},
		},
		{
			name: "monthly-nth",
			cfg: Config{
				Schedules: []Schedule{
					{Freq: FreqMonthly, Weekday: time.Saturday, Nth: ptr(-1),
						Start: TimeOfDay{Hour: 22}, End: TimeOfDay{EndOfDay: true}},
				},
			},
		},
		{
			name: "monthly-after",
			cfg: Config{
				Schedules: []Schedule{
					{Freq: FreqMonthly, Weekday: time.Tuesday,
						After: &Anchor{Weekday: time.Monday, Nth: 1},
						Start: TimeOfDay{Hour: 3}, End: TimeOfDay{Hour: 5}},
				},
			},
		},
		{
			name: "monthly-before",
			cfg: Config{
				Schedules: []Schedule{
					{Freq: FreqMonthly, Weekday: time.Thursday,
						Before: &Anchor{Weekday: time.Friday, Nth: 2},
						Start:  TimeOfDay{Hour: 1}, End: TimeOfDay{Hour: 3}},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := yaml.Marshal(tc.cfg)
			require.NoError(t, err, "Marshal must not fail")

			var got Config
			require.NoError(t, yaml.Unmarshal(data, &got), "Unmarshal must not fail")
			assert.Equal(t, tc.cfg, got, "round-trip must preserve all fields")
		})
	}
}
