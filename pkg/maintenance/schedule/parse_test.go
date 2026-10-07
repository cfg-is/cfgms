// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package schedule

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scheduleYAML wraps a raw body under the Config fields (no reboot_window: wrapper).
func scheduleYAML(body string) []byte {
	return []byte(body)
}

func TestParse_ThreeShapes(t *testing.T) {
	yaml := scheduleYAML(`
timezone: America/Chicago
schedules:
  - freq: monthly
    weekday: thursday
    after:
      weekday: tuesday
      nth: 2
    start: "02:00"
    end: "04:00"
  - freq: monthly
    weekday: thursday
    nth: 2
    start: "02:00"
    end: "06:00"
  - freq: weekly
    days: [saturday, sunday]
    start: "01:00"
    end: "06:00"
`)
	cfg, warnings, err := Parse(yaml)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, cfg.Schedules, 3)

	// Shape 1: monthly after-anchored
	s0 := cfg.Schedules[0]
	assert.Equal(t, FreqMonthly, s0.Freq)
	assert.Equal(t, time.Thursday, s0.Weekday)
	require.NotNil(t, s0.After)
	assert.Equal(t, time.Tuesday, s0.After.Weekday)
	assert.Equal(t, 2, s0.After.Nth)
	assert.Nil(t, s0.Nth)
	assert.Nil(t, s0.Before)
	assert.Equal(t, TimeOfDay{Hour: 2, Minute: 0}, s0.Start)
	assert.Equal(t, TimeOfDay{Hour: 4, Minute: 0}, s0.End)

	// Shape 2: monthly plain nth
	s1 := cfg.Schedules[1]
	assert.Equal(t, FreqMonthly, s1.Freq)
	assert.Equal(t, time.Thursday, s1.Weekday)
	require.NotNil(t, s1.Nth)
	assert.Equal(t, 2, *s1.Nth)
	assert.Nil(t, s1.After)
	assert.Nil(t, s1.Before)
	assert.Equal(t, TimeOfDay{Hour: 2, Minute: 0}, s1.Start)
	assert.Equal(t, TimeOfDay{Hour: 6, Minute: 0}, s1.End)

	// Shape 3: weekly days
	s2 := cfg.Schedules[2]
	assert.Equal(t, FreqWeekly, s2.Freq)
	assert.ElementsMatch(t, []time.Weekday{time.Saturday, time.Sunday}, s2.Days)
	assert.Equal(t, TimeOfDay{Hour: 1, Minute: 0}, s2.Start)
	assert.Equal(t, TimeOfDay{Hour: 6, Minute: 0}, s2.End)
}

func TestParse_WeekdayCaseInsensitive(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - freq: weekly
    days: [Saturday, SUNDAY, monday]
    start: "01:00"
    end: "06:00"
`)
	cfg, _, err := Parse(yaml)
	require.NoError(t, err)
	assert.ElementsMatch(t, []time.Weekday{time.Saturday, time.Sunday, time.Monday}, cfg.Schedules[0].Days)
}

func TestParse_End24h(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - freq: weekly
    days: [tuesday]
    start: "02:00"
    end: "24:00"
`)
	cfg, _, err := Parse(yaml)
	require.NoError(t, err)
	require.Len(t, cfg.Schedules, 1)
	assert.True(t, cfg.Schedules[0].End.EndOfDay)
	assert.Equal(t, 0, cfg.Schedules[0].End.Hour)
	assert.Equal(t, 0, cfg.Schedules[0].End.Minute)
}

func TestParse_NthNegativeOne(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - freq: monthly
    weekday: friday
    nth: -1
    start: "03:00"
    end: "05:00"
`)
	cfg, _, err := Parse(yaml)
	require.NoError(t, err)
	require.NotNil(t, cfg.Schedules[0].Nth)
	assert.Equal(t, -1, *cfg.Schedules[0].Nth)
}

// Validation rule: nth and after/before are mutually exclusive.
func TestParse_Validation_NthAndAfterMutuallyExclusive(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - freq: monthly
    weekday: thursday
    nth: 2
    after:
      weekday: tuesday
      nth: 2
    start: "02:00"
    end: "04:00"
`)
	_, _, err := Parse(yaml)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestParse_Validation_NthAndBeforeMutuallyExclusive(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - freq: monthly
    weekday: thursday
    nth: 1
    before:
      weekday: tuesday
      nth: 2
    start: "02:00"
    end: "04:00"
`)
	_, _, err := Parse(yaml)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestParse_Validation_AfterAndBeforeMutuallyExclusive(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - freq: monthly
    weekday: thursday
    after:
      weekday: tuesday
      nth: 2
    before:
      weekday: wednesday
      nth: 1
    start: "02:00"
    end: "04:00"
`)
	_, _, err := Parse(yaml)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

// Validation rule: with freq: monthly + weekday, exactly one of nth/after/before must be present.
func TestParse_Validation_MonthlyMissingAnchor(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - freq: monthly
    weekday: thursday
    start: "02:00"
    end: "04:00"
`)
	_, _, err := Parse(yaml)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one")
}

// Validation rule: after/before/nth valid only with freq: monthly.
func TestParse_Validation_NthOnlyWithMonthly(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - freq: weekly
    days: [saturday]
    nth: 2
    start: "02:00"
    end: "04:00"
`)
	_, _, err := Parse(yaml)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only valid with freq: monthly")
}

func TestParse_Validation_AfterOnlyWithMonthly(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - freq: weekly
    days: [saturday]
    after:
      weekday: tuesday
      nth: 2
    start: "02:00"
    end: "04:00"
`)
	_, _, err := Parse(yaml)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only valid with freq: monthly")
}

func TestParse_Validation_BeforeOnlyWithMonthly(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - freq: weekly
    days: [saturday]
    before:
      weekday: tuesday
      nth: 2
    start: "02:00"
    end: "04:00"
`)
	_, _, err := Parse(yaml)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only valid with freq: monthly")
}

// Validation rule: days valid only with freq: weekly.
func TestParse_Validation_DaysOnlyWithWeekly(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - freq: monthly
    weekday: thursday
    nth: 2
    days: [saturday]
    start: "02:00"
    end: "04:00"
`)
	_, _, err := Parse(yaml)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only valid with freq: weekly")
}

// Validation rule: weekly must have at least one day.
func TestParse_Validation_WeeklyNoDays(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - freq: weekly
    start: "02:00"
    end: "04:00"
`)
	_, _, err := Parse(yaml)
	require.Error(t, err)
}

// Validation rule: timezone must be empty, "device", or valid IANA zone.
func TestParse_Validation_InvalidTimezone(t *testing.T) {
	yaml := scheduleYAML(`
timezone: Not/A/Real/Zone
schedules:
  - freq: weekly
    days: [saturday]
    start: "02:00"
    end: "04:00"
`)
	_, _, err := Parse(yaml)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timezone")
}

func TestParse_Validation_TimezoneDevice(t *testing.T) {
	yaml := scheduleYAML(`
timezone: device
schedules:
  - freq: weekly
    days: [saturday]
    start: "01:00"
    end: "06:00"
`)
	_, _, err := Parse(yaml)
	require.NoError(t, err)
}

func TestParse_Validation_TimezoneEmpty(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - freq: weekly
    days: [saturday]
    start: "01:00"
    end: "06:00"
`)
	_, _, err := Parse(yaml)
	require.NoError(t, err)
}

// Validation rule: missing freq is an error.
func TestParse_Validation_MissingFreq(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - weekday: thursday
    nth: 2
    start: "02:00"
    end: "04:00"
`)
	_, _, err := Parse(yaml)
	require.Error(t, err)
}

// Validation rule: invalid freq string.
func TestParse_Validation_InvalidFreq(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - freq: biweekly
    days: [saturday]
    start: "02:00"
    end: "04:00"
`)
	_, _, err := Parse(yaml)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "freq")
}

// DST warning: a schedule whose entire span falls inside a spring-forward
// skipped hour must produce a warning (not an error), verified with a concrete
// DST-transition date in America/New_York (second Sunday of March).
func TestParse_DSTWarning_WindowInsideSpringForwardGap(t *testing.T) {
	// America/New_York springs forward on the second Sunday of March:
	// 2025-03-09 02:00 → 03:00. A window 02:15–02:45 is entirely skipped.
	yaml := scheduleYAML(`
timezone: America/New_York
schedules:
  - freq: weekly
    days: [sunday]
    start: "02:15"
    end: "02:45"
`)
	cfg, warnings, err := Parse(yaml)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.NotEmpty(t, warnings, "expected DST warning for window entirely inside spring-forward gap")
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "DST") || strings.Contains(w, "spring-forward") || strings.Contains(w, "skipped") {
			found = true
			break
		}
	}
	assert.True(t, found, "DST warning should mention spring-forward gap; got: %v", warnings)
}

// DST warning: a multi-hour window that only partially overlaps a DST gap must NOT warn.
func TestParse_DSTWarning_MultiHourWindowNoWarn(t *testing.T) {
	yaml := scheduleYAML(`
timezone: America/New_York
schedules:
  - freq: weekly
    days: [sunday]
    start: "01:00"
    end: "04:00"
`)
	_, warnings, err := Parse(yaml)
	require.NoError(t, err)
	// A multi-hour window spanning the gap should not produce a warning.
	for _, w := range warnings {
		assert.False(t, strings.Contains(w, "spring-forward"), "unexpected DST warning for multi-hour window: %s", w)
	}
}

// Cross-month boundary offsets are legal: no validation error when after-anchor
// resolution falls in the next month.
func TestParse_CrossMonthOffsetIsLegal(t *testing.T) {
	// Last Tuesday of January 2025 is Jan 28; Thursday after = Jan 30.
	// But last Tuesday of some months will have Thursday spilling into next month
	// (e.g., last Tuesday is Jan 30 → Thursday after = Feb 1).
	// Parse should not error; the evaluator handles the overflow.
	yaml := scheduleYAML(`
schedules:
  - freq: monthly
    weekday: thursday
    after:
      weekday: tuesday
      nth: -1
    start: "02:00"
    end: "04:00"
`)
	_, _, err := Parse(yaml)
	require.NoError(t, err)
}

// Empty schedules list is an error (no point in a window with no schedules).
func TestParse_EmptySchedulesList(t *testing.T) {
	yaml := scheduleYAML(`
schedules: []
`)
	_, _, err := Parse(yaml)
	require.Error(t, err)
}

// Minimum valid weekly schedule.
func TestParse_MinimalWeekly(t *testing.T) {
	yaml := scheduleYAML(`
schedules:
  - freq: weekly
    days: [monday]
    start: "00:00"
    end: "01:00"
`)
	cfg, _, err := Parse(yaml)
	require.NoError(t, err)
	assert.Len(t, cfg.Schedules, 1)
}
