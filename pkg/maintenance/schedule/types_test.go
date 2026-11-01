// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package schedule

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFreq_Constants(t *testing.T) {
	assert.Equal(t, Freq("monthly"), FreqMonthly)
	assert.Equal(t, Freq("weekly"), FreqWeekly)
}

func TestTimeOfDay_MinutesSinceMidnight(t *testing.T) {
	cases := []struct {
		tod  TimeOfDay
		want int
	}{
		{TimeOfDay{Hour: 0, Minute: 0}, 0},
		{TimeOfDay{Hour: 2, Minute: 0}, 120},
		{TimeOfDay{Hour: 23, Minute: 59}, 1439},
		{TimeOfDay{EndOfDay: true}, 1440},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.tod.minutesSinceMidnight(), "tod=%+v", tc.tod)
	}
}

func TestTimeOfDay_EndOfDay_Sentinel(t *testing.T) {
	tod := TimeOfDay{EndOfDay: true}
	// EndOfDay=true should dominate Hour/Minute regardless of their values.
	tod.Hour, tod.Minute = 0, 0
	assert.Equal(t, 1440, tod.minutesSinceMidnight())
}

func TestConfig_TimezoneField(t *testing.T) {
	c := Config{Timezone: "device", Schedules: []Schedule{}}
	assert.Equal(t, "device", c.Timezone)
}

func TestConfig_EmptyTimezone(t *testing.T) {
	c := Config{Schedules: []Schedule{}}
	assert.Equal(t, "", c.Timezone, "empty timezone means not set at this level")
}

func TestSchedule_NthPointerNilByDefault(t *testing.T) {
	s := Schedule{Freq: FreqMonthly, Weekday: time.Thursday}
	assert.Nil(t, s.Nth)
	assert.Nil(t, s.After)
	assert.Nil(t, s.Before)
}

func TestAnchor_Fields(t *testing.T) {
	a := Anchor{Weekday: time.Tuesday, Nth: 2}
	assert.Equal(t, time.Tuesday, a.Weekday)
	assert.Equal(t, 2, a.Nth)

	last := Anchor{Weekday: time.Friday, Nth: -1}
	assert.Equal(t, -1, last.Nth)
}
