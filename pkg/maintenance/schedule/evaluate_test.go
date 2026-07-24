// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package schedule

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loc is a helper for loading time zones in tests.
func loc(t *testing.T, name string) *time.Location {
	t.Helper()
	l, err := time.LoadLocation(name)
	require.NoError(t, err)
	return l
}

// newTOD builds a TimeOfDay for a HH:MM string.
func newTOD(h, m int) TimeOfDay { return TimeOfDay{Hour: h, Minute: m} }

// weeklySchedule is a helper for weekly-only InWindow tests.
func weeklySchedule(days []time.Weekday, start, end TimeOfDay) Schedule {
	return Schedule{
		Freq:  FreqWeekly,
		Days:  days,
		Start: start,
		End:   end,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// InWindow
// ─────────────────────────────────────────────────────────────────────────────

func TestInWindow_NonWrapping_Inside(t *testing.T) {
	s := weeklySchedule([]time.Weekday{time.Monday}, newTOD(2, 0), newTOD(4, 0))
	now := time.Date(2025, 3, 3, 3, 0, 0, 0, time.UTC) // Monday, 03:00
	assert.True(t, InWindow(now, s))
}

func TestInWindow_NonWrapping_BeforeStart(t *testing.T) {
	s := weeklySchedule([]time.Weekday{time.Monday}, newTOD(2, 0), newTOD(4, 0))
	now := time.Date(2025, 3, 3, 1, 59, 0, 0, time.UTC) // Monday, 01:59
	assert.False(t, InWindow(now, s))
}

func TestInWindow_NonWrapping_AfterEnd(t *testing.T) {
	s := weeklySchedule([]time.Weekday{time.Monday}, newTOD(2, 0), newTOD(4, 0))
	now := time.Date(2025, 3, 3, 4, 1, 0, 0, time.UTC) // Monday, 04:01
	assert.False(t, InWindow(now, s))
}

func TestInWindow_NonWrapping_BoundaryStart(t *testing.T) {
	s := weeklySchedule([]time.Weekday{time.Monday}, newTOD(2, 0), newTOD(4, 0))
	now := time.Date(2025, 3, 3, 2, 0, 0, 0, time.UTC) // Monday, exactly 02:00
	assert.True(t, InWindow(now, s))
}

func TestInWindow_NonWrapping_BoundaryEnd(t *testing.T) {
	s := weeklySchedule([]time.Weekday{time.Monday}, newTOD(2, 0), newTOD(4, 0))
	now := time.Date(2025, 3, 3, 4, 0, 0, 0, time.UTC) // Monday, exactly 04:00
	assert.True(t, InWindow(now, s))
}

func TestInWindow_NonWrapping_WrongDay(t *testing.T) {
	s := weeklySchedule([]time.Weekday{time.Monday}, newTOD(2, 0), newTOD(4, 0))
	now := time.Date(2025, 3, 4, 3, 0, 0, 0, time.UTC) // Tuesday, 03:00 — not Monday
	assert.False(t, InWindow(now, s))
}

// Midnight-wrapping window: start > end (e.g., 23:00–02:00).
func TestInWindow_MidnightWrap_OpenSide(t *testing.T) {
	// Saturday 23:30 — scheduled day is Saturday, within [23:00, ∞)
	s := weeklySchedule([]time.Weekday{time.Saturday}, newTOD(23, 0), newTOD(2, 0))
	now := time.Date(2025, 3, 8, 23, 30, 0, 0, time.UTC) // Saturday 23:30
	assert.True(t, InWindow(now, s))
}

func TestInWindow_MidnightWrap_CloseSide(t *testing.T) {
	// Sunday 01:00 — yesterday (Saturday) was the scheduled day, within [0, 02:00]
	s := weeklySchedule([]time.Weekday{time.Saturday}, newTOD(23, 0), newTOD(2, 0))
	now := time.Date(2025, 3, 9, 1, 0, 0, 0, time.UTC) // Sunday 01:00
	assert.True(t, InWindow(now, s))
}

func TestInWindow_MidnightWrap_Gap(t *testing.T) {
	// Sunday 03:00 — after end, before next start
	s := weeklySchedule([]time.Weekday{time.Saturday}, newTOD(23, 0), newTOD(2, 0))
	now := time.Date(2025, 3, 9, 3, 0, 0, 0, time.UTC) // Sunday 03:00
	assert.False(t, InWindow(now, s))
}

func TestInWindow_MidnightWrap_BoundaryStart(t *testing.T) {
	s := weeklySchedule([]time.Weekday{time.Saturday}, newTOD(23, 0), newTOD(2, 0))
	now := time.Date(2025, 3, 8, 23, 0, 0, 0, time.UTC) // Saturday exactly 23:00
	assert.True(t, InWindow(now, s))
}

func TestInWindow_MidnightWrap_BoundaryEnd(t *testing.T) {
	s := weeklySchedule([]time.Weekday{time.Saturday}, newTOD(23, 0), newTOD(2, 0))
	now := time.Date(2025, 3, 9, 2, 0, 0, 0, time.UTC) // Sunday exactly 02:00
	assert.True(t, InWindow(now, s))
}

// end: "24:00" — end-of-day sentinel (non-wrapping).
func TestInWindow_EndOfDay_Inside(t *testing.T) {
	s := weeklySchedule([]time.Weekday{time.Wednesday}, newTOD(2, 0), TimeOfDay{EndOfDay: true})
	now := time.Date(2025, 3, 5, 22, 0, 0, 0, time.UTC) // Wednesday 22:00
	assert.True(t, InWindow(now, s))
}

func TestInWindow_EndOfDay_BeforeStart(t *testing.T) {
	s := weeklySchedule([]time.Weekday{time.Wednesday}, newTOD(2, 0), TimeOfDay{EndOfDay: true})
	now := time.Date(2025, 3, 5, 1, 59, 0, 0, time.UTC) // Wednesday 01:59
	assert.False(t, InWindow(now, s))
}

func TestInWindow_EndOfDay_WrongDay(t *testing.T) {
	s := weeklySchedule([]time.Weekday{time.Wednesday}, newTOD(2, 0), TimeOfDay{EndOfDay: true})
	now := time.Date(2025, 3, 6, 22, 0, 0, 0, time.UTC) // Thursday 22:00
	assert.False(t, InWindow(now, s))
}

// Monthly nth schedule — InWindow on the correct nth weekday.
func TestInWindow_Monthly_Nth_CorrectDay(t *testing.T) {
	nth := 2
	s := Schedule{
		Freq:    FreqMonthly,
		Weekday: time.Thursday,
		Nth:     &nth,
		Start:   newTOD(2, 0),
		End:     newTOD(4, 0),
	}
	// 2nd Thursday of March 2025 is March 13.
	now := time.Date(2025, 3, 13, 3, 0, 0, 0, time.UTC)
	assert.True(t, InWindow(now, s))
}

func TestInWindow_Monthly_Nth_WrongWeek(t *testing.T) {
	nth := 2
	s := Schedule{
		Freq:    FreqMonthly,
		Weekday: time.Thursday,
		Nth:     &nth,
		Start:   newTOD(2, 0),
		End:     newTOD(4, 0),
	}
	// 1st Thursday of March 2025 is March 6 — not the 2nd.
	now := time.Date(2025, 3, 6, 3, 0, 0, 0, time.UTC)
	assert.False(t, InWindow(now, s))
}

// Monthly after-anchor — InWindow on the correct after-anchor day.
func TestInWindow_Monthly_After_CorrectDay(t *testing.T) {
	// 2nd Thursday after the 2nd Tuesday of March 2025.
	// 2nd Tuesday of March 2025 = March 11.
	// First Thursday after March 11 = March 13.
	s := Schedule{
		Freq:    FreqMonthly,
		Weekday: time.Thursday,
		After:   &Anchor{Weekday: time.Tuesday, Nth: 2},
		Start:   newTOD(2, 0),
		End:     newTOD(4, 0),
	}
	now := time.Date(2025, 3, 13, 3, 0, 0, 0, time.UTC)
	assert.True(t, InWindow(now, s))
}

// Same-weekday rule: weekday: tuesday + after: {weekday: tuesday, nth: 2} → +7 days.
func TestInWindow_Monthly_After_SameWeekday_PlusSeven(t *testing.T) {
	// 2nd Tuesday of March 2025 = March 11.
	// Same weekday rule: result = March 11 + 7 = March 18.
	s := Schedule{
		Freq:    FreqMonthly,
		Weekday: time.Tuesday,
		After:   &Anchor{Weekday: time.Tuesday, Nth: 2},
		Start:   newTOD(2, 0),
		End:     newTOD(4, 0),
	}
	// March 18 is a Tuesday (+7 from March 11)
	assert.True(t, InWindow(time.Date(2025, 3, 18, 3, 0, 0, 0, time.UTC), s))
	// March 11 itself must NOT match (it is the anchor, not +7)
	assert.False(t, InWindow(time.Date(2025, 3, 11, 3, 0, 0, 0, time.UTC), s))
}

// ─────────────────────────────────────────────────────────────────────────────
// NextOccurrence
// ─────────────────────────────────────────────────────────────────────────────

func TestNextOccurrence_Weekly_Today(t *testing.T) {
	s := weeklySchedule([]time.Weekday{time.Monday}, newTOD(2, 0), newTOD(4, 0))
	// Monday 01:00 — today's start (02:00) is after now, so return today's start.
	after := time.Date(2025, 3, 3, 1, 0, 0, 0, time.UTC)
	next := NextOccurrence(after, s)
	assert.Equal(t, time.Date(2025, 3, 3, 2, 0, 0, 0, time.UTC), next)
}

func TestNextOccurrence_Weekly_NextWeek(t *testing.T) {
	s := weeklySchedule([]time.Weekday{time.Monday}, newTOD(2, 0), newTOD(4, 0))
	// Monday 03:00 — already past today's start, so next Monday.
	after := time.Date(2025, 3, 3, 3, 0, 0, 0, time.UTC)
	next := NextOccurrence(after, s)
	assert.Equal(t, time.Date(2025, 3, 10, 2, 0, 0, 0, time.UTC), next)
}

func TestNextOccurrence_Weekly_MultipleDays(t *testing.T) {
	s := weeklySchedule([]time.Weekday{time.Saturday, time.Sunday}, newTOD(1, 0), newTOD(6, 0))
	// Thursday — next occurrence is Saturday.
	after := time.Date(2025, 3, 6, 12, 0, 0, 0, time.UTC) // Thursday
	next := NextOccurrence(after, s)
	assert.Equal(t, time.Date(2025, 3, 8, 1, 0, 0, 0, time.UTC), next) // Saturday
}

// NextOccurrence with nth: -1 (last weekday of month) — 28-day month (Feb non-leap).
func TestNextOccurrence_Monthly_LastWeekday_Feb28(t *testing.T) {
	nth := -1
	s := Schedule{
		Freq:    FreqMonthly,
		Weekday: time.Friday,
		Nth:     &nth,
		Start:   newTOD(2, 0),
		End:     newTOD(4, 0),
	}
	// February 2025 has 28 days. Last Friday of Feb 2025:
	// Feb 1 is Saturday; days: 1=Sat,2=Sun,...,7=Fri → Feb 7 is Fri.
	// Fridays: Feb 7, 14, 21, 28. Last = Feb 28.
	after := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)
	next := NextOccurrence(after, s)
	assert.Equal(t, time.Date(2025, 2, 28, 2, 0, 0, 0, time.UTC), next)
}

// NextOccurrence with nth: -1 — 30-day month (April).
func TestNextOccurrence_Monthly_LastWeekday_30Day(t *testing.T) {
	nth := -1
	s := Schedule{
		Freq:    FreqMonthly,
		Weekday: time.Wednesday,
		Nth:     &nth,
		Start:   newTOD(2, 0),
		End:     newTOD(4, 0),
	}
	// April 2025 has 30 days. Wednesdays: Apr 2, 9, 16, 23, 30. Last = Apr 30.
	after := time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC)
	next := NextOccurrence(after, s)
	assert.Equal(t, time.Date(2025, 4, 30, 2, 0, 0, 0, time.UTC), next)
}

// NextOccurrence with nth: -1 — 31-day month (January).
func TestNextOccurrence_Monthly_LastWeekday_31Day(t *testing.T) {
	nth := -1
	s := Schedule{
		Freq:    FreqMonthly,
		Weekday: time.Thursday,
		Nth:     &nth,
		Start:   newTOD(2, 0),
		End:     newTOD(4, 0),
	}
	// January 2025 has 31 days. Thursdays: Jan 2, 9, 16, 23, 30. Last = Jan 30.
	after := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	next := NextOccurrence(after, s)
	assert.Equal(t, time.Date(2025, 1, 30, 2, 0, 0, 0, time.UTC), next)
}

// NextOccurrence nth: -1 — does not use a day-count table (handles 28/29/30/31 uniformly).
func TestNextOccurrence_Monthly_LastWeekday_Feb29_LeapYear(t *testing.T) {
	nth := -1
	s := Schedule{
		Freq:    FreqMonthly,
		Weekday: time.Saturday,
		Nth:     &nth,
		Start:   newTOD(3, 0),
		End:     newTOD(5, 0),
	}
	// February 2020 (leap, 29 days). Saturdays: Feb 1, 8, 15, 22, 29. Last = Feb 29.
	after := time.Date(2020, 2, 1, 0, 0, 0, 0, time.UTC)
	next := NextOccurrence(after, s)
	assert.Equal(t, time.Date(2020, 2, 29, 3, 0, 0, 0, time.UTC), next)
}

// NextOccurrence after-anchor: cross-month boundary is legal.
func TestNextOccurrence_Monthly_After_CrossMonthBoundary(t *testing.T) {
	// Last Tuesday of January 2025 is Jan 28. Thursday after = Jan 30.
	// But in a month where last Tuesday is on the 30th (e.g., Jan has 31 days,
	// last Tuesday = Jan 28, Thursday = Jan 30 — still in Jan).
	// Test case: last Tuesday of October 2025. Oct has 31 days.
	// Tuesdays in Oct 2025: 7, 14, 21, 28. Last = Oct 28.
	// Thursday after Oct 28 = Oct 30 (in Oct, still).
	// Now pick a month where the overflow goes into next month:
	// Last Tuesday of November 2025. Nov has 30 days.
	// Tuesdays in Nov 2025: 4, 11, 18, 25. Last = Nov 25.
	// Thursday after Nov 25 = Nov 27.
	// Pick a month where it overflows: last Tuesday of March 2025.
	// Tuesdays in March 2025: 4, 11, 18, 25. Last = March 25.
	// Thursday after March 25 = March 27 (same month).
	// To get overflow: last Tuesday of January 2025 = Jan 28.
	// Thursday after Jan 28 = Jan 30 (still in Jan).
	// Try: last Sunday of January 2025 = Jan 26. Tuesday after Jan 26 = Jan 28.
	// No overflow there either. Let's try Saturday after last Thursday of January:
	// Thursdays Jan 2025: Jan 2, 9, 16, 23, 30. Last = Jan 30.
	// Saturday after Jan 30 = Feb 1 (crosses to February).
	s := Schedule{
		Freq:    FreqMonthly,
		Weekday: time.Saturday,
		After:   &Anchor{Weekday: time.Thursday, Nth: -1},
		Start:   newTOD(2, 0),
		End:     newTOD(4, 0),
	}
	// Searching from Jan 1, 2025: last Thursday of Jan = Jan 30, Saturday after = Feb 1.
	after := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	next := NextOccurrence(after, s)
	assert.Equal(t, time.Date(2025, 2, 1, 2, 0, 0, 0, time.UTC), next)
}

// NextOccurrence monthly with before anchor.
func TestNextOccurrence_Monthly_Before(t *testing.T) {
	// Thursday before the 2nd Tuesday of March 2025.
	// 2nd Tuesday of March 2025 = March 11. Thursday before = March 6.
	s := Schedule{
		Freq:    FreqMonthly,
		Weekday: time.Thursday,
		Before:  &Anchor{Weekday: time.Tuesday, Nth: 2},
		Start:   newTOD(2, 0),
		End:     newTOD(4, 0),
	}
	after := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	next := NextOccurrence(after, s)
	assert.Equal(t, time.Date(2025, 3, 6, 2, 0, 0, 0, time.UTC), next)
}

// Same-weekday rule for before: weekday == before anchor weekday resolves to -7 days.
func TestInWindow_Monthly_Before_SameWeekday_MinusSeven(t *testing.T) {
	// 2nd Tuesday of March 2025 = March 11. Same weekday rule: result = March 11 - 7 = March 4.
	s := Schedule{
		Freq:    FreqMonthly,
		Weekday: time.Tuesday,
		Before:  &Anchor{Weekday: time.Tuesday, Nth: 2},
		Start:   newTOD(2, 0),
		End:     newTOD(4, 0),
	}
	// March 4 is a Tuesday (-7 from March 11).
	assert.True(t, InWindow(time.Date(2025, 3, 4, 3, 0, 0, 0, time.UTC), s))
	// March 11 itself must NOT match (it is the anchor, not -7).
	assert.False(t, InWindow(time.Date(2025, 3, 11, 3, 0, 0, 0, time.UTC), s))
}

// NextOccurrence monthly — after is exactly the window start time, should include it.
func TestNextOccurrence_AtOrAfterSemantics(t *testing.T) {
	nth := 1
	s := Schedule{
		Freq:    FreqMonthly,
		Weekday: time.Thursday,
		Nth:     &nth,
		Start:   newTOD(2, 0),
		End:     newTOD(4, 0),
	}
	// 1st Thursday of March 2025 = March 6. Exact start time.
	exactly := time.Date(2025, 3, 6, 2, 0, 0, 0, time.UTC)
	next := NextOccurrence(exactly, s)
	assert.Equal(t, exactly, next)
}

// NextOccurrence respects the time zone in the provided time.Time.
func TestNextOccurrence_RespectsTimezone(t *testing.T) {
	s := weeklySchedule([]time.Weekday{time.Monday}, newTOD(2, 0), newTOD(4, 0))
	chicago := loc(t, "America/Chicago")
	// Monday 01:00 Chicago — today's start (02:00 Chicago) is still ahead.
	after := time.Date(2025, 3, 3, 1, 0, 0, 0, chicago)
	next := NextOccurrence(after, s)
	assert.Equal(t, time.Date(2025, 3, 3, 2, 0, 0, 0, chicago), next)
}
