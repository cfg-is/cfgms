// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package schedule implements the reboot_window schema, parser, and evaluator (ADR-026).
package schedule

import "time"

// Freq is the recurrence frequency for a schedule entry.
type Freq string

const (
	FreqMonthly Freq = "monthly"
	FreqWeekly  Freq = "weekly"
)

// TimeOfDay represents a wall-clock time within a day.
type TimeOfDay struct {
	Hour   int
	Minute int
	// EndOfDay is true when the original YAML value was "24:00".
	EndOfDay bool
}

// minutesSinceMidnight returns the time as minutes since midnight (0–1440).
// "24:00" is treated as 1440 (end-of-day sentinel, never wrapped).
func (t TimeOfDay) minutesSinceMidnight() int {
	if t.EndOfDay {
		return 24 * 60
	}
	return t.Hour*60 + t.Minute
}

// Anchor is the reference point for a monthly after:/before: anchor rule.
type Anchor struct {
	Weekday time.Weekday
	// Nth is the occurrence index within the month. -1 means "last".
	Nth int
}

// Schedule is a single validated entry from the schedules: list.
// All string fields from YAML have been resolved to typed values.
type Schedule struct {
	Freq Freq

	// Weekday is the day the window opens (monthly only).
	Weekday time.Weekday

	// Days is the set of days the window opens (weekly only).
	Days []time.Weekday

	// Nth is set for the plain monthly case (1st, 2nd, … or last=-1).
	// Nil when After or Before is set.
	Nth *int

	// After anchors the window to the first occurrence of Weekday strictly
	// after the anchor day (monthly only). Nil when Nth or Before is set.
	After *Anchor

	// Before anchors the window to the last occurrence of Weekday strictly
	// before the anchor day (monthly only). Nil when Nth or After is set.
	Before *Anchor

	Start TimeOfDay
	End   TimeOfDay
}

// Config is the top-level reboot_window configuration for one device level.
// Timezone is the window-level explicit value only: empty means "not set at
// this level" (inherit from tenant or device); "device" means use the
// endpoint's own zone. Timezone resolution is handled by Story 2 (pkg/maintenance
// cascade layer) and does not belong here.
type Config struct {
	Timezone  string
	Schedules []Schedule
}
