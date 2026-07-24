// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package schedule

import "time"

// InWindow reports whether now falls inside the schedule's reboot window.
//
// Evaluation semantics (ADR-026 §"Evaluation semantics (authoritative)"):
//
//	if end > start:   inWindow = start <= now.time <= end
//	else:             inWindow = now.time >= start || now.time <= end  (midnight-wrap)
//
// The day selector applies to the start day. For midnight-wrapping windows:
// the "now.time >= start" branch checks today; the "now.time <= end" branch
// checks whether yesterday was a scheduled start day.
//
// now must already be in the schedule's resolved timezone (timezone resolution
// is handled by the pkg/maintenance cascade layer, not this package).
func InWindow(now time.Time, s Schedule) bool {
	nowMin := now.Hour()*60 + now.Minute()
	startMin := s.Start.minutesSinceMidnight()
	endMin := s.End.minutesSinceMidnight()

	if endMin > startMin {
		// Non-wrapping window (includes end: "24:00" since 1440 > any start).
		if nowMin < startMin || nowMin > endMin {
			return false
		}
		return isScheduledDay(now, s)
	}

	// Midnight-wrapping window (start > end).
	if nowMin >= startMin {
		return isScheduledDay(now, s)
	}
	if nowMin <= endMin {
		return isScheduledDay(now.AddDate(0, 0, -1), s)
	}
	return false
}

// NextOccurrence returns the next window start time at or after the given time.
//
// now must already be in the schedule's resolved timezone.
func NextOccurrence(after time.Time, s Schedule) time.Time {
	// Try today's start time first (handles "at or after" semantics).
	todayStart := time.Date(after.Year(), after.Month(), after.Day(),
		s.Start.Hour, s.Start.Minute, 0, 0, after.Location())
	if !todayStart.Before(after) && isScheduledDay(todayStart, s) {
		return todayStart
	}

	// Search forward day by day (bounded to avoid infinite loops on invalid input).
	day := after.AddDate(0, 0, 1)
	for range 400 {
		candidate := time.Date(day.Year(), day.Month(), day.Day(),
			s.Start.Hour, s.Start.Minute, 0, 0, after.Location())
		if isScheduledDay(candidate, s) {
			return candidate
		}
		day = day.AddDate(0, 0, 1)
	}

	return time.Time{} // unreachable for well-formed schedules
}

// isScheduledDay reports whether the calendar date of t is a scheduled start
// day according to s.
func isScheduledDay(t time.Time, s Schedule) bool {
	switch s.Freq {
	case FreqWeekly:
		for _, d := range s.Days {
			if t.Weekday() == d {
				return true
			}
		}
		return false
	case FreqMonthly:
		return isMonthlyScheduledDay(t, s)
	default:
		return false
	}
}

// isMonthlyScheduledDay reports whether t falls on the monthly schedule's
// computed date. It checks both t's own month and the adjacent month to handle
// cross-month boundary cases:
//   - after: an anchor at the end of month M can push the result into M+1
//     (e.g., Saturday after the last Thursday of January may fall in February).
//   - before: an anchor at the start of month M can pull the result into M-1
//     (e.g., Saturday before the first Monday of March may fall in February).
func isMonthlyScheduledDay(t time.Time, s Schedule) bool {
	if t.Weekday() != s.Weekday {
		return false
	}

	y, m := t.Year(), t.Month()

	// Primary check: resolve from t's own month.
	if sameDay(resolveMonthlyDate(y, m, s), t) {
		return true
	}

	// Cross-month: for after anchors, check whether the previous month's
	// anchor resolution overflows into the current month.
	if s.After != nil {
		py, pm := shiftMonth(y, m, -1)
		return sameDay(resolveMonthlyDate(py, pm, s), t)
	}

	// Cross-month: for before anchors, check whether the next month's
	// anchor resolution underflows into the current month.
	if s.Before != nil {
		ny, nm := shiftMonth(y, m, +1)
		return sameDay(resolveMonthlyDate(ny, nm, s), t)
	}

	return false
}

// resolveMonthlyDate returns the concrete scheduled date for a monthly schedule
// in the given year/month, without regard to month boundaries.
func resolveMonthlyDate(y int, m time.Month, s Schedule) time.Time {
	switch {
	case s.Nth != nil:
		nth := *s.Nth
		if nth == -1 {
			return lastWeekdayOfMonth(y, m, s.Weekday)
		}
		return nthWeekdayOfMonth(y, m, s.Weekday, nth)
	case s.After != nil:
		return weekdayAfterAnchor(y, m, s.Weekday, s.After.Weekday, s.After.Nth)
	case s.Before != nil:
		return weekdayBeforeAnchor(y, m, s.Weekday, s.Before.Weekday, s.Before.Nth)
	default:
		return time.Time{}
	}
}

// shiftMonth returns the year and month delta months away from (y, m).
func shiftMonth(y int, m time.Month, delta int) (int, time.Month) {
	t := time.Date(y, m, 1, 0, 0, 0, 0, time.UTC).AddDate(0, delta, 0)
	return t.Year(), t.Month()
}

// sameDay reports whether a and b fall on the same calendar date.
func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

// nthWeekdayOfMonth returns the nth occurrence of wd in year/month.
// nth must be >= 1; use lastWeekdayOfMonth for nth == -1.
func nthWeekdayOfMonth(year int, month time.Month, wd time.Weekday, nth int) time.Time {
	first := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
	daysToFirst := (int(wd) - int(first.Weekday()) + 7) % 7
	return first.AddDate(0, 0, daysToFirst+(nth-1)*7)
}

// lastWeekdayOfMonth returns the last occurrence of wd in year/month.
// The implementation is anchored to the first day of the next month (handles
// 28/29/30/31-day months uniformly without a day-count table).
func lastWeekdayOfMonth(year int, month time.Month, wd time.Weekday) time.Time {
	// Last day of month = first day of next month minus one day.
	lastDay := time.Date(year, month+1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -1)
	daysBack := (int(lastDay.Weekday()) - int(wd) + 7) % 7
	return lastDay.AddDate(0, 0, -daysBack)
}

// anchorDate returns the anchor occurrence for after/before rules.
func anchorDate(year int, month time.Month, anchorWD time.Weekday, anchorNth int) time.Time {
	if anchorNth == -1 {
		return lastWeekdayOfMonth(year, month, anchorWD)
	}
	return nthWeekdayOfMonth(year, month, anchorWD, anchorNth)
}

// weekdayAfterAnchor returns the first occurrence of wd strictly after the
// anchor date. When wd == anchorWD, the same-weekday rule applies: +7 days
// (ADR-026 validation rule 3).
func weekdayAfterAnchor(year int, month time.Month, wd time.Weekday, anchorWD time.Weekday, anchorNth int) time.Time {
	anchor := anchorDate(year, month, anchorWD, anchorNth)
	if wd == anchorWD {
		return anchor.AddDate(0, 0, 7)
	}
	daysAfter := (int(wd) - int(anchor.Weekday()) + 7) % 7
	if daysAfter == 0 {
		daysAfter = 7
	}
	return anchor.AddDate(0, 0, daysAfter)
}

// weekdayBeforeAnchor returns the last occurrence of wd strictly before the
// anchor date. When wd == anchorWD, the same-weekday rule applies: -7 days.
func weekdayBeforeAnchor(year int, month time.Month, wd time.Weekday, anchorWD time.Weekday, anchorNth int) time.Time {
	anchor := anchorDate(year, month, anchorWD, anchorNth)
	if wd == anchorWD {
		return anchor.AddDate(0, 0, -7)
	}
	daysBack := (int(anchor.Weekday()) - int(wd) + 7) % 7
	if daysBack == 0 {
		daysBack = 7
	}
	return anchor.AddDate(0, 0, -daysBack)
}
