// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package schedule

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// rawConfig is the YAML-unmarshal target for a Config block.
type rawConfig struct {
	Timezone  string        `yaml:"timezone"`
	Schedules []rawSchedule `yaml:"schedules"`
}

// rawSchedule is the YAML-unmarshal target for a single schedule entry.
type rawSchedule struct {
	Freq    string     `yaml:"freq"`
	Weekday string     `yaml:"weekday"`
	Days    []string   `yaml:"days"`
	Nth     *int       `yaml:"nth"`
	After   *rawAnchor `yaml:"after"`
	Before  *rawAnchor `yaml:"before"`
	Start   string     `yaml:"start"`
	End     string     `yaml:"end"`
}

type rawAnchor struct {
	Weekday string `yaml:"weekday"`
	Nth     int    `yaml:"nth"`
}

// Parse unmarshals and validates a reboot_window config body (the YAML under
// the reboot_window: key, not including that key itself).
//
// It returns the validated Config, a list of non-blocking warnings (e.g., DST
// issues), and a non-nil error if any validation rule fails.
func Parse(data []byte) (*Config, []string, error) {
	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("unmarshal reboot_window: %w", err)
	}

	if len(raw.Schedules) == 0 {
		return nil, nil, fmt.Errorf("reboot_window: schedules must contain at least one entry")
	}

	// Validate timezone before iterating schedules; we need the location for DST checks.
	var loc *time.Location
	if raw.Timezone != "" && raw.Timezone != "device" {
		var err error
		loc, err = time.LoadLocation(raw.Timezone)
		if err != nil {
			return nil, nil, fmt.Errorf("reboot_window: invalid timezone %q: %w", raw.Timezone, err)
		}
	}

	schedules := make([]Schedule, 0, len(raw.Schedules))
	var warnings []string

	for i, rs := range raw.Schedules {
		s, ws, err := validateSchedule(i, rs, loc)
		if err != nil {
			return nil, nil, err
		}
		schedules = append(schedules, s)
		warnings = append(warnings, ws...)
	}

	return &Config{
		Timezone:  raw.Timezone,
		Schedules: schedules,
	}, warnings, nil
}

func validateSchedule(idx int, rs rawSchedule, loc *time.Location) (Schedule, []string, error) {
	prefix := fmt.Sprintf("schedules[%d]", idx)

	// Validate freq.
	var freq Freq
	switch strings.ToLower(rs.Freq) {
	case "monthly":
		freq = FreqMonthly
	case "weekly":
		freq = FreqWeekly
	case "":
		return Schedule{}, nil, fmt.Errorf("%s: freq is required", prefix)
	default:
		return Schedule{}, nil, fmt.Errorf("%s: invalid freq %q (must be 'monthly' or 'weekly')", prefix, rs.Freq)
	}

	// Validate mutual exclusivity: nth, after, before.
	anchorCount := 0
	if rs.Nth != nil {
		anchorCount++
	}
	if rs.After != nil {
		anchorCount++
	}
	if rs.Before != nil {
		anchorCount++
	}
	if anchorCount > 1 {
		return Schedule{}, nil, fmt.Errorf("%s: nth, after, and before are mutually exclusive; specify exactly one", prefix)
	}

	// Validate freq-scoping rules.
	if freq == FreqWeekly {
		if rs.Nth != nil {
			return Schedule{}, nil, fmt.Errorf("%s: nth is only valid with freq: monthly", prefix)
		}
		if rs.After != nil {
			return Schedule{}, nil, fmt.Errorf("%s: after is only valid with freq: monthly", prefix)
		}
		if rs.Before != nil {
			return Schedule{}, nil, fmt.Errorf("%s: before is only valid with freq: monthly", prefix)
		}
		if len(rs.Days) == 0 {
			return Schedule{}, nil, fmt.Errorf("%s: freq: weekly requires at least one entry in days", prefix)
		}
	}
	if freq == FreqMonthly {
		if len(rs.Days) > 0 {
			return Schedule{}, nil, fmt.Errorf("%s: days: is only valid with freq: weekly", prefix)
		}
		if anchorCount == 0 {
			return Schedule{}, nil, fmt.Errorf("%s: freq: monthly requires exactly one of nth, after, or before", prefix)
		}
	}

	// Parse start time.
	start, err := parseTimeOfDay(rs.Start, false)
	if err != nil {
		return Schedule{}, nil, fmt.Errorf("%s: invalid start %q: %w", prefix, rs.Start, err)
	}

	// Parse end time (24:00 is allowed).
	end, err := parseTimeOfDay(rs.End, true)
	if err != nil {
		return Schedule{}, nil, fmt.Errorf("%s: invalid end %q: %w", prefix, rs.End, err)
	}

	// Build the Schedule.
	s := Schedule{
		Freq:  freq,
		Start: start,
		End:   end,
	}

	switch freq {
	case FreqWeekly:
		days := make([]time.Weekday, 0, len(rs.Days))
		for _, d := range rs.Days {
			wd, err := parseWeekday(d)
			if err != nil {
				return Schedule{}, nil, fmt.Errorf("%s: invalid day %q: %w", prefix, d, err)
			}
			days = append(days, wd)
		}
		s.Days = days

	case FreqMonthly:
		wd, err := parseWeekday(rs.Weekday)
		if err != nil {
			return Schedule{}, nil, fmt.Errorf("%s: invalid weekday %q: %w", prefix, rs.Weekday, err)
		}
		s.Weekday = wd

		switch {
		case rs.Nth != nil:
			nth := *rs.Nth
			s.Nth = &nth
		case rs.After != nil:
			anchorWD, err := parseWeekday(rs.After.Weekday)
			if err != nil {
				return Schedule{}, nil, fmt.Errorf("%s: invalid after.weekday %q: %w", prefix, rs.After.Weekday, err)
			}
			s.After = &Anchor{Weekday: anchorWD, Nth: rs.After.Nth}
		case rs.Before != nil:
			anchorWD, err := parseWeekday(rs.Before.Weekday)
			if err != nil {
				return Schedule{}, nil, fmt.Errorf("%s: invalid before.weekday %q: %w", prefix, rs.Before.Weekday, err)
			}
			s.Before = &Anchor{Weekday: anchorWD, Nth: rs.Before.Nth}
		}
	}

	// DST warning check (requires a concrete timezone location).
	var ws []string
	if loc != nil && !end.EndOfDay {
		if w := dstWarning(s, loc); w != "" {
			ws = append(ws, w)
		}
	}

	return s, ws, nil
}

// parseTimeOfDay parses "HH:MM" or, when allowEndOfDay is true, "24:00".
func parseTimeOfDay(s string, allowEndOfDay bool) (TimeOfDay, error) {
	if s == "" {
		return TimeOfDay{}, fmt.Errorf("time string is empty")
	}
	if allowEndOfDay && s == "24:00" {
		return TimeOfDay{EndOfDay: true}, nil
	}
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return TimeOfDay{}, fmt.Errorf("expected HH:MM format")
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return TimeOfDay{}, fmt.Errorf("hour must be 00–23")
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return TimeOfDay{}, fmt.Errorf("minute must be 00–59")
	}
	return TimeOfDay{Hour: h, Minute: m}, nil
}

// parseWeekday parses a case-insensitive weekday name to time.Weekday.
func parseWeekday(s string) (time.Weekday, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "sunday":
		return time.Sunday, nil
	case "monday":
		return time.Monday, nil
	case "tuesday":
		return time.Tuesday, nil
	case "wednesday":
		return time.Wednesday, nil
	case "thursday":
		return time.Thursday, nil
	case "friday":
		return time.Friday, nil
	case "saturday":
		return time.Saturday, nil
	default:
		return 0, fmt.Errorf("unknown weekday %q", s)
	}
}

// dstWarning checks whether the schedule's entire time window falls inside a
// spring-forward DST-skipped hour in the given location. It scans a 10-year
// window of dates so it catches both near-future and current-year transitions.
//
// Returns a non-empty warning string if a gap is found, or "" if no issue.
func dstWarning(s Schedule, loc *time.Location) string {
	startH, startM := s.Start.Hour, s.Start.Minute
	endH, endM := s.End.Hour, s.End.Minute

	// Scan 10 years starting from 2025.
	for year := 2025; year <= 2035; year++ {
		for month := time.January; month <= time.December; month++ {
			// Find last day of this month.
			lastDay := time.Date(year, month+1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -1).Day()
			for day := 1; day <= lastDay; day++ {
				ts := time.Date(year, month, day, startH, startM, 0, 0, loc)
				te := time.Date(year, month, day, endH, endM, 0, 0, loc)

				startSkipped := ts.Hour() != startH || ts.Minute() != startM
				endSkipped := te.Hour() != endH || te.Minute() != endM

				if startSkipped && endSkipped {
					return fmt.Sprintf(
						"schedule window %02d:%02d–%02d:%02d falls entirely within a spring-forward DST gap on %04d-%02d-%02d (in %s); window will not open that day",
						startH, startM, endH, endM, year, month, day, loc,
					)
				}
			}
		}
	}
	return ""
}
