// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package schedule

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// MarshalYAML encodes Config back to the human-readable raw form that Parse accepts,
// so that a StewardConfig containing a *Config round-trips through yaml.Marshal /
// yaml.Unmarshal unchanged.
func (c Config) MarshalYAML() (interface{}, error) {
	raw := rawConfig{
		Timezone:  c.Timezone,
		Schedules: make([]rawSchedule, len(c.Schedules)),
	}
	for i, s := range c.Schedules {
		raw.Schedules[i] = toRawSchedule(s)
	}
	return raw, nil
}

// UnmarshalYAML decodes a YAML node for a reboot_window block by re-encoding the
// node to bytes and passing them through Parse, which validates the schedule.
func (c *Config) UnmarshalYAML(value *yaml.Node) error {
	data, err := yaml.Marshal(value)
	if err != nil {
		return fmt.Errorf("reboot_window: cannot re-encode yaml node: %w", err)
	}
	parsed, _, err := Parse(data)
	if err != nil {
		return err
	}
	*c = *parsed
	return nil
}

func weekdayName(w time.Weekday) string {
	switch w {
	case time.Sunday:
		return "sunday"
	case time.Monday:
		return "monday"
	case time.Tuesday:
		return "tuesday"
	case time.Wednesday:
		return "wednesday"
	case time.Thursday:
		return "thursday"
	case time.Friday:
		return "friday"
	case time.Saturday:
		return "saturday"
	default:
		return fmt.Sprintf("unknown(%d)", int(w))
	}
}

func formatTimeOfDay(t TimeOfDay) string {
	if t.EndOfDay {
		return "24:00"
	}
	return fmt.Sprintf("%02d:%02d", t.Hour, t.Minute)
}

func toRawSchedule(s Schedule) rawSchedule {
	rs := rawSchedule{
		Freq:  string(s.Freq),
		Start: formatTimeOfDay(s.Start),
		End:   formatTimeOfDay(s.End),
	}

	switch s.Freq {
	case FreqWeekly:
		rs.Days = make([]string, len(s.Days))
		for i, d := range s.Days {
			rs.Days[i] = weekdayName(d)
		}
	case FreqMonthly:
		rs.Weekday = weekdayName(s.Weekday)
		switch {
		case s.Nth != nil:
			nth := *s.Nth
			rs.Nth = &nth
		case s.After != nil:
			rs.After = &rawAnchor{
				Weekday: weekdayName(s.After.Weekday),
				Nth:     s.After.Nth,
			}
		case s.Before != nil:
			rs.Before = &rawAnchor{
				Weekday: weekdayName(s.Before.Weekday),
				Nth:     s.Before.Nth,
			}
		}
	}

	return rs
}
