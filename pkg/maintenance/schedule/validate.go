// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package schedule

import (
	"fmt"
	"time"
)

// Validate checks that cfg is a structurally valid, fully-parsed Config.
// It mirrors the invariants enforced during Parse; use it when a Config has
// been constructed programmatically or deserialized outside of Parse.
func Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("reboot_window: config is nil")
	}
	if len(cfg.Schedules) == 0 {
		return fmt.Errorf("reboot_window: schedules must contain at least one entry")
	}
	if cfg.Timezone != "" && cfg.Timezone != "device" {
		if _, err := time.LoadLocation(cfg.Timezone); err != nil {
			return fmt.Errorf("reboot_window: invalid timezone %q: %w", cfg.Timezone, err)
		}
	}
	for i, s := range cfg.Schedules {
		if err := validateParsedSchedule(i, s); err != nil {
			return err
		}
	}
	return nil
}

func validateParsedSchedule(idx int, s Schedule) error {
	prefix := fmt.Sprintf("schedules[%d]", idx)
	switch s.Freq {
	case FreqMonthly, FreqWeekly:
		// valid
	default:
		return fmt.Errorf("%s: invalid freq %q", prefix, s.Freq)
	}

	anchorCount := 0
	if s.Nth != nil {
		anchorCount++
	}
	if s.After != nil {
		anchorCount++
	}
	if s.Before != nil {
		anchorCount++
	}

	if s.Freq == FreqWeekly {
		if len(s.Days) == 0 {
			return fmt.Errorf("%s: freq weekly requires at least one day", prefix)
		}
		if anchorCount > 0 {
			return fmt.Errorf("%s: nth/after/before are only valid with freq monthly", prefix)
		}
	}

	if s.Freq == FreqMonthly {
		if len(s.Days) > 0 {
			return fmt.Errorf("%s: days is only valid with freq weekly", prefix)
		}
		if anchorCount != 1 {
			return fmt.Errorf("%s: freq monthly requires exactly one of nth, after, or before", prefix)
		}
	}

	return nil
}
