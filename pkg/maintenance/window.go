// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package maintenance provides system-wide maintenance window management.
// This enables all operations (patching, reboots, updates) to honor maintenance windows.
package maintenance

import (
	"context"
	"fmt"
	"time"
)

// WindowManager manages maintenance windows and reboot permissions
type WindowManager interface {
	// CanReboot checks if a reboot is allowed at the current time
	CanReboot(ctx context.Context, deviceID string) (bool, error)

	// CanPerformMaintenance checks if maintenance operations are allowed
	CanPerformMaintenance(ctx context.Context, deviceID string) (bool, error)

	// GetNextWindow returns the next maintenance window start time
	GetNextWindow(ctx context.Context, deviceID string) (time.Time, error)

	// IsInWindow checks if the current time is within a maintenance window
	IsInWindow(ctx context.Context, deviceID string) (bool, error)
}

// Window represents a maintenance window configuration
type Window struct {
	// Schedule defines when the window occurs (cron format or named schedule)
	Schedule string `yaml:"schedule" json:"schedule"`

	// Duration is how long the window lasts
	Duration time.Duration `yaml:"duration" json:"duration"`

	// Timezone for the schedule (default: UTC)
	Timezone string `yaml:"timezone" json:"timezone"`

	// DeferReboot determines if reboots outside the window should be deferred
	DeferReboot bool `yaml:"defer_reboot" json:"defer_reboot"`

	// MaxDeferDays is the maximum number of days a reboot can be deferred
	MaxDeferDays int `yaml:"max_defer_days" json:"max_defer_days"`

	// RespectUserPresence determines if the window should be skipped if a user is logged in
	RespectUserPresence bool `yaml:"respect_user_presence" json:"respect_user_presence"`

	// AllowOverride determines if the window can be overridden for emergency operations
	AllowOverride bool `yaml:"allow_override" json:"allow_override"`
}

// Policy defines the maintenance window policy for a device/group/client
type Policy struct {
	// Enabled determines if maintenance windows are enforced
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Windows defines one or more maintenance windows
	Windows []Window `yaml:"windows" json:"windows"`

	// DefaultAction defines what happens outside maintenance windows
	// Options: "defer", "allow", "deny"
	DefaultAction string `yaml:"default_action" json:"default_action"`

	// EmergencyBypass allows emergency operations to bypass windows
	EmergencyBypass bool `yaml:"emergency_bypass" json:"emergency_bypass"`
}

// Manager implements WindowManager for maintenance window management
type Manager struct {
	policy Policy
	parser ScheduleParser
}

// ScheduleParser parses schedule strings into concrete times
type ScheduleParser interface {
	// Parse converts a schedule string to the next occurrence
	Parse(schedule string, timezone string) (time.Time, error)

	// IsInSchedule checks if the current time matches the schedule
	IsInSchedule(schedule string, timezone string, now time.Time) (bool, error)
}

// NewManager creates a new maintenance window manager
func NewManager(policy Policy, parser ScheduleParser) *Manager {
	if parser == nil {
		parser = &defaultParser{}
	}

	return &Manager{
		policy: policy,
		parser: parser,
	}
}

// CanReboot checks if a reboot is allowed at the current time
func (m *Manager) CanReboot(ctx context.Context, deviceID string) (bool, error) {
	// If maintenance windows are not enabled, allow reboots
	if !m.policy.Enabled {
		return true, nil
	}

	// Check if we're in a maintenance window
	inWindow, err := m.IsInWindow(ctx, deviceID)
	if err != nil {
		return false, fmt.Errorf("failed to check maintenance window: %w", err)
	}

	// If we're in a window, allow reboot
	if inWindow {
		return true, nil
	}

	// Outside window - check default action
	switch m.policy.DefaultAction {
	case "allow":
		return true, nil
	case "deny":
		return false, nil
	case "defer":
		// Check if deferral limit has been reached
		// In a real implementation, this would check the last reboot attempt time
		// and compare against MaxDeferDays
		return false, nil
	default:
		// Default to defer for safety
		return false, nil
	}
}

// CanPerformMaintenance checks if maintenance operations are allowed
func (m *Manager) CanPerformMaintenance(ctx context.Context, deviceID string) (bool, error) {
	// Maintenance operations follow the same rules as reboots
	return m.CanReboot(ctx, deviceID)
}

// GetNextWindow returns the next maintenance window start time
func (m *Manager) GetNextWindow(ctx context.Context, deviceID string) (time.Time, error) {
	if !m.policy.Enabled || len(m.policy.Windows) == 0 {
		return time.Time{}, fmt.Errorf("no maintenance windows configured")
	}

	// Find the earliest next window from all configured windows
	var nextWindow time.Time
	for _, window := range m.policy.Windows {
		windowTime, err := m.parser.Parse(window.Schedule, window.Timezone)
		if err != nil {
			continue
		}

		if nextWindow.IsZero() || windowTime.Before(nextWindow) {
			nextWindow = windowTime
		}
	}

	if nextWindow.IsZero() {
		return time.Time{}, fmt.Errorf("no valid maintenance windows found")
	}

	return nextWindow, nil
}

// IsInWindow checks if the current time is within a maintenance window
func (m *Manager) IsInWindow(ctx context.Context, deviceID string) (bool, error) {
	if !m.policy.Enabled || len(m.policy.Windows) == 0 {
		return false, nil
	}

	now := time.Now()

	// Check each window to see if we're currently in it
	for _, window := range m.policy.Windows {
		inSchedule, err := m.parser.IsInSchedule(window.Schedule, window.Timezone, now)
		if err != nil {
			continue
		}

		if inSchedule {
			return true, nil
		}
	}

	return false, nil
}

// defaultParser provides a simple schedule parser for common formats
type defaultParser struct{}

func (p *defaultParser) Parse(schedule string, timezone string) (time.Time, error) {
	// Parse common schedule formats
	// For now, implement basic named schedules

	loc := time.UTC
	if timezone != "" {
		location, err := time.LoadLocation(timezone)
		if err == nil {
			loc = location
		}
	}

	now := time.Now().In(loc)

	// Handle named schedules
	switch schedule {
	case "daily_2am":
		next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, loc)
		if now.After(next) {
			next = next.Add(24 * time.Hour)
		}
		return next, nil

	case "daily_3am":
		next := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, loc)
		if now.After(next) {
			next = next.Add(24 * time.Hour)
		}
		return next, nil

	case "sunday_3am":
		// Find next Sunday at 3am
		next := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, loc)
		// Calculate days until next Sunday
		daysUntilSunday := (7 - int(now.Weekday())) % 7
		if daysUntilSunday == 0 && now.Hour() >= 3 {
			daysUntilSunday = 7
		}
		next = next.Add(time.Duration(daysUntilSunday) * 24 * time.Hour)
		return next, nil

	default:
		// For other formats, return a default time in the future
		return now.Add(24 * time.Hour), nil
	}
}

func (p *defaultParser) IsInSchedule(schedule string, timezone string, now time.Time) (bool, error) {
	loc := time.UTC
	if timezone != "" {
		location, err := time.LoadLocation(timezone)
		if err == nil {
			loc = location
		}
	}

	localNow := now.In(loc)

	// Handle named schedules
	switch schedule {
	case "daily_2am":
		// Check if it's between 2am and 4am (assuming 2-hour window)
		return localNow.Hour() >= 2 && localNow.Hour() < 4, nil

	case "daily_3am":
		// Check if it's between 3am and 5am
		return localNow.Hour() >= 3 && localNow.Hour() < 5, nil

	case "sunday_3am":
		// Check if it's Sunday and between 3am and 5am
		return localNow.Weekday() == time.Sunday && localNow.Hour() >= 3 && localNow.Hour() < 5, nil

	default:
		return false, nil
	}
}

// DefaultPolicy returns a default maintenance window policy
func DefaultPolicy() Policy {
	return Policy{
		Enabled:         false, // Disabled by default for backwards compatibility
		DefaultAction:   "allow",
		EmergencyBypass: true,
		Windows: []Window{
			{
				Schedule:            "sunday_3am",
				Duration:            2 * time.Hour,
				Timezone:            "UTC",
				DeferReboot:         true,
				MaxDeferDays:        30,
				RespectUserPresence: true,
				AllowOverride:       true,
			},
		},
	}
}
