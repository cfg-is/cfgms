// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package patch

import (
	"context"
	"sync"
	"time"
)

// compile-time assertion that the in-memory manager satisfies the CFGMS
// WindowManager contract.
var _ WindowManager = (*InMemoryWindowManager)(nil)

// MaintenanceWindow is a concrete, scheduled maintenance interval. A window is
// active for the half-open range [Start, Start+Duration) and records whether
// reboots and general maintenance are permitted while it is active.
type MaintenanceWindow struct {
	Start            time.Time
	Duration         time.Duration
	AllowReboot      bool
	AllowMaintenance bool
}

// end returns the exclusive end of the window.
func (w MaintenanceWindow) end() time.Time {
	return w.Start.Add(w.Duration)
}

// contains reports whether the window is active at t.
func (w MaintenanceWindow) contains(t time.Time) bool {
	return !t.Before(w.Start) && t.Before(w.end())
}

// InMemoryWindowManager is a real, self-contained implementation of
// WindowManager that evaluates reboot and maintenance permission against a
// concrete schedule of maintenance windows held in memory. It performs the same
// wall-clock evaluation that a schedule-backed manager performs against a
// persisted maintenance calendar, but against an in-memory schedule so tests can
// drive the patch and upgrade managers deterministically.
//
// It is not a mock: every method computes its result from the current time
// relative to real [start, start+duration) intervals. There is no call
// recording or pre-programmed return sequencing. Failure (a schedule store that
// cannot be read) is modelled as a real backend state rather than an injected
// per-method error.
type InMemoryWindowManager struct {
	mu sync.RWMutex

	// now supplies the current time. It defaults to time.Now and exists so the
	// evaluation logic can be driven deterministically without sleeping.
	now func() time.Time

	// windows holds the maintenance schedule for each device.
	windows map[string][]MaintenanceWindow

	// scheduleAvailable models whether the maintenance schedule can be read.
	// When false the manager genuinely has no calendar to evaluate and returns
	// ErrNetworkError, exactly as a store-backed manager would when its backing
	// store is unreachable.
	scheduleAvailable bool
}

// NewInMemoryWindowManager creates an in-memory window manager with an empty
// schedule. A device with no scheduled windows is never in a window, so reboot
// and maintenance are denied until windows are added.
func NewInMemoryWindowManager() *InMemoryWindowManager {
	return &InMemoryWindowManager{
		now:               time.Now,
		windows:           make(map[string][]MaintenanceWindow),
		scheduleAvailable: true,
	}
}

// AddWindow appends a maintenance window to a device's schedule.
func (m *InMemoryWindowManager) AddWindow(deviceID string, window MaintenanceWindow) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.windows[deviceID] = append(m.windows[deviceID], window)
}

// SetScheduleAvailable controls whether the maintenance schedule can be read.
// Setting it false drives real ErrNetworkError responses from every query.
func (m *InMemoryWindowManager) SetScheduleAvailable(available bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scheduleAvailable = available
}

// activeWindow returns the window currently active for the device at now, and
// whether one was found. Callers must hold at least a read lock.
func (m *InMemoryWindowManager) activeWindow(deviceID string, now time.Time) (MaintenanceWindow, bool) {
	for _, w := range m.windows[deviceID] {
		if w.contains(now) {
			return w, true
		}
	}
	return MaintenanceWindow{}, false
}

// IsInWindow reports whether the device is currently inside a maintenance window.
func (m *InMemoryWindowManager) IsInWindow(_ context.Context, deviceID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.scheduleAvailable {
		return false, ErrNetworkError
	}

	_, ok := m.activeWindow(deviceID, m.now())
	return ok, nil
}

// CanReboot reports whether a reboot is permitted right now: the device must be
// inside an active window that allows reboots.
func (m *InMemoryWindowManager) CanReboot(_ context.Context, deviceID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.scheduleAvailable {
		return false, ErrNetworkError
	}

	w, ok := m.activeWindow(deviceID, m.now())
	return ok && w.AllowReboot, nil
}

// CanPerformMaintenance reports whether general maintenance is permitted right
// now: the device must be inside an active window that allows maintenance.
func (m *InMemoryWindowManager) CanPerformMaintenance(_ context.Context, deviceID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.scheduleAvailable {
		return false, ErrNetworkError
	}

	w, ok := m.activeWindow(deviceID, m.now())
	return ok && w.AllowMaintenance, nil
}

// GetNextWindow returns the start time of the next upcoming maintenance window
// for the device. It returns ErrMaintenanceWindowNotActive when no window is
// scheduled in the future.
func (m *InMemoryWindowManager) GetNextWindow(_ context.Context, deviceID string) (time.Time, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.scheduleAvailable {
		return time.Time{}, ErrNetworkError
	}

	now := m.now()
	var next time.Time
	found := false
	for _, w := range m.windows[deviceID] {
		if w.Start.After(now) && (!found || w.Start.Before(next)) {
			next = w.Start
			found = true
		}
	}

	if !found {
		return time.Time{}, ErrMaintenanceWindowNotActive
	}

	return next, nil
}
