// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package authdefense

import (
	"sync"
	"time"
)

// Clock abstracts time operations for deterministic testing
type Clock interface {
	Now() time.Time
	Since(t time.Time) time.Duration
}

// realClock uses the system clock
type realClock struct{}

func (realClock) Now() time.Time                  { return time.Now() }
func (realClock) Since(t time.Time) time.Duration { return time.Since(t) }

// TestClock provides deterministic time control for testing
type TestClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewTestClock creates a TestClock starting at the given time.
// If zero, starts at a fixed point.
func NewTestClock(start time.Time) *TestClock {
	if start.IsZero() {
		start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return &TestClock{now: start}
}

// Now returns the current test time
func (c *TestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Since returns the duration since t using the test clock's current time
func (c *TestClock) Since(t time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.Sub(t)
}

// Advance moves the test clock forward by the given duration
func (c *TestClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
