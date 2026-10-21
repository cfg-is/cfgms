// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package lease

import "time"

// Clock is the time source for a Manager's local-authority arithmetic and for
// SingletonJob's renewal ticker and retry backoff. Production code always uses
// the real clock (NewManager); NewManagerWithClock exists so a test can drive
// lease renewal timing by explicit events instead of racing the wall clock.
//
// The lease row's own expires_at is not governed by this Clock — it is stamped
// and evaluated by the business.LeaseStore on the store's clock (see the
// package doc's split-brain bound).
type Clock interface {
	// Now returns the current instant. The real clock returns time.Now(), whose
	// monotonic reading keeps elapsed-time arithmetic immune to wall-clock
	// steps (ADR-029 Decision 2).
	Now() time.Time
	// Until returns the duration from now until t.
	Until(t time.Time) time.Duration
	// After returns a channel that receives once d has elapsed.
	After(d time.Duration) <-chan time.Time
	// NewTicker returns a Ticker that fires every d.
	NewTicker(d time.Duration) Ticker
}

// Ticker is the subset of *time.Ticker that SingletonJob uses.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// Timer is the subset of *time.Timer that the authority-deadline watchdog uses.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
}

// TimerClock is an optional extension of Clock. A Clock that implements it
// drives SingletonJob's authority-deadline watchdog; any other Clock leaves
// the watchdog on a real timer. It is separate from Clock so existing Clock
// implementations keep compiling.
type TimerClock interface {
	Clock
	// NewTimer returns a Timer that fires once d has elapsed on this clock.
	NewTimer(d time.Duration) Timer
}

// realClock is the production Clock: a thin pass-through to package time.
type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) Until(t time.Time) time.Duration        { return time.Until(t) }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
func (realClock) NewTicker(d time.Duration) Ticker       { return realTicker{time.NewTicker(d)} }

func (realClock) NewTimer(d time.Duration) Timer { return realTimer{time.NewTimer(d)} }

type realTimer struct{ t *time.Timer }

func (r realTimer) C() <-chan time.Time { return r.t.C }
func (r realTimer) Stop() bool          { return r.t.Stop() }

type realTicker struct{ t *time.Ticker }

func (r realTicker) C() <-chan time.Time { return r.t.C }
func (r realTicker) Stop()               { r.t.Stop() }
