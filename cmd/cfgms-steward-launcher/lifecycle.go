// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// Supervisor exec's the steward and decides what to do when it exits.
//
// The lifecycle contract is intentionally simple for the Phase-1 launcher:
//
//   - Exit code 0 after at least StartupWindow elapsed → restart (operator
//     stopped the steward intentionally, or the service manager sent stop;
//     normal restart in either case).
//   - Exit code != 0 or any exit BEFORE StartupWindow elapsed → consider
//     the current version "broken." If a previous version is recorded,
//     roll back and exec from there. If no previous, exit non-zero and let
//     the OS service manager retry per its recovery actions.
//
// The launcher itself never panics on these branches. Edge cases (missing
// binary, version-file pointing at nothing on disk) surface as errors
// returned from Supervise; main() translates them to non-zero exits.
type Supervisor struct {
	// Layout describes the on-disk binary layout.
	Layout Layout

	// StartupWindow is the time a child must stay running before we
	// consider its start "healthy." A child that exits inside this window
	// is treated as a failed upgrade — auto-rollback fires.
	StartupWindow time.Duration

	// MaxRollbackCycles caps how many times we will roll back per Supervise
	// call. Without this, a pair of binaries that each fail their startup
	// window would ping-pong indefinitely. Default 1 — one fall-back, then
	// give up.
	MaxRollbackCycles int

	// Stdout / Stderr are the streams the child inherits. Tests inject
	// buffers; production callers pass os.Stdout / os.Stderr so the
	// service-manager log captures the child output.
	Stdout io.Writer
	Stderr io.Writer

	// ExtraArgs are appended to the child's argv after argv[0]. Production
	// callers leave it empty; the OS service manager arranges --regtoken
	// (and any other steward CLI flags) via the registered service-binPath
	// arguments. Tests set this to control what their fake child does.
	ExtraArgs []string

	// clock is injectable for tests; production uses time.Now / time.Since.
	clock clock
}

type clock interface {
	Now() time.Time
	Since(time.Time) time.Duration
}

type realClock struct{}

func (realClock) Now() time.Time              { return time.Now() }
func (realClock) Since(t time.Time) time.Duration { return time.Since(t) }

// Supervise runs the supervision loop until ctx is cancelled, the child
// exits normally without triggering rollback, or all rollback attempts are
// exhausted.
//
// Returns nil if the child completed normally; an error describing the
// final fault otherwise.
func (s *Supervisor) Supervise(ctx context.Context) error {
	if s.clock == nil {
		s.clock = realClock{}
	}
	if s.StartupWindow <= 0 {
		s.StartupWindow = 30 * time.Second
	}
	// MaxRollbackCycles: zero (or negative) is a legitimate operator
	// choice — "no auto-rollback, just fail-fast and let the OS service
	// manager retry per its recovery policy." The previous behaviour
	// silently coerced 0 → 1, which masked the operator's intent and
	// confused review tests. Only negative values get coerced (they
	// represent a programming mistake, not a deliberate choice).
	if s.MaxRollbackCycles < 0 {
		s.MaxRollbackCycles = 0
	}

	rollbacksRemaining := s.MaxRollbackCycles
	for {
		current, err := s.Layout.ReadCurrent()
		if err != nil {
			return fmt.Errorf("launcher: read current version: %w", err)
		}
		if current == "" {
			return errors.New("launcher: no current version recorded — install layout is missing or corrupt")
		}

		exe, err := s.Layout.StewardExeFor(current)
		if err != nil {
			return fmt.Errorf("launcher: resolve steward exe for %q: %w", current, err)
		}
		if _, statErr := os.Stat(exe); statErr != nil {
			return fmt.Errorf("launcher: steward exe %q for version %q is missing: %w", exe, current, statErr)
		}

		started := s.clock.Now()
		exitErr := s.execOnce(ctx, exe)
		ranFor := s.clock.Since(started)

		// Context cancelled → service manager is shutting us down.
		// Distinguish two sub-cases:
		//   (a) The child was still running when ctx fired and got
		//       killed by exec.CommandContext. exitErr is non-nil but
		//       reflects the cancellation, not a child fault. Return
		//       nil so the service manager logs a clean shutdown.
		//   (b) The child had ALREADY crashed by the time ctx fired —
		//       e.g. SIGTERM and a crash arriving in the same scheduler
		//       turn during an in-progress upgrade. exitErr is non-nil
		//       AND ranFor < StartupWindow. Discarding this as "just a
		//       cancellation" would silently mask the upgrade failure.
		//       Differentiate by checking whether the child had time
		//       to exit on its own: a child that ran past StartupWindow
		//       definitionally wasn't crashing-during-startup, so
		//       treat its exit as graceful regardless of code. A child
		//       that exited inside the window with a non-zero code
		//       gets the failure surfaced even on cancel.
		if ctx.Err() != nil {
			failedStartupOnCancel := ranFor < s.StartupWindow && exitErr != nil
			if !failedStartupOnCancel {
				return nil
			}
			// Fall through to the rollback logic below — this looks
			// like a real upgrade failure that happened to coincide
			// with a cancel. The operator (or the next startup) will
			// observe the rolled-back state.
		}

		failedStartup := ranFor < s.StartupWindow
		nonZeroExit := exitErr != nil

		if !failedStartup && !nonZeroExit {
			// Child stayed up past the startup window then exited cleanly.
			// Normal restart-on-clean-exit path.
			continue
		}

		// Anything else (early exit OR non-zero exit) is a "broken
		// child" signal. Attempt rollback if we have a previous version
		// AND we haven't exhausted our budget.
		previous, perr := s.Layout.ReadPrevious()
		if perr != nil {
			return fmt.Errorf("launcher: read previous version after child failure: %w", perr)
		}
		if previous == "" || rollbacksRemaining == 0 {
			if exitErr != nil {
				return fmt.Errorf("launcher: child failed (ran for %s) and no rollback available: %w", ranFor, exitErr)
			}
			return fmt.Errorf("launcher: child exited inside startup window (%s) and no rollback available", ranFor)
		}

		newCurrent, rbErr := s.Layout.Rollback()
		if rbErr != nil {
			return fmt.Errorf("launcher: rollback after child failure: %w", rbErr)
		}
		rollbacksRemaining--
		fmt.Fprintf(s.Stderr, "launcher: rolled back to version %q after child failure (ran for %s)\n", newCurrent, ranFor)
	}
}

// execOnce runs the child to completion, returning any non-nil error from
// Wait. The child inherits the launcher's stdin/stdout/stderr (overridable
// in tests via Supervisor.Stdout / .Stderr). The child also receives any
// ExtraArgs.
func (s *Supervisor) execOnce(ctx context.Context, exe string) error {
	cmd := exec.CommandContext(ctx, exe, s.ExtraArgs...) //#nosec G204 -- exe path is validated via Layout
	cmd.Stdin = os.Stdin
	cmd.Stdout = s.Stdout
	cmd.Stderr = s.Stderr
	return cmd.Run()
}
