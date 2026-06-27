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
	"path/filepath"
	"time"

	"github.com/cfgis/cfgms/pkg/version"
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

	// CertStoreDir is the directory where upgrade flag files (upgrade-committed,
	// upgrade-rolled-back) are written so the steward process can emit the
	// corresponding lifecycle events to the controller on reconnect.
	// Set from --cert-store-dir in production; tests set it directly via t.TempDir().
	// If empty, flag-file writes are skipped (no cert store configured).
	CertStoreDir string

	// RetentionPolicy controls pruning of old version directories under
	// <Root>/versions/ after each successful (committed) startup.
	// Zero value means no pruning occurs.
	RetentionPolicy RetentionPolicy
}

type clock interface {
	Now() time.Time
	Since(time.Time) time.Duration
}

type realClock struct{}

func (realClock) Now() time.Time                  { return time.Now() }
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

		// Compute the binary hash AFTER the child exits. Hashing before exec
		// would delay the child launch on every restart — for a large binary
		// the I/O adds hundreds of milliseconds, creating a window where a
		// caller that checks connection state may observe stale "connected"
		// from the previous process and dispatch a command to the dead
		// connection. Hashing after exec still catches on-disk replacements:
		// if the binary was swapped while the child ran, the new hash differs
		// from the stored known-good hash and probation rules apply correctly.
		exeHash, hashErr := computeBinaryHash(exe)
		isKnownGood := false
		if hashErr == nil {
			if kgPS, kgErr := s.Layout.loadState(); kgErr == nil {
				isKnownGood = kgPS.KnownGood == current && kgPS.KnownGoodHash == exeHash
			}
		}
		// If the binary cannot be hashed (deleted, permission error), isKnownGood
		// stays false — conservative treatment applies probation rules. This does
		// not abort supervision; the stat check at the top of the next iteration
		// will surface a missing-binary error if the file is truly gone.

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
			// A known-good version that fast-exits coinciding with a
			// context cancel is an environmental fault (e.g. WMI race on
			// boot), not an upgrade failure. Return clean shutdown rather
			// than rolling back or looping on a cancelled context.
			if isKnownGood {
				return nil
			}
			// Fall through to the rollback logic below — this looks
			// like a real upgrade failure that happened to coincide
			// with a cancel. The operator (or the next startup) will
			// observe the rolled-back state.
		} else if exitErr == nil {
			// Detect an intentional upgrade self-exit: the steward called
			// StageBinary (which advances state.json.current to the new version)
			// then exited cleanly so the launcher re-execs the staged binary.
			// This must NOT be treated as a startup failure — skip the rollback
			// guard and loop to exec the new current version.
			if after, readErr := s.Layout.ReadCurrent(); readErr == nil && after != current {
				continue
			}
		}

		failedStartup := ranFor < s.StartupWindow
		nonZeroExit := exitErr != nil

		if !failedStartup && !nonZeroExit {
			// Child stayed up past the startup window then exited cleanly.
			// Reset the failure counter, persist the known-good marker, and
			// prune old version directories. Write the committed flag file
			// last so its presence is a reliable completion signal for tests
			// and the steward process.
			if ps, loadErr := s.Layout.loadState(); loadErr == nil {
				ps.ConsecutiveFailures = 0
				// Only update the known-good marker if the post-exec hash
				// succeeded; if it failed (binary deleted/unreadable after
				// run) leave any existing marker untouched.
				if hashErr == nil {
					ps.KnownGood = current
					ps.KnownGoodHash = exeHash
				}
				if saveErr := s.Layout.saveState(ps); saveErr != nil {
					_, _ = fmt.Fprintf(s.Stderr, "launcher: save state after commit: %v\n", saveErr)
				}
			} else {
				_, _ = fmt.Fprintf(s.Stderr, "launcher: load state for counter reset: %v\n", loadErr)
			}
			if _, pruneErr := pruneVersions(s.Layout.VersionsDir(), current, s.RetentionPolicy, s.clock.Now()); pruneErr != nil {
				_, _ = fmt.Fprintf(s.Stderr, "launcher: retention prune: %v\n", pruneErr)
			}
			if flagErr := s.writeFlagFile("upgrade-committed", current); flagErr != nil {
				_, _ = fmt.Fprintf(s.Stderr, "launcher: write upgrade-committed flag: %v\n", flagErr)
			}
			continue
		}

		// Anything else (early exit OR non-zero exit) is a "broken child"
		// signal. Increment the consecutive-failure counter on any non-clean
		// exit regardless of whether a rollback will fire.
		if ps, loadErr := s.Layout.loadState(); loadErr == nil {
			ps.ConsecutiveFailures++
			if saveErr := s.Layout.saveState(ps); saveErr != nil {
				_, _ = fmt.Fprintf(s.Stderr, "launcher: save state on failure: %v\n", saveErr)
			}
		} else {
			_, _ = fmt.Fprintf(s.Stderr, "launcher: load state for failure counter: %v\n", loadErr)
		}

		// Known-good fast-exit: a proven binary that exits inside the startup
		// window is suffering a transient environmental fault (e.g. a boot-time
		// dependency race), not an upgrade regression. Restart it in place so
		// SCM recovery and the OS backoff handle persistence — never roll back
		// a binary that has already proven healthy (Issue #2033).
		if isKnownGood && failedStartup {
			_, _ = fmt.Fprintf(s.Stderr, "launcher: version %q is known-good — restarting in place after fast exit (ran %s); rollback suppressed\n", current, ranFor)
			continue
		}

		// Attempt rollback if we have a previous version AND budget.
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

		// Rollback is going to fire: write the flag file with the version we
		// are rolling back TO (previous), which will be the version the steward
		// process is running when it reconnects and reads the flag.
		if flagErr := s.writeFlagFile("upgrade-rolled-back", previous); flagErr != nil {
			_, _ = fmt.Fprintf(s.Stderr, "launcher: write upgrade-rolled-back flag: %v\n", flagErr)
		}

		newCurrent, rbErr := s.Layout.Rollback()
		if rbErr != nil {
			return fmt.Errorf("launcher: rollback after child failure: %w", rbErr)
		}
		rollbacksRemaining--
		_, _ = fmt.Fprintf(s.Stderr, "launcher: rolled back to version %q after child failure (ran for %s)\n", newCurrent, ranFor)
	}
}

// execOnce runs the child to completion, returning any non-nil error from
// Wait. The child inherits the launcher's stdin/stdout/stderr (overridable
// in tests via Supervisor.Stdout / .Stderr). The child also receives any
// ExtraArgs.
//
// On Windows, the child is assigned to a Job Object with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE so that an abnormal launcher exit
// (SCM TerminateProcess, crash, panic-without-defer) takes the steward
// with it (#1928). attachChildToJobObject is a no-op on POSIX —
// process-group / pdeathsig semantics already cover that case.
func (s *Supervisor) execOnce(ctx context.Context, exe string) error {
	cmd := exec.CommandContext(ctx, exe, s.ExtraArgs...) //#nosec G204 -- exe path is validated via Layout
	cmd.Stdin = os.Stdin
	cmd.Stdout = s.Stdout
	cmd.Stderr = s.Stderr
	// Mark the child as launcher-managed. The steward gates its pushed-upgrade
	// self-exit on this marker: it only self-exits (so we re-exec the staged
	// binary) when supervised by a launcher. A bare/standalone steward must not
	// self-exit. (Issue #2003)
	cmd.Env = append(os.Environ(), version.EnvStewardLauncherManaged+"=1")
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := attachChildToJobObject(cmd); err != nil {
		// Best-effort: if the assignment fails, the child is already
		// running and orphaning it on launcher exit is the very bug we
		// were trying to prevent. Kill the child and return so the
		// supervisor can decide whether to retry / rollback. Surface
		// any kill/wait error in the wrapped message so an unkillable
		// child (very rare; insufficient privilege under a restricted
		// token) does not hide as a plain attach failure while a
		// fully-unsupervised steward keeps running.
		killErr := cmd.Process.Kill()
		waitErr := cmd.Wait()
		if killErr != nil || waitErr != nil {
			return fmt.Errorf("attachChildToJobObject failed: %w (cleanup: kill=%v wait=%v)", err, killErr, waitErr)
		}
		return fmt.Errorf("attachChildToJobObject failed: %w", err)
	}
	return cmd.Wait()
}

// writeFlagFile atomically writes a version string to a named flag file in
// CertStoreDir. The steward process reads these files on startup to emit the
// corresponding upgrade lifecycle events to the controller.
//
// If CertStoreDir is empty the write is skipped silently — this allows tests
// that do not care about flag files to omit the field.
func (s *Supervisor) writeFlagFile(name, version string) error {
	if s.CertStoreDir == "" {
		return nil
	}
	if err := os.MkdirAll(s.CertStoreDir, 0o755); err != nil {
		return err
	}
	dst := filepath.Join(s.CertStoreDir, name)
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, []byte(version+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
