// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
//     the current version "broken." A known-good version is restarted in
//     place and never rolled back. Otherwise, if a previous version is
//     recorded and rollback budget remains, roll back and exec from there;
//     if not, keep restarting the current version with capped backoff.
//
// The launcher never gives up supervising. Edge cases (missing binary,
// version-file pointing at nothing on disk, rollback failure) are written to
// Stderr and retried with capped exponential backoff until they heal.
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
	// callers leave it empty; the OS service manager arranges --regtoken-file
	// (and any other steward CLI flags) via the registered service-binPath
	// arguments. Tests set this to control what their fake child does.
	ExtraArgs []string

	// clock is injectable for tests; production uses time.Now / time.Since.
	clock clock

	// sleep waits for d or until ctx is done, whichever comes first. Tests
	// inject a recorder so backoff runs without wall-clock sleeps; nil uses
	// sleepWithJitter.
	sleep func(ctx context.Context, d time.Duration)

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

	// ServiceRepairInterval is the cadence of the dedicated SCM
	// service-registration self-repair ticker (#2465), independent of the
	// supervised child's exit/restart cadence. Zero uses
	// defaultServiceRepairInterval. Tests set a short interval to drive the
	// check quickly.
	ServiceRepairInterval time.Duration
}

// defaultServiceRepairInterval is the production cadence of the SCM
// service-registration self-repair check (#2465). It is set at or tighter than
// the fastest install-time SCM recovery-action delay (10s — see
// cmd/steward/service/manager_windows.go's SetRecoveryActions) so a repair can
// plausibly land before or alongside the SCM's own first restart attempt. It is
// deliberately NOT gated on supervise-loop iterations: execOnce blocks for the
// full child lifetime (days/weeks for a stable steward), so a per-iteration
// cadence would leave a deleted registration undetected for that entire span.
const defaultServiceRepairInterval = 10 * time.Second

// errChildNeverStarted marks an execOnce failure in which no child process was
// ever created because ctx was already cancelled by the time exec reached
// Start. exec.Cmd.Start returns ctx.Err() verbatim in that case, so without
// this marker the supervise loop cannot tell "the steward crashed instantly"
// (ranFor ≈ 0, non-nil error) from "we never launched the steward at all"
// (ranFor ≈ 0, non-nil error). The two demand opposite responses: the first is
// a failed upgrade that must roll back, the second is an ordinary shutdown that
// must not — rolling a version back because the service manager stopped us is a
// silent, unattended downgrade of a perfectly healthy install.
var errChildNeverStarted = errors.New("launcher: child never started (context cancelled before exec)")

const (
	// initialRestartBackoff is the first delay before a failed launch is
	// retried; it doubles per consecutive failure up to maxRestartBackoff.
	initialRestartBackoff = time.Second
	maxRestartBackoff     = 5 * time.Minute
)

// sleepWithJitter waits d plus up to 10% jitter, returning early if ctx is done.
func sleepWithJitter(ctx context.Context, d time.Duration) {
	if j := int64(d / 10); j > 0 {
		d += time.Duration(rand.Int63n(j)) //#nosec G404 -- retry jitter, not security-sensitive
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

type clock interface {
	Now() time.Time
	Since(time.Time) time.Duration
}

type realClock struct{}

func (realClock) Now() time.Time                  { return time.Now() }
func (realClock) Since(t time.Time) time.Duration { return time.Since(t) }

// runServiceRegistrationRepair runs check on its own ticker until ctx is
// cancelled. Supervise launches it in a goroutine so the SCM
// service-registration self-repair (#2465) runs independent of the supervised
// child's exit/restart cadence. check is maybeRepairServiceRegistration in
// production (a no-op on non-Windows); tests inject a check bound to a unique
// throwaway service so they never touch the host's real registration. Uses a
// real time.Ticker, not s.clock, because the repair cadence is wall-clock
// (SCM recovery timing), not the injectable child-lifecycle clock.
func (s *Supervisor) runServiceRegistrationRepair(ctx context.Context, interval time.Duration, check func(io.Writer)) {
	if check == nil || interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check(s.Stderr)
		}
	}
}

// childOutcome is how a finished child run is acted on by the supervise loop.
type childOutcome int

const (
	// outcomeShutdown: ctx was cancelled (or the failure was suppressed on a
	// known-good version); Supervise returns nil.
	outcomeShutdown childOutcome = iota
	// outcomeAdvance: the steward staged a new version and exited cleanly.
	outcomeAdvance
	// outcomeHealthy: the child outlived the startup window and exited cleanly.
	outcomeHealthy
	// outcomeRestartInPlace: a known-good version failed; restart it, never roll back.
	outcomeRestartInPlace
	// outcomeRollback: a probation version failed; roll back if possible.
	outcomeRollback
)

// childRun is the record of one finished child execution.
type childRun struct {
	current     string
	exitErr     error
	ranFor      time.Duration
	exeHash     string
	hashErr     error
	isKnownGood bool
}

// superviseLoop carries the per-Supervise state of the child loop.
type superviseLoop struct {
	s                  *Supervisor
	ctx                context.Context
	backoff            time.Duration
	rollbacksRemaining int
}

// Supervise runs the supervision loop until ctx is cancelled. Every fault
// (unreadable or missing layout, missing binary, rollback failure, a child
// that keeps failing) is written to Stderr and retried with capped backoff.
//
// Returns nil on context cancellation. The only error returned is an
// invalid ExtraArgs value, rejected before the loop starts.
func (s *Supervisor) Supervise(ctx context.Context) error {
	if err := s.normalize(); err != nil {
		return err
	}

	// Start the SCM service-registration self-repair ticker (#2465) BEFORE the
	// supervise loop. It runs in its own goroutine on its own ticker, fully
	// decoupled from execOnce's blocking child lifecycle, so a registration
	// deleted out from under a long-running healthy steward is detected and
	// re-created within one interval rather than not until the next child exit.
	// repairCtx is cancelled when Supervise returns (any path), stopping the
	// goroutine. maybeRepairServiceRegistration is a no-op on non-Windows builds.
	repairInterval := s.ServiceRepairInterval
	if repairInterval <= 0 {
		repairInterval = defaultServiceRepairInterval
	}
	repairCtx, cancelRepair := context.WithCancel(ctx)
	defer cancelRepair()
	go s.runServiceRegistrationRepair(repairCtx, repairInterval, maybeRepairServiceRegistration)

	if s.sleep == nil {
		s.sleep = sleepWithJitter
	}
	l := &superviseLoop{s: s, ctx: ctx, backoff: initialRestartBackoff, rollbacksRemaining: s.MaxRollbackCycles}
	for {
		// Never begin (or re-begin) a child launch once shutdown has been
		// requested. Every `continue` below re-enters this loop, and a cancel
		// that lands between a child's exit and the next iteration would
		// otherwise exec a doomed child: exec.Cmd.Start refuses to fork on a
		// cancelled ctx, returning ctx.Err() after a few microseconds, which
		// the classifier below reads as "the steward died inside its startup
		// window" and answers with a rollback. Stopping here makes shutdown
		// the only outcome of a cancel, which is what the service manager
		// asked for.
		if ctx.Err() != nil {
			return nil
		}

		current, exe, ok := l.resolveChild()
		if !ok {
			continue
		}
		run := s.runChild(ctx, current, exe)

		switch s.classifyRun(ctx, run) {
		case outcomeShutdown:
			return nil
		case outcomeAdvance:
			l.backoff = initialRestartBackoff
		case outcomeHealthy:
			l.handleHealthy(run)
		case outcomeRestartInPlace:
			l.handleRestartInPlace(run)
		case outcomeRollback:
			l.handleRollback(run)
		}
	}
}

// normalize validates ExtraArgs and fills in the Supervisor defaults.
func (s *Supervisor) normalize() error {
	if err := rejectRegtokenValue(s.ExtraArgs); err != nil {
		return err
	}
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
	return nil
}

// retryAfter waits out the current backoff (honouring ctx) and doubles it.
func (l *superviseLoop) retryAfter() {
	l.s.sleep(l.ctx, l.backoff)
	l.backoff = min(l.backoff*2, maxRestartBackoff)
}

// fault reports a supervision fault to Stderr and backs off before retrying.
func (l *superviseLoop) fault(err error) {
	_, _ = fmt.Fprintln(l.s.Stderr, err.Error())
	l.retryAfter()
}

// resolveChild reads the current version and its steward exe. On any fault it
// reports it, backs off and returns ok=false so the caller retries.
func (l *superviseLoop) resolveChild() (current, exe string, ok bool) {
	current, err := l.s.Layout.ReadCurrent()
	if err != nil {
		l.fault(fmt.Errorf("launcher: read current version: %w", err))
		return "", "", false
	}
	if current == "" {
		l.fault(errors.New("launcher: no current version recorded — install layout is missing or corrupt"))
		return "", "", false
	}

	exe, err = l.s.Layout.StewardExeFor(current)
	if err != nil {
		l.fault(fmt.Errorf("launcher: resolve steward exe for %q: %w", current, err))
		return "", "", false
	}
	if _, statErr := os.Stat(exe); statErr != nil {
		l.fault(fmt.Errorf("launcher: steward exe %q for version %q is missing: %w", exe, current, statErr))
		return "", "", false
	}
	return current, exe, true
}

// runChild executes the child once and records its exit, runtime and whether
// the binary that ran is the recorded known-good one.
func (s *Supervisor) runChild(ctx context.Context, current, exe string) childRun {
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
	return childRun{current: current, exitErr: exitErr, ranFor: ranFor, exeHash: exeHash, hashErr: hashErr, isKnownGood: isKnownGood}
}

// classifyRun maps a finished child run to the action the loop takes.
func (s *Supervisor) classifyRun(ctx context.Context, run childRun) childOutcome {
	if ctx.Err() != nil {
		return s.classifyCancelledRun(run)
	}
	if run.exitErr == nil {
		// Detect an intentional upgrade self-exit: the steward called
		// StageBinary (which advances state.json.current to the new version)
		// then exited cleanly so the launcher re-execs the staged binary.
		// This must NOT be treated as a startup failure — skip the rollback
		// guard and loop to exec the new current version.
		if after, readErr := s.Layout.ReadCurrent(); readErr == nil && after != run.current {
			return outcomeAdvance
		}
		if run.ranFor >= s.StartupWindow {
			return outcomeHealthy
		}
	}
	return s.classifyFailure(run)
}

// classifyFailure picks restart-in-place for a known-good version and rollback
// otherwise.
func (s *Supervisor) classifyFailure(run childRun) childOutcome {
	if run.isKnownGood {
		return outcomeRestartInPlace
	}
	return outcomeRollback
}

// classifyCancelledRun classifies a run that finished with ctx cancelled.
// Distinguish two sub-cases:
//
//	(a) The child was still running when ctx fired and got killed by
//	    exec.CommandContext. exitErr is non-nil but reflects the cancellation,
//	    not a child fault. Return a clean shutdown.
//	(b) The child had ALREADY crashed by the time ctx fired — e.g. SIGTERM and
//	    a crash arriving in the same scheduler turn during an in-progress
//	    upgrade. exitErr is non-nil AND ranFor < StartupWindow. Discarding this
//	    as "just a cancellation" would silently mask the upgrade failure. A
//	    child that ran past StartupWindow definitionally wasn't
//	    crashing-during-startup, so treat its exit as graceful regardless of
//	    code. A child that exited inside the window with a non-zero code gets
//	    the failure surfaced even on cancel.
func (s *Supervisor) classifyCancelledRun(run childRun) childOutcome {
	// The guard at the top of the loop is a check-then-act, so a cancel can
	// still land in the window between it and Start. When it does, no child
	// process was created, so there is no child outcome to classify — this is
	// purely a shutdown.
	if errors.Is(run.exitErr, errChildNeverStarted) {
		return outcomeShutdown
	}
	failedStartupOnCancel := run.ranFor < s.StartupWindow && run.exitErr != nil
	if !failedStartupOnCancel {
		return outcomeShutdown
	}
	// A known-good version that fast-exits coinciding with a context cancel
	// is an environmental fault (e.g. WMI race on boot), not an upgrade
	// failure. Return clean shutdown rather than rolling back or looping on a
	// cancelled context. Log the suppression decision first: without it, an
	// operator inspecting why the launcher exited on a proven binary sees
	// nothing, and the rollback-suppression guarantee for known-good versions
	// (Issue #2033) is indistinguishable from a silent crash.
	if run.isKnownGood {
		_, _ = fmt.Fprintf(s.Stderr, "launcher: version %q is known-good — fast exit (ran %s) coincided with shutdown; rollback suppressed, exiting cleanly\n", run.current, run.ranFor)
		return outcomeShutdown
	}
	// This looks like a real upgrade failure that happened to coincide with a
	// cancel: fall through to the rollback logic. The operator (or the next
	// startup) will observe the rolled-back state.
	return outcomeRollback
}

// handleHealthy runs after a child stayed up past the startup window then
// exited cleanly. Reset the failure counter, persist the known-good marker,
// and prune old version directories. Write the committed flag file last so its
// presence is a reliable completion signal for tests and the steward process.
func (l *superviseLoop) handleHealthy(run childRun) {
	s := l.s
	if ps, loadErr := s.Layout.loadState(); loadErr == nil {
		ps.ConsecutiveFailures = 0
		// Only update the known-good marker if the post-exec hash
		// succeeded; if it failed (binary deleted/unreadable after
		// run) leave any existing marker untouched.
		if run.hashErr == nil {
			ps.KnownGood = run.current
			ps.KnownGoodHash = run.exeHash
		}
		if saveErr := s.Layout.saveState(ps); saveErr != nil {
			_, _ = fmt.Fprintf(s.Stderr, "launcher: save state after commit: %v\n", saveErr)
		}
	} else {
		_, _ = fmt.Fprintf(s.Stderr, "launcher: load state for counter reset: %v\n", loadErr)
	}
	if _, pruneErr := pruneVersions(s.Layout.VersionsDir(), run.current, s.RetentionPolicy, s.clock.Now()); pruneErr != nil {
		_, _ = fmt.Fprintf(s.Stderr, "launcher: retention prune: %v\n", pruneErr)
	}
	if flagErr := s.writeFlagFile("upgrade-committed", run.current); flagErr != nil {
		_, _ = fmt.Fprintf(s.Stderr, "launcher: write upgrade-committed flag: %v\n", flagErr)
	}
	l.backoff = initialRestartBackoff
}

// recordFailure increments the consecutive-failure counter on any non-clean
// exit regardless of whether a rollback will fire, and restarts the backoff if
// the child was healthy for a while before failing.
func (l *superviseLoop) recordFailure(run childRun) {
	s := l.s
	if ps, loadErr := s.Layout.loadState(); loadErr == nil {
		ps.ConsecutiveFailures++
		if saveErr := s.Layout.saveState(ps); saveErr != nil {
			_, _ = fmt.Fprintf(s.Stderr, "launcher: save state on failure: %v\n", saveErr)
		}
	} else {
		_, _ = fmt.Fprintf(s.Stderr, "launcher: load state for failure counter: %v\n", loadErr)
	}

	// A child that ran past the startup window was healthy for a while, so
	// whatever failed it is new: start the backoff over.
	if run.ranFor >= s.StartupWindow {
		l.backoff = initialRestartBackoff
	}
}

// handleRestartInPlace restarts a known-good binary that exited non-zero (or
// fast). It is suffering a transient environmental fault (e.g. a boot-time
// dependency race, a late crash), not an upgrade regression, so it is restarted
// with backoff — never rolled back (Issue #2033).
func (l *superviseLoop) handleRestartInPlace(run childRun) {
	l.recordFailure(run)
	_, _ = fmt.Fprintf(l.s.Stderr, "launcher: version %q is known-good — restarting in place after failure (ran %s); rollback suppressed\n", run.current, run.ranFor)
	l.retryAfter()
}

// handleRollback rolls a failed probation version back to the previous one when
// a previous version exists and rollback budget remains; otherwise it reports
// the fault and keeps retrying the current version.
func (l *superviseLoop) handleRollback(run childRun) {
	s := l.s
	l.recordFailure(run)

	previous, perr := s.Layout.ReadPrevious()
	if perr != nil {
		l.fault(fmt.Errorf("launcher: read previous version after child failure: %w", perr))
		return
	}
	if previous == "" || l.rollbacksRemaining == 0 {
		if run.exitErr != nil {
			l.fault(fmt.Errorf("launcher: child failed (ran for %s) and no rollback available: %w", run.ranFor, run.exitErr))
		} else {
			l.fault(fmt.Errorf("launcher: child exited inside startup window (%s) and no rollback available", run.ranFor))
		}
		return
	}

	// Rollback is going to fire: write the flag file with the version we
	// are rolling back TO (previous), which will be the version the steward
	// process is running when it reconnects and reads the flag.
	if flagErr := s.writeFlagFile("upgrade-rolled-back", previous); flagErr != nil {
		_, _ = fmt.Fprintf(s.Stderr, "launcher: write upgrade-rolled-back flag: %v\n", flagErr)
	}

	newCurrent, rbErr := s.Layout.Rollback()
	if rbErr != nil {
		l.fault(fmt.Errorf("launcher: rollback after child failure: %w", rbErr))
		return
	}
	l.rollbacksRemaining--
	l.backoff = initialRestartBackoff
	_, _ = fmt.Fprintf(s.Stderr, "launcher: rolled back to version %q after child failure (ran for %s)\n", newCurrent, run.ranFor)
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
		// exec.Cmd.Start declines to fork when ctx is already done and returns
		// ctx.Err() unchanged. Tag that case so the supervise loop can tell it
		// apart from a genuine start failure (missing/corrupt binary, denied
		// exec permission), which still means the current version is broken
		// and must roll back.
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return fmt.Errorf("%w: %w", errChildNeverStarted, err)
		}
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
	// #nosec G301 -- this store contains only public CA certificates needed by
	// the unprivileged steward service, so directory traversal is intentional.
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

// rejectedTokenFlag is the removed token-on-the-command-line flag; use --regtoken-file.
const rejectedTokenFlag = "--regtoken" // use --regtoken-file

// rejectRegtokenValue refuses child arguments that carry the registration token
// as a command-line value, which other local users could read from the process
// list. Each argument is split on whitespace because a service definition holds
// the whole --child-args value as one argument.
func rejectRegtokenValue(args []string) error {
	for _, arg := range args {
		for _, field := range strings.Fields(arg) {
			if name, _, _ := strings.Cut(field, "="); name == rejectedTokenFlag {
				return errors.New("--regtoken is not supported in child arguments: pass the token in a root-only file with --regtoken-file PATH")
			}
		}
	}
	return nil
}
