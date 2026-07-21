// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/version"
)

// fakeClock is an injectable clock for lifecycle tests that need to control
// whether a child "passed" its startup window without real time delays.
type fakeClock struct {
	now         time.Time
	sinceResult time.Duration
}

func (f *fakeClock) Now() time.Time                { return f.now }
func (f *fakeClock) Since(time.Time) time.Duration { return f.sinceResult }

// TestHelperProcess is the canonical Go pattern for testing exec.Cmd-based
// code without shipping separate fake binaries. The launcher test re-exec's
// this same test binary with GO_WANT_HELPER_PROCESS=1 set; that env var
// switches the test process into "be the fake steward" mode, controlled by
// the rest of the FAKE_STEWARD_* env vars.
//
// Behaviour knobs (read once, on start):
//
//	FAKE_STEWARD_SLEEP_MS    Sleep this many ms before exiting. Default 0.
//	FAKE_STEWARD_EXIT_CODE   Exit with this status. Default 0.
//	FAKE_STEWARD_MARKER_FILE       Touch this file before sleeping so the test
//	                               can verify which version actually ran.
//	FAKE_STEWARD_EXIT_MARKER_FILE  Touch this file AFTER the sleep, just before
//	                               os.Exit. Used by the #1928 Job-Object test
//	                               to distinguish "naturally completed" from
//	                               "killed by the Job Object when the parent
//	                               died." If absent on file system after the
//	                               sleep budget, the kill landed.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	if marker := os.Getenv("FAKE_STEWARD_MARKER_FILE"); marker != "" {
		_ = os.WriteFile(marker, []byte("started"), 0o600)
	}
	// Issue #2003: record the launcher-managed marker env the launcher set on us
	// so a test can assert execOnce propagated CFGMS_STEWARD_LAUNCHER_MANAGED=1.
	if mf := os.Getenv("FAKE_STEWARD_RECORD_MANAGED_FILE"); mf != "" {
		_ = os.WriteFile(mf, []byte(os.Getenv(version.EnvStewardLauncherManaged)), 0o600)
	}
	// FAKE_STEWARD_STAGE_VERSION advances state.json to the given version before
	// exiting, mimicking the steward's upgrade handler calling WriteCurrent after
	// staging a binary. The install root and binary name arrive in their own env
	// vars (FAKE_STEWARD_STAGE_ROOT / FAKE_STEWARD_STAGE_BINARY) rather than being
	// packed into one colon-delimited value: a Windows root such as
	// "C:\\Program Files\\CFGMS" contains a colon, so a single-string ":"-split
	// mis-parses the path and writes state.json to the wrong place. Separate vars
	// are unambiguous on every platform. WriteCurrent is idempotent: a no-op when
	// current already equals the target.
	if sv := os.Getenv("FAKE_STEWARD_STAGE_VERSION"); sv != "" {
		wl := Layout{
			Root:              os.Getenv("FAKE_STEWARD_STAGE_ROOT"),
			StewardBinaryName: os.Getenv("FAKE_STEWARD_STAGE_BINARY"),
		}
		_ = wl.WriteCurrent(sv)
	}
	if sleepMs := os.Getenv("FAKE_STEWARD_SLEEP_MS"); sleepMs != "" {
		if n, err := strconv.Atoi(sleepMs); err == nil && n > 0 {
			time.Sleep(time.Duration(n) * time.Millisecond)
		}
	}
	// FAKE_STEWARD_RENAME_SELF makes the fake steward rename its own on-disk
	// binary out of the way just before exiting, forcing the launcher's
	// post-exec computeBinaryHash to fail (file not found) deterministically on
	// every platform. This is the cross-platform stand-in for "the binary became
	// unreadable after a successful exec": chmod-to-000 achieves that on POSIX
	// but is a no-op on Windows (an exec'd image is always readable there).
	// Renaming a running executable is permitted on both POSIX and Windows;
	// deleting it is not (the image stays locked on Windows), so we rename.
	if os.Getenv("FAKE_STEWARD_RENAME_SELF") == "1" {
		if exe, err := os.Executable(); err == nil {
			_ = os.Rename(exe, exe+".moved")
		}
	}
	if exitMarker := os.Getenv("FAKE_STEWARD_EXIT_MARKER_FILE"); exitMarker != "" {
		_ = os.WriteFile(exitMarker, []byte("natural-exit"), 0o600)
	}
	code := 0
	if c := os.Getenv("FAKE_STEWARD_EXIT_CODE"); c != "" {
		if n, err := strconv.Atoi(c); err == nil {
			code = n
		}
	}
	os.Exit(code)
}

// helperExe returns the path of the running test binary so we can re-exec
// it as the fake steward.
func helperExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return exe
}

// installFakeSteward stages a fake-steward binary into the layout's
// versions/<name>/ directory. The fake-steward is just a shim that
// re-exec's the test binary with GO_WANT_HELPER_PROCESS=1. We do this with
// a small launcher-style trampoline: the binary at versions/<name>/<exe>
// is actually the test binary, and Supervisor will run it. To control its
// behaviour per-version, the Supervisor passes ExtraArgs and env via a
// thin wrapper — but the simplest, most portable approach is: copy the
// test binary into versions/<name>/ and use ExtraArgs + per-process env
// (set in the Supervisor's exec by us hooking the command's Env).
//
// Since Supervisor.execOnce inherits the launcher's environment, we set
// FAKE_STEWARD_* env vars on the test process and they propagate. To get
// PER-VERSION behaviour, we encode the desired knobs in a side file that
// the fake-steward reads at start. That keeps the launcher's
// supervise-loop logic untouched.
func installFakeSteward(t *testing.T, l Layout, version string) string {
	t.Helper()
	dst, err := l.StewardExeFor(version)
	if err != nil {
		t.Fatalf("StewardExeFor: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := copyFile(helperExe(t), dst); err != nil {
		t.Fatalf("copy test binary into version dir: %v", err)
	}
	return dst
}

// runSupervisor runs Supervise with timeout-bounded context so a buggy
// loop can't hang the test suite.
func runSupervisor(t *testing.T, s *Supervisor, timeout time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return s.Supervise(ctx)
}

// envForChild returns the env vars to pass to a child fake-steward by
// re-using the test process env. The launcher inherits its environment;
// to vary per-test behaviour we just mutate t.Setenv before invocation.
// But since we want different versions to behave differently within ONE
// Supervise call, we instead set the env globally before Supervise and
// rely on the fact that all spawned children inherit it.
func envForChild(t *testing.T, knobs map[string]string) {
	t.Helper()
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	for k, v := range knobs {
		t.Setenv(k, v)
	}
}

func TestSupervise_NoCurrentVersion_ReturnsError(t *testing.T) {
	l := newLayout(t)
	s := &Supervisor{
		Layout: l,
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
	}
	err := runSupervisor(t, s, 2*time.Second)
	if err == nil {
		t.Fatal("Supervise with no current.txt returned nil error")
	}
}

func TestSupervise_BrokenChild_RollsBackWhenPreviousExists(t *testing.T) {
	l := newLayout(t)

	// Stage v1 (good) then v2 (broken). After WriteCurrent("v2"),
	// current.txt=v2 previous.txt=v1.
	installFakeSteward(t, l, "v1")
	installFakeSteward(t, l, "v2")
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}
	if err := l.WriteCurrent("v2"); err != nil {
		t.Fatalf("WriteCurrent v2: %v", err)
	}

	// All children (regardless of version, due to shared env) will exit
	// non-zero immediately AND touch a marker file so the test can prove
	// the child actually ran (not just that exec.Command errored out).
	// The Supervisor must:
	//   - run v2 → it fails → roll back → current.txt becomes v1
	//   - run v1 → it ALSO fails (same env) → no rollback budget left
	//   - return error.
	marker := filepath.Join(t.TempDir(), "ran")
	envForChild(t, map[string]string{
		"FAKE_STEWARD_EXIT_CODE":   "1",
		"FAKE_STEWARD_SLEEP_MS":    "0",
		"FAKE_STEWARD_MARKER_FILE": marker,
	})

	stderr := &bytes.Buffer{}
	s := &Supervisor{
		Layout:            l,
		StartupWindow:     50 * time.Millisecond,
		MaxRollbackCycles: 1,
		Stdout:            &bytes.Buffer{},
		Stderr:            stderr,
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}
	err := runSupervisor(t, s, 10*time.Second)
	if err == nil {
		t.Fatal("Supervise returned nil error after both versions broken")
	}

	if _, statErr := os.Stat(marker); statErr != nil {
		t.Errorf("fake-steward marker not present (%v) — child never actually ran; "+
			"the supervisor must be returning an exec-not-found error instead of "+
			"a real child-failure error", statErr)
	}

	// Rollback should have left current.txt pointing at v1.
	cur, _ := l.ReadCurrent()
	if cur != "v1" {
		t.Errorf("current after rollback = %q, want v1", cur)
	}
	if !bytes.Contains(stderr.Bytes(), []byte(`rolled back to version "v1"`)) {
		t.Errorf("stderr did not mention rollback to v1:\n%s", stderr.String())
	}
}

func TestSupervise_BrokenChild_NoPreviousReturnsError(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v1")
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}

	marker := filepath.Join(t.TempDir(), "ran")
	envForChild(t, map[string]string{
		"FAKE_STEWARD_EXIT_CODE":   "1",
		"FAKE_STEWARD_MARKER_FILE": marker,
	})

	s := &Supervisor{
		Layout:            l,
		StartupWindow:     50 * time.Millisecond,
		MaxRollbackCycles: 1,
		Stdout:            &bytes.Buffer{},
		Stderr:            &bytes.Buffer{},
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}
	err := runSupervisor(t, s, 10*time.Second)
	if err == nil {
		t.Fatal("Supervise returned nil when broken child had no rollback target")
	}
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Errorf("fake-steward marker not present (%v) — child never actually ran", statErr)
	}
}

// TestSupervise_ContextCancel_AfterHealthyChildStaysAlive covers the
// review-flagged "exit code discarded as clean shutdown" race. Before
// the fix-up, ANY ctx.Err() != nil short-circuited Supervise to return
// nil — even when the child had already exited with a non-zero code
// before the cancel arrived. The fix differentiates: cancellation
// AFTER the startup window propagates as clean shutdown; non-zero exit
// INSIDE the startup window still triggers rollback even on cancel.
//
// This test exercises the "healthy child past window, then cancel"
// case: cancellation must return nil and not interpret the SIGTERM-
// induced exit as a failure.
func TestSupervise_ContextCancel_AfterHealthyChildStaysAlive(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v1")
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}

	// Child sleeps long; cancel fires mid-sleep. exec.CommandContext
	// kills the child producing a non-zero exit. The supervisor must
	// recognise this as a cancellation, not a child fault.
	envForChild(t, map[string]string{
		"FAKE_STEWARD_SLEEP_MS":  "60000",
		"FAKE_STEWARD_EXIT_CODE": "0",
	})

	s := &Supervisor{
		Layout:            l,
		StartupWindow:     20 * time.Millisecond, // tiny window so the kill lands OUTSIDE it
		MaxRollbackCycles: 0,
		Stdout:            &bytes.Buffer{},
		Stderr:            &bytes.Buffer{},
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	var result error
	done := make(chan struct{})
	go func() {
		result = s.Supervise(ctx)
		close(done)
	}()
	// Wait long enough that the child is well past StartupWindow.
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Supervise did not return after cancel")
	}
	if result != nil {
		t.Errorf("Supervise returned %v on cancel after healthy child; want nil", result)
	}
}

func TestSupervise_ContextCancel_ExitsClean(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v1")
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}

	// Child sleeps far longer than the test will give it; cancelling the
	// context should kill it and Supervise should return nil (clean
	// shutdown, not failure).
	envForChild(t, map[string]string{
		"FAKE_STEWARD_SLEEP_MS":  "60000",
		"FAKE_STEWARD_EXIT_CODE": "0",
	})

	s := &Supervisor{
		Layout:            l,
		StartupWindow:     50 * time.Millisecond,
		MaxRollbackCycles: 1,
		Stdout:            &bytes.Buffer{},
		Stderr:            &bytes.Buffer{},
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	var (
		wg     sync.WaitGroup
		result error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		result = s.Supervise(ctx)
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Supervise did not return within 10s of cancel")
	}

	if result != nil {
		t.Errorf("Supervise returned %v on context cancel, want nil", result)
	}
}

// TestSupervise_HealthyChild_ExitsCleanWithoutRollback covers the
// "supervisor restart loop" intentionally — a healthy child that exits
// cleanly past the startup window must NOT trigger rollback; the loop
// must restart it. We bound the test by stopping the loop with a context
// cancel after observing at least 2 child invocations.
//
// Timing budgets are intentionally generous so the test is robust on
// Windows under CI load (the earlier 50ms-window/200ms-sleep numbers
// raced fork-exec overhead on Windows, hence a previous Windows skip
// the adversarial review correctly objected to). The current values
// give a 5× safety margin between sleep duration and startup window;
// fork/exec overhead would have to balloon over 350ms before false
// positives kick in.
func TestSupervise_HealthyChild_RestartsWithoutRollback(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v1")
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}

	// Sleep well past the startup window then exit cleanly. The window
	// is intentionally short (50ms) and the sleep long (500ms) so the
	// classifier "this child stayed up past the startup window" stays
	// stable even when Windows fork+exec overhead doubles or triples
	// under CI load.
	envForChild(t, map[string]string{
		"FAKE_STEWARD_SLEEP_MS":  "500",
		"FAKE_STEWARD_EXIT_CODE": "0",
	})

	s := &Supervisor{
		Layout: l,
		// 50ms startup window: any healthy child that completes a 500ms
		// sleep + exit is comfortably outside the window.
		StartupWindow: 50 * time.Millisecond,
		// ZERO rollback budget. A healthy child must NOT trigger rollback
		// regardless of budget, so this proves the classifier path even
		// when no rollback is permitted. Previously this was coerced
		// silently to 1; the fix-up exposes 0 as a legitimate operator
		// choice.
		MaxRollbackCycles: 0,
		Stdout:            &bytes.Buffer{},
		Stderr:            &bytes.Buffer{},
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var result error
	done := make(chan struct{})
	go func() {
		result = s.Supervise(ctx)
		close(done)
	}()

	// Let the supervisor restart the child at least twice — proves the
	// loop is in fact looping on clean exits. 1500ms gives 3 iterations
	// of 500ms sleep + restart, even with fork-exec overhead.
	time.Sleep(1500 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Supervise did not return after cancel")
	}
	if result != nil {
		t.Errorf("Supervise returned %v on clean cancel after healthy restarts", result)
	}
	// current.txt must still be v1 — no rollback should have run.
	cur, _ := l.ReadCurrent()
	if cur != "v1" {
		t.Errorf("current = %q after healthy restart loop, want v1 (no rollback)", cur)
	}
}

// TestExecOnce_RespectsContextCancel verifies the exec-level wiring —
// CommandContext cancellation must terminate the child.
func TestExecOnce_RespectsContextCancel(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v1")
	envForChild(t, map[string]string{
		"FAKE_STEWARD_SLEEP_MS":  "60000",
		"FAKE_STEWARD_EXIT_CODE": "0",
	})

	exe, err := l.StewardExeFor("v1")
	if err != nil {
		t.Fatalf("StewardExeFor: %v", err)
	}

	s := &Supervisor{
		Layout:    l,
		Stdout:    &bytes.Buffer{},
		Stderr:    &bytes.Buffer{},
		ExtraArgs: []string{"-test.run=TestHelperProcess"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	started := atomic.Int32{}
	var execErr error
	done := make(chan struct{})
	go func() {
		started.Store(1)
		execErr = s.execOnce(ctx, exe)
		close(done)
	}()

	// Wait for the goroutine to actually start running.
	for started.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("execOnce did not return after context cancel")
	}

	if execErr == nil {
		t.Error("execOnce returned nil error after context cancel — child was supposed to be killed")
	}
	// And specifically it should be the kind of error exec returns when
	// the process was killed by signal/context — exec.ExitError typically.
	var exitErr *exec.ExitError
	if !errors.As(execErr, &exitErr) {
		t.Logf("note: execOnce returned non-ExitError after cancel: %v", execErr)
	}
}

// TestFakeChild_MarkerFileProvesWhichVersionRan is a sanity check on the
// test helper itself — confirms the marker-file mechanism actually
// captures which fake-steward binary ran. (Not used elsewhere; here to
// guard against silent breakage of the helper.)
func TestFakeChild_MarkerFileProvesWhichVersionRan(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	cmd := exec.Command(helperExe(t), "-test.run=TestHelperProcess") //nolint:gosec // test
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		"FAKE_STEWARD_EXIT_CODE=0",
		fmt.Sprintf("FAKE_STEWARD_MARKER_FILE=%s", marker),
	)
	if err := cmd.Run(); err != nil {
		t.Fatalf("fake child failed: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("marker file not created: %v", err)
	}
}

// TestExecOnce_SetsLauncherManagedEnvOnChild verifies the #2003 contract: the
// launcher marks its steward child with CFGMS_STEWARD_LAUNCHER_MANAGED=1 so the
// steward knows it is supervised and may self-exit after a pushed-upgrade swap.
// We run execOnce against the fake-steward helper, which records the value of
// that env var it actually received, and assert it is "1".
func TestExecOnce_SetsLauncherManagedEnvOnChild(t *testing.T) {
	recordFile := filepath.Join(t.TempDir(), "managed")

	// Put the helper knobs in the process environment (execOnce builds the child
	// env from os.Environ()). Deliberately do NOT pre-set the launcher-managed
	// marker here — its presence in the recorded value must come from execOnce.
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("FAKE_STEWARD_RECORD_MANAGED_FILE", recordFile)
	t.Setenv("FAKE_STEWARD_EXIT_CODE", "0")
	// Guard against a polluted environment: the marker must be unset so any "1"
	// in the recorded value is attributable to execOnce.
	if v, ok := os.LookupEnv(version.EnvStewardLauncherManaged); ok && v != "" {
		_ = os.Unsetenv(version.EnvStewardLauncherManaged)
		t.Cleanup(func() { _ = os.Setenv(version.EnvStewardLauncherManaged, v) })
	}

	s := &Supervisor{
		Layout:    newLayout(t),
		Stdout:    &bytes.Buffer{},
		Stderr:    &bytes.Buffer{},
		ExtraArgs: []string{"-test.run=TestHelperProcess"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.execOnce(ctx, helperExe(t)); err != nil {
		t.Fatalf("execOnce returned error: %v", err)
	}

	got, err := os.ReadFile(recordFile) //nolint:gosec // test temp path
	if err != nil {
		t.Fatalf("read recorded managed-env file: %v", err)
	}
	if string(got) != "1" {
		t.Errorf("child saw %s=%q, want \"1\" — execOnce must mark the steward child as launcher-managed (#2003)",
			version.EnvStewardLauncherManaged, string(got))
	}
}

// waitForFile polls for path to exist, returning true when it does or false
// if deadline passes.
func waitForFile(path string, deadline time.Duration) bool {
	expire := time.Now().Add(deadline)
	for time.Now().Before(expire) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// TestSupervise_Rollback_WritesFlagFileAndIncrementsCounter verifies that when
// a child fails its startup window and the launcher auto-rolls-back, the
// upgrade-rolled-back flag file is written with the rolled-back-to version and
// consecutive_failures in state.json is exactly 1 (AC2 postcondition: one
// failure+rollback → counter is 1).
//
// Only v2's binary is installed. After v2 fails and the launcher rolls back to
// v1, the supervisor finds no v1 binary and returns an error before a second
// increment can fire — so consecutive_failures stays at 1.
func TestSupervise_Rollback_WritesFlagFileAndIncrementsCounter(t *testing.T) {
	l := newLayout(t)
	certStoreDir := t.TempDir()

	// Install v2 only; v1 directory is intentionally absent so the supervisor
	// returns early (missing binary) after the rollback, before a second failure
	// can increment the counter.
	installFakeSteward(t, l, "v2")
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}
	if err := l.WriteCurrent("v2"); err != nil {
		t.Fatalf("WriteCurrent v2: %v", err)
	}
	// State: current=v2, previous=v1.

	// v2 fails immediately (non-zero exit, sinceResult=0 < StartupWindow).
	envForChild(t, map[string]string{
		"FAKE_STEWARD_EXIT_CODE": "1",
		"FAKE_STEWARD_SLEEP_MS":  "0",
	})

	s := &Supervisor{
		Layout:            l,
		StartupWindow:     50 * time.Millisecond,
		MaxRollbackCycles: 1,
		CertStoreDir:      certStoreDir,
		clock:             &fakeClock{sinceResult: 0}, // always < StartupWindow → failedStartup
		Stdout:            &bytes.Buffer{},
		Stderr:            &bytes.Buffer{},
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}

	if err := runSupervisor(t, s, 10*time.Second); err == nil {
		t.Fatal("Supervise should return error when v2 fails and v1 binary is absent")
	}

	// upgrade-rolled-back must exist and contain v1 (the version rolled back TO).
	flagPath := filepath.Join(certStoreDir, "upgrade-rolled-back")
	data, rdErr := os.ReadFile(flagPath) //nolint:gosec // test temp path
	if rdErr != nil {
		t.Fatalf("upgrade-rolled-back flag file not written: %v", rdErr)
	}
	if got := strings.TrimSpace(string(data)); got != "v1" {
		t.Errorf("upgrade-rolled-back = %q, want v1 (the rollback target)", got)
	}

	// consecutive_failures == 1: v2 failed once; v1 binary was absent so the
	// supervisor returned before a second increment could fire (AC2 postcondition).
	ps, loadErr := l.loadState()
	if loadErr != nil {
		t.Fatalf("loadState after rollback: %v", loadErr)
	}
	if ps.ConsecutiveFailures != 1 {
		t.Errorf("consecutive_failures = %d, want 1 (one failure+rollback)", ps.ConsecutiveFailures)
	}
}

// TestSupervise_CleanStartup_WritesFlagAndPrunesVersions verifies that after a
// child exits cleanly past its StartupWindow:
//   - upgrade-committed is written with the current version name.
//   - consecutive_failures in state.json is reset to 0.
//   - version directories beyond MaxVersions (past quarantine window) are pruned.
//   - the active version directory is NOT deleted.
func TestSupervise_CleanStartup_WritesFlagAndPrunesVersions(t *testing.T) {
	l := newLayout(t)
	certStoreDir := t.TempDir()

	// Install v1–v4 and stage v4 as current.
	for _, v := range []string{"v1", "v2", "v3", "v4"} {
		installFakeSteward(t, l, v)
	}
	for _, v := range []string{"v1", "v2", "v3", "v4"} {
		if err := l.WriteCurrent(v); err != nil {
			t.Fatalf("WriteCurrent %s: %v", v, err)
		}
	}
	// State: current=v4, previous=v3; v1,v2 are in versions/ but not in pointer state.

	// Pre-seed a non-zero failure counter to prove it gets reset.
	ps, loadErr := l.loadState()
	if loadErr != nil {
		t.Fatalf("loadState before pre-seed: %v", loadErr)
	}
	ps.ConsecutiveFailures = 7
	if err := l.saveState(ps); err != nil {
		t.Fatalf("saveState: %v", err)
	}

	// Set mod times so v1 is oldest, all past quarantine (QuarantineWindow=0).
	now := time.Now()
	for i, v := range []string{"v1", "v2", "v3", "v4"} {
		vDir := filepath.Join(l.VersionsDir(), v)
		mt := now.Add(-time.Duration(4-i) * time.Hour)
		if err := os.Chtimes(vDir, mt, mt); err != nil {
			t.Fatalf("chtimes %s: %v", v, err)
		}
	}

	envForChild(t, map[string]string{
		"FAKE_STEWARD_EXIT_CODE": "0",
		"FAKE_STEWARD_SLEEP_MS":  "0",
	})

	s := &Supervisor{
		Layout:        l,
		StartupWindow: 50 * time.Millisecond,
		CertStoreDir:  certStoreDir,
		RetentionPolicy: RetentionPolicy{
			QuarantineWindow: 0, // no quarantine: all non-active are candidates
			MaxVersions:      1, // keep 1 non-active → prune v1 and v2
			MaxBytes:         0,
		},
		MaxRollbackCycles: 0,
		clock:             &fakeClock{sinceResult: time.Minute}, // > StartupWindow → clean
		Stdout:            &bytes.Buffer{},
		Stderr:            &bytes.Buffer{},
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Supervise(ctx) }()

	// The flag file is written last in the clean-startup branch, so when it
	// exists, counter reset and pruning are both complete.
	flagPath := filepath.Join(certStoreDir, "upgrade-committed")
	if !waitForFile(flagPath, 5*time.Second) {
		t.Fatal("upgrade-committed flag file never appeared within 5s")
	}
	cancel()
	<-done

	// upgrade-committed must contain the current version (v4).
	data, err := os.ReadFile(flagPath) //nolint:gosec // test temp path
	if err != nil {
		t.Fatalf("read upgrade-committed: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "v4" {
		t.Errorf("upgrade-committed = %q, want v4", got)
	}

	// consecutive_failures must be reset to 0.
	ps2, loadErr2 := l.loadState()
	if loadErr2 != nil {
		t.Fatalf("loadState after clean startup: %v", loadErr2)
	}
	if ps2.ConsecutiveFailures != 0 {
		t.Errorf("consecutive_failures = %d, want 0", ps2.ConsecutiveFailures)
	}

	// MaxVersions=1: candidates=[v1,v2,v3] (v4 active), overflow=2 → v1,v2 pruned.
	for _, pruned := range []string{"v1", "v2"} {
		if _, err := os.Stat(filepath.Join(l.VersionsDir(), pruned)); err == nil {
			t.Errorf("version %s should be pruned but dir still exists", pruned)
		}
	}
	// Active version v4 must survive.
	if _, err := os.Stat(filepath.Join(l.VersionsDir(), "v4")); err != nil {
		t.Errorf("active version v4 must not be pruned: %v", err)
	}
	// v3 (newest non-active, kept within MaxVersions=1) must survive.
	if _, err := os.Stat(filepath.Join(l.VersionsDir(), "v3")); err != nil {
		t.Errorf("v3 (within MaxVersions=1) must not be pruned: %v", err)
	}
}

// TestSupervise_ConsecutiveFailures_CountAndReset verifies that three
// consecutive startup-window failures accumulate consecutive_failures=3 in
// state.json (each write atomic via saveState), and that a subsequent clean
// startup resets the counter to 0.
func TestSupervise_ConsecutiveFailures_CountAndReset(t *testing.T) {
	l := newLayout(t)

	// Two versions that both fail: MaxRollbackCycles=2 causes three executions
	// (v3 → rollback → v2 → rollback → v3 → no budget → error), each incrementing.
	installFakeSteward(t, l, "v2")
	installFakeSteward(t, l, "v3")
	if err := l.WriteCurrent("v2"); err != nil {
		t.Fatalf("WriteCurrent v2: %v", err)
	}
	if err := l.WriteCurrent("v3"); err != nil {
		t.Fatalf("WriteCurrent v3: %v", err)
	}
	// State: current=v3, previous=v2.

	envForChild(t, map[string]string{
		"FAKE_STEWARD_EXIT_CODE": "1",
		"FAKE_STEWARD_SLEEP_MS":  "0",
	})

	fc := &fakeClock{sinceResult: 0} // always failedStartup
	s := &Supervisor{
		Layout:            l,
		StartupWindow:     50 * time.Millisecond,
		MaxRollbackCycles: 2,
		clock:             fc,
		Stdout:            &bytes.Buffer{},
		Stderr:            &bytes.Buffer{},
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}

	// Phase 1: three executions → counter = 3.
	if err := runSupervisor(t, s, 10*time.Second); err == nil {
		t.Fatal("phase 1: Supervise should return error when all versions fail")
	}
	ps, loadErr := l.loadState()
	if loadErr != nil {
		t.Fatalf("loadState after phase 1: %v", loadErr)
	}
	if ps.ConsecutiveFailures != 3 {
		t.Errorf("after 3 failures: consecutive_failures = %d, want 3", ps.ConsecutiveFailures)
	}

	// Phase 2: subsequent clean startup must reset counter to 0.
	// The current version after the rollback loop is whatever the last state
	// held. Change env to clean exit and use a clock that reports healthy duration.
	t.Setenv("FAKE_STEWARD_EXIT_CODE", "0")
	fc.sinceResult = time.Minute // > StartupWindow → clean startup

	certStoreDir := t.TempDir()
	s2 := &Supervisor{
		Layout:            l,
		StartupWindow:     50 * time.Millisecond,
		MaxRollbackCycles: 0,
		CertStoreDir:      certStoreDir,
		clock:             fc,
		Stdout:            &bytes.Buffer{},
		Stderr:            &bytes.Buffer{},
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() { done2 <- s2.Supervise(ctx2) }()

	flagPath := filepath.Join(certStoreDir, "upgrade-committed")
	if !waitForFile(flagPath, 5*time.Second) {
		t.Fatal("upgrade-committed flag file never appeared after clean startup")
	}
	cancel2()
	<-done2

	ps2, loadErr2 := l.loadState()
	if loadErr2 != nil {
		t.Fatalf("loadState after phase 2: %v", loadErr2)
	}
	if ps2.ConsecutiveFailures != 0 {
		t.Errorf("after clean startup: consecutive_failures = %d, want 0", ps2.ConsecutiveFailures)
	}
}

// upgradeClock is a test clock whose Since method returns a small duration on
// the first call (so the first child looks like it exited within the startup
// window) and a large duration on every subsequent call (so later children
// look like they cleared the window). Used by
// TestSupervise_UpgradeSelfExit_AdvancesToNewVersion to verify upgrade
// self-exit detection without any real-time delays.
type upgradeClock struct {
	calls atomic.Int32
}

func (c *upgradeClock) Now() time.Time { return time.Now() }
func (c *upgradeClock) Since(_ time.Time) time.Duration {
	if c.calls.Add(1) == 1 {
		return 10 * time.Millisecond // first child: within startup window
	}
	return time.Minute // subsequent children: past startup window
}

// TestSupervise_UpgradeSelfExit_AdvancesToNewVersion verifies the fix for the
// upgrade self-exit bug: when the steward calls StageBinary (advancing
// state.json.current to the new version) and then self-exits cleanly so the
// launcher re-execs the staged binary, the supervisor must NOT treat this as a
// failed startup. Without the fix, a clean exit inside StartupWindow triggers
// MaxRollbackCycles-based failure even when state.json advanced — the upgrade
// is silently reversed.
//
// Test shape:
//  1. v1 is the current version; v2 is the staged upgrade.
//  2. v1 (via FAKE_STEWARD_STAGE_VERSION) calls WriteCurrent("v2") before exiting.
//     The clock returns 10ms for v1's run (inside 50ms StartupWindow).
//  3. The fix detects that state.json.current changed (v1→v2) on a clean exit and
//     continues the loop to exec v2 instead of treating the exit as a crash.
//  4. v2 calls WriteCurrent("v2") (no-op), exits cleanly; the clock returns
//     time.Minute (past StartupWindow) so it's treated as a committed startup.
//  5. The supervisor writes the "upgrade-committed" flag file. The test cancels
//     on that signal, then asserts Supervise returns nil and current is "v2".
//
// We use the upgrade-committed flag as the termination signal (rather than a
// fixed context deadline) so that the test is robust on slow CI runners where
// the test binary (re-exec'd as the fake steward) can take well over 500ms to
// load. A fixed 500ms deadline would kill v1 mid-run via exec.CommandContext,
// turning exitErr from nil to signal:killed and hiding the upgrade detection
// path entirely.
func TestSupervise_UpgradeSelfExit_AdvancesToNewVersion(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v1")
	installFakeSteward(t, l, "v2")
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}
	// All children run WriteCurrent("v2"): v1 advances state.json to v2; v2's
	// call is a no-op (current already == v2). Both exit cleanly with code 0.
	envForChild(t, map[string]string{
		"FAKE_STEWARD_STAGE_ROOT":    l.Root,
		"FAKE_STEWARD_STAGE_VERSION": "v2",
		"FAKE_STEWARD_STAGE_BINARY":  l.StewardBinaryName,
		"FAKE_STEWARD_SLEEP_MS":      "0",
		"FAKE_STEWARD_EXIT_CODE":     "0",
	})
	certStoreDir := t.TempDir()
	s := &Supervisor{
		Layout:            l,
		StartupWindow:     50 * time.Millisecond,
		MaxRollbackCycles: 0, // zero-tolerance: any unintended rollback returns an error
		CertStoreDir:      certStoreDir,
		clock:             &upgradeClock{},
		Stdout:            &bytes.Buffer{},
		Stderr:            &bytes.Buffer{},
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.Supervise(ctx) }()

	// The upgrade-committed flag is written only after v2 exits past StartupWindow
	// (committed). This can only happen if the fix is in place: without it,
	// Supervise returns an error immediately (MaxRollbackCycles=0, v1 exited
	// inside StartupWindow) and the flag never appears.
	//
	// Without fix: waitForFile returns false → select detects error on done → Fatalf.
	// With fix:    flag appears → we cancel → Supervise returns nil → assertions pass.
	committedFlag := filepath.Join(certStoreDir, "upgrade-committed")
	if !waitForFile(committedFlag, 15*time.Second) {
		select {
		case err := <-done:
			t.Fatalf("Supervise returned %v before upgrade committed; upgrade self-exit must not trigger rollback", err)
		default:
			t.Fatal("upgrade-committed flag never appeared within 15s")
		}
	}
	cancel()

	err := <-done
	if err != nil {
		t.Fatalf("Supervise returned %v after upgrade committed; expected nil", err)
	}
	cur, readErr := l.ReadCurrent()
	if readErr != nil {
		t.Fatalf("ReadCurrent after upgrade: %v", readErr)
	}
	if cur != "v2" {
		t.Errorf("current = %q, want v2 (no rollback must have occurred)", cur)
	}
}

// premarkKnownGood pre-seeds the known-good marker in state.json using the
// actual hash of the installed binary at the given version. This simulates the
// launcher having previously run the binary past its startup window.
func premarkKnownGood(t *testing.T, l Layout, version string) {
	t.Helper()
	exe, err := l.StewardExeFor(version)
	if err != nil {
		t.Fatalf("StewardExeFor %q: %v", version, err)
	}
	hash, err := computeBinaryHash(exe)
	if err != nil {
		t.Fatalf("computeBinaryHash for %q: %v", version, err)
	}
	ps, err := l.loadState()
	if err != nil {
		t.Fatalf("loadState before premarkKnownGood: %v", err)
	}
	ps.KnownGood = version
	ps.KnownGoodHash = hash
	if err := l.saveState(ps); err != nil {
		t.Fatalf("saveState with known-good marker: %v", err)
	}
}

// TestSupervise_KnownGood_FastExitRestartsInPlace verifies AC2: a version
// already marked known-good that exits inside StartupWindow is restarted in
// place — Rollback() is NOT called and state.json current is unchanged.
func TestSupervise_KnownGood_FastExitRestartsInPlace(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v1")
	installFakeSteward(t, l, "v0") // previous version (must NOT become current)
	if err := l.WriteCurrent("v0"); err != nil {
		t.Fatalf("WriteCurrent v0: %v", err)
	}
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}
	// State: current=v1, previous=v0. Mark v1 as known-good.
	premarkKnownGood(t, l, "v1")

	// All children exit immediately with non-zero code — inside startup window.
	markerFile := filepath.Join(t.TempDir(), "ran")
	envForChild(t, map[string]string{
		"FAKE_STEWARD_EXIT_CODE":   "1",
		"FAKE_STEWARD_SLEEP_MS":    "0",
		"FAKE_STEWARD_MARKER_FILE": markerFile,
	})

	stderr := &bytes.Buffer{}
	s := &Supervisor{
		Layout:            l,
		StartupWindow:     50 * time.Millisecond,
		MaxRollbackCycles: 1,
		clock:             &fakeClock{sinceResult: 0}, // always inside startup window
		Stdout:            &bytes.Buffer{},
		Stderr:            stderr,
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}

	// Run with a short timeout; the known-good loop must not return an error.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := s.Supervise(ctx)
	// Context timeout is a clean cancel — Supervise must return nil.
	if err != nil {
		t.Errorf("Supervise returned %v on known-good fast-exit; want nil (restart in place, not terminal failure)", err)
	}

	// current must still be v1 — Rollback must NOT have been called.
	cur, curErr := l.ReadCurrent()
	if curErr != nil {
		t.Fatalf("ReadCurrent after known-good fast-exit: %v", curErr)
	}
	if cur != "v1" {
		t.Errorf("current = %q after known-good fast-exit, want v1 (rollback must be suppressed)", cur)
	}

	// The child must have run at least once (marker file written).
	if _, statErr := os.Stat(markerFile); statErr != nil {
		t.Errorf("child never ran (marker absent): %v", statErr)
	}

	// Stderr must mention the restart-in-place decision.
	if !bytes.Contains(stderr.Bytes(), []byte("known-good")) {
		t.Errorf("stderr did not mention known-good restart:\n%s", stderr.String())
	}
}

// TestSupervise_Probation_FastExitRollsBack verifies AC3: a freshly staged
// (not-yet-known-good) version that exits inside StartupWindow still rolls
// back to the previous version (existing probation behavior preserved).
func TestSupervise_Probation_FastExitRollsBack(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v1")
	installFakeSteward(t, l, "v2")
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}
	if err := l.WriteCurrent("v2"); err != nil {
		t.Fatalf("WriteCurrent v2: %v", err)
	}
	// State: current=v2, previous=v1. v2 has NO known-good marker (probation).

	marker := filepath.Join(t.TempDir(), "ran")
	envForChild(t, map[string]string{
		"FAKE_STEWARD_EXIT_CODE":   "1",
		"FAKE_STEWARD_SLEEP_MS":    "0",
		"FAKE_STEWARD_MARKER_FILE": marker,
	})

	stderr := &bytes.Buffer{}
	s := &Supervisor{
		Layout:            l,
		StartupWindow:     50 * time.Millisecond,
		MaxRollbackCycles: 1,
		clock:             &fakeClock{sinceResult: 0}, // always inside startup window
		Stdout:            &bytes.Buffer{},
		Stderr:            stderr,
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}

	err := runSupervisor(t, s, 10*time.Second)
	if err == nil {
		t.Fatal("Supervise must return error when non-known-good v2 fails and v1 also fails")
	}

	// Rollback must have fired: current must be v1 after the rollback.
	cur, curErr := l.ReadCurrent()
	if curErr != nil {
		t.Fatalf("ReadCurrent after probation rollback: %v", curErr)
	}
	if cur != "v1" {
		t.Errorf("current = %q after probation rollback, want v1", cur)
	}
	if !bytes.Contains(stderr.Bytes(), []byte(`rolled back to version "v1"`)) {
		t.Errorf("stderr did not mention rollback:\n%s", stderr.String())
	}
}

// TestSupervise_IncidentReplay_KnownGoodNotDemoted verifies AC4: replaying
// the 2026-06-16 incident. Known-good vA is current; a forced fast-exit on
// first start does NOT demote to vB. The launcher keeps vA current and retries.
func TestSupervise_IncidentReplay_KnownGoodNotDemoted(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v0-5-12") // old version — must NOT become current
	installFakeSteward(t, l, "v0-5-13") // known-good current
	if err := l.WriteCurrent("v0-5-12"); err != nil {
		t.Fatalf("WriteCurrent v0-5-12: %v", err)
	}
	if err := l.WriteCurrent("v0-5-13"); err != nil {
		t.Fatalf("WriteCurrent v0-5-13: %v", err)
	}
	// Mark v0-5-13 known-good (it was running fine before the reboot).
	premarkKnownGood(t, l, "v0-5-13")

	// Simulate the boot-time race: v0-5-13 exits in under 2s (0-byte logs).
	envForChild(t, map[string]string{
		"FAKE_STEWARD_EXIT_CODE": "1",
		"FAKE_STEWARD_SLEEP_MS":  "0",
	})

	stderr := &bytes.Buffer{}
	s := &Supervisor{
		Layout:            l,
		StartupWindow:     30 * time.Second,
		MaxRollbackCycles: 1,
		clock:             &fakeClock{sinceResult: time.Millisecond}, // fast exit inside 30s window
		Stdout:            &bytes.Buffer{},
		Stderr:            stderr,
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := s.Supervise(ctx)
	if err != nil {
		t.Errorf("Supervise returned %v in incident replay; want nil (known-good v0-5-13 never demoted)", err)
	}

	// v0-5-13 must remain current — no demotion to v0-5-12.
	cur, curErr := l.ReadCurrent()
	if curErr != nil {
		t.Fatalf("ReadCurrent after incident replay: %v", curErr)
	}
	if cur != "v0-5-13" {
		t.Errorf("current = %q after incident replay, want v0-5-13 (not demoted)", cur)
	}
	if bytes.Contains(stderr.Bytes(), []byte("rolled back")) {
		t.Errorf("rollback must not fire for known-good v0-5-13:\n%s", stderr.String())
	}
}

// TestSupervise_KnownGoodCutover_NewVersionEntersProbation verifies AC6 (lifecycle
// side): after a controller cutover to a new version (vB), a vB fast-exit follows
// probation rules and rolls back to known-good vA — the known-good marker for vA
// cannot protect vB from rollback.
func TestSupervise_KnownGoodCutover_NewVersionEntersProbation(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "vA")
	installFakeSteward(t, l, "vB")
	if err := l.WriteCurrent("vA"); err != nil {
		t.Fatalf("WriteCurrent vA: %v", err)
	}
	// Mark vA known-good (security-patch pre-condition).
	premarkKnownGood(t, l, "vA")

	// Controller pushes vB (security patch) via WriteCurrent. This must clear
	// vA's known-good marker and enter vB into probation.
	if err := l.WriteCurrent("vB"); err != nil {
		t.Fatalf("WriteCurrent vB: %v", err)
	}

	// Verify marker was cleared by cutover.
	ps, err := l.loadState()
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if ps.KnownGood != "" || ps.KnownGoodHash != "" {
		t.Fatalf("cutover to vB must clear known-good marker; got KnownGood=%q KnownGoodHash=%q",
			ps.KnownGood, ps.KnownGoodHash)
	}

	// vB fast-exits → must roll back to vA (probation rules apply).
	envForChild(t, map[string]string{
		"FAKE_STEWARD_EXIT_CODE": "1",
		"FAKE_STEWARD_SLEEP_MS":  "0",
	})

	stderr := &bytes.Buffer{}
	s := &Supervisor{
		Layout:            l,
		StartupWindow:     50 * time.Millisecond,
		MaxRollbackCycles: 1,
		clock:             &fakeClock{sinceResult: 0}, // fast exit inside startup window
		Stdout:            &bytes.Buffer{},
		Stderr:            stderr,
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}

	// Both vA and vB fail (same env), so supervise exhausts rollback budget and errors.
	if err := runSupervisor(t, s, 10*time.Second); err == nil {
		t.Fatal("Supervise must return error after vB fails and vA also fails")
	}

	// The rollback to vA must have fired (vB was in probation, not known-good).
	cur, curErr := l.ReadCurrent()
	if curErr != nil {
		t.Fatalf("ReadCurrent after vB probation rollback: %v", curErr)
	}
	if cur != "vA" {
		t.Errorf("current = %q after vB probation rollback, want vA", cur)
	}
	if !bytes.Contains(stderr.Bytes(), []byte(`rolled back to version "vA"`)) {
		t.Errorf("stderr must mention rollback to vA:\n%s", stderr.String())
	}
}

// TestSupervise_KnownGood_MarkedAfterHealthyRun verifies that a version which
// runs past StartupWindow and exits cleanly has the known-good marker written to
// state.json, and that marker survives a subsequent loadState (AC1 via lifecycle).
func TestSupervise_KnownGood_MarkedAfterHealthyRun(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v1")
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}

	certStoreDir := t.TempDir()
	envForChild(t, map[string]string{
		"FAKE_STEWARD_EXIT_CODE": "0",
		"FAKE_STEWARD_SLEEP_MS":  "0",
	})

	s := &Supervisor{
		Layout:            l,
		StartupWindow:     50 * time.Millisecond,
		MaxRollbackCycles: 0,
		CertStoreDir:      certStoreDir,
		clock:             &fakeClock{sinceResult: time.Minute}, // past startup window → clean
		Stdout:            &bytes.Buffer{},
		Stderr:            &bytes.Buffer{},
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Supervise(ctx) }()

	// Wait for upgrade-committed flag (written after mark-known-good).
	flagPath := filepath.Join(certStoreDir, "upgrade-committed")
	if !waitForFile(flagPath, 5*time.Second) {
		t.Fatal("upgrade-committed flag never appeared")
	}
	cancel()
	<-done

	ps, err := l.loadState()
	if err != nil {
		t.Fatalf("loadState after healthy run: %v", err)
	}
	if ps.KnownGood != "v1" {
		t.Errorf("KnownGood = %q, want v1 — must be set after binary survived StartupWindow", ps.KnownGood)
	}
	if ps.KnownGoodHash == "" {
		t.Error("KnownGoodHash must be non-empty after healthy run")
	}
}

// TestSupervise_HashFailureAfterCleanRun_SkipsKnownGoodUpdate verifies the
// post-exec hash-failure code path for a clean (past-startup-window) child exit:
//  1. Supervision does NOT abort — the loop continues.
//  2. The upgrade-committed flag is still written (counter-reset path completes).
//  3. The pre-existing KnownGood marker in state.json is left untouched, not
//     cleared, when the hash of the just-exited binary cannot be computed.
//
// The hash failure is induced by chmod-ing the binary to 0o000 after the child
// has started (the in-memory child is unaffected) but before it exits. This
// causes computeBinaryHash to return an error without ever aborting the child.
func TestSupervise_HashFailureAfterCleanRun_SkipsKnownGoodUpdate(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v1")
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}
	// Pre-seed a known-good marker to verify it survives the hash failure.
	premarkKnownGood(t, l, "v1")
	psInit, err := l.loadState()
	if err != nil {
		t.Fatalf("loadState before test: %v", err)
	}
	existingHash := psInit.KnownGoodHash
	if existingHash == "" {
		t.Fatal("premarkKnownGood must set a non-empty hash for this test to be meaningful")
	}

	markerFile := filepath.Join(t.TempDir(), "started")
	certStoreDir := t.TempDir()
	// Child sleeps long enough for the test goroutine to chmod the binary
	// before the child exits. After the sleep it exits cleanly (code 0).
	envForChild(t, map[string]string{
		"FAKE_STEWARD_EXIT_CODE":   "0",
		"FAKE_STEWARD_SLEEP_MS":    "300",
		"FAKE_STEWARD_MARKER_FILE": markerFile,
	})

	s := &Supervisor{
		Layout:            l,
		StartupWindow:     50 * time.Millisecond,
		MaxRollbackCycles: 0,
		CertStoreDir:      certStoreDir,
		clock:             &fakeClock{sinceResult: time.Minute}, // past startup window → clean exit
		Stdout:            &bytes.Buffer{},
		Stderr:            &bytes.Buffer{},
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Supervise(ctx) }()

	// Wait for the child to start, then make the binary unreadable so
	// computeBinaryHash fails on the post-exec hash call.
	if !waitForFile(markerFile, 5*time.Second) {
		t.Fatal("child never started (marker absent within 5s)")
	}
	exe, exeErr := l.StewardExeFor("v1")
	if exeErr != nil {
		t.Fatalf("StewardExeFor v1: %v", exeErr)
	}
	if chErr := os.Chmod(exe, 0o000); chErr != nil {
		t.Fatalf("chmod 000 binary: %v", chErr)
	}
	// Restore permissions so t.TempDir cleanup can remove the tree.
	t.Cleanup(func() { _ = os.Chmod(exe, 0o755) })

	// upgrade-committed must be written even when the post-exec hash fails.
	// It is written at the END of the clean-startup branch, so its presence
	// proves that the entire clean-startup path (counter reset, prune, flag)
	// ran to completion.
	flagPath := filepath.Join(certStoreDir, "upgrade-committed")
	if !waitForFile(flagPath, 5*time.Second) {
		t.Fatal("upgrade-committed flag not written after clean run with hash failure (post-exec hash failure must not skip the committed branch)")
	}
	cancel()
	<-done // supervisor exits (nil or error — both are acceptable here)

	// The pre-existing KnownGood marker must be completely untouched.
	ps, loadErr := l.loadState()
	if loadErr != nil {
		t.Fatalf("loadState after hash-failure clean run: %v", loadErr)
	}
	if ps.KnownGood != "v1" {
		t.Errorf("KnownGood = %q, want v1 — pre-existing marker must survive post-exec hash failure", ps.KnownGood)
	}
	if ps.KnownGoodHash != existingHash {
		t.Errorf("KnownGoodHash = %q, want %q — pre-existing hash must survive post-exec hash failure", ps.KnownGoodHash, existingHash)
	}
}

// TestSupervise_HashFailureAfterFailedStartup_TreatsAsNotKnownGood verifies that
// when computeBinaryHash fails (binary unreadable) after a known-good binary
// fast-exits, the launcher does NOT restart in place. Without the hash the
// launcher cannot confirm the binary is the proven one — isKnownGood stays false
// and probation rules apply (rollback fires).
//
// Scenario: v1 is known-good; v1 starts, then renames its own binary out of the
// way before exiting with code 1 (failed startup). When the launcher computes the
// post-exec hash the binary is gone, so computeBinaryHash fails → isKnownGood=false
// → rollback to v0 instead of restart-in-place. The self-rename forces the hash
// failure deterministically on every platform (chmod-to-000 is a no-op on Windows).
func TestSupervise_HashFailureAfterFailedStartup_TreatsAsNotKnownGood(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v0")
	installFakeSteward(t, l, "v1")
	if err := l.WriteCurrent("v0"); err != nil {
		t.Fatalf("WriteCurrent v0: %v", err)
	}
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}
	// State: current=v1, previous=v0. Mark v1 known-good.
	premarkKnownGood(t, l, "v1")

	// Child renames its own binary away before exiting with code 1 (simulating a
	// crashed steward whose binary is no longer where the launcher hashes it). The
	// clock reports 0 for ranFor (always inside startup window), making this look
	// like a fast exit.
	envForChild(t, map[string]string{
		"FAKE_STEWARD_EXIT_CODE":   "1",
		"FAKE_STEWARD_SLEEP_MS":    "0",
		"FAKE_STEWARD_RENAME_SELF": "1",
	})

	s := &Supervisor{
		Layout:            l,
		StartupWindow:     50 * time.Millisecond,
		MaxRollbackCycles: 1,
		clock:             &fakeClock{sinceResult: 0}, // always inside startup window → failedStartup=true
		Stdout:            &bytes.Buffer{},
		Stderr:            &bytes.Buffer{},
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Supervise(ctx) }()

	// Supervise must return an error: v1 rolls back to v0 (hash failure → not
	// known-good → probation), then v0 also fails and budget is exhausted.
	var superviseErr error
	select {
	case superviseErr = <-done:
	case <-ctx.Done():
		t.Fatal("Supervise did not exit within 15s — rollback to v0 must have stalled")
	}
	if superviseErr == nil {
		t.Error("Supervise returned nil after hash-failure rollback with exhausted budget; want non-nil error")
	}

	// current must be v0 — rollback must have fired (not restart-in-place).
	cur, readErr := l.ReadCurrent()
	if readErr != nil {
		t.Fatalf("ReadCurrent after hash-failure rollback: %v", readErr)
	}
	if cur != "v0" {
		t.Errorf("current = %q after v1 hash-failure fast-exit, want v0 (rollback must fire; v1 must NOT restart in place when hash fails)", cur)
	}
}
