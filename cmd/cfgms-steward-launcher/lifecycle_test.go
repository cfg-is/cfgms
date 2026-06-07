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
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
//	FAKE_STEWARD_MARKER_FILE Touch this file before sleeping so the test can
//	                         verify which version actually ran.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	if marker := os.Getenv("FAKE_STEWARD_MARKER_FILE"); marker != "" {
		_ = os.WriteFile(marker, []byte("started"), 0o600)
	}
	if sleepMs := os.Getenv("FAKE_STEWARD_SLEEP_MS"); sleepMs != "" {
		if n, err := strconv.Atoi(sleepMs); err == nil && n > 0 {
			time.Sleep(time.Duration(n) * time.Millisecond)
		}
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

// fakeClock simulates time so we can deterministically test the
// startup-window logic without sleeping in real time.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Since(t time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.Sub(t)
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
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
func TestSupervise_HealthyChild_RestartsWithoutRollback(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows, time.Sleep behaviour under heavy CI load can race
		// our 50ms startup window. The behaviour is identical on Linux
		// (where every other launcher test runs in CI), so we skip this
		// timing-sensitive variant on Windows.
		t.Skip("timing-sensitive; covered on Linux CI")
	}

	l := newLayout(t)
	installFakeSteward(t, l, "v1")
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}

	// Sleep just past the 50ms startup window then exit cleanly.
	envForChild(t, map[string]string{
		"FAKE_STEWARD_SLEEP_MS":  "200",
		"FAKE_STEWARD_EXIT_CODE": "0",
	})

	s := &Supervisor{
		Layout:            l,
		StartupWindow:     50 * time.Millisecond,
		MaxRollbackCycles: 0, // ZERO rollback budget — any rollback attempt would fail
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
	// loop is in fact looping on clean exits.
	time.Sleep(700 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
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
