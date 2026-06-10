// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestAttachChildToJobObject_KillsChildOnLauncherExit covers the #1928
// guarantee: an abnormal launcher exit must take the supervised steward
// with it.
//
// The test re-execs this binary twice:
//
//  1. an outer "launcher" sub-process that spawns
//  2. an inner "steward" sub-process and calls attachChildToJobObject
//     to put it in a kill-on-close Job Object.
//
// The outer process exits abnormally (os.Exit(2) without Wait) after
// attaching the child to the job. If the Job Object did its job, the
// inner process must terminate within a short window even though no
// signal was delivered to it directly. The parent test polls a marker
// file to detect whether the inner process completed its sleep (= bug:
// still alive after launcher death) or was killed early (= fix
// working).
//
// Outer-process knobs:
//
//	GO_WANT_OUTER_LAUNCHER=1
//	OUTER_SELF_EXE     path to this test binary (re-exec target)
//	OUTER_MARKER_FILE  marker file the inner steward writes on natural exit
//
// Inner steward uses the existing FAKE_STEWARD_* knobs from the
// TestHelperProcess in lifecycle_test.go (sleep 10s, then write marker on
// natural completion). If the marker is absent after the wait, the kill
// landed before the steward could finish — the desired behaviour.
func TestAttachChildToJobObject_KillsChildOnLauncherExit(t *testing.T) {
	if os.Getenv("GO_WANT_OUTER_LAUNCHER") == "1" {
		runOuterLauncher()
		return
	}

	t.Logf("expected wall-clock: ~12s (3s post-kill grace + 8s past inner's 10s sleep budget, to prove the inner died early)")

	exe, err := os.Executable()
	require.NoError(t, err, "os.Executable for self re-exec")

	dir := t.TempDir()
	naturalExitMarker := filepath.Join(dir, "natural-exit.marker")
	innerStartedMarker := filepath.Join(dir, "inner-started.marker")

	outer := exec.Command(exe, "-test.run=TestAttachChildToJobObject_KillsChildOnLauncherExit") //#nosec G204 -- test self-exec
	outer.Env = append(os.Environ(),
		"GO_WANT_OUTER_LAUNCHER=1",
		"OUTER_SELF_EXE="+exe,
		"OUTER_MARKER_FILE="+naturalExitMarker,
		"OUTER_STARTED_FILE="+innerStartedMarker,
	)
	var outerOutput strings.Builder
	outer.Stdout = &outerOutput
	outer.Stderr = &outerOutput

	require.NoError(t, outer.Start(), "outer launcher start")

	// Wait for the inner steward to actually launch (marker proves
	// CreateProcess + AssignProcessToJobObject have completed).
	deadline := time.Now().Add(5 * time.Second)
	for !fileExists(innerStartedMarker) {
		if time.Now().After(deadline) {
			_ = outer.Process.Kill()
			_ = outer.Wait()
			t.Fatalf("inner steward never wrote started marker within 5s\nouter output: %s", outerOutput.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for outer to die (it self-exits 2 after attaching the child).
	require.Error(t, outer.Wait(), "outer launcher should exit non-zero")

	// Give the kernel up to 3 s to honour KILL_ON_JOB_CLOSE. In
	// practice it's near-instant after the launcher's handle closes.
	time.Sleep(3 * time.Second)

	// The inner steward was set to sleep 10 s before writing the natural-
	// exit marker. We've waited ~3 s after launcher death (well under 10 s),
	// so either (a) the kill worked and natural-exit.marker is absent, or
	// (b) the kill didn't work and the inner is still running (also no
	// marker yet). To disambiguate, wait the full 10 s window and assert
	// the marker is STILL absent — proves the inner died before completing
	// its sleep.
	time.Sleep(8 * time.Second)
	if fileExists(naturalExitMarker) {
		t.Fatalf("inner steward reached its natural exit — Job Object did NOT kill it on launcher death (orphan bug #1928 not fixed)")
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// runOuterLauncher executes inside the outer process. It spawns the inner
// "fake steward", calls attachChildToJobObject, then exits abnormally
// (os.Exit(2) without Wait) so the kernel-level JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
// is the only thing that can clean up the child.
func runOuterLauncher() {
	exe := os.Getenv("OUTER_SELF_EXE")
	naturalMarker := os.Getenv("OUTER_MARKER_FILE")
	startedMarker := os.Getenv("OUTER_STARTED_FILE")

	cmd := exec.Command(exe, "-test.run=TestHelperProcess") //#nosec G204 -- test self-exec
	// Inherit parent env (PATH, SystemRoot, etc. are required for the
	// child Go test runtime to start on Windows) and append the helper
	// knobs. The started-marker is written before the sleep; the
	// exit-marker is written after the sleep so its presence proves the
	// inner survived the 10s window. Job Object kill should land before
	// then.
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		"FAKE_STEWARD_SLEEP_MS=10000",
		"FAKE_STEWARD_MARKER_FILE="+startedMarker,
		"FAKE_STEWARD_EXIT_MARKER_FILE="+naturalMarker,
	)

	if err := cmd.Start(); err != nil {
		_, _ = os.Stderr.WriteString("outer: cmd.Start failed: " + err.Error() + "\n")
		os.Exit(3)
	}
	_, _ = os.Stderr.WriteString("outer: inner pid=" + strconv.Itoa(cmd.Process.Pid) + "\n")
	if err := attachChildToJobObject(cmd); err != nil {
		_, _ = os.Stderr.WriteString("outer: attachChildToJobObject failed: " + err.Error() + "\n")
		_ = cmd.Process.Kill()
		os.Exit(4)
	}

	// Give the inner a chance to write its started-marker. Without this,
	// outer exits so fast the kernel kills the inner before it ever
	// reaches the WriteFile call — the test then can't distinguish
	// "killed before start" from "killed after start", both of which are
	// the bug-fixed behavior we want, but the started-marker is how the
	// test detects that the inner actually entered its sleep phase.
	time.Sleep(500 * time.Millisecond)

	// Abnormal exit: do NOT Wait. The launcher process terminates
	// while the supervised steward is still running. The Job Object's
	// kill-on-close limit is the only thing that can cull the child.
	os.Exit(2)
}

