// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// TestWindowsServiceHandler_TerminalFailure_ReportsServiceSpecificExitCode
// verifies AC5: when the supervise loop exits on its own (terminal failure —
// no rollback available), Execute must return svcSpecificEC=true with a
// non-zero exit code so that Win32_Service.ExitCode is non-zero and the SCM
// applies its configured RESTART recovery actions.
//
// The three independent self-heal caps are:
//   - SCM's OS-configured reset period (sc failure reset=86400)
//   - launcher MaxRollbackCycles (default 1): governs how many times the
//     launcher itself will roll back before giving up and surfacing a terminal
//     failure to the SCM.
//   - Known-good restart-in-place loop: a proven binary is retried
//     indefinitely; SCM recovery fires only when a non-known-good binary
//     exhausts rollback budget and the launcher process exits.
//
// Expected Win32_Service state after terminal failure:
//
//	ExitCode:        ERROR_SERVICE_SPECIFIC_ERROR (1066)
//	ServiceExitCode: the launcher's own exit code (1 for supervise error)
func TestWindowsServiceHandler_TerminalFailure_ReportsServiceSpecificExitCode(t *testing.T) {
	// Empty root with no current version: Supervise returns an error immediately.
	root := t.TempDir()

	r := make(chan svc.ChangeRequest)
	status := make(chan svc.Status, 10)

	h := &windowsServiceHandler{
		// --max-rollbacks 0: no rollback budget → terminal failure on first child error.
		args: []string{"--root", root, "--max-rollbacks", "0"},
	}

	svcSpecific, exitCode := h.Execute(nil, r, status)

	if !svcSpecific {
		t.Errorf("Execute returned svcSpecificEC=false on terminal failure; want true so SCM " +
			"records ERROR_SERVICE_SPECIFIC_ERROR and applies recovery actions (AC5)")
	}
	if exitCode == 0 {
		t.Errorf("Execute returned exitCode=0 on terminal failure; want non-zero so " +
			"Win32_Service.ExitCode is non-zero and SCM recovery fires (AC5)")
	}
}

// TestWindowsServiceHandler_AdminStop_DoesNotTriggerRecovery verifies AC5
// (negative case): an SCM-initiated Stop must NOT trigger recovery — it must
// return svcSpecificEC=false so Win32_Service.ExitCode stays 0 (clean stop).
func TestWindowsServiceHandler_AdminStop_DoesNotTriggerRecovery(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v1")
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}

	// Child sleeps long. Use a 10ms startup window so the child is considered
	// past it before Stop arrives (~100ms after Running is reported).
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("FAKE_STEWARD_SLEEP_MS", "60000")
	t.Setenv("FAKE_STEWARD_EXIT_CODE", "0")

	r := make(chan svc.ChangeRequest, 1)
	status := make(chan svc.Status, 20)

	h := &windowsServiceHandler{
		args: []string{
			"--root", l.Root,
			"--startup-window", "10ms",
			"--child-args", "-test.run=TestHelperProcess",
		},
	}

	type execResult struct {
		svcSpecific bool
		code        uint32
	}
	resultCh := make(chan execResult, 1)
	go func() {
		s, c := h.Execute(nil, r, status)
		resultCh <- execResult{s, c}
	}()

	// Drain status until Running, then wait for the startup window to elapse,
	// then send Stop.
	deadline := time.Now().Add(15 * time.Second)
	var runningStatus svc.Status
	for {
		select {
		case st := <-status:
			if st.State == svc.Running {
				runningStatus = st
				goto sendStop
			}
		case <-time.After(time.Until(deadline)):
			t.Fatal("service did not reach Running state within 15s")
		}
	}
sendStop:
	// Give the startup window (10ms) time to elapse so ranFor > StartupWindow
	// when the child is killed. This ensures ctx cancel is seen as a clean
	// shutdown rather than a startup failure.
	time.Sleep(100 * time.Millisecond)
	r <- svc.ChangeRequest{Cmd: svc.Stop, CurrentStatus: runningStatus}

	select {
	case res := <-resultCh:
		if res.svcSpecific {
			t.Errorf("Execute returned svcSpecificEC=true on admin Stop; " +
				"must be false (clean stop, no SCM recovery) (AC5)")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Execute did not return after Stop within 15s")
	}
}

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

// TestSupervise_RepairsMissingServiceRegistration (REQUIRED, #2465): the
// dedicated repair ticker the supervise loop launches (runServiceRegistrationRepair)
// re-creates a service registration that is deleted mid-flight, within one check
// interval, and logs a greppable self-repair event.
//
// It drives runServiceRegistrationRepair directly with the real per-tick action
// (repairServiceIfMissing) bound to a UNIQUE throwaway service — not via a full
// Supervise() run, which would need a live steward child, and not against the
// real CFGMSSteward name, which would delete the host's running steward. This is
// the exact goroutine + per-tick function Supervise wires in production.
func TestSupervise_RepairsMissingServiceRegistration(t *testing.T) {
	scm := requireSCM(t)
	name := uniqueTestServiceName(t)

	// Create the service, then delete it out from under us — the incident's
	// "AV remediation deleted the registration" failure mode.
	s, err := scm.CreateService(name, testRepairExePath, mgr.Config{StartType: mgr.StartAutomatic})
	require.NoError(t, err)
	s.Close()
	existing, err := scm.OpenService(name)
	require.NoError(t, err)
	require.NoError(t, existing.Delete())
	existing.Close()

	ok, err := serviceRegistrationOK(name)
	require.NoError(t, err)
	require.False(t, ok, "precondition: registration deleted")

	// Run the repair ticker on a short interval, targeting the test service.
	// buf is mutex-guarded because the ticker goroutine writes to it concurrently
	// with the assertion read below; repaired signals once the per-tick action has
	// both re-created the registration AND written its event, establishing a
	// happens-before edge so the read after <-repaired sees the completed write.
	buf := &syncBuffer{}
	sup := &Supervisor{Stderr: buf}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repaired := make(chan struct{}, 1)
	go sup.runServiceRegistrationRepair(ctx, 100*time.Millisecond, func(w io.Writer) {
		repairServiceIfMissing(w, name, testRepairExePath, nil)
		if ok, err := serviceRegistrationOK(name); err == nil && ok {
			select {
			case repaired <- struct{}{}:
			default:
			}
		}
	})

	select {
	case <-repaired:
	case <-time.After(3 * time.Second):
		t.Fatal("the supervise repair ticker did not re-create the deleted registration within 3s")
	}
	cancel()

	ok, err = serviceRegistrationOK(name)
	require.NoError(t, err)
	require.True(t, ok, "registration must exist after the repair ticker ran")
	assert.Contains(t, buf.String(), "event=service_registration_repaired",
		"the repair must emit a greppable structured event")
}

// syncBuffer is a minimal mutex-guarded io.Writer for tests that read a buffer
// written by a background goroutine — avoids the data race a bare bytes.Buffer
// would incur under `go test -race`.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
