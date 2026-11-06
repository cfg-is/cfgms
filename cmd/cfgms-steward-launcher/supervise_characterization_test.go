// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Characterization tests for Supervisor.Supervise (Issue #5828). They pin the
// branches that lifecycle_test.go leaves uncovered so the complexity refactor
// can be proven behaviour-preserving. They reuse the package's real
// TestHelperProcess child, sleepRecorder, hookWriter and layout helpers.

// superviseCharStage stages v0 (previous) and v1 (current) fake stewards.
func superviseCharStage(t *testing.T) Layout {
	t.Helper()
	l := newLayout(t)
	installFakeSteward(t, l, "v0")
	installFakeSteward(t, l, "v1")
	if err := l.WriteCurrent("v0"); err != nil {
		t.Fatal(err)
	}
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatal(err)
	}
	return l
}

// MaxRollbackCycles zero is a deliberate "no auto-rollback" choice and negative
// values coerce to zero: a failing probation child is retried, never rolled back.
func TestSuperviseChar_MaxRollbackCycles_ZeroAndNegativeNeverRollBack(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cycles int
	}{
		{"zero", 0},
		{"negative", -3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := superviseCharStage(t)
			envForChild(t, map[string]string{"FAKE_STEWARD_EXIT_CODE": "1"})
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			rec := &sleepRecorder{n: 3, cancel: cancel}
			stderr := &bytes.Buffer{}
			s := &Supervisor{
				Layout:            l,
				StartupWindow:     time.Hour,
				MaxRollbackCycles: tc.cycles,
				Stdout:            &bytes.Buffer{},
				Stderr:            stderr,
				ExtraArgs:         []string{"-test.run=TestHelperProcess"},
				sleep:             rec.sleep,
				clock:             &fakeClock{sinceResult: 0},
			}
			if err := s.Supervise(ctx); err != nil {
				t.Fatalf("Supervise = %v, want nil", err)
			}
			if s.MaxRollbackCycles != 0 {
				t.Errorf("MaxRollbackCycles = %d after Supervise, want 0", s.MaxRollbackCycles)
			}
			if cur, _ := l.ReadCurrent(); cur != "v1" {
				t.Errorf("current = %q, want v1 (no rollback)", cur)
			}
			out := stderr.String()
			if strings.Contains(out, "rolled back") {
				t.Errorf("rollback fired:\n%s", out)
			}
			if !strings.Contains(out, "no rollback available") {
				t.Errorf("stderr missing no-rollback fault:\n%s", out)
			}
			d := rec.got()
			if len(d) < 3 || d[0] != initialRestartBackoff || d[1] != 2*initialRestartBackoff {
				t.Errorf("backoff delays = %v, want doubling from %s", d, initialRestartBackoff)
			}
			ps, err := l.loadState()
			if err != nil {
				t.Fatal(err)
			}
			if ps.ConsecutiveFailures < 3 {
				t.Errorf("ConsecutiveFailures = %d, want >= 3", ps.ConsecutiveFailures)
			}
		})
	}
}

// A known-good version whose fast non-zero exit coincides with a context cancel
// exits cleanly, logs the suppression, and is not rolled back.
func TestSuperviseChar_KnownGood_FastExitOnCancel_SuppressedCleanExit(t *testing.T) {
	l := superviseCharStage(t)
	premarkKnownGood(t, l, "v1")
	envForChild(t, map[string]string{"FAKE_STEWARD_EXIT_CODE": "1"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	stderr := &bytes.Buffer{}
	s := &Supervisor{
		Layout:            l,
		StartupWindow:     time.Hour,
		MaxRollbackCycles: 2,
		Stdout:            &bytes.Buffer{},
		Stderr:            stderr,
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
		// Since runs right after the child exits: cancel there so the fast
		// exit coincides with shutdown.
		clock: &scriptedClock{since: func() time.Duration { cancel(); return 0 }},
	}
	if err := s.Supervise(ctx); err != nil {
		t.Fatalf("Supervise = %v, want nil", err)
	}
	if !strings.Contains(stderr.String(), "fast exit (ran 0s) coincided with shutdown; rollback suppressed, exiting cleanly") {
		t.Errorf("stderr missing suppression line:\n%s", stderr.String())
	}
	if cur, _ := l.ReadCurrent(); cur != "v1" {
		t.Errorf("current = %q, want v1", cur)
	}
}

// A probation child that fast-exits on cancel is still a failed upgrade: it
// falls through to the rollback logic.
func TestSuperviseChar_Probation_FastExitOnCancel_RollsBack(t *testing.T) {
	l := superviseCharStage(t)
	envForChild(t, map[string]string{"FAKE_STEWARD_EXIT_CODE": "1"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	stderr := &bytes.Buffer{}
	s := &Supervisor{
		Layout:            l,
		StartupWindow:     time.Hour,
		MaxRollbackCycles: 1,
		Stdout:            &bytes.Buffer{},
		Stderr:            stderr,
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
		clock:             &scriptedClock{since: func() time.Duration { cancel(); return 0 }},
	}
	if err := s.Supervise(ctx); err != nil {
		t.Fatalf("Supervise = %v, want nil", err)
	}
	if cur, _ := l.ReadCurrent(); cur != "v0" {
		t.Errorf("current = %q, want v0 (rolled back)", cur)
	}
	if !strings.Contains(stderr.String(), `rolled back to version "v0"`) {
		t.Errorf("stderr missing rollback line:\n%s", stderr.String())
	}
}

// A clean exit inside the startup window with no previous version reports the
// "exited inside startup window" fault (not the child-failed variant).
func TestSuperviseChar_CleanFastExit_NoPrevious_ReportsWindowFault(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v1")
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatal(err)
	}
	envForChild(t, map[string]string{"FAKE_STEWARD_EXIT_CODE": "0"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rec := &sleepRecorder{n: 1, cancel: cancel}
	stderr := &bytes.Buffer{}
	s := &Supervisor{
		Layout:            l,
		StartupWindow:     time.Hour,
		MaxRollbackCycles: 1,
		Stdout:            &bytes.Buffer{},
		Stderr:            stderr,
		ExtraArgs:         []string{"-test.run=TestHelperProcess"},
		sleep:             rec.sleep,
		clock:             &fakeClock{sinceResult: 0},
	}
	if err := s.Supervise(ctx); err != nil {
		t.Fatalf("Supervise = %v, want nil", err)
	}
	if !strings.Contains(stderr.String(), "launcher: child exited inside startup window (0s) and no rollback available") {
		t.Errorf("stderr missing window fault:\n%s", stderr.String())
	}
}

// A healthy run whose state cannot be loaded reports it and keeps supervising.
func TestSuperviseChar_HealthyRun_StateLoadFailure_Reported(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v1")
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatal(err)
	}
	envForChild(t, map[string]string{"FAKE_STEWARD_EXIT_CODE": "0"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rec := &sleepRecorder{n: 1, cancel: cancel}
	stderr := &bytes.Buffer{}
	s := &Supervisor{
		Layout:        l,
		StartupWindow: time.Second,
		Stdout:        &bytes.Buffer{},
		Stderr:        stderr,
		ExtraArgs:     []string{"-test.run=TestHelperProcess"},
		sleep:         rec.sleep,
		clock: &scriptedClock{since: func() time.Duration {
			writeRawState(t, l, "{not json")
			return time.Minute
		}},
	}
	if err := s.Supervise(ctx); err != nil {
		t.Fatalf("Supervise = %v, want nil", err)
	}
	out := stderr.String()
	if !strings.Contains(out, "launcher: load state for counter reset:") {
		t.Errorf("stderr missing load-state line:\n%s", out)
	}
	if !strings.Contains(out, "launcher: read current version:") {
		t.Errorf("loop did not continue to the next iteration:\n%s", out)
	}
}

// A healthy run whose upgrade-committed flag cannot be written reports it.
func TestSuperviseChar_HealthyRun_CommitFlagWriteFailure_Reported(t *testing.T) {
	l := newLayout(t)
	installFakeSteward(t, l, "v1")
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatal(err)
	}
	envForChild(t, map[string]string{"FAKE_STEWARD_EXIT_CODE": "0"})
	certStore := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(certStore, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	stderr := &hookWriter{needle: "write upgrade-committed flag", hook: cancel}
	s := &Supervisor{
		Layout:        l,
		StartupWindow: time.Second,
		CertStoreDir:  certStore,
		Stdout:        &bytes.Buffer{},
		Stderr:        stderr,
		ExtraArgs:     []string{"-test.run=TestHelperProcess"},
		clock:         &fakeClock{sinceResult: time.Minute},
	}
	if err := s.Supervise(ctx); err != nil {
		t.Fatalf("Supervise = %v, want nil", err)
	}
	if !strings.Contains(stderr.String(), "launcher: write upgrade-committed flag:") {
		t.Errorf("stderr missing commit-flag failure:\n%s", stderr.String())
	}
	ps, err := l.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if ps.KnownGood != "v1" || ps.ConsecutiveFailures != 0 {
		t.Errorf("state = %+v, want known-good v1 with zero failures", ps)
	}
}
