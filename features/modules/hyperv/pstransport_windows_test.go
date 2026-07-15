// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestRunFresh_DeadlineKillProducesDistinguishableError is the [REQUIRED TEST]
// for the #2467 diagnosability fix. When a fresh seed-op process is killed by
// the module-call context deadline (not a normal non-zero exit), runFresh must
// return an error that names the deadline kill + elapsed time — never a bare
// "fresh seed op failed: exit status 1: " with empty output that hides the fact
// that WE killed the process at the deadline.
//
// runFresh spawns its own powershell.exe -File process and references no
// psHostTransport field, so a zero-value transport exercises the real path
// without standing up the persistent PS host.
func TestRunFresh_DeadlineKillProducesDistinguishableError(t *testing.T) {
	tr := &psHostTransport{}

	// A deliberately slow seed op against a short deadline: CommandContext kills
	// powershell.exe when the 2s deadline fires, well before the 30s sleep ends.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	out, err := tr.runFresh(ctx, "Start-Sleep -Seconds 30")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected an error from a deadline-killed seed op, got nil (out=%q)", out)
	}

	msg := err.Error()

	// It must be classified as a deadline kill and name the elapsed time...
	if !strings.Contains(msg, "killed by deadline") {
		t.Fatalf("deadline-kill error must name the deadline kill; got: %v", err)
	}
	// ...and wrap the context cause (DeadlineExceeded)...
	if !strings.Contains(msg, "ctx:") {
		t.Fatalf("deadline-kill error must wrap the ctx cause; got: %v", err)
	}
	// ...and NOT masquerade as the generic non-zero-exit path.
	if strings.Contains(msg, "fresh seed op failed") {
		t.Fatalf("a deadline kill must not use the generic exit-failure path; got: %v", err)
	}

	// Sanity: the process was killed near the 2s deadline, not after the full
	// 30s sleep — proving the deadline (not a natural exit) ended it.
	if elapsed > 15*time.Second {
		t.Fatalf("expected the op to be killed near the 2s deadline, took %s", elapsed)
	}
}

// TestRunFresh_NonZeroExitUsesGenericError proves the OTHER side of the #2467
// branch: a genuine non-zero exit (the process ran to completion and failed, no
// deadline involved) still takes the generic "fresh seed op failed" path and is
// NOT mislabeled as a deadline kill.
func TestRunFresh_NonZeroExitUsesGenericError(t *testing.T) {
	tr := &psHostTransport{}

	// Ample deadline; the script exits non-zero on its own via `exit 1`.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := tr.runFresh(ctx, "Write-Output 'boom'; exit 1")
	if err == nil {
		t.Fatal("expected an error from a non-zero-exit seed op, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "fresh seed op failed") {
		t.Fatalf("a normal non-zero exit must use the generic exit-failure path; got: %v", err)
	}
	if strings.Contains(msg, "killed by deadline") {
		t.Fatalf("a normal non-zero exit must NOT be labeled a deadline kill; got: %v", err)
	}
}
