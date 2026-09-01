// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// ── #3168: runFresh failure diagnostics ────────────────────────────────────

// TestFreshSeedOpError_EmptyOutputSaysSo is the [REQUIRED TEST] for the
// diagnostic that made the #3168 investigation expensive. The old message,
// `fresh seed op failed: exit status 1: `, reads as a truncated string — it
// gives no hint that PowerShell genuinely printed nothing on either stream, and
// names no verb, so a log reader cannot tell WHICH seed op failed or why there
// is no detail. The empty case must say so in words and name the verb.
func TestFreshSeedOpError_EmptyOutputSaysSo(t *testing.T) {
	err := freshSeedOpError(errors.New("exit status 1"), "",
		`Cfgms-AttachSeedDisk -Name "stw-01" -SeedPath "C:\seeds\s.vhdx"`, 1500*time.Millisecond)

	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "exit status 1", "the underlying exec error must be preserved")
	assert.Contains(t, msg, "NO output",
		"an empty combined output must be stated explicitly, not left as a dangling colon")
	assert.Contains(t, msg, "Cfgms-AttachSeedDisk",
		"the failing verb must be named so a log reader knows which seed op died")
	assert.Contains(t, msg, "1.5s", "elapsed time helps separate a hang from an instant failure")
}

// TestFreshSeedOpError_RealOutputIsSurfacedVerbatim: when PowerShell DID print
// something, that text is the diagnosis and must be surfaced unchanged rather
// than replaced by the generic empty-output wording.
func TestFreshSeedOpError_RealOutputIsSurfacedVerbatim(t *testing.T) {
	psText := "Add-VMHardDiskDrive : Failed to add device 'Virtual Hard Disk'. (0x80070020)"
	err := freshSeedOpError(errors.New("exit status 1"), "\n  "+psText+"  \n",
		"Cfgms-AttachSeedDisk -Name \"stw-01\"", time.Second)

	require.Error(t, err)
	assert.Contains(t, err.Error(), psText, "real PowerShell output must be surfaced verbatim")
	assert.NotContains(t, err.Error(), "NO output",
		"the empty-output wording must not appear when there IS output")
}

// TestPSVerbOf_DoesNotLeakArguments: the verb is safe to embed in an error, but
// the argument tail carries host paths and other caller-supplied values that
// must not be pasted into an error string.
func TestPSVerbOf_DoesNotLeakArguments(t *testing.T) {
	got := psVerbOf(`Cfgms-CopyToSeedVHD -SeedPath "C:\seeds\secret-host-path.vhdx" -Content "user-data"`)
	assert.Equal(t, "Cfgms-CopyToSeedVHD", got)

	for _, in := range []string{"", "   ", "Write-Output 'hi'", "$x = 1"} {
		assert.Equal(t, "unknown", psVerbOf(in),
			"a non-Cfgms expression must not be echoed back into an error message: %q", in)
	}
}
