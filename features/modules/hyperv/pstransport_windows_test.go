// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"context"
	"errors"
	"os"
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

// ── #3168 follow-up: deadline kill must not leak a host-attached seed VHD ────

// TestMountedSeedPathForCleanup_OnlyMountingVerbs is the [REQUIRED TEST] for the
// post-kill dismount decision. exec.CommandContext KILLS powershell.exe when the
// module-call deadline fires, and a killed process never runs its finally block —
// so the try/finally added to the mount functions in #3766 cannot clean up this
// path. Mount-VHD attaches host-wide, so the VHD survives the dead process and
// fails the NEXT VM's Add-VMHardDiskDrive with 0x80070020.
//
// Only the two verbs that actually Mount-VHD may leak. Dismounting for the others
// would be wrong: Cfgms-AttachSeedDisk attaches the disk to the VM, and force-
// dismounting there could yank a disk the VM legitimately holds.
func TestMountedSeedPathForCleanup_OnlyMountingVerbs(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want string
	}{
		{
			"MountSeedVHD leaks -Path",
			`Cfgms-MountSeedVHD -Path 'C:\cfgms-seeds\cfgms-seed-web-01.vhdx' -Label 'CIDATA'`,
			`C:\cfgms-seeds\cfgms-seed-web-01.vhdx`,
		},
		{
			"CopyToSeedVHD leaks -SeedPath",
			`Cfgms-CopyToSeedVHD -SeedPath 'C:\seeds\s.vhdx' -FileName 'user-data' -Content 'x'`,
			`C:\seeds\s.vhdx`,
		},
		{
			"NewSeedVHD only creates a file — nothing mounted",
			`Cfgms-NewSeedVHD -Path 'C:\seeds\s.vhdx' -SizeBytes 268435456`,
			"",
		},
		{
			"AttachSeedDisk attaches to the VM, not the host — must NOT be dismounted",
			`Cfgms-AttachSeedDisk -Name 'web-01' -SeedPath 'C:\seeds\s.vhdx'`,
			"",
		},
		{
			"unrelated verb",
			`Cfgms-GetVM -Name 'web-01'`,
			"",
		},
		{
			"embedded quote is unescaped from the doubled PS form",
			`Cfgms-MountSeedVHD -Path 'C:\se''ed\s.vhdx'`,
			`C:\se'ed\s.vhdx`,
		},
		{
			"unterminated literal refuses to guess",
			`Cfgms-MountSeedVHD -Path 'C:\seeds\s.vhdx`,
			"",
		},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mountedSeedPathForCleanup(tc.expr))
		})
	}
}

// TestMountedSeedPathForCleanup_RoundTripsDispatcherQuoting proves the extractor
// understands exactly what the dispatcher emits, rather than a hand-written
// approximation of it: the path is rendered with quoteForPS and must come back
// byte-identical. Without this, a path containing a quote would silently yield a
// wrong path and the cleanup would dismount nothing (or the wrong disk).
func TestMountedSeedPathForCleanup_RoundTripsDispatcherQuoting(t *testing.T) {
	for _, path := range []string{
		`C:\cfgms-seeds\cfgms-seed-web-01.vhdx`,
		`C:\ClusterStorage\CSV01\seeds\seed.vhdx`,
		`C:\od''d\se'ed name.vhdx`,
		`C:\with space\seed.vhdx`,
	} {
		expr := "Cfgms-MountSeedVHD -Path " + quoteForPS(path) + " -Label 'CIDATA'"
		assert.Equal(t, path, mountedSeedPathForCleanup(expr),
			"extractor must round-trip whatever quoteForPS produced")
	}
}

// TestDismountAfterKill_UsesFreshContext guards the subtlety that makes this fix
// work at all: the cleanup runs BECAUSE the caller's context was cancelled, so it
// must not reuse that context — doing so would kill the cleanup process
// immediately and leave the mount exactly as it was.
//
// Asserted structurally (the cleanup path shells out, so it cannot run in a unit
// test on a non-Hyper-V host): dismountAfterKill must derive its context from
// context.Background(), never from a caller-supplied one — its signature takes no
// context at all, which is what makes that impossible to get wrong.
func TestDismountAfterKill_TakesNoCallerContext(t *testing.T) {
	src := funcSourceTextPS(t, "dismountAfterKill")
	assert.Contains(t, src, "context.Background()",
		"cleanup must start from a fresh context — the caller's is already cancelled")
	assert.NotContains(t, src, "ctx context.Context",
		"dismountAfterKill must not accept a caller context; reusing the cancelled one would no-op the cleanup")
	assert.Contains(t, src, "runFreshNoCleanup",
		"cleanup must not recurse through runFresh's own kill handling")
}

// funcSourceTextPS returns the source text of a function in
// pstransport_windows.go, for assertions about how a function is written rather
// than what it returns. Used where behaviour cannot be exercised in a unit test
// (the cleanup path shells out to powershell.exe) but a structural invariant
// still needs pinning.
func funcSourceTextPS(t *testing.T, name string) string {
	t.Helper()
	src, err := os.ReadFile("pstransport_windows.go")
	require.NoError(t, err)
	s := string(src)
	marker := ") " + name + "("
	start := strings.Index(s, marker)
	require.NotEqual(t, -1, start, "function %s not found", name)
	// Walk back to the start of the func declaration line.
	for start > 0 && !strings.HasPrefix(s[start:], "func ") {
		start--
	}
	rest := s[start+1:]
	end := strings.Index(rest, "\nfunc ")
	if end == -1 {
		return s[start:]
	}
	return s[start : start+1+end]
}
