// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/pkg/security"
	"github.com/cfgis/cfgms/pkg/testutil/winacct"
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
	useTestStagingBase(t)
	tr := &psHostTransport{}

	// A deliberately slow seed op against a short deadline: CommandContext kills
	// powershell.exe when the 2s deadline fires, well before the 30s sleep ends.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	out, err := tr.runFresh(ctx, "Sleep", "Start-Sleep -Seconds 30", nil)
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
	useTestStagingBase(t)
	tr := &psHostTransport{}

	// Ample deadline; the script exits non-zero on its own via `exit 1`.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := tr.runFresh(ctx, "Boom", "Write-Output 'boom'; exit 1", nil)
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
	err := freshSeedOpError(errors.New("exit status 1"), "", "AttachSeedDisk", 1500*time.Millisecond)

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
	err := freshSeedOpError(errors.New("exit status 1"), "\n  "+psText+"  \n", "AttachSeedDisk", time.Second)

	require.Error(t, err)
	assert.Contains(t, err.Error(), psText, "real PowerShell output must be surfaced verbatim")
	assert.NotContains(t, err.Error(), "NO output",
		"the empty-output wording must not appear when there IS output")
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
//
// [REQUIRED TEST] The path is taken from the call's structured args (Path for
// MountSeedVHD, SeedPath for CopyToSeedVHD), never parsed out of script text.
func TestMountedSeedPathForCleanup_OnlyMountingVerbs(t *testing.T) {
	args := map[string]string{
		"Path":     `C:\cfgms-seeds\se'ed \u2019web-01.vhdx`,
		"SeedPath": `C:\seeds\s.vhdx`,
		"Name":     "web-01",
	}
	assert.Equal(t, args["Path"], mountedSeedPathForCleanup("MountSeedVHD", args),
		"MountSeedVHD leaks its Path, byte for byte")
	assert.Equal(t, args["SeedPath"], mountedSeedPathForCleanup("CopyToSeedVHD", args),
		"CopyToSeedVHD leaks its SeedPath")
	assert.Empty(t, mountedSeedPathForCleanup("MountSeedVHD", map[string]string{}))

	// Every other verb returns "": NewSeedVHD only creates a file, and
	// AttachSeedDisk attaches to the VM, not the host — it must NOT be dismounted.
	for _, spec := range psDispatchTable {
		if spec.Verb == "MountSeedVHD" || spec.Verb == "CopyToSeedVHD" {
			continue
		}
		assert.Empty(t, mountedSeedPathForCleanup(spec.Verb, args), "Cfgms-%s cannot leak a mount", spec.Verb)
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

// ── #5111: values travel as data, never as script text ───────────────────

// newTestPSHost starts the real persistent PowerShell host with the
// production preamble. The runner has no Hyper-V cmdlets, so tests use verbs
// that fail before, or never reach, a Hyper-V cmdlet.
func newTestPSHost(t *testing.T) *psHostTransport {
	t.Helper()
	useTestStagingBase(t) // calls stage their args files (#5635)
	tr, err := newPSHostTransport(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// TestPSHost_IntegerSubexpressionIsNotEvaluated is the [REQUIRED TEST] for
// the demonstrated hole. Before #5111, the dispatcher spliced the trimmed MemoryMB
// string into the command text unquoted, so a subexpression ran at parameter
// binding as LocalSystem — before Set-VM was ever reached. Now the value must
// fail integer parsing and run nothing.
func TestPSHost_IntegerSubexpressionIsNotEvaluated(t *testing.T) {
	tr := newTestPSHost(t)
	ctx := context.Background()
	dir := t.TempDir()

	marker := filepath.Join(dir, "int-marker.txt")
	_, err := tr.ExecutePS(ctx, psSetVMMemory, map[string]string{
		"Name":     "web-01",
		"MemoryMB": "$(New-Item -ItemType File -Path '" + marker + "')",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not an integer")
	assert.NoFileExists(t, marker, "an integer parameter must never be evaluated as code")

	// A string path carrying a statement separator and a marker-creating
	// command is a literal path to Remove-Item -LiteralPath, nothing more.
	marker2 := filepath.Join(dir, "str-marker.txt")
	_, err = tr.ExecutePS(ctx, psDeleteSeedMedia, map[string]string{
		"Path": "x'; New-Item -ItemType File -Path '" + marker2 + "'; '",
	})
	require.NoError(t, err)
	assert.NoFileExists(t, marker2, "a string value must never be evaluated as code")
}

// TestPSHost_UnicodeQuotePathIsData: a file whose name holds U+2018 and
// U+2019, passed as the Path of the seed-media delete verb, is deleted — the
// value arrived byte for byte as data. Regression test; not claimed to fail
// on the old quoting.
func TestPSHost_UnicodeQuotePathIsData(t *testing.T) {
	tr := newTestPSHost(t)
	target := filepath.Join(t.TempDir(), "seed \u2018web\u2019 01.vhdx")
	require.NoError(t, os.WriteFile(target, []byte("seed"), 0o600))

	_, err := tr.ExecutePS(context.Background(), psDeleteSeedMedia, map[string]string{"Path": target})
	require.NoError(t, err)
	assert.NoFileExists(t, target)
}

// TestPSHost_CfgmsInvokeStringRoundTrip is the [REQUIRED TEST] for verbatim
// strings. Windows PowerShell 5.1's ConvertFrom-Json turns the escaped
// "\/Date(...)\/" form into [DateTime]; Go's encoder never emits that escape,
// so a /Date(0)/ value must arrive as the same string. Quotes must survive too.
// A test-only echo verb, defined in the live host, reports the bound value's
// type and its UTF-8 bytes in hex, so console encoding cannot blur the check.
func TestPSHost_CfgmsInvokeStringRoundTrip(t *testing.T) {
	tr := newTestPSHost(t)
	ctx := context.Background()
	_, err := tr.run(ctx, "function Cfgms-EchoTest { param($Value) "+
		"if ($Value -is [string]) { 'string:' + [BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes($Value)) } "+
		"else { 'type:' + $Value.GetType().FullName } }")
	require.NoError(t, err)

	tmp := t.TempDir()
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)
	for _, v := range []string{
		"/Date(0)/",
		`\/Date(0)\/`,
		"2026-10-16T00:00:00Z",
		"O'Brien \u2018a\u2019 \u201ab\u201b \"c\"",
		"line1\r\nline2 $(x) `n",
	} {
		out, err := tr.runCall(ctx, psCall{Verb: "EchoTest", Mode: psModeHost, Args: []psArg{{"Value", v}}})
		require.NoError(t, err)
		want := "string:" + strings.ToUpper(strings.Join(hexBytes([]byte(v)), "-"))
		assert.Equal(t, want, strings.TrimSpace(out), "value %q must arrive unchanged", v)
	}
	left, err := os.ReadDir(tmp)
	require.NoError(t, err)
	assert.Empty(t, left, "every args file must be removed after its call")
}

// TestPSHost_CfgmsInvokeRefusesNonScalar: a JSON property that is not a
// string, number or boolean is refused before the verb runs.
func TestPSHost_CfgmsInvokeRefusesNonScalar(t *testing.T) {
	tr := newTestPSHost(t)
	ctx := context.Background()
	for name, body := range map[string]string{
		"object": `{"Name":{"a":1}}`,
		"array":  `{"Name":[1,2]}`,
		"null":   `{"Name":null}`,
		"date":   `{"Name":"\/Date(0)\/"}`,
	} {
		t.Run(name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "cfgms-args-*.json")
			require.NoError(t, err)
			_, err = f.WriteString(body)
			require.NoError(t, err)
			require.NoError(t, f.Close())
			expr, err := invokeExpression("GetVM", f.Name())
			require.NoError(t, err)
			_, err = tr.run(ctx, expr)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "is not a string, number or boolean")
		})
	}

	t.Run("unknown verb", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "cfgms-args-*.json")
		require.NoError(t, err)
		require.NoError(t, f.Close())
		expr, err := invokeExpression("NoSuchVerb", f.Name())
		require.NoError(t, err)
		_, err = tr.run(ctx, expr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown verb")
	})
}

func hexBytes(b []byte) []string {
	out := make([]string, len(b))
	for i, c := range b {
		out[i] = fmt.Sprintf("%02x", c)
	}
	return out
}

// TestPSHost_ClusterAccessHintQuotesClusterName: the operator-facing
// Grant-ClusterAccess hint built by Cfgms-GetClusterAccessSelf single-quotes the
// cluster name and doubles embedded single quotes, so a copied hint passes it as
// one literal argument. The hint expression is taken from the production
// preamble and evaluated in a real PowerShell host.
func TestPSHost_ClusterAccessHintQuotesClusterName(t *testing.T) {
	body := preambleFunctionBody(t, "Cfgms-GetClusterAccessSelf")
	start := strings.Index(body, `("Grant-ClusterAccess`)
	require.NotEqual(t, -1, start, "remediation hint not found")
	end := strings.Index(body[start:], "$me)")
	require.NotEqual(t, -1, end)
	hint := body[start : start+end+len("$me)")]

	tr := newTestPSHost(t)
	out, err := tr.run(context.Background(),
		`$ClusterName = 'lab''hv; Stop-Computer'; $me = 'LAB\NODE1$'; `+hint)
	require.NoError(t, err)
	assert.Equal(t, `Grant-ClusterAccess -Cluster 'lab''hv; Stop-Computer' -User 'LAB\NODE1$' -Full`, strings.TrimSpace(out))
}

// ── #5635: staging in a steward-only directory ───────────────────────────

// requireElevated skips t unless the test runs elevated. Securing the Hyper-V
// staging base assigns BUILTIN\Administrators as owner, and the tests hand
// directories to other principals; both need an elevated administrator, as
// the steward (a SYSTEM service) and the native Windows CI runners are.
func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated administrator: securing the Hyper-V staging base assigns BUILTIN\\Administrators as owner")
	}
}

// stagingBaseOwnedBy creates a staging base under t.TempDir() owned by the
// owner in sddl (e.g. "O:BA") and points hypervStagingBase at it for the test.
func stagingBaseOwnedBy(t *testing.T, sddl string) string {
	t.Helper()
	return stagingBaseAt(t, filepath.Join(t.TempDir(), "hyperv-staging"), sddl)
}

// stagingBaseAt creates the staging base at base, owned by the owner in sddl,
// and points hypervStagingBase at it for the test.
func stagingBaseAt(t *testing.T, base, sddl string) string {
	t.Helper()
	requireElevated(t)
	require.NoError(t, os.Mkdir(base, 0o700))
	sd, err := windows.SecurityDescriptorFromString(sddl)
	require.NoError(t, err)
	owner, _, err := sd.Owner()
	require.NoError(t, err)
	winacct.SetOwner(t, base, owner)

	prev := hypervStagingBase
	hypervStagingBase = base
	t.Cleanup(func() { hypervStagingBase = prev })
	return base
}

// useTestStagingBase points hypervStagingBase at an admin-owned temporary
// directory, so tests that stage never write under the real %ProgramData%.
func useTestStagingBase(t *testing.T) string {
	t.Helper()
	return stagingBaseOwnedBy(t, "O:BA")
}

// moveSystemTemp points the system temporary directory at a fresh directory,
// so a regression to os.CreateTemp("", ...) would stage there.
func moveSystemTemp(t *testing.T) {
	t.Helper()
	fakeTemp := filepath.Join(t.TempDir(), "system-temp")
	require.NoError(t, os.Mkdir(fakeTemp, 0o700))
	t.Setenv("TMP", fakeTemp)
	t.Setenv("TEMP", fakeTemp)
	require.True(t, strings.EqualFold(filepath.Clean(os.TempDir()), filepath.Clean(fakeTemp)))
}

// isUnderDir reports whether path lies inside dir, ignoring case.
func isUnderDir(path, dir string) bool {
	return strings.HasPrefix(strings.ToLower(resolvePath(path)),
		strings.ToLower(resolvePath(dir))+string(filepath.Separator))
}

// resolvePath returns the long-form, symlink-free form of p so an 8.3 short
// name (C:\Users\RUNNER~1) and its long form compare equal. A path that cannot
// be resolved falls back to its cleaned form.
func resolvePath(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return filepath.Clean(resolved)
	}
	// The leaf may already be removed; resolve the parent and re-attach it.
	if parent, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		return filepath.Join(parent, filepath.Base(p))
	}
	return filepath.Clean(p)
}

// isDirectlyIn reports whether path's parent directory is dir, ignoring case
// and short/long name forms. A file in a subfolder or elsewhere is false.
func isDirectlyIn(path, dir string) bool {
	return strings.EqualFold(resolvePath(filepath.Dir(path)), resolvePath(dir))
}

// TestRunFresh_StagesScriptInSecuredBase (REQUIRED, #5635): the script
// runFresh hands to powershell.exe lives directly in the configured base and
// not under os.TempDir().
func TestRunFresh_StagesScriptInSecuredBase(t *testing.T) {
	base := useTestStagingBase(t)
	moveSystemTemp(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := (&psHostTransport{}).runFresh(ctx, "ScriptPath", "Write-Output $PSCommandPath", nil)
	require.NoError(t, err)

	path := strings.TrimSpace(out)
	require.NotEmpty(t, path)
	assert.True(t, isDirectlyIn(path, base),
		"staged script %q must be directly in the staging base %q", path, base)
	assert.False(t, isUnderDir(path, os.TempDir()),
		"staged script %q must not be under the system temporary directory", path)
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "runFresh must remove its staged script")
}

// TestRunDetached_StagesScriptInSecuredBase (REQUIRED, #5635): the detached
// move script lives in the configured base, and its self-delete and the reaper
// still remove it.
func TestRunDetached_StagesScriptInSecuredBase(t *testing.T) {
	base := useTestStagingBase(t)
	moveSystemTemp(t)

	record := filepath.Join(t.TempDir(), "detached-path.txt")
	expression := "Set-Content -LiteralPath '" + record + "' -Value $PSCommandPath -NoNewline"
	exited := make(chan struct{})
	_, err := (&psHostTransport{}).runDetached(expression, func() { close(exited) })
	require.NoError(t, err)

	select {
	case <-exited:
	case <-time.After(60 * time.Second):
		t.Fatal("detached PowerShell process did not exit within 60s")
	}

	var recorded []byte
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if recorded, err = os.ReadFile(record); err == nil && len(recorded) > 0 { // #nosec G304 - test reads the file it named
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.NoError(t, err, "the detached script must record its path")
	path := strings.TrimSpace(string(recorded))
	assert.True(t, isDirectlyIn(path, base),
		"detached script %q must be directly in the staging base %q", path, base)
	assert.False(t, isUnderDir(path, os.TempDir()),
		"detached script %q must not be under the system temporary directory", path)
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "the detached script must be removed after it exits")
}

// TestWriteArgsFile_StagesInSecuredBase (REQUIRED, #5635): the call-arguments
// file lives directly in the configured base and not under os.TempDir().
func TestWriteArgsFile_StagesInSecuredBase(t *testing.T) {
	base := useTestStagingBase(t)
	moveSystemTemp(t)

	path, remove, err := writeArgsFile(psCall{Verb: "GetVM"})
	require.NoError(t, err)
	assert.True(t, isDirectlyIn(path, base),
		"args file %q must be directly in the staging base %q", path, base)
	assert.False(t, isUnderDir(path, os.TempDir()),
		"args file %q must not be under the system temporary directory", path)

	remove()
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "remove must delete the args file")
	remove() // a second remove is a no-op
}

// TestRunFresh_RefusesBaseOwnedByUsers (REQUIRED, #5635): with a staging base
// owned by BUILTIN\Users, runFresh returns an error naming the staging step,
// runs no PowerShell, and leaves the base empty.
func TestRunFresh_RefusesBaseOwnedByUsers(t *testing.T) {
	base := stagingBaseOwnedBy(t, "O:BU")

	marker := filepath.Join(t.TempDir(), "ran.txt")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := (&psHostTransport{}).runFresh(ctx, "Marker",
		"Set-Content -LiteralPath '"+marker+"' -Value ran", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrUntrustedDirOwner)
	assert.Contains(t, err.Error(), "secure staging directory")

	_, statErr := os.Stat(marker)
	assert.True(t, os.IsNotExist(statErr), "PowerShell must not run when the staging base cannot be secured")
	entries, rerr := os.ReadDir(base)
	require.NoError(t, rerr)
	assert.Empty(t, entries, "nothing may be staged in a refused base")
}

func TestDefaultHypervStagingBase(t *testing.T) {
	t.Setenv("ProgramData", `D:\PD`)
	assert.Equal(t, `D:\PD\cfgms\hyperv-staging`, defaultHypervStagingBase())
	t.Setenv("ProgramData", "")
	assert.Equal(t, `C:\ProgramData\cfgms\hyperv-staging`, defaultHypervStagingBase())
}
