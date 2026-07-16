// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package script

// This file is compiled only on Windows (Go filename convention: _windows.go suffix).

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWTSGetActiveConsoleSessionId_FindsInKernel32 verifies that
// WTSGetActiveConsoleSessionId is loadable from kernel32.dll (not wtsapi32.dll).
// This test always runs regardless of whether a console session is active, providing
// CI-safe regression coverage for the DLL fix.
func TestWTSGetActiveConsoleSessionId_FindsInKernel32(t *testing.T) {
	err := procWTSGetActiveConsoleSessionId.Find()
	require.NoError(t, err, "WTSGetActiveConsoleSessionId must be found in kernel32.dll")
}

// TestParseActiveSessionID_SentinelReturnsNoUser verifies that the sentinel value
// 0xFFFFFFFF maps to ErrNoUserLoggedIn. Pure function; no WTS API call needed.
func TestParseActiveSessionID_SentinelReturnsNoUser(t *testing.T) {
	id, err := parseActiveSessionID(uintptr(activeConsoleSessionNone))
	require.ErrorIs(t, err, ErrNoUserLoggedIn)
	assert.Zero(t, id)
}

// TestParseActiveSessionID_ValidIDPassesThrough verifies that a non-sentinel session ID
// is returned unchanged. Pure function; no WTS API call needed.
func TestParseActiveSessionID_ValidIDPassesThrough(t *testing.T) {
	const testSessionID uint32 = 1
	id, err := parseActiveSessionID(uintptr(testSessionID))
	require.NoError(t, err)
	assert.Equal(t, testSessionID, id)
}

// TestDetectLoggedInUser_Windows_Behavior verifies that detectLoggedInUser either
// returns a non-empty username or ErrNoUserLoggedIn. Both are valid depending on
// whether an interactive console session is active.
func TestDetectLoggedInUser_Windows_Behavior(t *testing.T) {
	user, err := detectLoggedInUser()
	if err != nil {
		assert.ErrorIs(t, err, ErrNoUserLoggedIn,
			"should return ErrNoUserLoggedIn when no console session is active; got: %v", err)
		assert.Empty(t, user)
	} else {
		assert.NotEmpty(t, user, "detected user must not be empty")
	}
}

// TestGetActiveConsoleSessionID_Behavior verifies getActiveConsoleSessionID returns
// either a valid session ID or ErrNoUserLoggedIn.
func TestGetActiveConsoleSessionID_Behavior(t *testing.T) {
	sessionID, err := getActiveConsoleSessionID()
	if err != nil {
		assert.ErrorIs(t, err, ErrNoUserLoggedIn)
	} else {
		assert.NotEqual(t, activeConsoleSessionNone, sessionID,
			"returned session ID must not be the sentinel value")
	}
}

// TestApplyExecutionContext_Windows_SystemPassesThrough verifies that the system
// execution context returns the original cmd pointer unchanged.
func TestApplyExecutionContext_Windows_SystemPassesThrough(t *testing.T) {
	ctx := context.Background()
	config := &ScriptConfig{
		Content:          "echo hello",
		Shell:            ShellPowerShell,
		Timeout:          5 * time.Second,
		ExecutionContext: ExecutionContextSystem,
	}

	original := exec.CommandContext(ctx, "powershell.exe", "-Command", "echo hello")
	cmd, user, cleanup, err := applyExecutionContext(ctx, config, original)
	require.NoError(t, err)
	cleanup()

	assert.Same(t, original, cmd, "system context must return the original cmd pointer")
	assert.Empty(t, user, "system context must not set an actual user")
}

// TestApplyExecutionContext_Windows_LoggedInUser_NoUser verifies that ErrNoUserLoggedIn
// is returned when no interactive console session is present. Uses test hook injection so
// this test is environment-independent and always runs in CI.
func TestApplyExecutionContext_Windows_LoggedInUser_NoUser(t *testing.T) {
	// Inject a no-session error without calling the real WTS API.
	old := windowsGetSessionID
	windowsGetSessionID = func() (uint32, error) { return 0, ErrNoUserLoggedIn }
	defer func() { windowsGetSessionID = old }()

	ctx := context.Background()
	config := &ScriptConfig{
		Content:          "echo hello",
		Shell:            ShellPowerShell,
		Timeout:          5 * time.Second,
		ExecutionContext: ExecutionContextLoggedInUser,
	}

	original := exec.CommandContext(ctx, "powershell.exe", "-Command", "echo hello")
	_, _, cleanup, err := applyExecutionContext(ctx, config, original)
	cleanup()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoUserLoggedIn,
		"must propagate ErrNoUserLoggedIn so the caller can queue for retry")
}

// TestApplyExecutionContext_Windows_LoggedInUser_WithUser verifies that when a console
// session is active, applyExecutionContext attaches the user token to SysProcAttr and
// returns the correct username. Skipped in headless CI environments.
// When SE_TCB_NAME privilege is unavailable, falls back to validating system-context
// so the test always exercises a real code path.
func TestApplyExecutionContext_Windows_LoggedInUser_WithUser(t *testing.T) {
	user, err := detectLoggedInUser()
	if err != nil {
		t.Skip("no interactive console session; skipping token-acquisition test")
	}

	ctx := context.Background()
	config := &ScriptConfig{
		Content:          "echo hello",
		Shell:            ShellPowerShell,
		Timeout:          5 * time.Second,
		ExecutionContext: ExecutionContextLoggedInUser,
	}

	original := exec.CommandContext(ctx, "powershell.exe", "-Command", "echo hello")
	cmd, actualUser, cleanup, err := applyExecutionContext(ctx, config, original)
	if err != nil && strings.Contains(err.Error(), "WTSQueryUserToken failed") {
		// WTSQueryUserToken requires SE_TCB_NAME privilege, which is typically
		// unavailable in CI runners (e.g., GitHub Actions runneradmin).
		// Fall back to validating the system-context path instead.
		cleanup()
		t.Logf("user-token acquisition failed (%v); falling back to system-context validation", err)

		sysConfig := &ScriptConfig{
			Content:          "echo hello",
			Shell:            ShellPowerShell,
			Timeout:          5 * time.Second,
			ExecutionContext: ExecutionContextSystem,
		}
		sysOriginal := exec.CommandContext(ctx, "powershell.exe", "-Command", "echo hello")
		sysCmd, sysUser, sysCleanup, sysErr := applyExecutionContext(ctx, sysConfig, sysOriginal)
		defer sysCleanup()

		require.NoError(t, sysErr, "system-context fallback must not error")
		assert.Same(t, sysOriginal, sysCmd, "system context must return the original cmd pointer")
		assert.Empty(t, sysUser, "system context must not set an actual user")
		return
	}
	require.NoError(t, err, "unexpected error from applyExecutionContext")
	cleanup()

	assert.Equal(t, user, actualUser, "actualUser must match the detected console user")
	require.NotNil(t, cmd)

	// The same cmd pointer is returned (SysProcAttr is set in-place on Windows,
	// unlike Unix which builds a new sudo-wrapper command).
	assert.Same(t, original, cmd, "Windows applyExecutionContext modifies SysProcAttr in-place")

	// Token must be set on SysProcAttr; a non-zero token confirms the WTS path was taken.
	require.NotNil(t, cmd.SysProcAttr, "SysProcAttr must be non-nil after token attachment")
	assert.NotZero(t, cmd.SysProcAttr.Token, "Token must be set to the active console session token")
}

// TestExecute_Windows_TimeoutKillsProcessTree reproduces Issue #2715: a Windows
// `.cmd` job backgrounds a detached grandchild (via `start /b`) that inherits the
// executor's stdout/stderr pipe and outlives the configured timeout. Before the
// Job Object fix, the timeout path called cmd.Process.Kill(), which terminated
// only the top-level cmd.exe; the grandchild survived, kept the inherited pipe
// write handle open, and cmd.Wait() — and therefore Execute — blocked forever,
// wedging the steward's per-device execution slot.
//
// With the fix the whole process tree is terminated on timeout, so Execute
// returns promptly (well within the bounded reap window, never the grandchild's
// full sleep) and the grandchild process is gone. Reaching the timeout path at
// all proves the grandchild held the pipe — otherwise cmd.exe would have exited
// immediately and Execute would have returned success before the timeout.
func TestExecute_Windows_TimeoutKillsProcessTree(t *testing.T) {
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		t.Skip("powershell.exe not available; cannot spawn the grandchild for this test")
	}

	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")

	// The grandchild records its own PID, then holds the inherited stdout/stderr
	// open by sleeping far past the timeout. `start /b` runs it in the same
	// console (inheriting the redirected pipe) and backgrounds it, so cmd.exe
	// returns immediately, leaving only the grandchild holding the pipe.
	const grandchildSleep = 30 // seconds; must exceed timeout + reap window below
	script := "@echo off\r\n" +
		"start /b \"\" powershell.exe -NoProfile -NonInteractive -Command " +
		"\"Set-Content -LiteralPath '" + pidFile + "' -Value $PID; Start-Sleep -Seconds " +
		strconv.Itoa(grandchildSleep) + "\"\r\n"

	const timeout = 4 * time.Second
	cfg := &ScriptConfig{
		Content:          script,
		Shell:            ShellCmd,
		Timeout:          timeout,
		ExecutionContext: ExecutionContextSystem,
	}
	exe := NewExecutor(cfg)

	// Run Execute under a hard wall-clock guard so a regression (infinite block)
	// fails the test instead of hanging the whole suite. The guard is shorter than
	// the grandchild's sleep, so a hang is caught before the grandchild would
	// self-exit and mask the bug.
	type outcome struct {
		res *ExecutionResult
		err error
	}
	ch := make(chan outcome, 1)
	start := time.Now()
	go func() {
		res, err := exe.Execute(context.Background())
		ch <- outcome{res: res, err: err}
	}()

	var got outcome
	select {
	case got = <-ch:
	case <-time.After(timeout + reapGracePeriod + 10*time.Second):
		t.Fatalf("Execute did not return within the bounded reap window — process-tree kill regressed (Issue #2715)")
	}
	elapsed := time.Since(start)

	// Best-effort cleanup in case a regression left the grandchild running.
	pid := readPIDFile(t, pidFile)
	if pid != 0 {
		t.Cleanup(func() { _ = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(pid)).Run() })
	}

	// Must have hit the timeout path (confirms the grandchild held the pipe).
	require.Error(t, got.err, "expected a timeout error from Execute")
	assert.Contains(t, got.err.Error(), "timed out", "error must report the timeout")
	require.NotNil(t, got.res)
	assert.Equal(t, -1, got.res.ExitCode, "timed-out execution must report exit code -1")

	// Returned promptly after the timeout, not after the grandchild's long sleep.
	assert.Less(t, elapsed, timeout+reapGracePeriod,
		"Execute must return shortly after the timeout once the process tree is killed")

	// AC3: the grandchild must be terminated along with the tree.
	require.NotZero(t, pid, "grandchild must have recorded its PID before the timeout")
	assert.Eventually(t, func() bool { return !isProcessAlive(pid) },
		5*time.Second, 100*time.Millisecond,
		"grandchild process (pid %d) must be terminated with the tree", pid)
}

// TestExecute_Windows_SuccessLeavesDetachedGrandchildRunning guards against the
// process-tree kill over-reaching: a script that completes successfully after
// deliberately backgrounding a detached descendant (one that does not inherit the
// stdout/stderr pipe, so cmd.Wait returns normally) must NOT have that descendant
// collaterally killed when Execute returns. This is why the Job Object is created
// without JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE — termination happens only on the
// timeout path, never on the success path.
func TestExecute_Windows_SuccessLeavesDetachedGrandchildRunning(t *testing.T) {
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		t.Skip("powershell.exe not available; cannot spawn the detached grandchild for this test")
	}

	pidFile := filepath.Join(t.TempDir(), "detached.pid")

	// Start-Process launches a new process that does NOT inherit the parent's
	// stdio handles, so it holds no pipe and cmd.exe/powershell exit immediately
	// (Execute takes the success path). The grandchild sleeps well past the run so
	// we can observe whether Execute's cleanup left it alive.
	const grandchildSleep = 30 // seconds; must outlast the whole Execute call
	script := "@echo off\r\n" +
		"powershell.exe -NoProfile -NonInteractive -Command " +
		"\"$p = Start-Process powershell.exe -ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds " +
		strconv.Itoa(grandchildSleep) + "' -WindowStyle Hidden -PassThru; " +
		"Set-Content -LiteralPath '" + pidFile + "' -Value $p.Id\"\r\n"

	cfg := &ScriptConfig{
		Content:          script,
		Shell:            ShellCmd,
		Timeout:          20 * time.Second, // generous; the script itself completes in ~1-2s
		ExecutionContext: ExecutionContextSystem,
	}
	exe := NewExecutor(cfg)

	res, err := exe.Execute(context.Background())
	require.NoError(t, err, "script must complete successfully, not time out")
	require.NotNil(t, res)
	assert.Equal(t, 0, res.ExitCode, "successful script must report exit code 0")

	pid := readPIDFile(t, pidFile)
	require.NotZero(t, pid, "detached grandchild must have recorded its PID")
	t.Cleanup(func() { _ = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(pid)).Run() })

	assert.True(t, isProcessAlive(pid),
		"a deliberately-detached grandchild (pid %d) must survive a successful Execute — "+
			"the job must not kill it on the success path", pid)
}

// readPIDFile polls briefly for the grandchild's PID file and returns the parsed
// PID, or 0 if it was never written or is unparseable.
func readPIDFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if data, err := readFileTrim(path); err == nil && data != "" {
			if pid, perr := strconv.Atoi(data); perr == nil {
				return pid
			}
		}
		if time.Now().After(deadline) {
			return 0
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// readFileTrim reads a file and returns its whitespace-trimmed contents.
func readFileTrim(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// isProcessAlive reports whether a process with the given PID is currently
// running, via tasklist (a stable, always-present Windows utility). tasklist
// emits the PID quoted in its CSV output only when the process exists.
func isProcessAlive(pid int) bool {
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH", "/FO", "CSV").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), fmt.Sprintf("\"%d\"", pid))
}

// TestResolveExecutionUID_Windows verifies that ResolveExecutionUID returns -1
// on Windows for every execution context: process identity is SID-based and the
// relay named pipe uses an explicit DACL, so no POSIX-UID chown applies.
func TestResolveExecutionUID_Windows(t *testing.T) {
	for _, ec := range []ExecutionContext{ExecutionContextSystem, ExecutionContextLoggedInUser} {
		uid, err := ResolveExecutionUID(ec)
		require.NoError(t, err)
		assert.Equal(t, -1, uid, "Windows ResolveExecutionUID must return -1 (no UID chown)")
	}
}

// TestCmdScriptPathWithSpaces verifies that buildCmdExeCommand sets SysProcAttr.CmdLine
// to a correctly quoted cmd.exe /c <path> invocation when the temp directory path
// contains a space. This covers the logged_in_user execution context where %TEMP%
// resolves to a user-profile directory such as C:\Users\John Smith\AppData\Local\Temp\.
// Without the CmdLine override, cmd.exe /c strips the outer quotes and cannot locate
// the batch file.
func TestCmdScriptPathWithSpaces(t *testing.T) {
	// Synthetic path with a space in the directory component — mirrors a real
	// user-profile %TEMP% path. No file is created: we verify CmdLine construction only.
	spacedPath := `C:\Users\John Smith\AppData\Local\Temp\cfgms-script-abc123.cmd`

	cmd := buildCmdExeCommand(context.Background(), spacedPath)

	require.NotNil(t, cmd)
	require.NotNil(t, cmd.SysProcAttr, "SysProcAttr must be set to override cmd.exe arg parsing")

	// EscapeArg wraps a path containing spaces in double-quotes, so the CmdLine must
	// be: cmd.exe /c "C:\Users\John Smith\AppData\Local\Temp\cfgms-script-abc123.cmd"
	expectedCmdLine := `cmd.exe /c "C:\Users\John Smith\AppData\Local\Temp\cfgms-script-abc123.cmd"`
	assert.Equal(t, expectedCmdLine, cmd.SysProcAttr.CmdLine,
		"CmdLine must double-quote the path to handle spaces in the %%TEMP%% directory")
}

// TestCmdScriptPathWithoutSpaces verifies that buildCmdExeCommand also works correctly
// for paths without spaces (the SYSTEM-context case where %TEMP% is C:\Windows\Temp\).
func TestCmdScriptPathWithoutSpaces(t *testing.T) {
	noSpacePath := `C:\Windows\Temp\cfgms-script-abc123.cmd`

	cmd := buildCmdExeCommand(context.Background(), noSpacePath)

	require.NotNil(t, cmd)
	require.NotNil(t, cmd.SysProcAttr)

	// EscapeArg does not add quotes when the path contains no spaces.
	expectedCmdLine := `cmd.exe /c C:\Windows\Temp\cfgms-script-abc123.cmd`
	assert.Equal(t, expectedCmdLine, cmd.SysProcAttr.CmdLine)
}

// TestBuildCmdExeCommand_ContentNotInline verifies that the CmdLine for buildCmdExeCommand
// contains a file path, never inline script content — the file-path-only constraint
// that distinguishes it from the banned pattern cmd.exe /c <inline-content>.
func TestBuildCmdExeCommand_ContentNotInline(t *testing.T) {
	tmpPath := `C:\Windows\Temp\cfgms-script-abc123.cmd`
	inlineContent := "@echo hello from cfgms"

	cmd := buildCmdExeCommand(context.Background(), tmpPath)

	require.NotNil(t, cmd.SysProcAttr)
	assert.NotContains(t, cmd.SysProcAttr.CmdLine, inlineContent,
		"CmdLine must not contain inline script content")
	assert.Contains(t, cmd.SysProcAttr.CmdLine, "cfgms-script-",
		"CmdLine must reference the temp script file path")
}
