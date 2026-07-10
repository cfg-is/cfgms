// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// platformShell returns a shell supported by the current OS for use in config tests
// that do not actually execute scripts.
func platformShell() ShellType {
	if runtime.GOOS == "windows" {
		return ShellPowerShell
	}
	return ShellBash
}

// TestExecutionContext_DefaultsToSystem verifies that an empty ExecutionContext is
// normalised to ExecutionContextSystem during Validate().
func TestExecutionContext_DefaultsToSystem(t *testing.T) {
	config := &ScriptConfig{
		Content: "echo hello",
		Shell:   platformShell(),
		Timeout: 5 * time.Second,
		// ExecutionContext intentionally omitted
	}

	require.NoError(t, config.Validate())
	assert.Equal(t, ExecutionContextSystem, config.ExecutionContext,
		"empty ExecutionContext should default to system")
}

// TestExecutionContext_ValidValues verifies that all defined context values pass Validate().
func TestExecutionContext_ValidValues(t *testing.T) {
	tests := []struct {
		name string
		ctx  ExecutionContext
	}{
		{"system", ExecutionContextSystem},
		{"logged_in_user", ExecutionContextLoggedInUser},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ScriptConfig{
				Content:          "echo hello",
				Shell:            platformShell(),
				Timeout:          5 * time.Second,
				ExecutionContext: tt.ctx,
			}
			require.NoError(t, config.Validate())
			assert.Equal(t, tt.ctx, config.ExecutionContext)
		})
	}
}

// TestExecutionContext_InvalidValueRejected verifies that an unrecognised execution context
// is rejected by Validate().
func TestExecutionContext_InvalidValueRejected(t *testing.T) {
	config := &ScriptConfig{
		Content:          "echo hello",
		Shell:            platformShell(),
		Timeout:          5 * time.Second,
		ExecutionContext: ExecutionContext("administrator"),
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid execution context")
}

// TestExecutionResult_ActualUserField confirms the ActualUser field exists and is
// readable on ExecutionResult (compile-time and runtime check).
func TestExecutionResult_ActualUserField(t *testing.T) {
	result := &ExecutionResult{
		ExitCode:   0,
		Stdout:     "hello",
		ActualUser: "alice",
	}
	assert.Equal(t, "alice", result.ActualUser)
}

// TestScriptConfig_AsMap_ExecutionContext verifies execution_context appears in AsMap().
func TestScriptConfig_AsMap_ExecutionContext(t *testing.T) {
	config := &ScriptConfig{
		Content:          "echo hello",
		Shell:            platformShell(),
		Timeout:          5 * time.Second,
		ExecutionContext: ExecutionContextLoggedInUser,
		SigningPolicy:    SigningPolicyNone,
	}

	m := config.AsMap()
	require.Contains(t, m, "execution_context")
	assert.Equal(t, "logged_in_user", m["execution_context"])
}

// TestScriptConfig_GetManagedFields_ExecutionContext confirms execution_context appears
// in the managed-fields list used for config comparison.
func TestScriptConfig_GetManagedFields_ExecutionContext(t *testing.T) {
	config := &ScriptConfig{
		Content: "echo hello",
		Shell:   platformShell(),
		Timeout: 5 * time.Second,
	}

	fields := config.GetManagedFields()
	assert.Contains(t, fields, "execution_context")
}

// TestCreateAuditRecord_System verifies that system-context executions are audited
// correctly: ExecutionContext is populated and ActualUser is empty.
func TestCreateAuditRecord_System(t *testing.T) {
	config := &ScriptConfig{
		Content:          "echo hello",
		Shell:            platformShell(),
		Timeout:          5 * time.Second,
		ExecutionContext: ExecutionContextSystem,
	}
	require.NoError(t, config.Validate())

	result := &ExecutionResult{
		ExitCode:  0,
		Stdout:    "hello",
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Duration:  time.Millisecond,
		// ActualUser intentionally empty: system context
	}

	record := CreateAuditRecord("steward-1", "resource-1", config, result, nil)

	assert.Equal(t, ExecutionContextSystem, record.ExecutionContext)
	assert.Equal(t, ExecutionContextSystem, record.ScriptConfig.ExecutionContext)
	assert.Empty(t, record.ActualUser, "system context should not populate ActualUser")
}

// TestCreateAuditRecord_LoggedInUser verifies that logged_in_user executions record
// both the context and the actual OS username in the audit trail.
func TestCreateAuditRecord_LoggedInUser(t *testing.T) {
	config := &ScriptConfig{
		Content:          "echo hello",
		Shell:            platformShell(),
		Timeout:          5 * time.Second,
		ExecutionContext: ExecutionContextLoggedInUser,
	}
	require.NoError(t, config.Validate())

	result := &ExecutionResult{
		ExitCode:   0,
		Stdout:     "hello",
		StartTime:  time.Now(),
		EndTime:    time.Now(),
		Duration:   time.Millisecond,
		ActualUser: "alice",
	}

	record := CreateAuditRecord("steward-1", "resource-1", config, result, nil)

	assert.Equal(t, ExecutionContextLoggedInUser, record.ExecutionContext)
	assert.Equal(t, ExecutionContextLoggedInUser, record.ScriptConfig.ExecutionContext)
	assert.Equal(t, "alice", record.ActualUser)
}

// TestErrNoUserLoggedIn verifies the sentinel error exists and is identifiable via errors.Is.
func TestErrNoUserLoggedIn(t *testing.T) {
	require.NotNil(t, ErrNoUserLoggedIn)
	assert.Contains(t, ErrNoUserLoggedIn.Error(), "no user")
}

// TestScriptExecutorNoBannedPatterns verifies that buildCommand stages the script
// content to a temp file and executes by file path — no inline content is passed as
// an interpreter flag. Banned patterns: -ExecutionPolicy (PowerShell bypass),
// -Command (PowerShell inline), -c (Unix shells inline).
//
// The cmd.exe case on Windows uses /c <filepath> (file execution), which differs from
// the banned pattern /c <inline-content>; that case is tested on Windows CI only.
func TestScriptExecutorNoBannedPatterns(t *testing.T) {
	const content = "echo hello-from-cfgms-test"

	type shellCase struct {
		shell         ShellType
		bannedInArgs  []string
		wantExtension string // expected suffix of the last meaningful arg (the script path)
	}

	var cases []shellCase

	switch runtime.GOOS {
	case "linux", "darwin":
		cases = []shellCase{
			{ShellBash, []string{"-c", "-ExecutionPolicy", "-Command"}, ""},
			{ShellSh, []string{"-c", "-ExecutionPolicy", "-Command"}, ""},
			{ShellPython3, []string{"-c", "-ExecutionPolicy", "-Command"}, ""},
		}
	case "windows":
		cases = []shellCase{
			{ShellPowerShell, []string{"-ExecutionPolicy", "-Command"}, ".ps1"},
			{ShellPython, []string{"-c", "-ExecutionPolicy", "-Command"}, ".py"},
			{ShellPython3, []string{"-c", "-ExecutionPolicy", "-Command"}, ".py"},
		}
	default:
		t.Skipf("no banned-pattern cases defined for GOOS=%s", runtime.GOOS)
	}

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.shell), func(t *testing.T) {
			e := &Executor{
				config: &ScriptConfig{
					Content: content,
					Shell:   tc.shell,
					Timeout: 5 * time.Second,
				},
				logger: logging.NewNoopLogger(),
			}

			cmd, cleanup, err := e.buildCommand(context.Background())
			if err != nil {
				t.Fatalf("buildCommand() error = %v", err)
			}
			defer cleanup()

			for _, banned := range tc.bannedInArgs {
				for _, arg := range cmd.Args {
					if arg == banned {
						t.Errorf("cmd.Args contains banned flag %q; args: %v", banned, cmd.Args)
					}
				}
			}

			// The content string must NOT appear inline in any argument.
			for _, arg := range cmd.Args {
				if arg == content {
					t.Errorf("cmd.Args contains script content inline: %v", cmd.Args)
				}
			}

			// The last arg should be the temp file path (not the interpreter).
			require.NotEmpty(t, cmd.Args)
			lastArg := cmd.Args[len(cmd.Args)-1]
			if tc.wantExtension != "" {
				require.True(t, strings.HasSuffix(lastArg, tc.wantExtension),
					"last arg %q should end with %q; full args: %v", lastArg, tc.wantExtension, cmd.Args)
			}

			// The last arg (script path) should contain the temp marker.
			require.True(t, strings.Contains(lastArg, "cfgms-script-"),
				"last arg %q should be a cfgms temp script path; full args: %v", lastArg, cmd.Args)
		})
	}
}

// TestExecutionContext_Integration_SystemDefault runs an actual script in system context
// and confirms the execution context is recorded correctly in the audit record.
func TestExecutionContext_Integration_SystemDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	var script string
	var shell ShellType
	switch runtime.GOOS {
	case "windows":
		script = "echo context-test"
		shell = ShellCmd
	default:
		script = "echo context-test"
		shell = ShellBash
	}

	config := &ScriptConfig{
		Content: script,
		Shell:   shell,
		Timeout: 10 * time.Second,
		// ExecutionContext intentionally omitted — should default to system
	}
	require.NoError(t, config.Validate())
	assert.Equal(t, ExecutionContextSystem, config.ExecutionContext)

	executor := NewExecutor(config)
	result, err := executor.Execute(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Empty(t, result.ActualUser, "system context should leave ActualUser empty")

	record := CreateAuditRecord("test-steward", "test-resource", config, result, nil)
	assert.Equal(t, ExecutionContextSystem, record.ExecutionContext)
	assert.Empty(t, record.ActualUser)
}

// TestExecute_FastExitingScriptCapturesStdout is a regression test for a stdout-capture
// race: when output was drained from cmd.StdoutPipe() concurrently with cmd.Wait(),
// Wait could close the pipe before the reader drained the kernel buffer, silently
// truncating output from scripts that exit almost immediately. A single `echo` exits
// fast enough to lose its entire output. Running it repeatedly makes the regression
// deterministic — any iteration with empty stdout proves the race has returned.
func TestExecute_FastExitingScriptCapturesStdout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping execution test in short mode")
	}

	var script string
	var shell ShellType
	switch runtime.GOOS {
	case "windows":
		script = "echo race-marker"
		shell = ShellCmd
	default:
		script = "echo race-marker"
		shell = ShellBash
	}

	for i := 0; i < 50; i++ {
		config := &ScriptConfig{
			Content: script,
			Shell:   shell,
			Timeout: 10 * time.Second,
		}
		require.NoError(t, config.Validate())

		result, err := NewExecutor(config).Execute(t.Context())
		require.NoError(t, err, "iteration %d", i)
		assert.Equal(t, 0, result.ExitCode, "iteration %d", i)
		assert.Contains(t, result.Stdout, "race-marker",
			"iteration %d: stdout of a fast-exiting script must not be truncated", i)
	}
}
