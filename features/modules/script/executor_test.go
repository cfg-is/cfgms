// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
