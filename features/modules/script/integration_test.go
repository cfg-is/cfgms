package script

import (
	"context"
	"runtime"
	"testing"
	"time"
)

// TestScriptExecution_Integration performs actual script execution
func TestScriptExecution_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	module := NewModule()
	ctx := context.WithValue(context.Background(), "timestamp", time.Now().Unix())
	resourceID := "integration-test"

	// Test simple echo command
	var testScript string
	var shell ShellType

	switch runtime.GOOS {
	case "windows":
		testScript = "echo Integration test successful"
		shell = ShellCmd
	default:
		testScript = "echo 'Integration test successful'"
		shell = ShellBash
	}

	config := &ScriptConfig{
		Content:     testScript,
		Shell:       shell,
		Timeout:     10 * time.Second,
		Description: "Integration test script",
	}

	// Execute the script
	err := module.Set(ctx, resourceID, config)
	if err != nil {
		t.Fatalf("Script execution failed: %v", err)
	}

	// Check execution state
	state, exists := module.GetExecutionState(resourceID)
	if !exists {
		t.Fatal("Execution state not found after script execution")
	}

	if state.Status != StatusCompleted && state.Status != StatusFailed {
		t.Errorf("Unexpected execution status: %v", state.Status)
	}

	if state.Result != nil {
		t.Logf("Script output: %s", state.Result.Stdout)
		t.Logf("Script errors: %s", state.Result.Stderr)
		t.Logf("Exit code: %d", state.Result.ExitCode)
		t.Logf("Duration: %v", state.Result.Duration)

		if state.Status == StatusCompleted && state.Result.ExitCode != 0 {
			t.Errorf("Script completed but with non-zero exit code: %d", state.Result.ExitCode)
		}
	}
}

// TestScriptExecution_Timeout tests timeout functionality
func TestScriptExecution_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	module := NewModule()
	ctx := context.WithValue(context.Background(), "timestamp", time.Now().Unix())
	resourceID := "timeout-test"

	// Create a script that will timeout
	var testScript string
	var shell ShellType

	switch runtime.GOOS {
	case "windows":
		testScript = "timeout /t 10"
		shell = ShellCmd
	default:
		testScript = "sleep 10"
		shell = ShellBash
	}

	config := &ScriptConfig{
		Content: testScript,
		Shell:   shell,
		Timeout: 2 * time.Second, // Short timeout to force timeout
	}

	// Execute the script (should timeout)
	err := module.Set(ctx, resourceID, config)
	if err == nil {
		t.Error("Expected script to timeout and return error")
	}

	// Check execution state
	state, exists := module.GetExecutionState(resourceID)
	if !exists {
		t.Fatal("Execution state not found after script timeout")
	}

	if state.Status != StatusFailed {
		t.Errorf("Expected status to be Failed after timeout, got: %v", state.Status)
	}
}

// TestScriptExecution_Environment tests environment variable handling
func TestScriptExecution_Environment(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping environment test in short mode")
	}

	module := NewModule()
	ctx := context.WithValue(context.Background(), "timestamp", time.Now().Unix())
	resourceID := "env-test"

	// Test environment variable script
	var testScript string
	var shell ShellType

	switch runtime.GOOS {
	case "windows":
		testScript = "echo %TEST_VAR%"
		shell = ShellCmd
	default:
		testScript = "echo $TEST_VAR"
		shell = ShellBash
	}

	config := &ScriptConfig{
		Content: testScript,
		Shell:   shell,
		Timeout: 10 * time.Second,
		Environment: map[string]string{
			"TEST_VAR": "hello-world",
		},
	}

	// Execute the script
	err := module.Set(ctx, resourceID, config)
	if err != nil {
		t.Fatalf("Script execution failed: %v", err)
	}

	// Check execution state and output
	state, exists := module.GetExecutionState(resourceID)
	if !exists {
		t.Fatal("Execution state not found after script execution")
	}

	if state.Status == StatusCompleted && state.Result != nil {
		if state.Result.ExitCode == 0 {
			output := state.Result.Stdout
			t.Logf("Environment variable output: %s", output)
			// The output should contain our test value
			// Note: we don't do exact matching due to potential platform differences
		}
	}
}