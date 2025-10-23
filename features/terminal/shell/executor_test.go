// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package shell

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFactory(t *testing.T) {
	factory := NewFactory()
	require.NotNil(t, factory)

	tests := []struct {
		name     string
		config   *Config
		wantErr  bool
		skipOnOS string
	}{
		{
			name: "bash config (platform dependent)",
			config: &Config{
				Shell: "bash",
				Cols:  80,
				Rows:  24,
			},
			wantErr: runtime.GOOS == "windows", // bash doesn't work on Windows
		},
		{
			name: "powershell config (platform dependent)",
			config: &Config{
				Shell: "powershell",
				Cols:  80,
				Rows:  24,
			},
			wantErr: runtime.GOOS != "windows", // PowerShell only works on Windows
		},
		{
			name: "invalid shell",
			config: &Config{
				Shell: "invalid-shell",
				Cols:  80,
				Rows:  24,
			},
			wantErr: true,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnOS != "" && runtime.GOOS == tt.skipOnOS {
				t.Skipf("Skipping test on %s", runtime.GOOS)
				return
			}

			executor, err := factory.CreateExecutor(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, executor)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, executor)
			}
		})
	}
}

func TestGetDefaultShell(t *testing.T) {
	defaultShell := GetDefaultShell()
	assert.NotEmpty(t, defaultShell)

	switch runtime.GOOS {
	case "windows":
		assert.Equal(t, "powershell", defaultShell)
	default:
		assert.Equal(t, "bash", defaultShell)
	}
}

func TestGetSupportedShells(t *testing.T) {
	shells := GetSupportedShells()
	assert.NotEmpty(t, shells)

	switch runtime.GOOS {
	case "windows":
		assert.Contains(t, shells, "powershell")
		assert.Contains(t, shells, "cmd")
	default:
		assert.Contains(t, shells, "bash")
		assert.Contains(t, shells, "sh")
	}
}

func TestShellExecutorLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping shell executor test in short mode")
	}

	factory := NewFactory()

	// Use default shell for the platform
	config := &Config{
		Shell: GetDefaultShell(),
		Cols:  80,
		Rows:  24,
		Environment: map[string]string{
			"TEST_VAR": "test_value",
		},
	}

	executor, err := factory.CreateExecutor(config)
	require.NoError(t, err)
	require.NotNil(t, executor)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Initially not running
	assert.False(t, executor.IsRunning())

	// Start the executor
	err = executor.Start(ctx, nil)
	require.NoError(t, err)

	// Should be running now
	assert.True(t, executor.IsRunning())

	// Test writing data
	testCommand := getTestCommand()
	err = executor.WriteData(ctx, []byte(testCommand))
	assert.NoError(t, err)

	// Read some output
	select {
	case output := <-executor.OutputChannel():
		assert.NotEmpty(t, output)
		t.Logf("Received output: %s", string(output))
	case err := <-executor.ErrorChannel():
		t.Logf("Received error: %v", err)
	case <-time.After(2 * time.Second):
		t.Log("No output received within timeout")
	}

	// Test resize
	err = executor.Resize(ctx, 120, 30)
	assert.NoError(t, err)

	// Close the executor
	err = executor.Close(ctx)
	assert.NoError(t, err)

	// Should not be running after close
	assert.False(t, executor.IsRunning())
}

func TestShellExecutorMultipleCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping shell executor test in short mode")
	}

	factory := NewFactory()

	config := &Config{
		Shell: GetDefaultShell(),
		Cols:  80,
		Rows:  24,
	}

	executor, err := factory.CreateExecutor(config)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err = executor.Start(ctx, nil)
	require.NoError(t, err)
	defer func() {
		if err := executor.Close(ctx); err != nil {
			t.Logf("Failed to close executor: %v", err)
		}
	}()

	commands := getTestCommands()

	for i, cmd := range commands {
		t.Logf("Executing command %d: %s", i+1, cmd)

		err = executor.WriteData(ctx, []byte(cmd))
		assert.NoError(t, err)

		// Give time for command to execute and produce output
		time.Sleep(500 * time.Millisecond)

		// Try to read output (non-blocking)
		select {
		case output := <-executor.OutputChannel():
			t.Logf("Command %d output: %s", i+1, string(output))
		case err := <-executor.ErrorChannel():
			t.Logf("Command %d error: %v", i+1, err)
		default:
			t.Logf("Command %d: No immediate output", i+1)
		}
	}
}

// getTestCommand returns a simple test command for the current platform
func getTestCommand() string {
	switch runtime.GOOS {
	case "windows":
		return "echo Hello World\r\n"
	default:
		return "echo 'Hello World'\n"
	}
}

// getTestCommands returns a series of test commands for the current platform
func getTestCommands() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			"echo Test 1\r\n",
			"dir /b\r\n",
			"echo Test 2\r\n",
		}
	default:
		return []string{
			"echo 'Test 1'\n",
			"ls -la\n",
			"echo 'Test 2'\n",
		}
	}
}

func TestShellExecutorError(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping shell executor test in short mode")
	}

	factory := NewFactory()

	config := &Config{
		Shell: GetDefaultShell(),
		Cols:  80,
		Rows:  24,
	}

	executor, err := factory.CreateExecutor(config)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try to write data before starting
	err = executor.WriteData(ctx, []byte("test"))
	assert.Error(t, err)

	// Try to resize before starting
	err = executor.Resize(ctx, 120, 30)
	assert.Error(t, err)

	// Start executor
	err = executor.Start(ctx, nil)
	require.NoError(t, err)
	defer func() {
		if err := executor.Close(ctx); err != nil {
			t.Logf("Failed to close executor: %v", err)
		}
	}()

	// Try to start again (should fail)
	err = executor.Start(ctx, nil)
	assert.Error(t, err)
}
