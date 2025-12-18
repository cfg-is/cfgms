// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package shell

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// WindowsExecutor implements shell execution for Windows systems
type WindowsExecutor struct {
	mu       sync.RWMutex
	config   *Config
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	stdout   io.ReadCloser
	stderr   io.ReadCloser
	outputCh chan []byte
	errorCh  chan error
	running  bool
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewWindowsExecutor creates a new Windows shell executor
func NewWindowsExecutor(config *Config) (*WindowsExecutor, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	executor := &WindowsExecutor{
		config:   config,
		outputCh: make(chan []byte, 100),
		errorCh:  make(chan error, 10),
		running:  false,
	}

	return executor, nil
}

// Start starts the shell process
func (e *WindowsExecutor) Start(ctx context.Context, config *Config) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return fmt.Errorf("shell is already running")
	}

	if config != nil {
		e.config = config
	}

	// Create context for the shell process
	e.ctx, e.cancel = context.WithCancel(ctx)

	// Determine shell command and arguments
	var cmdPath string
	var args []string

	switch e.config.Shell {
	case "powershell":
		cmdPath = "powershell.exe"
		args = []string{
			"-NoExit",       // Don't exit after running commands
			"-NoLogo",       // Don't show PowerShell logo
			"-OutputFormat", // Set output format
			"Text",
			"-InputFormat", // Set input format
			"Text",
		}
	case "cmd":
		cmdPath = "cmd.exe"
		args = []string{"/Q"} // Quiet mode
	default:
		return fmt.Errorf("unsupported Windows shell: %s", e.config.Shell)
	}

	// Create command
	// #nosec G204 - Terminal requires shell execution with validated shell paths
	e.cmd = exec.CommandContext(e.ctx, cmdPath, args...)

	// Set environment variables
	e.cmd.Env = os.Environ()
	for key, value := range e.config.Environment {
		e.cmd.Env = append(e.cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Set working directory
	if e.config.WorkingDir != "" {
		e.cmd.Dir = e.config.WorkingDir
	}

	// Configure process attributes for Windows
	e.cmd.SysProcAttr = &syscall.SysProcAttr{
		// Hide the console window (Windows only)
	}

	// Set up pipes for stdin, stdout, and stderr
	var err error
	e.stdin, err = e.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	e.stdout, err = e.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	e.stderr, err = e.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	if err := e.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	e.running = true

	// Start output readers
	go e.readOutput(e.stdout, false) // stdout
	go e.readOutput(e.stderr, true)  // stderr

	// Start process monitor
	go e.monitorProcess()

	return nil
}

// WriteData sends input data to the shell
func (e *WindowsExecutor) WriteData(ctx context.Context, data []byte) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.running || e.stdin == nil {
		return fmt.Errorf("shell is not running")
	}

	_, err := e.stdin.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write to shell: %w", err)
	}

	return nil
}

// Resize resizes the terminal (limited support on Windows)
func (e *WindowsExecutor) Resize(ctx context.Context, cols, rows int) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return fmt.Errorf("shell is not running")
	}

	e.config.Cols = cols
	e.config.Rows = rows

	// Windows console resizing is more complex and requires Windows API calls
	// For now, we'll just update the config values
	// Full implementation would require syscalls to SetConsoleScreenBufferSize

	return nil
}

// Close terminates the shell process
func (e *WindowsExecutor) Close(ctx context.Context) error {
	// First, check if already closed and mark as closing
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return nil // Already closed
	}
	e.running = false

	// Cancel internal context to signal goroutines to exit
	if e.cancel != nil {
		e.cancel()
	}

	// Store references to resources we need to clean up
	stdin := e.stdin
	stdout := e.stdout
	stderr := e.stderr
	cmd := e.cmd
	e.mu.Unlock()

	// Close stdin pipe first to signal the process to exit
	if stdin != nil {
		_ = stdin.Close()
	}

	// Force kill the process immediately on Windows
	// PowerShell doesn't exit cleanly when stdin is closed
	if cmd != nil && cmd.Process != nil {
		if err := cmd.Process.Kill(); err != nil {
			// Log but continue - process might already be dead
			_ = err // Explicitly ignore kill errors for cleanup
		}
	}

	// Close remaining pipes
	if stdout != nil {
		_ = stdout.Close()
	}
	if stderr != nil {
		_ = stderr.Close()
	}

	// Give goroutines a moment to see the context cancellation
	// before closing channels
	time.Sleep(10 * time.Millisecond)

	// Close channels - safe now that goroutines should have exited
	close(e.outputCh)
	close(e.errorCh)

	return nil
}

// OutputChannel returns a channel for receiving output data
func (e *WindowsExecutor) OutputChannel() <-chan []byte {
	return e.outputCh
}

// ErrorChannel returns a channel for receiving error notifications
func (e *WindowsExecutor) ErrorChannel() <-chan error {
	return e.errorCh
}

// IsRunning returns true if the shell process is running
func (e *WindowsExecutor) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

// readOutput reads output from stdout or stderr and sends it to the output channel
func (e *WindowsExecutor) readOutput(reader io.ReadCloser, isStderr bool) {
	defer func() {
		if isStderr {
			return // Don't mark as not running for stderr reader
		}
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
	}()

	buffer := make([]byte, 4096)
	for {
		select {
		case <-e.ctx.Done():
			return
		default:
			n, err := reader.Read(buffer)
			if err != nil {
				if err != io.EOF {
					select {
					case e.errorCh <- fmt.Errorf("shell read error: %w", err):
					case <-e.ctx.Done():
						// Context cancelled, don't send
					default:
						// Channel full, drop error
					}
				}
				return
			}

			if n > 0 {
				// Make a copy of the data
				data := make([]byte, n)
				copy(data, buffer[:n])

				select {
				case e.outputCh <- data:
				case <-e.ctx.Done():
					return
				default:
					// Drop data if channel is full
				}
			}
		}
	}
}

// monitorProcess monitors the shell process and handles its exit
func (e *WindowsExecutor) monitorProcess() {
	if e.cmd == nil {
		return
	}

	err := e.cmd.Wait()

	e.mu.Lock()
	e.running = false
	e.mu.Unlock()

	// Check if context is done before sending to channels
	// This prevents panic when Close() has already closed the channels
	select {
	case <-e.ctx.Done():
		return
	default:
	}

	if err != nil {
		select {
		case e.errorCh <- fmt.Errorf("shell process exited: %w", err):
		case <-e.ctx.Done():
			// Context cancelled, don't send
		default:
			// Channel full, drop error
		}
	}
}
