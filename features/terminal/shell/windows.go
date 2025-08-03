package shell

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

// WindowsExecutor implements shell execution for Windows systems
type WindowsExecutor struct {
	mu         sync.RWMutex
	config     *Config
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdout     io.ReadCloser
	stderr     io.ReadCloser
	outputCh   chan []byte
	errorCh    chan error
	running    bool
	ctx        context.Context
	cancel     context.CancelFunc
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
			"-NoExit",           // Don't exit after running commands
			"-NoLogo",           // Don't show PowerShell logo
			"-OutputFormat",     // Set output format
			"Text",
			"-InputFormat",      // Set input format
			"Text",
		}
	case "cmd":
		cmdPath = "cmd.exe"
		args = []string{"/Q"} // Quiet mode
	default:
		return fmt.Errorf("unsupported Windows shell: %s", e.config.Shell)
	}

	// Create command
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
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return nil // Already closed
	}

	e.running = false

	// Cancel context
	if e.cancel != nil {
		e.cancel()
	}

	// Close pipes - ignore errors as they may already be closed
	if e.stdin != nil {
		_ = e.stdin.Close()
	}
	if e.stdout != nil {
		_ = e.stdout.Close()
	}
	if e.stderr != nil {
		_ = e.stderr.Close()
	}

	// Terminate process gracefully
	if e.cmd != nil && e.cmd.Process != nil {
		// Try graceful termination first
		done := make(chan error, 1)
		go func() {
			done <- e.cmd.Wait()
		}()

		select {
		case <-ctx.Done():
			// Force kill if context expires
			if err := e.cmd.Process.Kill(); err != nil {
				// Log but continue - process might already be dead
			}
		case <-done:
			// Process exited gracefully
		}
	}

	// Close channels
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
					default:
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

	if err != nil {
		select {
		case e.errorCh <- fmt.Errorf("shell process exited: %w", err):
		default:
		}
	}
}