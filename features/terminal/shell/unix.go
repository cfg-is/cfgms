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

	"github.com/creack/pty"
)

// UnixExecutor implements shell execution for Unix-like systems
type UnixExecutor struct {
	mu         sync.RWMutex
	config     *Config
	cmd        *exec.Cmd
	pty        *os.File
	outputCh   chan []byte
	errorCh    chan error
	running    bool
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup // To wait for goroutines to finish
}

// NewUnixExecutor creates a new Unix shell executor
func NewUnixExecutor(config *Config) (*UnixExecutor, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	executor := &UnixExecutor{
		config:   config,
		outputCh: make(chan []byte, 100),
		errorCh:  make(chan error, 10),
		running:  false,
	}

	return executor, nil
}

// Start starts the shell process
func (e *UnixExecutor) Start(ctx context.Context, config *Config) error {
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

	// Determine shell command
	shellPath, err := e.getShellPath()
	if err != nil {
		return fmt.Errorf("failed to find shell: %w", err)
	}

	// Create command
	e.cmd = exec.CommandContext(e.ctx, shellPath)
	
	// Set environment variables
	e.cmd.Env = os.Environ()
	for key, value := range e.config.Environment {
		e.cmd.Env = append(e.cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Set working directory
	if e.config.WorkingDir != "" {
		e.cmd.Dir = e.config.WorkingDir
	}

	// Start the command with a PTY
	ptyFile, err := pty.StartWithSize(e.cmd, &pty.Winsize{
		Rows: uint16(e.config.Rows),
		Cols: uint16(e.config.Cols),
	})
	if err != nil {
		return fmt.Errorf("failed to start shell with PTY: %w", err)
	}

	e.pty = ptyFile
	e.running = true

	// Start output reader
	e.wg.Add(1)
	go e.readOutput()

	// Start process monitor
	e.wg.Add(1)
	go e.monitorProcess()

	return nil
}

// WriteData sends input data to the shell
func (e *UnixExecutor) WriteData(ctx context.Context, data []byte) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.running || e.pty == nil {
		return fmt.Errorf("shell is not running")
	}

	_, err := e.pty.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write to shell: %w", err)
	}

	return nil
}

// Resize resizes the terminal
func (e *UnixExecutor) Resize(ctx context.Context, cols, rows int) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running || e.pty == nil {
		return fmt.Errorf("shell is not running")
	}

	e.config.Cols = cols
	e.config.Rows = rows

	err := pty.Setsize(e.pty, &pty.Winsize{
		Rows: uint16(rows),
		Cols: uint16(cols),
	})
	if err != nil {
		return fmt.Errorf("failed to resize terminal: %w", err)
	}

	return nil
}

// Close terminates the shell process
func (e *UnixExecutor) Close(ctx context.Context) error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return nil // Already closed
	}
	e.running = false
	
	// Cancel context first to signal goroutines to stop
	if e.cancel != nil {
		e.cancel()
	}

	// Close PTY to break read operations
	if e.pty != nil {
		if err := e.pty.Close(); err != nil {
			// Log error but continue cleanup
			_ = err // Explicitly ignore PTY close errors during cleanup
		}
	}

	// Terminate process gracefully
	if e.cmd != nil && e.cmd.Process != nil {
		// Try SIGTERM first - ignore errors as process might already be dead
		_ = e.cmd.Process.Signal(syscall.SIGTERM)

		// Wait a short time for graceful shutdown, then force kill if needed
		select {
		case <-ctx.Done():
			// Force kill if context expires - ignore errors as process might be dead
			_ = e.cmd.Process.Kill()
		case <-time.After(2 * time.Second):
			// Force kill after timeout - ignore errors as process might be dead
			_ = e.cmd.Process.Kill()
		}
	}
	e.mu.Unlock()

	// Wait for goroutines to finish before closing channels (without holding lock)
	e.wg.Wait()

	// Close channels
	close(e.outputCh)
	close(e.errorCh)

	return nil
}

// OutputChannel returns a channel for receiving output data
func (e *UnixExecutor) OutputChannel() <-chan []byte {
	return e.outputCh
}

// ErrorChannel returns a channel for receiving error notifications
func (e *UnixExecutor) ErrorChannel() <-chan error {
	return e.errorCh
}

// IsRunning returns true if the shell process is running
func (e *UnixExecutor) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

// getShellPath returns the full path to the shell executable
func (e *UnixExecutor) getShellPath() (string, error) {
	shellPaths := map[string][]string{
		"bash": {"/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash"},
		"zsh":  {"/bin/zsh", "/usr/bin/zsh", "/usr/local/bin/zsh"},
		"sh":   {"/bin/sh", "/usr/bin/sh"},
	}

	paths, exists := shellPaths[e.config.Shell]
	if !exists {
		return "", fmt.Errorf("unsupported shell: %s", e.config.Shell)
	}

	// Try to find the shell executable
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Fallback to PATH lookup
	path, err := exec.LookPath(e.config.Shell)
	if err != nil {
		return "", fmt.Errorf("shell not found: %s", e.config.Shell)
	}

	return path, nil
}

// readOutput reads output from the PTY and sends it to the output channel
func (e *UnixExecutor) readOutput() {
	defer func() {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
		e.wg.Done()
	}()

	buffer := make([]byte, 4096)
	for {
		select {
		case <-e.ctx.Done():
			return
		default:
			n, err := e.pty.Read(buffer)
			if err != nil {
				if err != io.EOF {
					select {
					case e.errorCh <- fmt.Errorf("PTY read error: %w", err):
					case <-e.ctx.Done():
						return
					default:
						// Drop error if channel is closed
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
					// Drop data if channel is full or closed
				}
			}
		}
	}
}

// monitorProcess monitors the shell process and handles its exit
func (e *UnixExecutor) monitorProcess() {
	defer e.wg.Done()
	
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
		case <-e.ctx.Done():
			return
		default:
			// Drop error if channel is closed
		}
	}
}