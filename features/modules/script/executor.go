// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// Executor handles cross-platform script execution
type Executor struct {
	config         *ScriptConfig
	logger         logging.Logger
	secretStore    interfaces.SecretStore
	secretBindings []ParamBinding
}

// NewExecutor creates a new script executor with the given configuration
func NewExecutor(config *ScriptConfig) *Executor {
	return &Executor{
		config: config,
		logger: logging.NewLogger("info"),
	}
}

// NewExecutorWithSecrets creates a script executor that resolves secret
// bindings from the provided store at execution time. Secrets are delivered
// via process-scoped environment variables and cleared after the script exits.
func NewExecutorWithSecrets(config *ScriptConfig, store interfaces.SecretStore, bindings []ParamBinding) *Executor {
	return &Executor{
		config:         config,
		logger:         logging.NewLogger("info"),
		secretStore:    store,
		secretBindings: bindings,
	}
}

// Execute runs the script and returns the execution result
func (e *Executor) Execute(ctx context.Context) (*ExecutionResult, error) {
	startTime := time.Now()

	// Enhanced security monitoring: Log script execution details
	e.logger.Info("Script execution initiated",
		"shell", e.config.Shell,
		"working_dir", e.config.WorkingDir,
		"timeout", e.config.Timeout,
		"content_hash", hashScriptContent(e.config.Content),
		"env_vars", len(e.config.Environment),
		"execution_context", string(e.config.ExecutionContext))

	// Resolve param bindings before building the command. All params — both
	// secret-store and literal — are injected exclusively into cmd.Env on the
	// child process; the parent process environment is never modified, eliminating
	// race conditions at 50k+ steward scale and preventing value leakage via
	// /proc/pid/cmdline (Linux), ps output, or Windows Event 4688.
	//
	// Env var naming by binding type:
	//   secret-store  → SecretEnvVarName(): CFGMS_SECRET_<PARAM> on Windows (avoids
	//                   Event 4688 cmdline logging), <PARAM> on Unix (12-factor)
	//   literal       → strings.ToUpper(param.Name) on all platforms — no secret
	//                   prefix because the value is not a credential
	var secretEnvEntries []string
	if e.secretStore != nil && len(e.secretBindings) > 0 {
		resolved, err := ResolveSecretBindings(ctx, e.secretStore, e.secretBindings)
		if err != nil {
			return nil, fmt.Errorf("secret injection blocked: %w", err)
		}
		secretEnvEntries = make([]string, 0, len(resolved))
		for _, param := range resolved {
			var envKey string
			if param.IsSecret {
				envKey = SecretEnvVarName(e.config.Shell, param.Name)
			} else {
				envKey = strings.ToUpper(param.Name)
			}
			secretEnvEntries = append(secretEnvEntries, fmt.Sprintf("%s=%s", envKey, param.Value))
		}
	}

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, e.config.Timeout)
	defer cancel()

	// Build command based on shell type and platform
	cmd, err := e.buildCommand(timeoutCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to build command: %w", err)
	}

	// Apply execution context: may replace cmd with a sudo wrapper (Unix) or attach a
	// user token (Windows). This must happen before Dir/Env are set so those values
	// land on the final command regardless of which platform path is taken.
	cmd, actualUser, cleanupToken, err := applyExecutionContext(timeoutCtx, e.config, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to apply execution context: %w", err)
	}

	// Set working directory on the (potentially wrapped) command
	if e.config.WorkingDir != "" {
		cmd.Dir = e.config.WorkingDir
	}

	// Build child process environment from the parent snapshot plus any
	// configured env vars and resolved secrets. Always set cmd.Env explicitly
	// when there is anything to add so secrets are isolated to the child.
	if len(e.config.Environment) > 0 || len(secretEnvEntries) > 0 {
		env := os.Environ()
		for key, value := range e.config.Environment {
			env = append(env, fmt.Sprintf("%s=%s", key, value))
		}
		env = append(env, secretEnvEntries...)
		cmd.Env = env
	}

	// Execute the command
	result := &ExecutionResult{
		StartTime:  startTime,
		ActualUser: actualUser,
	}

	// Capture stdout and stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		cleanupToken()
		return nil, fmt.Errorf("failed to start command: %w", err)
	}
	// Token (Windows) or no-op (Unix): release the handle after the process is created.
	cleanupToken()

	result.PID = cmd.Process.Pid

	// Read output
	stdoutData := make([]byte, 0)
	stderrData := make([]byte, 0)

	// Use goroutines to read stdout and stderr concurrently
	stdoutDone := make(chan error, 1)
	stderrDone := make(chan error, 1)

	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				stdoutData = append(stdoutData, buf[:n]...)
			}
			if err != nil {
				stdoutDone <- err
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				stderrData = append(stderrData, buf[:n]...)
			}
			if err != nil {
				stderrDone <- err
				return
			}
		}
	}()

	// Wait for command completion or timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		// Command completed
		<-stdoutDone
		<-stderrDone

		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		result.Stdout = string(stdoutData)
		result.Stderr = string(stderrData)

		if err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				result.ExitCode = exitError.ExitCode()
			} else {
				return nil, fmt.Errorf("command execution failed: %w", err)
			}
		} else {
			result.ExitCode = 0
		}

		return result, nil

	case <-timeoutCtx.Done():
		// Timeout occurred
		if err := cmd.Process.Kill(); err != nil {
			e.logger.Warn("failed to kill timed-out script process", "error", err)
		}
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		result.ExitCode = -1
		result.Stderr = "Script execution timed out"

		return result, fmt.Errorf("script execution timed out after %v", e.config.Timeout)
	}
}

// hashScriptContent creates a secure hash of script content for audit logging
func hashScriptContent(content string) string {
	hash := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", hash[:8]) // First 8 bytes for logging
}

// buildCommand creates the appropriate command for the shell type and platform
func (e *Executor) buildCommand(ctx context.Context) (*exec.Cmd, error) {
	switch runtime.GOOS {
	case "windows":
		return e.buildWindowsCommand(ctx)
	case "linux", "darwin":
		return e.buildUnixCommand(ctx)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// buildWindowsCommand creates commands for Windows platforms
func (e *Executor) buildWindowsCommand(ctx context.Context) (*exec.Cmd, error) {
	switch e.config.Shell {
	case ShellPowerShell:
		// Use PowerShell with appropriate execution policy
		// #nosec G204 - CMS requires script execution for configuration management
		return exec.CommandContext(ctx, "powershell.exe",
			"-ExecutionPolicy", "Bypass",
			"-NonInteractive",
			"-Command", e.config.Content), nil

	case ShellCmd:
		// Use Command Prompt
		// #nosec G204 - CMS requires script execution for configuration management
		return exec.CommandContext(ctx, "cmd.exe", "/c", e.config.Content), nil

	case ShellPython, ShellPython3:
		// Use Python interpreter
		pythonCmd := "python"
		if e.config.Shell == ShellPython3 {
			pythonCmd = "python3"
		}
		// #nosec G204 - CMS requires script execution for configuration management
		return exec.CommandContext(ctx, pythonCmd, "-c", e.config.Content), nil

	default:
		return nil, fmt.Errorf("unsupported shell on Windows: %s", e.config.Shell)
	}
}

// buildUnixCommand creates commands for Unix-like platforms (Linux/macOS)
func (e *Executor) buildUnixCommand(ctx context.Context) (*exec.Cmd, error) {
	switch e.config.Shell {
	case ShellBash:
		// #nosec G204 - CMS requires script execution for configuration management
		return exec.CommandContext(ctx, "/bin/bash", "-c", e.config.Content), nil

	case ShellZsh:
		// #nosec G204 - CMS requires script execution for configuration management
		return exec.CommandContext(ctx, "/bin/zsh", "-c", e.config.Content), nil

	case ShellSh:
		// #nosec G204 - CMS requires script execution for configuration management
		return exec.CommandContext(ctx, "/bin/sh", "-c", e.config.Content), nil

	case ShellPython, ShellPython3:
		pythonCmd := "/usr/bin/python"
		if e.config.Shell == ShellPython3 {
			pythonCmd = "/usr/bin/python3"
		}
		// #nosec G204 - CMS requires script execution for configuration management
		return exec.CommandContext(ctx, pythonCmd, "-c", e.config.Content), nil

	default:
		return nil, fmt.Errorf("unsupported shell on Unix: %s", e.config.Shell)
	}
}

// ValidateShellAvailability checks if the required shell is available on the system
func (e *Executor) ValidateShellAvailability() error {
	switch runtime.GOOS {
	case "windows":
		return e.validateWindowsShell()
	case "linux", "darwin":
		return e.validateUnixShell()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// validateWindowsShell checks Windows shell availability
func (e *Executor) validateWindowsShell() error {
	switch e.config.Shell {
	case ShellPowerShell:
		if _, err := exec.LookPath("powershell.exe"); err != nil {
			return fmt.Errorf("PowerShell is not available: %w", err)
		}
	case ShellCmd:
		if _, err := exec.LookPath("cmd.exe"); err != nil {
			return fmt.Errorf("command prompt is not available: %w", err)
		}
	case ShellPython:
		if _, err := exec.LookPath("python"); err != nil {
			return fmt.Errorf("python is not available: %w", err)
		}
	case ShellPython3:
		if _, err := exec.LookPath("python3"); err != nil {
			return fmt.Errorf("python 3 is not available: %w", err)
		}
	default:
		return fmt.Errorf("unsupported shell on Windows: %s", e.config.Shell)
	}
	return nil
}

// validateUnixShell checks Unix shell availability
func (e *Executor) validateUnixShell() error {
	var shellPath string

	switch e.config.Shell {
	case ShellBash:
		shellPath = "/bin/bash"
	case ShellZsh:
		shellPath = "/bin/zsh"
	case ShellSh:
		shellPath = "/bin/sh"
	case ShellPython:
		shellPath = "/usr/bin/python"
	case ShellPython3:
		shellPath = "/usr/bin/python3"
	default:
		return fmt.Errorf("unsupported shell on Unix: %s", e.config.Shell)
	}

	if _, err := os.Stat(shellPath); os.IsNotExist(err) {
		// Try to find in PATH as fallback
		shellName := strings.TrimPrefix(shellPath, "/usr/bin/")
		shellName = strings.TrimPrefix(shellName, "/bin/")
		if _, err := exec.LookPath(shellName); err != nil {
			return fmt.Errorf("shell %s is not available at %s or in PATH: %w", e.config.Shell, shellPath, err)
		}
	}

	return nil
}
