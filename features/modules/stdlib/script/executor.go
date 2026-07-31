// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"bytes"
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

// reapGracePeriod bounds how long Execute waits for cmd.Wait to return after it
// has terminated a timed-out process tree. A successful tree kill closes the
// inherited pipe handles and Wait returns almost immediately, well within this
// window; the timer only fires in the pathological case where a handle lingers,
// guaranteeing Execute returns rather than wedging the steward's exec channel
// indefinitely (Issue #2715).
const reapGracePeriod = 10 * time.Second

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
	//   literal       → ParamEnvVarName(): CFGMS_PARAM_<PARAM> on all platforms —
	//                   namespaced to prevent shadowing standard env vars (e.g. PATH)
	var secretEnvEntries []string
	if len(e.secretBindings) > 0 {
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
				envKey = ParamEnvVarName(e.config.Shell, param.Name)
			}
			secretEnvEntries = append(secretEnvEntries, fmt.Sprintf("%s=%s", envKey, param.Value))
		}
	}

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, e.config.Timeout)
	defer cancel()

	// Build command based on shell type and platform. cleanup removes the temp
	// script file after execution completes.
	cmd, cleanup, err := e.buildCommand(timeoutCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to build command: %w", err)
	}
	defer cleanup()

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

	// Capture stdout and stderr into buffers. Assigning *bytes.Buffer directly to
	// cmd.Stdout/cmd.Stderr lets exec.Cmd own the output-copy goroutines: cmd.Wait
	// blocks until that copying finishes, so there is no race between draining the
	// output and Wait closing the underlying pipes. The StdoutPipe/StderrPipe
	// contract explicitly forbids reading the pipe concurrently with Wait, which
	// silently truncated output from fast-exiting scripts.
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// Prepare process-tree tracking BEFORE Start so the Job Object exists and the
	// process can be assigned to it as the very first post-Start action. On Windows
	// this closes Issue #2715: a detached grandchild (e.g. a `--runasservice` step)
	// that inherited the stdout/stderr pipe would otherwise keep cmd.Wait() — and
	// this goroutine, plus the steward's per-device execution slot — blocked forever
	// after a top-level-only cmd.Process.Kill().
	tree := newProcessTree(e.logger)
	tree.prepare()
	defer tree.close()

	// Start the command
	if err := cmd.Start(); err != nil {
		cleanupToken()
		return nil, fmt.Errorf("failed to start command: %w", err)
	}
	// Assign the process to its Job Object immediately, before any other work, so
	// it becomes a job member before it can spawn descendants.
	tree.track(cmd)
	// Token (Windows) or no-op (Unix): release the handle after the process is created.
	cleanupToken()

	result.PID = cmd.Process.Pid

	// Wait for command completion or timeout.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		// Command completed; cmd.Wait has flushed all output into the buffers.
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		result.Stdout = stdoutBuf.String()
		result.Stderr = stderrBuf.String()

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
		// Timeout occurred. Terminate the ENTIRE process tree (Issue #2715), not
		// just the top-level process — otherwise a grandchild holding an inherited
		// stdout/stderr pipe keeps cmd.Wait() blocked forever below.
		tree.terminate(cmd)

		// Reap the killed process so cmd.Wait returns and its output-copy
		// goroutines exit; partial output is discarded on timeout. With the tree
		// terminated the inherited pipe handles close and done fires promptly. The
		// grace timer is a bounded backstop so Execute can never block the exec
		// channel indefinitely even in the pathological case where the tree kill
		// did not release every handle (AC2). A working tree kill always reaches
		// done first, so the executor goroutine exits and is not leaked.
		select {
		case <-done:
		case <-time.After(reapGracePeriod):
			e.logger.Warn("script process tree did not reap within grace period after termination",
				"grace", reapGracePeriod, "pid", result.PID)
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

// buildCommand creates the appropriate command for the shell type and platform.
// The returned cleanup function removes any temporary script file created; callers
// must call it after the command has finished executing.
func (e *Executor) buildCommand(ctx context.Context) (*exec.Cmd, func(), error) {
	switch runtime.GOOS {
	case "windows":
		return e.buildWindowsCommand(ctx)
	case "linux", "darwin":
		return e.buildUnixCommand(ctx)
	default:
		return nil, func() {}, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// writeTempScript writes content to a temp file with the given name pattern and
// returns the path and a cleanup function that removes the file.
func writeTempScript(pattern, content string) (string, func(), error) {
	noop := func() {}
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", noop, fmt.Errorf("create temp script: %w", err)
	}
	tmpPath := f.Name()
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return "", noop, fmt.Errorf("write temp script: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", noop, fmt.Errorf("close temp script: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmpPath) }
	return tmpPath, cleanup, nil
}

// buildWindowsCommand creates commands for Windows platforms.
// Scripts are staged to a temp file and executed by file path — no inline content
// is passed to the interpreter, eliminating -ExecutionPolicy Bypass, -Command <string>,
// and python -c <string> injection vectors.
func (e *Executor) buildWindowsCommand(ctx context.Context) (*exec.Cmd, func(), error) {
	noop := func() {}
	switch e.config.Shell {
	case ShellPowerShell:
		tmpPath, cleanup, err := writeTempScript("cfgms-script-*.ps1", e.config.Content)
		if err != nil {
			return nil, noop, err
		}
		// #nosec G204 - tmpPath is a temp file created by this process; not user input
		return exec.CommandContext(ctx, "powershell.exe", "-NonInteractive", "-File", tmpPath), cleanup, nil

	case ShellPwsh:
		tmpPath, cleanup, err := writeTempScript("cfgms-script-*.ps1", e.config.Content)
		if err != nil {
			return nil, noop, err
		}
		// PowerShell Core (pwsh.exe). Same temp-script / -File pattern as Windows
		// PowerShell — no -Command string, no inline composition (CLAUDE.md banned patterns).
		// #nosec G204 - tmpPath is a temp file created by this process; not user input
		return exec.CommandContext(ctx, "pwsh.exe", "-NonInteractive", "-File", tmpPath), cleanup, nil

	case ShellCmd:
		tmpPath, cleanup, err := writeTempScript("cfgms-script-*.cmd", e.config.Content)
		if err != nil {
			return nil, noop, err
		}
		// buildCmdExeCommand (executor_windows.go) sets SysProcAttr.CmdLine so that
		// the path is quoted before cmd.exe /c sees it. This is required when %TEMP%
		// contains a space (e.g. a user-profile directory under logged_in_user context).
		return buildCmdExeCommand(ctx, tmpPath), cleanup, nil

	case ShellPython:
		tmpPath, cleanup, err := writeTempScript("cfgms-script-*.py", e.config.Content)
		if err != nil {
			return nil, noop, err
		}
		// #nosec G204 - tmpPath is a temp file created by this process; not user input
		return exec.CommandContext(ctx, "python.exe", tmpPath), cleanup, nil

	case ShellPython3:
		tmpPath, cleanup, err := writeTempScript("cfgms-script-*.py", e.config.Content)
		if err != nil {
			return nil, noop, err
		}
		// #nosec G204 - tmpPath is a temp file created by this process; not user input
		return exec.CommandContext(ctx, "python3.exe", tmpPath), cleanup, nil

	default:
		return nil, noop, fmt.Errorf("unsupported shell on Windows: %s", e.config.Shell)
	}
}

// buildUnixCommand creates commands for Unix-like platforms (Linux/macOS).
// Scripts are staged to a temp file and executed by file path — no inline content
// is passed via -c flags, eliminating the bash -c <string> injection vector.
func (e *Executor) buildUnixCommand(ctx context.Context) (*exec.Cmd, func(), error) {
	noop := func() {}

	writeExec := func(pattern string) (string, func(), error) {
		tmpPath, cleanup, err := writeTempScript(pattern, e.config.Content)
		if err != nil {
			return "", noop, err
		}
		// #nosec G302 -- the temporary script must be executable; 0700 grants
		// access only to its owning steward process.
		if err := os.Chmod(tmpPath, 0700); err != nil {
			cleanup()
			return "", noop, fmt.Errorf("chmod temp script: %w", err)
		}
		return tmpPath, cleanup, nil
	}

	switch e.config.Shell {
	case ShellBash:
		tmpPath, cleanup, err := writeExec("cfgms-script-*")
		if err != nil {
			return nil, noop, err
		}
		// #nosec G204 - tmpPath is a temp file created by this process; not user input
		return exec.CommandContext(ctx, "/bin/bash", tmpPath), cleanup, nil

	case ShellZsh:
		tmpPath, cleanup, err := writeExec("cfgms-script-*")
		if err != nil {
			return nil, noop, err
		}
		// #nosec G204 - tmpPath is a temp file created by this process; not user input
		return exec.CommandContext(ctx, "/bin/zsh", tmpPath), cleanup, nil

	case ShellSh:
		tmpPath, cleanup, err := writeExec("cfgms-script-*")
		if err != nil {
			return nil, noop, err
		}
		// #nosec G204 - tmpPath is a temp file created by this process; not user input
		return exec.CommandContext(ctx, "/bin/sh", tmpPath), cleanup, nil

	case ShellPwsh:
		// PowerShell Core (pwsh) is cross-platform. Same safe temp-script / -File
		// pattern as on Windows — no -Command string, no inline composition
		// (CLAUDE.md banned patterns). Resolved via PATH since the install location
		// varies across distributions.
		tmpPath, cleanup, err := writeTempScript("cfgms-script-*.ps1", e.config.Content)
		if err != nil {
			return nil, noop, err
		}
		// #nosec G204 - tmpPath is a temp file created by this process; not user input
		return exec.CommandContext(ctx, "pwsh", "-NonInteractive", "-File", tmpPath), cleanup, nil

	case ShellPython:
		tmpPath, cleanup, err := writeTempScript("cfgms-script-*", e.config.Content)
		if err != nil {
			return nil, noop, err
		}
		// #nosec G204 - tmpPath is a temp file created by this process; not user input
		return exec.CommandContext(ctx, "/usr/bin/python", tmpPath), cleanup, nil

	case ShellPython3:
		tmpPath, cleanup, err := writeTempScript("cfgms-script-*", e.config.Content)
		if err != nil {
			return nil, noop, err
		}
		// #nosec G204 - tmpPath is a temp file created by this process; not user input
		return exec.CommandContext(ctx, "/usr/bin/python3", tmpPath), cleanup, nil

	default:
		return nil, noop, fmt.Errorf("unsupported shell on Unix: %s", e.config.Shell)
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
	case ShellPwsh:
		if _, err := exec.LookPath("pwsh.exe"); err != nil {
			return fmt.Errorf("PowerShell Core (pwsh) is not available: %w", err)
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
	case ShellPwsh:
		// PowerShell Core has no canonical install path on Unix; resolve via PATH.
		if _, err := exec.LookPath("pwsh"); err != nil {
			return fmt.Errorf("PowerShell Core (pwsh) is not available: %w", err)
		}
		return nil
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
