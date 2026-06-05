// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// psRunner is the injectable PowerShell execution abstraction.
// Production code uses execPSRunner; tests substitute a recording implementation.
type psRunner interface {
	// RunPS executes scriptBlock via powershell.exe.
	// args are non-sensitive positional arguments passed as separate exec.Command
	// arguments after the script block — they MUST NOT contain passwords or other
	// secrets, as they appear in cmd.Args (visible to process-list tools).
	// stdinData is sensitive data (e.g. passwords) piped to the process via stdin;
	// it does NOT appear in cmd.Args or the process list.
	RunPS(scriptBlock string, args []string, stdinData string) (string, error)
}

// execPSRunner executes PowerShell scripts via os/exec.
// User-supplied values in args are passed as separate exec.Command arguments —
// never interpolated into the script block string.
type execPSRunner struct{}

// RunPS executes scriptBlock with args as separate exec arguments.
// stdinData is piped via stdin and does NOT appear in cmd.Args.
func (r *execPSRunner) RunPS(scriptBlock string, args []string, stdinData string) (string, error) {
	cmd := buildPSCmd(scriptBlock, args)
	if stdinData != "" {
		cmd.Stdin = strings.NewReader(stdinData)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("powershell: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// buildPSCmd constructs the exec.Cmd for PowerShell execution without running it.
// User-supplied values in args appear in cmd.Args as separate elements after the
// script block. Sensitive values (passwords) must NOT be in args — pass via
// cmd.Stdin in the caller (or stdinData in execPSRunner.RunPS).
//
// The script block is wrapped in `& { ... }` because powershell.exe -Command
// does NOT bind trailing CLI arguments to $args by default — it concatenates
// them onto the command string. Invoking via the call operator (`&`) on a
// script-block literal does bind $args, which is the contract every caller
// in this package relies on.
func buildPSCmd(scriptBlock string, args []string) *exec.Cmd {
	exeArgs := make([]string, 0, 4+len(args))
	exeArgs = append(exeArgs, "-NonInteractive", "-NoProfile", "-Command", "& { "+scriptBlock+" }")
	exeArgs = append(exeArgs, args...)
	return exec.Command("powershell.exe", exeArgs...) //#nosec G204 -- scriptBlock is a hardcoded template; user values are in args[]
}
