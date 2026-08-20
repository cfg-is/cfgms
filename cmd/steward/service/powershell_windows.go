// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import (
	"os/exec"
)

// buildPSCmd constructs the exec.Cmd for PowerShell execution without running it.
// User-supplied values in args appear in cmd.Args as separate elements after the
// script block. Sensitive values (passwords) must NOT be in args — pass them via
// cmd.Stdin in the caller, where they do not appear in cmd.Args or the process
// list.
//
// The psRunner/execPSRunner injection seam that used to wrap this helper was
// removed with the last of its callers: the hyperv WinRM + service-account
// install path deleted in 2e4bfcec (Issue #1894, "steward: generic install —
// remove hyperv/winrm flags"). The helper itself is kept because it is the
// safe-by-construction way to build a PowerShell invocation — script block
// fixed, user values as separate argv entries, never string-composed — and its
// injection-safety tests still pin that contract for the next caller.
func buildPSCmd(scriptBlock string, args []string) *exec.Cmd {
	exeArgs := make([]string, 0, 4+len(args))
	exeArgs = append(exeArgs, "-NonInteractive", "-NoProfile", "-Command", scriptBlock)
	exeArgs = append(exeArgs, args...)
	return exec.Command("powershell.exe", exeArgs...) //#nosec G204 -- scriptBlock is a hardcoded template; user values are in args[]
}
