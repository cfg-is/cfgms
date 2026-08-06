//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package patch

import (
	"context"
	"os/exec"
	"syscall"
)

// newScriptCommand builds the cmd.exe invocation for a .bat/.cmd patch script.
//
// The command line is assembled explicitly rather than passed as argv because
// os/exec applies Windows argument escaping: a quoted path handed to
// exec.CommandContext arrives at cmd.exe as \"C:\path\x.bat\", which cmd reads as
// a command name containing backslash-quote and rejects with "is not recognized
// as an internal or external command".
//
// The doubled quotes are required, not redundant. With /s, cmd.exe strips the
// first and last quote of the remainder and runs what is left verbatim, so
// ""C:\path with space\x.bat"" reduces to a correctly quoted single command,
// while a single pair would reduce to a bare path that cmd would split on its
// spaces. scriptPath is metacharacter-rejected by validateWindowsScriptPath
// before it reaches here, so it cannot introduce a quote of its own and close
// the string early.
//
// /d skips any AutoRun command registered in the registry, so a compromised
// HKCU\...\Command Processor\AutoRun value cannot ride along with a patch script.
func newScriptCommand(ctx context.Context, scriptPath string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "cmd")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine: `cmd /d /s /c ""` + scriptPath + `""`,
	}
	return cmd
}
