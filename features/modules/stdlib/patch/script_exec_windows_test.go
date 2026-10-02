//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package patch

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// The command line is what cmd.exe actually parses, and os/exec's argument
// escaping is bypassed to produce it, so it is asserted directly. Passing the
// quoted path through argv instead yields \"C:\...\x.bat\", which cmd rejects as
// an unrecognised command.
func TestNewScriptCommandBuildsCmdLineForCmdExe(t *testing.T) {
	t.Parallel()

	cmd := newScriptCommand(context.Background(), `C:\patches\update.cmd`)

	require.NotNil(t, cmd.SysProcAttr)
	require.Equal(t, `cmd /d /s /c ""C:\patches\update.cmd""`, cmd.SysProcAttr.CmdLine)
}

// A path with spaces is explicitly allowed by validateWindowsScriptPath, and is
// the case the doubled quotes exist for: /s strips only the outermost pair, so
// the inner pair still quotes the path when cmd splits the command line.
func TestNewScriptCommandQuotesPathContainingSpaces(t *testing.T) {
	t.Parallel()

	const scriptPath = `C:\Program Files\CFGMS Patches\update.cmd`
	require.NoError(t, validateWindowsScriptPath(scriptPath))

	cmd := newScriptCommand(context.Background(), scriptPath)

	require.NotNil(t, cmd.SysProcAttr)
	require.Equal(t,
		`cmd /d /s /c ""C:\Program Files\CFGMS Patches\update.cmd""`,
		cmd.SysProcAttr.CmdLine)
}
