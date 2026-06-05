// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// psCall records a single RunPS invocation for test inspection.
type psCall struct {
	ScriptBlock string
	Args        []string
	StdinData   string
	Cmd         *exec.Cmd
}

// recordingPSRunner captures RunPS calls without executing them.
// Used by tests to verify injection safety and argument construction.
type recordingPSRunner struct {
	Calls []psCall
}

func (r *recordingPSRunner) RunPS(scriptBlock string, args []string, stdinData string) (string, error) {
	cmd := buildPSCmd(scriptBlock, args)
	if stdinData != "" {
		cmd.Stdin = strings.NewReader(stdinData)
	}
	r.Calls = append(r.Calls, psCall{
		ScriptBlock: scriptBlock,
		Args:        args,
		StdinData:   stdinData,
		Cmd:         cmd,
	})
	return "ok", nil
}

// TestInstallHyperVPSHelper_InjectionSafe verifies that user-supplied values —
// including values with spaces, quotes, and semicolons — are passed as separate
// os/exec arguments and are never concatenated into the script block string.
func TestInstallHyperVPSHelper_InjectionSafe(t *testing.T) {
	cases := []struct {
		name        string
		scriptBlock string
		args        []string
		stdinData   string
	}{
		{
			name:        "username with spaces",
			scriptBlock: `$username = $args[0]; Write-Output $username`,
			args:        []string{"user with spaces"},
		},
		{
			name:        "username with double quotes",
			scriptBlock: `$username = $args[0]; Write-Output $username`,
			args:        []string{`user"with"quotes`},
		},
		{
			name:        "username with semicolons",
			scriptBlock: `$username = $args[0]; Write-Output $username`,
			args:        []string{"user;rm -rf /;attempt"},
		},
		{
			name:        "username with backtick",
			scriptBlock: `$username = $args[0]; Write-Output $username`,
			args:        []string{"user`injection"},
		},
		{
			name:        "password via stdin not in args",
			scriptBlock: `$username = $args[0]; $pass = [Console]::In.ReadToEnd()`,
			args:        []string{"safe-user"},
			stdinData:   "s3cr3t!P@ss#with<special>&chars",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := buildPSCmd(tc.scriptBlock, tc.args)

			// cmd.Args layout: [powershell.exe, -NonInteractive, -NoProfile, -Command, scriptBlock, ...args...]
			require.GreaterOrEqual(t, len(cmd.Args), 5,
				"cmd.Args must have at least 5 elements")

			scriptBlockInCmd := cmd.Args[4]

			// Verify the user-supplied script content is preserved inside the
			// `& { ... }` wrapper. The wrapper is what makes PowerShell bind
			// $args from trailing CLI arguments; the wrapped content itself
			// MUST equal the input scriptBlock byte-for-byte.
			assert.Equal(t, "& { "+tc.scriptBlock+" }", scriptBlockInCmd,
				"script block must be wrapped in `& { ... }` with content unchanged")

			// Verify each user-supplied arg is a separate element (not in script block).
			for _, arg := range tc.args {
				// The arg must NOT appear in the script block element.
				assert.NotContains(t, scriptBlockInCmd, arg,
					"user-supplied arg %q must not be embedded in the script block", arg)

				// The arg MUST appear as a separate cmd.Args element.
				found := false
				for _, cmdArg := range cmd.Args[5:] {
					if cmdArg == arg {
						found = true
						break
					}
				}
				assert.True(t, found,
					"user-supplied arg %q must appear as a separate cmd.Args element", arg)
			}

			// Sensitive stdin data must NOT appear in any cmd.Args element.
			if tc.stdinData != "" {
				for _, cmdArg := range cmd.Args {
					assert.NotContains(t, cmdArg, tc.stdinData,
						"sensitive stdin data must not appear in cmd.Args element %q", cmdArg)
				}
			}
		})
	}
}

// TestBuildPSCmd_StructureIsCorrect verifies the fixed argument positions
// that TestInstallHyperV_PassNotInArgv relies on.
//
// cmd.Args[4] wraps the user script in `& { ... }` so that powershell.exe
// invokes it as a script block and binds the trailing args to $args.
// Without the wrapper, `-Command "<script>" arg1` appends arg1 textually to
// the script string and $args stays empty.
func TestBuildPSCmd_StructureIsCorrect(t *testing.T) {
	cmd := buildPSCmd("Write-Output 'hello'", []string{"arg1", "arg2"})

	require.Equal(t, "powershell.exe", cmd.Args[0])
	require.Equal(t, "-NonInteractive", cmd.Args[1])
	require.Equal(t, "-NoProfile", cmd.Args[2])
	require.Equal(t, "-Command", cmd.Args[3])
	require.Equal(t, "& { Write-Output 'hello' }", cmd.Args[4])
	require.Equal(t, "arg1", cmd.Args[5])
	require.Equal(t, "arg2", cmd.Args[6])
	assert.Len(t, cmd.Args, 7)
}

// TestExecPSRunner_ArgsBoundToArgsArray verifies that values passed in args[]
// are reachable as $args[N] inside the executing script block when invoked
// by the real powershell.exe.
//
// Regression test: prior to wrapping the script block in `& { ... }`, calling
// `powershell.exe -Command "<script>" arg0` appended arg0 textually after the
// script content and $args[0] stayed undefined — breaking every Hyper-V install
// helper that relied on $args. The structural-only test passed because it
// inspected cmd.Args layout without ever launching PowerShell.
func TestExecPSRunner_ArgsBoundToArgsArray(t *testing.T) {
	runner := &execPSRunner{}
	out, err := runner.RunPS(`Write-Output $args[0]`, []string{"hello-world"}, "")
	require.NoError(t, err)
	assert.Equal(t, "hello-world", out)
}

// TestExecPSRunner_ArgsBoundForMultiStatementScript ensures that $args is
// bound for every reference site in a multi-line script — mirrors the shape
// of generateHyperVCert in hyperv_windows.go where $args[0] is read at the
// top and its derivative is emitted at the bottom of a multi-line block.
func TestExecPSRunner_ArgsBoundForMultiStatementScript(t *testing.T) {
	script := `$x = $args[0]
$y = $args[1]
Write-Output "$x|$y"`
	runner := &execPSRunner{}
	out, err := runner.RunPS(script, []string{"first", "second"}, "")
	require.NoError(t, err)
	assert.Equal(t, "first|second", out)
}

// TestExecPSRunner_StdinDeliveredToScript verifies that stdinData is readable
// from the executing script block via [Console]::In.ReadToEnd(). This is the
// path the WinRM service-account password takes — argv stays clean, the
// secret lives only on stdin.
func TestExecPSRunner_StdinDeliveredToScript(t *testing.T) {
	runner := &execPSRunner{}
	out, err := runner.RunPS(`[Console]::In.ReadToEnd()`, nil, "piped-stdin-data")
	require.NoError(t, err)
	assert.Equal(t, "piped-stdin-data", out)
}
