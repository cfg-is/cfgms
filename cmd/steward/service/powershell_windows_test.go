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

			// Verify the script block is unmodified.
			assert.Equal(t, tc.scriptBlock, scriptBlockInCmd,
				"script block must not be modified")

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
func TestBuildPSCmd_StructureIsCorrect(t *testing.T) {
	cmd := buildPSCmd("Write-Output 'hello'", []string{"arg1", "arg2"})

	require.Equal(t, "powershell.exe", cmd.Args[0])
	require.Equal(t, "-NonInteractive", cmd.Args[1])
	require.Equal(t, "-NoProfile", cmd.Args[2])
	require.Equal(t, "-Command", cmd.Args[3])
	require.Equal(t, "Write-Output 'hello'", cmd.Args[4])
	require.Equal(t, "arg1", cmd.Args[5])
	require.Equal(t, "arg2", cmd.Args[6])
	assert.Len(t, cmd.Args, 7)
}
