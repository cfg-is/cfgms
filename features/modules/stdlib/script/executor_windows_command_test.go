// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package script

// This file is intentionally cross-platform (no _windows suffix): buildWindowsCommand
// lives in executor.go and compiles on every platform (buildCmdExeCommand has a Unix
// stub). The table-driven coverage here guarantees the steward executor's accepted
// Windows shell taxonomy matches the controller allow-list (Issue #1995, root cause B).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildWindowsCommand_ShellTaxonomy verifies that the Windows executor accepts
// powershell, pwsh, and cmd (and python/python3), and rejects unknown shells with
// an "unsupported shell" error. This is the steward side of the unified taxonomy;
// TestAllowedShellsMatchesExecutor (handlers_runs_test.go) pins the controller side.
func TestBuildWindowsCommand_ShellTaxonomy(t *testing.T) {
	tests := []struct {
		name        string
		shell       ShellType
		wantErr     bool
		wantExeHint string // substring expected in cmd.Path/Args[0] for accepted shells
	}{
		{name: "windows powershell 5.1", shell: ShellPowerShell, wantErr: false, wantExeHint: "powershell"},
		{name: "powershell core pwsh", shell: ShellPwsh, wantErr: false, wantExeHint: "pwsh"},
		{name: "cmd", shell: ShellCmd, wantErr: false},
		{name: "python", shell: ShellPython, wantErr: false, wantExeHint: "python"},
		{name: "python3", shell: ShellPython3, wantErr: false, wantExeHint: "python3"},
		{name: "unknown shell rejected", shell: ShellType("nushell"), wantErr: true},
		{name: "unix bash rejected on windows path", shell: ShellBash, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &Executor{config: &ScriptConfig{
				Content: "echo hi",
				Shell:   tc.shell,
				Timeout: 5 * time.Second,
			}}

			cmd, cleanup, err := e.buildWindowsCommand(context.Background())
			if cleanup != nil {
				defer cleanup()
			}

			if tc.wantErr {
				require.Error(t, err, "shell %q must be rejected by the Windows executor", tc.shell)
				assert.Contains(t, err.Error(), "unsupported shell",
					"rejection must be an unsupported-shell error")
				return
			}

			require.NoError(t, err, "shell %q must be accepted by the Windows executor", tc.shell)

			// The cmd case routes through buildCmdExeCommand, which is a no-op stub on
			// Unix (returns nil). Skip the exe-name assertion for that case off-Windows.
			if tc.wantExeHint == "" {
				return
			}
			require.NotNil(t, cmd, "accepted shell %q must produce a command", tc.shell)
			joined := strings.ToLower(cmd.Path + " " + strings.Join(cmd.Args, " "))
			assert.Contains(t, joined, tc.wantExeHint,
				"command for shell %q must invoke the %q interpreter", tc.shell, tc.wantExeHint)

			// CLAUDE.md banned-pattern guard: PowerShell variants must execute by
			// file (-File), never via -Command or an inline string.
			if tc.shell == ShellPowerShell || tc.shell == ShellPwsh {
				assert.Contains(t, cmd.Args, "-File",
					"PowerShell shells must execute a temp script with -File, not -Command")
				assert.NotContains(t, joined, "-command",
					"PowerShell shells must not use -Command (inline composition is banned)")
			}
		})
	}
}

// controllerAllowedShells mirrors the controller's allowedShells map
// (features/controller/api/handlers_runs.go). The api-package test
// TestAllowedShellsMatchesExecutorTaxonomy pins that map to the ShellType
// constants; this list pins the EXECUTOR side so neither can drift away from the
// other (Issue #1995, root cause B — pwsh added in some sites but not others).
var controllerAllowedShells = []ShellType{
	ShellBash, ShellSh, ShellPowerShell, ShellPwsh, ShellCmd,
}

// TestExecutorHandlesEveryControllerAllowedShell asserts that every shell the
// controller will dispatch is handled by the steward executor's build AND validate
// paths on the platform(s) where it is valid — never falling through to the
// "unsupported shell" default.
func TestExecutorHandlesEveryControllerAllowedShell(t *testing.T) {
	// Platform applicability for each controller-allowed shell.
	windowsShells := map[ShellType]bool{
		ShellPowerShell: true, ShellPwsh: true, ShellCmd: true,
	}
	unixShells := map[ShellType]bool{
		ShellBash: true, ShellSh: true, ShellPwsh: true,
	}

	for _, sh := range controllerAllowedShells {
		sh := sh
		t.Run(string(sh), func(t *testing.T) {
			require.True(t, windowsShells[sh] || unixShells[sh],
				"controller-allowed shell %q must be valid on at least one platform", sh)

			e := &Executor{config: &ScriptConfig{Content: "echo hi", Shell: sh, Timeout: 5 * time.Second}}

			if windowsShells[sh] {
				_, cleanup, err := e.buildWindowsCommand(context.Background())
				if cleanup != nil {
					cleanup()
				}
				require.NoError(t, err, "Windows executor must handle controller-allowed shell %q", sh)
			}
			if unixShells[sh] {
				cmd, cleanup, err := e.buildUnixCommand(context.Background())
				if cleanup != nil {
					cleanup()
				}
				require.NoError(t, err, "Unix executor must handle controller-allowed shell %q", sh)
				require.NotNil(t, cmd)
			}
		})
	}
}

// TestValidateWindowsShell_AcceptsPwsh pins that validateWindowsShell handles pwsh
// (it previously fell through to the unsupported-shell default, inconsistent with
// buildWindowsCommand — Issue #1995 review B1). pwsh.exe is unlikely to be present
// on CI, so we assert the rejection is an availability error, never the
// unsupported-shell taxonomy error.
func TestValidateWindowsShell_AcceptsPwsh(t *testing.T) {
	e := &Executor{config: &ScriptConfig{Content: "echo hi", Shell: ShellPwsh, Timeout: 5 * time.Second}}
	err := e.validateWindowsShell()
	if err != nil {
		assert.NotContains(t, err.Error(), "unsupported shell on Windows",
			"pwsh must be a recognized Windows shell (availability error is acceptable, taxonomy rejection is not)")
		assert.Contains(t, err.Error(), "pwsh",
			"a pwsh validation failure must reference pwsh availability")
	}
}

// TestIsShellSupported_PwshCrossPlatform verifies pwsh is accepted by config
// validation on the current platform (Windows and Unix), since PowerShell Core is
// cross-platform (Issue #1995 review B1).
func TestIsShellSupported_PwshCrossPlatform(t *testing.T) {
	c := &ScriptConfig{Shell: ShellPwsh}
	assert.True(t, c.isShellSupported(),
		"pwsh (PowerShell Core) must be supported on the current platform")
}

// TestIsPowerShellScript_IncludesPwsh verifies the signing path treats pwsh as a
// PowerShell variant (Issue #1995 review B1).
func TestIsPowerShellScript_IncludesPwsh(t *testing.T) {
	assert.True(t, isPowerShellScript(ShellPwsh), "pwsh must be treated as a PowerShell variant")
	assert.True(t, isPowerShellScript(ShellPowerShell), "powershell must be treated as a PowerShell variant")
	assert.False(t, isPowerShellScript(ShellBash), "bash is not a PowerShell variant")
}
