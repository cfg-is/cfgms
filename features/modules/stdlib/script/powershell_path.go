// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"os"
	"strings"
)

// windowsPowerShellPath resolves powershell.exe via an absolute path under %SystemRoot%
// (then %windir%, then C:\Windows) rather than %PATH%, so a planted powershell.exe earlier
// on PATH cannot stand in for the Authenticode verifier. It returns "" if the result is
// not absolute; callers must treat that as a failure, never fall back to a bare name.
func windowsPowerShellPath(getenv func(string) string) string {
	root := getenv("SystemRoot")
	if root == "" {
		root = getenv("windir")
	}
	if root == "" {
		root = `C:\Windows`
	}
	p := root + `\System32\WindowsPowerShell\v1.0\powershell.exe`
	driveAbs := len(root) >= 3 && root[1] == ':' && (root[2] == '\\' || root[2] == '/')
	if !driveAbs && !strings.HasPrefix(root, `\\`) {
		// Not an absolute Windows path (checked textually so this works on any GOOS).
		return ""
	}
	return p
}

// systemPowerShellPath resolves the PowerShell path from the process environment.
func systemPowerShellPath() string { return windowsPowerShellPath(os.Getenv) }
