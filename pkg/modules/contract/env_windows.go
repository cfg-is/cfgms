// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build windows

package contract

import "strings"

// baselineEnvNames are the variables every module process receives from the
// parent when the parent has them set (Windows).
var baselineEnvNames = []string{
	"PATH", "PATHEXT",
	"SystemRoot", "windir", "SystemDrive",
	"TEMP", "TMP",
	"ProgramData", "ProgramFiles", "ProgramFiles(x86)",
	"USERPROFILE", "APPDATA", "LOCALAPPDATA",
	"PSModulePath",
	"COMPUTERNAME", "PROCESSOR_ARCHITECTURE",
}

// envMatchKey returns the key names are compared by. Names are
// case-insensitive on Windows.
func envMatchKey(name string) string { return strings.ToUpper(name) }
