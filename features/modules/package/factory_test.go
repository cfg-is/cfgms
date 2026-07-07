// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWingetCandidates verifies the WindowsApps glob resolution used by
// SYSTEM/service contexts that have no winget app-execution alias (#2337):
// only the DesktopAppInstaller x64 package family matches, and candidates are
// returned newest package version first.
func TestWingetCandidates(t *testing.T) {
	programFiles := t.TempDir()
	apps := filepath.Join(programFiles, "WindowsApps")

	mk := func(dir string, withExe bool) {
		full := filepath.Join(apps, dir)
		require.NoError(t, os.MkdirAll(full, 0o755))
		if withExe {
			require.NoError(t, os.WriteFile(filepath.Join(full, "winget.exe"), []byte("stub"), 0o755))
		}
	}

	mk("Microsoft.DesktopAppInstaller_1.26.510.0_x64__8wekyb3d8bbwe", true)
	mk("Microsoft.DesktopAppInstaller_1.29.280.0_x64__8wekyb3d8bbwe", true)
	// Wrong publisher hash and wrong architecture must never match.
	mk("Evil.DesktopAppInstaller_9.9.9.9_x64__attacker00000", true)
	mk("Microsoft.DesktopAppInstaller_1.30.0.0_arm64__8wekyb3d8bbwe", true)
	// Package dir without the binary must not produce a candidate.
	mk("Microsoft.DesktopAppInstaller_1.31.0.0_x64__8wekyb3d8bbwe", false)

	got := wingetCandidates(programFiles)
	require.Len(t, got, 2, "only x64 DesktopAppInstaller dirs containing winget.exe match")
	assert.Contains(t, got[0], "1.29.280.0", "newest package version probed first")
	assert.Contains(t, got[1], "1.26.510.0")
	for _, c := range got {
		assert.NotContains(t, c, "attacker", "foreign publisher directories must never match")
		assert.NotContains(t, c, "arm64")
	}
}

// TestWingetCandidates_Empty verifies absent WindowsApps and empty
// ProgramFiles cases degrade to no candidates (factory then falls through to
// chocolatey / the no-manager error).
func TestWingetCandidates_Empty(t *testing.T) {
	assert.Nil(t, wingetCandidates(t.TempDir()), "no WindowsApps dir → no candidates")
}
