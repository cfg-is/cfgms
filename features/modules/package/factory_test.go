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
	// Digit-width boundary: 1.9.x must sort BELOW 1.10.x and 1.29.x — a lexical
	// path sort would wrongly rank it first.
	mk("Microsoft.DesktopAppInstaller_1.9.25200.0_x64__8wekyb3d8bbwe", true)
	// Wrong publisher hash and wrong architecture must never match.
	mk("Evil.DesktopAppInstaller_9.9.9.9_x64__attacker00000", true)
	mk("Microsoft.DesktopAppInstaller_1.30.0.0_arm64__8wekyb3d8bbwe", true)
	// Package dir without the binary must not produce a candidate.
	mk("Microsoft.DesktopAppInstaller_1.31.0.0_x64__8wekyb3d8bbwe", false)

	got := wingetCandidates(programFiles)
	require.Len(t, got, 3, "only x64 DesktopAppInstaller dirs containing winget.exe match")
	assert.Contains(t, got[0], "1.29.280.0", "newest package version probed first (numeric compare)")
	assert.Contains(t, got[1], "1.26.510.0")
	assert.Contains(t, got[2], "1.9.25200.0", "1.9.x sorts below 1.26.x/1.29.x despite lexical order")
	for _, c := range got {
		assert.NotContains(t, c, "attacker", "foreign publisher directories must never match")
		assert.NotContains(t, c, "arm64")
	}
}

// TestCompareVersionSlices pins the numeric comparison, including the
// digit-width boundary and missing-segment-as-zero semantics.
func TestCompareVersionSlices(t *testing.T) {
	assert.Equal(t, 1, compareVersionSlices([]int{1, 10}, []int{1, 9}), "1.10 > 1.9")
	assert.Equal(t, -1, compareVersionSlices([]int{1, 9, 25200}, []int{1, 26, 510}), "1.9.x < 1.26.x")
	assert.Equal(t, 0, compareVersionSlices([]int{1, 29}, []int{1, 29, 0}), "1.29 == 1.29.0")
	assert.Equal(t, 1, compareVersionSlices([]int{2}, nil), "anything beats an unparseable version")
}

// TestWingetCandidates_Empty verifies absent WindowsApps and empty
// ProgramFiles cases degrade to no candidates (factory then falls through to
// chocolatey / the no-manager error).
func TestWingetCandidates_Empty(t *testing.T) {
	assert.Nil(t, wingetCandidates(t.TempDir()), "no WindowsApps dir → no candidates")
}
