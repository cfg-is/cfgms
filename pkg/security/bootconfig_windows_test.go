// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package security

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func shortPathOf(t *testing.T, path string) string {
	t.Helper()
	p16, err := windows.UTF16PtrFromString(path)
	require.NoError(t, err)
	n, err := windows.GetShortPathName(p16, nil, 0)
	require.NoError(t, err)
	buf := make([]uint16, n)
	n, err = windows.GetShortPathName(p16, &buf[0], uint32(len(buf)))
	require.NoError(t, err)
	return windows.UTF16ToString(buf[:n])
}

// Every alias of steward.cfg must be recognised by file identity, not by
// string comparison. Fails if the guard is reverted to string comparison.
func TestIsProtectedBootConfigPath_WindowsAliases(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	cfg := filepath.Join(cwd, BootConfigFileName)
	require.NoError(t, os.WriteFile(cfg, []byte("steward: {}\n"), 0o600))

	other := t.TempDir()
	junction := filepath.Join(other, "junction")
	out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, cwd).CombinedOutput()
	require.NoError(t, err, string(out))
	hardlink := filepath.Join(other, "innocent.txt")
	require.NoError(t, os.Link(cfg, hardlink))

	aliases := map[string]string{
		"exact":          cfg,
		"case":           filepath.Join(strings.ToUpper(cwd), "STEWARD.CFG"),
		"trailing dot":   cfg + ".",
		"trailing dots":  cfg + "...",
		"trailing space": cfg + " ",
		"device prefix":  `\\?\` + cfg,
		"dot prefix":     `\\.\` + cfg,
		"stream":         cfg + "::$DATA",
		"named stream":   cfg + ":evil",
		"junction":       filepath.Join(junction, BootConfigFileName),
		"junction case":  filepath.Join(junction, "Steward.CFG"),
		"hard link":      hardlink,
	}
	short := shortPathOf(t, cfg)
	if !strings.EqualFold(short, cfg) {
		aliases["8.3 short name"] = short
	} else {
		t.Logf("8.3 short names are disabled on this volume; short-name alias not exercised")
	}
	for name, alias := range aliases {
		t.Run(name, func(t *testing.T) {
			assert.True(t, IsProtectedBootConfigPath(alias), alias)
		})
	}

	t.Run("unrelated file in the directory", func(t *testing.T) {
		assert.False(t, IsProtectedBootConfigPath(filepath.Join(cwd, "other.txt")))
	})
	t.Run("unrelated file elsewhere", func(t *testing.T) {
		assert.False(t, IsProtectedBootConfigPath(filepath.Join(other, "plain.txt")))
	})
}

// A boot-config name that does not exist yet in a search directory is still
// protected, including through aliases of the not-yet-existing leaf.
func TestIsProtectedBootConfigPath_WindowsNotYetExisting(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	host, err := os.Hostname()
	require.NoError(t, err)

	for _, name := range []string{BootConfigFileName, host + ".cfg", "STEWARD.CFG", BootConfigFileName + ".", BootConfigFileName + " "} {
		assert.True(t, IsProtectedBootConfigPath(filepath.Join(cwd, name)), name)
	}

	// Search directory that does not exist yet (PROGRAMDATA\cfgms).
	pd := t.TempDir()
	t.Setenv("PROGRAMDATA", pd)
	assert.True(t, IsProtectedBootConfigPath(filepath.Join(pd, "cfgms", BootConfigFileName)))
	assert.True(t, IsProtectedBootConfigPath(filepath.Join(pd, "CFGMS")))
	assert.False(t, IsProtectedBootConfigPath(filepath.Join(pd, "cfgms", "other.txt")))
}

// When identity cannot be established the guard refuses.
func TestIsProtectedBootConfigPath_WindowsFailsClosed(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)

	// Embedded NUL cannot be converted to a Win32 path.
	assert.True(t, IsProtectedBootConfigPath(filepath.Join(cwd, "a\x00b")))
}
