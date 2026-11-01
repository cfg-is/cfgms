// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package security

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsProtectedBootConfigPath(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)

	assert.True(t, IsProtectedBootConfigPath(filepath.Join(cwd, BootConfigFileName)))
	assert.True(t, IsProtectedBootConfigPath(cwd))
	assert.False(t, IsProtectedBootConfigPath(filepath.Join(cwd, "other.txt")))

	host, err := os.Hostname()
	require.NoError(t, err)
	assert.True(t, IsProtectedBootConfigPath(filepath.Join(cwd, host+".cfg")))

	if runtime.GOOS != "windows" {
		link := filepath.Join(t.TempDir(), "alias")
		require.NoError(t, os.Symlink(cwd, link))
		assert.True(t, IsProtectedBootConfigPath(filepath.Join(link, BootConfigFileName)))
	}
}

func TestLoadedBootConfigSurvivesHostnameChange(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PROGRAMDATA", home)
	t.Chdir(t.TempDir())
	var dir string
	for _, d := range BootConfigDirs() {
		if strings.HasPrefix(d, home) {
			dir = d
			break
		}
	}
	require.NotEmpty(t, dir)
	require.NoError(t, os.MkdirAll(dir, 0o700))

	orig := hostnameFunc
	resetLoadedBootConfig()
	t.Cleanup(func() { hostnameFunc = orig; resetLoadedBootConfig() })

	hostnameFunc = func() (string, error) { return "oldhost", nil }
	SetLoadedBootConfigPath(filepath.Join(dir, "oldhost.cfg"))
	hostnameFunc = func() (string, error) { return "newhost", nil }

	assert.True(t, IsProtectedBootConfigPath(filepath.Join(dir, "oldhost.cfg")))
	assert.True(t, IsProtectedBootConfigPath(filepath.Join(dir, "newhost.cfg")))
	assert.True(t, IsProtectedBootConfigPath(filepath.Join(dir, "steward.cfg")))
	assert.False(t, IsProtectedBootConfigPath(filepath.Join(dir, "other.cfg")))

	assert.False(t, BootConfigExistsForHostname("planted"))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "planted.cfg"), []byte("x"), 0o600))
	assert.True(t, BootConfigExistsForHostname("planted"))
}

// A host name recorded for a pending rename protects "<name>.cfg" even though
// the current host name has not changed yet (Issue #5490).
func TestAddProtectedBootConfigHostname(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PROGRAMDATA", home)
	t.Chdir(t.TempDir())
	var dir string
	for _, d := range BootConfigDirs() {
		if strings.HasPrefix(d, home) {
			dir = d
			break
		}
	}
	require.NotEmpty(t, dir)
	require.NoError(t, os.MkdirAll(dir, 0o700))

	orig := hostnameFunc
	resetLoadedBootConfig()
	t.Cleanup(func() { hostnameFunc = orig; resetLoadedBootConfig() })
	hostnameFunc = func() (string, error) { return "oldhost", nil }

	assert.False(t, IsProtectedBootConfigPath(filepath.Join(dir, "pending.cfg")))
	AddProtectedBootConfigHostname("")
	AddProtectedBootConfigHostname("pending")
	assert.True(t, IsProtectedBootConfigPath(filepath.Join(dir, "pending.cfg")))
	assert.True(t, IsProtectedBootConfigPath(filepath.Join(dir, "oldhost.cfg")))
	assert.False(t, IsProtectedBootConfigPath(filepath.Join(dir, ".cfg")))
}
