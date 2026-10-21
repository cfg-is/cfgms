// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/security"
)

// chdirEmpty moves the test into an empty directory so the development path
// ./controller.cfg cannot satisfy the lookup.
func chdirEmpty(t *testing.T) {
	t.Helper()
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(t.TempDir()))
	t.Cleanup(func() { _ = os.Chdir(orig) })
}

func setWindowsProductionPath(t *testing.T, p string) {
	t.Helper()
	orig := windowsProductionConfigPath
	windowsProductionConfigPath = p
	t.Cleanup(func() { windowsProductionConfigPath = orig })
	t.Setenv("CFGMS_CONTROLLER_CONFIG", "")
}

func TestFindConfigFile_WindowsProductionPath_AdminOnlyAccepted(t *testing.T) {
	chdirEmpty(t)
	dir := filepath.Join(t.TempDir(), "cfgms")
	require.NoError(t, security.EnsureAdminOnlyDir(dir))
	path := filepath.Join(dir, "controller.cfg")
	require.NoError(t, os.WriteFile(path, []byte("listen_addr: 127.0.0.1:0\n"), 0o600))
	setWindowsProductionPath(t, path)

	got, err := findConfigFile("")
	require.NoError(t, err)
	assert.Equal(t, path, got)
}

func TestFindConfigFile_WindowsProductionPath_UsersWritableRefused(t *testing.T) {
	chdirEmpty(t)
	dir := t.TempDir() // inherits the user-writable temp ACL
	path := filepath.Join(dir, "controller.cfg")
	require.NoError(t, os.WriteFile(path, []byte("listen_addr: 127.0.0.1:0\n"), 0o600))
	out, err := exec.Command("icacls", dir, "/grant", "*S-1-5-32-545:(OI)(CI)M").CombinedOutput()
	require.NoError(t, err, string(out))
	setWindowsProductionPath(t, path)

	got, err := findConfigFile("")
	require.Error(t, err)
	assert.Empty(t, got)
	assert.Contains(t, err.Error(), path)
	assert.Contains(t, err.Error(), "SYSTEM and Administrators")

	// LoadWithPath must not load the file either.
	cfg, err := LoadWithPath("")
	require.Error(t, err)
	assert.Nil(t, cfg)
}

func TestFindConfigFile_WindowsProductionPath_RefusalDoesNotFallThroughToDevPath(t *testing.T) {
	devDir := t.TempDir()
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(devDir))
	t.Cleanup(func() { _ = os.Chdir(orig) })
	require.NoError(t, os.WriteFile("controller.cfg", []byte("listen_addr: 127.0.0.1:0\n"), 0o600))

	path := filepath.Join(t.TempDir(), "controller.cfg")
	require.NoError(t, os.WriteFile(path, []byte("x: y\n"), 0o600))
	out, err2 := exec.Command("icacls", filepath.Dir(path), "/grant", "*S-1-5-32-545:(OI)(CI)M").CombinedOutput()
	require.NoError(t, err2, string(out))
	setWindowsProductionPath(t, path)

	got, err := findConfigFile("")
	require.Error(t, err)
	assert.Empty(t, got)
}
