// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/pkg/security"
)

// systemBundleInLockedTree points systemBundlePathFn at a bundle written in an
// EnsureAdminOnlyDir tree and isolates the other candidates.
func systemBundleInLockedTree(t *testing.T) string {
	t.Helper()
	origSystem, origConfig, origFlag := systemBundlePathFn, userConfigDirFn, bundlePath
	t.Cleanup(func() {
		systemBundlePathFn, userConfigDirFn, bundlePath = origSystem, origConfig, origFlag
	})

	dir := filepath.Join(t.TempDir(), "cfgms")
	require.NoError(t, security.EnsureAdminOnlyDir(dir))
	file := filepath.Join(dir, "admin.bundle.yaml")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))

	bundlePath = ""
	userConfigDirFn = func() (string, error) { return t.TempDir(), nil }
	systemBundlePathFn = func() string { return file }
	return file
}

func TestFindBundlePath_WindowsSystemBundleAdminOnlyIsReturned(t *testing.T) {
	file := systemBundleInLockedTree(t)

	got, err := findBundlePath("")
	require.NoError(t, err)
	assert.Equal(t, file, got)
}

func TestFindBundlePath_WindowsSystemBundleGrantingUsersIsRefused(t *testing.T) {
	file := systemBundleInLockedTree(t)

	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)")
	require.NoError(t, err)
	acl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(file, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil))

	got, err := findBundlePath("")
	require.Error(t, err)
	assert.Empty(t, got)
	assert.ErrorIs(t, err, security.ErrUntrustedDirEntry)
	assert.Contains(t, err.Error(), file)
}

func TestFindBundlePath_WindowsMissingSystemBundleFallsThrough(t *testing.T) {
	file := systemBundleInLockedTree(t)
	require.NoError(t, os.Remove(file))

	got, err := findBundlePath("")
	require.NoError(t, err)
	assert.Empty(t, got)
}
