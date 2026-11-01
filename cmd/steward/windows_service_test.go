// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// writeAdminOnlyTokenFile creates path holding token, owned by
// BUILTIN\Administrators with a protected DACL for SYSTEM and Administrators
// only, the descriptor the installer gives the token file. Assigning
// Administrators as owner needs an elevated administrator, so t is skipped
// otherwise; the native Windows CI runners are elevated.
func writeAdminOnlyTokenFile(t *testing.T, path, token string) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated administrator: the token file is owned by BUILTIN\\Administrators")
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	require.NoError(t, err)
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_WRITE, 0, &sa,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	require.NoError(t, err)
	f := os.NewFile(uintptr(h), path)
	_, err = f.WriteString(token + "\n")
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

// makeReadableByOthers gives BUILTIN\Users read access to path through an
// explicit, protected DACL. Inheritance cannot be relied on for this: under
// SYSTEM, t.TempDir() is in C:\Windows\Temp, whose inheritable ACEs name only
// SYSTEM and Administrators, so a file created there is already admin-only.
func makeReadableByOthers(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)")
	require.NoError(t, err)
	acl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil))
}

func TestServiceRegToken_RefusesFileOtherPrincipalsCanRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registration-token")
	require.NoError(t, os.WriteFile(path, []byte("tok_user_readable\n"), 0o600))
	makeReadableByOthers(t, path)

	_, err := serviceRegToken(path)
	require.Error(t, err)
	// The owner check or the ACE check refuses it, depending on whether the
	// runner's default owner is its own account or Administrators.
	assert.Regexp(t, `must be owned by SYSTEM or BUILTIN\\Administrators|must grant access to SYSTEM and BUILTIN\\Administrators only`, err.Error())
	assert.NotContains(t, err.Error(), "tok_user_readable", "the error must not print the token")
}

func TestRegTokenFile_WindowsAdminOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registration-token")
	writeAdminOnlyTokenFile(t, path, "tok_admin_only")

	token, err := serviceRegToken(path)
	require.NoError(t, err)
	assert.Equal(t, "tok_admin_only", token, "the service handler reads --regtoken-file")

	token, started, err := runRootWithSeam(t, "--regtoken-file", path)
	require.NoError(t, err)
	assert.True(t, started)
	assert.Equal(t, "tok_admin_only", token, "the foreground command reads --regtoken-file")
}
