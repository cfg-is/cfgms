// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/sys/windows"
)

const (
	sidUsers              = "S-1-5-32-545"
	sidAuthenticatedUsers = "S-1-5-11"
	sidEveryone           = "S-1-1-0"
)

// requireElevatedToken skips t unless the test runs elevated. writeTokenFile
// assigns BUILTIN\Administrators as owner and the tests hand files to other
// principals; both need an elevated administrator, as the installer and the
// native Windows CI runners are.
func requireElevatedToken(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated administrator: the token file is created with BUILTIN\\Administrators as owner")
	}
}

// fileACESIDs returns the SIDs named by the ACEs of path's DACL and whether the
// DACL is protected from inheritance.
func fileACESIDs(t *testing.T, path string) (sids []string, protected bool) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	ctrl, _, err := sd.Control()
	require.NoError(t, err)
	acl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NotNil(t, acl)
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(acl, i, &ace))
		sids = append(sids, (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	return sids, ctrl&windows.SE_DACL_PROTECTED != 0
}

// setDACLFromSDDL replaces path's DACL with the DACL of sddl. The DACL is
// protected from inheritance only when protect is set.
func setDACLFromSDDL(t *testing.T, path, sddl string, protect bool) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	require.NoError(t, err)
	acl, _, err := sd.DACL()
	require.NoError(t, err)
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	if protect {
		info = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, acl, nil))
}

// assertSystemAndAdministratorsOnly asserts path has a protected DACL whose
// ACEs name only SYSTEM and BUILTIN\Administrators.
func assertSystemAndAdministratorsOnly(t *testing.T, path string) {
	t.Helper()
	sids, protected := fileACESIDs(t, path)
	assert.True(t, protected, "token file DACL must not inherit ACEs from the directory")
	assert.ElementsMatch(t, []string{sidLocalSystem, sidAdministrators}, sids)
	for _, denied := range []string{sidUsers, sidAuthenticatedUsers, sidEveryone} {
		assert.NotContains(t, sids, denied)
	}
}

func TestWriteTokenFile_WindowsDACLIsSystemAndAdministratorsOnly(t *testing.T) {
	requireElevatedToken(t)
	t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
	path := platformTokenFilePath()

	require.NoError(t, writeTokenFile(path, "tok_windows_dacl"))

	assertSystemAndAdministratorsOnly(t, path)
	data, err := os.ReadFile(path) // #nosec G304 - test-controlled path
	require.NoError(t, err)
	assert.Equal(t, "tok_windows_dacl\n", string(data))
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temporary token file may be left behind")
}

func TestWriteTokenFile_ReplacesInheritedUsersReadableDACL(t *testing.T) {
	requireElevatedToken(t)
	t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
	path := platformTokenFilePath()
	dir := filepath.Dir(path)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	// A directory that was not locked yet: its files inherit a Users read ACE.
	setDACLFromSDDL(t, dir, "D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)", false)
	require.NoError(t, os.WriteFile(path, []byte("tok_old\n"), 0o600))
	before, protected := fileACESIDs(t, path)
	require.Contains(t, before, sidUsers, "precondition: the existing token file is readable by Users")
	require.False(t, protected, "precondition: the existing token file inherits its DACL")

	require.NoError(t, writeTokenFile(path, "tok_new"))

	assertSystemAndAdministratorsOnly(t, path)
	data, err := os.ReadFile(path) // #nosec G304 - test-controlled path
	require.NoError(t, err)
	assert.Equal(t, "tok_new\n", string(data))
}

func TestReadTokenFile_WindowsAcceptsFileWrittenByWriteTokenFile(t *testing.T) {
	requireElevatedToken(t)
	t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
	path := platformTokenFilePath()
	require.NoError(t, writeTokenFile(path, "tok_round_trip"))

	token, err := ReadTokenFile(path)
	require.NoError(t, err)
	assert.Equal(t, "tok_round_trip", token)
}

func TestReadTokenFile_WindowsRefusesFileOwnedByUsers(t *testing.T) {
	requireElevatedToken(t)
	t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
	path := platformTokenFilePath()
	require.NoError(t, writeTokenFile(path, "tok_owned_by_users"))
	setOwnerWithRestorePrivilege(t, path, sidUsers)

	_, err := ReadTokenFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be owned by SYSTEM or BUILTIN\\Administrators")
	assert.NotContains(t, err.Error(), "tok_owned_by_users", "the error must not print the token")
}

func TestReadTokenFile_WindowsRefusesUsersACE(t *testing.T) {
	requireElevatedToken(t)
	t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
	path := platformTokenFilePath()
	require.NoError(t, writeTokenFile(path, "tok_users_ace"))
	setDACLFromSDDL(t, path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)", true)

	_, err := ReadTokenFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must grant access to SYSTEM and BUILTIN\\Administrators only")
	assert.NotContains(t, err.Error(), "tok_users_ace", "the error must not print the token")
}

func TestReadTokenFile_WindowsRefusesDenyACE(t *testing.T) {
	requireElevatedToken(t)
	t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
	path := platformTokenFilePath()
	require.NoError(t, writeTokenFile(path, "tok_deny_ace"))
	setDACLFromSDDL(t, path, "D:P(D;;FA;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)", true)

	_, err := ReadTokenFile(path)
	require.Error(t, err, "a DACL naming any other principal is refused, deny ACEs included")
	assert.Contains(t, err.Error(), "must grant access to SYSTEM and BUILTIN\\Administrators only")
	assert.NotContains(t, err.Error(), "tok_deny_ace")
}

func TestReadTokenFile_WindowsRefusesNullDACL(t *testing.T) {
	requireElevatedToken(t)
	t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
	path := platformTokenFilePath()
	require.NoError(t, writeTokenFile(path, "tok_null_dacl"))
	// A NULL DACL grants everyone full access.
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil))

	_, err := ReadTokenFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has no access control list")
	assert.NotContains(t, err.Error(), "tok_null_dacl")
}

func TestReadTokenFile_WindowsRefusesSymlink(t *testing.T) {
	requireElevatedToken(t)
	t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
	target := platformTokenFilePath()
	require.NoError(t, writeTokenFile(target, "tok_behind_link"))
	link := filepath.Join(t.TempDir(), "link-token")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("creating a symbolic link needs SeCreateSymbolicLinkPrivilege, which this runner lacks: %v", err)
	}

	_, err := ReadTokenFile(link)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not a regular file")
	assert.NotContains(t, err.Error(), "tok_behind_link")
}

func TestReadTokenFile_WindowsRefusesDirectory(t *testing.T) {
	_, err := ReadTokenFile(t.TempDir())
	require.Error(t, err)
}

func TestReadTokenFile_WindowsRefusesBadContent(t *testing.T) {
	requireElevatedToken(t)
	for name, tc := range map[string]struct {
		content string
		want    string
	}{
		"empty":      {"\n", "is empty"},
		"too large":  {strings.Repeat("a", maxTokenFileSize+1), "is too large"},
		"whitespace": {"tok_inner space\n", "contains whitespace"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
			path := platformTokenFilePath()
			require.NoError(t, writeTokenFile(path, "tok_placeholder"))
			// Rewriting the content keeps the admin-only descriptor.
			require.NoError(t, os.WriteFile(path, []byte(tc.content), 0o600))

			_, err := ReadTokenFile(path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestReadTokenFile_WindowsMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), tokenFileName)

	_, err := ReadTokenFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

func TestWriteTokenFile_WindowsRejectsWhitespaceToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), tokenFileName)

	require.Error(t, writeTokenFile(path, "tok with space"))
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), "no token file may be written for an invalid token")
}
