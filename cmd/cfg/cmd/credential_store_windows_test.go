// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/pkg/credential"
	"github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	"github.com/cfgis/cfgms/pkg/testutil/winacct"
)

// credentialDACL returns whether path's DACL is protected and the SID strings
// its ACEs name.
func credentialDACL(t *testing.T, path string) (protected bool, sids []string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	control, _, err := sd.Control()
	require.NoError(t, err)
	acl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NotNil(t, acl, "%s must not have a NULL DACL", path)
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(acl, i, &ace))
		sids = append(sids, (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	return control&windows.SE_DACL_PROTECTED != 0, sids
}

// assertUserAndSystemOnly asserts path carries a protected DACL whose ACEs name
// only the current user and SYSTEM.
func assertUserAndSystemOnly(t *testing.T, path string) {
	t.Helper()
	user, err := currentUserSID()
	require.NoError(t, err)
	protected, sids := credentialDACL(t, path)
	assert.True(t, protected, "%s must carry a protected DACL (no inherited ACEs)", path)
	assert.Contains(t, sids, user.String(), path)
	assert.Contains(t, sids, "S-1-5-18", path)
	for _, sid := range sids {
		assert.Contains(t, []string{user.String(), "S-1-5-18"}, sid,
			"%s grants access to a principal other than the current user and SYSTEM", path)
	}
	for _, denied := range []string{"S-1-5-32-545", "S-1-5-11", "S-1-1-0"} {
		assert.NotContains(t, sids, denied, path)
	}
}

func TestCredentialStore_WindowsDACLIsUserAndSystemOnly(t *testing.T) {
	credDir := filepath.Join(t.TempDir(), "cfgms", "credentials")
	overrideCredentialsDir(t, credDir)

	store, err := newCredentialStore()
	require.NoError(t, err)
	require.NoError(t, store.Store(context.Background(), "ctrl", []byte("bundle")))

	assertUserAndSystemOnly(t, credDir)
	assertUserAndSystemOnly(t, filepath.Join(credDir, "ctrl.enc"))
}

// TestCredentialStore_WindowsDACLAppliedToExistingDir covers an upgrade: the
// directory already exists with the inherited profile ACL.
func TestCredentialStore_WindowsDACLAppliedToExistingDir(t *testing.T) {
	credDir := filepath.Join(t.TempDir(), "credentials")
	require.NoError(t, os.Mkdir(credDir, 0700))
	overrideCredentialsDir(t, credDir)

	store, err := newCredentialStore()
	require.NoError(t, err)
	require.NoError(t, store.Store(context.Background(), "ctrl", []byte("bundle")))

	assertUserAndSystemOnly(t, credDir)
	assertUserAndSystemOnly(t, filepath.Join(credDir, "ctrl.enc"))
}

func TestCredentialStore_WindowsRefusesDirOwnedByAnotherPrincipal(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("assigning another principal as owner needs SeRestorePrivilege, which only an elevated administrator holds (CI runners are elevated)")
	}
	credDir := filepath.Join(t.TempDir(), "credentials")
	require.NoError(t, os.Mkdir(credDir, 0700))
	winacct.SetOwner(t, credDir, winacct.StandardUser(t))
	overrideCredentialsDir(t, credDir)

	_, err := newCredentialStore()
	require.Error(t, err)
	assert.Contains(t, err.Error(), credDir, "the refusal must name the directory")
}

func TestCredentialStore_WindowsRefusesFileAsDir(t *testing.T) {
	credDir := filepath.Join(t.TempDir(), "credentials")
	require.NoError(t, os.WriteFile(credDir, []byte("x"), 0600))
	overrideCredentialsDir(t, credDir)

	_, err := newCredentialStore()
	require.Error(t, err)
	assert.Contains(t, err.Error(), credDir)
}

// TestCredentialStore_OldMachineScopeCredentialAsksToStoreAgain covers a
// credential written before the user-scope change: Load reports ErrLocked and
// tells the admin how to store it again, with no fallback decryption.
func TestCredentialStore_OldMachineScopeCredentialAsksToStoreAgain(t *testing.T) {
	credDir := filepath.Join(t.TempDir(), "credentials")
	overrideCredentialsDir(t, credDir)
	store, err := newCredentialStore()
	require.NoError(t, err)

	old, err := steward.NewPlatformEncryptor(credDir)
	require.NoError(t, err)
	ct, err := old.Encrypt([]byte("bundle stored before the user-scope change"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(credDir, "ctrl.enc"), ct, 0600))

	_, err = store.Load(context.Background(), "ctrl")
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrLocked)
	assert.Contains(t, err.Error(), "cfg connect")
	assert.Contains(t, err.Error(), "cfg credential enroll")
}
