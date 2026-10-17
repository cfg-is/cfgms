// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package security

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

const (
	sidSystem         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
	sidUsers          = "S-1-5-32-545"
	sidAuthenticated  = "S-1-5-11"
	sidEveryone       = "S-1-1-0"
)

// daclSIDs returns the SIDs named by the ACEs of path's DACL and whether the
// DACL is protected from inheritance.
func daclSIDs(t *testing.T, path string) (sids []string, protected bool) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	ctrl, _, err := sd.Control()
	require.NoError(t, err)
	protected = ctrl&windows.SE_DACL_PROTECTED != 0
	acl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NotNil(t, acl)
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(acl, i, &ace))
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		sids = append(sids, sid.String())
	}
	return sids, protected
}

func TestEnsureAdminOnlyDir_FreshDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfgms")
	require.NoError(t, EnsureAdminOnlyDir(dir))

	sids, protected := daclSIDs(t, dir)
	assert.True(t, protected, "DACL must be protected from inheritance")
	assert.ElementsMatch(t, []string{sidSystem, sidAdministrators}, sids)

	file := filepath.Join(dir, "secret.bin")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))
	fileSIDs, _ := daclSIDs(t, file)
	for _, denied := range []string{sidUsers, sidAuthenticated, sidEveryone} {
		assert.NotContains(t, fileSIDs, denied)
	}
	assert.Contains(t, fileSIDs, sidSystem)
	assert.Contains(t, fileSIDs, sidAdministrators)
}

func TestEnsureAdminOnlyDir_CorrectsExistingTreeInPlace(t *testing.T) {
	dir := t.TempDir() // admin-owned in CI; inherits a permissive DACL
	child := filepath.Join(dir, "child")
	require.NoError(t, os.Mkdir(child, 0755))
	file := filepath.Join(child, "old.bin")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))

	require.NoError(t, EnsureAdminOnlyDir(dir))

	fileSIDs, _ := daclSIDs(t, file)
	for _, denied := range []string{sidUsers, sidAuthenticated, sidEveryone} {
		assert.NotContains(t, fileSIDs, denied, "existing child must pick up the new DACL")
	}
}

func TestEnsureAdminOnlyDir_RefusesFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))
	assert.Error(t, EnsureAdminOnlyDir(file))
}

func TestOwnerIsTrusted(t *testing.T) {
	tests := []struct {
		name    string
		sddl    string
		trusted bool
	}{
		{"builtin users refused", "O:BUG:BUD:(A;;FA;;;BU)", false},
		{"administrators accepted", "O:BAG:BAD:(A;;FA;;;BA)", true},
		{"system accepted", "O:SYG:SYD:(A;;FA;;;SY)", true},
		{"everyone refused", "O:WDG:WDD:(A;;FA;;;WD)", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			require.NoError(t, err)
			got, err := ownerIsTrusted(sd)
			require.NoError(t, err)
			assert.Equal(t, tc.trusted, got)
		})
	}
}

// ownerSID returns the SID string of path's owner.
func ownerSID(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	require.NoError(t, err)
	owner, _, err := sd.Owner()
	require.NoError(t, err)
	require.NotNil(t, owner)
	return owner.String()
}

func TestEnsureAdminOnlyDir_CreatesWithTrustedOwner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "cfgms")
	require.NoError(t, EnsureAdminOnlyDir(dir))

	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	require.NoError(t, err)
	trusted, err := ownerIsTrusted(sd)
	require.NoError(t, err)
	assert.True(t, trusted, "created directory owner %s must be trusted", ownerSID(t, dir))
}

func TestCreateAdminOnlyDir_ExistingDirectoryIsNotCreated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfgms")
	require.NoError(t, os.Mkdir(dir, 0755)) // e.g. planted between checks

	created, err := createAdminOnlyDir(dir)
	require.NoError(t, err)
	assert.False(t, created, "an existing directory must go through the owner check, never be treated as created")
}

func TestCreateAdminOnlyDir_NewDirectoryHasAdminOnlyDACLFromBirth(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfgms")

	created, err := createAdminOnlyDir(dir)
	require.NoError(t, err)
	assert.True(t, created)

	sids, protected := daclSIDs(t, dir)
	assert.True(t, protected, "DACL must be protected at creation")
	assert.ElementsMatch(t, []string{sidSystem, sidAdministrators}, sids)
}

func TestEnsureAdminOnlyDir_RefusesRootSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	require.NoError(t, os.Mkdir(target, 0755))
	link := filepath.Join(base, "cfgms")
	require.NoError(t, os.Symlink(target, link))

	err := EnsureAdminOnlyDir(link)
	require.Error(t, err)
	sids, _ := daclSIDs(t, target)
	assert.NotElementsMatch(t, []string{sidSystem, sidAdministrators}, sids, "link target must be left untouched")
}

func TestEnsureAdminOnlyDir_RefusesChildReparsePoint(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	require.NoError(t, os.Mkdir(outside, 0755))
	dir := filepath.Join(base, "cfgms")
	require.NoError(t, os.Mkdir(dir, 0755))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "certs")))

	err := EnsureAdminOnlyDir(dir)
	require.ErrorIs(t, err, ErrUntrustedDirEntry)
	_, protected := daclSIDs(t, dir)
	assert.False(t, protected, "a refused directory must be left unchanged")
}

func TestEnsureAdminOnlyDir_RefusesChildWithExplicitNonAdminACE(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "steward", "certs")
	require.NoError(t, os.MkdirAll(child, 0755))
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")
	require.NoError(t, err)
	dacl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(child, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil))

	err = EnsureAdminOnlyDir(dir)
	require.ErrorIs(t, err, ErrUntrustedDirEntry)
}

func TestDACLIsAdminOnly(t *testing.T) {
	tests := []struct {
		name string
		sddl string
		ok   bool
	}{
		{"admin only", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true},
		{"inherited admin only", "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)", true},
		{"deny users accepted", "D:P(D;;FA;;;BU)(A;;FA;;;BA)", true},
		{"users read refused", "D:P(A;;FA;;;BA)(A;;FR;;;BU)", false},
		{"creator owner refused", "D:P(A;;FA;;;BA)(A;OICIIO;FA;;;CO)", false},
		{"everyone refused", "D:P(A;;FA;;;SY)(A;;FA;;;WD)", false},
		{"null dacl refused", "D:NO_ACCESS_CONTROL", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			require.NoError(t, err)
			got, err := daclIsAdminOnly(sd)
			require.NoError(t, err)
			assert.Equal(t, tc.ok, got)
		})
	}
}
